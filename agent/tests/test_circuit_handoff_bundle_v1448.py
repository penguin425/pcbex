from __future__ import annotations

import copy
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from pcbex_agent import bounded_io, cli
from pcbex_agent import circuit_handoff_bundle as handoff_module
from pcbex_agent.catalog import (
    load_catalog_snapshot,
    select_catalog_parts,
    validate_catalog_receipt,
)
from pcbex_agent.circuit_generation import (
    _compact_json,
    _render_skidl,
    generate_circuit_with_command,
    generate_circuit_with_llm,
)
from pcbex_agent.circuit_handoff_bundle import (
    CIRCUIT_HANDOFF_BUNDLE_ADAPTER,
    CircuitHandoffBundleError,
    build_circuit_handoff_archive,
    circuit_handoff_bundle_json_schema,
    handoff_circuit_generation,
    validate_circuit_generation_bundle,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _spec() -> dict[str, object]:
    return {
        "schema_version": 2,
        "parts": [
            {
                "reference": "R1",
                "lib_id": "Device:R",
                "value": "1k",
                "footprint": "Resistor_SMD:R_0603_1608Metric",
                "mpn": None,
                "power": {
                    "rail_voltage_uv": None,
                    "max_voltage_uv": None,
                    "requires_decoupling": False,
                    "decoupling": False,
                },
                "pins": [
                    {
                        "number": "1",
                        "name": "1",
                        "net": "SIGNAL",
                        "electrical_type": "passive",
                    },
                    {
                        "number": "2",
                        "name": "2",
                        "net": None,
                        "electrical_type": "no_connect",
                    },
                ],
            },
            {
                "reference": "R2",
                "lib_id": "Device:R",
                "value": "1k",
                "footprint": "Resistor_SMD:R_0603_1608Metric",
                "mpn": None,
                "power": {
                    "rail_voltage_uv": None,
                    "max_voltage_uv": None,
                    "requires_decoupling": False,
                    "decoupling": False,
                },
                "pins": [
                    {
                        "number": "1",
                        "name": "1",
                        "net": "SIGNAL",
                        "electrical_type": "passive",
                    },
                    {
                        "number": "2",
                        "name": "2",
                        "net": None,
                        "electrical_type": "no_connect",
                    },
                ],
            },
        ],
        "nets": [
            {
                "name": "SIGNAL",
                "voltage_uv": None,
                "connections": [
                    {"reference": "R1", "pin": "1"},
                    {"reference": "R2", "pin": "1"},
                ],
            }
        ],
    }


def _review() -> dict[str, object]:
    return {
        "schema_version": 1,
        "schematic_sha256": "1" * 64,
        "policy_sha256": "2" * 64,
        "policy_id": "pcbex-electrical-default-v1",
        "approved": True,
        "counts": {"errors": 0, "warnings": 0, "info": 0},
        "findings": [],
    }


def _catalog_snapshot():
    return load_catalog_snapshot(
        {
            "schema_version": 1,
            "supplier": "test-supplier",
            "snapshot_id": "resistor-snapshot",
            "captured_at_unix": 100,
            "expires_at_unix": 200,
            "parts": [
                {
                    "mpn": "R-1K-0603",
                    "supplier_part_number": "C1000",
                    "description": "1k resistor",
                    "footprint": "Resistor_SMD:R_0603_1608Metric",
                    "tags": ["1k", "resistor"],
                    "vendor": "Example",
                    "stock": 10,
                    "basic": True,
                    "datasheet_url": "https://example.test/r-1k",
                }
            ],
        },
        evaluated_at_unix=150,
    )


def _bundle() -> dict[str, object]:
    spec = _spec()
    review = _review()
    check = {
        "schema_version": 1,
        "circuit_spec_sha256": _sha(_compact_json(spec)),
        "electrical_review_sha256": _sha(_compact_json(review)),
        "normalized_spec": spec,
        "electrical_review": review,
    }
    history = {
        "attempt": 1,
        "prompt_bytes": 1,
        "prompt_sha256": _sha(b"p"),
        "response_bytes": 1,
        "response_sha256": _sha(b"r"),
        "outcome": "approved",
        "spec_sha256": _sha(_compact_json(spec)),
        "check_sha256": _sha(_compact_json(check)),
        "circuit_spec_sha256": check["circuit_spec_sha256"],
        "electrical_review_sha256": check["electrical_review_sha256"],
        "resolved_spec_sha256": None,
        "resolved_check_sha256": None,
        "resolved_circuit_spec_sha256": None,
        "resolved_electrical_review_sha256": None,
        "catalog_receipt_sha256": None,
        "errors": 0,
        "warnings": 0,
        "error_count": 0,
    }
    skidl = _render_skidl(
        spec,
        check["circuit_spec_sha256"],
        check["electrical_review_sha256"],
    )
    return {
        "schema_version": 2,
        "requirements": {"bytes": 1, "sha256": _sha(b"q")},
        "provider": {
            "adapter": "provider-command-v1",
            "executable": "fake-provider",
            "argv_sha256": _sha(b"argv"),
            "timeout_seconds": 30.0,
            "maximum_output_bytes": 1024,
        },
        "attempts": 1,
        "attempt_history": [history],
        "repaired": False,
        "spec": spec,
        "check": check,
        "circuit_spec_sha256": check["circuit_spec_sha256"],
        "electrical_review_sha256": check["electrical_review_sha256"],
        "catalog_receipt": None,
        "catalog_receipt_sha256": None,
        "skidl": skidl,
        "skidl_sha256": _sha(skidl.encode()),
    }


def _replace_native_check(
    bundle: dict[str, object], check: dict[str, object]
) -> dict[str, object]:
    value = copy.deepcopy(bundle)
    spec = check["normalized_spec"]
    value["spec"] = spec
    value["check"] = check
    value["circuit_spec_sha256"] = check["circuit_spec_sha256"]
    value["electrical_review_sha256"] = check["electrical_review_sha256"]
    history = value["attempt_history"][-1]
    history["spec_sha256"] = _sha(_compact_json(spec))
    history["check_sha256"] = _sha(_compact_json(check))
    history["circuit_spec_sha256"] = check["circuit_spec_sha256"]
    history["electrical_review_sha256"] = check["electrical_review_sha256"]
    history["warnings"] = check["electrical_review"]["counts"]["warnings"]
    skidl = _render_skidl(
        spec,
        check["circuit_spec_sha256"],
        check["electrical_review_sha256"],
    )
    value["skidl"] = skidl
    value["skidl_sha256"] = _sha(skidl.encode())
    return value


def _render(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def _write_fake_pcbex(
    root: Path,
    check: dict[str, object],
    *,
    initial_check: dict[str, object] | None = None,
    fail: str | None = None,
    forge: str | None = None,
) -> list[str]:
    expected = root / "expected-check.json"
    expected.write_bytes(_render(check))
    if initial_check is not None:
        (root / "expected-initial-check.json").write_bytes(_render(initial_check))
    script = root / "fake_pcbex.py"
    script.write_text(
        """#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).parent
check = json.loads((root / "expected-check.json").read_text(encoding="utf-8"))
initial_path = root / "expected-initial-check.json"
initial_check = (
    json.loads(initial_path.read_text(encoding="utf-8"))
    if initial_path.exists()
    else None
)
command = sys.argv[1]
fail = %r
forge = %r
if command == fail:
    raise SystemExit(9)
output = Path(sys.argv[sys.argv.index("--output") + 1])
if command == "check-circuit-spec":
    selected = (
        initial_check
        if initial_check is not None and "catalog-input" in Path(sys.argv[2]).name
        else check
    )
    output.write_text(json.dumps(selected, indent=2) + "\\n", encoding="utf-8")
elif command == "write-circuit-spec-kicad-schematic":
    if forge == "empty_schematic":
        output.write_bytes(b"")
    else:
        output.write_bytes(b"(kicad_sch (version 20231120) (generator pcbex-test))\\n")
elif command == "verify-circuit-kicad-handoff":
    circuit = Path(sys.argv[2]).read_bytes()
    schematic = Path(sys.argv[3]).read_bytes()
    compact = json.dumps(check, ensure_ascii=False, separators=(",", ":")).encode()
    review = check["electrical_review"]
    schematic_review = json.loads(json.dumps(review))
    schematic_review["schematic_sha256"] = hashlib.sha256(schematic).hexdigest()
    report = {
        "schema_version": 1,
        "engine_version": "1.448.0-test",
        "circuit_source_bytes": len(circuit),
        "circuit_source_sha256": hashlib.sha256(circuit).hexdigest(),
        "schematic_source_bytes": len(schematic),
        "schematic_source_sha256": hashlib.sha256(schematic).hexdigest(),
        "circuit_spec_sha256": check["circuit_spec_sha256"],
        "circuit_check_sha256": hashlib.sha256(compact).hexdigest(),
        "circuit_review": review,
        "schematic_sha256": schematic_review["schematic_sha256"],
        "schematic_review": schematic_review,
        "policy_sha256": review["policy_sha256"],
        "findings": [],
        "counts": {"errors": 0, "warnings": 0, "info": 0},
        "approved": True,
    }
    if forge == "float_source_bytes":
        report["schematic_source_bytes"] = float(report["schematic_source_bytes"])
    elif forge == "missing_schematic_review":
        report["schematic_review"] = None
    output.write_text(json.dumps(report, indent=2) + "\\n", encoding="utf-8")
else:
    raise SystemExit(8)
"""
        % (fail, forge),
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return [sys.executable, str(script)]


class CircuitHandoffBundleTests(unittest.TestCase):
    def test_validates_complete_generation_evidence(self) -> None:
        bundle = _bundle()
        self.assertEqual(validate_circuit_generation_bundle(bundle), bundle)

        for mutation in (
            lambda value: value.update(extra=True),
            lambda value: value["check"].update(circuit_spec_sha256="0" * 64),
            lambda value: value.update(skidl="# executable-looking but inert\n"),
            lambda value: value["attempt_history"][-1].update(errors=1),
        ):
            value = copy.deepcopy(bundle)
            mutation(value)
            with self.subTest(value=value), self.assertRaises(CircuitHandoffBundleError):
                validate_circuit_generation_bundle(value)

        for location in ("spec", "check", "review"):
            value = copy.deepcopy(bundle)
            if location == "spec":
                value["spec"]["schema_version"] = True
                value["check"]["normalized_spec"]["schema_version"] = True
            elif location == "check":
                value["check"]["schema_version"] = True
            else:
                value["check"]["electrical_review"]["schema_version"] = True
            with self.subTest(boolean_schema=location), self.assertRaises(
                CircuitHandoffBundleError
            ):
                validate_circuit_generation_bundle(value)

        for key in ("prompt_bytes", "response_bytes"):
            value = copy.deepcopy(bundle)
            value["attempt_history"][-1][key] = 0
            with self.subTest(empty_evidence=key), self.assertRaises(
                CircuitHandoffBundleError
            ):
                validate_circuit_generation_bundle(value)

    def test_validates_catalog_resolved_generation_evidence(self) -> None:
        initial = _spec()
        snapshot = _catalog_snapshot()

        def envelope(spec: dict[str, object]) -> dict[str, object]:
            review = _review()
            return {
                "schema_version": 1,
                "circuit_spec_sha256": _sha(_compact_json(spec)),
                "electrical_review_sha256": _sha(_compact_json(review)),
                "normalized_spec": spec,
                "electrical_review": review,
            }

        def checker(path: Path, _remaining: float) -> dict[str, object]:
            if path.name.startswith("candidate-"):
                return envelope(initial)
            return envelope(json.loads(path.read_text(encoding="utf-8")))

        def selector(spec: dict[str, object], _remaining: float):
            return select_catalog_parts(spec, snapshot, evaluated_at_unix=150)

        def receipt_validator(original, resolved, receipt, _remaining):
            validate_catalog_receipt(
                receipt,
                original,
                resolved,
                snapshot,
                evaluated_at_unix=150,
            )

        bundle = generate_circuit_with_llm(
            "two 1k resistors",
            {"type": "object"},
            lambda _prompt, _remaining: '{"candidate":1}',
            checker,
            catalog_selector=selector,
            catalog_receipt_validator=receipt_validator,
        )
        initial_check = envelope(initial)
        with self.assertRaises(CircuitHandoffBundleError):
            validate_circuit_generation_bundle(bundle)
        self.assertEqual(
            validate_circuit_generation_bundle(
                bundle,
                catalog_initial_check=initial_check,
            ),
            bundle,
        )

        with tempfile.TemporaryDirectory() as directory:
            command = _write_fake_pcbex(
                Path(directory),
                bundle["check"],
                initial_check=initial_check,
            )
            archive, manifest = build_circuit_handoff_archive(
                _render(bundle),
                command,
            )
            self.assertTrue(archive)
            self.assertTrue(manifest["approved"])

            for key in (
                "spec_sha256",
                "check_sha256",
                "circuit_spec_sha256",
                "electrical_review_sha256",
            ):
                forged = copy.deepcopy(bundle)
                forged["attempt_history"][-1][key] = "f" * 64
                with self.subTest(forged_catalog_history=key), self.assertRaises(
                    CircuitHandoffBundleError
                ):
                    build_circuit_handoff_archive(_render(forged), command)

        reordered = copy.deepcopy(bundle)
        reordered["spec"] = json.loads(
            json.dumps(bundle["spec"], sort_keys=True)
        )
        reordered["check"]["normalized_spec"] = copy.deepcopy(reordered["spec"])
        reordered["check"]["circuit_spec_sha256"] = _sha(
            _compact_json(reordered["spec"])
        )
        reordered["check"]["electrical_review_sha256"] = _sha(
            _compact_json(reordered["check"]["electrical_review"])
        )
        reordered["circuit_spec_sha256"] = reordered["check"][
            "circuit_spec_sha256"
        ]
        reordered["electrical_review_sha256"] = reordered["check"][
            "electrical_review_sha256"
        ]
        history = reordered["attempt_history"][-1]
        history["resolved_spec_sha256"] = _sha(_compact_json(reordered["spec"]))
        history["resolved_check_sha256"] = _sha(_compact_json(reordered["check"]))
        history["resolved_circuit_spec_sha256"] = reordered["check"][
            "circuit_spec_sha256"
        ]
        history["resolved_electrical_review_sha256"] = reordered["check"][
            "electrical_review_sha256"
        ]
        skidl = _render_skidl(
            reordered["spec"],
            reordered["check"]["circuit_spec_sha256"],
            reordered["check"]["electrical_review_sha256"],
            reordered["catalog_receipt_sha256"],
        )
        reordered["skidl"] = skidl
        reordered["skidl_sha256"] = _sha(skidl.encode())
        self.assertEqual(
            validate_circuit_generation_bundle(
                reordered,
                catalog_initial_check=initial_check,
            ),
            reordered,
        )

    def test_builds_deterministic_exact_set_archive_and_closed_manifest(self) -> None:
        bundle = _bundle()
        bundle_raw = _render(bundle)
        with tempfile.TemporaryDirectory() as directory:
            command = _write_fake_pcbex(Path(directory), bundle["check"])
            first, manifest = build_circuit_handoff_archive(bundle_raw, command)
            second, repeated = build_circuit_handoff_archive(bundle_raw, command)

        self.assertEqual(first, second)
        self.assertEqual(manifest, repeated)
        self.assertEqual(manifest["adapter"], CIRCUIT_HANDOFF_BUNDLE_ADAPTER)
        self.assertTrue(manifest["approved"])
        with zipfile.ZipFile(io.BytesIO(first)) as archive:
            self.assertEqual(
                archive.namelist(),
                [
                    "generation-bundle.json",
                    "circuit-spec-v2.json",
                    "circuit-spec-check.json",
                    "circuit-spec.kicad_sch",
                    "circuit-kicad-handoff.json",
                    "manifest.json",
                ],
            )
            self.assertEqual(archive.read("generation-bundle.json"), bundle_raw)
            self.assertEqual(json.loads(archive.read("manifest.json")), manifest)
            for info in archive.infolist():
                self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0))
                self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
            for descriptor in manifest["artifacts"].values():
                raw = archive.read(descriptor["name"])
                self.assertEqual(descriptor["bytes"], len(raw))
                self.assertEqual(descriptor["sha256"], _sha(raw))

        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional local dependency
            return
        validator = Draft202012Validator(circuit_handoff_bundle_json_schema())
        self.assertEqual(list(validator.iter_errors(manifest)), [])
        forged = copy.deepcopy(manifest)
        forged["extra"] = True
        self.assertTrue(list(validator.iter_errors(forged)))

    def test_rejects_duplicate_keys_before_starting_native_command(self) -> None:
        bundle = _bundle()
        raw = _render(bundle)
        duplicate = raw.replace(
            b'{\n  "schema_version": 2,',
            b'{\n  "schema_version": 2,\n  "schema_version": 2,',
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "spawned"
            script = Path(directory) / "must_not_run.py"
            script.write_text(
                "from pathlib import Path\nPath(%r).write_text('spawned')\n" % str(marker),
                encoding="utf-8",
            )
            with self.assertRaises(CircuitHandoffBundleError):
                build_circuit_handoff_archive(duplicate, [sys.executable, str(script)])
            self.assertFalse(marker.exists())

    def test_failure_and_preflight_collision_publish_nothing(self) -> None:
        bundle = _bundle()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "generation.json"
            source.write_bytes(_render(bundle))
            output = root / "handoff.zip"
            command = _write_fake_pcbex(
                root,
                bundle["check"],
                fail="write-circuit-spec-kicad-schematic",
            )
            with self.assertRaises(CircuitHandoffBundleError):
                handoff_circuit_generation(source, output, command)
            self.assertFalse(output.exists())

            output.write_bytes(b"owned")
            marker = root / "spawned"
            no_run = root / "no_run.py"
            no_run.write_text(
                "from pathlib import Path\nPath(%r).write_text('spawned')\n" % str(marker),
                encoding="utf-8",
            )
            with self.assertRaises(CircuitHandoffBundleError):
                handoff_circuit_generation(
                    source,
                    output,
                    [sys.executable, str(no_run)],
                )
            self.assertEqual(output.read_bytes(), b"owned")
            self.assertFalse(marker.exists())

    @unittest.skipIf(os.name == "nt", "Windows skips directory fsync")
    def test_final_directory_sync_failure_rolls_back_archive(self) -> None:
        bundle = _bundle()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "generation.json"
            source.write_bytes(_render(bundle))
            output = root / "handoff.zip"
            command = _write_fake_pcbex(root, bundle["check"])
            real_sync = bounded_io._sync_parent
            calls = 0

            def fail_final_sync(parent: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise bounded_io.BoundedIOError(
                        errno.EIO,
                        "directory sync failed",
                        os.fspath(parent),
                    )
                real_sync(parent)

            with mock.patch.object(
                bounded_io,
                "_sync_parent",
                side_effect=fail_final_sync,
            ), self.assertRaises(CircuitHandoffBundleError):
                handoff_circuit_generation(source, output, command)

            self.assertEqual(calls, 2)
            self.assertFalse(output.exists())

    def test_rejects_empty_or_malformed_native_outputs(self) -> None:
        bundle = _bundle()
        bundle_raw = _render(bundle)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for forge in (
                "empty_schematic",
                "float_source_bytes",
                "missing_schematic_review",
            ):
                command = _write_fake_pcbex(root, bundle["check"], forge=forge)
                with self.subTest(forge=forge), self.assertRaises(
                    CircuitHandoffBundleError
                ):
                    build_circuit_handoff_archive(bundle_raw, command)
            for invalid_command in ("", None, 1, object()):
                with self.subTest(invalid_command=invalid_command), self.assertRaises(
                    CircuitHandoffBundleError
                ):
                    build_circuit_handoff_archive(bundle_raw, invalid_command)

    def test_deadline_starts_before_input_read_and_native_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "generation.json"
            source.write_bytes(_render(_bundle()))
            output = root / "handoff.zip"
            ticks = iter((0.0, 2.0))
            with mock.patch.object(handoff_module, "read_bytes") as read:
                with self.assertRaises(CircuitHandoffBundleError):
                    handoff_circuit_generation(
                        source,
                        output,
                        "must-not-run",
                        timeout_seconds=1.0,
                        _clock=lambda: next(ticks),
                    )
            read.assert_not_called()
            self.assertFalse(output.exists())

    def test_cli_routes_handoff_and_schema_without_provider_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "generation.json"
            output = root / "handoff.zip"
            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "handoff-circuit",
                    str(source),
                    "--output",
                    str(output),
                    "--pcbex",
                    "native-pcbex",
                    "--timeout-seconds",
                    "42",
                ],
            ), mock.patch.object(
                cli,
                "handoff_circuit_generation",
                return_value={"bundle_sha256": "a" * 64},
            ) as handoff:
                cli.main()
            handoff.assert_called_once_with(
                source,
                output,
                "native-pcbex",
                timeout_seconds=42.0,
            )

            schema = root / "schema.json"
            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "circuit-handoff-bundle-schema",
                    "--output",
                    str(schema),
                ],
            ):
                cli.main()
            self.assertFalse(
                circuit_handoff_bundle_json_schema().get("additionalProperties", True)
            )
            self.assertEqual(json.loads(schema.read_text()), circuit_handoff_bundle_json_schema())

    def test_real_native_erc_writer_and_handoff_when_binary_is_supplied(self) -> None:
        binary = os.environ.get("PCBEX_TEST_BINARY")
        if not binary:
            self.skipTest("PCBEX_TEST_BINARY is not set")
        binary_path = Path(binary).resolve()
        if not binary_path.is_file():
            self.fail("PCBEX_TEST_BINARY does not name a regular file")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = root / "spec.json"
            spec.write_bytes(_render(_spec()))
            result = subprocess.run(
                [str(binary_path), "check-circuit-spec", str(spec)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
            check = json.loads(result.stdout)
            self.assertTrue(check["electrical_review"]["approved"])
            bundle = _replace_native_check(_bundle(), check)
            source = root / "generation.json"
            source.write_bytes(_render(bundle))
            output = root / "handoff.zip"
            manifest = handoff_circuit_generation(
                source,
                output,
                str(binary_path),
                timeout_seconds=30,
            )
            self.assertTrue(manifest["approved"])
            with zipfile.ZipFile(output) as archive:
                schematic = archive.read("circuit-spec.kicad_sch")
                handoff = json.loads(archive.read("circuit-kicad-handoff.json"))
            self.assertTrue(schematic.startswith(b"(kicad_sch\n"))
            self.assertTrue(handoff["approved"])
            self.assertEqual(handoff["findings"], [])

            provider_source = json.dumps(
                _spec(),
                ensure_ascii=False,
                separators=(",", ":"),
            )
            catalog_bundle = generate_circuit_with_command(
                "two 1k resistors",
                str(binary_path),
                [
                    sys.executable,
                    "-c",
                    "import sys;sys.stdout.write(sys.argv[1])",
                    provider_source,
                ],
                catalog_snapshot=_catalog_snapshot(),
                evaluated_at_unix=150,
                timeout_seconds=30,
            )
            catalog_source = root / "catalog-generation.json"
            catalog_source.write_bytes(_render(catalog_bundle))
            catalog_output = root / "catalog-handoff.zip"
            catalog_manifest = handoff_circuit_generation(
                catalog_source,
                catalog_output,
                str(binary_path),
                timeout_seconds=30,
            )
            self.assertTrue(catalog_manifest["approved"])
            self.assertTrue(catalog_output.is_file())


if __name__ == "__main__":
    unittest.main()
