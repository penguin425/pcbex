from __future__ import annotations

import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent.tests.test_circuit_handoff_bundle_v1448 import (
    _bundle,
    _catalog_snapshot,
    _render,
    _replace_native_check,
    _spec,
    _write_fake_pcbex,
)
from agent.tests.test_circuit_handoff_bundle_v1449 import (
    _archive_entries,
    _canonical,
    _rebind_manifest,
)
from pcbex_agent import cli
from pcbex_agent import circuit_handoff_bundle as handoff_module
from pcbex_agent.catalog import select_catalog_parts, validate_catalog_receipt
from pcbex_agent.circuit_generation import (
    _compact_json,
    generate_circuit_with_llm,
)
from pcbex_agent.circuit_handoff_bundle import (
    CircuitHandoffBundleError,
    build_circuit_handoff_archive,
    circuit_handoff_bundle_replay_result_json_schema,
    circuit_handoff_bundle_result_json_schema,
    handoff_circuit_generation,
    replay_circuit_handoff_bundle,
    validate_circuit_handoff_archive,
    verify_circuit_handoff_bundle,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _valid_archive_with_command(
    root: Path,
    *,
    catalog: bool = False,
) -> tuple[bytes, dict[str, object], list[str], dict[str, object] | None]:
    if not catalog:
        bundle = _bundle()
        initial_check = None
    else:
        bundle, initial_check = _catalog_generation_bundle()
    command = _write_fake_pcbex(
        root,
        bundle["check"],
        initial_check=initial_check,
    )
    archive, manifest = build_circuit_handoff_archive(
        _render(bundle),
        command,
    )
    return archive, manifest, command, initial_check


def _catalog_generation_bundle() -> tuple[dict[str, object], dict[str, object]]:
    initial = _spec()

    def envelope(spec: dict[str, object]) -> dict[str, object]:
        review = {
            "schema_version": 1,
            "schematic_sha256": "1" * 64,
            "policy_sha256": "2" * 64,
            "policy_id": "pcbex-electrical-default-v1",
            "approved": True,
            "counts": {"errors": 0, "warnings": 0, "info": 0},
            "findings": [],
        }
        return {
            "schema_version": 1,
            "circuit_spec_sha256": _sha(_compact_json(spec)),
            "electrical_review_sha256": _sha(_compact_json(review)),
            "normalized_spec": spec,
            "electrical_review": review,
        }

    def checker(path: Path, _remaining: float) -> dict[str, object]:
        if Path(path).name.startswith("candidate-"):
            return envelope(initial)
        return envelope(json.loads(Path(path).read_text(encoding="utf-8")))

    def selector(spec: dict[str, object], _remaining: float):
        return select_catalog_parts(spec, _catalog_snapshot(), evaluated_at_unix=150)

    def receipt_validator(
        original: dict[str, object],
        resolved: dict[str, object],
        receipt: dict[str, object],
        _remaining: float,
    ) -> None:
        validate_catalog_receipt(
            receipt,
            original,
            resolved,
            _catalog_snapshot(),
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
    return bundle, envelope(initial)


class CircuitHandoffBundleV1450Tests(unittest.TestCase):
    def test_replays_non_catalog_bundle_and_reports_closed_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, manifest, command, _initial_check = _valid_archive_with_command(root)
            archive = root / "handoff.zip"
            archive.write_bytes(raw)

            result = replay_circuit_handoff_bundle(
                archive,
                command,
                expected_archive_sha256=_sha(raw),
                expected_bundle_sha256=manifest["bundle_sha256"],
            )

        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["operation"], "replay")
        self.assertTrue(result["replayed"])
        self.assertNotIn("extracted", result)
        self.assertTrue(result["verified"])
        self.assertEqual(
            result["validation"],
            {
                "internal_consistency": True,
                "expected_identity_matched": True,
                "archive_reproduced": True,
                "native_handoff_replayed": True,
                "catalog_input_erc_required": False,
                "catalog_input_erc_replayed": False,
                "native_kicad_erc_replayed": False,
            },
        )
        self.assertEqual(result["bundle_sha256"], manifest["bundle_sha256"])

    def test_replays_catalog_bundle_and_replays_initial_erc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, manifest, command, initial_check = _valid_archive_with_command(
                root,
                catalog=True,
            )
            archive = root / "catalog-handoff.zip"
            archive.write_bytes(raw)

            result = replay_circuit_handoff_bundle(
                archive,
                command,
                expected_archive_sha256=_sha(raw),
                expected_bundle_sha256=manifest["bundle_sha256"],
            )

        self.assertIsNotNone(initial_check)
        self.assertTrue(result["validation"]["catalog_input_erc_required"])
        self.assertTrue(result["validation"]["catalog_input_erc_replayed"])
        self.assertTrue(result["validation"]["native_handoff_replayed"])

    def test_replay_result_schema_is_closed_and_accepts_success(self) -> None:
        schema = circuit_handoff_bundle_replay_result_json_schema()
        self.assertTrue(schema["additionalProperties"] is False)
        self.assertEqual(
            schema["$id"],
            "https://github.com/penguin425/pcbex/schemas/"
            "circuit-generation-kicad-handoff-bundle-replay-result-v1.json",
        )
        self.assertEqual(schema["properties"]["operation"], {"const": "replay"})
        self.assertEqual(schema["properties"]["replayed"], {"const": True})
        self.assertTrue(schema["properties"]["validation"]["additionalProperties"] is False)

        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional local dependency
            return

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, manifest, command, _initial_check = _valid_archive_with_command(root)
            archive = root / "handoff.zip"
            archive.write_bytes(raw)
            result = replay_circuit_handoff_bundle(
                archive,
                command,
                expected_archive_sha256=_sha(raw),
                expected_bundle_sha256=manifest["bundle_sha256"],
            )
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(result)), [])

    def test_expected_root_mismatch_is_rejected_before_child_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, manifest, _command, _initial_check = _valid_archive_with_command(root)
            archive = root / "handoff.zip"
            archive.write_bytes(raw)
            marker = root / "spawned"
            child = root / "must-not-run.py"
            child.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('spawned', encoding='utf-8')\n",
                encoding="utf-8",
            )
            command = [sys.executable, str(child)]

            for option, value in (
                ("archive", "f" * 64),
                ("bundle", "e" * 64),
            ):
                kwargs = {
                    "expected_archive_sha256": None,
                    "expected_bundle_sha256": None,
                }
                if option == "archive":
                    kwargs["expected_archive_sha256"] = value
                else:
                    kwargs["expected_bundle_sha256"] = value
                with self.subTest(expected_root=option), self.assertRaises(
                    CircuitHandoffBundleError
                ):
                    replay_circuit_handoff_bundle(archive, command, **kwargs)
                self.assertFalse(marker.exists())

    def test_forged_self_consistent_archive_fails_fresh_reproduction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, _manifest, command, _initial_check = _valid_archive_with_command(root)
            entries = _archive_entries(raw)
            schematic = b"not a KiCad schematic\n"
            entries[handoff_module.SCHEMATIC_NAME] = schematic
            report = json.loads(entries[handoff_module.HANDOFF_REPORT_NAME])
            report["schematic_source_bytes"] = len(schematic)
            report["schematic_source_sha256"] = _sha(schematic)
            report["schematic_sha256"] = _sha(schematic)
            report["schematic_review"]["schematic_sha256"] = _sha(schematic)
            entries[handoff_module.HANDOFF_REPORT_NAME] = _render(report)
            _rebind_manifest(entries)
            forged = _canonical(entries)
            archive = root / "forged.zip"
            archive.write_bytes(forged)

            # The offline v1 consumer intentionally accepts this as an
            # internally consistent archive; replay must not.
            offline, _ = validate_circuit_handoff_archive(forged)
            self.assertTrue(offline["validation"]["internal_consistency"])
            with self.assertRaisesRegex(
                CircuitHandoffBundleError,
                "fresh handoff-chain replay did not reproduce",
            ):
                replay_circuit_handoff_bundle(archive, command)

    def test_native_reproduction_failure_is_typed_and_does_not_publish(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, _manifest, _command, _initial_check = _valid_archive_with_command(root)
            archive = root / "handoff.zip"
            archive.write_bytes(raw)
            failing = _write_fake_pcbex(
                root,
                _bundle()["check"],
                fail="write-circuit-spec-kicad-schematic",
            )
            with self.assertRaisesRegex(
                CircuitHandoffBundleError,
                "native KiCad schematic writer rejected the handoff",
            ):
                replay_circuit_handoff_bundle(archive, failing)
            self.assertTrue(archive.is_file())
            self.assertEqual(archive.read_bytes(), raw)

    def test_timeout_expires_before_native_child_and_preserves_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, _manifest, command, _initial_check = _valid_archive_with_command(root)
            archive = root / "handoff.zip"
            archive.write_bytes(raw)
            ticks = iter((0.0, 2.0))
            with self.assertRaises(CircuitHandoffBundleError):
                replay_circuit_handoff_bundle(
                    archive,
                    command,
                    timeout_seconds=1.0,
                    _clock=lambda: next(ticks),
                )
            self.assertEqual(archive.read_bytes(), raw)

    def test_offline_v1449_result_and_schema_remain_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, manifest, _command, _initial_check = _valid_archive_with_command(root)
            archive = root / "handoff.zip"
            archive.write_bytes(raw)
            result = verify_circuit_handoff_bundle(
                archive,
                expected_archive_sha256=_sha(raw),
                expected_bundle_sha256=manifest["bundle_sha256"],
            )

        self.assertEqual(result["operation"], "verify")
        self.assertFalse(result["extracted"])
        self.assertEqual(
            result["validation"],
            {
                "internal_consistency": True,
                "expected_identity_matched": True,
                "native_handoff_replayed": False,
                "catalog_input_erc_replayed": False,
            },
        )
        self.assertNotIn("replayed", result)
        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional local dependency
            return
        self.assertEqual(
            list(
                Draft202012Validator(circuit_handoff_bundle_result_json_schema()).iter_errors(
                    result
                )
            ),
            [],
        )

    def test_cli_routes_replay_and_writes_replay_schema(self) -> None:
        result = {
            "schema_version": 1,
            "operation": "replay",
            "replayed": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive = root / "handoff.zip"
            schema_path = root / "replay-schema.json"
            stdout = io.StringIO()
            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "replay-circuit-handoff-bundle",
                    str(archive),
                    "--pcbex",
                    "native-pcbex",
                    "--timeout-seconds",
                    "42",
                    "--expected-archive-sha256",
                    "a" * 64,
                    "--expected-bundle-sha256",
                    "b" * 64,
                ],
            ), mock.patch.object(
                cli,
                "replay_circuit_handoff_bundle",
                return_value=result,
            ) as replay, redirect_stdout(stdout):
                cli.main()
            replay.assert_called_once_with(
                Path(archive),
                "native-pcbex",
                timeout_seconds=42.0,
                expected_archive_sha256="a" * 64,
                expected_bundle_sha256="b" * 64,
            )
            self.assertEqual(json.loads(stdout.getvalue()), result)

            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "circuit-handoff-bundle-replay-result-schema",
                    "--output",
                    str(schema_path),
                ],
            ):
                cli.main()
            self.assertEqual(
                json.loads(schema_path.read_text(encoding="utf-8")),
                circuit_handoff_bundle_replay_result_json_schema(),
            )

    def test_real_rust_handoff_chain_replays_when_binary_is_supplied(self) -> None:
        binary = os.environ.get("PCBEX_TEST_BINARY")
        if not binary:
            self.skipTest("PCBEX_TEST_BINARY is not set")
        binary_path = Path(binary).resolve()
        if not binary_path.is_file():
            self.fail("PCBEX_TEST_BINARY does not name a regular file")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            spec_path = root / "spec.json"
            spec_path.write_bytes(_render(_spec()))
            native = subprocess.run(
                [str(binary_path), "check-circuit-spec", str(spec_path)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
            generation = _replace_native_check(_bundle(), json.loads(native.stdout))
            source = root / "generation.json"
            source.write_bytes(_render(generation))
            archive_path = root / "handoff.zip"
            manifest = handoff_circuit_generation(
                source,
                archive_path,
                str(binary_path),
                timeout_seconds=30,
            )
            archive_raw = archive_path.read_bytes()
            result = replay_circuit_handoff_bundle(
                archive_path,
                str(binary_path),
                timeout_seconds=30,
                expected_archive_sha256=_sha(archive_raw),
                expected_bundle_sha256=manifest["bundle_sha256"],
            )
        self.assertTrue(result["replayed"])
        self.assertTrue(result["validation"]["archive_reproduced"])
        self.assertTrue(result["validation"]["native_handoff_replayed"])
        self.assertFalse(result["validation"]["native_kicad_erc_replayed"])


if __name__ == "__main__":
    unittest.main()
