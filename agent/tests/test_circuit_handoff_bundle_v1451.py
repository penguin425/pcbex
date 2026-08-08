from __future__ import annotations

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
    _render,
    _replace_native_check,
    _spec,
)
from agent.tests.test_circuit_handoff_bundle_v1449 import _archive_entries
from agent.tests.test_circuit_handoff_bundle_v1450 import _valid_archive_with_command
from pcbex_agent import cli
from pcbex_agent import circuit_handoff_bundle as handoff_module
from pcbex_agent.circuit_handoff_bundle import (
    CircuitHandoffBundleError,
    circuit_handoff_bundle_native_erc_replay_result_json_schema,
    handoff_circuit_generation,
    replay_circuit_handoff_bundle,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_native_wrapper(
    root: Path,
    base_command: list[str],
    **configuration: object,
) -> list[str]:
    (root / "base-command.json").write_text(
        json.dumps(base_command),
        encoding="utf-8",
    )
    (root / "native-configuration.json").write_text(
        json.dumps(configuration),
        encoding="utf-8",
    )
    wrapper = root / "fake_pcbex_native.py"
    wrapper.write_text(
        """from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import time

root = Path(__file__).parent
base = json.loads((root / "base-command.json").read_text(encoding="utf-8"))
configuration = json.loads(
    (root / "native-configuration.json").read_text(encoding="utf-8")
)
if sys.argv[1] != "verify-native-kicad-erc-report":
    os.execv(base[0], [*base, *sys.argv[1:]])

(root / "native-invocation.json").write_text(
    json.dumps(sys.argv[1:]),
    encoding="utf-8",
)
time.sleep(float(configuration.get("sleep_seconds", 0)))
separator = sys.argv.index("--")
schematic_path = Path(sys.argv[separator + 1])
report_path = Path(sys.argv[separator + 2])
schematic_raw = schematic_path.read_bytes()
report_raw = report_path.read_bytes()
report = json.loads(report_raw)
if report.get("test_source_sha256") != hashlib.sha256(schematic_raw).hexdigest():
    raise SystemExit(7)

policy_argument = next(
    (value for value in sys.argv[2:separator] if value.startswith("--warning-policy=")),
    None,
)
schema_version = int(configuration.get("schema_version", 1))
if (schema_version == 2) != (policy_argument is not None):
    raise SystemExit(8)
approved = bool(configuration.get("approved", True))
error_count = int(configuration.get("error_count", 0 if approved else 1))
policy_failure_count = int(
    configuration.get("policy_failure_count", 0 if approved else 1)
)
if "--require-approved" in sys.argv and not approved:
    raise SystemExit(9)

summary = {
    "schema_version": schema_version,
    "approved": approved,
    "error_count": error_count,
    "run_sha256": "c" * 64,
    "report_bytes": len(report_raw),
    "report_sha256": hashlib.sha256(report_raw).hexdigest(),
}
if configuration.get("forge_report_sha256"):
    summary["report_sha256"] = "f" * 64
if schema_version == 2:
    policy_path = Path(policy_argument.split("=", 1)[1])
    policy_raw = policy_path.read_bytes()
    summary.update(
        warning_count=int(configuration.get("warning_count", 0)),
        policy_failure_count=policy_failure_count,
        warning_policy_sha256="d" * 64,
        warning_policy_source_bytes=len(policy_raw),
        warning_policy_source_sha256=hashlib.sha256(policy_raw).hexdigest(),
    )
mutation = configuration.get("mutate_path")
if mutation:
    Path(mutation).write_bytes(b"changed during native replay\\n")
print(json.dumps(summary, separators=(",", ":")))
""",
        encoding="utf-8",
    )
    return [sys.executable, str(wrapper)]


def _retained_report(schematic_raw: bytes) -> bytes:
    return _render({"test_source_sha256": _sha(schematic_raw)})


class CircuitHandoffBundleV1451Tests(unittest.TestCase):
    def test_omitted_report_preserves_exact_v1450_result_and_skips_kicad(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, manifest, base, _initial = _valid_archive_with_command(root)
            command = _write_native_wrapper(root, base, schema_version=1)
            archive = root / "handoff.zip"
            archive.write_bytes(raw)
            result = replay_circuit_handoff_bundle(archive, command)
            self.assertFalse((root / "native-invocation.json").exists())

        manifest_raw = _archive_entries(raw)[handoff_module.MANIFEST_NAME]
        self.assertEqual(
            result,
            {
                "schema_version": 1,
                "operation": "replay",
                "verified": True,
                "replayed": True,
                "verification_scope": handoff_module.CIRCUIT_HANDOFF_BUNDLE_REPLAY_SCOPE,
                "archive": {"bytes": len(raw), "sha256": _sha(raw)},
                "manifest": {
                    "name": handoff_module.MANIFEST_NAME,
                    "bytes": len(manifest_raw),
                    "sha256": _sha(manifest_raw),
                },
                "expected": {
                    "archive_sha256": None,
                    "bundle_sha256": None,
                },
                "validation": {
                    "internal_consistency": True,
                    "expected_identity_matched": False,
                    "archive_reproduced": True,
                    "native_handoff_replayed": True,
                    "catalog_input_erc_required": False,
                    "catalog_input_erc_replayed": False,
                    "native_kicad_erc_replayed": False,
                },
                "adapter": manifest["adapter"],
                "engine_version": manifest["engine_version"],
                "bundle_sha256": manifest["bundle_sha256"],
                "artifacts": manifest["artifacts"],
            },
        )

    def test_v1_native_erc_replay_returns_closed_path_free_v2_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(raw)[handoff_module.SCHEMATIC_NAME]
            report_raw = _retained_report(schematic_raw)
            archive = root / "handoff.zip"
            report = root / "native-erc.json"
            archive.write_bytes(raw)
            report.write_bytes(report_raw)
            command = _write_native_wrapper(root, base, schema_version=1)
            kicad_command = "--literal KiCad ; executable"

            result = replay_circuit_handoff_bundle(
                archive,
                command,
                retained_native_kicad_erc_report=report,
                kicad_cli=kicad_command,
                require_native_kicad_erc_approved=True,
                timeout_seconds=30,
                expected_archive_sha256=_sha(raw),
                expected_bundle_sha256=manifest["bundle_sha256"],
            )
            invocation = json.loads(
                (root / "native-invocation.json").read_text(encoding="utf-8")
            )

            self.assertEqual(archive.read_bytes(), raw)
            self.assertEqual(report.read_bytes(), report_raw)

        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(
            result["verification_scope"],
            handoff_module.CIRCUIT_HANDOFF_BUNDLE_NATIVE_ERC_REPLAY_SCOPE,
        )
        self.assertTrue(result["validation"]["native_kicad_erc_replayed"])
        self.assertEqual(
            result["native_kicad_erc"],
            {
                "schema_version": 1,
                "approved": True,
                "approval_required": True,
                "error_count": 0,
                "warning_count": None,
                "policy_failure_count": None,
                "run_sha256": "c" * 64,
                "report": {"bytes": len(report_raw), "sha256": _sha(report_raw)},
                "warning_policy": None,
            },
        )
        self.assertIn("--require-approved", invocation)
        self.assertIn("--mcp-echo-report-summary", invocation)
        timeout_argument = next(
            value for value in invocation if value.startswith("--timeout-seconds=")
        )
        self.assertGreater(float(timeout_argument.split("=", 1)[1]), 0)
        self.assertLess(float(timeout_argument.split("=", 1)[1]), 30)
        self.assertEqual(invocation[-3], "--")
        self.assertIn(f"--kicad-cli={kicad_command}", invocation)

        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional local dependency
            return
        schema = circuit_handoff_bundle_native_erc_replay_result_json_schema()
        self.assertEqual(
            schema["$id"],
            "https://github.com/penguin425/pcbex/schemas/"
            "circuit-generation-kicad-handoff-bundle-native-erc-replay-result-v2.json",
        )
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(result)), [])

    def test_v2_warning_policy_identity_is_retained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            report = root / "--native erc v2.json"
            policy = root / "--warning policy.json"
            archive.write_bytes(raw)
            report.write_bytes(_retained_report(schematic_raw))
            policy_raw = b'{"schema_version":1,"id":"strict"}\n'
            policy.write_bytes(policy_raw)
            command = _write_native_wrapper(
                root,
                base,
                schema_version=2,
                warning_count=3,
            )

            result = replay_circuit_handoff_bundle(
                archive,
                command,
                retained_native_kicad_erc_report=report,
                native_kicad_erc_warning_policy=policy,
            )

            rejected_command = _write_native_wrapper(
                root,
                base,
                schema_version=2,
                approved=False,
                error_count=0,
                warning_count=3,
                policy_failure_count=2,
            )
            rejected = replay_circuit_handoff_bundle(
                archive,
                rejected_command,
                retained_native_kicad_erc_report=report,
                native_kicad_erc_warning_policy=policy,
            )
            with self.assertRaises(CircuitHandoffBundleError):
                replay_circuit_handoff_bundle(
                    archive,
                    rejected_command,
                    retained_native_kicad_erc_report=report,
                    native_kicad_erc_warning_policy=policy,
                    require_native_kicad_erc_approved=True,
                )

        evidence = result["native_kicad_erc"]
        self.assertEqual(evidence["schema_version"], 2)
        self.assertEqual(evidence["warning_count"], 3)
        self.assertEqual(evidence["policy_failure_count"], 0)
        self.assertEqual(
            evidence["warning_policy"],
            {
                "source": {"bytes": len(policy_raw), "sha256": _sha(policy_raw)},
                "policy_sha256": "d" * 64,
            },
        )
        self.assertFalse(rejected["native_kicad_erc"]["approved"])
        self.assertEqual(rejected["native_kicad_erc"]["error_count"], 0)
        self.assertEqual(rejected["native_kicad_erc"]["policy_failure_count"], 2)

    def test_native_options_without_report_fail_before_any_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, _manifest, _base, _initial = _valid_archive_with_command(root)
            archive = root / "handoff.zip"
            policy = root / "policy.json"
            marker = root / "spawned"
            child = root / "child.py"
            archive.write_bytes(raw)
            policy.write_text("{}\n", encoding="utf-8")
            child.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('spawned', encoding='utf-8')\n",
                encoding="utf-8",
            )
            command = [sys.executable, str(child)]

            for kwargs in (
                {"native_kicad_erc_warning_policy": policy},
                {"require_native_kicad_erc_approved": True},
                {"require_native_kicad_erc_approved": 1},
                {"kicad_cli": "custom-kicad-cli"},
            ):
                with self.subTest(kwargs=kwargs), self.assertRaises(
                    CircuitHandoffBundleError
                ):
                    replay_circuit_handoff_bundle(archive, command, **kwargs)
            self.assertFalse(marker.exists())

            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "replay-circuit-handoff-bundle",
                    str(archive),
                    "--kicad-cli",
                    "custom-kicad-cli",
                ],
            ), self.assertRaisesRegex(
                SystemExit,
                "native KiCad ERC options require a retained report",
            ):
                cli.main()
            self.assertFalse(marker.exists())

    def test_oversized_native_sidecars_fail_before_any_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            report = root / "native-erc.json"
            policy = root / "warning-policy.json"
            archive.write_bytes(raw)
            command = _write_native_wrapper(root, base, schema_version=1)

            with report.open("wb") as stream:
                stream.truncate(
                    handoff_module.MAX_NATIVE_KICAD_ERC_REPORT_BYTES + 1
                )
            with mock.patch.object(handoff_module, "_run_native") as run_native:
                with self.assertRaises(CircuitHandoffBundleError):
                    replay_circuit_handoff_bundle(
                        archive,
                        command,
                        retained_native_kicad_erc_report=report,
                    )
                run_native.assert_not_called()

            report.write_bytes(_retained_report(schematic_raw))
            with policy.open("wb") as stream:
                stream.truncate(
                    handoff_module.MAX_NATIVE_KICAD_ERC_WARNING_POLICY_BYTES + 1
                )
            with mock.patch.object(handoff_module, "_run_native") as run_native:
                with self.assertRaises(CircuitHandoffBundleError):
                    replay_circuit_handoff_bundle(
                        archive,
                        command,
                        retained_native_kicad_erc_report=report,
                        native_kicad_erc_warning_policy=policy,
                    )
                run_native.assert_not_called()

    def test_report_schema_and_warning_policy_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            report = root / "native-erc.json"
            policy = root / "warning-policy.json"
            archive.write_bytes(raw)
            report.write_bytes(_retained_report(schematic_raw))
            policy.write_text('{"schema_version":1}\n', encoding="utf-8")

            for label, schema_version, replay_options in (
                ("v2-without-policy", 2, {}),
                (
                    "v1-with-policy",
                    1,
                    {"native_kicad_erc_warning_policy": policy},
                ),
            ):
                command = _write_native_wrapper(
                    root,
                    base,
                    schema_version=schema_version,
                )
                with self.subTest(label=label), self.assertRaises(
                    CircuitHandoffBundleError
                ):
                    replay_circuit_handoff_bundle(
                        archive,
                        command,
                        retained_native_kicad_erc_report=report,
                        **replay_options,
                    )

    def test_forged_summary_and_stale_schematic_binding_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            report = root / "native-erc.json"
            archive.write_bytes(raw)

            for label, report_raw, configuration in (
                (
                    "forged-summary",
                    _retained_report(schematic_raw),
                    {"schema_version": 1, "forge_report_sha256": True},
                ),
                (
                    "stale-source",
                    _retained_report(b"different schematic"),
                    {"schema_version": 1},
                ),
            ):
                report.write_bytes(report_raw)
                command = _write_native_wrapper(root, base, **configuration)
                with self.subTest(label=label), self.assertRaises(
                    CircuitHandoffBundleError
                ):
                    replay_circuit_handoff_bundle(
                        archive,
                        command,
                        retained_native_kicad_erc_report=report,
                    )
                self.assertEqual(archive.read_bytes(), raw)

    def test_rejected_evidence_is_visible_and_optional_approval_gate_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            report = root / "native-erc-rejected.json"
            archive.write_bytes(raw)
            report.write_bytes(_retained_report(schematic_raw))
            command = _write_native_wrapper(
                root,
                base,
                schema_version=1,
                approved=False,
                error_count=1,
            )

            result = replay_circuit_handoff_bundle(
                archive,
                command,
                retained_native_kicad_erc_report=report,
            )
            self.assertFalse(result["native_kicad_erc"]["approved"])
            self.assertFalse(result["native_kicad_erc"]["approval_required"])

            with self.assertRaises(CircuitHandoffBundleError):
                replay_circuit_handoff_bundle(
                    archive,
                    command,
                    retained_native_kicad_erc_report=report,
                    require_native_kicad_erc_approved=True,
                )

    def test_caller_sidecar_mutation_during_native_replay_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            report = root / "native-erc.json"
            policy = root / "warning-policy.json"
            archive.write_bytes(raw)
            for label, schema_version, mutation, replay_options in (
                ("report", 1, report, {}),
                (
                    "warning-policy",
                    2,
                    policy,
                    {"native_kicad_erc_warning_policy": policy},
                ),
            ):
                report.write_bytes(_retained_report(schematic_raw))
                policy.write_text('{"schema_version":1}\n', encoding="utf-8")
                command = _write_native_wrapper(
                    root,
                    base,
                    schema_version=schema_version,
                    mutate_path=str(mutation),
                )
                with self.subTest(label=label), self.assertRaisesRegex(
                    CircuitHandoffBundleError,
                    "changed during replay",
                ):
                    replay_circuit_handoff_bundle(
                        archive,
                        command,
                        retained_native_kicad_erc_report=report,
                        **replay_options,
                    )
            self.assertEqual(archive.read_bytes(), raw)

    def test_native_child_timeout_uses_same_aggregate_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            raw, _manifest, base, _initial = _valid_archive_with_command(root)
            schematic_raw = _archive_entries(raw)[handoff_module.SCHEMATIC_NAME]
            archive = root / "handoff.zip"
            report = root / "native-erc.json"
            archive.write_bytes(raw)
            report.write_bytes(_retained_report(schematic_raw))
            command = _write_native_wrapper(
                root,
                base,
                schema_version=1,
                sleep_seconds=5,
            )

            with self.assertRaises(CircuitHandoffBundleError):
                replay_circuit_handoff_bundle(
                    archive,
                    command,
                    retained_native_kicad_erc_report=report,
                    timeout_seconds=1.5,
                )
            self.assertEqual(archive.read_bytes(), raw)

    def test_cli_routes_native_inputs_and_writes_v2_schema(self) -> None:
        result = {"schema_version": 2, "operation": "replay", "replayed": True}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            archive = root / "handoff.zip"
            report = root / "erc.json"
            policy = root / "policy.json"
            schema_path = root / "native-replay-schema.json"
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
                    "--native-kicad-erc-report",
                    str(report),
                    "--native-kicad-erc-warning-policy",
                    str(policy),
                    "--kicad-cli=--native KiCad cli",
                    "--require-native-kicad-erc-approved",
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
                retained_native_kicad_erc_report=Path(report),
                kicad_cli="--native KiCad cli",
                native_kicad_erc_warning_policy=Path(policy),
                require_native_kicad_erc_approved=True,
                timeout_seconds=120.0,
                expected_archive_sha256=None,
                expected_bundle_sha256=None,
            )
            self.assertEqual(json.loads(stdout.getvalue()), result)

            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "circuit-handoff-bundle-native-erc-replay-result-schema",
                    "--output",
                    str(schema_path),
                ],
            ):
                cli.main()
            self.assertEqual(
                json.loads(schema_path.read_text(encoding="utf-8")),
                circuit_handoff_bundle_native_erc_replay_result_json_schema(),
            )

    def test_real_rust_and_kicad_replay_when_binary_is_supplied(self) -> None:
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
            archive = root / "handoff.zip"
            manifest = handoff_circuit_generation(
                source,
                archive,
                str(binary_path),
                timeout_seconds=30,
            )
            archive_raw = archive.read_bytes()
            schematic = root / "replayed.kicad_sch"
            schematic.write_bytes(
                _archive_entries(archive_raw)[handoff_module.SCHEMATIC_NAME]
            )
            report = root / "native-erc.json"
            subprocess.run(
                [
                    str(binary_path),
                    "run-native-kicad-erc",
                    str(schematic),
                    "--output",
                    str(report),
                    "--require-approved",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )

            result = replay_circuit_handoff_bundle(
                archive,
                str(binary_path),
                retained_native_kicad_erc_report=report,
                kicad_cli="kicad-cli",
                require_native_kicad_erc_approved=True,
                timeout_seconds=60,
                expected_archive_sha256=_sha(archive_raw),
                expected_bundle_sha256=manifest["bundle_sha256"],
            )

        self.assertTrue(result["validation"]["native_kicad_erc_replayed"])
        self.assertTrue(result["native_kicad_erc"]["approved"])
        self.assertEqual(result["native_kicad_erc"]["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()
