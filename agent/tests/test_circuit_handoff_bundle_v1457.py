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

try:
    from jsonschema import Draft202012Validator
except ImportError:  # Optional in the minimal macOS/Windows boundary environment.
    Draft202012Validator = None

from agent.tests.test_circuit_handoff_bundle_v1454 import (
    _board_case,
    _board_case_from_archive,
    _board_kwargs,
    _write_board_wrapper,
)
from agent.tests.test_circuit_handoff_bundle_v1449 import _archive_entries
from agent.tests.test_circuit_handoff_bundle_v1451 import (
    _retained_report,
    _write_native_wrapper,
)
from agent.tests.test_circuit_handoff_bundle_v1452 import (
    _write_ai_inputs,
    _write_ai_wrapper,
)
from agent.tests.test_circuit_handoff_bundle_v1453 import (
    _catalog_artifacts,
    _catalog_kwargs,
)
from pcbex_agent import cli
from pcbex_agent import circuit_handoff_bundle as handoff_module
from pcbex_agent import manufacturing_replay as manufacturing_module
from pcbex_agent.circuit_handoff_bundle import (
    CircuitHandoffBundleError,
    circuit_handoff_bundle_manufacturing_replay_result_json_schema,
    replay_circuit_handoff_bundle,
)


SCHEMA_COMMAND = "circuit-handoff-bundle-manufacturing-replay-result-schema"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_manufacturing_wrapper(
    root: Path,
    base_command: list[str],
    package_raw: bytes,
    **configuration: object,
) -> list[str]:
    (root / "manufacturing-base-command.json").write_text(
        json.dumps(base_command), encoding="utf-8"
    )
    (root / "manufacturing-config.json").write_text(
        json.dumps(configuration), encoding="utf-8"
    )
    (root / "manufacturing-package.bin").write_bytes(package_raw)
    wrapper = root / "fake-composed-manufacturing.py"
    wrapper.write_text(
        r'''from __future__ import annotations
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).parent
base = json.loads((root / "manufacturing-base-command.json").read_text(encoding="utf-8"))
config = json.loads((root / "manufacturing-config.json").read_text(encoding="utf-8"))
argv = sys.argv[1:]
if not argv or argv[0] != "fabricate":
    completed = subprocess.run([*base, *argv], check=False)
    raise SystemExit(completed.returncode)

(root / "manufacturing-invocation.json").write_text(
    json.dumps(argv), encoding="utf-8"
)

def option(name: str) -> str | None:
    prefix = "--" + name + "="
    for index, value in enumerate(argv):
        if value.startswith(prefix):
            return value[len(prefix):]
        if value == "--" + name and index + 1 < len(argv):
            return argv[index + 1]
    return None

board = Path(argv[1])
output = Path(option("output-dir"))
output.mkdir()
(root / "manufacturing-board.bin").write_bytes(board.read_bytes())
package = (root / "manufacturing-package.bin").read_bytes()
if config.get("mismatch"):
    package += b"mismatch"
fresh = output / "manufacturing.zip"
if config.get("symlink_output"):
    target = root / "manufacturing-symlink-target.bin"
    target.write_bytes(package)
    fresh.symlink_to(target)
else:
    fresh.write_bytes(package)

for raw_path in config.get("mutate_paths", []):
    path = Path(raw_path)
    raw = path.read_bytes()
    if config.get("same_size_mutation") and raw:
        path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
    else:
        path.write_bytes(raw + b"changed")
if config.get("mutate_staged_board"):
    raw = board.read_bytes()
    board.write_bytes(raw + b"changed")
raise SystemExit(int(config.get("returncode", 0)))
''',
        encoding="utf-8",
    )
    return [sys.executable, str(wrapper)]


def _case(
    root: Path,
    *,
    approved: bool = True,
    package_raw: bytes = b"PK\x03\x04v1457-manufacturing-package",
    **configuration: object,
) -> tuple[dict[str, object], Path, bytes, list[str]]:
    case = _board_case(root, approved=approved)
    package = root / "retained-manufacturing.zip"
    package.write_bytes(package_raw)
    board_command = _write_board_wrapper(
        root,
        case["base"],
        case["report_raw"],
        approved=approved,
    )
    command = _write_manufacturing_wrapper(
        root,
        board_command,
        package_raw,
        **configuration,
    )
    return case, package, package_raw, command


def _options(
    case: dict[str, object],
    package: Path,
    **overrides: object,
) -> dict[str, object]:
    options = {
        **_board_kwargs(case),
        "retained_manufacturing_package": package,
    }
    options.update(overrides)
    return options


def _captured_result(
    capture: manufacturing_module._ManufacturingReplayCapture,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "verification_scope": "manufacturing-package-fresh-replay-v1",
        "verified": True,
        "board": {"name": capture.board_name, **capture.board_identity},
        "project": capture.project_identity,
        "rules": capture.rules_identity,
        "profile": {"kind": "none"},
        "package": {
            "retained": capture.retained_identity,
            "fresh": capture.retained_identity,
            "identical": True,
        },
        "validation": {
            "inputs_captured": True,
            "package_reproduced": True,
            "staged_inputs_unchanged": True,
            "caller_inputs_unchanged": True,
        },
    }


class CircuitHandoffBundleV1457Tests(unittest.TestCase):
    def test_same_captured_board_produces_closed_schema_valid_v6(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case, package, package_raw, command = _case(root)
            result = replay_circuit_handoff_bundle(
                case["archive"],
                command,
                **_options(case, package),
            )
            invocation = json.loads(
                (root / "manufacturing-invocation.json").read_text(encoding="utf-8")
            )
            manufactured_board = (root / "manufacturing-board.bin").read_bytes()
            root_text = str(root)

        self.assertEqual(result["schema_version"], 6)
        self.assertEqual(
            result["verification_scope"],
            handoff_module.CIRCUIT_HANDOFF_BUNDLE_MANUFACTURING_REPLAY_SCOPE,
        )
        self.assertTrue(result["validation"]["board_binding_replayed"])
        self.assertTrue(result["validation"]["manufacturing_package_replayed"])
        self.assertTrue(
            result["validation"]["manufacturing_board_identity_matched"]
        )
        manufacturing = result["manufacturing_package"]
        self.assertEqual(manufactured_board, case["board_raw"])
        self.assertEqual(
            manufacturing["board"]["sha256"],
            result["board_binding"]["board"]["sha256"],
        )
        self.assertEqual(
            manufacturing["board"]["bytes"],
            result["board_binding"]["board"]["bytes"],
        )
        self.assertEqual(
            manufacturing["package"]["retained"],
            {"bytes": len(package_raw), "sha256": _sha(package_raw)},
        )
        self.assertTrue(manufacturing["package"]["identical"])
        self.assertIn("--outer-process-tree-supervised", invocation)
        self.assertTrue(
            any(value.startswith("--kicad-cli=kicad-cli") for value in invocation)
        )
        self.assertNotIn(root_text, json.dumps(result))
        schema = circuit_handoff_bundle_manufacturing_replay_result_json_schema()
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("board_binding", schema["required"])
        self.assertIn("manufacturing_package", schema["required"])
        validation_schema = schema["properties"]["validation"]
        self.assertFalse(validation_schema["additionalProperties"])
        for flag in (
            "manufacturing_package_replayed",
            "manufacturing_board_identity_matched",
        ):
            self.assertIn(flag, validation_schema["required"])
            self.assertEqual(validation_schema["properties"][flag], {"const": True})
        manufacturing_schema = schema["properties"]["manufacturing_package"]
        self.assertFalse(manufacturing_schema["additionalProperties"])
        if Draft202012Validator is not None:
            self.assertEqual(
                list(Draft202012Validator(schema).iter_errors(result)), []
            )

    def test_manufacturing_requires_complete_v5_and_preflights_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case, package, _package_raw, command = _case(root)
            incomplete = (
                {"retained_manufacturing_package": package},
                {
                    "kicad_board": case["board"],
                    "retained_manufacturing_package": package,
                },
                {
                    **_board_kwargs(case),
                    "manufacturing_kicad_project": root / "project.json",
                },
                {
                    **_board_kwargs(case),
                    "manufacturing_kicad_cli": "kicad-cli",
                },
                {
                    **_options(case, package),
                    "manufacturing_fab": "jlcpcb-2layer",
                    "manufacturing_fab_profile": root / "profile.json",
                },
            )
            with mock.patch.object(handoff_module, "_run_native") as native, mock.patch.object(
                manufacturing_module, "run_bounded"
            ) as manufacturing:
                for options in incomplete:
                    with self.subTest(options=tuple(options)), self.assertRaises(
                        CircuitHandoffBundleError
                    ):
                        replay_circuit_handoff_bundle(
                            case["archive"], command, **options
                        )
                native.assert_not_called()
                manufacturing.assert_not_called()

    def test_package_mismatch_and_mutations_by_last_child_fail_closed(self) -> None:
        scenarios = (
            {"mismatch": True},
            {"mutate": "archive"},
            {"mutate": "report"},
            {"mutate": "package"},
            {"mutate": "board", "same_size_mutation": True},
            {"symlink_output": True},
            {"mutate_staged_board": True},
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                case = _board_case(root)
                package = root / "retained-manufacturing.zip"
                package_raw = b"PK\x03\x04v1457-manufacturing-package"
                package.write_bytes(package_raw)
                targets = {
                    "archive": case["archive"],
                    "report": case["report"],
                    "package": package,
                    "board": case["board"],
                }
                config = dict(scenario)
                selected = config.pop("mutate", None)
                if selected is not None:
                    config["mutate_paths"] = [str(targets[selected])]
                board_command = _write_board_wrapper(
                    root, case["base"], case["report_raw"]
                )
                command = _write_manufacturing_wrapper(
                    root, board_command, package_raw, **config
                )
                with self.assertRaises(CircuitHandoffBundleError) as raised:
                    replay_circuit_handoff_bundle(
                        case["archive"],
                        command,
                        **_options(case, package),
                    )
                self.assertNotIn(str(root), str(raised.exception))

    def test_rejected_binding_is_evidence_and_required_gate_precedes_fabricate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case, package, _package_raw, command = _case(root, approved=False)
            result = replay_circuit_handoff_bundle(
                case["archive"], command, **_options(case, package)
            )
            self.assertFalse(result["board_binding"]["approved"])
            self.assertTrue(result["manufacturing_package"]["verified"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case, package, _package_raw, command = _case(root, approved=False)
            with self.assertRaisesRegex(
                CircuitHandoffBundleError, "approval was not granted"
            ):
                replay_circuit_handoff_bundle(
                    case["archive"],
                    command,
                    **_options(
                        case,
                        package,
                        require_board_binding_approved=True,
                    ),
                )
            self.assertFalse((root / "manufacturing-invocation.json").exists())

    def test_forged_nested_board_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case, package, _package_raw, command = _case(root)

            def forged(capture, *_args, **_kwargs):
                result = _captured_result(capture)
                result["board"]["sha256"] = "f" * 64
                return result

            with mock.patch.object(
                manufacturing_module,
                "_replay_captured_manufacturing_package",
                side_effect=forged,
            ), self.assertRaisesRegex(
                CircuitHandoffBundleError, "board identity is inconsistent"
            ):
                replay_circuit_handoff_bundle(
                    case["archive"], command, **_options(case, package)
                )

    def test_v6_composes_with_native_ai_and_catalog_evidence(self) -> None:
        compositions = (
            ("board", False, False, False),
            ("native", True, False, False),
            ("ai", False, True, False),
            ("catalog", False, False, True),
            ("all", True, True, True),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            for label, native, ai, catalog in compositions:
                with self.subTest(composition=label):
                    case_root = root / label
                    case_root.mkdir()
                    catalog_options = {}
                    if catalog:
                        artifacts = _catalog_artifacts(case_root / "catalog")
                        case = _board_case_from_archive(
                            case_root,
                            artifacts["archive_raw"],
                            artifacts["manifest"],
                            artifacts["command"],
                        )
                        catalog_options = _catalog_kwargs(artifacts)
                    else:
                        case = _board_case(case_root)

                    wrapper_base = case["base"]
                    native_options = {}
                    ai_options = {}
                    schematic_raw = _archive_entries(case["archive_raw"])[
                        handoff_module.SCHEMATIC_NAME
                    ]
                    if native:
                        native_report = case_root / "native-erc.json"
                        native_report.write_bytes(_retained_report(schematic_raw))
                        wrapper_base = _write_native_wrapper(
                            case_root, wrapper_base, schema_version=1
                        )
                        native_options = {
                            "retained_native_kicad_erc_report": native_report,
                            "require_native_kicad_erc_approved": True,
                        }
                    if ai:
                        ai_options, ai_report_raw, _source_raws = _write_ai_inputs(
                            case_root, schematic_raw
                        )
                        wrapper_base = _write_ai_wrapper(
                            case_root, wrapper_base, ai_report_raw
                        )
                        ai_options["require_ai_quorum"] = True
                    board_command = _write_board_wrapper(
                        case_root, wrapper_base, case["report_raw"]
                    )
                    package_raw = b"PK\x03\x04" + label.encode("ascii")
                    package = case_root / "retained-manufacturing.zip"
                    package.write_bytes(package_raw)
                    command = _write_manufacturing_wrapper(
                        case_root, board_command, package_raw
                    )
                    result = replay_circuit_handoff_bundle(
                        case["archive"],
                        command,
                        **_options(case, package),
                        **catalog_options,
                        **native_options,
                        **ai_options,
                    )

                    self.assertEqual(result["schema_version"], 6)
                    self.assertTrue(
                        result["validation"]["manufacturing_package_replayed"]
                    )
                    self.assertEqual(
                        result["validation"]["native_kicad_erc_replayed"], native
                    )
                    self.assertEqual(
                        result["validation"]["ai_schematic_quorum_replayed"], ai
                    )
                    self.assertEqual(
                        result["validation"][
                            "catalog_generation_provenance_replayed"
                        ],
                        catalog,
                    )

    def test_manufacturing_uses_a_strict_parent_subdeadline(self) -> None:
        observed: dict[str, object] = {}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case, package, _package_raw, command = _case(root)

            def replay_capture(capture, child_command, kicad_cli, **kwargs):
                observed["capture"] = capture
                observed["command"] = list(child_command)
                observed["kicad_cli"] = kicad_cli
                observed["deadline"] = kwargs["deadline"]
                return _captured_result(capture)

            with mock.patch.object(
                manufacturing_module,
                "_replay_captured_manufacturing_package",
                side_effect=replay_capture,
            ):
                result = replay_circuit_handoff_bundle(
                    case["archive"],
                    command,
                    **_options(
                        case,
                        package,
                        manufacturing_kicad_cli="trusted-kicad-cli",
                    ),
                    timeout_seconds=120.0,
                    _clock=lambda: 0.0,
                )
        self.assertEqual(observed["deadline"], 105.0)
        self.assertEqual(observed["kicad_cli"], "trusted-kicad-cli")
        self.assertEqual(observed["command"], command)
        self.assertEqual(result["schema_version"], 6)

    def test_manufacturing_pathlikes_are_frozen_once(self) -> None:
        class FlippingPath:
            def __init__(self, first: str, second: str) -> None:
                self.first = first
                self.second = second
                self.calls = 0

            def __fspath__(self) -> str:
                self.calls += 1
                return self.first if self.calls == 1 else self.second

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case, package, _package_raw, command = _case(root)
            project = root / "project.input"
            rules = root / "rules.input"
            profile = root / "JLC-production.json"
            project.write_bytes(b"project")
            rules.write_bytes(b"rules")
            profile.write_bytes(b"profile")
            decoy = str(root / "must-not-be-read")
            paths = {
                "archive": FlippingPath(str(case["archive"]), decoy),
                "board": FlippingPath(str(case["board"]), decoy),
                "report": FlippingPath(str(case["report"]), decoy),
                "package": FlippingPath(str(package), decoy),
                "project": FlippingPath(str(project), decoy),
                "rules": FlippingPath(str(rules), decoy),
                "profile": FlippingPath(str(profile), decoy),
                "kicad": FlippingPath("trusted-kicad-cli", decoy),
            }
            result = replay_circuit_handoff_bundle(
                paths["archive"],
                command,
                kicad_board=paths["board"],
                retained_board_binding_report=paths["report"],
                retained_manufacturing_package=paths["package"],
                manufacturing_kicad_project=paths["project"],
                manufacturing_kicad_rules=paths["rules"],
                manufacturing_fab_profile=paths["profile"],
                manufacturing_kicad_cli=paths["kicad"],
            )
            invocation = (root / "manufacturing-invocation.json").read_text(
                encoding="utf-8"
            )
        self.assertEqual(result["schema_version"], 6)
        self.assertTrue(all(path.calls == 1 for path in paths.values()))
        self.assertNotIn(decoy, invocation)

    def test_omission_preserves_exact_v5_result_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case, _package, _package_raw, command = _case(root)
            first = replay_circuit_handoff_bundle(
                case["archive"], command, **_board_kwargs(case)
            )
            second = replay_circuit_handoff_bundle(
                case["archive"],
                command,
                **_board_kwargs(case),
                retained_manufacturing_package=None,
            )
        self.assertEqual(first["schema_version"], 5)
        self.assertEqual(
            json.dumps(first, separators=(",", ":")),
            json.dumps(second, separators=(",", ":")),
        )
        self.assertNotIn("manufacturing_package", first)
        self.assertNotIn("manufacturing_package_replayed", first["validation"])

    def test_schema_rejects_missing_or_forged_manufacturing_evidence(self) -> None:
        schema = circuit_handoff_bundle_manufacturing_replay_result_json_schema()
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("board_binding", schema["required"])
        self.assertIn("manufacturing_package", schema["required"])
        self.assertFalse(
            schema["properties"]["manufacturing_package"]["additionalProperties"]
        )
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case, package, _package_raw, command = _case(root)
            result = replay_circuit_handoff_bundle(
                case["archive"], command, **_options(case, package)
            )
        validator = Draft202012Validator(schema)
        for mutation in ("missing", "false-flag", "extra", "missing-board"):
            forged = json.loads(json.dumps(result))
            if mutation == "missing":
                forged.pop("manufacturing_package")
            elif mutation == "false-flag":
                forged["validation"]["manufacturing_package_replayed"] = False
            elif mutation == "extra":
                forged["manufacturing_package"]["unexpected"] = None
            else:
                forged.pop("board_binding")
            with self.subTest(mutation=mutation):
                self.assertNotEqual(list(validator.iter_errors(forged)), [])

    def test_cli_routes_composed_options_and_schema_is_no_clobber(self) -> None:
        result = {"schema_version": 6, "verified": True}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            schema_path = root / "v6-schema.json"
            stdout = io.StringIO()
            argv = [
                "pcbex-agent",
                "replay-circuit-handoff-bundle",
                str(root / "handoff.zip"),
                "--pcbex",
                "trusted-pcbex",
                "--kicad-board",
                str(root / "design.kicad_pcb"),
                "--board-binding-report",
                str(root / "board-binding.json"),
                "--manufacturing-package",
                str(root / "manufacturing.zip"),
                "--manufacturing-kicad-cli",
                "trusted-kicad-cli",
                "--manufacturing-kicad-project",
                str(root / "design.kicad_pro"),
                "--manufacturing-kicad-rules",
                str(root / "design.kicad_dru"),
                "--manufacturing-fab",
                "jlcpcb-2layer",
            ]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                cli, "replay_circuit_handoff_bundle", return_value=result
            ) as replay, redirect_stdout(stdout):
                cli.main()
            kwargs = replay.call_args.kwargs
            self.assertEqual(
                kwargs["retained_manufacturing_package"],
                root / "manufacturing.zip",
            )
            self.assertEqual(kwargs["manufacturing_kicad_cli"], "trusted-kicad-cli")
            self.assertEqual(kwargs["manufacturing_fab"], "jlcpcb-2layer")
            self.assertEqual(json.loads(stdout.getvalue()), result)

            with mock.patch.object(
                sys,
                "argv",
                ["pcbex-agent", SCHEMA_COMMAND, "--output", str(schema_path)],
            ):
                cli.main()
            first = schema_path.read_bytes()
            self.assertEqual(json.loads(first)["properties"]["schema_version"], {"const": 6})
            with mock.patch.object(
                sys,
                "argv",
                ["pcbex-agent", SCHEMA_COMMAND, "--output", str(schema_path)],
            ), self.assertRaises(SystemExit):
                cli.main()
            self.assertEqual(schema_path.read_bytes(), first)


if __name__ == "__main__":
    unittest.main()
