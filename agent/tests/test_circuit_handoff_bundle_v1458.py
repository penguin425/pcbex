from __future__ import annotations

from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

try:
    from jsonschema import Draft202012Validator
except ImportError:  # Optional in minimal boundary environments.
    Draft202012Validator = None

from agent.tests.test_circuit_handoff_bundle_v1454 import _write_board_wrapper
from agent.tests.test_circuit_handoff_bundle_v1449 import _archive_entries
from agent.tests.test_deterministic_pipeline_replay_v1456 import (
    FIRMWARE_ARTIFACTS,
    _compact,
    _descriptor,
    _write_case,
)
from agent.tests.test_circuit_handoff_bundle_v1457 import (
    _case as _manufacturing_case,
    _write_manufacturing_wrapper,
)
from pcbex_agent import cli
from pcbex_agent import circuit_handoff_bundle as handoff_module
from pcbex_agent import deterministic_pipeline_replay as pipeline_module
from pcbex_agent import manufacturing_replay as manufacturing_module
from pcbex_agent.circuit_handoff_bundle import (
    CircuitHandoffBundleError,
    circuit_handoff_bundle_pipeline_replay_result_json_schema,
    replay_circuit_handoff_bundle,
)


PIPELINE_SCHEMA_COMMAND = (
    "circuit-handoff-bundle-pipeline-replay-result-schema"
)
PIPELINE_SCOPE = (
    "deterministic-electrical-handoff-chain-manufacturing-pipeline-replay-v7"
)
PIPELINE_FLAGS = (
    "deterministic_pipeline_replayed",
    "pipeline_circuit_spec_matched",
    "pipeline_schematic_matched",
    "pipeline_effective_policy_matched",
    "pipeline_board_matched",
    "pipeline_manufacturing_package_matched",
    "pipeline_board_binding_matched",
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(raw: bytes) -> dict[str, object]:
    return {"bytes": len(raw), "sha256": _sha(raw)}


def _semantic_run_digest(report: dict[str, object]) -> str:
    value = dict(report)
    value.pop("run_sha256", None)
    return pipeline_module._semantic_run_digest(value)


def _write_pipeline_wrapper(
    root: Path,
    base_command: list[str],
    fresh_report: bytes,
    **configuration: object,
) -> list[str]:
    """Wrap v1457's board/manufacturing child with a deterministic runner."""

    (root / "pipeline-base-command.json").write_text(
        json.dumps(base_command), encoding="utf-8"
    )
    (root / "pipeline-config.json").write_text(
        json.dumps(configuration), encoding="utf-8"
    )
    (root / "pipeline-fresh-report.bin").write_bytes(fresh_report)
    wrapper = root / "fake-pipeline.py"
    wrapper.write_text(
        r'''from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).parent
base = json.loads((root / "pipeline-base-command.json").read_text(encoding="utf-8"))
config = json.loads((root / "pipeline-config.json").read_text(encoding="utf-8"))
argv = sys.argv[1:]
if not argv or argv[0] != "run-deterministic-pipeline":
    completed = subprocess.run([*base, *argv], check=False)
    raise SystemExit(completed.returncode)

(root / "pipeline-invocation.json").write_text(json.dumps(argv), encoding="utf-8")

def option(name: str) -> str | None:
    prefix = "--" + name + "="
    for index, value in enumerate(argv):
        if value.startswith(prefix):
            return value[len(prefix):]
        if value == "--" + name and index + 1 < len(argv):
            return argv[index + 1]
    return None

plan_path = Path(argv[1])
plan = json.loads(plan_path.read_bytes())
output = Path(option("output"))
output.parent.mkdir(parents=True, exist_ok=True)
fresh = (root / "pipeline-fresh-report.bin").read_bytes()
if config.get("mismatch"):
    fresh += b"mismatch"
output.write_bytes(fresh)

if config.get("mutate_staged_plan"):
    plan_path.write_bytes(plan_path.read_bytes() + b"changed")
staged_role = config.get("mutate_staged_role")
if staged_role:
    source = plan_path.parent / plan[staged_role]["path"]
    source.write_bytes(source.read_bytes() + b"changed")
staged_firmware = config.get("mutate_staged_firmware")
if staged_firmware:
    source = plan_path.parent / plan["firmware_manifest"]["path"]
    source = source.parent / staged_firmware
    source.write_bytes(source.read_bytes() + b"changed")
for raw_path in config.get("mutate_caller_paths", []):
    path = Path(raw_path)
    path.write_bytes(path.read_bytes() + b"changed")

report = json.loads(fresh)
summary = {
    "schema_version": report.get("schema_version", 1),
    "approved": report.get("approved", False),
    "plan_sha256": report.get("plan_sha256", "0" * 64),
    "run_sha256": report.get("run_sha256", "0" * 64),
    "failure_count": len(report.get("failures", [])),
    "report_bytes": len(fresh),
    "report_sha256": hashlib.sha256(fresh).hexdigest(),
}
if config.get("summary_override"):
    summary.update(config["summary_override"])
print(json.dumps(summary, separators=(",", ":")))
raise SystemExit(int(config.get("returncode", 0)))
''',
        encoding="utf-8",
    )
    return [sys.executable, str(wrapper)]


def _rewrite_plan_and_report(
    plan: Path,
    retained: Path,
    roles: dict[str, Path],
    root: Path,
    board_case: dict[str, object],
    policy: Path,
) -> bytes:
    """Rebind v1456's fixture to the exact v1457 archive identities."""

    entries = _archive_entries(board_case["archive_raw"])
    handoff = json.loads(entries[handoff_module.HANDOFF_REPORT_NAME])
    roles["circuit_spec"].write_bytes(entries[handoff_module.CIRCUIT_SPEC_NAME])
    roles["schematic"].write_bytes(entries[handoff_module.SCHEMATIC_NAME])
    roles["electrical_review"].write_bytes(
        _compact(handoff["schematic_review"])
    )
    roles["board"].write_bytes(board_case["board_raw"])
    roles["manufacturing_package"].write_bytes(board_case["package_raw"])
    policy.write_bytes(board_case["policy_raw"])

    plan_value = json.loads(plan.read_bytes())
    for role, path in roles.items():
        plan_value[role] = _descriptor(path, root)
    plan_value["electrical_policy"] = _descriptor(policy, root)
    plan_raw = _compact(plan_value)
    plan.write_bytes(plan_raw)

    report = json.loads(retained.read_bytes())
    report["engine_version"] = handoff["engine_version"]
    report["plan_source_bytes"] = len(plan_raw)
    report["plan_source_sha256"] = _sha(plan_raw)
    report["plan_sha256"] = pipeline_module._semantic_plan_digest(plan_value)
    evidence = [
        {
            "role": role,
            "path": descriptor["path"],
            "bytes": descriptor["bytes"],
            "sha256": descriptor["sha256"],
        }
        for role, descriptor in plan_value.items()
        if isinstance(descriptor, dict) and "path" in descriptor
    ]
    firmware_root = roles["firmware_manifest"].parent
    for name in FIRMWARE_ARTIFACTS:
        path = firmware_root / name
        evidence.append(
            {
                "role": f"firmware_artifact:{name}",
                "path": path.relative_to(root).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": _sha(path.read_bytes()),
            }
        )
    report["input_evidence"] = sorted(
        evidence, key=lambda item: (item["role"], item["path"])
    )
    report["binding"] = json.loads(board_case["report_raw"])
    report["pipeline"]["identities"] = {
        "schematic_sha256": handoff["schematic_sha256"],
        "board_sha256": _sha(roles["board"].read_bytes()),
    }
    report["run_sha256"] = _semantic_run_digest(report)
    report_raw = _compact(report)
    retained.write_bytes(report_raw)
    return report_raw


def _pipeline_case(
    root: Path, *, approved: bool = True
) -> dict[str, object]:
    board_root = root / "board"
    pipeline_root = root / "pipeline"
    manufacturing_root = root / "manufacturing"
    for path in (board_root, pipeline_root, manufacturing_root):
        path.mkdir(parents=True)

    package_raw = b"PK\x03\x04v1458-manufacturing-package"
    board_case, _package_path, package_raw, _old_command = _manufacturing_case(
        board_root, approved=approved, package_raw=package_raw
    )
    board_case = dict(board_case)
    board_case["package_raw"] = package_raw
    plan, retained, _old_report, roles = _write_case(
        pipeline_root, approved=approved
    )
    policy = pipeline_root / "sources" / "electrical-policy.json"
    report_raw = _rewrite_plan_and_report(
        plan, retained, roles, pipeline_root, board_case, policy
    )

    board_command = _write_board_wrapper(
        board_root,
        board_case["base"],
        board_case["report_raw"],
        approved=approved,
    )
    manufacturing_command = _write_manufacturing_wrapper(
        manufacturing_root, board_command, package_raw
    )
    board_case["board"] = roles["board"]
    board_case["package"] = roles["manufacturing_package"]
    board_case["policy"] = policy
    return {
        "board": board_case,
        "plan": plan,
        "retained": retained,
        "report_raw": report_raw,
        "roles": roles,
        "policy": policy,
        "command_base": manufacturing_command,
        "package": roles["manufacturing_package"],
    }


def _options(case: dict[str, object], **overrides: object) -> dict[str, object]:
    board = case["board"]
    options: dict[str, object] = {
        "kicad_board": board["board"],
        "retained_board_binding_report": board["report"],
        "board_binding_policy": case["policy"],
        "retained_manufacturing_package": case["package"],
        "deterministic_pipeline_plan": case["plan"],
        "retained_deterministic_pipeline_report": case["retained"],
    }
    options.update(overrides)
    return options


def _command(case: dict[str, object], **configuration: object) -> list[str]:
    return _write_pipeline_wrapper(
        case["board"]["archive"].parent.parent,
        case["command_base"],
        case["report_raw"],
        **configuration,
    )


def _refresh_report(case: dict[str, object], mutate) -> bytes:
    value = json.loads(case["retained"].read_bytes())
    mutate(value)
    value["run_sha256"] = _semantic_run_digest(value)
    raw = _compact(value)
    case["retained"].write_bytes(raw)
    case["report_raw"] = raw
    return raw


def _rebind_plan_role(
    case: dict[str, object], role: str, source: Path, raw: bytes
) -> bytes:
    """Replace one plan source while keeping retained evidence self-consistent."""

    source.write_bytes(raw)
    plan = case["plan"]
    root = plan.parent
    plan_value = json.loads(plan.read_bytes())
    descriptor = _descriptor(source, root)
    plan_value[role] = descriptor
    plan_raw = _compact(plan_value)
    plan.write_bytes(plan_raw)

    report = json.loads(case["retained"].read_bytes())
    report["plan_source_bytes"] = len(plan_raw)
    report["plan_source_sha256"] = _sha(plan_raw)
    report["plan_sha256"] = pipeline_module._semantic_plan_digest(plan_value)
    for evidence in report["input_evidence"]:
        if evidence["role"] == role:
            evidence.update(
                path=descriptor["path"],
                bytes=descriptor["bytes"],
                sha256=descriptor["sha256"],
            )
            break
    else:
        raise AssertionError(f"missing fixture evidence for {role}")
    report["input_evidence"] = sorted(
        report["input_evidence"], key=lambda item: (item["role"], item["path"])
    )
    report["run_sha256"] = _semantic_run_digest(report)
    report_raw = _compact(report)
    case["retained"].write_bytes(report_raw)
    case["report_raw"] = report_raw
    case["roles"][role] = source
    return report_raw


def _mark_pipeline_rejected(
    case: dict[str, object], phase_name: str, failure: str
) -> bytes:
    """Retain a structurally valid downstream rejection for composition tests."""

    report = json.loads(case["retained"].read_bytes())
    phase = next(
        item for item in report["pipeline"]["phases"] if item["name"] == phase_name
    )
    phase["passed"] = False
    phase["failures"] = [failure]
    report["pipeline"]["passed"] = False
    report["pipeline"]["failures"] = [failure]
    report["failures"] = [failure]
    report["approved"] = False
    report["run_sha256"] = _semantic_run_digest(report)
    report_raw = _compact(report)
    case["retained"].write_bytes(report_raw)
    case["report_raw"] = report_raw
    return report_raw


class CircuitHandoffBundleV1458Tests(unittest.TestCase):
    def test_valid_v7_is_closed_path_free_and_rebinds_exact_v6_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _pipeline_case(root)
            plan_identity = _identity(case["plan"].read_bytes())
            report_identity = _identity(case["retained"].read_bytes())
            result = replay_circuit_handoff_bundle(
                case["board"]["archive"],
                _command(case),
                **_options(case),
            )

        self.assertEqual(result["schema_version"], 7)
        self.assertEqual(result["verification_scope"], PIPELINE_SCOPE)
        self.assertTrue(set(PIPELINE_FLAGS).issubset(result["validation"]))
        for flag in PIPELINE_FLAGS:
            self.assertTrue(result["validation"][flag])
        pipeline = result["deterministic_pipeline"]
        self.assertEqual(
            pipeline["plan"]["source"], plan_identity
        )
        self.assertEqual(
            pipeline["report"]["retained"], report_identity
        )
        self.assertEqual(pipeline["report"]["fresh"], pipeline["report"]["retained"])
        self.assertEqual(
            pipeline["inputs"]["count"], len(pipeline_module._REQUIRED_ROLES)
            + 1 + len(FIRMWARE_ARTIFACTS)
        )
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(root), rendered)
        schema = circuit_handoff_bundle_pipeline_replay_result_json_schema()
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("deterministic_pipeline", schema["required"])
        self.assertEqual(schema["properties"]["schema_version"], {"const": 7})
        if Draft202012Validator is not None:
            self.assertEqual(list(Draft202012Validator(schema).iter_errors(result)), [])

    def test_pipeline_pair_and_full_v6_inputs_are_preflight_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _pipeline_case(root)
            command = _command(case)
            incomplete = (
                {"deterministic_pipeline_plan": case["plan"]},
                {"retained_deterministic_pipeline_report": case["retained"]},
                {
                    "deterministic_pipeline_plan": case["plan"],
                    "retained_deterministic_pipeline_report": case["retained"],
                    "kicad_board": case["board"]["board"],
                    "retained_board_binding_report": case["board"]["report"],
                },
            )
            with mock.patch.object(handoff_module, "_run_native") as native, mock.patch.object(
                manufacturing_module, "run_bounded"
            ) as manufacturing, mock.patch.object(
                pipeline_module, "run_bounded"
            ) as pipeline_run:
                for options in incomplete:
                    with self.subTest(options=tuple(options)), self.assertRaises(
                        CircuitHandoffBundleError
                    ):
                        replay_circuit_handoff_bundle(
                            case["board"]["archive"], command, **options
                        )
            native.assert_not_called()
            manufacturing.assert_not_called()
            pipeline_run.assert_not_called()

    def test_each_cross_binding_source_mismatch_fails_closed(self) -> None:
        mutations = {
            "circuit": lambda value: value["binding"]["circuit_kicad_handoff"].update(
                circuit_source_sha256="f" * 64
            ),
            "schematic": lambda value: value["binding"]["circuit_kicad_handoff"].update(
                schematic_source_sha256="f" * 64
            ),
            "review": lambda value: value["binding"]["circuit_kicad_handoff"].update(
                schematic_review={}
            ),
            "board": lambda value: value["binding"].update(
                board_source_sha256="f" * 64
            ),
            "policy": lambda value: value["binding"]["circuit_kicad_handoff"].update(
                policy_sha256="f" * 64
            ),
            "binding": lambda value: value["binding"].update(
                binding_sha256="f" * 64
            ),
            "binding_counts": lambda value: value["binding"]["counts"].update(
                warnings=1
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(mismatch=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                case = _pipeline_case(root)
                _refresh_report(case, mutate)
                with self.assertRaises(CircuitHandoffBundleError) as raised:
                    replay_circuit_handoff_bundle(
                        case["board"]["archive"],
                        _command(case),
                        **_options(case),
                    )
                self.assertNotIn(str(root), str(raised.exception))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _pipeline_case(root)
            case["roles"]["manufacturing_package"].write_bytes(b"mismatch")
            with self.assertRaises(CircuitHandoffBundleError):
                replay_circuit_handoff_bundle(
                    case["board"]["archive"], _command(case), **_options(case)
                )

    def test_rejected_review_and_board_name_mismatches_remain_visible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _pipeline_case(root)
            review = json.loads(case["roles"]["electrical_review"].read_bytes())
            review["schema_version"] = 1.0
            _rebind_plan_role(
                case,
                "electrical_review",
                case["roles"]["electrical_review"],
                _compact(review),
            )
            _mark_pipeline_rejected(
                case, "electrical-erc", "electrical-erc: supplied review rejected"
            )
            result = replay_circuit_handoff_bundle(
                case["board"]["archive"], _command(case), **_options(case)
            )
            self.assertEqual(result["schema_version"], 7)
            self.assertFalse(result["deterministic_pipeline"]["report"]["approved"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _pipeline_case(root)
            renamed = case["roles"]["board"].with_name("renamed.kicad_pcb")
            _rebind_plan_role(
                case,
                "board",
                renamed,
                case["roles"]["board"].read_bytes(),
            )
            _mark_pipeline_rejected(
                case,
                "manufacturing-package",
                "manufacturing-package: board filename rejected",
            )
            result = replay_circuit_handoff_bundle(
                case["board"]["archive"], _command(case), **_options(case)
            )
            self.assertEqual(result["schema_version"], 7)
            self.assertFalse(result["deterministic_pipeline"]["report"]["approved"])

    def test_approved_report_rejects_review_and_board_name_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _pipeline_case(root)
            review = json.loads(case["roles"]["electrical_review"].read_bytes())
            review["schema_version"] = 1.0
            _rebind_plan_role(
                case,
                "electrical_review",
                case["roles"]["electrical_review"],
                _compact(review),
            )
            with self.assertRaises(CircuitHandoffBundleError):
                replay_circuit_handoff_bundle(
                    case["board"]["archive"], _command(case), **_options(case)
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _pipeline_case(root)
            renamed = case["roles"]["board"].with_name("renamed.kicad_pcb")
            _rebind_plan_role(
                case,
                "board",
                renamed,
                case["roles"]["board"].read_bytes(),
            )
            with self.assertRaises(CircuitHandoffBundleError):
                replay_circuit_handoff_bundle(
                    case["board"]["archive"], _command(case), **_options(case)
                )

    def test_rejected_pipeline_is_visible_and_approval_gate_is_final(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _pipeline_case(root, approved=False)
            result = replay_circuit_handoff_bundle(
                case["board"]["archive"], _command(case), **_options(case)
            )
            self.assertFalse(result["board_binding"]["approved"])
            self.assertFalse(result["deterministic_pipeline"]["report"]["approved"])
            self.assertTrue((root / "pipeline-invocation.json").exists())
            with self.assertRaisesRegex(
                CircuitHandoffBundleError, "approval was not granted"
            ):
                replay_circuit_handoff_bundle(
                    case["board"]["archive"],
                    _command(case),
                    **_options(case, require_deterministic_pipeline_approved=True),
                )

    def test_final_pipeline_child_mutations_of_v6_and_pipeline_callers_fail(self) -> None:
        scenarios = (
            {"mutate_staged_role": "board"},
            {"mutate_staged_plan": True},
            {"mutate_caller_paths": "plan"},
            {"mutate_caller_paths": "report"},
            {"mutate_caller_paths": "board"},
            {"mutate_caller_paths": "binding"},
            {"mutate_caller_paths": "package"},
            {"mutate_caller_paths": "policy"},
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                case = _pipeline_case(root)
                mutation = dict(scenario)
                selected = mutation.get("mutate_caller_paths")
                if selected:
                    mutation["mutate_caller_paths"] = [
                        str({
                            "plan": case["plan"],
                            "report": case["retained"],
                            "board": case["roles"]["board"],
                            "binding": case["board"]["report"],
                            "package": case["package"],
                            "policy": case["policy"],
                        }[selected])
                    ]
                with self.assertRaises(CircuitHandoffBundleError):
                    replay_circuit_handoff_bundle(
                        case["board"]["archive"],
                        _command(case, **mutation),
                        **_options(case),
                    )

    def test_outer_final_check_rejects_late_firmware_directory_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _pipeline_case(root)
            real = pipeline_module._replay_captured_deterministic_pipeline

            def add_after_nested_replay(capture, *args, **kwargs):
                result = real(capture, *args, **kwargs)
                (capture.firmware_source_directory / "late-extra.bin").write_bytes(
                    b"late mutation"
                )
                return result

            with mock.patch.object(
                pipeline_module,
                "_replay_captured_deterministic_pipeline",
                side_effect=add_after_nested_replay,
            ), self.assertRaises(CircuitHandoffBundleError):
                replay_circuit_handoff_bundle(
                    case["board"]["archive"],
                    _command(case),
                    **_options(case),
                )

    def test_pipeline_receives_a_strict_subdeadline(self) -> None:
        observed: dict[str, object] = {}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _pipeline_case(root)
            real = pipeline_module._replay_captured_deterministic_pipeline

            def capture(*args, **kwargs):
                observed["deadline"] = kwargs["deadline"]
                observed["clock"] = kwargs["clock"]
                return real(*args, **kwargs)

            with mock.patch.object(
                pipeline_module,
                "_replay_captured_deterministic_pipeline",
                side_effect=capture,
            ):
                result = replay_circuit_handoff_bundle(
                    case["board"]["archive"],
                    _command(case),
                    **_options(case),
                    timeout_seconds=120.0,
                    _clock=lambda: 0.0,
                )
        self.assertEqual(observed["deadline"], 90.0)
        self.assertIsNotNone(observed["clock"])
        self.assertEqual(result["schema_version"], 7)

    def test_pipeline_pathlikes_are_frozen_once(self) -> None:
        class FlippingPath:
            def __init__(self, first: Path | str, second: Path | str) -> None:
                self.first = first
                self.second = second
                self.calls = 0

            def __fspath__(self) -> str:
                self.calls += 1
                return os.fspath(self.first if self.calls == 1 else self.second)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _pipeline_case(root)
            decoy = root / "must-not-read"
            paths = {
                "archive": FlippingPath(case["board"]["archive"], decoy),
                "board": FlippingPath(case["board"]["board"], decoy),
                "binding": FlippingPath(case["board"]["report"], decoy),
                "policy": FlippingPath(case["policy"], decoy),
                "package": FlippingPath(case["package"], decoy),
                "plan": FlippingPath(case["plan"], decoy),
                "report": FlippingPath(case["retained"], decoy),
            }
            options = {
                "kicad_board": paths["board"],
                "retained_board_binding_report": paths["binding"],
                "board_binding_policy": paths["policy"],
                "retained_manufacturing_package": paths["package"],
                "deterministic_pipeline_plan": paths["plan"],
                "retained_deterministic_pipeline_report": paths["report"],
            }
            result = replay_circuit_handoff_bundle(
                paths["archive"], _command(case), **options
            )
        self.assertEqual(result["schema_version"], 7)
        self.assertTrue(all(path.calls == 1 for path in paths.values()))

    def test_pipeline_paths_freeze_before_command_normalization(self) -> None:
        class SwitchPath:
            def __init__(self, path: Path, decoy: Path) -> None:
                self.path = path
                self.decoy = decoy
                self.switched = False
                self.calls = 0

            def __fspath__(self) -> str:
                self.calls += 1
                return os.fspath(self.decoy if self.switched else self.path)

        class MutatingCommand(list[str]):
            def __init__(self, values: list[str], paths: tuple[SwitchPath, ...]) -> None:
                super().__init__(values)
                self.paths = paths

            def __iter__(self):
                for path in self.paths:
                    path.switched = True
                return super().__iter__()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _pipeline_case(root)
            decoy = root / "must-not-read"
            plan = SwitchPath(case["plan"], decoy)
            report = SwitchPath(case["retained"], decoy)
            command = MutatingCommand(_command(case), (plan, report))
            result = replay_circuit_handoff_bundle(
                case["board"]["archive"],
                command,
                **_options(
                    case,
                    deterministic_pipeline_plan=plan,
                    retained_deterministic_pipeline_report=report,
                ),
            )
        self.assertEqual(result["schema_version"], 7)
        self.assertEqual((plan.calls, report.calls), (1, 1))

    def test_staged_pipeline_reread_checks_deadline_per_file(self) -> None:
        state = {"now": 0.0, "staged": 0}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _pipeline_case(root)
            real = pipeline_module._verify_capture

            def expire_on_first_staged(*args, **kwargs):
                label = args[3]
                result = real(*args, **kwargs)
                if label.startswith("staged "):
                    state["staged"] += 1
                    if state["staged"] == 1:
                        state["now"] = 121.0
                return result

            with mock.patch.object(
                pipeline_module, "_verify_capture", side_effect=expire_on_first_staged
            ), self.assertRaises(CircuitHandoffBundleError):
                replay_circuit_handoff_bundle(
                    case["board"]["archive"],
                    _command(case),
                    **_options(case),
                    timeout_seconds=120.0,
                    _clock=lambda: state["now"],
                )
        self.assertEqual(state["staged"], 1)

    def test_omitted_pipeline_preserves_exact_v6_serialized_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            case = _pipeline_case(root)
            v6 = replay_circuit_handoff_bundle(
                case["board"]["archive"],
                _command(case),
                **{
                    key: value
                    for key, value in _options(case).items()
                    if not key.startswith("deterministic_pipeline")
                    and key != "retained_deterministic_pipeline_report"
                },
            )
            omitted = replay_circuit_handoff_bundle(
                case["board"]["archive"],
                _command(case),
                **{
                    key: value
                    for key, value in _options(case).items()
                    if key not in {
                        "deterministic_pipeline_plan",
                        "retained_deterministic_pipeline_report",
                    }
                },
            )
        self.assertEqual(v6["schema_version"], 6)
        self.assertEqual(
            json.dumps(v6, separators=(",", ":")),
            json.dumps(omitted, separators=(",", ":")),
        )
        self.assertNotIn("deterministic_pipeline", omitted)

    def test_v7_schema_closes_nested_pipeline_and_const_true_flags(self) -> None:
        schema = circuit_handoff_bundle_pipeline_replay_result_json_schema()
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"], {"const": 7})
        self.assertEqual(schema["properties"]["verification_scope"], {"const": PIPELINE_SCOPE})
        validation = schema["properties"]["validation"]
        self.assertFalse(validation["additionalProperties"])
        for flag in PIPELINE_FLAGS:
            self.assertEqual(validation["properties"][flag], {"const": True})
            self.assertIn(flag, validation["required"])
        self.assertFalse(
            schema["properties"]["deterministic_pipeline"]["additionalProperties"]
        )
        if Draft202012Validator is not None:
            Draft202012Validator.check_schema(schema)
            self.assertTrue(
                list(
                    Draft202012Validator(schema).iter_errors(
                        {"schema_version": 7, "verification_scope": PIPELINE_SCOPE}
                    )
                )
            )

    def test_cli_routes_pipeline_options_and_schema_forgery_is_rejected(self) -> None:
        result = {"schema_version": 7, "verified": True}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            schema_path = root / "pipeline-schema.json"
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
                "--board-binding-policy",
                str(root / "policy.json"),
                "--manufacturing-package",
                str(root / "manufacturing.zip"),
                "--deterministic-pipeline-plan",
                str(root / "pipeline-plan.json"),
                "--deterministic-pipeline-report",
                str(root / "pipeline-report.json"),
                "--require-deterministic-pipeline-approved",
            ]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                cli, "replay_circuit_handoff_bundle", return_value=result
            ) as replay, redirect_stdout(stdout):
                cli.main()
            kwargs = replay.call_args.kwargs
            self.assertEqual(kwargs["deterministic_pipeline_plan"], root / "pipeline-plan.json")
            self.assertEqual(
                kwargs["retained_deterministic_pipeline_report"],
                root / "pipeline-report.json",
            )
            self.assertTrue(kwargs["require_deterministic_pipeline_approved"])
            self.assertEqual(json.loads(stdout.getvalue()), result)

            with mock.patch.object(
                sys,
                "argv",
                ["pcbex-agent", PIPELINE_SCHEMA_COMMAND, "--output", str(schema_path)],
            ):
                cli.main()
            first = schema_path.read_bytes()
            schema = json.loads(first)
            self.assertEqual(schema["properties"]["schema_version"], {"const": 7})
            self.assertIn("deterministic_pipeline", schema["required"])
            if Draft202012Validator is not None:
                Draft202012Validator.check_schema(schema)
                forged = copy.deepcopy(schema)
                forged["required"].remove("deterministic_pipeline")
                self.assertTrue(
                    list(Draft202012Validator(schema).iter_errors({"schema_version": 7}))
                )
                self.assertNotEqual(forged["required"], schema["required"])
            with mock.patch.object(
                sys,
                "argv",
                ["pcbex-agent", PIPELINE_SCHEMA_COMMAND, "--output", str(schema_path)],
            ), self.assertRaises(SystemExit):
                cli.main()
            self.assertEqual(schema_path.read_bytes(), first)


if __name__ == "__main__":
    unittest.main()
