from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path, PureWindowsPath
import sys
import tempfile
import unittest
from unittest import mock

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional in minimal agent installs
    Draft202012Validator = None

from pcbex_agent import cli
from pcbex_agent import deterministic_pipeline_replay as replay_module
from pcbex_agent.bounded_process import BoundedProcessResult
from pcbex_agent.deterministic_pipeline_replay import (
    DeterministicPipelineReplayError,
    deterministic_pipeline_replay_result_json_schema,
    replay_deterministic_pipeline,
)


FIRMWARE_ARTIFACTS = (
    "pinout.h",
    "firmware.h",
    "firmware.c",
    "firmware_smoke_test.c",
    "firmware.cpp",
    "firmware_cpp_smoke_test.cpp",
    "host.py",
)
PLAN_HASH_DOMAIN = b"pcbex:deterministic-pipeline-plan:v1\0"
RUN_HASH_DOMAIN = b"pcbex:deterministic-pipeline-runner:v1\0"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(raw: bytes) -> dict[str, object]:
    return {"bytes": len(raw), "sha256": _sha(raw)}


def _compact(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def _descriptor(path: Path, root: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "bytes": len(raw),
        "sha256": _sha(raw),
    }


def _nested_electrical_review(approved: bool, engine: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "schematic_sha256": "a" * 64,
        "policy_sha256": "b" * 64,
        "policy_id": "fixture-policy",
        "approved": approved,
        "counts": {"errors": 0, "warnings": 0, "info": 0},
        "findings": [],
    }


def _nested_handoff(approved: bool, engine: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "engine_version": engine,
        "circuit_source_bytes": 1,
        "circuit_source_sha256": "c" * 64,
        "schematic_source_bytes": 1,
        "schematic_source_sha256": "d" * 64,
        "circuit_spec_sha256": "e" * 64,
        "circuit_check_sha256": "f" * 64,
        "circuit_review": _nested_electrical_review(approved, engine),
        "schematic_sha256": "a" * 64,
        "schematic_review": _nested_electrical_review(approved, engine),
        "policy_sha256": "b" * 64,
        "findings": [],
        "counts": {"errors": 0, "warnings": 0, "info": 0},
        "approved": approved,
    }


def _nested_binding(approved: bool, engine: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "engine_version": engine,
        "board_source_bytes": 1,
        "board_source_sha256": "1" * 64,
        "board_electrical_sha256": "2" * 64,
        "circuit_kicad_handoff_sha256": "3" * 64,
        "binding_sha256": "4" * 64,
        "circuit_kicad_handoff": _nested_handoff(approved, engine),
        "findings": [],
        "counts": {"errors": 0, "warnings": 0, "info": 0},
        "approved": approved,
    }


def _nested_pipeline(approved: bool) -> dict[str, object]:
    names = (
        "electrical-erc",
        "analysis-drc",
        "routing-quality",
        "manufacturing-package",
        "firmware-build",
    )
    phases = [
        {
            "name": name,
            "evidence": [],
            "passed": approved,
            "checks": [],
            "failures": [] if approved else [f"{name} rejected"],
        }
        for name in names
    ]
    return {
        "schema_version": 1,
        "pipeline": "pcbex-hardware-v1",
        "identities": {"schematic_sha256": "5" * 64, "board_sha256": "6" * 64},
        "phases": phases,
        "passed": approved,
        "failures": [] if approved else ["pipeline rejected"],
    }


def _write_case(
    root: Path, *, approved: bool = True
) -> tuple[Path, Path, bytes, dict[str, Path]]:
    sources = root / "sources"
    analysis = root / "analysis"
    firmware = root / "firmware"
    for directory in (sources, analysis, firmware):
        directory.mkdir()

    role_paths = {
        "circuit_spec": sources / "circuit-spec-v2.json",
        "schematic": sources / "controller.kicad_sch",
        "electrical_review": analysis / "electrical-review.json",
        "board": sources / "controller.kicad_pcb",
        "analysis_manifest": analysis / "run.json",
        "analysis_checks": analysis / "checks.json",
        "quality": analysis / "quality.json",
        "manufacturing_package": analysis / "manufacturing.zip",
        "firmware_manifest": firmware / "manifest.json",
    }
    for index, (role, path) in enumerate(role_paths.items(), start=1):
        path.write_bytes(f"{role}:stable-input:{index}\n".encode())
    for index, name in enumerate(FIRMWARE_ARTIFACTS, start=1):
        (firmware / name).write_bytes(f"{name}:stable-firmware:{index}\n".encode())

    plan_value: dict[str, object] = {
        "schema_version": 1,
        "circuit_spec": _descriptor(role_paths["circuit_spec"], root),
        "schematic": _descriptor(role_paths["schematic"], root),
        "electrical_policy": None,
        "electrical_review": _descriptor(role_paths["electrical_review"], root),
        "board": _descriptor(role_paths["board"], root),
        "analysis_manifest": _descriptor(role_paths["analysis_manifest"], root),
        "analysis_checks": _descriptor(role_paths["analysis_checks"], root),
        "quality": _descriptor(role_paths["quality"], root),
        "analysis_project": None,
        "analysis_rules": None,
        "analysis_dfm_profile": None,
        "analysis_policy_pack": None,
        "analysis_physical_profile": None,
        "manufacturing_package": _descriptor(
            role_paths["manufacturing_package"], root
        ),
        "firmware_manifest": _descriptor(role_paths["firmware_manifest"], root),
        "factory_receipt": None,
        "require_factory": False,
    }
    plan = root / "pipeline-plan.json"
    plan_raw = _compact(plan_value)
    plan.write_bytes(plan_raw)
    plan_sha256 = _sha(PLAN_HASH_DOMAIN + plan_raw[:-1])

    failures = [] if approved else ["manufacturing-package: retained rejection"]
    input_evidence = [
        {
            "role": role,
            "path": descriptor["path"],
            "bytes": descriptor["bytes"],
            "sha256": descriptor["sha256"],
        }
        for role, descriptor in plan_value.items()
        if isinstance(descriptor, dict)
    ]
    for name in FIRMWARE_ARTIFACTS:
        path = firmware / name
        input_evidence.append(
            {
                "role": f"firmware_artifact:{name}",
                "path": path.relative_to(root).as_posix(),
                "bytes": len(path.read_bytes()),
                "sha256": _sha(path.read_bytes()),
            }
        )
    input_evidence.sort(key=lambda item: (item["role"], item["path"]))
    report_value = {
        "schema_version": 1,
        "engine_version": "1.456.0-test",
        "plan_source_bytes": len(plan_raw),
        "plan_source_sha256": _sha(plan_raw),
        "plan_sha256": plan_sha256,
        "input_evidence": input_evidence,
        "binding": _nested_binding(approved, "1.456.0-test"),
        "pipeline": _nested_pipeline(approved),
        "failures": failures,
        "approved": approved,
    }
    report_hash_input = json.dumps(
        report_value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    report_value["run_sha256"] = _sha(RUN_HASH_DOMAIN + report_hash_input)
    report_raw = _compact(report_value)
    retained = root / "retained-pipeline-report.json"
    retained.write_bytes(report_raw)
    return plan, retained, report_raw, role_paths


def _write_fake_pcbex(
    root: Path, fresh_report: bytes, **configuration: object
) -> list[str]:
    (root / "fake-fresh-report.bin").write_bytes(fresh_report)
    (root / "fake-config.json").write_text(
        json.dumps(configuration), encoding="utf-8"
    )
    wrapper = root / "fake-pcbex.py"
    wrapper.write_text(
        r'''from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import time

root = Path(__file__).parent
config = json.loads((root / "fake-config.json").read_text(encoding="utf-8"))
argv = sys.argv[1:]
(root / "invocation.json").write_text(json.dumps(argv), encoding="utf-8")
if len(argv) < 2 or argv[0] != "run-deterministic-pipeline":
    raise SystemExit(91)

def option(name: str) -> str | None:
    prefix = "--" + name + "="
    for index, value in enumerate(argv):
        if value.startswith(prefix):
            return value[len(prefix):]
        if value == "--" + name and index + 1 < len(argv):
            return argv[index + 1]
    return None

plan_path = Path(argv[1])
plan_raw = plan_path.read_bytes()
plan = json.loads(plan_raw)
observed = {
    "plan_sha256": hashlib.sha256(plan_raw).hexdigest(),
    "plan_name": plan_path.name,
    "roles": {},
}
for role, descriptor in plan.items():
    if isinstance(descriptor, dict) and "path" in descriptor:
        source = plan_path.parent / descriptor["path"]
        observed["roles"][role] = {
            "path": descriptor["path"],
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        }
firmware_parent = (plan_path.parent / plan["firmware_manifest"]["path"]).parent
observed["firmware_entries"] = sorted(path.name for path in firmware_parent.iterdir())
(root / "stage-observation.json").write_text(
    json.dumps(observed), encoding="utf-8"
)

if config.get("sleep_seconds"):
    time.sleep(float(config["sleep_seconds"]))

fresh = (root / "fake-fresh-report.bin").read_bytes()
published = fresh + (b"mismatch" if config.get("mismatch") else b"")
output_name = option("output")
if output_name is None:
    raise SystemExit(92)
output = Path(output_name)
if not config.get("no_output"):
    if config.get("symlink_output"):
        target = root / "fake-output-target.json"
        target.write_bytes(published)
        output.symlink_to(target)
    else:
        output.write_bytes(published)

if config.get("mutate_staged_plan"):
    plan_path.write_bytes(plan_path.read_bytes() + b"changed")
staged_role = config.get("mutate_staged_role")
if staged_role:
    source = plan_path.parent / plan[staged_role]["path"]
    source.write_bytes(source.read_bytes() + b"changed")
staged_firmware = config.get("mutate_staged_firmware")
if staged_firmware:
    source = firmware_parent / staged_firmware
    source.write_bytes(source.read_bytes() + b"changed")
for key in (
    "mutate_caller_plan",
    "mutate_caller_report",
    "mutate_caller_input",
    "mutate_caller_firmware",
):
    selected = config.get(key)
    if selected:
        path = Path(selected)
        path.write_bytes(path.read_bytes() + b"changed")

try:
    report = json.loads(fresh)
except Exception:
    report = {}
summary = {
    "schema_version": report.get("schema_version", 1),
    "approved": report.get("approved", False),
    "plan_sha256": report.get("plan_sha256", "0" * 64),
    "run_sha256": report.get("run_sha256", "0" * 64),
    "failure_count": len(report.get("failures", [])),
    "report_bytes": len(fresh),
    "report_sha256": hashlib.sha256(fresh).hexdigest(),
}
summary.update(config.get("summary_override", {}))
if config.get("malformed_summary"):
    sys.stdout.write("not-json\n")
elif config.get("stdout_bytes"):
    sys.stdout.write("x" * int(config["stdout_bytes"]))
else:
    sys.stdout.write(json.dumps(summary, separators=(",", ":")) + "\n")
raise SystemExit(int(config.get("returncode", 0)))
''',
        encoding="utf-8",
    )
    return [sys.executable, str(wrapper)]


def _schema_objects_are_closed(value: object) -> None:
    if isinstance(value, dict):
        if value.get("type") == "object":
            if "properties" in value:
                assert value.get("additionalProperties") is False
        for nested in value.values():
            _schema_objects_are_closed(nested)
    elif isinstance(value, list):
        for nested in value:
            _schema_objects_are_closed(nested)


class DeterministicPipelineReplayTests(unittest.TestCase):
    def test_approved_success_is_exact_closed_path_free_and_preserves_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            plan, retained, report_raw, role_paths = _write_case(root)
            plan_raw = plan.read_bytes()
            command = _write_fake_pcbex(root, report_raw)

            result = replay_deterministic_pipeline(plan, retained, command)

            self.assertEqual(result["schema_version"], 1)
            self.assertEqual(
                result["verification_scope"],
                "deterministic-pipeline-fresh-replay-v1",
            )
            self.assertTrue(result["verified"])
            self.assertEqual(result["engine_version"], "1.456.0-test")
            self.assertEqual(result["plan"]["source"], _identity(plan_raw))
            report_value = json.loads(report_raw)
            self.assertEqual(
                result["plan"]["plan_sha256"], report_value["plan_sha256"]
            )
            self.assertFalse(result["plan"]["factory_required"])
            self.assertEqual(result["report"]["retained"], _identity(report_raw))
            self.assertEqual(result["report"]["fresh"], _identity(report_raw))
            self.assertTrue(result["report"]["identical"])
            self.assertTrue(result["report"]["approved"])
            self.assertEqual(result["report"]["failure_count"], 0)
            self.assertEqual(
                result["report"]["run_sha256"], report_value["run_sha256"]
            )
            self.assertEqual(result["inputs"]["count"], 16)
            self.assertEqual(
                result["inputs"]["bytes"],
                sum(path.stat().st_size for path in role_paths.values())
                + sum(
                    (role_paths["firmware_manifest"].parent / name).stat().st_size
                    for name in FIRMWARE_ARTIFACTS
                ),
            )
            self.assertEqual(
                set(result["validation"]),
                {
                    "plan_captured_before_replay",
                    "inputs_captured_before_replay",
                    "fresh_report_reproduced",
                    "retained_report_identical",
                    "staged_inputs_unchanged",
                    "caller_inputs_unchanged",
                },
            )
            self.assertTrue(all(result["validation"].values()))

            rendered = json.dumps(result, sort_keys=True)
            self.assertNotIn(str(root), rendered)
            self.assertNotIn(str(command[1]), rendered)
            self.assertNotIn(report_raw.hex(), rendered)
            for value in self._all_strings(result):
                self.assertFalse(Path(value).is_absolute(), value)
                self.assertFalse(PureWindowsPath(value).is_absolute(), value)
                self.assertFalse(PureWindowsPath(value).drive, value)

            invocation = json.loads((root / "invocation.json").read_text())
            self.assertEqual(invocation[0], "run-deterministic-pipeline")
            self.assertEqual(invocation.count("--mcp-echo-report-summary"), 1)
            self.assertNotEqual(Path(invocation[1]), plan)
            output = self._output_path(invocation)
            self.assertNotEqual(output, retained)
            self.assertFalse(output.exists(), "private fresh report escaped cleanup")

            observation = json.loads((root / "stage-observation.json").read_text())
            self.assertEqual(observation["plan_sha256"], _sha(plan_raw))
            self.assertEqual(
                set(observation["roles"]),
                set(role_paths),
            )
            for role, path in role_paths.items():
                self.assertEqual(
                    observation["roles"][role]["path"],
                    path.relative_to(root).as_posix(),
                )
            self.assertEqual(
                observation["firmware_entries"],
                sorted(("manifest.json", *FIRMWARE_ARTIFACTS)),
            )

            schema = deterministic_pipeline_replay_result_json_schema()
            self.assertEqual(set(result), set(schema["required"]))
            self.assertEqual(schema["properties"]["inputs"]["properties"]["count"]["maximum"], 23)
            _schema_objects_are_closed(schema)
            if Draft202012Validator is not None:
                self.assertEqual(
                    list(Draft202012Validator(schema).iter_errors(result)), []
                )

    def test_rejected_report_is_verified_but_not_approved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            plan, retained, report_raw, _roles = _write_case(root, approved=False)
            result = replay_deterministic_pipeline(
                plan, retained, _write_fake_pcbex(root, report_raw)
            )

            self.assertTrue(result["verified"])
            self.assertFalse(result["report"]["approved"])
            self.assertEqual(result["report"]["failure_count"], 1)
            self.assertEqual(result["report"]["retained"], result["report"]["fresh"])
            self.assertTrue(result["report"]["identical"])

    def test_exact_report_mismatch_and_child_summary_forgery_fail_closed(self):
        configurations = (
            {"mismatch": True},
            {"summary_override": {"report_sha256": "d" * 64}},
            {"summary_override": {"report_bytes": 1}},
            {"summary_override": {"plan_sha256": "d" * 64}},
            {"summary_override": {"run_sha256": "d" * 64}},
            {"summary_override": {"approved": False}},
            {"summary_override": {"failure_count": 99}},
            {"malformed_summary": True},
        )
        for index, configuration in enumerate(configurations):
            with self.subTest(configuration=configuration), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                plan, retained, report_raw, _roles = _write_case(root)
                command = _write_fake_pcbex(root, report_raw, **configuration)
                with self.assertRaises(DeterministicPipelineReplayError) as raised:
                    replay_deterministic_pipeline(plan, retained, command)
                self.assertNotIn(str(root), str(raised.exception))
                self.assertEqual(retained.read_bytes(), report_raw)
                self.assertFalse((root / f"unexpected-result-{index}.json").exists())

    def test_report_domain_hashes_and_path_free_fields_are_recomputed(self):
        scenarios = (
            "plan-digest",
            "run-digest",
            "engine-path",
            "float-schema",
            "float-plan-source-bytes",
            "float-evidence-bytes",
            "nested-extra",
            "pipeline-phase-invariant",
            "unsorted-failures",
            "oversized-failure",
            "inconsistent-approval",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                plan, retained, report_raw, _roles = _write_case(root)
                value = json.loads(report_raw)
                if scenario == "plan-digest":
                    value["plan_sha256"] = "d" * 64
                elif scenario == "run-digest":
                    value["run_sha256"] = "d" * 64
                elif scenario == "engine-path":
                    value["engine_version"] = str(root / "escaped-engine")
                elif scenario == "float-schema":
                    value["schema_version"] = 1.0
                elif scenario == "float-plan-source-bytes":
                    value["plan_source_bytes"] = float(value["plan_source_bytes"])
                elif scenario == "float-evidence-bytes":
                    value["input_evidence"][0]["bytes"] = float(
                        value["input_evidence"][0]["bytes"]
                    )
                elif scenario == "nested-extra":
                    value["binding"]["unexpected"] = True
                elif scenario == "pipeline-phase-invariant":
                    value["pipeline"]["phases"][0]["passed"] = False
                    value["pipeline"]["phases"][0]["failures"] = ["phase rejected"]
                elif scenario == "unsorted-failures":
                    value["approved"] = False
                    value["binding"]["approved"] = False
                    value["pipeline"]["passed"] = False
                    value["failures"] = ["z-last", "a-first"]
                elif scenario == "oversized-failure":
                    value["approved"] = False
                    value["binding"]["approved"] = False
                    value["pipeline"]["passed"] = False
                    value["failures"] = ["x" * 4097]
                else:
                    value["failures"] = ["approved-but-failed"]
                if scenario != "run-digest":
                    hash_value = dict(value)
                    hash_value.pop("run_sha256", None)
                    encoded = json.dumps(
                        hash_value,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode()
                    value["run_sha256"] = _sha(RUN_HASH_DOMAIN + encoded)
                forged = _compact(value)
                retained.write_bytes(forged)
                command = _write_fake_pcbex(root, forged)
                with self.assertRaises(DeterministicPipelineReplayError) as raised:
                    replay_deterministic_pipeline(plan, retained, command)
                self.assertNotIn(str(root), str(raised.exception))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            plan, retained, _report_raw, _roles = _write_case(root)
            value = json.loads(plan.read_bytes())
            value["schema_version"] = 1.0
            plan.write_bytes(_compact(value))
            with mock.patch.object(replay_module, "run_bounded") as run:
                with self.assertRaises(DeterministicPipelineReplayError):
                    replay_deterministic_pipeline(plan, retained, "pcbex")
                run.assert_not_called()

    def test_noncanonical_or_one_byte_retained_report_never_matches(self):
        variants = (
            lambda raw: raw[:-1],
            lambda raw: raw + b"\n",
            lambda raw: b" " + raw,
            lambda raw: raw.replace(b'"schema_version":1', b'"schema_version": 1', 1),
            lambda raw: bytes([raw[0] ^ 1]) + raw[1:],
        )
        for mutate in variants:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                plan, retained, canonical, _roles = _write_case(root)
                retained.write_bytes(mutate(canonical))
                command = _write_fake_pcbex(root, canonical)
                with self.assertRaises(DeterministicPipelineReplayError) as raised:
                    replay_deterministic_pipeline(plan, retained, command)
                self.assertNotIn(str(root), str(raised.exception))

    def test_staged_and_caller_mutations_are_rejected(self):
        scenarios = (
            ("mutate_staged_plan", True),
            ("mutate_staged_role", "board"),
            ("mutate_staged_firmware", "host.py"),
            ("mutate_caller_plan", "plan"),
            ("mutate_caller_report", "report"),
            ("mutate_caller_input", "board"),
            ("mutate_caller_firmware", "firmware"),
        )
        for key, selected in scenarios:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                plan, retained, report_raw, roles = _write_case(root)
                value: object = selected
                if selected == "plan":
                    value = str(plan)
                elif selected == "report":
                    value = str(retained)
                elif selected == "board":
                    value = str(roles["board"])
                elif selected == "firmware":
                    value = str(roles["firmware_manifest"].parent / "host.py")
                command = _write_fake_pcbex(root, report_raw, **{key: value})
                with self.assertRaises(DeterministicPipelineReplayError) as raised:
                    replay_deterministic_pipeline(plan, retained, command)
                self.assertRegex(str(raised.exception), "changed|mutation|replay")
                self.assertNotIn(str(root), str(raised.exception))

    def test_plan_report_and_firmware_bounds_are_applied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            plan, retained, report_raw, roles = _write_case(root)
            command = _write_fake_pcbex(root, report_raw)
            original = replay_module.read_bytes
            observed: list[tuple[str, int]] = []

            def recording(path: object, *, max_bytes: int) -> bytes:
                observed.append((Path(path).name, max_bytes))
                return original(path, max_bytes=max_bytes)

            with mock.patch.object(replay_module, "read_bytes", side_effect=recording):
                replay_deterministic_pipeline(plan, retained, command)
            self.assertIn((plan.name, 4 * 1024 * 1024), observed)
            self.assertIn((retained.name, 128 * 1024 * 1024), observed)
            for name in FIRMWARE_ARTIFACTS:
                self.assertTrue(
                    any(
                        observed_name == name and maximum <= 16 * 1024 * 1024
                        for observed_name, maximum in observed
                    ),
                    name,
                )

            for constant, limit in (
                ("MAXIMUM_PLAN_BYTES", len(plan.read_bytes()) - 1),
                ("MAXIMUM_REPORT_BYTES", len(report_raw) - 1),
                (
                    "_FIRMWARE_ARTIFACT_LIMIT",
                    len((roles["firmware_manifest"].parent / "host.py").read_bytes()) - 1,
                ),
                ("MAXIMUM_TOTAL_INPUT_BYTES", 1),
            ):
                with self.subTest(constant=constant), mock.patch.object(
                    replay_module, constant, limit
                ), self.assertRaises(DeterministicPipelineReplayError):
                    replay_deterministic_pipeline(plan, retained, command)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support is required")
    def test_symlink_inputs_and_unsafe_plan_paths_fail_before_child(self):
        for target_kind in ("plan", "report", "input", "firmware"):
            with self.subTest(target_kind=target_kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                plan, retained, report_raw, roles = _write_case(root)
                selected = {
                    "plan": plan,
                    "report": retained,
                    "input": roles["board"],
                    "firmware": roles["firmware_manifest"].parent / "host.py",
                }[target_kind]
                real = selected.with_name(selected.name + ".real")
                selected.rename(real)
                selected.symlink_to(real)
                with mock.patch.object(replay_module, "run_bounded") as run:
                    with self.assertRaises(DeterministicPipelineReplayError) as raised:
                        replay_deterministic_pipeline(plan, retained, "pcbex")
                    run.assert_not_called()
                self.assertNotIn(str(root), str(raised.exception))

        unsafe_paths = (
            "../escape.json",
            "/absolute.json",
            "bad\\windows.json",
            "nested//empty.json",
            "CON.json",
            "trailing-space ",
        )
        for unsafe in unsafe_paths:
            with self.subTest(path=unsafe), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                plan, retained, _report_raw, _roles = _write_case(root)
                value = json.loads(plan.read_bytes())
                value["board"]["path"] = unsafe
                plan.write_bytes(_compact(value))
                with mock.patch.object(replay_module, "run_bounded") as run:
                    with self.assertRaises(DeterministicPipelineReplayError):
                        replay_deterministic_pipeline(plan, retained, "pcbex")
                    run.assert_not_called()

    def test_duplicate_unknown_alias_and_inexact_firmware_sets_fail_pre_child(self):
        mutations = ("duplicate-key", "unknown-key", "duplicate-path", "extra", "missing")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                plan, retained, _report_raw, roles = _write_case(root)
                if mutation == "duplicate-key":
                    raw = plan.read_text(encoding="utf-8")
                    plan.write_text(
                        raw.replace(
                            '{"schema_version":1,',
                            '{"schema_version":1,"schema_version":1,',
                            1,
                        ),
                        encoding="utf-8",
                    )
                else:
                    value = json.loads(plan.read_bytes())
                    if mutation == "unknown-key":
                        value["unexpected"] = None
                    elif mutation == "duplicate-path":
                        value["analysis_checks"]["path"] = value["quality"]["path"]
                    elif mutation == "extra":
                        (roles["firmware_manifest"].parent / "extra.txt").write_bytes(b"extra")
                    else:
                        (roles["firmware_manifest"].parent / "host.py").unlink()
                    plan.write_bytes(_compact(value))
                with mock.patch.object(replay_module, "run_bounded") as run:
                    with self.assertRaises(DeterministicPipelineReplayError):
                        replay_deterministic_pipeline(plan, retained, "pcbex")
                    run.assert_not_called()

    def test_timeout_argv_and_child_output_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            plan, retained, report_raw, _roles = _write_case(root)
            observed: dict[str, object] = {}

            def fake_run(argv: list[str], **kwargs: object) -> BoundedProcessResult:
                observed["argv"] = list(argv)
                observed["kwargs"] = dict(kwargs)
                output = self._output_path(argv)
                output.write_bytes(report_raw)
                report = json.loads(report_raw)
                summary = _compact(
                    {
                        "schema_version": 1,
                        "approved": report["approved"],
                        "plan_sha256": report["plan_sha256"],
                        "run_sha256": report["run_sha256"],
                        "failure_count": len(report["failures"]),
                        "report_bytes": len(report_raw),
                        "report_sha256": _sha(report_raw),
                    }
                )
                return BoundedProcessResult(tuple(argv), 0, summary, b"")

            with mock.patch.object(replay_module, "run_bounded", side_effect=fake_run):
                replay_deterministic_pipeline(
                    plan,
                    retained,
                    ["trusted-wrapper", "pcbex"],
                    timeout_seconds=80.0,
                )
            argv = observed["argv"]
            kwargs = observed["kwargs"]
            self.assertEqual(argv[:3], ["trusted-wrapper", "pcbex", "run-deterministic-pipeline"])
            self.assertEqual(argv.count("--mcp-echo-report-summary"), 1)
            self.assertGreater(float(kwargs["timeout_seconds"]), 0)
            self.assertLessEqual(float(kwargs["timeout_seconds"]), 80.0)
            self.assertGreater(float(kwargs["cleanup_timeout_seconds"]), 0)
            self.assertLess(
                float(kwargs["timeout_seconds"])
                + float(kwargs["cleanup_timeout_seconds"]),
                80.0,
            )
            self.assertEqual(kwargs["max_stdout_bytes"], 64 * 1024)
            self.assertEqual(kwargs["max_stderr_bytes"], 1024 * 1024)

            for timeout in (True, 0, -1, float("inf"), 601):
                with self.subTest(timeout=timeout), self.assertRaisesRegex(
                    DeterministicPipelineReplayError, "timeout"
                ):
                    replay_deterministic_pipeline(
                        plan, retained, "pcbex", timeout_seconds=timeout
                    )

            yielded = 0

            def oversized_command():
                nonlocal yielded
                while True:
                    yielded += 1
                    yield "wrapper"

            with self.assertRaisesRegex(
                DeterministicPipelineReplayError, "command|argv"
            ):
                replay_deterministic_pipeline(plan, retained, oversized_command())
            self.assertLessEqual(yielded, 257)

            for command in (
                ["wrapper"] * 252,
                ["x" * 32_600],
            ):
                with self.subTest(final_argv=command[0][:16]), mock.patch.object(
                    replay_module, "run_bounded"
                ) as run, self.assertRaisesRegex(
                    DeterministicPipelineReplayError, "command|argv"
                ):
                    replay_deterministic_pipeline(plan, retained, command)
                run.assert_not_called()

            command = _write_fake_pcbex(
                root, report_raw, stdout_bytes=64 * 1024 + 1
            )
            with self.assertRaises(DeterministicPipelineReplayError):
                replay_deterministic_pipeline(plan, retained, command)

    def test_windows_private_staging_path_length_is_rejected_before_writes(self):
        long_path = Path("/") / ("x" * 300)
        short_path = Path("/tmp/replay.json")
        boundary_path = Path("boundary")
        with mock.patch.object(replay_module.os, "name", "nt"):
            with self.assertRaisesRegex(
                DeterministicPipelineReplayError, "staging path is too long"
            ):
                replay_module._validate_private_staging_paths([long_path])

            replay_module._validate_private_staging_paths([short_path])
            with mock.patch.object(
                replay_module.os.path, "abspath", return_value="x" * 259
            ):
                replay_module._validate_private_staging_paths([boundary_path])
            with mock.patch.object(
                replay_module.os.path, "abspath", return_value="x" * 260
            ), self.assertRaisesRegex(
                DeterministicPipelineReplayError, "staging path is too long"
            ):
                replay_module._validate_private_staging_paths([boundary_path])

    def test_child_failure_missing_or_symlink_output_is_stable_and_path_free(self):
        configurations = (
            {"returncode": 2},
            {"no_output": True},
            {"symlink_output": True},
        )
        for configuration in configurations:
            with self.subTest(configuration=configuration), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                plan, retained, report_raw, _roles = _write_case(root)
                command = _write_fake_pcbex(root, report_raw, **configuration)
                with self.assertRaises(DeterministicPipelineReplayError) as raised:
                    replay_deterministic_pipeline(plan, retained, command)
                self.assertNotIn(str(root), str(raised.exception))
                self.assertEqual(retained.read_bytes(), report_raw)

    def test_mutable_caller_pathlikes_are_frozen_once(self):
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
            plan, retained, report_raw, _roles = _write_case(root)
            decoy = str(root / "must-not-be-read")
            plan_path = FlippingPath(str(plan), decoy)
            report_path = FlippingPath(str(retained), decoy)
            result = replay_deterministic_pipeline(
                plan_path,
                report_path,
                _write_fake_pcbex(root, report_raw),
            )
            self.assertTrue(result["verified"])
            self.assertEqual(plan_path.calls, 1)
            self.assertEqual(report_path.calls, 1)

    def test_cli_routes_replay_and_enforces_approval_after_json_output(self):
        approved = {
            "schema_version": 1,
            "verification_scope": "deterministic-pipeline-fresh-replay-v1",
            "verified": True,
            "engine_version": "1.456.0-test",
            "plan": {},
            "report": {"approved": True},
            "inputs": {},
            "validation": {},
        }
        rejected = json.loads(json.dumps(approved))
        rejected["report"]["approved"] = False

        with mock.patch.object(
            sys,
            "argv",
            [
                "pcbex-agent",
                "replay-deterministic-pipeline",
                "plan.json",
                "retained.json",
                "--pcbex",
                "trusted-pcbex",
                "--timeout-seconds",
                "75.5",
            ],
        ), mock.patch.object(
            cli, "replay_deterministic_pipeline", return_value=approved
        ) as replay, io.StringIO() as output, redirect_stdout(output):
            cli.main()
            self.assertEqual(json.loads(output.getvalue()), approved)
        replay.assert_called_once_with(
            Path("plan.json"),
            Path("retained.json"),
            "trusted-pcbex",
            timeout_seconds=75.5,
        )

        with mock.patch.object(
            sys,
            "argv",
            [
                "pcbex-agent",
                "replay-deterministic-pipeline",
                "plan.json",
                "retained.json",
                "--require-approved",
            ],
        ), mock.patch.object(
            cli, "replay_deterministic_pipeline", return_value=rejected
        ), io.StringIO() as output, redirect_stdout(output):
            with self.assertRaises(SystemExit):
                cli.main()
            self.assertEqual(json.loads(output.getvalue()), rejected)

    def test_schema_cli_stdout_and_no_clobber(self):
        schema = deterministic_pipeline_replay_result_json_schema()
        with mock.patch.object(
            sys,
            "argv",
            ["pcbex-agent", "deterministic-pipeline-replay-result-schema"],
        ), io.StringIO() as output, redirect_stdout(output):
            cli.main()
            self.assertEqual(json.loads(output.getvalue()), schema)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            destination = root / "schema.json"
            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "deterministic-pipeline-replay-result-schema",
                    "--output",
                    str(destination),
                ],
            ):
                cli.main()
            self.assertEqual(json.loads(destination.read_text()), schema)
            original = destination.read_bytes()
            with mock.patch.object(
                sys,
                "argv",
                [
                    "pcbex-agent",
                    "deterministic-pipeline-replay-result-schema",
                    "--output",
                    str(destination),
                ],
            ), self.assertRaises(SystemExit):
                cli.main()
            self.assertEqual(destination.read_bytes(), original)

    @staticmethod
    def _output_path(argv: list[str]) -> Path:
        for index, value in enumerate(argv):
            if value == "--output" and index + 1 < len(argv):
                return Path(argv[index + 1])
            if value.startswith("--output="):
                return Path(value.split("=", 1)[1])
        raise AssertionError("child argv has no --output")

    @classmethod
    def _all_strings(cls, value: object) -> list[str]:
        if isinstance(value, dict):
            return [item for nested in value.values() for item in cls._all_strings(nested)]
        if isinstance(value, list):
            return [item for nested in value for item in cls._all_strings(nested)]
        return [value] if isinstance(value, str) else []


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
