from __future__ import annotations

from contextlib import redirect_stdout
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
except ImportError:  # pragma: no cover
    Draft202012Validator = None

from pcbex_agent import cli
from pcbex_agent import routing_drc_manufacturing_handoff as module
from pcbex_agent import routing_manufacturing_handoff as handoff_module
from pcbex_agent.routing_drc_manufacturing_handoff import (
    RoutingDrcManufacturingHandoffError,
    evaluate_routing_drc_manufacturing_handoff,
    render_routing_drc_manufacturing_handoff_report,
    routing_drc_manufacturing_handoff_report_json_schema,
)
from pcbex_agent.routing_manufacturing_handoff import (
    evaluate_routing_manufacturing_handoff,
    render_routing_manufacturing_handoff_report,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(raw: bytes) -> dict[str, object]:
    return {"bytes": len(raw), "sha256": _sha(raw)}


def _native_drc_report(
    board_raw: bytes,
    project_raw: bytes,
    rules_raw: bytes,
    *,
    approved: bool,
) -> bytes:
    findings: list[dict[str, object]] = []
    if not approved:
        findings.append(
            {
                "category": "violation",
                "description": "Clearance violation",
                "items": [
                    {
                        "description": "U1 pad 1",
                        "position_nm": {"x": 1_000_000, "y": 2_000_000},
                    }
                ],
                "severity": "error",
                "type": "clearance",
            }
        )
    report: dict[str, object] = {
        "schema_version": 1,
        "engine": "pcbex",
        "engine_version": "1.477.0-test",
        "kicad_version": "10.0.5",
        "source": _identity(board_raw),
        "project": _identity(project_raw),
        "rules_file": _identity(rules_raw),
        "invocation": {
            "command": "pcb drc",
            "format": "json",
            "units": "mm",
            "severities": ["error", "warning"],
            "exit_code_violations": True,
            "all_track_errors": False,
            "schematic_parity": False,
            "refill_zones": False,
            "save_board": False,
        },
        "ignored_checks": [],
        "findings": findings,
        "violation_count": 0 if approved else 1,
        "unconnected_item_count": 0,
        "schematic_parity_count": 0,
        "error_count": 0 if approved else 1,
        "warning_count": 0,
        "approved": approved,
    }
    report["run_sha256"] = _sha(
        b"pcbex/native-kicad-pcb-drc/v1\0"
        + json.dumps(report, separators=(",", ":")).encode()
    )
    return (json.dumps(report, separators=(",", ":")) + "\n").encode()


def _write_fake_pcbex(
    root: Path,
    *,
    package_raw: bytes,
    fresh_verification_raw: bytes,
    mutate: Path | None = None,
    forged_summary: bool = False,
    summary_override: dict[str, object] | None = None,
) -> list[str]:
    (root / "fake-package.bin").write_bytes(package_raw)
    (root / "fresh-verification.bin").write_bytes(fresh_verification_raw)
    (root / "fake-config.json").write_text(
        json.dumps(
            {
                "mutate": None if mutate is None else str(mutate),
                "forged_summary": forged_summary,
                "summary_override": summary_override or {},
            }
        ),
        encoding="utf-8",
    )
    wrapper = root / "fake-pcbex.py"
    wrapper.write_text(
        r'''from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).parent
config = json.loads((root / "fake-config.json").read_text(encoding="utf-8"))
argv = sys.argv[1:]
calls_path = root / "calls.json"
calls = json.loads(calls_path.read_text(encoding="utf-8")) if calls_path.exists() else []
calls.append(argv)
calls_path.write_text(json.dumps(calls), encoding="utf-8")

def option(name: str) -> str | None:
    prefix = "--" + name + "="
    for index, value in enumerate(argv):
        if value.startswith(prefix):
            return value[len(prefix):]
        if value == "--" + name and index + 1 < len(argv):
            return argv[index + 1]
    return None

if argv and argv[0] == "verify-kicad-routing-convergence":
    Path(option("output")).write_bytes((root / "fresh-verification.bin").read_bytes())
    raise SystemExit(0)

if argv and argv[0] == "fabricate":
    output = Path(option("output-dir"))
    output.mkdir()
    (output / "manufacturing.zip").write_bytes((root / "fake-package.bin").read_bytes())
    raise SystemExit(0)

if argv and argv[0] == "verify-native-kicad-drc-report":
    raw = Path(argv[2]).read_bytes()
    report = json.loads(raw)
    def companion(prefix: str, value):
        return {
            prefix + "_bytes": "" if value is None else value["bytes"],
            prefix + "_sha256": "" if value is None else value["sha256"],
        }
    summary = {
        "schema_version": 1,
        "approved": report["approved"],
        "violation_count": report["violation_count"],
        "unconnected_item_count": report["unconnected_item_count"],
        "schematic_parity_count": report["schematic_parity_count"],
        "error_count": report["error_count"],
        "warning_count": report["warning_count"],
        "ignored_check_count": len(report["ignored_checks"]),
        "board_bytes": report["source"]["bytes"],
        "board_sha256": report["source"]["sha256"],
        **companion("project", report["project"]),
        **companion("rules_file", report["rules_file"]),
        "run_sha256": report["run_sha256"],
        "report_bytes": len(raw),
        "report_sha256": hashlib.sha256(raw).hexdigest(),
    }
    if config["forged_summary"]:
        summary["board_sha256"] = "0" * 64
    summary.update(config["summary_override"])
    sys.stdout.buffer.write(
        (json.dumps(summary, separators=(",", ":")) + "\n").encode("utf-8")
    )
    mutation = config["mutate"]
    if mutation:
        path = Path(mutation)
        path.write_bytes(path.read_bytes() + b"changed")
    raise SystemExit(0)

raise SystemExit(91)
''',
        encoding="utf-8",
    )
    return [sys.executable, str(wrapper)]


class RoutingDrcManufacturingHandoffTests(unittest.TestCase):
    def _sources(
        self,
        root: Path,
        *,
        routing_complete: bool = True,
        drc_approved: bool = True,
    ) -> dict[str, object]:
        input_board = root / "controller.placed.kicad_pcb"
        routed_board = root / "controller.routed.kicad_pcb"
        convergence = root / "routing-convergence.json"
        verification = root / "routing-verification.json"
        package = root / "manufacturing.zip"
        project = root / "controller.kicad_pro"
        rules = root / "controller.kicad_dru"
        profile = root / "factory-profile.json"
        handoff = root / "routing-manufacturing.json"
        native_drc = root / "native-drc.json"
        input_raw = b"(kicad_pcb (version 20240108) (generator pcbex-input))\n"
        routed_raw = b"(kicad_pcb (version 20240108) (generator pcbex-routed))\n"
        convergence_raw = b'{"schema_version":1,"fixture":"convergence"}\n'
        package_raw = b"PK\x03\x04exact-manufacturing-package"
        project_raw = b'{"board": {}}\n'
        rules_raw = b"(version 1)\n"
        profile_raw = b'{"schema_version":1,"id":"fixture"}\n'
        for path, raw in (
            (input_board, input_raw),
            (routed_board, routed_raw),
            (convergence, convergence_raw),
            (package, package_raw),
            (project, project_raw),
            (rules, rules_raw),
            (profile, profile_raw),
        ):
            path.write_bytes(raw)

        status = "verified_complete" if routing_complete else "verified_partial"
        convergence_status = "converged" if routing_complete else "partial"
        routing_report: dict[str, object] = {
            "schema_version": 1,
            "scope": "fresh_exact_routing_convergence_verification",
            "engine_version": "1.475.0-test",
            "input_kind": "kicad_pcb",
            "status": status,
            "routing_complete": routing_complete,
            "source_authenticity_verified": False,
            "native_kicad_drc_verified": False,
            "manufacturability_verified": False,
            "release_authorized": False,
            "built_in_dfm_profile": None,
            "sources": {
                "input": _identity(input_raw),
                "routed_output": _identity(routed_raw),
                "retained_report": _identity(convergence_raw),
                "project": _identity(project_raw),
                "rules_file": _identity(rules_raw),
                "fab_profile": _identity(profile_raw),
                "policy_pack": None,
                "physical_profile": None,
            },
            "convergence": {
                "status": convergence_status,
                "converged": routing_complete,
                "final_metrics": {"unrouted_nets": 0 if routing_complete else 1},
                "final_drc_violation_count": 0,
            },
            "validation": {
                "source_closure_captured": True,
                "retained_report_canonical": True,
                "fresh_convergence_replayed": True,
                "retained_report_exact": True,
                "routed_output_exact": True,
                "caller_inputs_unchanged": True,
            },
            "binding_sha256": "",
        }
        routing_report["binding_sha256"] = handoff_module._routing_binding(
            routing_report
        )
        verification_raw = (
            json.dumps(routing_report, indent=2, ensure_ascii=False) + "\n"
        ).encode()
        verification.write_bytes(verification_raw)
        native_drc.write_bytes(
            _native_drc_report(
                routed_raw,
                project_raw,
                rules_raw,
                approved=drc_approved,
            )
        )
        return {
            "input": input_board,
            "routed": routed_board,
            "convergence": convergence,
            "verification": verification,
            "package": package,
            "project": project,
            "rules": rules,
            "profile": profile,
            "handoff": handoff,
            "native_drc": native_drc,
            "package_raw": package_raw,
            "verification_raw": verification_raw,
        }

    def _prepare(
        self,
        root: Path,
        *,
        routing_complete: bool = True,
        drc_approved: bool = True,
        mutate: Path | None = None,
        forged_summary: bool = False,
        summary_override: dict[str, object] | None = None,
    ) -> tuple[dict[str, object], list[str]]:
        sources = self._sources(
            root,
            routing_complete=routing_complete,
            drc_approved=drc_approved,
        )
        command = _write_fake_pcbex(
            root,
            package_raw=sources["package_raw"],
            fresh_verification_raw=sources["verification_raw"],
            mutate=mutate,
            forged_summary=forged_summary,
            summary_override=summary_override,
        )
        handoff = evaluate_routing_manufacturing_handoff(
            sources["input"],
            sources["routed"],
            sources["convergence"],
            sources["verification"],
            sources["package"],
            command,
            kicad_project=sources["project"],
            kicad_rules=sources["rules"],
            fab_profile=sources["profile"],
        )
        sources["handoff"].write_bytes(
            render_routing_manufacturing_handoff_report(handoff)
        )
        calls = root / "calls.json"
        if calls.exists():
            calls.unlink()
        return sources, command

    def _evaluate(self, sources: dict[str, object], command: list[str]):
        return evaluate_routing_drc_manufacturing_handoff(
            sources["input"],
            sources["routed"],
            sources["convergence"],
            sources["verification"],
            sources["package"],
            sources["handoff"],
            sources["native_drc"],
            command,
            kicad_project=sources["project"],
            kicad_rules=sources["rules"],
            fab_profile=sources["profile"],
        )

    def test_positive_replays_handoff_and_native_drc_on_one_board(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, command = self._prepare(root)
            result = self._evaluate(sources, command)
            self.assertEqual(result["status"], "verified_ready")
            self.assertTrue(result["ready"])
            self.assertTrue(result["native_kicad_drc_verified"])
            self.assertEqual(result["gate_failures"], [])
            self.assertEqual(
                result["native_kicad_drc"]["source"],
                result["sources"]["routed_board"],
            )
            self.assertEqual(
                result["routing_manufacturing_handoff"]["sources"][
                    "manufacturing_package"
                ],
                result["sources"]["manufacturing_package"],
            )
            for claim in (
                "source_authenticity_verified",
                "manufacturability_verified",
                "fabrication_authorized",
                "release_authorized",
            ):
                self.assertFalse(result[claim])
            rendered = render_routing_drc_manufacturing_handoff_report(result)
            self.assertEqual(rendered[-1:], b"\n")
            self.assertNotIn(str(root).encode(), rendered)
            calls = json.loads((root / "calls.json").read_text(encoding="utf-8"))
            self.assertEqual(
                [call[0] for call in calls],
                [
                    "verify-kicad-routing-convergence",
                    "fabricate",
                    "verify-native-kicad-drc-report",
                ],
            )
            if Draft202012Validator is not None:
                Draft202012Validator(
                    routing_drc_manufacturing_handoff_report_json_schema()
                ).validate(result)

    def test_native_drc_rejection_is_retained_not_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, command = self._prepare(root, drc_approved=False)
            result = self._evaluate(sources, command)
            self.assertEqual(result["status"], "not_ready")
            self.assertFalse(result["ready"])
            self.assertFalse(result["native_kicad_drc_verified"])
            self.assertEqual(result["gate_failures"], ["native_drc_rejected"])
            self.assertFalse(result["native_kicad_drc"]["approved"])
            self.assertTrue(result["validation"]["native_kicad_drc_replayed"])
            if Draft202012Validator is not None:
                validator = Draft202012Validator(
                    routing_drc_manufacturing_handoff_report_json_schema()
                )
                validator.validate(result)
                forged = json.loads(
                    render_routing_drc_manufacturing_handoff_report(result)
                )
                forged["gate_failures"] = ["routing_incomplete"]
                self.assertTrue(list(validator.iter_errors(forged)))

    def test_incomplete_routing_skips_native_drc(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, command = self._prepare(root, routing_complete=False)
            result = self._evaluate(sources, command)
            self.assertEqual(result["gate_failures"], ["routing_incomplete"])
            self.assertIsNone(result["native_kicad_drc"])
            self.assertFalse(result["validation"]["native_kicad_drc_replayed"])
            calls = json.loads((root / "calls.json").read_text(encoding="utf-8"))
            self.assertEqual(
                [call[0] for call in calls],
                ["verify-kicad-routing-convergence"],
            )
            if Draft202012Validator is not None:
                Draft202012Validator(
                    routing_drc_manufacturing_handoff_report_json_schema()
                ).validate(result)

    def test_summary_types_and_native_finding_discriminators_are_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, command = self._prepare(
                root,
                summary_override={"error_count": False},
            )
            with self.assertRaisesRegex(
                RoutingDrcManufacturingHandoffError,
                "summary counts are inconsistent",
            ):
                self._evaluate(sources, command)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, command = self._prepare(root, drc_approved=False)
            report = json.loads(sources["native_drc"].read_bytes())
            report["findings"][0]["category"] = []
            sources["native_drc"].write_bytes(
                (json.dumps(report, separators=(",", ":")) + "\n").encode()
            )
            with self.assertRaisesRegex(
                RoutingDrcManufacturingHandoffError,
                "finding category is invalid",
            ):
                self._evaluate(sources, command)

    def test_backwards_clock_and_cwd_changing_path_hook_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, command = self._prepare(root)
            samples = iter((10.0, 9.0))
            with self.assertRaisesRegex(
                RoutingDrcManufacturingHandoffError,
                "clock moved backwards",
            ):
                evaluate_routing_drc_manufacturing_handoff(
                    sources["input"],
                    sources["routed"],
                    sources["convergence"],
                    sources["verification"],
                    sources["package"],
                    sources["handoff"],
                    sources["native_drc"],
                    command,
                    kicad_project=sources["project"],
                    kicad_rules=sources["rules"],
                    fab_profile=sources["profile"],
                    _clock=lambda: next(samples),
                )

        class ChangingPath:
            def __init__(self, rendered: Path, destination: Path):
                self.rendered = rendered
                self.destination = destination

            def __fspath__(self) -> str:
                os.chdir(self.destination)
                return str(self.rendered)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, command = self._prepare(root)
            entry = Path.cwd()
            with self.assertRaisesRegex(
                RoutingDrcManufacturingHandoffError,
                "changed the working directory",
            ):
                evaluate_routing_drc_manufacturing_handoff(
                    ChangingPath(sources["input"], root),
                    sources["routed"],
                    sources["convergence"],
                    sources["verification"],
                    sources["package"],
                    sources["handoff"],
                    sources["native_drc"],
                    command,
                    kicad_project=sources["project"],
                    kicad_rules=sources["rules"],
                    fab_profile=sources["profile"],
                )
            self.assertEqual(Path.cwd(), entry)

    def test_native_drc_sidecar_cross_binding_is_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, command = self._prepare(root)
            sources["native_drc"].write_bytes(
                _native_drc_report(
                    sources["routed"].read_bytes(),
                    b'{"different":true}\n',
                    sources["rules"].read_bytes(),
                    approved=True,
                )
            )
            with self.assertRaisesRegex(
                RoutingDrcManufacturingHandoffError,
                "project does not match",
            ):
                self._evaluate(sources, command)

    def test_retained_handoff_and_drc_summary_substitution_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, command = self._prepare(root)
            raw = bytearray(sources["handoff"].read_bytes())
            raw[-3] = ord("1") if raw[-3] != ord("1") else ord("2")
            sources["handoff"].write_bytes(raw)
            with self.assertRaises(RoutingDrcManufacturingHandoffError):
                self._evaluate(sources, command)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, command = self._prepare(root, forged_summary=True)
            with self.assertRaisesRegex(
                RoutingDrcManufacturingHandoffError, "summary is inconsistent"
            ):
                self._evaluate(sources, command)

    def test_source_mutation_and_alias_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, command = self._prepare(root)
            (root / "fake-config.json").write_text(
                json.dumps(
                    {
                        "mutate": str(sources["package"]),
                        "forged_summary": False,
                        "summary_override": {},
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RoutingDrcManufacturingHandoffError, "source changed"
            ):
                self._evaluate(sources, command)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, command = self._prepare(root)
            with self.assertRaisesRegex(
                RoutingDrcManufacturingHandoffError, "must not alias"
            ):
                evaluate_routing_drc_manufacturing_handoff(
                    sources["input"],
                    sources["routed"],
                    sources["convergence"],
                    sources["verification"],
                    sources["package"],
                    sources["handoff"],
                    sources["handoff"],
                    command,
                    kicad_project=sources["project"],
                    kicad_rules=sources["rules"],
                    fab_profile=sources["profile"],
                )

    def test_renderer_binding_and_schema_are_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, command = self._prepare(root)
            result = self._evaluate(sources, command)
            forged = json.loads(
                render_routing_drc_manufacturing_handoff_report(result)
            )
            forged["native_kicad_drc"]["approved"] = False
            with self.assertRaises(RoutingDrcManufacturingHandoffError):
                render_routing_drc_manufacturing_handoff_report(forged)

        schema = routing_drc_manufacturing_handoff_report_json_schema()
        objects = 0
        arrays = 0
        stack = [schema]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                if value.get("type") == "object":
                    objects += 1
                    self.assertFalse(value.get("additionalProperties", True))
                if value.get("type") == "array":
                    arrays += 1
                    self.assertIn("maxItems", value)
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
        self.assertGreaterEqual(objects, 7)
        self.assertGreaterEqual(arrays, 1)

    def test_cli_retains_negative_before_require_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, command = self._prepare(root, drc_approved=False)
            negative = self._evaluate(sources, command)
            output = root / "result.json"
            argv = [
                "pcbex-agent",
                "replay-routing-drc-manufacturing-handoff",
                str(sources["input"]),
                str(sources["routed"]),
                "--convergence-report",
                str(sources["convergence"]),
                "--routing-verification-report",
                str(sources["verification"]),
                "--manufacturing-package",
                str(sources["package"]),
                "--routing-manufacturing-handoff-report",
                str(sources["handoff"]),
                "--native-drc-report",
                str(sources["native_drc"]),
                "--kicad-project",
                str(sources["project"]),
                "--kicad-rules",
                str(sources["rules"]),
                "--fab-profile",
                str(sources["profile"]),
                "--output",
                str(output),
                "--require-ready",
            ]
            with mock.patch.object(
                cli,
                "evaluate_routing_drc_manufacturing_handoff",
                return_value=negative,
            ), mock.patch.object(sys, "argv", argv), self.assertRaisesRegex(
                SystemExit, "was retained but is not ready"
            ):
                cli.main()
            self.assertEqual(
                output.read_bytes(),
                render_routing_drc_manufacturing_handoff_report(negative),
            )

    def test_schema_cli_stdout_and_no_clobber(self):
        stdout = io.StringIO()
        with mock.patch.object(
            sys,
            "argv",
            ["pcbex-agent", "routing-drc-manufacturing-handoff-report-schema"],
        ), redirect_stdout(stdout):
            cli.main()
        self.assertEqual(
            json.loads(stdout.getvalue()),
            routing_drc_manufacturing_handoff_report_json_schema(),
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve(strict=True) / "schema.json"
            argv = [
                "pcbex-agent",
                "routing-drc-manufacturing-handoff-report-schema",
                "--output",
                str(output),
            ]
            with mock.patch.object(sys, "argv", argv):
                cli.main()
            before = output.read_bytes()
            with mock.patch.object(sys, "argv", argv), self.assertRaises(SystemExit):
                cli.main()
            self.assertEqual(output.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
