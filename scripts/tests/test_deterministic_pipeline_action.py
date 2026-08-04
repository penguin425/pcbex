"""Regression tests for the deterministic pipeline composite-action bridge.

The Rust runner owns the plan and report contracts.  This test module exercises
the shell/Action boundary with a fake executable so that malformed child
summaries, stale files, and unsafe plan paths cannot accidentally become a
successful Action output.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
ANALYSIS_SCRIPT = ROOT / "scripts" / "github-analysis.sh"

DETERMINISTIC_OUTPUTS = (
    "deterministic-pipeline-report",
    "deterministic-pipeline-schema-version",
    "deterministic-pipeline-approved",
    "deterministic-pipeline-plan-sha256",
    "deterministic-pipeline-run-sha256",
    "deterministic-pipeline-failure-count",
    "deterministic-pipeline-report-bytes",
    "deterministic-pipeline-report-sha256",
)

AI_ARTIFACT_OUTPUTS = (
    "ai-review-artifacts-verified",
    "ai-review-generated-schematic-bytes",
    "ai-review-generated-schematic-sha256",
    "ai-review-pipeline-plan-source-bytes",
    "ai-review-pipeline-plan-source-sha256",
    "ai-review-pipeline-plan-sha256",
    "ai-review-pipeline-report-bytes",
    "ai-review-pipeline-report-sha256",
    "ai-review-pipeline-run-sha256",
    "ai-review-native-kicad-erc-report-bytes",
    "ai-review-native-kicad-erc-report-sha256",
    "ai-review-native-kicad-erc-run-sha256",
)

REPORT_KEYS = {
    "schema_version",
    "engine_version",
    "plan_source_bytes",
    "plan_source_sha256",
    "plan_sha256",
    "input_evidence",
    "binding",
    "pipeline",
    "failures",
    "approved",
    "run_sha256",
}


class DeterministicPipelineActionTests(unittest.TestCase):
    @staticmethod
    def _write_fake_binary(path: Path) -> None:
        """Write a deterministic fake pcbex executable used by shell tests."""

        path.write_text(
            textwrap.dedent(
                r"""
                #!/usr/bin/env python3
                import hashlib
                import json
                import os
                from pathlib import Path
                import sys

                arguments = Path(os.environ["PCBEX_TEST_ARGUMENTS"])
                with arguments.open("a", encoding="utf-8") as stream:
                    stream.write("COMMAND=" + (sys.argv[1] if len(sys.argv) > 1 else "") + "\n")
                    stream.write("\n".join(sys.argv[1:]) + "\n")

                command = sys.argv[1] if len(sys.argv) > 1 else ""
                if command == "analyze-kicad":
                    output_dir = Path(sys.argv[sys.argv.index("--output-dir") + 1])
                    output_dir.mkdir(parents=True, exist_ok=True)
                    (output_dir / "run.json").write_text(
                        '{"result":{"violations":0}}\n', encoding="utf-8"
                    )
                    (output_dir / "checks.json").write_text("{}\n", encoding="utf-8")
                    (output_dir / "quality.json").write_text("{}\n", encoding="utf-8")
                    (output_dir / "report.sarif").write_text("{}\n", encoding="utf-8")
                    (output_dir / "summary.md").write_text("ok\n", encoding="utf-8")
                    if os.environ.get("PCBEX_DETERMINISTIC_PIPELINE_TEST_MODE") == "plant-stale":
                        (output_dir.parent / "deterministic-pipeline-report.json").write_bytes(
                            b"stale report planted by analyze\n"
                        )
                    raise SystemExit(0)

                if command == "verify-ai-quorum":
                    output = Path(sys.argv[sys.argv.index("--output") + 1])
                    summary = Path(sys.argv[sys.argv.index("--summary-output") + 1])
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text('{"quorum_met":true}\n', encoding="utf-8")
                    summary.write_text("quorum ok\n", encoding="utf-8")
                    raise SystemExit(0)

                if command != "run-deterministic-pipeline":
                    raise SystemExit(0)

                output = Path(sys.argv[sys.argv.index("--output") + 1])
                mode = os.environ.get("PCBEX_DETERMINISTIC_PIPELINE_TEST_MODE", "approved")
                if mode == "no-report":
                    raise SystemExit(int(os.environ.get("PCBEX_DETERMINISTIC_PIPELINE_TEST_EXIT", "0")))

                failures = [] if mode == "approved" else ["synthetic deterministic failure"]
                approved = not failures
                report = {
                    "schema_version": 1,
                    "engine_version": "1.419.0-test",
                    "plan_source_bytes": 128,
                    "plan_source_sha256": "1" * 64,
                    "plan_sha256": "a" * 64,
                    "input_evidence": [],
                    "binding": None,
                    "pipeline": None,
                    "failures": failures,
                    "approved": approved,
                    "run_sha256": "b" * 64,
                }
                if mode == "bad-report-top-level":
                    report.pop("run_sha256")
                report_bytes = (json.dumps(report, separators=(",", ":")) + "\n").encode()
                if mode == "bad-report-duplicate":
                    report_bytes = (
                        b'{"schema_version":1,"engine_version":"1.419.0-test",'
                        b'"plan_source_bytes":128,"plan_source_sha256":"'
                        + b"1" * 64
                        + b'","plan_sha256":"'
                        + b"a" * 64
                        + b'","input_evidence":[],"binding":null,"pipeline":null,'
                        b'"failures":[],"approved":true,"approved":true,"run_sha256":"'
                        + b"b" * 64
                        + b'"}\n'
                    )
                output.parent.mkdir(parents=True, exist_ok=True)
                if mode == "report-symlink":
                    target = output.with_name("report-target.json")
                    target.write_bytes(report_bytes)
                    output.symlink_to(target)
                elif mode == "report-directory":
                    output.mkdir()
                elif mode == "report-oversize":
                    output.touch()
                    with output.open("r+b") as stream:
                        stream.truncate(128 * 1024 * 1024 + 1)
                else:
                    output.write_bytes(report_bytes)

                summary = {
                    "schema_version": report["schema_version"],
                    "approved": report["approved"],
                    "plan_sha256": report["plan_sha256"],
                    "run_sha256": report.get("run_sha256", "b" * 64),
                    "failure_count": len(report["failures"]),
                    "report_bytes": len(report_bytes),
                    "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
                }
                if mode == "summary-duplicate":
                    rendered = (
                        '{"schema_version":1,"approved":true,"approved":false,'
                        '"plan_sha256":"' + "a" * 64 + '","run_sha256":"' + "b" * 64
                        + '","failure_count":0,"report_bytes":' + str(len(report_bytes))
                        + ',"report_sha256":"' + hashlib.sha256(report_bytes).hexdigest() + '"}'
                    )
                else:
                    malformed = {
                        "summary-extra": lambda: summary | {"extra": True},
                        "summary-missing": lambda: {key: value for key, value in summary.items() if key != "run_sha256"},
                        "summary-approved-type": lambda: summary | {"approved": "true"},
                        "summary-schema-type": lambda: summary | {"schema_version": True},
                        "summary-failure-type": lambda: summary | {"failure_count": "0"},
                        "summary-report-bytes-zero": lambda: summary | {"report_bytes": 0},
                        "summary-report-bytes-bound": lambda: summary | {"report_bytes": 128 * 1024 * 1024 + 1},
                        "summary-failure-bound": lambda: summary | {"failure_count": 129},
                        "summary-uppercase-sha": lambda: summary | {"plan_sha256": "A" * 64},
                        "summary-short-sha": lambda: summary | {"run_sha256": "b" * 63},
                        "summary-bad-report-sha": lambda: summary | {"report_sha256": "c" * 64},
                        "summary-bad-report-bytes": lambda: summary | {"report_bytes": len(report_bytes) + 1},
                        "summary-bad-plan": lambda: summary | {"plan_sha256": "c" * 64},
                        "summary-bad-run": lambda: summary | {"run_sha256": "c" * 64},
                        "summary-bad-failure-count": lambda: summary | {"failure_count": 0 if failures else 1},
                        "summary-bad-approved": lambda: summary | {"approved": not approved},
                    }.get(mode)
                    if mode == "summary-malformed":
                        rendered = "{not-json"
                    elif malformed is not None:
                        rendered = json.dumps(malformed(), separators=(",", ":"))
                    else:
                        rendered = json.dumps(summary, separators=(",", ":"))
                        if mode == "summary-trailing":
                            rendered += "\ntrailing"

                if "--mcp-echo-report-summary" in sys.argv:
                    if mode == "summary-utf8":
                        sys.stdout.buffer.write(b"\xff\n")
                    elif mode == "summary-oversize":
                        sys.stdout.buffer.write(b"x" * (4 * 1024 + 1))
                    else:
                        print(rendered)
                raise SystemExit(int(os.environ.get("PCBEX_DETERMINISTIC_PIPELINE_TEST_EXIT", "0")))
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    @staticmethod
    def _sha256(payload: bytes) -> str:
        return hashlib.sha256(payload).hexdigest()

    @classmethod
    def _descriptor(cls, root: Path, path: Path) -> dict[str, object]:
        payload = path.read_bytes()
        return {
            "path": path.relative_to(root).as_posix(),
            "bytes": len(payload),
            "sha256": cls._sha256(payload),
        }

    @classmethod
    def _write_plan(cls, root: Path) -> Path:
        files = {
            "circuit.json": b"{}\n",
            "design.kicad_sch": b"(kicad_sch)\n",
            "electrical-review.json": b"{}\n",
            "board.kicad_pcb": b"(kicad_pcb)\n",
            "analysis-manifest.json": b"{}\n",
            "analysis-checks.json": b"{}\n",
            "quality.json": b"{}\n",
            "manufacturing.zip": b"PK\x03\x04\n",
        }
        for name, payload in files.items():
            (root / name).write_bytes(payload)

        firmware = root / "firmware"
        firmware.mkdir()
        artifact_names = (
            "pinout.h",
            "firmware.h",
            "firmware.c",
            "firmware_smoke_test.c",
            "firmware.cpp",
            "firmware_cpp_smoke_test.cpp",
            "host.py",
        )
        for index, name in enumerate(artifact_names):
            (firmware / name).write_bytes(f"artifact-{index}\n".encode())
        manifest = {
            "schema_version": 2,
            "engine": "pcbex",
            "engine_version": "1.419.0-test",
            "schematic_sha256": "0" * 64,
            "artifacts": [
                cls._descriptor(root, firmware / name) for name in artifact_names
            ],
        }
        (firmware / "manifest.json").write_text(
            json.dumps(manifest, separators=(",", ":")) + "\n", encoding="utf-8"
        )

        descriptor = lambda name: cls._descriptor(root, root / name)
        plan = {
            "schema_version": 1,
            "circuit_spec": descriptor("circuit.json"),
            "schematic": descriptor("design.kicad_sch"),
            "electrical_policy": None,
            "electrical_review": descriptor("electrical-review.json"),
            "board": descriptor("board.kicad_pcb"),
            "analysis_manifest": descriptor("analysis-manifest.json"),
            "analysis_checks": descriptor("analysis-checks.json"),
            "quality": descriptor("quality.json"),
            "analysis_project": None,
            "analysis_rules": None,
            "analysis_dfm_profile": None,
            "analysis_policy_pack": None,
            "analysis_physical_profile": None,
            "manufacturing_package": descriptor("manufacturing.zip"),
            "firmware_manifest": descriptor("firmware/manifest.json"),
            "factory_receipt": None,
            "require_factory": False,
        }
        path = root / "plan.json"
        path.write_text(json.dumps(plan, separators=(",", ":")) + "\n", encoding="utf-8")
        return path

    @classmethod
    def _run_script(
        cls,
        root: Path,
        fake_binary: Path,
        *,
        plan: str = "plan.json",
        require_approved: str = "false",
        mode: str = "approved",
        pipeline_verify: str = "false",
        extra: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GITHUB_ACTION_PATH": str(ROOT),
            "GITHUB_OUTPUT": str(root / "github-output"),
            "GITHUB_STEP_SUMMARY": str(root / "step-summary"),
            "PCBEX_BINARY": str(fake_binary),
            "PCBEX_BOARD": "board.kicad_pcb",
            "PCBEX_OUTPUT_DIR": "artifacts",
            "PCBEX_PIPELINE_VERIFY": pipeline_verify,
            "PCBEX_DETERMINISTIC_PIPELINE_PLAN": plan,
            "PCBEX_DETERMINISTIC_PIPELINE_REQUIRE_APPROVED": require_approved,
            "PCBEX_DETERMINISTIC_PIPELINE_TEST_MODE": mode,
            "PCBEX_TEST_ARGUMENTS": str(root / "arguments"),
        }
        if extra:
            env.update(extra)
        return subprocess.run(
            ["bash", str(ANALYSIS_SCRIPT)],
            cwd=root,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def _outputs(path: Path) -> dict[str, str]:
        if not path.exists():
            return {}
        lines = path.read_text(encoding="utf-8").splitlines()
        return dict(line.split("=", 1) for line in lines if "=" in line)

    @staticmethod
    def _commands(root: Path) -> list[str]:
        if not (root / "arguments").exists():
            return []
        return [
            line.removeprefix("COMMAND=")
            for line in (root / "arguments").read_text(encoding="utf-8").splitlines()
            if line.startswith("COMMAND=")
        ]

    def _prepare_fixture(self) -> tuple[Path, Path]:
        raw = tempfile.TemporaryDirectory(prefix="pcbex-deterministic-action-")
        self.addCleanup(raw.cleanup)
        root = Path(raw.name)
        fake_binary = root / "fake-pcbex"
        self._write_fake_binary(fake_binary)
        self._write_plan(root)
        (root / "native-erc-report.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "engine_version": "10.0.5-test",
                    "approved": True,
                    "violations": [],
                    "run_sha256": "c" * 64,
                },
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        return root, fake_binary

    def _valid_run(
        self,
        *,
        require_approved: str = "false",
        mode: str = "approved",
        plan: str = "plan.json",
        pipeline_verify: str = "false",
        extra: dict[str, str] | None = None,
    ) -> tuple[Path, subprocess.CompletedProcess[str], dict[str, str]]:
        root, fake_binary = self._prepare_fixture()
        result = self._run_script(
            root,
            fake_binary,
            plan=plan,
            require_approved=require_approved,
            mode=mode,
            pipeline_verify=pipeline_verify,
            extra=extra,
        )
        return root, result, self._outputs(root / "github-output")

    def test_action_declares_deterministic_inputs_outputs_and_summary_bridge(self):
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn("  deterministic-pipeline-plan:\n", action)
        self.assertIn("  deterministic-pipeline-require-approved:\n", action)
        self.assertIn("  ai-review-generated-schematic:\n", action)
        self.assertIn("  ai-review-native-kicad-erc-report:\n", action)
        self.assertIn("  ai-review-kicad-cli:\n", action)
        self.assertIn("PCBEX_AI_REVIEW_GENERATED_SCHEMATIC", action)
        self.assertIn("PCBEX_AI_REVIEW_NATIVE_KICAD_ERC_REPORT", action)
        self.assertIn("PCBEX_AI_REVIEW_KICAD_CLI", action)
        for name in DETERMINISTIC_OUTPUTS:
            self.assertIn(f"  {name}:\n", action)
        for name in AI_ARTIFACT_OUTPUTS:
            self.assertIn(f"  {name}:\n", action)
        script = ANALYSIS_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("PCBEX_DETERMINISTIC_PIPELINE_PLAN", script)
        self.assertIn("run-deterministic-pipeline", script)
        self.assertIn("--mcp-echo-report-summary", script)
        self.assertIn("deterministic_pipeline_summary.py", script)

    def test_disabled_runner_does_not_invoke_child_and_clears_outputs(self):
        root, result, outputs = self._valid_run(plan="", mode="approved")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._commands(root), ["analyze-kicad"])
        for name in DETERMINISTIC_OUTPUTS:
            self.assertEqual(outputs.get(name), "", name)

    def test_bound_ai_quorum_runs_after_fresh_runner_and_forwards_exact_artifact_flags(self):
        root, fake_binary = self._prepare_fixture()
        result = self._run_script(
            root,
            fake_binary,
            extra={
                "PCBEX_POLICY_PACK": "policy-pack.json",
                "PCBEX_AI_REVIEW_REQUEST": "request.json",
                "PCBEX_AI_APPROVAL_FILES": "approval.json",
                "PCBEX_AI_RESPONSE_FILES": "response.json",
                "PCBEX_AI_REVIEW_GENERATED_SCHEMATIC": "design.kicad_sch",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self._commands(root),
            ["analyze-kicad", "run-deterministic-pipeline", "verify-ai-quorum"],
        )
        arguments = (root / "arguments").read_text(encoding="utf-8").splitlines()
        self.assertIn("--require-approved", arguments)
        self.assertIn("--generated-schematic", arguments)
        self.assertIn("design.kicad_sch", arguments)
        self.assertIn("--deterministic-pipeline-plan", arguments)
        self.assertIn("plan.json", arguments)
        self.assertIn("--deterministic-pipeline-report", arguments)
        self.assertIn("artifacts/deterministic-pipeline-report.json", arguments)
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs["ai-review-artifacts-verified"], "true")
        schematic_bytes = (root / "design.kicad_sch").read_bytes()
        plan_bytes = (root / "plan.json").read_bytes()
        report_bytes = (
            root / "artifacts/deterministic-pipeline-report.json"
        ).read_bytes()
        self.assertEqual(
            outputs["ai-review-generated-schematic-bytes"],
            str(len(schematic_bytes)),
        )
        self.assertEqual(
            outputs["ai-review-generated-schematic-sha256"],
            self._sha256(schematic_bytes),
        )
        self.assertEqual(
            outputs["ai-review-pipeline-plan-source-bytes"], str(len(plan_bytes))
        )
        self.assertEqual(
            outputs["ai-review-pipeline-plan-source-sha256"],
            self._sha256(plan_bytes),
        )
        self.assertEqual(outputs["ai-review-pipeline-plan-sha256"], "a" * 64)
        self.assertEqual(
            outputs["ai-review-pipeline-report-bytes"], str(len(report_bytes))
        )
        self.assertEqual(
            outputs["ai-review-pipeline-report-sha256"],
            self._sha256(report_bytes),
        )
        self.assertEqual(outputs["ai-review-pipeline-run-sha256"], "b" * 64)

    def test_native_kicad_erc_binding_forwards_cli_and_publishes_exact_identities(self):
        root, fake_binary = self._prepare_fixture()
        result = self._run_script(
            root,
            fake_binary,
            extra={
                "PCBEX_POLICY_PACK": "policy-pack.json",
                "PCBEX_AI_REVIEW_REQUEST": "request.json",
                "PCBEX_AI_APPROVAL_FILES": "approval.json",
                "PCBEX_AI_RESPONSE_FILES": "response.json",
                "PCBEX_AI_REVIEW_GENERATED_SCHEMATIC": "design.kicad_sch",
                "PCBEX_AI_REVIEW_NATIVE_KICAD_ERC_REPORT": "native-erc-report.json",
                "PCBEX_AI_REVIEW_KICAD_CLI": "kicad-cli-10",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self._commands(root),
            ["analyze-kicad", "run-deterministic-pipeline", "verify-ai-quorum"],
        )
        arguments = (root / "arguments").read_text(encoding="utf-8").splitlines()
        native_index = arguments.index("--native-kicad-erc-report")
        self.assertEqual(arguments[native_index + 1], "native-erc-report.json")
        self.assertEqual(arguments[native_index + 2], "--kicad-cli")
        self.assertEqual(arguments[native_index + 3], "kicad-cli-10")
        report_bytes = (root / "native-erc-report.json").read_bytes()
        outputs = self._outputs(root / "github-output")
        self.assertEqual(
            outputs["ai-review-native-kicad-erc-report-bytes"], str(len(report_bytes))
        )
        self.assertEqual(
            outputs["ai-review-native-kicad-erc-report-sha256"],
            self._sha256(report_bytes),
        )
        self.assertEqual(outputs["ai-review-native-kicad-erc-run-sha256"], "c" * 64)

    def test_legacy_ai_quorum_keeps_v1_arguments_without_artifact_flags(self):
        root, fake_binary = self._prepare_fixture()
        result = self._run_script(
            root,
            fake_binary,
            extra={
                "PCBEX_POLICY_PACK": "policy-pack.json",
                "PCBEX_AI_REVIEW_REQUEST": "request.json",
                "PCBEX_AI_APPROVAL_FILES": "approval.json",
                "PCBEX_AI_RESPONSE_FILES": "response.json",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = (root / "arguments").read_text(encoding="utf-8").splitlines()
        self.assertNotIn("--generated-schematic", arguments)
        self.assertNotIn("--deterministic-pipeline-plan", arguments)
        self.assertNotIn("--deterministic-pipeline-report", arguments)
        self.assertNotIn("--native-kicad-erc-report", arguments)
        self.assertNotIn("--kicad-cli", arguments)
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs["ai-review-artifacts-verified"], "")
        self.assertEqual(outputs["ai-review-native-kicad-erc-report-bytes"], "")
        self.assertEqual(outputs["ai-review-native-kicad-erc-report-sha256"], "")
        self.assertEqual(outputs["ai-review-native-kicad-erc-run-sha256"], "")

    def test_generated_schematic_requires_complete_quorum_and_runner_plan(self):
        root, fake_binary = self._prepare_fixture()
        result = self._run_script(
            root,
            fake_binary,
            plan="",
            extra={"PCBEX_AI_REVIEW_GENERATED_SCHEMATIC": "design.kicad_sch"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._commands(root), [])

        root, fake_binary = self._prepare_fixture()
        result = self._run_script(
            root,
            fake_binary,
            extra={
                "PCBEX_AI_REVIEW_GENERATED_SCHEMATIC": "design.kicad_sch",
                "PCBEX_AI_REVIEW_REQUEST": "request.json",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._commands(root), [])

    def test_native_kicad_erc_report_requires_complete_bound_workflow(self):
        root, fake_binary = self._prepare_fixture()
        result = self._run_script(
            root,
            fake_binary,
            extra={"PCBEX_AI_REVIEW_NATIVE_KICAD_ERC_REPORT": "native-erc-report.json"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._commands(root), [])

        root, fake_binary = self._prepare_fixture()
        result = self._run_script(
            root,
            fake_binary,
            plan="",
            extra={
                "PCBEX_POLICY_PACK": "policy-pack.json",
                "PCBEX_AI_REVIEW_REQUEST": "request.json",
                "PCBEX_AI_APPROVAL_FILES": "approval.json",
                "PCBEX_AI_RESPONSE_FILES": "response.json",
                "PCBEX_AI_REVIEW_GENERATED_SCHEMATIC": "design.kicad_sch",
                "PCBEX_AI_REVIEW_NATIVE_KICAD_ERC_REPORT": "native-erc-report.json",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._commands(root), [])

        root, fake_binary = self._prepare_fixture()
        (root / "native-erc-report.json").write_text(
            '{"run_sha256":"BAD"}\n', encoding="utf-8"
        )
        result = self._run_script(
            root,
            fake_binary,
            extra={
                "PCBEX_POLICY_PACK": "policy-pack.json",
                "PCBEX_AI_REVIEW_REQUEST": "request.json",
                "PCBEX_AI_APPROVAL_FILES": "approval.json",
                "PCBEX_AI_RESPONSE_FILES": "response.json",
                "PCBEX_AI_REVIEW_GENERATED_SCHEMATIC": "design.kicad_sch",
                "PCBEX_AI_REVIEW_NATIVE_KICAD_ERC_REPORT": "native-erc-report.json",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("verify-ai-quorum", self._commands(root))

    def test_ai_quorum_preflight_fails_before_analysis_or_runner(self):
        root, fake_binary = self._prepare_fixture()
        result = self._run_script(
            root,
            fake_binary,
            extra={"PCBEX_AI_REVIEW_REQUEST": "request.json"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._commands(root), [])

        root, fake_binary = self._prepare_fixture()
        result = self._run_script(
            root,
            fake_binary,
            extra={
                "PCBEX_AI_REVIEW_REQUEST": "request.json",
                "PCBEX_AI_APPROVAL_FILES": "approval.json",
                "PCBEX_AI_RESPONSE_FILES": "response.json",
                "PCBEX_AI_REVIEW_GENERATED_SCHEMATIC": "design.kicad_sch",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._commands(root), [])

    def test_bound_ai_quorum_rejects_nonapproved_summary_even_on_zero_exit(self):
        root, fake_binary = self._prepare_fixture()
        result = self._run_script(
            root,
            fake_binary,
            mode="rejected",
            extra={
                "PCBEX_POLICY_PACK": "policy-pack.json",
                "PCBEX_AI_REVIEW_REQUEST": "request.json",
                "PCBEX_AI_APPROVAL_FILES": "approval.json",
                "PCBEX_AI_RESPONSE_FILES": "response.json",
                "PCBEX_AI_REVIEW_GENERATED_SCHEMATIC": "design.kicad_sch",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            self._commands(root), ["analyze-kicad", "run-deterministic-pipeline"]
        )
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs.get("ai-review-artifacts-verified"), "")

    def test_approved_run_retains_exact_report_and_all_output_identities(self):
        root, result, outputs = self._valid_run(require_approved="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-deterministic-pipeline", self._commands(root))
        report_path = root / outputs["deterministic-pipeline-report"]
        report_bytes = report_path.read_bytes()
        report = json.loads(report_bytes)
        self.assertEqual(set(report), REPORT_KEYS)
        self.assertEqual(report["failures"], [])
        self.assertIs(report["approved"], True)
        self.assertEqual(outputs["deterministic-pipeline-schema-version"], "1")
        self.assertEqual(outputs["deterministic-pipeline-approved"], "true")
        self.assertEqual(outputs["deterministic-pipeline-plan-sha256"], "a" * 64)
        self.assertEqual(outputs["deterministic-pipeline-run-sha256"], "b" * 64)
        self.assertEqual(outputs["deterministic-pipeline-failure-count"], "0")
        self.assertEqual(
            outputs["deterministic-pipeline-report-bytes"], str(len(report_bytes))
        )
        self.assertEqual(
            outputs["deterministic-pipeline-report-sha256"], self._sha256(report_bytes)
        )

    def test_rejected_without_enforcement_succeeds_and_retains_report(self):
        root, result, outputs = self._valid_run(mode="rejected")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(
            (root / outputs["deterministic-pipeline-report"]).read_bytes()
        )
        self.assertEqual(report["failures"], ["synthetic deterministic failure"])
        self.assertIs(report["approved"], False)
        self.assertEqual(outputs["deterministic-pipeline-approved"], "false")
        self.assertEqual(outputs["deterministic-pipeline-failure-count"], "1")

    def test_rejected_with_enforcement_fails_after_retaining_outputs(self):
        root, result, outputs = self._valid_run(
            require_approved="true", mode="rejected"
        )
        self.assertNotEqual(result.returncode, 0)
        report_path = root / outputs["deterministic-pipeline-report"]
        self.assertTrue(report_path.is_file())
        report_bytes = report_path.read_bytes()
        report = json.loads(report_bytes)
        self.assertIs(report["approved"], False)
        self.assertEqual(len(report["failures"]), 1)
        self.assertEqual(outputs["deterministic-pipeline-failure-count"], "1")
        self.assertEqual(
            outputs["deterministic-pipeline-report-sha256"], self._sha256(report_bytes)
        )
        arguments = (root / "arguments").read_text(encoding="utf-8")
        self.assertIn("--require-approved", arguments.splitlines())

    def test_summary_rejects_duplicate_malformed_unknown_and_wrong_types(self):
        for mode in (
            "summary-duplicate",
            "summary-malformed",
            "summary-trailing",
            "summary-extra",
            "summary-missing",
            "summary-utf8",
            "summary-oversize",
            "summary-approved-type",
            "summary-schema-type",
            "summary-failure-type",
        ):
            with self.subTest(mode=mode):
                root, result, outputs = self._valid_run(mode=mode)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertTrue(
                    (root / "artifacts/deterministic-pipeline-report.json").is_file()
                )
                for name in DETERMINISTIC_OUTPUTS:
                    self.assertEqual(outputs.get(name), "", name)

    def test_summary_rejects_bounds_uppercase_and_identity_mismatches(self):
        for mode in (
            "summary-report-bytes-zero",
            "summary-report-bytes-bound",
            "summary-failure-bound",
            "summary-uppercase-sha",
            "summary-short-sha",
            "summary-bad-report-sha",
            "summary-bad-report-bytes",
            "summary-bad-plan",
            "summary-bad-run",
            "summary-bad-failure-count",
            "summary-bad-approved",
            "bad-report-top-level",
            "bad-report-duplicate",
            "report-symlink",
            "report-directory",
            "report-oversize",
        ):
            with self.subTest(mode=mode):
                root, result, outputs = self._valid_run(mode=mode)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                report_path = root / "artifacts/deterministic-pipeline-report.json"
                if mode == "report-symlink":
                    self.assertTrue(report_path.is_symlink())
                elif mode == "report-directory":
                    self.assertTrue(report_path.is_dir())
                else:
                    self.assertTrue(report_path.is_file())
                for name in DETERMINISTIC_OUTPUTS:
                    self.assertEqual(outputs.get(name), "", name)

    def test_missing_or_malformed_or_stale_report_fails_closed(self):
        root, result, _ = self._valid_run(mode="no-report")
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-deterministic-pipeline", self._commands(root))

        root, result, _ = self._valid_run(mode="approved", plan="missing-plan.json")
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("run-deterministic-pipeline", self._commands(root))

        root, result, _ = self._valid_run(mode="plant-stale")
        self.assertNotEqual(result.returncode, 0)
        report_path = root / "artifacts/deterministic-pipeline-report.json"
        sentinel = b"stale report planted by analyze\n"
        self.assertEqual(report_path.read_bytes(), sentinel)
        self.assertEqual(self._commands(root), ["analyze-kicad"])

    def test_invalid_boolean_inputs_fail_before_child_invocation(self):
        for name, value in (
            ("require", "maybe"),
            ("pipeline", "maybe"),
        ):
            with self.subTest(name=name):
                root, result, _ = self._valid_run(
                    require_approved=value if name == "require" else "false",
                    pipeline_verify=value if name == "pipeline" else "false",
                )
                self.assertNotEqual(result.returncode, 0)
                commands = self._commands(root)
                if name == "require":
                    self.assertEqual(commands, [])
                else:
                    self.assertIn("analyze-kicad", commands)
                    self.assertNotIn("pipeline-verify", commands)

    def test_plan_path_must_be_relative_portable_regular_and_bounded(self):
        invalid_paths = (
            "/absolute/plan.json",
            "../plan.json",
            "./plan.json",
            "nested//plan.json",
            "nested\\plan.json",
            "C:plan.json",
            "CON",
            "con.txt",
            "COM1.json",
            "nested/plan. ",
            "bad*/plan.json",
            ("x" * 256) + ".json",
            "p" * 4097,
        )
        for invalid in invalid_paths:
            with self.subTest(path=invalid):
                root, result, _ = self._valid_run(plan=invalid)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self._commands(root), [])

        root, fake_binary = self._prepare_fixture()
        plan = root / "plan.json"
        link = root / "plan-link.json"
        if hasattr(os, "symlink"):
            os.symlink(plan, link)
            result = self._run_script(root, fake_binary, plan="plan-link.json")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self._commands(root), [])

            root, fake_binary = self._prepare_fixture()
            target = root / "real-plans"
            target.mkdir()
            target_plan = target / "plan.json"
            target_plan.write_bytes((root / "plan.json").read_bytes())
            os.symlink(target, root / "linked", target_is_directory=True)
            result = self._run_script(root, fake_binary, plan="linked/plan.json")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self._commands(root), [])

        root, fake_binary = self._prepare_fixture()
        (root / "plan-dir").mkdir()
        result = self._run_script(root, fake_binary, plan="plan-dir")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._commands(root), [])

        root, fake_binary = self._prepare_fixture()
        (root / "oversized-plan.json").write_bytes(b"x" * (4 * 1024 * 1024 + 1))
        result = self._run_script(root, fake_binary, plan="oversized-plan.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._commands(root), [])


if __name__ == "__main__":
    unittest.main()
