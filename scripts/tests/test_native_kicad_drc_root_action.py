"""Contract tests for the opt-in root native KiCad PCB DRC bridge.

The root hardware Action already has a large analysis surface.  These tests
exercise only the new bridge by replacing ``pcbex`` and the summary verifier
with bounded fakes.  They deliberately run the real ``github-analysis.sh`` so
the process, argument, output and final-status boundaries remain covered.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "action.yml"
ANALYSIS = ROOT / "scripts" / "github-analysis.sh"

DRC_OUTPUTS = (
    "native-kicad-drc-report",
    "native-kicad-drc-schema-version",
    "native-kicad-drc-approved",
    "native-kicad-drc-violation-count",
    "native-kicad-drc-unconnected-item-count",
    "native-kicad-drc-schematic-parity-count",
    "native-kicad-drc-error-count",
    "native-kicad-drc-warning-count",
    "native-kicad-drc-ignored-check-count",
    "native-kicad-drc-board-bytes",
    "native-kicad-drc-board-sha256",
    "native-kicad-drc-project-bytes",
    "native-kicad-drc-project-sha256",
    "native-kicad-drc-rules-file-bytes",
    "native-kicad-drc-rules-file-sha256",
    "native-kicad-drc-run-sha256",
    "native-kicad-drc-report-bytes",
    "native-kicad-drc-report-sha256",
)


class NativeKicadDrcRootActionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.board = self.workspace / "board.kicad_pcb"
        self.board.write_bytes(b"board\n")
        self.action = self.root / "action"
        (self.action / "scripts").mkdir(parents=True)
        (self.action / "agent" / "src").mkdir(parents=True)
        shutil.copy2(ROOT / "scripts" / "ci_runtime.py", self.action / "scripts")
        shutil.copytree(
            ROOT / "agent" / "src" / "pcbex_agent",
            self.action / "agent" / "src" / "pcbex_agent",
        )
        self.arguments = self.workspace / "arguments.jsonl"
        self.fake = self.root / "fake-pcbex.py"
        self.fake.write_text(
            textwrap.dedent(
                """
                #!/usr/bin/env python3
                import json
                import os
                from pathlib import Path
                import sys

                argv = sys.argv[1:]
                command = argv[0] if argv else ""
                with Path(os.environ["PCBEX_TEST_ARGUMENTS"]).open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"command": command, "argv": argv}) + "\\n")

                def option(name, default=""):
                    prefix = name + "="
                    for item in argv:
                        if item.startswith(prefix):
                            return item[len(prefix):]
                    try:
                        return argv[argv.index(name) + 1]
                    except (ValueError, IndexError):
                        return default

                if command == "analyze-kicad":
                    output = Path(option("--output-dir"))
                    output.mkdir(parents=True, exist_ok=True)
                    (output / "run.json").write_text(
                        '{"result":{"violations":0}}\\n', encoding="utf-8"
                    )
                    (output / "report.sarif").write_text("{}\\n", encoding="utf-8")
                    (output / "summary.md").write_text("fake analysis\\n", encoding="utf-8")
                    raise SystemExit(0)

                if command == "run-native-kicad-drc":
                    if os.environ.get("PCBEX_NATIVE_KICAD_DRC_TEST_MODE") == "fatal":
                        raise SystemExit(9)
                    if os.environ.get("PCBEX_NATIVE_KICAD_DRC_TEST_MODE") != "missing":
                        output = Path(option("--output"))
                        output.write_bytes(b"{}\\n")
                    print("{}")
                """
            ).lstrip(),
            encoding="utf-8",
        )
        self.fake.chmod(self.fake.stat().st_mode | stat.S_IXUSR)
        self.summary = self.action / "scripts" / "native_kicad_drc_summary.py"
        self.summary.write_text(
            textwrap.dedent(
                """
                #!/usr/bin/env python3
                import json
                import os
                import sys

                sys.stdin.buffer.read()
                mode = os.environ.get("PCBEX_NATIVE_KICAD_DRC_TEST_MODE", "approved")
                if mode == "malformed":
                    print(json.dumps({"schema_version": 1, "unexpected": True}))
                    raise SystemExit(0)
                if mode == "duplicate":
                    print('{"schema_version":1,"schema_version":1}')
                    raise SystemExit(0)
                if mode == "nonstandard-number":
                    print('{"schema_version":NaN}')
                    raise SystemExit(0)
                approved = mode != "rejected"
                print(json.dumps({
                    "schema_version": 1,
                    "approved": approved,
                    "violation_count": 0 if approved else 1,
                    "unconnected_item_count": 0,
                    "schematic_parity_count": 0,
                    "error_count": 0 if approved else 1,
                    "warning_count": 0,
                    "ignored_check_count": 0,
                    "board_bytes": 5,
                    "board_sha256": "a" * 64,
                    "project_bytes": "",
                    "project_sha256": "",
                    "rules_file_bytes": "",
                    "rules_file_sha256": "",
                    "run_sha256": "b" * 64,
                    "report_bytes": 3,
                    "report_sha256": "c" * 64,
                }))
                """
            ).lstrip(),
            encoding="utf-8",
        )
        self.summary.chmod(self.summary.stat().st_mode | stat.S_IXUSR)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_analysis(
        self,
        *,
        enabled: str = "false",
        mode: str = "approved",
        cli: str = "kicad-cli",
        board: str = "board.kicad_pcb",
        output_dir: str = "artifacts",
        require_approved: str = "false",
    ) -> subprocess.CompletedProcess[str]:
        output = self.workspace / "github-output"
        summary = self.workspace / "step-summary.md"
        env = os.environ.copy()
        env.update(
            {
                "GITHUB_ACTION_PATH": str(self.action),
                "GITHUB_OUTPUT": str(output),
                "GITHUB_STEP_SUMMARY": str(summary),
                "PCBEX_BINARY": str(self.fake),
                "PCBEX_BOARD": board,
                "PCBEX_OUTPUT_DIR": output_dir,
                "PCBEX_NATIVE_KICAD_DRC_ENABLED": enabled,
                "PCBEX_NATIVE_KICAD_DRC_KICAD_CLI": cli,
                "PCBEX_NATIVE_KICAD_DRC_REQUIRE_APPROVED": require_approved,
                "PCBEX_NATIVE_KICAD_DRC_TEST_MODE": mode,
                "PCBEX_TEST_ARGUMENTS": str(self.arguments),
            }
        )
        return subprocess.run(
            ["bash", str(ANALYSIS)],
            cwd=self.workspace,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def outputs(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for line in (self.workspace / "github-output").read_text().splitlines():
            key, _, value = line.partition("=")
            result[key] = value
        return result

    def invocations(self, command: str) -> list[list[str]]:
        if not self.arguments.exists():
            return []
        return [
            item["argv"]
            for item in map(json.loads, self.arguments.read_text().splitlines())
            if item["command"] == command
        ]

    def test_action_declares_opt_in_inputs_outputs_and_enforce_gate(self) -> None:
        document = ACTION.read_text(encoding="utf-8")
        for name in (
            "native-kicad-drc-enabled",
            "native-kicad-drc-kicad-cli",
            "native-kicad-drc-require-approved",
        ):
            self.assertIn(f"  {name}:\n", document)
        self.assertIn('PCBEX_NATIVE_KICAD_DRC_ENABLED: ${{ inputs.native-kicad-drc-enabled }}', document)
        self.assertIn('PCBEX_NATIVE_KICAD_DRC_KICAD_CLI: ${{ inputs.native-kicad-drc-kicad-cli }}', document)
        self.assertIn('PCBEX_NATIVE_KICAD_DRC_REQUIRE_APPROVED: ${{ inputs.native-kicad-drc-require-approved }}', document)
        self.assertIn("id: artifact-inputs", document)
        self.assertIn("upload-artifact must be true or false", document)
        self.assertIn("upload-sarif must be true or false", document)
        self.assertIn("artifact-name must not contain control characters", document)
        self.assertIn("retention-days must be an integer from 1 through 90", document)
        self.assertIn("id: upload", document)
        self.assertIn("id: upload-sarif", document)
        self.assertIn("PCBEX_ARTIFACT_BOUNDARY_SAFE: ${{ steps.artifact-boundary.outputs.safe }}", document)
        self.assertIn("PCBEX_UPLOAD_OUTCOME: ${{ steps.upload.outcome }}", document)
        self.assertIn("PCBEX_UPLOAD_SARIF_OUTCOME: ${{ steps.upload-sarif.outcome }}", document)
        self.assertIn("analysis artifact boundary was not verified", document)
        self.assertIn("analysis artifact upload did not succeed", document)
        self.assertIn("SARIF upload did not succeed", document)
        for name in DRC_OUTPUTS:
            self.assertIn(f"  {name}:\n", document)
            self.assertIn(f"steps.analyze.outputs.{name}", document)
        self.assertIn('"$PCBEX_NATIVE_KICAD_DRC_ENABLED" == "true"', document)
        self.assertIn('"$PCBEX_NATIVE_KICAD_DRC_REQUIRE_APPROVED" == "true"', document)
        self.assertIn("native KiCad PCB DRC report is absent or not approved", document)

    def test_disabled_mode_does_not_invoke_drc_and_clears_outputs(self) -> None:
        result = self.run_analysis()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.invocations("run-native-kicad-drc")), 0)
        values = self.outputs()
        for name in DRC_OUTPUTS:
            self.assertEqual(values.get(name, ""), "", name)

    def test_approved_report_and_exact_boundary_arguments_are_published(self) -> None:
        option_like_board = self.workspace / "-board.kicad_pcb"
        option_like_board.write_bytes(self.board.read_bytes())
        result = self.run_analysis(
            enabled="true",
            cli="-trusted-kicad-cli",
            board="-board.kicad_pcb",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        invocation = self.invocations("run-native-kicad-drc")
        self.assertEqual(len(invocation), 1)
        self.assertEqual(
            invocation[0][-2:],
            ["--", "-board.kicad_pcb"],
        )
        self.assertIn("--output=artifacts/native-kicad-drc.json", invocation[0])
        self.assertIn("--kicad-cli=-trusted-kicad-cli", invocation[0])
        self.assertIn("--mcp-echo-report-summary", invocation[0])
        self.assertNotIn("--require-approved", invocation[0])
        values = self.outputs()
        self.assertEqual(values["native-kicad-drc-report"], "artifacts/native-kicad-drc.json")
        self.assertEqual(values["native-kicad-drc-approved"], "true")
        self.assertEqual(values["native-kicad-drc-violation-count"], "0")
        self.assertEqual(values["native-kicad-drc-project-bytes"], "")
        self.assertEqual(values["native-kicad-drc-rules-file-bytes"], "")
        self.assertRegex(values["native-kicad-drc-board-sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(values["native-kicad-drc-run-sha256"], r"^[0-9a-f]{64}$")
        summary = (self.workspace / "step-summary.md").read_text()
        self.assertIn("# pcbex native KiCad PCB DRC", summary)
        self.assertIn("- Violations: 0", summary)

    def test_rejected_report_is_valid_evidence_and_retained_for_final_gate(self) -> None:
        result = self.run_analysis(enabled="true", mode="rejected")
        self.assertEqual(result.returncode, 0, result.stderr)
        values = self.outputs()
        self.assertEqual(values["native-kicad-drc-approved"], "false")
        self.assertEqual(values["native-kicad-drc-violation-count"], "1")
        self.assertTrue((self.workspace / values["native-kicad-drc-report"]).is_file())
        self.assertIn('"$PCBEX_NATIVE_KICAD_DRC_REQUIRE_APPROVED" == "true"', ACTION.read_text())

    def test_fatal_or_malformed_summary_sets_analysis_error(self) -> None:
        for mode in ("fatal", "malformed", "duplicate", "nonstandard-number", "missing"):
            with self.subTest(mode=mode):
                result = self.run_analysis(enabled="true", mode=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.outputs().get("status"), "error")
                self.assertEqual(self.outputs().get("native-kicad-drc-report"), "")

    def test_enabled_and_require_values_are_strict_booleans(self) -> None:
        for arguments in (
            {"enabled": "yes", "output_dir": "invalid-enabled"},
            {"require_approved": "yes", "output_dir": "invalid-require"},
        ):
            with self.subTest(arguments=arguments):
                result = self.run_analysis(**arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.invocations("analyze-kicad"), [])

    def test_require_approved_requires_enabled_drc(self) -> None:
        result = self.run_analysis(require_approved="true")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "PCBEX_NATIVE_KICAD_DRC_REQUIRE_APPROVED requires "
            "PCBEX_NATIVE_KICAD_DRC_ENABLED=true",
            result.stderr,
        )
        self.assertEqual(self.invocations("analyze-kicad"), [])

    def test_output_root_preserves_spaces_and_rejects_globs_before_writes(self) -> None:
        result = self.run_analysis(output_dir="artifacts with space")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.workspace / "artifacts with space").is_dir())

        for output_dir in ("artifacts*", "artifacts?", "[artifacts]"):
            with self.subTest(output_dir=output_dir):
                if self.arguments.exists():
                    self.arguments.unlink()
                result = self.run_analysis(output_dir=output_dir)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.arguments.exists())

    def test_same_stem_regular_companions_are_forwarded_to_both_boundaries(self) -> None:
        dotted = self.workspace / "dir.with.dot"
        dotted.mkdir()
        board = dotted / "board.kicad_pcb"
        board.write_bytes(self.board.read_bytes())
        project = dotted / "board.kicad_pro"
        rules = dotted / "board.kicad_dru"
        project.write_text("project\n", encoding="utf-8")
        rules.write_text("rules\n", encoding="utf-8")
        result = self.run_analysis(enabled="true", board="dir.with.dot/board.kicad_pcb")
        self.assertEqual(result.returncode, 0, result.stderr)
        invocation = self.invocations("run-native-kicad-drc")[0]
        self.assertIn("--project=dir.with.dot/board.kicad_pro", invocation)
        self.assertIn("--rules-file=dir.with.dot/board.kicad_dru", invocation)

    def test_absolute_board_same_stem_companions_preserve_root_action_semantics(self) -> None:
        project = self.board.with_suffix(".kicad_pro")
        rules = self.board.with_suffix(".kicad_dru")
        project.write_text("project\n", encoding="utf-8")
        rules.write_text("rules\n", encoding="utf-8")
        result = self.run_analysis(enabled="true", board=str(self.board))
        self.assertEqual(result.returncode, 0, result.stderr)
        invocation = self.invocations("run-native-kicad-drc")[0]
        self.assertIn(f"--project={project}", invocation)
        self.assertIn(f"--rules-file={rules}", invocation)
        self.assertEqual(invocation[-2:], ["--", str(self.board)])

    def test_non_regular_companion_fails_closed(self) -> None:
        (self.workspace / "board.kicad_pro").mkdir()
        result = self.run_analysis(enabled="true")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.invocations("run-native-kicad-drc"), [])


if __name__ == "__main__":
    unittest.main()
