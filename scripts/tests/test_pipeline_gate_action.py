"""Regression tests for the opt-in pipeline gate in the composite action."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "action.yml"
ANALYSIS_SCRIPT = ROOT / "scripts" / "github-analysis.sh"


class PipelineGateActionTests(unittest.TestCase):
    def test_action_declares_pipeline_inputs_outputs_and_enforcement(self):
        document = ACTION.read_text(encoding="utf-8")
        for name in (
            "pipeline-verify",
            "pipeline-electrical-policy",
            "pipeline-electrical-review",
            "pipeline-manufacturing-package",
            "pipeline-firmware-manifest",
            "pipeline-factory-receipt",
            "pipeline-require-factory",
        ):
            self.assertIn(f"  {name}:\n", document)
        self.assertIn("  pipeline-report:\n", document)
        self.assertIn("  pipeline-passed:\n", document)
        self.assertIn(
            "PCBEX_PIPELINE_VERIFY: ${{ inputs.pipeline-verify }}", document
        )
        self.assertIn(
            'if [[ "$PCBEX_PIPELINE_VERIFY" == "true" && "$PCBEX_PIPELINE_PASSED" != "true" ]]',
            document,
        )
        self.assertIn("always()", document)

    def test_script_uses_bounded_pipeline_command_and_forwards_profiles(self):
        document = ANALYSIS_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("pipeline-verify", document)
        self.assertIn(
            'pipeline_arguments+=(--analysis-dfm-profile "$PCBEX_FAB_PROFILE")',
            document,
        )
        self.assertIn(
            'pipeline_arguments+=(--analysis-policy-pack "$effective_policy_pack")',
            document,
        )
        self.assertIn(
            'pipeline_arguments+=(--analysis-physical-profile "$PCBEX_PHYSICAL_PROFILE")',
            document,
        )
        self.assertIn('ci_runtime.py" exec', document)
        self.assertNotIn("eval ", document)
        self.assertNotIn("curl", document)
        self.assertNotIn("wget", document)

    @staticmethod
    def _write_fake_binary(path: Path) -> None:
        path.write_text(
            textwrap.dedent(
                r"""
                #!/usr/bin/env bash
                set -euo pipefail
                printf 'COMMAND=%s\n' "${1:-}" >> "$PCBEX_TEST_ARGUMENTS"
                printf '%s\n' "$@" >> "$PCBEX_TEST_ARGUMENTS"
                if [[ "${1:-}" == "analyze-kicad" ]]; then
                  output_dir=""
                  args=("$@")
                  for ((index = 0; index < ${#args[@]}; index++)); do
                    if [[ "${args[index]}" == "--output-dir" ]]; then
                      output_dir="${args[index + 1]}"
                      break
                    fi
                  done
                  mkdir -p "$output_dir"
                  printf '%s\n' '{"result":{"violations":0}}' > "$output_dir/run.json"
                  printf '%s\n' '{}' > "$output_dir/report.sarif"
                  printf '%s\n' 'ok' > "$output_dir/summary.md"
                elif [[ "${1:-}" == "compare-schematics" ]]; then
                  output=""
                  summary_output=""
                  sarif_output=""
                  args=("$@")
                  for ((index = 0; index < ${#args[@]}; index++)); do
                    case "${args[index]}" in
                      --output) output="${args[index + 1]}" ;;
                      --summary-output) summary_output="${args[index + 1]}" ;;
                      --sarif-output) sarif_output="${args[index + 1]}" ;;
                    esac
                  done
                  mkdir -p "$(dirname "$output")" "$(dirname "$summary_output")" "$(dirname "$sarif_output")"
                  printf '%s\n' '{"review_required":false}' > "$output"
                  printf '%s\n' 'no schematic changes' > "$summary_output"
                  printf '%s\n' '{}' > "$sarif_output"
                elif [[ "${1:-}" == "pipeline-verify" ]]; then
                  output=""
                  args=("$@")
                  for ((index = 0; index < ${#args[@]}; index++)); do
                    if [[ "${args[index]}" == "--output" ]]; then
                      output="${args[index + 1]}"
                      break
                    fi
                  done
                  mkdir -p "$(dirname "$output")"
                  printf '{"passed":%s}\n' "${PCBEX_PIPELINE_TEST_PASSED:-true}" > "$output"
                  exit "${PCBEX_PIPELINE_TEST_EXIT:-0}"
                fi
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def _run_script(
        self,
        directory: Path,
        fake_binary: Path,
        *,
        pipeline_verify: str = "false",
        pipeline_passed: str = "true",
        pipeline_exit: str = "0",
        complete_pipeline_inputs: bool = True,
        extra: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        output_dir = directory / "artifacts"
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GITHUB_ACTION_PATH": str(ROOT),
            "GITHUB_OUTPUT": str(directory / "github-output"),
            "GITHUB_STEP_SUMMARY": str(directory / "step-summary"),
            "PCBEX_BINARY": str(fake_binary),
            "PCBEX_BOARD": "board.kicad_pcb",
            "PCBEX_OUTPUT_DIR": "artifacts",
            "PCBEX_PIPELINE_VERIFY": pipeline_verify,
            "PCBEX_PIPELINE_TEST_PASSED": pipeline_passed,
            "PCBEX_PIPELINE_TEST_EXIT": pipeline_exit,
            "PCBEX_TEST_ARGUMENTS": str(directory / "arguments"),
        }
        if pipeline_verify == "true" and complete_pipeline_inputs:
            env.update(
                {
                    "PCBEX_SCHEMATIC": "schematic.kicad_sch",
                    "PCBEX_PIPELINE_ELECTRICAL_REVIEW": "electrical-review.json",
                    "PCBEX_PIPELINE_MANUFACTURING_PACKAGE": "manufacturing.zip",
                    "PCBEX_PIPELINE_FIRMWARE_MANIFEST": "firmware.json",
                }
            )
        if extra:
            env.update(extra)
        return subprocess.run(
            ["bash", str(ANALYSIS_SCRIPT)],
            cwd=directory,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def _outputs(path: Path) -> dict[str, str]:
        return dict(
            line.split("=", 1)
            for line in path.read_text(encoding="utf-8").splitlines()
            if "=" in line
        )

    def test_disabled_gate_preserves_existing_analysis_behavior(self):
        with tempfile.TemporaryDirectory(prefix="pcbex-pipeline-disabled-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            result = self._run_script(directory, fake_binary)
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = (directory / "arguments").read_text(encoding="utf-8")
            self.assertIn("COMMAND=analyze-kicad", arguments)
            self.assertNotIn("COMMAND=pipeline-verify", arguments)
            outputs = self._outputs(directory / "github-output")
            self.assertEqual(outputs["pipeline-report"], "")
            self.assertEqual(outputs["pipeline-passed"], "")
            self.assertTrue((directory / "artifacts/current/run.json").is_file())

    def test_successful_gate_publishes_fixed_report_and_pipeline_summary(self):
        with tempfile.TemporaryDirectory(prefix="pcbex-pipeline-success-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            result = self._run_script(directory, fake_binary, pipeline_verify="true")
            self.assertEqual(result.returncode, 0, result.stderr)
            outputs = self._outputs(directory / "github-output")
            self.assertEqual(outputs["pipeline-report"], "artifacts/pipeline-gate.json")
            self.assertEqual(outputs["pipeline-passed"], "true")
            self.assertTrue((directory / outputs["pipeline-report"]).is_file())
            summary = (directory / "step-summary").read_text(encoding="utf-8")
            self.assertIn("# pcbex hardware pipeline gate", summary)
            self.assertIn("Passed: `true`", summary)

    def test_pipeline_gate_accepts_current_schematic_without_diff_baseline(self):
        with tempfile.TemporaryDirectory(prefix="pcbex-pipeline-current-schematic-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            result = self._run_script(
                directory,
                fake_binary,
                pipeline_verify="true",
                extra={"PCBEX_BASELINE_SCHEMATIC": ""},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = (directory / "arguments").read_text(encoding="utf-8")
            self.assertIn("COMMAND=pipeline-verify", arguments)
            self.assertNotIn("COMMAND=compare-schematics", arguments)
            outputs = self._outputs(directory / "github-output")
            self.assertEqual(outputs["pipeline-passed"], "true")

    def test_pipeline_failure_retains_report_and_current_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="pcbex-pipeline-failure-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            result = self._run_script(
                directory,
                fake_binary,
                pipeline_verify="true",
                pipeline_passed="false",
                pipeline_exit="1",
            )
            self.assertNotEqual(result.returncode, 0)
            outputs = self._outputs(directory / "github-output")
            self.assertEqual(outputs["pipeline-report"], "artifacts/pipeline-gate.json")
            self.assertEqual(outputs["pipeline-passed"], "false")
            self.assertTrue((directory / outputs["pipeline-report"]).is_file())
            self.assertTrue((directory / "artifacts/current/run.json").is_file())
            self.assertIn("Passed: `false`", (directory / "step-summary").read_text())

    def test_existing_report_is_never_misattributed_to_current_invocation(self):
        with tempfile.TemporaryDirectory(prefix="pcbex-pipeline-stale-report-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            stale = directory / "artifacts" / "pipeline-gate.json"
            stale.parent.mkdir()
            stale.write_text('{"passed":true,"stale":true}\n', encoding="utf-8")

            result = self._run_script(directory, fake_binary, pipeline_verify="true")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be empty", result.stderr)
            self.assertFalse((directory / "arguments").exists())
            self.assertEqual(
                stale.read_text(encoding="utf-8"),
                '{"passed":true,"stale":true}\n',
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_nested_output_link_is_rejected_before_any_analysis_write(self):
        with tempfile.TemporaryDirectory(prefix="pcbex-pipeline-output-link-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            external = directory / "external"
            external.mkdir()
            artifact_dir = directory / "artifacts"
            artifact_dir.mkdir()
            os.symlink(external, artifact_dir / "current", target_is_directory=True)

            result = self._run_script(directory, fake_binary)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be empty", result.stderr)
            self.assertFalse((directory / "arguments").exists())
            self.assertEqual(list(external.iterdir()), [])

    def test_pipeline_profile_forwarding_uses_dedicated_flags(self):
        variants = (
            ({"PCBEX_FAB_PROFILE": "fab-profile.json"}, "--analysis-dfm-profile"),
            ({"PCBEX_POLICY_PACK": "policy-pack.json"}, "--analysis-policy-pack"),
            ({"PCBEX_PHYSICAL_PROFILE": "physical-profile.json"}, "--analysis-physical-profile"),
        )
        for extra, flag in variants:
            with self.subTest(flag=flag), tempfile.TemporaryDirectory(
                prefix="pcbex-pipeline-profile-"
            ) as raw:
                directory = Path(raw)
                fake_binary = directory / "fake-pcbex"
                self._write_fake_binary(fake_binary)
                result = self._run_script(
                    directory,
                    fake_binary,
                    pipeline_verify="true",
                    extra=extra,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = (directory / "arguments").read_text(encoding="utf-8")
                self.assertIn(f"COMMAND=pipeline-verify", arguments)
                self.assertIn(flag, arguments)
                self.assertIn(next(iter(extra.values())), arguments)

    def test_invalid_or_incomplete_pipeline_inputs_fail_without_running_gate(self):
        with tempfile.TemporaryDirectory(prefix="pcbex-pipeline-invalid-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            invalid = self._run_script(directory, fake_binary, pipeline_verify="maybe")
            self.assertNotEqual(invalid.returncode, 0)
            arguments = (directory / "arguments").read_text(encoding="utf-8")
            self.assertNotIn("COMMAND=pipeline-verify", arguments)
            self.assertIn("must be true or false", invalid.stderr)

        with tempfile.TemporaryDirectory(prefix="pcbex-pipeline-missing-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            missing = self._run_script(
                directory,
                fake_binary,
                pipeline_verify="true",
                complete_pipeline_inputs=False,
            )
            self.assertNotEqual(missing.returncode, 0)
            arguments = (directory / "arguments").read_text(encoding="utf-8")
            self.assertNotIn("COMMAND=pipeline-verify", arguments)
            self.assertIn("requires PCBEX_SCHEMATIC", missing.stderr)


if __name__ == "__main__":
    unittest.main()
