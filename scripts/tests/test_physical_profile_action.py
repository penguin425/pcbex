"""Regression tests for the physical-profile GitHub Action boundary."""

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


class PhysicalProfileActionTests(unittest.TestCase):
    def test_action_declares_and_exports_physical_profile(self):
        document = ACTION.read_text(encoding="utf-8")
        self.assertIn("  physical-profile:\n", document)
        self.assertIn(
            "PCBEX_PHYSICAL_PROFILE: ${{ inputs.physical-profile }}", document
        )

    def test_script_forwards_profile_to_current_and_baseline_analysis(self):
        document = ANALYSIS_SCRIPT.read_text(encoding="utf-8")
        selection = (
            'if [[ -n "${PCBEX_PHYSICAL_PROFILE:-}" ]]; then '
            "((profile_selections += 1)); fi"
        )
        forwarding = 'analysis_arguments+=(--physical-profile "$PCBEX_PHYSICAL_PROFILE")'
        baseline_forwarding = (
            'baseline_arguments+=(--physical-profile "$PCBEX_PHYSICAL_PROFILE")'
        )
        self.assertIn(selection, document)
        self.assertIn(forwarding, document)
        self.assertIn(baseline_forwarding, document)

    def test_script_forwards_profile_and_rejects_conflicting_selection(self):
        """Exercise the shell boundary with a bounded fake pcbex binary."""

        with tempfile.TemporaryDirectory(prefix="pcbex-physical-action-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            fake_binary.write_text(
                textwrap.dedent(
                    """
                    #!/usr/bin/env bash
                    set -euo pipefail
                    printf '%s\\n' "$@" > "$PCBEX_TEST_ARGUMENTS"
                    if [[ "${1:-}" == "analyze-kicad" ]]; then
                      output_dir=""
                      for ((index = 1; index <= $#; index++)); do
                        if [[ "${!index}" == "--output-dir" ]]; then
                          next=$((index + 1))
                          output_dir="${!next}"
                          break
                        fi
                      done
                      mkdir -p "$output_dir"
                      printf '%s\\n' '{"result":{"violations":0}}' > "$output_dir/run.json"
                      printf '%s\\n' '{}' > "$output_dir/report.sarif"
                      printf '%s\\n' 'ok' > "$output_dir/summary.md"
                    fi
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            fake_binary.chmod(0o755)

            def environment(*, fab: str = "") -> dict[str, str]:
                output_dir = directory / ("conflict" if fab else "profile")
                output_dir.mkdir()
                env = {
                    "PATH": os.environ.get("PATH", ""),
                    "GITHUB_OUTPUT": str(output_dir / "github-output"),
                    "GITHUB_STEP_SUMMARY": str(output_dir / "summary"),
                    "PCBEX_BINARY": str(fake_binary),
                    "PCBEX_BOARD": "board.kicad_pcb",
                    "PCBEX_OUTPUT_DIR": str(output_dir / "artifacts"),
                    "PCBEX_PHYSICAL_PROFILE": "physical-profile.json",
                    "PCBEX_TEST_ARGUMENTS": str(output_dir / "arguments"),
                }
                if fab:
                    env["PCBEX_FAB"] = fab
                return env

            forwarded_environment = environment()
            forwarded = subprocess.run(
                ["bash", str(ANALYSIS_SCRIPT)],
                env=forwarded_environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(forwarded.returncode, 0, forwarded.stderr)
            arguments = Path(
                forwarded_environment["PCBEX_TEST_ARGUMENTS"]
            ).read_text(encoding="utf-8").splitlines()
            self.assertIn("--physical-profile", arguments)
            self.assertIn("physical-profile.json", arguments)

            conflict = subprocess.run(
                ["bash", str(ANALYSIS_SCRIPT)],
                env=environment(fab="jlcpcb-2layer"),
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(conflict.returncode, 2)
            self.assertIn("mutually exclusive", conflict.stderr)
            self.assertFalse((directory / "conflict" / "arguments").exists())


if __name__ == "__main__":
    unittest.main()
