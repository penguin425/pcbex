"""Regression tests for circuit-spec schematic writer Action parity."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "action.yml"
ANALYSIS_SCRIPT = ROOT / "scripts" / "github-analysis.sh"


class CircuitSpecWriterActionTests(unittest.TestCase):
    def test_action_declares_opt_in_input_and_authenticated_outputs(self):
        action = ACTION.read_text(encoding="utf-8")
        script = ANALYSIS_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("  circuit-spec:\n", action)
        self.assertIn("  circuit-spec-schematic:\n", action)
        self.assertIn("  circuit-spec-check:\n", action)
        self.assertIn("  circuit-spec-approved:\n", action)
        self.assertIn("  circuit-spec-schematic-bytes:\n", action)
        self.assertIn("  circuit-spec-schematic-sha256:\n", action)
        self.assertIn("PCBEX_CIRCUIT_SPEC: ${{ inputs.circuit-spec }}", action)
        self.assertIn(
            'circuit_spec_schematic="${artifact_dir}/circuit-spec.kicad_sch"',
            script,
        )
        self.assertIn("write-circuit-spec-kicad-schematic", script)
        self.assertIn("max_bytes=64 * 1024 * 1024", script)
        self.assertNotIn("eval ", script)
        self.assertNotIn("curl", script)
        self.assertNotIn("wget", script)

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
                elif [[ "${1:-}" == "check-circuit-spec" ]]; then
                  output=""
                  args=("$@")
                  for ((index = 0; index < ${#args[@]}; index++)); do
                    if [[ "${args[index]}" == "--output" ]]; then
                      output="${args[index + 1]}"
                      break
                    fi
                  done
                  if [[ "${PCBEX_WRITER_TEST_MODE:-success}" == "malformed" ]]; then
                    exit 3
                  elif [[ "${PCBEX_WRITER_TEST_MODE:-success}" == "erc-reject" ]]; then
                    printf '%s\n' '{"electrical_review":{"approved":false}}' > "$output"
                  else
                    printf '%s\n' '{"electrical_review":{"approved":true}}' > "$output"
                  fi
                elif [[ "${1:-}" == "write-circuit-spec-kicad-schematic" ]]; then
                  output=""
                  args=("$@")
                  for ((index = 0; index < ${#args[@]}; index++)); do
                    if [[ "${args[index]}" == "--output" ]]; then
                      output="${args[index + 1]}"
                      break
                    fi
                  done
                  case "${PCBEX_WRITER_TEST_MODE:-success}" in
                    reject)
                      exit 3
                      ;;
                    oversize)
                      python3 - "$output" <<'PY'
from pathlib import Path
import sys

with Path(sys.argv[1]).open("wb") as destination:
    destination.seek(64 * 1024 * 1024)
    destination.write(b"x")
PY
                      ;;
                    symlink)
                      ln -s "$PCBEX_WRITER_EXTERNAL" "$output"
                      ;;
                    success)
                      printf '%s' "${PCBEX_WRITER_PAYLOAD}" > "$output"
                      ;;
                    *)
                      exit 4
                      ;;
                  esac
                fi
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def _run(
        self,
        directory: Path,
        fake_binary: Path,
        *,
        circuit_spec: str = "",
        mode: str = "success",
        payload: str = "(kicad_sch (version 20231120))\n",
        extra: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GITHUB_ACTION_PATH": str(ROOT),
            "GITHUB_OUTPUT": str(directory / "github-output"),
            "GITHUB_STEP_SUMMARY": str(directory / "step-summary"),
            "PCBEX_BINARY": str(fake_binary),
            "PCBEX_BOARD": "board.kicad_pcb",
            "PCBEX_CIRCUIT_SPEC": circuit_spec,
            "PCBEX_OUTPUT_DIR": "artifacts",
            "PCBEX_TEST_ARGUMENTS": str(directory / "arguments"),
            "PCBEX_WRITER_TEST_MODE": mode,
            "PCBEX_WRITER_PAYLOAD": payload,
        }
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

    def test_disabled_writer_preserves_analysis_only_behavior(self):
        with tempfile.TemporaryDirectory(prefix="pcbex-action-writer-disabled-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            result = self._run(directory, fake_binary)
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = (directory / "arguments").read_text(encoding="utf-8")
            self.assertIn("COMMAND=analyze-kicad", arguments)
            self.assertNotIn("COMMAND=write-circuit-spec-kicad-schematic", arguments)
            outputs = self._outputs(directory / "github-output")
            self.assertEqual(outputs["circuit-spec-schematic"], "")
            self.assertEqual(outputs["circuit-spec-check"], "")
            self.assertEqual(outputs["circuit-spec-approved"], "")
            self.assertEqual(outputs["circuit-spec-schematic-bytes"], "")
            self.assertEqual(outputs["circuit-spec-schematic-sha256"], "")

    def test_success_returns_fixed_path_size_and_digest_without_pipeline_wiring(self):
        with tempfile.TemporaryDirectory(prefix="pcbex-action-writer-success-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            payload = "(kicad_sch (version 20231120) (generator pcbex))\n"
            result = self._run(
                directory,
                fake_binary,
                circuit_spec="circuit-spec-v2.json",
                payload=payload,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            outputs = self._outputs(directory / "github-output")
            self.assertEqual(
                outputs["circuit-spec-schematic"],
                "artifacts/circuit-spec.kicad_sch",
            )
            self.assertEqual(
                outputs["circuit-spec-check"], "artifacts/circuit-spec-check.json"
            )
            self.assertEqual(outputs["circuit-spec-approved"], "true")
            self.assertEqual(
                outputs["circuit-spec-schematic-bytes"],
                str(len(payload.encode("utf-8"))),
            )
            self.assertEqual(
                outputs["circuit-spec-schematic-sha256"],
                hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            )
            generated = directory / outputs["circuit-spec-schematic"]
            self.assertEqual(generated.read_text(encoding="utf-8"), payload)
            arguments = (directory / "arguments").read_text(encoding="utf-8")
            self.assertIn("COMMAND=write-circuit-spec-kicad-schematic", arguments)
            self.assertIn("COMMAND=check-circuit-spec", arguments)
            self.assertIn("circuit-spec-v2.json", arguments)
            self.assertIn("artifacts/circuit-spec.kicad_sch", arguments)
            self.assertNotIn("COMMAND=pipeline-verify", arguments)
            self.assertNotIn("COMMAND=compare-schematics", arguments)
            summary = (directory / "step-summary").read_text(encoding="utf-8")
            self.assertIn("Generated circuit-spec schematic", summary)
            self.assertIn(outputs["circuit-spec-schematic-sha256"], summary)

    def test_writer_rejection_attributes_no_generated_output(self):
        with tempfile.TemporaryDirectory(prefix="pcbex-action-writer-reject-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            result = self._run(
                directory,
                fake_binary,
                circuit_spec="rejected.json",
                mode="reject",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((directory / "artifacts/circuit-spec.kicad_sch").exists())
            outputs = self._outputs(directory / "github-output")
            self.assertEqual(outputs["circuit-spec-schematic"], "")
            self.assertEqual(outputs["circuit-spec-schematic-sha256"], "")
            self.assertTrue((directory / "artifacts/current/run.json").is_file())

    def test_erc_rejection_retains_check_and_never_invokes_writer(self):
        with tempfile.TemporaryDirectory(prefix="pcbex-action-writer-erc-reject-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            result = self._run(
                directory,
                fake_binary,
                circuit_spec="rejected.json",
                mode="erc-reject",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("immutable ERC rejected", result.stderr)
            outputs = self._outputs(directory / "github-output")
            self.assertEqual(
                outputs["circuit-spec-check"], "artifacts/circuit-spec-check.json"
            )
            self.assertEqual(outputs["circuit-spec-approved"], "false")
            self.assertEqual(outputs["circuit-spec-schematic"], "")
            self.assertTrue((directory / outputs["circuit-spec-check"]).is_file())
            arguments = (directory / "arguments").read_text(encoding="utf-8")
            self.assertIn("COMMAND=check-circuit-spec", arguments)
            self.assertNotIn("COMMAND=write-circuit-spec-kicad-schematic", arguments)

    def test_oversized_writer_output_is_not_attributed(self):
        with tempfile.TemporaryDirectory(prefix="pcbex-action-writer-oversize-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            result = self._run(
                directory,
                fake_binary,
                circuit_spec="oversized.json",
                mode="oversize",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exceeds the 67108864-byte limit", result.stderr)
            outputs = self._outputs(directory / "github-output")
            self.assertEqual(outputs["circuit-spec-schematic"], "")
            self.assertEqual(outputs["circuit-spec-schematic-bytes"], "")
            self.assertEqual(outputs["circuit-spec-schematic-sha256"], "")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_generated_output_symlink_is_not_attributed_or_followed(self):
        with tempfile.TemporaryDirectory(prefix="pcbex-action-writer-link-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            external = directory / "external.kicad_sch"
            external.write_text("external remains unchanged\n", encoding="utf-8")
            result = self._run(
                directory,
                fake_binary,
                circuit_spec="linked.json",
                mode="symlink",
                extra={"PCBEX_WRITER_EXTERNAL": str(external)},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symbolic link", result.stderr)
            self.assertEqual(
                external.read_text(encoding="utf-8"), "external remains unchanged\n"
            )
            outputs = self._outputs(directory / "github-output")
            self.assertEqual(outputs["circuit-spec-schematic"], "")

    def test_nonempty_output_root_is_rejected_before_writer(self):
        with tempfile.TemporaryDirectory(prefix="pcbex-action-writer-stale-") as raw:
            directory = Path(raw)
            fake_binary = directory / "fake-pcbex"
            self._write_fake_binary(fake_binary)
            artifact_dir = directory / "artifacts"
            artifact_dir.mkdir()
            stale = artifact_dir / "circuit-spec.kicad_sch"
            stale.write_text("stale\n", encoding="utf-8")
            result = self._run(
                directory,
                fake_binary,
                circuit_spec="circuit-spec-v2.json",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be empty", result.stderr)
            self.assertFalse((directory / "arguments").exists())
            self.assertEqual(stale.read_text(encoding="utf-8"), "stale\n")


if __name__ == "__main__":
    unittest.main()
