"""Contract tests for the standalone native KiCad PCB DRC Action bridge."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "native-kicad-drc-action.sh"
GATE = ROOT / "scripts" / "native-kicad-drc-action-gate.sh"
ACTION = ROOT / "actions" / "native-kicad-drc" / "action.yml"


class NativeKicadDrcActionTests(unittest.TestCase):
    @staticmethod
    def _fake_binary(path: Path) -> None:
        path.write_text(
            textwrap.dedent(
                f"""
                #!/usr/bin/env python3
                import hashlib, json, os, sys
                from pathlib import Path
                sys.path.insert(0, {str(ROOT / 'scripts')!r})
                import native_kicad_drc_summary as v

                args = sys.argv[1:]
                Path(os.environ['PCBEX_TEST_ARGUMENTS']).write_text(json.dumps(args))
                if os.environ.get('PCBEX_TEST_MODE') == 'fatal':
                    raise SystemExit(7)
                output = next(item.split('=', 1)[1] for item in args if item.startswith('--output='))
                board = args[args.index('--') + 1]
                project = next((item.split('=', 1)[1] for item in args if item.startswith('--project=')), '')
                rules = next((item.split('=', 1)[1] for item in args if item.startswith('--rules-file=')), '')
                board_bytes = Path(board).read_bytes()
                project_bytes = Path(project).read_bytes() if project else None
                rules_bytes = Path(rules).read_bytes() if rules else None
                rejected = os.environ.get('PCBEX_TEST_MODE') == 'rejected'
                finding = {{
                    'category': 'violation', 'description': 'clearance',
                    'items': [{{'description': 'U1', 'position_nm': {{'x': 1000, 'y': 2000}}}}],
                    'severity': 'error', 'type': 'clearance',
                }}
                findings = [finding] if rejected else []
                report = {{
                    'schema_version': 1, 'engine': 'pcbex', 'engine_version': 'test', 'kicad_version': '10.0.5',
                    'source': {{'bytes': len(board_bytes), 'sha256': hashlib.sha256(board_bytes).hexdigest()}},
                    'project': None if project_bytes is None else {{'bytes': len(project_bytes), 'sha256': hashlib.sha256(project_bytes).hexdigest()}},
                    'rules_file': None if rules_bytes is None else {{'bytes': len(rules_bytes), 'sha256': hashlib.sha256(rules_bytes).hexdigest()}},
                    'invocation': {{'command': 'pcb drc', 'format': 'json', 'units': 'mm', 'severities': ['error', 'warning'],
                        'exit_code_violations': True, 'all_track_errors': False, 'schematic_parity': False,
                        'refill_zones': False, 'save_board': False}},
                    'ignored_checks': [], 'findings': findings, 'violation_count': int(rejected),
                    'unconnected_item_count': 0, 'schematic_parity_count': 0, 'error_count': int(rejected),
                    'warning_count': 0, 'approved': not rejected,
                }}
                report['run_sha256'] = v._run_sha256(report)
                rendered = v._canonical_report_bytes(report)
                Path(output).write_bytes(rendered)
                expected = v._validate_report(report, board=board_bytes, project=project_bytes,
                    rules_file=rules_bytes, report_bytes=rendered)
                if os.environ.get('PCBEX_TEST_MODE') == 'malformed':
                    expected['error_count'] = 'forged'
                print(json.dumps(expected, separators=(',', ':')))
                """
            ).lstrip(),
            encoding="utf-8",
        )
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    @staticmethod
    def _outputs(path: Path) -> dict[str, str]:
        values: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            key, value = line.split("=", 1)
            values[key] = value
        return values

    @classmethod
    def _run(
        cls,
        root: Path,
        fake_binary: Path,
        *,
        mode: str = "approved",
        board: str = "design.kicad_pcb",
        project: str = "",
        rules_file: str = "",
        output_dir: str = "artifacts",
    ) -> subprocess.CompletedProcess[str]:
        (root / board).write_bytes(b"(kicad_pcb)\n")
        if project:
            (root / project).write_bytes(b"{\"board\":true}\n")
        if rules_file:
            (root / rules_file).write_bytes(b"(version 1)\n")
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GITHUB_OUTPUT": str(root / "github-output"),
            "GITHUB_STEP_SUMMARY": str(root / "step-summary"),
            "PCBEX_BINARY": str(fake_binary),
            "PCBEX_NATIVE_KICAD_DRC_BOARD": board,
            "PCBEX_NATIVE_KICAD_DRC_PROJECT": project,
            "PCBEX_NATIVE_KICAD_DRC_RULES_FILE": rules_file,
            "PCBEX_NATIVE_KICAD_DRC_KICAD_CLI": "trusted-kicad-cli",
            "PCBEX_NATIVE_KICAD_DRC_REQUIRE_APPROVED": "false",
            "PCBEX_OUTPUT_DIR": output_dir,
            "PCBEX_TEST_MODE": mode,
            "PCBEX_TEST_ARGUMENTS": str(root / "arguments"),
        }
        return subprocess.run(["bash", str(RUNNER)], cwd=root, env=env, capture_output=True, text=True, check=False)

    def test_approved_rejected_and_companions_are_retained(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fake = root / "fake-pcbex"
            self._fake_binary(fake)
            result = self._run(root, fake, project="design.kicad_pro", rules_file="design.kicad_dru")
            self.assertEqual(result.returncode, 0, result.stderr)
            outputs = self._outputs(root / "github-output")
            self.assertEqual(outputs["status"], "ok")
            self.assertEqual(outputs["approved"], "true")
            self.assertEqual(outputs["project-bytes"], "15")
            self.assertRegex(outputs["project-sha256"], r"^[0-9a-f]{64}$")
            report = root / outputs["native-kicad-drc-report"]
            self.assertTrue(report.is_file())
            result = self._run(root, fake, mode="rejected", output_dir="artifacts-rejected")
            self.assertEqual(result.returncode, 0, result.stderr)
            outputs = self._outputs(root / "github-output")
            self.assertEqual(outputs["approved"], "false")
            self.assertEqual(outputs["error-count"], "1")
            self.assertTrue((root / outputs["native-kicad-drc-report"]).is_file())

    def test_option_like_and_space_paths_are_passed_as_single_options(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fake = root / "fake-pcbex"
            self._fake_binary(fake)
            result = self._run(
                root,
                fake,
                board="-design.kicad_pcb",
                project="-design.kicad_pro",
                rules_file="-design.kicad_dru",
                output_dir="-artifacts.with space",
            )
            # A literal output component deliberately rejects spaces; verify a
            # safe literal output while preserving option-like input coverage.
            self.assertNotEqual(result.returncode, 0)
            result = self._run(
                root, fake, board="-design.kicad_pcb", project="-design.kicad_pro",
                rules_file="-design.kicad_dru", output_dir="-artifacts.with-space",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = json.loads((root / "arguments").read_text())
            self.assertIn("--project=-design.kicad_pro", arguments)
            self.assertIn("--rules-file=-design.kicad_dru", arguments)
            self.assertEqual(arguments[-2:], ["--", "-design.kicad_pcb"])

    def test_fatal_and_malformed_evidence_fail_closed_without_success_output(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fake = root / "fake-pcbex"
            self._fake_binary(fake)
            result = self._run(root, fake, mode="fatal")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self._outputs(root / "github-output")["status"], "error")
            result = self._run(root, fake, mode="malformed")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self._outputs(root / "github-output")["status"], "error")

    def test_gate_matrix_checks_wrapper_scan_upload_and_approval(self):
        base = {
            "PCBEX_PREFLIGHT_VALID": "true",
            "PCBEX_NATIVE_DRC_OUTCOME": "success",
            "PCBEX_NATIVE_DRC_STATUS": "ok",
            "PCBEX_NATIVE_DRC_REPORT": "artifacts/native-kicad-drc.json",
            "PCBEX_NATIVE_DRC_APPROVED": "true",
            "PCBEX_ARTIFACT_SAFE": "true",
            "PCBEX_UPLOAD_ARTIFACT": "false",
            "PCBEX_UPLOAD_OUTCOME": "skipped",
            "PCBEX_REQUIRE_APPROVED": "false",
        }
        for key, value in (("PCBEX_NATIVE_DRC_STATUS", "error"), ("PCBEX_NATIVE_DRC_OUTCOME", "failure"), ("PCBEX_ARTIFACT_SAFE", "false")):
            with self.subTest(key=key):
                env = os.environ.copy()
                env.update(base)
                env[key] = value
                result = subprocess.run(["bash", str(GATE)], env=env, capture_output=True, text=True, check=False)
                self.assertNotEqual(result.returncode, 0)
        env = os.environ.copy()
        env.update(base | {"PCBEX_REQUIRE_APPROVED": "true", "PCBEX_NATIVE_DRC_APPROVED": "false"})
        result = subprocess.run(["bash", str(GATE)], env=env, capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_action_contract_and_upload_pin(self):
        document = ACTION.read_text(encoding="utf-8")
        for field in (
            "board", "project", "rules-file", "kicad-cli", "require-approved", "output-dir",
            "upload-artifact", "artifact-name", "retention-days",
            "native-kicad-drc-report", "schema-version", "approved", "violation-count",
            "unconnected-item-count", "schematic-parity-count", "error-count", "warning-count",
            "ignored-check-count", "board-bytes", "board-sha256", "project-bytes", "project-sha256",
            "rules-file-bytes", "rules-file-sha256", "run-sha256", "report-bytes", "report-sha256",
        ):
            self.assertIn(f"  {field}:\n", document)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", document)
        self.assertIn("native-kicad-drc-action-gate.sh", document)


if __name__ == "__main__":
    unittest.main()
