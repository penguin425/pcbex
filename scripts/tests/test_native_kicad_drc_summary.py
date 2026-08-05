"""Unit tests for the authenticated native KiCad PCB DRC summary bridge."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "native_kicad_drc_summary.py"
sys.path.insert(0, str(ROOT / "scripts"))
import native_kicad_drc_summary as verifier  # noqa: E402


class NativeKicadDrcSummaryTests(unittest.TestCase):
    @staticmethod
    def _sha(payload: bytes) -> str:
        return hashlib.sha256(payload).hexdigest()

    @classmethod
    def _write_report(
        cls,
        root: Path,
        *,
        rejected: bool = False,
        project: bool = False,
        rules_file: bool = False,
    ) -> tuple[Path, Path, Path | None, Path | None, dict[str, object]]:
        board = root / "design.kicad_pcb"
        board.write_bytes(b"(kicad_pcb (version 20240108))\n")
        project_path = root / "design.kicad_pro" if project else None
        rules_path = root / "design.kicad_dru" if rules_file else None
        if project_path is not None:
            project_path.write_bytes(b"{\"board\":true}\n")
        if rules_path is not None:
            rules_path.write_bytes(b"(version 1)\n")
        findings: list[dict[str, object]] = []
        if rejected:
            findings.append(
                {
                    "category": "unconnected-item",
                    "description": "Missing connection between items",
                    "items": [
                        {
                            "description": "PTH pad 1 of J1",
                            "position_nm": {"x": 1_250_000, "y": -2_500_000},
                        }
                    ],
                    "severity": "error",
                    "type": "unconnected_items",
                }
            )
        board_bytes = board.read_bytes()
        project_bytes = None if project_path is None else project_path.read_bytes()
        rules_bytes = None if rules_path is None else rules_path.read_bytes()
        report: dict[str, object] = {
            "schema_version": 1,
            "engine": "pcbex",
            "engine_version": "1.429.0-test",
            "kicad_version": "10.0.5-test",
            "source": {"bytes": len(board_bytes), "sha256": cls._sha(board_bytes)},
            "project": None if project_bytes is None else {"bytes": len(project_bytes), "sha256": cls._sha(project_bytes)},
            "rules_file": None if rules_bytes is None else {"bytes": len(rules_bytes), "sha256": cls._sha(rules_bytes)},
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
            "violation_count": 0,
            "unconnected_item_count": int(rejected),
            "schematic_parity_count": 0,
            "error_count": int(rejected),
            "warning_count": 0,
            "approved": not rejected,
        }
        report["run_sha256"] = verifier._run_sha256(report)
        report_path = root / "native-kicad-drc.json"
        report_path.write_bytes(verifier._canonical_report_bytes(report))
        expected = verifier._validate_report(
            report,
            board=board_bytes,
            project=project_bytes,
            rules_file=rules_bytes,
            report_bytes=report_path.read_bytes(),
        )
        summary = json.dumps(expected, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
        return board, report_path, project_path, rules_path, {"report": report, "summary": summary}

    @staticmethod
    def _run(
        board: Path,
        report: Path,
        summary: bytes,
        project: Path | None = None,
        rules_file: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        args = [sys.executable, str(SCRIPT), "--verify", "--board", str(board), "--report", str(report)]
        if project is not None:
            args.extend(("--project", str(project)))
        if rules_file is not None:
            args.extend(("--rules-file", str(rules_file)))
        return subprocess.run(args, input=summary, capture_output=True, check=False)

    def test_approved_and_rejected_reports_are_authenticated(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            board, report, _, _, fixture = self._write_report(root)
            result = self._run(board, report, fixture["summary"])  # type: ignore[index]
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertTrue(json.loads(result.stdout)["approved"])
            board, report, _, _, fixture = self._write_report(root, rejected=True)
            result = self._run(board, report, fixture["summary"])  # type: ignore[index]
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertFalse(json.loads(result.stdout)["approved"])

    def test_optional_project_and_rules_identities_are_bound(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            board, report, project, rules, fixture = self._write_report(root, project=True, rules_file=True)
            result = self._run(board, report, fixture["summary"], project, rules)  # type: ignore[index]
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            result = self._run(board, report, fixture["summary"], project)
            self.assertNotEqual(result.returncode, 0)
            result = self._run(board, report, fixture["summary"], None, rules)
            self.assertNotEqual(result.returncode, 0)

    def test_digest_count_decision_and_source_mutations_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            board, report, _, _, fixture = self._write_report(root, rejected=True)
            summary = fixture["summary"]  # type: ignore[index]
            value = json.loads(report.read_text())
            for mutation in (
                {"run_sha256": "0" * 64},
                {"error_count": 0, "approved": True},
                {"approved": True},
            ):
                forged = dict(value)
                forged.update(mutation)
                report.write_text(json.dumps(forged, separators=(",", ":")) + "\n")
                self.assertNotEqual(self._run(board, report, summary).returncode, 0)
                report.write_bytes(verifier._canonical_report_bytes(value))
            board.write_bytes(b"changed")
            self.assertNotEqual(self._run(board, report, summary).returncode, 0)

    def test_duplicate_keys_uuid_and_non_integer_position_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            board, report, _, _, fixture = self._write_report(root)
            summary = fixture["summary"]  # type: ignore[index]
            original = report.read_bytes()
            duplicate = original.replace(b'"approved":true', b'"approved":true,"approved":true')
            report.write_bytes(duplicate)
            self.assertNotEqual(self._run(board, report, summary).returncode, 0)
            report.write_bytes(original)
            value = json.loads(original)
            value["findings"] = [{
                "category": "violation",
                "description": "bad",
                "items": [{"description": "x", "position_nm": {"x": 1.5, "y": 2}}],
                "severity": "error",
                "type": "bad",
            }]
            value["violation_count"] = 1
            value["error_count"] = 1
            value["approved"] = False
            # Authenticate the otherwise-valid integer-position report first,
            # then mutate the coordinate to a float for the rejection case.
            value["findings"][0]["items"][0]["position_nm"]["x"] = 1  # type: ignore[index]
            value["run_sha256"] = verifier._run_sha256(value)
            value["findings"][0]["items"][0]["position_nm"]["x"] = 1.5  # type: ignore[index]
            report.write_text(json.dumps(value, separators=(",", ":")) + "\n")
            self.assertNotEqual(self._run(board, report, summary).returncode, 0)
            value["findings"][0]["items"][0]["position_nm"]["x"] = 1  # type: ignore[index]
            value["run_sha256"] = verifier._run_sha256(value)
            value["findings"][0]["items"][0]["uuid"] = "must-not-be-present"  # type: ignore[index]
            report.write_bytes(verifier._canonical_report_bytes(value))
            self.assertNotEqual(self._run(board, report, summary).returncode, 0)

    def test_symlink_and_noncanonical_report_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            board, report, _, _, fixture = self._write_report(root)
            summary = fixture["summary"]  # type: ignore[index]
            report_link = root / "report-link.json"
            report_link.symlink_to(report)
            self.assertNotEqual(self._run(board, report_link, summary).returncode, 0)
            report_link.unlink()
            value = json.loads(report.read_text())
            report.write_text(json.dumps(dict(reversed(list(value.items())),), indent=2) + "\n")
            self.assertNotEqual(self._run(board, report, summary).returncode, 0)

    def test_schematic_parity_is_rejected_when_fixed_invocation_disables_it(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            board, report, _, _, fixture = self._write_report(root)
            value = json.loads(report.read_text())
            value["findings"] = [{
                "category": "schematic-parity",
                "description": "parity",
                "items": [],
                "severity": "error",
                "type": "schematic_parity",
            }]
            value["schematic_parity_count"] = 1
            value["error_count"] = 1
            value["approved"] = False
            value["run_sha256"] = verifier._run_sha256(value)
            report.write_bytes(verifier._canonical_report_bytes(value))
            self.assertNotEqual(self._run(board, report, fixture["summary"]).returncode, 0)  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
