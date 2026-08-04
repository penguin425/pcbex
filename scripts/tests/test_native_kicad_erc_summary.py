"""Unit tests for the standalone native KiCad ERC summary verifier."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "native_kicad_erc_summary.py"
sys.path.insert(0, str(ROOT / "scripts"))
import native_kicad_erc_summary as verifier  # noqa: E402


class NativeKicadErcSummaryTests(unittest.TestCase):
    @staticmethod
    def _sha(payload: bytes) -> str:
        return hashlib.sha256(payload).hexdigest()

    @classmethod
    def _finding(cls, severity: str = "error", finding_type: str = "pin_not_connected") -> dict[str, object]:
        return {
            "description": "synthetic finding",
            "items": [
                {
                    "description": "U1.1",
                    "pos": {"x": 1.25, "y": 2.5},
                    "uuid": "uuid-1",
                }
            ],
            "severity": severity,
            "sheet_path": "/root",
            "sheet_uuid_path": "/root",
            "type": finding_type,
        }

    @classmethod
    def _write_v1(cls, root: Path, *, rejected: bool = False) -> tuple[Path, Path, dict[str, object]]:
        schematic = root / "design.kicad_sch"
        schematic.write_bytes(b"(kicad_sch (version 20231120))\n")
        findings = [cls._finding()] if rejected else []
        report: dict[str, object] = {
            "schema_version": 1,
            "engine": "pcbex",
            "engine_version": "1.427.0-test",
            "kicad_version": "10.0.0-test",
            "source": {"bytes": schematic.stat().st_size, "sha256": cls._sha(schematic.read_bytes())},
            "invocation": {
                "command": "sch erc",
                "format": "json",
                "units": "mm",
                "severity": "error",
                "exit_code_violations": True,
            },
            "ignored_checks": [],
            "findings": findings,
            "error_count": len(findings),
            "approved": not findings,
        }
        report["run_sha256"] = verifier._run_sha256(report, 1)
        report_path = root / "native-kicad-erc.json"
        rendered = (json.dumps(report, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        report_path.write_bytes(rendered)
        return schematic, report_path, report

    @classmethod
    def _write_v2(cls, root: Path, *, rejected: bool = False) -> tuple[Path, Path, Path, dict[str, object]]:
        schematic = root / "design.kicad_sch"
        schematic.write_bytes(b"(kicad_sch (version 20231120))\n")
        policy = {
            "schema_version": 1,
            "id": "default",
            "maximum_total_warnings": 0 if rejected else 1,
            "warning_limits": [{"finding_type": "lib_symbol_issues", "maximum_count": 1}],
            "allowed_ignored_checks": [],
        }
        policy_path = root / "warning-policy.json"
        policy_bytes = (json.dumps(policy, separators=(",", ":")) + "\n").encode("utf-8")
        policy_path.write_bytes(policy_bytes)
        findings = [cls._finding("warning", "lib_symbol_issues")]
        report: dict[str, object] = {
            "schema_version": 2,
            "engine": "pcbex",
            "engine_version": "1.427.0-test",
            "kicad_version": "10.0.0-test",
            "source": {"bytes": len(schematic.read_bytes()), "sha256": cls._sha(schematic.read_bytes())},
            "invocation": {
                "command": "sch erc",
                "format": "json",
                "units": "mm",
                "severities": ["error", "warning"],
                "exit_code_violations": True,
            },
            "ignored_checks": [],
            "findings": findings,
            "error_count": 0,
            "warning_count": 1,
            "warning_counts": [{"finding_type": "lib_symbol_issues", "count": 1}],
            "warning_policy": {
                "source": {"bytes": len(policy_bytes), "sha256": cls._sha(policy_bytes)},
                "policy_sha256": "",
                "policy": policy,
            },
            "policy_failures": [],
            "approved": not rejected,
        }
        report["warning_policy"]["policy_sha256"] = cls._sha(  # type: ignore[index]
            verifier.WARNING_POLICY_DOMAIN + verifier._canonical_policy(policy)
        )
        if rejected:
            report["policy_failures"] = [{
                "code": "total",
                "subject": "total_warnings",
                "actual_count": 1,
                "maximum_count": 0,
            }]
        report["run_sha256"] = verifier._run_sha256(report, 2)
        report_path = root / "native-kicad-erc-v2.json"
        rendered = (json.dumps(report, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        report_path.write_bytes(rendered)
        return schematic, policy_path, report_path, report

    @classmethod
    def _summary(cls, report_path: Path, report: dict[str, object]) -> bytes:
        rendered = report_path.read_bytes()
        summary: dict[str, object] = {
            "schema_version": report["schema_version"],
            "approved": report["approved"],
            "error_count": report["error_count"],
            "run_sha256": report["run_sha256"],
            "report_bytes": len(rendered),
            "report_sha256": cls._sha(rendered),
        }
        if report["schema_version"] == 2:
            summary.update({
                "warning_count": report["warning_count"],
                "policy_failure_count": len(report["policy_failures"]),
                "warning_policy_sha256": report["warning_policy"]["policy_sha256"],  # type: ignore[index]
                "warning_policy_source_bytes": report["warning_policy"]["source"]["bytes"],  # type: ignore[index]
                "warning_policy_source_sha256": report["warning_policy"]["source"]["sha256"],  # type: ignore[index]
            })
        return (json.dumps(summary, separators=(",", ":")) + "\n").encode("utf-8")

    @staticmethod
    def _run(schematic: Path, report: Path, summary: bytes, policy: Path | None = None) -> subprocess.CompletedProcess[bytes]:
        args = [sys.executable, str(SCRIPT), "--verify", "--schematic", str(schematic), "--report", str(report)]
        if policy is not None:
            args.extend(("--warning-policy", str(policy)))
        return subprocess.run(args, input=summary, capture_output=True, check=False)

    def test_rust_zmij_fixed_notation_boundary_for_coordinates(self):
        # serde_json/zmij's f64 boundary keeps e-5 fixed and switches to
        # exponent notation at e-6; exact spelling is authenticated.
        self.assertEqual(verifier._canonical_float(1e-5), "0.00001")
        self.assertEqual(verifier._canonical_float(-1.2e-5), "-0.000012")
        self.assertEqual(verifier._canonical_float(1e-6), "1e-6")
        self.assertEqual(verifier._canonical_float(-1.2e-6), "-1.2e-6")
        ordered = sorted((1.0, 0.0, -0.0, -1.0), key=verifier._f64_total_key)
        self.assertEqual(ordered, [-1.0, -0.0, 0.0, 1.0])

    def test_approved_and_rejected_v1_are_authenticated(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            schematic, report, approved = self._write_v1(root)
            result = self._run(schematic, report, self._summary(report, approved))
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads(result.stdout), json.loads(self._summary(report, approved)))
            schematic, report, rejected = self._write_v1(root, rejected=True)
            result = self._run(schematic, report, self._summary(report, rejected))
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIs(json.loads(result.stdout)["approved"], False)

    def test_approved_and_rejected_v2_are_authenticated(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            schematic, policy, report, approved = self._write_v2(root)
            result = self._run(schematic, report, self._summary(report, approved), policy)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads(result.stdout)["warning_count"], 1)
            schematic, policy, report, rejected = self._write_v2(root, rejected=True)
            result = self._run(schematic, report, self._summary(report, rejected), policy)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads(result.stdout)["policy_failure_count"], 1)
            self.assertIs(json.loads(result.stdout)["approved"], False)

    def test_summary_duplicate_malformed_type_bounds_and_stdin_oversize_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            schematic, report, fixture = self._write_v1(root)
            summary = json.loads(self._summary(report, fixture))
            duplicate = b'{"schema_version":1,"approved":true,"approved":false}'
            malformed = b"{not-json"
            typed = json.dumps(summary | {"error_count": True}, separators=(",", ":")).encode()
            bounded = json.dumps(summary | {"report_bytes": verifier.REPORT_MAX_BYTES + 1}, separators=(",", ":")).encode()
            for payload in (duplicate, malformed, typed, bounded, b"x" * (verifier.SUMMARY_MAX_BYTES + 1)):
                result = self._run(schematic, report, payload)
                self.assertNotEqual(result.returncode, 0, payload[:20])
                self.assertEqual(result.stdout, b"")

    def test_digest_count_decision_source_and_policy_mismatches_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            schematic, report, fixture = self._write_v1(root, rejected=True)
            valid_summary = self._summary(report, fixture)
            report_value = json.loads(report.read_text())
            cases: list[tuple[str, dict[str, object]]] = [
                ("digest", {"run_sha256": "0" * 64}),
                ("count", {"error_count": 0, "approved": True}),
                ("decision", {"approved": True}),
            ]
            for label, mutation in cases:
                with self.subTest(label=label):
                    forged = dict(report_value)
                    forged.update(mutation)
                    report.write_text(json.dumps(forged, separators=(",", ":")) + "\n")
                    result = self._run(schematic, report, valid_summary)
                    self.assertNotEqual(result.returncode, 0)
                    report.write_text(json.dumps(report_value, separators=(",", ":")) + "\n")
            changed_schematic = root / "changed.kicad_sch"
            changed_schematic.write_bytes(b"different")
            result = self._run(changed_schematic, report, valid_summary)
            self.assertNotEqual(result.returncode, 0)

            schematic, policy, report, fixture = self._write_v2(root)
            valid_summary = self._summary(report, fixture)
            altered_policy = root / "altered-policy.json"
            altered_policy.write_bytes(policy.read_bytes().replace(b"default", b"altered"))
            result = self._run(schematic, report, valid_summary, altered_policy)
            self.assertNotEqual(result.returncode, 0)

    def test_duplicate_and_nonstandard_numbers_in_retained_report_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            schematic, report, fixture = self._write_v1(root)
            summary = self._summary(report, fixture)
            original = report.read_bytes()
            duplicate = original.replace(b'"approved":true', b'"approved":true,"approved":true')
            report.write_bytes(duplicate)
            self.assertNotEqual(self._run(schematic, report, summary).returncode, 0)
            report.write_bytes(original.replace(b'"error_count":0', b'"error_count":NaN'))
            self.assertNotEqual(self._run(schematic, report, summary).returncode, 0)

    def test_noncanonical_retained_report_bytes_fail_closed_even_with_recomputed_summary(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            schematic, report, fixture = self._write_v1(root)
            value = json.loads(report.read_text())
            # The Rust CLI emits compact struct-order JSON plus one LF.  A
            # semantically equivalent pretty/reordered document is not trusted
            # merely because the summary digest was recomputed for it.
            reordered = dict(reversed(list(value.items())))
            report.write_text(json.dumps(reordered, indent=2) + "\n")
            self.assertNotEqual(
                self._run(schematic, report, self._summary(report, value)).returncode,
                0,
            )

    def test_v1_unsorted_findings_are_rejected_even_with_self_consistent_identity(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            schematic, report, fixture = self._write_v1(root, rejected=True)
            value = json.loads(report.read_text())
            first = value["findings"][0]
            second = json.loads(json.dumps(first))
            first["description"] = "z-last"
            second["description"] = "a-first"
            value["findings"] = [first, second]
            value["error_count"] = 2
            value["approved"] = False
            value["run_sha256"] = verifier._run_sha256(value, 1)
            report.write_text(json.dumps(value, separators=(",", ":")) + "\n")
            self.assertNotEqual(
                self._run(schematic, report, self._summary(report, value)).returncode,
                0,
            )

    def test_symlinked_report_schematic_and_policy_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            schematic, report, fixture = self._write_v1(root)
            summary = self._summary(report, fixture)
            report_link = root / "report-link.json"
            report_link.symlink_to(report)
            self.assertNotEqual(self._run(schematic, report_link, summary).returncode, 0)
            schematic_link = root / "schematic-link.kicad_sch"
            schematic_link.symlink_to(schematic)
            self.assertNotEqual(self._run(schematic_link, report, summary).returncode, 0)
            schematic, policy, report, fixture = self._write_v2(root)
            policy_link = root / "policy-link.json"
            policy_link.symlink_to(policy)
            self.assertNotEqual(self._run(schematic, report, self._summary(report, fixture), policy_link).returncode, 0)

    def test_policy_presence_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            schematic, report, fixture = self._write_v1(root)
            policy = root / "unused-policy.json"
            policy.write_text("{}")
            self.assertNotEqual(self._run(schematic, report, self._summary(report, fixture), policy).returncode, 0)
            schematic, policy, report, fixture = self._write_v2(root)
            self.assertNotEqual(self._run(schematic, report, self._summary(report, fixture)).returncode, 0)


if __name__ == "__main__":
    unittest.main()
