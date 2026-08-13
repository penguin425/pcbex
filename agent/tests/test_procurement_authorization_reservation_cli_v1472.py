from __future__ import annotations

import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import pcbex_agent.cli as cli


_DIGEST = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class ProcurementAuthorizationReservationCliV1472Tests(unittest.TestCase):
    def _argv(self, root: Path) -> list[str]:
        named = {name: root / f"{name}.json" for name in (
            "evidence", "handoff", "board", "package", "binding", "intent",
            "catalog", "cpl", "assembly", "offer", "receipt", "coverage",
            "policy", "report", "approval-a", "approval-b",
        )}
        return [
            "pcbex-agent",
            "reserve-procurement-authorization",
            str(named["evidence"]),
            str(named["handoff"]),
            str(named["board"]),
            str(named["package"]),
            "--board-binding-report", str(named["binding"]),
            "--procurement-intent", str(named["intent"]),
            "--catalog-snapshot", str(named["catalog"]),
            "--final-cpl-report", str(named["cpl"]),
            "--assembly-evidence", str(named["assembly"]),
            "--supplier-offer", str(named["offer"]),
            "--supplier-offer-fetch-receipt", str(named["receipt"]),
            "--supplier-offer-coverage", str(named["coverage"]),
            "--policy-pack", str(named["policy"]),
            "--report", str(named["report"]),
            "--approval", str(named["approval-a"]),
            "--approval", str(named["approval-b"]),
            "--requested-boards", "25",
            "--evaluated-at-unix", "100",
            "--expected-policy-pack-canonical-sha256", "e" * 64,
            "--reservation-ledger", str((root / "ledger").resolve()),
            "--expected-ledger-id", _DIGEST,
            "--timeout-seconds", "90",
        ]

    def test_cli_freshly_validates_then_commits_without_writing_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report = {"procurement_authorized": True}
            marker = {"marker": True}
            stdout = io.StringIO()
            with (
                mock.patch("sys.argv", self._argv(root)),
                mock.patch.object(
                    cli, "validate_procurement_release_authorization", return_value=report
                ) as validate,
                mock.patch.object(
                    cli, "build_procurement_authorization_reservation", return_value=marker
                ) as build,
                mock.patch.object(
                    cli, "commit_procurement_authorization_reservation", return_value=marker
                ) as commit,
                mock.patch.object(cli.time, "monotonic", side_effect=[100.0, 101.0]),
                mock.patch("sys.stdout", stdout),
            ):
                cli.main()
            self.assertEqual(Path(validate.call_args.args[0]), root / "report.json")
            self.assertEqual(validate.call_args.kwargs["timeout_seconds"], 75.0)
            build.assert_called_once_with(report, _DIGEST)
            protected = tuple(commit.call_args.args[4])
            self.assertIn(root / "report.json", protected)
            self.assertIn(root / "approval-a.json", protected)
            self.assertEqual(commit.call_args.kwargs["timeout_seconds"], 89.0)
            self.assertEqual(
                stdout.getvalue(),
                "procurement authorization reserved durably in trusted local ledger\n",
            )

    def test_cli_rejects_negative_before_ledger_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with (
                mock.patch("sys.argv", self._argv(root)),
                mock.patch.object(
                    cli,
                    "validate_procurement_release_authorization",
                    return_value={"procurement_authorized": False},
                ),
                mock.patch.object(
                    cli, "commit_procurement_authorization_reservation"
                ) as commit,
                mock.patch.object(cli.time, "monotonic", return_value=100.0),
            ):
                with self.assertRaisesRegex(
                    SystemExit, "fresh authorization did not authorize"
                ):
                    cli.main()
            commit.assert_not_called()

    def test_cli_windows_gate_fails_before_fresh_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with (
                mock.patch("sys.argv", self._argv(root)),
                mock.patch.object(cli.os, "name", "nt"),
                mock.patch.object(
                    cli, "validate_procurement_release_authorization"
                ) as validate,
            ):
                with self.assertRaisesRegex(SystemExit, "supported only on Unix"):
                    cli.main()
            validate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
