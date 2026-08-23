from __future__ import annotations

from copy import deepcopy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from agent.tests import test_signed_factory_receipt_release_v1480 as v1480_fixture
from pcbex_agent.bounded_process import BoundedProcessResult
from pcbex_agent import cli
from pcbex_agent import signed_factory_receipt_release as v1480
from pcbex_agent import signed_factory_receipt_release_reservation as subject


class SignedFactoryReceiptReleaseReservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        v1480_fixture.SignedFactoryReceiptReleaseTests.setUpClass()
        cls.fixture = v1480_fixture.SignedFactoryReceiptReleaseTests()
        cls.report = cls.fixture._evaluate()
        cls.raw = v1480.render_signed_factory_receipt_release_report(cls.report)

    @classmethod
    def tearDownClass(cls):
        v1480_fixture.SignedFactoryReceiptReleaseTests.tearDownClass()

    def test_builds_compact_authenticated_marker_and_rejects_changed_subject(self):
        marker = subject.build_signed_factory_receipt_release_reservation(
            self.report,
            self.report,
            "1" * 64,
        )
        self.assertTrue(marker["local_challenge_reserved"])
        self.assertFalse(marker["capacity_reserved"])
        self.assertFalse(marker["order_placed"])
        summary = marker["release_report_summary"]
        self.assertTrue(summary["release_authenticated"])
        self.assertEqual(summary["challenge"], "6" * 64)
        self.assertEqual(summary["retained_report_sha256"], summary["fresh_report_sha256"])
        rendered = subject.render_signed_factory_receipt_release_reservation(marker)
        self.assertEqual(rendered[-1:], b"\n")
        self.assertLessEqual(
            len(rendered),
            subject.MAXIMUM_SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_BYTES,
        )

        changed = deepcopy(self.report)
        changed["sources"]["signed_factory_receipt_attestation"]["sha256"] = "f" * 64
        changed["binding_sha256"] = v1480._binding(changed)
        with self.assertRaisesRegex(
            subject.SignedFactoryReceiptReleaseReservationError,
            "changed the retained subject",
        ):
            subject.build_signed_factory_receipt_release_reservation(
                self.report,
                changed,
                "1" * 64,
            )

    def test_negative_fresh_release_is_never_reserved(self):
        negative = self.fixture._evaluate(authenticated=False)
        with self.assertRaisesRegex(
            subject.SignedFactoryReceiptReleaseReservationError,
            "freshly authenticated",
        ):
            subject.build_signed_factory_receipt_release_reservation(
                negative,
                negative,
                "1" * 64,
            )

    def test_retained_report_must_be_exact_canonical_bytes(self):
        normalized = subject.normalize_retained_signed_factory_receipt_release(self.raw)
        self.assertEqual(normalized, self.report)
        compact = json.dumps(self.report, separators=(",", ":")).encode()
        with self.assertRaisesRegex(
            subject.SignedFactoryReceiptReleaseReservationError,
            "not canonical",
        ):
            subject.normalize_retained_signed_factory_receipt_release(compact)

    def test_public_mapping_hook_cannot_change_the_working_directory(self):
        marker = subject.build_signed_factory_receipt_release_reservation(
            self.report,
            self.report,
            "1" * 64,
        )
        entry = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            other = Path(directory).resolve()

            class ChangingMapping(dict):
                def keys(self):
                    os.chdir(other)
                    return super().keys()

            try:
                with self.assertRaisesRegex(
                    subject.SignedFactoryReceiptReleaseReservationError,
                    "changed the working directory",
                ):
                    subject.validate_signed_factory_receipt_release_reservation(
                        ChangingMapping(marker)
                    )
                self.assertEqual(Path.cwd(), entry)
            finally:
                os.chdir(entry)

    @unittest.skipUnless(os.name == "posix", "durable local ledger is Unix-only")
    def test_path_hook_is_rejected_before_the_reservation_helper(self):
        marker = subject.build_signed_factory_receipt_release_reservation(
            self.report,
            self.report,
            "1" * 64,
        )
        entry = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            ledger = root / "ledger"
            ledger.mkdir()
            other = root / "other"
            other.mkdir()

            class ChangingPath:
                def __fspath__(self):
                    os.chdir(other)
                    return str(ledger)

            try:
                with mock.patch.object(subject, "run_bounded") as run:
                    with self.assertRaisesRegex(
                        subject.SignedFactoryReceiptReleaseReservationError,
                        "path or command is invalid",
                    ):
                        subject.commit_signed_factory_receipt_release_reservation(
                            marker,
                            ChangingPath(),
                            "1" * 64,
                            "/trusted/pcbex",
                            (),
                            timeout_seconds=10,
                        )
                    run.assert_not_called()
                self.assertEqual(Path.cwd(), entry)
            finally:
                os.chdir(entry)

    @unittest.skipUnless(os.name == "posix", "durable local ledger is Unix-only")
    def test_commit_stages_exact_marker_and_protects_every_input(self):
        marker = subject.build_signed_factory_receipt_release_reservation(
            self.report,
            self.report,
            "1" * 64,
        )
        expected = subject.render_signed_factory_receipt_release_reservation(marker)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = root / "ledger"
            ledger.mkdir()
            protected = (root / "report.json", root / "package.zip")
            observed = {}

            def run(argv, **_kwargs):
                observed["argv"] = tuple(argv)
                observed["marker"] = Path(argv[2]).read_bytes()
                return BoundedProcessResult(tuple(argv), 0, b"", b"")

            with mock.patch.object(subject, "run_bounded", side_effect=run):
                result = subject.commit_signed_factory_receipt_release_reservation(
                    marker,
                    ledger,
                    "1" * 64,
                    "/trusted/pcbex",
                    protected,
                    timeout_seconds=10,
                )
            self.assertEqual(result, marker)
            self.assertEqual(observed["marker"], expected)
            self.assertEqual(
                observed["argv"][:2],
                (
                    "/trusted/pcbex",
                    "internal-reserve-signed-factory-receipt-release",
                ),
            )
            self.assertEqual(observed["argv"].count("--protected-input"), 2)

            with self.assertRaisesRegex(
                subject.SignedFactoryReceiptReleaseReservationError,
                "path or command is invalid",
            ):
                subject.commit_signed_factory_receipt_release_reservation(
                    marker,
                    Path("relative-ledger"),
                    "1" * 64,
                    "/trusted/pcbex",
                    (),
                    timeout_seconds=10,
                )

            with self.assertRaisesRegex(
                subject.SignedFactoryReceiptReleaseReservationError,
                "path or command is invalid",
            ):
                subject.commit_signed_factory_receipt_release_reservation(
                    marker,
                    ledger,
                    "1" * 64,
                    "/trusted/pcbex",
                    (root / "source.json",) * 129,
                    timeout_seconds=10,
                )

            with mock.patch.object(
                subject,
                "run_bounded",
                return_value=BoundedProcessResult(
                    ("/trusted/pcbex",), 1, b"", b"unexpected helper failure"
                ),
            ):
                with self.assertRaisesRegex(
                    subject.SignedFactoryReceiptReleaseReservationError,
                    "may remain reserved",
                ):
                    subject.commit_signed_factory_receipt_release_reservation(
                        marker,
                        ledger,
                        "1" * 64,
                        "/trusted/pcbex",
                        (),
                        timeout_seconds=10,
                    )

    @unittest.skipUnless(os.name == "posix", "durable local ledger is Unix-only")
    def test_cli_freshly_replays_before_committing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            retained = root / "release.json"
            retained.write_bytes(self.raw)
            ledger = root / "ledger"
            ledger.mkdir()
            sources = self.fixture.sources
            observed = {}

            def commit(marker, reservation_ledger, expected_ledger_id, command, protected, **kwargs):
                observed["marker"] = marker
                observed["ledger"] = reservation_ledger
                observed["expected"] = expected_ledger_id
                observed["command"] = command
                observed["protected"] = tuple(protected)
                observed["timeout"] = kwargs["timeout_seconds"]
                return marker

            argv = [
                "pcbex-agent",
                "reserve-signed-factory-receipt-release",
                str(retained),
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
                "--routing-drc-manufacturing-handoff-report",
                str(sources["release"]),
                "--deterministic-pipeline-plan",
                str(sources["plan"]),
                "--deterministic-pipeline-report",
                str(sources["report"]),
                "--approval",
                str(sources["approvals"][0]),
                "--approval",
                str(sources["approvals"][1]),
                "--routing-drc-fabrication-release-report",
                str(self.fixture.fixture.positive_retained),
                "--executable-pinned-fabrication-release-report",
                str(self.fixture.retained),
                "--factory-receipt",
                str(self.fixture.receipt),
                "--policy-pack",
                str(self.fixture.policy),
                "--signed-factory-receipt-attestation",
                str(self.fixture.root / "signed-True.json"),
                "--expected-policy-pack-canonical-sha256",
                self.fixture.fixture.case.policy_digest,
                "--expected-routing-pcbex-sha256",
                self.fixture.tool_digest,
                "--expected-authorization-pcbex-sha256",
                self.fixture.tool_digest,
                "--expected-kicad-cli-sha256",
                self.fixture.tool_digest,
                "--pcbex",
                str(self.fixture.tool),
                "--authorization-pcbex",
                str(self.fixture.tool),
                "--kicad-cli",
                str(self.fixture.tool),
                "--kicad-project",
                str(sources["project"]),
                "--kicad-rules",
                str(sources["rules"]),
                "--fab-profile",
                str(sources["profile"]),
                "--reservation-ledger",
                str(ledger),
                "--expected-ledger-id",
                "1" * 64,
                "--timeout-seconds",
                "30",
            ]
            with mock.patch.object(cli, "evaluate_signed_factory_receipt_release", return_value=self.report), mock.patch.object(
                cli,
                "commit_signed_factory_receipt_release_reservation",
                side_effect=commit,
            ), mock.patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()) as output:
                cli.main()
            self.assertTrue(observed["marker"]["local_challenge_reserved"])
            self.assertEqual(Path(observed["ledger"]), ledger)
            self.assertEqual(observed["expected"], "1" * 64)
            self.assertIn(retained, observed["protected"])
            self.assertIn(self.fixture.tool, observed["protected"])
            self.assertIn("reserved durably", output.getvalue())


if __name__ == "__main__":
    unittest.main()
