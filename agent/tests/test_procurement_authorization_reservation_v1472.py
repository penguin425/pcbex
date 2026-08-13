from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from pcbex_agent.bounded_process import BoundedProcessResult
import pcbex_agent.procurement_authorization_reservation as module


_DIGEST = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def _report() -> dict:
    return {
        "schema_version": 1,
        "status": "procurement_authorized",
        "procurement_authorized": True,
        "adapter_network_performed": False,
        "current_availability_verified": False,
        "supplier_authenticity_verified": False,
        "offer_authenticity_verified": False,
        "price_authenticity_verified": False,
        "receipt_observation_authenticity_verified": False,
        "policy_pack_authenticity_verified": False,
        "trusted_time_verified": False,
        "challenge_one_time_use_enforced": False,
        "evidence": {
            "commercial": {
                "requested_boards": 25,
                "supplier": "supplier-a",
                "offer_id": "offer-1",
                "currency": "USD",
                "covered": True,
                "component_subtotal_micros": 10_000_000,
                "offer_valid_from_unix": 900,
                "offer_valid_until_unix": 2_000,
                "receipt_fetched_at_unix": 950,
            }
        },
        "authorization_scope": {
            "authorization_id": "release-1472",
            "challenge": _DIGEST,
            "requested_boards": 25,
            "currency": "USD",
            "maximum_component_subtotal_micros": 11_000_000,
            "valid_from_unix": 1_000,
            "expires_at_unix": 1_500,
        },
        "policy_pack": {
            "procurement_authorization_policy": {
                "maximum_receipt_observation_age_seconds": 600
            }
        },
        "evaluated_at_unix": 1_100,
        "approvals": 2,
        "rejections": 0,
        "gate_failures": [],
        "binding_sha256": _DIGEST,
    }


def _report_raw(report: dict) -> bytes:
    return (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode()


class ProcurementAuthorizationReservationV1472Tests(unittest.TestCase):
    def _marker(self):
        report = _report()
        raw = _report_raw(report)
        with mock.patch.object(
            module, "render_procurement_authorization_report", return_value=raw
        ):
            marker = module.build_procurement_authorization_reservation(
                report, _DIGEST
            )
        return marker, raw

    def test_marker_binds_exact_report_and_preserves_nonclaims(self):
        marker, report_raw = self._marker()
        summary = marker["authorization_report_summary"]
        self.assertTrue(marker["local_challenge_reserved"])
        self.assertFalse(marker["adapter_network_performed"])
        self.assertFalse(marker["global_challenge_one_time_use_enforced"])
        self.assertFalse(marker["inventory_reserved"])
        self.assertFalse(marker["order_placed"])
        self.assertFalse(marker["payment_performed"])
        self.assertEqual(summary["authorization_id"], "release-1472")
        self.assertEqual(summary["supplier"], "supplier-a")
        self.assertEqual(summary["offer_id"], "offer-1")
        self.assertEqual(summary["requested_boards"], 25)
        self.assertEqual(summary["component_subtotal_micros"], 10_000_000)
        self.assertEqual(summary["maximum_component_subtotal_micros"], 11_000_000)
        self.assertEqual(summary["approvals"], 2)
        for key in (
            "current_availability_verified",
            "supplier_authenticity_verified",
            "offer_authenticity_verified",
            "price_authenticity_verified",
            "receipt_observation_authenticity_verified",
            "policy_pack_authenticity_verified",
            "trusted_time_verified",
            "challenge_one_time_use_enforced",
        ):
            self.assertFalse(summary[key], key)
        self.assertEqual(summary["report_bytes"], len(report_raw))
        self.assertEqual(summary["report_sha256"], hashlib.sha256(report_raw).hexdigest())
        rendered = module.render_procurement_authorization_reservation(marker)
        self.assertEqual(json.loads(rendered), marker)
        self.assertTrue(rendered.endswith(b"\n"))

    def test_builder_rejects_non_authorized_report(self):
        report = _report()
        report["procurement_authorized"] = False
        with mock.patch.object(
            module,
            "render_procurement_authorization_report",
            return_value=_report_raw(report),
        ):
            with self.assertRaisesRegex(
                module.ProcurementAuthorizationReservationError,
                "only a freshly verified authorized",
            ):
                module.build_procurement_authorization_reservation(report, _DIGEST)

    @unittest.skipUnless(os.name == "posix", "local ledger commits require Unix")
    def test_commit_stages_exact_marker_and_invokes_hidden_helper(self):
        marker, _ = self._marker()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            ledger = root / "ledger"
            ledger.mkdir()
            source = root / "source.json"
            source.write_text("source", encoding="utf-8")
            observed = []

            def child(argv, **kwargs):
                observed.append((list(argv), kwargs))
                staged = Path(argv[2]).read_bytes()
                self.assertEqual(
                    staged,
                    module.render_procurement_authorization_reservation(marker),
                )
                return BoundedProcessResult(tuple(argv), 0, b"", b"")

            with mock.patch.object(module, "run_bounded", side_effect=child):
                result = module.commit_procurement_authorization_reservation(
                    marker,
                    ledger,
                    _DIGEST,
                    "pcbex",
                    [source],
                    timeout_seconds=30,
                )
            self.assertEqual(result, marker)
            argv = observed[0][0]
            self.assertEqual(argv[1], "internal-reserve-procurement-authorization")
            self.assertEqual(argv[argv.index("--reservation-ledger") + 1], str(ledger))
            self.assertEqual(argv[argv.index("--protected-input") + 1], str(source))

    @unittest.skipUnless(os.name == "posix", "local ledger commits require Unix")
    def test_commit_detects_workspace_mutation_and_burned_challenge(self):
        marker, _ = self._marker()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            ledger = root / "ledger"
            ledger.mkdir()

            def mutate(argv, **_kwargs):
                Path(argv[2]).write_text("{}\n", encoding="utf-8")
                return BoundedProcessResult(tuple(argv), 0, b"", b"")

            with mock.patch.object(module, "run_bounded", side_effect=mutate):
                with self.assertRaisesRegex(
                    module.ProcurementAuthorizationReservationError,
                    "workspace changed",
                ):
                    module.commit_procurement_authorization_reservation(
                        marker, ledger, _DIGEST, "pcbex", [], timeout_seconds=30
                    )

            burned = BoundedProcessResult(
                ("pcbex",), 1, b"", b"Error: challenge is already reserved\n"
            )
            with mock.patch.object(module, "run_bounded", return_value=burned):
                with self.assertRaisesRegex(
                    module.ProcurementAuthorizationReservationError,
                    "challenge is already reserved",
                ):
                    module.commit_procurement_authorization_reservation(
                        marker, ledger, _DIGEST, "pcbex", [], timeout_seconds=30
                    )

            with (
                mock.patch.object(module.time, "monotonic", side_effect=[100.0, 131.0]),
                mock.patch.object(module, "run_bounded") as child,
            ):
                with self.assertRaisesRegex(
                    module.ProcurementAuthorizationReservationError,
                    "deadline expired before ledger commit",
                ):
                    module.commit_procurement_authorization_reservation(
                        marker, ledger, _DIGEST, "pcbex", [], timeout_seconds=30
                    )
            child.assert_not_called()

    def test_marker_shape_and_platform_gate_fail_closed(self):
        marker, _ = self._marker()
        extra = copy.deepcopy(marker)
        extra["extra"] = True
        with self.assertRaises(module.ProcurementAuthorizationReservationError):
            module.validate_procurement_authorization_reservation(extra)
        with mock.patch.object(module.os, "name", "nt"):
            with self.assertRaisesRegex(
                module.ProcurementAuthorizationReservationError,
                "supported only on Unix",
            ):
                module.commit_procurement_authorization_reservation(
                    marker, "/ledger", _DIGEST, "pcbex", [], timeout_seconds=30
                )


if __name__ == "__main__":
    unittest.main()
