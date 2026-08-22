from __future__ import annotations

from copy import deepcopy
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None

from agent.tests import test_executable_pinned_fabrication_release_v1479 as v1479_fixture
from pcbex_agent.bounded_process import BoundedProcessResult
from pcbex_agent import signed_factory_receipt_release as subject
from pcbex_agent import cli


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class SignedFactoryReceiptReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        v1479_fixture.ExecutablePinnedFabricationReleaseTests.setUpClass()
        cls.fixture = v1479_fixture.ExecutablePinnedFabricationReleaseTests()
        cls._temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls._temporary.name).resolve(strict=True)
        tool_root = cls.root / "tool"
        tool_root.mkdir()
        cls.tool, cls.tool_digest = cls.fixture._native_copy(tool_root)
        cls.nested = cls.fixture._evaluate(cls.tool, cls.tool_digest)
        cls.retained = cls.root / "executable-pinned-release.json"
        cls.retained.write_bytes(
            subject._v1479.render_executable_pinned_fabrication_release_report(cls.nested)
        )
        cls.sources = cls.fixture.positive_sources
        workspace = Path(cls.sources["plan"]).parent
        cls.receipt = workspace / "receipt.json"
        cls.policy = workspace / "policy.json"

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()
        v1479_fixture.ExecutablePinnedFabricationReleaseTests.tearDownClass()

    def _evidence(self) -> dict[str, object]:
        nested_sources = self.nested["routing_drc_fabrication_release"]["sources"]
        fabrication = self.nested["routing_drc_fabrication_release"][
            "fabrication_authorization"
        ]
        return {
            "manufacturing_package": deepcopy(nested_sources["manufacturing_package"]),
            "factory_receipt": deepcopy(nested_sources["factory_receipt"]),
            "provider": "generic",
            "adapter": "generic-factory-http-v1",
            "endpoint": fabrication["factory_receipt"]["endpoint"],
            "response_sha256": "9" * 64,
            "response_bytes": 100,
            "http_status": 200,
            "status": "quoted",
            "accepted": True,
            "dfm_passed": True,
            "quote_sha256": fabrication["factory_receipt"]["quote_sha256"],
            "policy_pack": {
                "source": deepcopy(nested_sources["policy_pack"]),
                "canonical_sha256": self.fixture.case.policy_digest,
                "id": "fixture-policy",
                "revision": 1,
            },
        }

    def _signed(
        self, *, issued_at_unix: int = 100, expires_at_unix: int = 160
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "verification_scope": "policy-pinned-signed-factory-receipt-v1",
            "evidence": self._evidence(),
            "attestation": {
                "attestation_id": "receipt-1480",
                "challenge": "6" * 64,
                "issued_at_unix": issued_at_unix,
                "expires_at_unix": expires_at_unix,
            },
            "factory_id": "factory-a",
            "algorithm": "ed25519",
            "public_key": "7" * 64,
            "signature": "8" * 128,
        }

    def _attestation_report(
        self, signed: dict[str, object], *, authenticated: bool = True
    ) -> dict[str, object]:
        canonical_signed = json.dumps(
            signed, separators=(",", ":"), ensure_ascii=False
        ).encode()
        report: dict[str, object] = {
            "schema_version": 1,
            "verification_scope": "policy-pinned-signed-factory-receipt-v1",
            "status": "receipt_authenticated" if authenticated else "not_authenticated",
            "signature_verified": True,
            "policy_pack_pin_matched": True,
            "attestation_active": authenticated,
            "factory_receipt_authenticity_verified": authenticated,
            "trusted_time_verified": False,
            "factory_legal_identity_verified": False,
            "endpoint_transport_authenticity_verified": False,
            "raw_response_authenticity_verified": False,
            "external_submission_performed": False,
            "capacity_reserved": False,
            "order_placed": False,
            "payment_performed": False,
            "challenge_one_time_use_enforced": False,
            "evidence": deepcopy(signed["evidence"]),
            "attestation": deepcopy(signed["attestation"]),
            "evaluated_at_unix": (
                signed["attestation"]["issued_at_unix"] + 10
                if authenticated
                else signed["attestation"]["expires_at_unix"] + 10
            ),
            "signer": {
                "factory_id": signed["factory_id"],
                "provider": signed["evidence"]["provider"],
                "public_key": signed["public_key"],
                "attestation_sha256": _sha(canonical_signed),
            },
            "signed_attestation": deepcopy(signed),
            "gate_failures": (
                []
                if authenticated
                else ["factory_receipt_attestation_window_inactive"]
            ),
            "binding_sha256": "",
        }
        report["binding_sha256"] = subject._attestation_binding(report)
        return report

    def _evaluate(
        self,
        *,
        authenticated: bool = True,
        substitute: bool = False,
        mutate_staged_policy: bool = False,
        mutate_caller_package: bool = False,
        second_nested: dict[str, object] | None = None,
        issued_at_unix: int = 100,
        expires_at_unix: int = 160,
        clock=None,
    ):
        signed = self._signed(
            issued_at_unix=issued_at_unix,
            expires_at_unix=expires_at_unix,
        )
        signed_path = self.root / (
            "signed-substitute.json" if substitute else f"signed-{authenticated}.json"
        )
        signed_path.unlink(missing_ok=True)
        signed_path.write_bytes((json.dumps(signed, indent=2) + "\n").encode())

        def run(argv, **_kwargs):
            retained = deepcopy(signed)
            if substitute:
                retained["attestation"]["attestation_id"] = "substituted"
            report = self._attestation_report(retained, authenticated=authenticated)
            output = Path(argv[argv.index("--output") + 1])
            output.write_bytes((json.dumps(report, indent=2) + "\n").encode())
            if mutate_staged_policy:
                Path(argv[argv.index("--policy-pack") + 1]).write_bytes(
                    b'{"changed":true}\n'
                )
            if mutate_caller_package:
                Path(self.sources["package"]).write_bytes(b"changed package")
            return BoundedProcessResult(tuple(argv), 0, b"", b"verified\n")

        replay_results = [deepcopy(self.nested), deepcopy(self.nested)]
        if second_nested is not None:
            replay_results[1] = deepcopy(second_nested)
        with mock.patch.object(
            subject._v1479,
            "evaluate_executable_pinned_fabrication_release",
            side_effect=replay_results,
        ), mock.patch.object(subject, "run_bounded", side_effect=run):
            kwargs = {}
            if clock is not None:
                kwargs["_clock"] = clock
            return subject.evaluate_signed_factory_receipt_release(
                self.sources["input"],
                self.sources["routed"],
                self.sources["convergence"],
                self.sources["verification"],
                self.sources["package"],
                self.sources["handoff"],
                self.sources["native_drc"],
                self.sources["release"],
                self.sources["plan"],
                self.sources["report"],
                self.sources["approvals"],
                self.fixture.positive_retained,
                self.retained,
                self.receipt,
                self.policy,
                signed_path,
                self.fixture.case.policy_digest,
                self.tool_digest,
                self.tool_digest,
                self.tool_digest,
                str(self.tool),
                str(self.tool),
                kicad_cli=self.tool,
                kicad_project=self.sources["project"],
                kicad_rules=self.sources["rules"],
                fab_profile=self.sources["profile"],
                **kwargs,
            )

    def test_authenticates_exact_fresh_release_and_retains_false_claims(self):
        result = self._evaluate()
        self.assertEqual(result["status"], "release_authenticated")
        self.assertTrue(result["release_authenticated"])
        self.assertTrue(result["factory_receipt_authenticity_verified"])
        self.assertEqual(result["gate_failures"], [])
        self.assertFalse(result["factory_legal_identity_verified"])
        self.assertFalse(result["raw_response_authenticity_verified"])
        self.assertFalse(result["capacity_reserved"])
        rendered = subject.render_signed_factory_receipt_release_report(result)
        self.assertEqual(rendered[-1:], b"\n")
        if Draft202012Validator is not None:
            Draft202012Validator(
                subject.signed_factory_receipt_release_report_json_schema()
            ).validate(result)

    def test_inactive_attestation_is_a_retained_negative(self):
        result = self._evaluate(authenticated=False)
        self.assertEqual(result["status"], "not_authenticated")
        self.assertFalse(result["release_authenticated"])
        self.assertEqual(
            result["gate_failures"],
            ["factory_receipt_attestation_not_authenticated"],
        )

    def test_verifier_cannot_substitute_signed_attestation(self):
        with self.assertRaisesRegex(
            subject.SignedFactoryReceiptReleaseError,
            "exact submitted attestation",
        ):
            self._evaluate(substitute=True)

    def test_attestation_must_overlap_the_fabrication_authorization_window(self):
        result = self._evaluate(issued_at_unix=4_000, expires_at_unix=4_060)
        self.assertTrue(result["executable_pinned_fabrication_release_authorized"])
        self.assertTrue(result["factory_receipt_authenticity_verified"])
        self.assertFalse(result["release_authenticated"])
        self.assertEqual(
            result["gate_failures"],
            [
                "factory_receipt_attestation_outside_fabrication_authorization_window"
            ],
        )

    def test_path_subclasses_are_rejected_without_running_their_hook(self):
        calls = []
        concrete_path_type = type(Path())

        class HookPath(concrete_path_type):
            def __str__(self):
                calls.append("called")
                return super().__str__()

        with self.assertRaisesRegex(
            subject.SignedFactoryReceiptReleaseError,
            "built-in path representation",
        ):
            subject.evaluate_signed_factory_receipt_release(
                HookPath(self.sources["input"]),
                self.sources["routed"],
                self.sources["convergence"],
                self.sources["verification"],
                self.sources["package"],
                self.sources["handoff"],
                self.sources["native_drc"],
                self.sources["release"],
                self.sources["plan"],
                self.sources["report"],
                self.sources["approvals"],
                self.fixture.positive_retained,
                self.retained,
                self.receipt,
                self.policy,
                self.root / "unused-attestation.json",
                self.fixture.case.policy_digest,
                self.tool_digest,
                self.tool_digest,
                self.tool_digest,
                str(self.tool),
                str(self.tool),
            )
        self.assertEqual(calls, [])

    def test_renderer_rejects_unknown_attestation_gate_even_when_rebound(self):
        report = self._evaluate()
        attestation = report["factory_receipt_attestation"]
        attestation["gate_failures"] = ["unknown_gate"]
        attestation["binding_sha256"] = subject._attestation_binding(attestation)
        report["binding_sha256"] = subject._binding(report)
        with self.assertRaisesRegex(
            subject.SignedFactoryReceiptReleaseError,
            "gate failure is unknown",
        ):
            subject.render_signed_factory_receipt_release_report(report)

    def test_second_replay_subject_substitution_is_rejected(self):
        changed = deepcopy(self.nested)
        pin = changed["executable_pins"]["authorization_pcbex"]
        pin["sha256"] = "e" * 64
        pin["expected_sha256"] = "e" * 64
        changed["binding_sha256"] = subject._v1479._binding(changed)
        with self.assertRaisesRegex(
            subject.SignedFactoryReceiptReleaseError,
            "subject changed",
        ):
            self._evaluate(second_nested=changed)

    def test_staged_policy_mutation_and_backwards_clock_fail_closed(self):
        with self.assertRaisesRegex(
            subject.SignedFactoryReceiptReleaseError,
            "staged factory receipt attestation input changed",
        ):
            self._evaluate(mutate_staged_policy=True)

        observations = iter((10.0, 9.0))
        with self.assertRaisesRegex(
            subject.SignedFactoryReceiptReleaseError,
            "clock moved backwards",
        ):
            self._evaluate(clock=lambda: next(observations))

    def test_final_deadline_and_caller_package_reread_fail_closed(self):
        observations = iter((0.0, 0.0, 0.0, 0.0, 0.0, 301.0))
        with self.assertRaisesRegex(
            subject.SignedFactoryReceiptReleaseError,
            "exceeded its aggregate deadline",
        ):
            self._evaluate(clock=lambda: next(observations))

        package = Path(self.sources["package"])
        original = package.read_bytes()
        try:
            with self.assertRaisesRegex(
                subject.SignedFactoryReceiptReleaseError,
                "manufacturing package changed",
            ):
                self._evaluate(mutate_caller_package=True)
        finally:
            package.write_bytes(original)

    def test_clock_cwd_change_is_restored(self):
        entry = Path.cwd()
        other = self.root / "clock-cwd"
        other.mkdir(exist_ok=True)

        def clock():
            os.chdir(other)
            return 10.0

        with self.assertRaisesRegex(
            subject.SignedFactoryReceiptReleaseError,
            "changed the working directory",
        ):
            self._evaluate(clock=clock)
        self.assertEqual(Path.cwd(), entry)

    def test_schema_is_recursively_closed_and_bounded(self):
        schema = subject.signed_factory_receipt_release_report_json_schema()
        objects = 0
        arrays = 0

        def walk(value):
            nonlocal objects, arrays
            if isinstance(value, dict):
                if value.get("type") == "object":
                    objects += 1
                    self.assertIs(value.get("additionalProperties"), False)
                if value.get("type") == "array":
                    arrays += 1
                    self.assertIn("maxItems", value)
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(schema)
        self.assertGreater(objects, 20)
        self.assertGreater(arrays, 5)

    def test_schema_cli_stdout(self):
        stdout = io.StringIO()
        with mock.patch.object(
            sys,
            "argv",
            ["pcbex-agent", "signed-factory-receipt-release-report-schema"],
        ), redirect_stdout(stdout):
            cli.main()
        self.assertEqual(
            json.loads(stdout.getvalue()),
            subject.signed_factory_receipt_release_report_json_schema(),
        )

    def test_cli_retains_valid_negative_before_require_gate(self):
        result = self._evaluate(authenticated=False)
        rendered = subject.render_signed_factory_receipt_release_report(result)
        output = self.root / "cli-negative.json"
        output.unlink(missing_ok=True)
        argv = [
            "pcbex-agent",
            "replay-signed-factory-receipt-release",
            str(self.sources["input"]),
            str(self.sources["routed"]),
            "--convergence-report",
            str(self.sources["convergence"]),
            "--routing-verification-report",
            str(self.sources["verification"]),
            "--manufacturing-package",
            str(self.sources["package"]),
            "--routing-manufacturing-handoff-report",
            str(self.sources["handoff"]),
            "--native-drc-report",
            str(self.sources["native_drc"]),
            "--routing-drc-manufacturing-handoff-report",
            str(self.sources["release"]),
            "--deterministic-pipeline-plan",
            str(self.sources["plan"]),
            "--deterministic-pipeline-report",
            str(self.sources["report"]),
            "--approval",
            str(self.sources["approvals"][0]),
            "--routing-drc-fabrication-release-report",
            str(self.fixture.positive_retained),
            "--executable-pinned-fabrication-release-report",
            str(self.retained),
            "--factory-receipt",
            str(self.receipt),
            "--policy-pack",
            str(self.policy),
            "--signed-factory-receipt-attestation",
            str(self.root / "signed-False.json"),
            "--expected-policy-pack-canonical-sha256",
            self.fixture.case.policy_digest,
            "--expected-routing-pcbex-sha256",
            self.tool_digest,
            "--expected-authorization-pcbex-sha256",
            self.tool_digest,
            "--expected-kicad-cli-sha256",
            self.tool_digest,
            "--output",
            str(output),
            "--require-authenticated",
        ]
        with mock.patch.object(
            cli, "evaluate_signed_factory_receipt_release", return_value=result
        ), mock.patch.object(
            cli, "render_signed_factory_receipt_release_report", return_value=rendered
        ), mock.patch.object(sys, "argv", argv), self.assertRaisesRegex(
            SystemExit, "was retained but is not authenticated"
        ):
            cli.main()
        self.assertEqual(output.read_bytes(), rendered)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
