"""Focused contracts for the public fabrication-authorization Action.

The real Rust verifier remains the Ed25519 and fresh-replay authority.  A
deterministic fake binary is used here only to exercise the Action's bounded
stdout/report bridge, argv construction, retention, and final gate.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
ACTION = ROOT / "actions" / "fabrication-authorization" / "action.yml"
WRAPPER = SCRIPTS / "fabrication-authorization-action.sh"
GATE = SCRIPTS / "fabrication-authorization-action-gate.sh"
SUMMARY_HELPER = SCRIPTS / "fabrication_authorization_summary.py"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import fabrication_authorization_summary as summary_helper  # noqa: E402


INPUTS = (
    "plan",
    "retained-report",
    "manufacturing-package",
    "factory-receipt",
    "policy-pack",
    "approval-files",
    "require-authorized",
    "output-dir",
    "upload-artifact",
    "artifact-name",
    "retention-days",
)
SUMMARY_OUTPUTS = (
    "schema-version",
    "authorization-status",
    "fabrication-authorized",
    "authorization-id",
    "challenge",
    "quantity",
    "currency",
    "maximum-total-minor-units",
    "valid-from-unix",
    "expires-at-unix",
    "evaluated-at-unix",
    "approvals",
    "rejections",
    "gate-failure-count",
    "plan-sha256",
    "run-sha256",
    "manufacturing-package-sha256",
    "factory-receipt-sha256",
    "policy-pack-sha256",
    "quote-authenticity-verified",
    "challenge-one-time-use-enforced",
    "report-bytes",
    "report-sha256",
)
OUTPUTS = ("status", "artifact-dir", "fabrication-authorization-report", *SUMMARY_OUTPUTS)
SUMMARY_TO_OUTPUT = dict(zip(summary_helper.SUMMARY_FIELDS, SUMMARY_OUTPUTS))


def _compact(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _identity(payload: bytes) -> dict[str, object]:
    return {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


def _fabrication_key(index: int) -> str:
    return hashlib.sha256(f"fabrication-key-{index:03d}".encode()).hexdigest()


def _policy_pack() -> dict[str, object]:
    trusted = [
        {"signer_id": f"fabricator-{index:03d}", "public_key": _fabrication_key(index)}
        for index in range(100)
    ]
    return {
        "schema_version": 1,
        "id": "test-policy-v1",
        "revision": 1,
        "verified_on": "2026-08-10",
        "description": "Bounded fabrication Action fixture",
        "dfm_profile": {
            "schema_version": 1,
            "id": "test-dfm-v1",
            "aliases": [],
            "revision": 1,
            "verified_on": "2026-08-10",
            "description": "Test DFM profile",
            "source_urls": ["https://example.invalid/dfm"],
            "rules": {
                "minimum_track_width_nm": 100_000,
                "minimum_clearance_nm": 100_000,
                "minimum_drill_nm": 150_000,
                "minimum_annular_ring_nm": 150_000,
                "minimum_copper_to_edge_nm": 200_000,
                "board_thickness_nm": 1_600_000,
                "maximum_via_aspect_ratio": 10,
                "minimum_drill_to_drill_nm": 200_000,
                "allow_via_in_pad": False,
                "minimum_trace_angle_deg": 0,
            },
        },
        "electrical_policy": {"schema_version": 1, "id": "test-electrical-v1", "rules": {}},
        "ai_requirements": [{"id": "review", "text": "Review the design"}],
        "require_simulation_evidence": False,
        "trusted_approval_keys": [{"signer_id": "ai-reviewer", "public_key": "e" * 64}],
        "fabrication_authorization_policy": {
            "minimum_approvals": 2,
            "maximum_validity_seconds": 3600,
            "trusted_keys": trusted,
        },
    }


def _report_and_summary(
    sources: dict[str, bytes], approval_count: int, *, rejected: bool = False
) -> tuple[dict[str, object], bytes, dict[str, object]]:
    policy = json.loads(sources["policy"].decode("utf-8"))
    policy_canonical = _compact(policy)
    evidence = {
        "pipeline": {
            "plan_source": _identity(sources["plan"]),
            "plan_sha256": hashlib.sha256(b"logical-plan").hexdigest(),
            "retained_report": _identity(sources["retained"]),
            "run_sha256": hashlib.sha256(b"pipeline-run").hexdigest(),
        },
        "manufacturing_package": _identity(sources["package"]),
        "factory_receipt": {
            "receipt": _identity(sources["receipt"]),
            "provider": "generic",
            "endpoint": "https://factory.example.invalid/quote",
            "quote_sha256": hashlib.sha256(b"opaque-quote").hexdigest(),
            "quote_authenticity_verified": False,
        },
        "policy_pack": {
            "source": _identity(sources["policy"]),
            "canonical_sha256": hashlib.sha256(policy_canonical).hexdigest(),
            "id": policy["id"],
            "revision": policy["revision"],
        },
    }
    scope = {
        "authorization_id": "fixture-authorization",
        "challenge": hashlib.sha256(b"fixture-challenge").hexdigest(),
        "quantity": 25,
        "currency": "USD",
        "maximum_total_minor_units": 100_000,
        "valid_from_unix": 1_000,
        "expires_at_unix": 2_000,
    }
    signed: list[dict[str, object]] = []
    members: list[dict[str, object]] = []
    for index in range(approval_count):
        decision = "reject" if rejected and index == 0 else "approve"
        approval = {
            "schema_version": 1,
            "evidence": copy.deepcopy(evidence),
            "scope": copy.deepcopy(scope),
            "decision": decision,
            "reason": f"private fabrication reason {index}",
            "ticket": f"private-ticket-{index}",
            "signer_id": f"fabricator-{index:03d}",
            "algorithm": "ed25519",
            "public_key": _fabrication_key(index),
            "signature": hashlib.sha512(f"signature-{index}".encode()).hexdigest(),
        }
        signed.append(approval)
        members.append(
            {
                "signer_id": approval["signer_id"],
                "public_key": approval["public_key"],
                "approval_sha256": hashlib.sha256(_compact(approval)).hexdigest(),
                "decision": decision,
                "reason": approval["reason"],
                "ticket": approval["ticket"],
            }
        )
    approvals = sum(item["decision"] == "approve" for item in signed)
    rejections = len(signed) - approvals
    failures: list[str] = []
    if approvals < 2:
        failures.append(f"insufficient_fabrication_approvals:required=2:actual={approvals}")
    if rejections:
        failures.append(f"human_rejection:count={rejections}")
    failures.sort()
    authorized = not failures
    report: dict[str, object] = {
        "schema_version": 1,
        "status": "fabrication_authorized" if authorized else "not_authorized",
        "evidence": evidence,
        "scope": scope,
        "policy_pack": policy,
        "evaluated_at_unix": 1_500,
        "approvals": approvals,
        "rejections": rejections,
        "members": members,
        "signed_approvals": signed,
        "fabrication_authorized": authorized,
        "gate_failures": failures,
        "challenge_one_time_use_enforced": False,
    }
    report_bytes = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    summary: dict[str, object] = {
        "schema_version": 1,
        "status": report["status"],
        "fabrication_authorized": authorized,
        "authorization_id": scope["authorization_id"],
        "challenge": scope["challenge"],
        "quantity": scope["quantity"],
        "currency": scope["currency"],
        "maximum_total_minor_units": scope["maximum_total_minor_units"],
        "valid_from_unix": scope["valid_from_unix"],
        "expires_at_unix": scope["expires_at_unix"],
        "evaluated_at_unix": report["evaluated_at_unix"],
        "approvals": approvals,
        "rejections": rejections,
        "gate_failure_count": len(failures),
        "plan_sha256": evidence["pipeline"]["plan_sha256"],
        "run_sha256": evidence["pipeline"]["run_sha256"],
        "manufacturing_package_sha256": evidence["manufacturing_package"]["sha256"],
        "factory_receipt_sha256": evidence["factory_receipt"]["receipt"]["sha256"],
        "policy_pack_sha256": evidence["policy_pack"]["source"]["sha256"],
        "quote_authenticity_verified": False,
        "challenge_one_time_use_enforced": False,
        "report_bytes": len(report_bytes),
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }
    return report, report_bytes, summary


def _update_report_identity(summary: dict[str, object], payload: bytes) -> None:
    summary["report_bytes"] = len(payload)
    summary["report_sha256"] = hashlib.sha256(payload).hexdigest()


class FabricationAuthorizationActionTests(unittest.TestCase):
    maxDiff = 4096

    @staticmethod
    def _mapping_keys(document: str, section: str) -> tuple[str, ...]:
        lines = document.splitlines()
        start = lines.index(f"{section}:") + 1
        keys: list[str] = []
        for line in lines[start:]:
            if line and not line.startswith(" "):
                break
            if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
                keys.append(line.strip()[:-1])
        return tuple(keys)

    @staticmethod
    def _write_fake_binary(path: Path) -> None:
        path.write_text(
            textwrap.dedent(
                r"""
                #!/usr/bin/env python3
                import json
                import os
                from pathlib import Path
                import sys

                argv = sys.argv[1:]
                Path(os.environ["PCBEX_TEST_ARGUMENTS"]).write_text(
                    json.dumps(argv), encoding="utf-8"
                )
                if not argv or argv[0] != "verify-fabrication-authorization":
                    raise SystemExit(2)
                mode = os.environ.get("PCBEX_TEST_MODE", "success")
                if mode == "fatal":
                    raise SystemExit(9)
                prefix = "--output="
                output = Path(next(item[len(prefix):] for item in argv if item.startswith(prefix)))
                report = Path(os.environ["PCBEX_TEST_REPORT"]).read_bytes()
                summary = Path(os.environ["PCBEX_TEST_SUMMARY"]).read_bytes()
                if mode != "no-report":
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with output.open("xb") as stream:
                        stream.write(report)
                if mode == "fatal-after-report":
                    raise SystemExit(9)
                if mode == "replacement-report":
                    output.write_bytes(b"{}\n")
                if mode == "oversized-report":
                    with output.open("r+b") as stream:
                        stream.truncate(128 * 1024 * 1024 + 1)
                sys.stdout.buffer.write(summary)
                """
            ).lstrip(),
            encoding="utf-8",
        )
        path.chmod(0o755)

    def _prepare(self) -> tuple[Path, Path]:
        raw = tempfile.mkdtemp()
        root = Path(raw)
        (root / "plan.json").write_bytes(b'{"schema_version":1}\n')
        (root / "retained.json").write_bytes(b'{"approved":true}\n')
        (root / "manufacturing.zip").write_bytes(b"synthetic package")
        (root / "receipt.json").write_bytes(b'{"receipt":"synthetic"}\n')
        (root / "policy.json").write_bytes(_compact(_policy_pack()) + b"\n")
        for index in range(101):
            (root / f"approval-{index:03d}.json").write_bytes(b"{}\n")
        fake = root / "fake-pcbex"
        self._write_fake_binary(fake)
        return root, fake

    @staticmethod
    def _outputs(path: Path) -> dict[str, str]:
        result: dict[str, str] = {}
        if not path.exists():
            return result
        for line in path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                result[key] = value
        return result

    def _payload(
        self,
        root: Path,
        *,
        approval_files: str,
        plan: str,
        retained: str,
        package: str,
        receipt: str,
        policy: str,
        mode: str,
    ) -> None:
        paths = [line for line in approval_files.rstrip("\n").split("\n") if line]
        count = max(1, min(len(paths), 100))
        sources = {
            "plan": (root / plan).read_bytes(),
            "retained": (root / retained).read_bytes(),
            "package": (root / package).read_bytes(),
            "receipt": (root / receipt).read_bytes(),
            "policy": (root / policy).read_bytes(),
        }
        report, report_bytes, summary = _report_and_summary(
            sources, count, rejected=mode == "not-authorized"
        )
        if mode == "unknown-report":
            report["unexpected"] = True
            report_bytes = _compact(report) + b"\n"
            _update_report_identity(summary, report_bytes)
        elif mode == "nested-mismatch":
            report["signed_approvals"][0]["scope"]["quantity"] = 26
            report_bytes = _compact(report) + b"\n"
            _update_report_identity(summary, report_bytes)
        elif mode == "member-mismatch":
            report["members"][0]["approval_sha256"] = "0" * 64
            report_bytes = _compact(report) + b"\n"
            _update_report_identity(summary, report_bytes)
        elif mode == "policy-mismatch":
            report["policy_pack"]["description"] = "changed"
            report_bytes = _compact(report) + b"\n"
            _update_report_identity(summary, report_bytes)
        elif mode == "duplicate-report":
            report_bytes = report_bytes.replace(
                b'{\n  "schema_version": 1,',
                b'{\n  "schema_version": 1,\n  "schema_version": 1,',
                1,
            )
            _update_report_identity(summary, report_bytes)
        if mode == "unknown-summary":
            summary["unexpected"] = True
        elif mode == "type-summary":
            summary["approvals"] = True
        elif mode == "digest-summary":
            summary["report_sha256"] = "0" * 64
        elif mode == "false-constant-summary":
            summary["quote_authenticity_verified"] = True
        summary_bytes = _compact(summary) + b"\n"
        if mode == "malformed-summary":
            summary_bytes = b"{\n"
        elif mode == "duplicate-summary":
            summary_bytes = summary_bytes.replace(
                b'{"schema_version":1,', b'{"schema_version":1,"schema_version":1,', 1
            )
        elif mode == "trailing-summary":
            summary_bytes += b"{}\n"
        (root / "fake-report.json").write_bytes(report_bytes)
        (root / "fake-summary.json").write_bytes(summary_bytes)

    def _run(
        self,
        root: Path,
        fake: Path,
        *,
        mode: str = "success",
        approval_files: str | None = None,
        output_dir: str = "artifacts",
        plan: str = "plan.json",
        retained: str = "retained.json",
        package: str = "manufacturing.zip",
        receipt: str = "receipt.json",
        policy: str = "policy.json",
        require_authorized: str = "false",
    ) -> subprocess.CompletedProcess[str]:
        if approval_files is None:
            approval_files = "approval-000.json\napproval-001.json"
        if approval_files and all(
            (root / item).is_file()
            for item in approval_files.rstrip("\n").split("\n")
            if item
        ):
            self._payload(
                root,
                approval_files=approval_files,
                plan=plan,
                retained=retained,
                package=package,
                receipt=receipt,
                policy=policy,
                mode=mode,
            )
        env = os.environ.copy()
        env.update(
            {
                "GITHUB_OUTPUT": os.fspath(root / "github-output"),
                "GITHUB_STEP_SUMMARY": os.fspath(root / "step-summary"),
                "PCBEX_BINARY": os.fspath(fake),
                "PCBEX_REPOSITORY_ROOT": os.fspath(ROOT),
                "PCBEX_FABRICATION_PLAN": plan,
                "PCBEX_FABRICATION_RETAINED_REPORT": retained,
                "PCBEX_FABRICATION_MANUFACTURING_PACKAGE": package,
                "PCBEX_FABRICATION_FACTORY_RECEIPT": receipt,
                "PCBEX_FABRICATION_POLICY_PACK": policy,
                "PCBEX_FABRICATION_APPROVAL_FILES": approval_files,
                "PCBEX_FABRICATION_REQUIRE_AUTHORIZED": require_authorized,
                "PCBEX_OUTPUT_DIR": output_dir,
                "PCBEX_TEST_ARGUMENTS": os.fspath(root / "arguments.json"),
                "PCBEX_TEST_REPORT": os.fspath(root / "fake-report.json"),
                "PCBEX_TEST_SUMMARY": os.fspath(root / "fake-summary.json"),
                "PCBEX_TEST_MODE": mode,
            }
        )
        return subprocess.run(
            [os.fspath(WRAPPER)],
            cwd=root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )

    def _revalidate(
        self,
        root: Path,
        initial: dict[str, str],
        *,
        scalar_override: tuple[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "GITHUB_OUTPUT": os.fspath(root / "publication-output"),
                "GITHUB_STEP_SUMMARY": os.fspath(root / "publication-summary"),
                "PCBEX_REPOSITORY_ROOT": os.fspath(ROOT),
                "PCBEX_FABRICATION_PLAN": "plan.json",
                "PCBEX_FABRICATION_RETAINED_REPORT": "retained.json",
                "PCBEX_FABRICATION_MANUFACTURING_PACKAGE": "manufacturing.zip",
                "PCBEX_FABRICATION_FACTORY_RECEIPT": "receipt.json",
                "PCBEX_FABRICATION_POLICY_PACK": "policy.json",
                "PCBEX_FABRICATION_APPROVAL_FILES": "approval-000.json\napproval-001.json",
                "PCBEX_FABRICATION_REQUIRE_AUTHORIZED": "false",
                "PCBEX_OUTPUT_DIR": "artifacts",
                "PCBEX_FABRICATION_REPORT": initial["fabrication-authorization-report"],
                "PCBEX_FABRICATION_INPUT_SNAPSHOT": initial["input-snapshot-sha256"],
            }
        )
        for field, output_name in SUMMARY_TO_OUTPUT.items():
            suffix = field.upper()
            env[f"PCBEX_FABRICATION_SUMMARY_{suffix}"] = initial[output_name]
        if scalar_override is not None:
            field, value = scalar_override
            env[f"PCBEX_FABRICATION_SUMMARY_{field.upper()}"] = value
        return subprocess.run(
            [os.fspath(WRAPPER), "--revalidate"],
            cwd=root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )

    @staticmethod
    def _invoke_helper(root: Path, report_bytes: bytes, summary: bytes) -> subprocess.CompletedProcess[bytes]:
        report_path = root / "report.json"
        report_path.write_bytes(report_bytes)
        return subprocess.run(
            [sys.executable, os.fspath(SUMMARY_HELPER), "--verify", "--report=report.json"],
            cwd=root,
            input=summary,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )

    def test_manifest_is_frozen_and_publication_outputs_only(self):
        document = ACTION.read_text(encoding="utf-8")
        self.assertTrue(document.startswith("name: pcbex fabrication authorization verification\n"))
        self.assertEqual(self._mapping_keys(document, "inputs"), INPUTS)
        self.assertEqual(self._mapping_keys(document, "outputs"), OUTPUTS)
        self.assertTrue(
            {"private-key", "signer", "signer-id", "decision", "scope", "evaluated-at", "timeout"}.isdisjoint(INPUTS)
        )
        self.assertNotIn("fabrication-authorization-summary:", document)
        for output in ("artifact-dir", "fabrication-authorization-report", *SUMMARY_OUTPUTS):
            self.assertIn(f"steps.publication-boundary.outputs.{output}", document)
        self.assertLess(document.index("Upload fabrication authorization evidence"), document.index("Enforce fabrication authorization gate"))
        self.assertIn("if: ${{ always() }}", document)
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
            document,
        )
        self.assertIn(
            '-- bash "$PCBEX_REPOSITORY_ROOT/scripts/fabrication-authorization-action.sh"',
            document,
        )

    def test_executable_shells_and_verification_only_attached_argv(self):
        self.assertTrue(WRAPPER.stat().st_mode & 0o111)
        self.assertTrue(GATE.stat().st_mode & 0o111)
        document = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("fabrication_authorization_summary.py", document)
        self.assertIn("verify-fabrication-authorization", document)
        self.assertIn("--mcp-echo-report-summary", document)
        self.assertNotIn("sign-fabrication-approval", document)
        self.assertNotIn("--require-authorized", document)
        for forbidden in ("declare -A", "declare -gA", "cleanup_candidate", "os.unlink"):
            self.assertNotIn(forbidden, document)

    def test_helper_accepts_exact_authorized_and_negative_reports_without_leakage(self):
        for count, rejected in ((2, False), (2, True), (1, False)):
            with self.subTest(count=count, rejected=rejected), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                policy = _compact(_policy_pack()) + b"\n"
                sources = {
                    "plan": b"plan\n",
                    "retained": b"retained\n",
                    "package": b"package\n",
                    "receipt": b"receipt\n",
                    "policy": policy,
                }
                _, report_bytes, summary = _report_and_summary(sources, count, rejected=rejected)
                result = self._invoke_helper(root, report_bytes, _compact(summary) + b"\n")
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(json.loads(result.stdout), summary)
                exposed = result.stdout + result.stderr
                for secret in (b"private fabrication reason", b"private-ticket", b"signed_approvals"):
                    self.assertNotIn(secret, exposed)

    def test_helper_rejects_raw_summary_and_closed_summary_mutations(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            sources = {name: (b"{}\n" if name == "policy" else name.encode()) for name in ("plan", "retained", "package", "receipt", "policy")}
            sources["policy"] = _compact(_policy_pack()) + b"\n"
            _, report_bytes, summary = _report_and_summary(sources, 2)
            valid = _compact(summary) + b"\n"
            cases = {
                "malformed": b"{\n",
                "trailing-object": valid + b"{}\n",
                "extra-lf": valid + b"\n",
                "reordered": _compact(dict(reversed(tuple(summary.items())))) + b"\n",
                "duplicate": valid.replace(b'{"schema_version":1,', b'{"schema_version":1,"schema_version":1,', 1),
                "unknown": _compact({**summary, "unexpected": 1}) + b"\n",
                "missing": _compact({key: value for key, value in summary.items() if key != "challenge"}) + b"\n",
                "type": _compact({**summary, "approvals": True}) + b"\n",
                "digest": _compact({**summary, "report_sha256": "0" * 64}) + b"\n",
                "constant": _compact({**summary, "quote_authenticity_verified": True}) + b"\n",
            }
            for label, payload in cases.items():
                with self.subTest(label=label):
                    result = self._invoke_helper(root, report_bytes, payload)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")

    def test_helper_rejects_strict_report_mutations_and_replacement(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            sources = {
                "plan": b"plan",
                "retained": b"retained",
                "package": b"package",
                "receipt": b"receipt",
                "policy": _compact(_policy_pack()) + b"\n",
            }
            report, original, base_summary = _report_and_summary(sources, 2)
            mutations: dict[str, bytes] = {}
            changed = copy.deepcopy(report)
            changed["unexpected"] = 1
            mutations["unknown"] = _compact(changed) + b"\n"
            changed = copy.deepcopy(report)
            changed["approvals"] = True
            mutations["type"] = _compact(changed) + b"\n"
            changed = copy.deepcopy(report)
            changed["members"][0]["approval_sha256"] = "0" * 64
            mutations["member"] = _compact(changed) + b"\n"
            changed = copy.deepcopy(report)
            changed["signed_approvals"][0]["scope"]["quantity"] = 26
            mutations["nested"] = _compact(changed) + b"\n"
            changed = copy.deepcopy(report)
            changed["policy_pack"]["description"] = "changed"
            mutations["policy"] = _compact(changed) + b"\n"
            changed = copy.deepcopy(report)
            changed["gate_failures"] = ["forged"]
            mutations["status-count"] = _compact(changed) + b"\n"
            mutations["duplicate"] = original.replace(
                b'{\n  "schema_version": 1,', b'{\n  "schema_version": 1,\n  "schema_version": 1,', 1
            )
            for label, payload in mutations.items():
                with self.subTest(label=label):
                    summary = copy.deepcopy(base_summary)
                    _update_report_identity(summary, payload)
                    result = self._invoke_helper(root, payload, _compact(summary) + b"\n")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")
            with mock.patch.object(summary_helper, "read_bytes", side_effect=[b"first", b"second"]):
                with self.assertRaisesRegex(summary_helper.SummaryValidationError, "changed"):
                    summary_helper._stable_read("ignored", maximum=10, role="retained report")

    def test_helper_rejects_oversized_retained_report(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            report = root / "report.json"
            with report.open("wb") as stream:
                stream.truncate(summary_helper.REPORT_MAX_BYTES + 1)
            summary = {field: "" for field in summary_helper.SUMMARY_FIELDS}
            summary.update(
                {
                    "schema_version": 1,
                    "status": "fabrication_authorized",
                    "fabrication_authorized": True,
                    "authorization_id": "a",
                    "challenge": "0" * 64,
                    "quantity": 1,
                    "currency": "USD",
                    "maximum_total_minor_units": 1,
                    "valid_from_unix": 1,
                    "expires_at_unix": 2,
                    "evaluated_at_unix": 1,
                    "approvals": 1,
                    "rejections": 0,
                    "gate_failure_count": 0,
                    "plan_sha256": "0" * 64,
                    "run_sha256": "0" * 64,
                    "manufacturing_package_sha256": "0" * 64,
                    "factory_receipt_sha256": "0" * 64,
                    "policy_pack_sha256": "0" * 64,
                    "quote_authenticity_verified": False,
                    "challenge_one_time_use_enforced": False,
                    "report_bytes": summary_helper.REPORT_MAX_BYTES,
                    "report_sha256": "0" * 64,
                }
            )
            result = subprocess.run(
                [sys.executable, os.fspath(SUMMARY_HELPER), "--verify", "--report=report.json"],
                cwd=root,
                input=_compact(summary) + b"\n",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")

    def test_wrapper_from_caller_cwd_forwards_attached_paths_and_no_gate_flag(self):
        root, fake = self._prepare()
        result = self._run(root, fake)
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = json.loads((root / "arguments.json").read_text(encoding="utf-8"))
        self.assertEqual(argv[0], "verify-fabrication-authorization")
        self.assertIn("--report=retained.json", argv)
        self.assertIn("--manufacturing-package=manufacturing.zip", argv)
        self.assertIn("--factory-receipt=receipt.json", argv)
        self.assertIn("--policy-pack=policy.json", argv)
        self.assertEqual([item for item in argv if item.startswith("--approval=")], ["--approval=approval-000.json", "--approval=approval-001.json"])
        self.assertEqual(argv[-2:], ["--", "plan.json"])
        self.assertNotIn("--require-authorized", argv)
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs["status"], "ok")
        self.assertEqual(outputs["authorization-status"], "fabrication_authorized")
        self.assertEqual(outputs["artifact-dir"], "artifacts")
        exposed = (root / "github-output").read_text() + (root / "step-summary").read_text()
        self.assertNotIn("private fabrication reason", exposed)
        self.assertNotIn("private-ticket", exposed)
        self.assertNotIn("signed_approvals", exposed)

    def test_approval_bounds_and_blank_records(self):
        for count, succeeds in ((0, False), (1, True), (100, True), (101, False)):
            root, fake = self._prepare()
            files = "\n".join(f"approval-{index:03d}.json" for index in range(count))
            result = self._run(root, fake, approval_files=files)
            with self.subTest(count=count):
                self.assertEqual(result.returncode == 0, succeeds, result.stderr)
                self.assertEqual((root / "arguments.json").exists(), succeeds)
                if count in (1, 100):
                    outputs = self._outputs(root / "github-output")
                    self.assertEqual(outputs["fabrication-authorized"], "true" if count == 100 else "false")
        root, fake = self._prepare()
        result = self._run(
            root,
            fake,
            approval_files="approval-000.json\n\napproval-001.json",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / "arguments.json").exists())

    def test_option_like_space_paths_links_and_no_clobber(self):
        root, fake = self._prepare()
        renames = {
            "plan.json": "-plan with space.json",
            "retained.json": "-retained report.json",
            "manufacturing.zip": "-manufacturing package.zip",
            "receipt.json": "-factory receipt.json",
            "policy.json": "-policy pack.json",
            "approval-000.json": "-approval one.json",
            "approval-001.json": "-approval two.json",
        }
        for source, target in renames.items():
            (root / source).rename(root / target)
        result = self._run(
            root,
            fake,
            plan=renames["plan.json"],
            retained=renames["retained.json"],
            package=renames["manufacturing.zip"],
            receipt=renames["receipt.json"],
            policy=renames["policy.json"],
            approval_files=f'{renames["approval-000.json"]}\n{renames["approval-001.json"]}',
            output_dir="output-space",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = json.loads((root / "arguments.json").read_text())
        self.assertEqual(argv[-2:], ["--", "-plan with space.json"])
        self.assertIn("--report=-retained report.json", argv)

        linked_root, linked_fake = self._prepare()
        (linked_root / "linked-plan.json").symlink_to(linked_root / "plan.json")
        linked = self._run(linked_root, linked_fake, plan="linked-plan.json")
        self.assertNotEqual(linked.returncode, 0)
        self.assertFalse((linked_root / "arguments.json").exists())

        stale_root, stale_fake = self._prepare()
        stale = stale_root / "artifacts"
        stale.mkdir()
        marker = stale / "fabrication-authorization.json"
        marker.write_bytes(b"do not overwrite")
        rejected = self._run(stale_root, stale_fake)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(marker.read_bytes(), b"do not overwrite")
        self.assertFalse((stale_root / "arguments.json").exists())

    def test_wrapper_rejects_summary_and_report_mutations_without_exposure(self):
        modes = (
            "malformed-summary",
            "duplicate-summary",
            "trailing-summary",
            "unknown-summary",
            "type-summary",
            "digest-summary",
            "false-constant-summary",
            "duplicate-report",
            "unknown-report",
            "nested-mismatch",
            "member-mismatch",
            "policy-mismatch",
            "replacement-report",
            "oversized-report",
            "no-report",
            "fatal-after-report",
        )
        for mode in modes:
            root, fake = self._prepare()
            result = self._run(root, fake, mode=mode)
            with self.subTest(mode=mode):
                self.assertNotEqual(result.returncode, 0)
                outputs = self._outputs(root / "github-output")
                self.assertEqual(outputs.get("fabrication-authorization-report", ""), "")
                self.assertEqual(outputs.get("artifact-dir", ""), "")
                self.assertEqual(outputs.get("authorization-status", ""), "")

    def test_valid_not_authorized_is_retained_then_final_gate_enforces(self):
        root, fake = self._prepare()
        result = self._run(root, fake, mode="not-authorized", require_authorized="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs["authorization-status"], "not_authorized")
        self.assertEqual(outputs["fabrication-authorized"], "false")
        self.assertTrue((root / outputs["fabrication-authorization-report"]).is_file())
        gate_env = os.environ.copy()
        gate_env.update(
            {
                "PCBEX_PREFLIGHT_VALID": "true",
                "PCBEX_FABRICATION_OUTCOME": "success",
                "PCBEX_FABRICATION_STATUS": "ok",
                "PCBEX_FABRICATION_REPORT": outputs["fabrication-authorization-report"],
                "PCBEX_FABRICATION_AUTHORIZED": "false",
                "PCBEX_ARTIFACT_SAFE": "true",
                "PCBEX_PUBLICATION_SAFE": "true",
                "PCBEX_UPLOAD_ARTIFACT": "true",
                "PCBEX_UPLOAD_OUTCOME": "success",
                "PCBEX_REQUIRE_AUTHORIZED": "true",
                "PCBEX_OUTPUT_DIR": "artifacts",
            }
        )
        gate = subprocess.run(
            [os.fspath(GATE)],
            cwd=root,
            env=gate_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(gate.returncode, 0)
        gate_env["PCBEX_REQUIRE_AUTHORIZED"] = "false"
        permissive = subprocess.run(
            [os.fspath(GATE)],
            cwd=root,
            env=gate_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertEqual(permissive.returncode, 0, permissive.stderr)

    def test_publication_revalidation_exposes_only_authenticated_final_outputs(self):
        root, fake = self._prepare()
        verified = self._run(root, fake)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        initial = self._outputs(root / "github-output")
        publication = self._revalidate(root, initial)
        self.assertEqual(publication.returncode, 0, publication.stderr)
        outputs = self._outputs(root / "publication-output")
        self.assertEqual(
            set(outputs),
            {"artifact-dir", "fabrication-authorization-report", *SUMMARY_OUTPUTS, "safe"},
        )
        self.assertEqual(outputs["safe"], "true")
        self.assertEqual(outputs["artifact-dir"], "artifacts")
        self.assertEqual(
            outputs["fabrication-authorization-report"],
            "artifacts/fabrication-authorization.json",
        )
        for output_name in SUMMARY_OUTPUTS:
            self.assertEqual(outputs[output_name], initial[output_name])

    def test_publication_revalidation_rejects_replacement_input_change_and_scalar_mismatch(self):
        for mutation in ("report", "input", "scalar", "extra"):
            root, fake = self._prepare()
            verified = self._run(root, fake)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            initial = self._outputs(root / "github-output")
            scalar_override = None
            if mutation == "report":
                (root / initial["fabrication-authorization-report"]).write_bytes(b"{}\n")
            elif mutation == "input":
                (root / "plan.json").write_bytes(b"changed after verification\n")
            elif mutation == "scalar":
                scalar_override = ("report_sha256", "0" * 64)
            else:
                (root / "artifacts" / "injected.txt").write_bytes(b"unexpected\n")
            publication = self._revalidate(
                root,
                initial,
                scalar_override=scalar_override,
            )
            with self.subTest(mutation=mutation):
                self.assertNotEqual(publication.returncode, 0)
                outputs = self._outputs(root / "publication-output")
                self.assertNotEqual(outputs.get("safe"), "true")
                self.assertNotIn("artifact-dir", outputs)
                self.assertNotIn("fabrication-authorization-report", outputs)

    def test_final_gate_upload_publication_and_verifier_matrix(self):
        base = {
            "PCBEX_PREFLIGHT_VALID": "true",
            "PCBEX_FABRICATION_OUTCOME": "success",
            "PCBEX_FABRICATION_STATUS": "ok",
            "PCBEX_FABRICATION_REPORT": "artifacts/fabrication-authorization.json",
            "PCBEX_FABRICATION_AUTHORIZED": "true",
            "PCBEX_ARTIFACT_SAFE": "true",
            "PCBEX_PUBLICATION_SAFE": "true",
            "PCBEX_UPLOAD_ARTIFACT": "true",
            "PCBEX_UPLOAD_OUTCOME": "success",
            "PCBEX_REQUIRE_AUTHORIZED": "false",
            "PCBEX_OUTPUT_DIR": "artifacts",
        }
        cases = (
            ("upload-failed", {"PCBEX_UPLOAD_OUTCOME": "failure"}, False),
            (
                "upload-disabled",
                {"PCBEX_UPLOAD_ARTIFACT": "false", "PCBEX_UPLOAD_OUTCOME": "skipped"},
                True,
            ),
            ("publication-failed", {"PCBEX_PUBLICATION_SAFE": "false"}, False),
            ("verifier-failed", {"PCBEX_FABRICATION_OUTCOME": "failure"}, False),
            ("status-error", {"PCBEX_FABRICATION_STATUS": "error"}, False),
        )
        for label, changes, succeeds in cases:
            env = os.environ.copy()
            env.update(base)
            env.update(changes)
            result = subprocess.run(
                [os.fspath(GATE)],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            with self.subTest(label=label):
                self.assertEqual(result.returncode == 0, succeeds, result.stderr)


if __name__ == "__main__":
    unittest.main()
