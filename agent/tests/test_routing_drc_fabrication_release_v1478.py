from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
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

from agent.tests import test_routing_drc_manufacturing_handoff_v1477 as v1477_fixture
from pcbex_agent import cli
from pcbex_agent.routing_drc_fabrication_release import (
    RoutingDrcFabricationReleaseError,
    evaluate_routing_drc_fabrication_release,
    render_routing_drc_fabrication_release_report,
    routing_drc_fabrication_release_report_json_schema,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _descriptor(path: str, raw: bytes) -> dict[str, object]:
    return {"path": path, "bytes": len(raw), "sha256": _sha(raw)}


def _write_fake_authorization(
    root: Path,
    *,
    canonical_policy_digest: str,
    authorized: bool = True,
    forge_summary: str | None = None,
    substitute_approval: bool = False,
    mutate_staged_policy: bool = False,
) -> list[str]:
    config = root / "fake-authorization-config.json"
    config.write_text(
        json.dumps(
            {
                "canonical_policy_digest": canonical_policy_digest,
                "authorized": authorized,
                "forge_summary": forge_summary,
                "substitute_approval": substitute_approval,
                "mutate_staged_policy": mutate_staged_policy,
            }
        ),
        encoding="utf-8",
    )
    script = root / "fake-authorization-pcbex.py"
    script.write_text(
        r'''from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).parent
config = json.loads((root / "fake-authorization-config.json").read_text())
argv = sys.argv[1:]
if not argv or argv[0] != "verify-fabrication-authorization":
    raise SystemExit(91)

def option(name: str) -> str:
    for index, value in enumerate(argv):
        if value == "--" + name:
            return argv[index + 1]
    raise SystemExit(92)

def options(name: str) -> list[str]:
    return [argv[index + 1] for index, value in enumerate(argv) if value == "--" + name]

def identity(raw: bytes) -> dict[str, object]:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

plan_raw = Path(argv[1]).read_bytes()
pipeline_raw = Path(option("report")).read_bytes()
package_raw = Path(option("manufacturing-package")).read_bytes()
receipt_raw = Path(option("factory-receipt")).read_bytes()
policy_raw = Path(option("policy-pack")).read_bytes()
approvals_raw = [Path(path).read_bytes() for path in options("approval")]
approval_values = [json.loads(raw) for raw in approvals_raw]
signed_values = sorted(approval_values, key=lambda value: value["signer_id"])
if config["substitute_approval"]:
    signed_values[0] = dict(signed_values[0])
    signed_values[0]["fixture"] = 999
authorized = config["authorized"]
gates = [] if authorized else ["insufficient_fabrication_approvals"]
scope = {
    "authorization_id": "release-fixture",
    "challenge": "a" * 64,
    "quantity": 20,
    "currency": "USD",
    "maximum_total_minor_units": 25000,
    "valid_from_unix": 1,
    "expires_at_unix": 3601,
}
evidence = {
    "pipeline": {
        "plan_source": identity(plan_raw),
        "plan_sha256": "b" * 64,
        "retained_report": identity(pipeline_raw),
        "run_sha256": "c" * 64,
    },
    "manufacturing_package": identity(package_raw),
    "factory_receipt": {
        "receipt": identity(receipt_raw),
        "provider": "generic",
        "endpoint": "https://factory.example/quote",
        "quote_sha256": "d" * 64,
        "quote_authenticity_verified": False,
    },
    "policy_pack": {
        "source": identity(policy_raw),
        "canonical_sha256": config["canonical_policy_digest"],
        "id": "fixture-policy",
        "revision": 1,
    },
}
approvals = len(approvals_raw) if authorized else 0
rejections = 0 if authorized else len(approvals_raw)
report = {
    "schema_version": 1,
    "status": "fabrication_authorized" if authorized else "not_authorized",
    "evidence": evidence,
    "scope": scope,
    "policy_pack": json.loads(policy_raw),
    "evaluated_at_unix": 100,
    "approvals": approvals,
    "rejections": rejections,
    "members": [{} for _ in approvals_raw],
    "signed_approvals": signed_values,
    "fabrication_authorized": authorized,
    "gate_failures": gates,
    "challenge_one_time_use_enforced": False,
}
raw = (json.dumps(report, indent=2) + "\n").encode()
Path(option("output")).write_bytes(raw)
if config["mutate_staged_policy"]:
    Path(option("policy-pack")).write_bytes(b'{"changed":true}\n')
summary = {
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
    "gate_failure_count": len(gates),
    "plan_sha256": evidence["pipeline"]["plan_sha256"],
    "run_sha256": evidence["pipeline"]["run_sha256"],
    "manufacturing_package_sha256": evidence["manufacturing_package"]["sha256"],
    "factory_receipt_sha256": evidence["factory_receipt"]["receipt"]["sha256"],
    "policy_pack_sha256": evidence["policy_pack"]["source"]["sha256"],
    "quote_authenticity_verified": False,
    "challenge_one_time_use_enforced": False,
    "report_bytes": len(raw),
    "report_sha256": hashlib.sha256(raw).hexdigest(),
}
if config["forge_summary"]:
    summary[config["forge_summary"]] = "0" * 64
sys.stdout.write(json.dumps(summary, separators=(",", ":")) + "\n")
''',
        encoding="utf-8",
    )
    return [sys.executable, str(script)]


class RoutingDrcFabricationReleaseTests(unittest.TestCase):
    policy_digest = "e" * 64

    def _pipeline(self, root: Path, package_raw: bytes) -> dict[str, object]:
        workspace = root / "pipeline"
        workspace.mkdir()
        firmware = workspace / "firmware"
        firmware.mkdir()
        roles: dict[str, bytes] = {
            "circuit_spec": b'{"schema_version":2}\n',
            "schematic": b"(kicad_sch)\n",
            "electrical_review": b'{"approved":true}\n',
            "board": b"(kicad_pcb)\n",
            "analysis_manifest": b'{"schema_version":1}\n',
            "analysis_checks": b'{"checks":[]}\n',
            "quality": b'{"passed":true}\n',
            "manufacturing_package": package_raw,
            "firmware_manifest": b'{"schema_version":2}\n',
            "analysis_policy_pack": b'{"id":"fixture-policy","revision":1}\n',
            "factory_receipt": b'{"status":"quoted"}\n',
        }
        role_paths = {
            "circuit_spec": "circuit.json",
            "schematic": "board.kicad_sch",
            "electrical_review": "electrical.json",
            "board": "board.kicad_pcb",
            "analysis_manifest": "analysis-manifest.json",
            "analysis_checks": "analysis-checks.json",
            "quality": "quality.json",
            "manufacturing_package": "manufacturing.zip",
            "firmware_manifest": "firmware/manifest.json",
            "analysis_policy_pack": "policy.json",
            "factory_receipt": "receipt.json",
        }
        for role, raw in roles.items():
            (workspace / role_paths[role]).write_bytes(raw)
        for name in (
            "pinout.h",
            "firmware.h",
            "firmware.c",
            "firmware_smoke_test.c",
            "firmware.cpp",
            "firmware_cpp_smoke_test.cpp",
            "host.py",
        ):
            (firmware / name).write_bytes((name + "\n").encode())
        required = (
            "circuit_spec",
            "schematic",
            "electrical_review",
            "board",
            "analysis_manifest",
            "analysis_checks",
            "quality",
            "manufacturing_package",
            "firmware_manifest",
        )
        optional = (
            "electrical_policy",
            "analysis_project",
            "analysis_rules",
            "analysis_dfm_profile",
            "analysis_policy_pack",
            "analysis_physical_profile",
            "factory_receipt",
        )
        plan: dict[str, object] = {"schema_version": 1}
        for role in required:
            plan[role] = _descriptor(role_paths[role], roles[role])
        for role in optional:
            plan[role] = (
                _descriptor(role_paths[role], roles[role]) if role in roles else None
            )
        plan["require_factory"] = True
        plan_path = workspace / "plan.json"
        plan_path.write_bytes((json.dumps(plan, separators=(",", ":")) + "\n").encode())
        report_path = workspace / "pipeline-report.json"
        report_path.write_bytes(b'{"fixture":"factory-pipeline"}\n')
        approvals = []
        for index in range(2):
            path = workspace / f"approval-{index}.json"
            path.write_bytes(
                (
                    json.dumps(
                        {
                            "signer_id": f"fabrication-{chr(ord('a') + index)}",
                            "fixture": index,
                        },
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode()
            )
            approvals.append(path)
        return {
            "plan": plan_path,
            "report": report_path,
            "approvals": approvals,
        }

    def _prepare(
        self,
        root: Path,
        *,
        drc_approved: bool = True,
        fabrication_authorized: bool = True,
        forge_summary: str | None = None,
        substitute_approval: bool = False,
        mutate_staged_policy: bool = False,
    ) -> tuple[dict[str, object], list[str], list[str]]:
        v1477 = v1477_fixture.RoutingDrcManufacturingHandoffTests()
        sources, routing_command = v1477._prepare(root, drc_approved=drc_approved)
        release = v1477._evaluate(sources, routing_command)
        retained_release = root / "routing-drc-manufacturing.json"
        from pcbex_agent.routing_drc_manufacturing_handoff import (
            render_routing_drc_manufacturing_handoff_report,
        )

        retained_release.write_bytes(
            render_routing_drc_manufacturing_handoff_report(release)
        )
        sources["release"] = retained_release
        sources.update(self._pipeline(root, sources["package_raw"]))
        authorization_command = _write_fake_authorization(
            root,
            canonical_policy_digest=self.policy_digest,
            authorized=fabrication_authorized,
            forge_summary=forge_summary,
            substitute_approval=substitute_approval,
            mutate_staged_policy=mutate_staged_policy,
        )
        calls = root / "calls.json"
        if calls.exists():
            calls.unlink()
        return sources, routing_command, authorization_command

    def _evaluate(
        self,
        sources: dict[str, object],
        routing_command: list[str],
        authorization_command: list[str],
        *,
        expected_digest: str | None = None,
        clock=None,
    ) -> dict[str, object]:
        keyword_arguments = {}
        if clock is not None:
            keyword_arguments["_clock"] = clock
        return evaluate_routing_drc_fabrication_release(
            sources["input"],
            sources["routed"],
            sources["convergence"],
            sources["verification"],
            sources["package"],
            sources["handoff"],
            sources["native_drc"],
            sources["release"],
            sources["plan"],
            sources["report"],
            sources["approvals"],
            self.policy_digest if expected_digest is None else expected_digest,
            routing_command,
            authorization_command,
            kicad_project=sources["project"],
            kicad_rules=sources["rules"],
            fab_profile=sources["profile"],
            **keyword_arguments,
        )

    def test_positive_cross_binds_ready_package_and_policy_pinned_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, routing, authorization = self._prepare(root)
            result = self._evaluate(sources, routing, authorization)
            self.assertEqual(result["status"], "release_authorized")
            self.assertTrue(result["routing_drc_manufacturing_ready"])
            self.assertTrue(result["fabrication_authorized"])
            self.assertTrue(result["release_authorized"])
            self.assertEqual(result["gate_failures"], [])
            self.assertEqual(
                result["routing_drc_manufacturing"]["manufacturing_package"],
                result["fabrication_authorization"]["manufacturing_package"],
            )
            self.assertEqual(
                result["policy_pin"]["expected_canonical_sha256"],
                self.policy_digest,
            )
            for claim in (
                "source_authenticity_verified",
                "toolchain_authenticity_verified",
                "policy_pack_authenticity_verified",
                "factory_receipt_authenticity_verified",
                "manufacturability_verified",
                "external_submission_performed",
                "capacity_reserved",
                "order_placed",
                "payment_performed",
                "challenge_one_time_use_enforced",
            ):
                self.assertFalse(result[claim])
            rendered = render_routing_drc_fabrication_release_report(result)
            self.assertEqual(rendered[-1:], b"\n")
            self.assertNotIn(str(root).encode(), rendered)
            if Draft202012Validator is not None:
                Draft202012Validator(
                    routing_drc_fabrication_release_report_json_schema()
                ).validate(result)

    def test_valid_negative_retains_each_independent_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, routing, authorization = self._prepare(
                root, drc_approved=False, fabrication_authorized=False
            )
            result = self._evaluate(sources, routing, authorization)
            self.assertEqual(result["status"], "not_authorized")
            self.assertEqual(
                result["gate_failures"],
                [
                    "routing_drc_manufacturing_not_ready",
                    "fabrication_not_authorized",
                ],
            )
            self.assertEqual(
                result["fabrication_authorization"]["gate_failures"],
                ["insufficient_fabrication_approvals"],
            )

    def test_policy_pin_package_and_child_summary_substitution_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, routing, authorization = self._prepare(root)
            with self.assertRaisesRegex(
                RoutingDrcFabricationReleaseError, "policy does not match"
            ):
                self._evaluate(sources, routing, authorization, expected_digest="f" * 64)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, routing, authorization = self._prepare(root)
            (Path(sources["plan"]).parent / "manufacturing.zip").write_bytes(b"different")
            with self.assertRaises(RoutingDrcFabricationReleaseError):
                self._evaluate(sources, routing, authorization)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, routing, authorization = self._prepare(
                root, forge_summary="report_sha256"
            )
            with self.assertRaisesRegex(
                RoutingDrcFabricationReleaseError, "summary does not match"
            ):
                self._evaluate(sources, routing, authorization)

    def test_pipeline_closure_is_captured_before_the_approval_iterator(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, routing, authorization = self._prepare(root)
            policy = Path(sources["plan"]).parent / "policy.json"
            original = policy.read_bytes()
            policy.write_bytes(b'{"id":"pre-call-invalid"}\n')

            class RepairingApprovals:
                calls = 0

                def __iter__(self):
                    self.calls += 1
                    policy.write_bytes(original)
                    return iter(sources["approvals"])

            approvals = RepairingApprovals()
            sources["approvals"] = approvals
            with self.assertRaisesRegex(
                RoutingDrcFabricationReleaseError,
                "pipeline closure capture failed",
            ):
                self._evaluate(sources, routing, authorization)
            self.assertEqual(approvals.calls, 0)

    def test_approval_must_not_alias_an_internal_pipeline_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, routing, authorization = self._prepare(root)
            policy = Path(sources["plan"]).parent / "policy.json"
            approval = Path(sources["approvals"][0])
            approval.unlink()
            try:
                os.link(policy, approval)
            except OSError as error:
                self.skipTest(f"hard links unavailable: {error}")
            with self.assertRaisesRegex(
                RoutingDrcFabricationReleaseError,
                "approval must not alias a pipeline input",
            ):
                self._evaluate(sources, routing, authorization)

    def test_child_cannot_substitute_approvals_or_mutate_staged_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, routing, authorization = self._prepare(
                root, substitute_approval=True
            )
            with self.assertRaisesRegex(
                RoutingDrcFabricationReleaseError,
                "exact submitted approvals",
            ):
                self._evaluate(sources, routing, authorization)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, routing, authorization = self._prepare(
                root, mutate_staged_policy=True
            )
            with self.assertRaisesRegex(
                RoutingDrcFabricationReleaseError,
                "trusted release workspace input changed",
            ):
                self._evaluate(sources, routing, authorization)

    def test_backwards_clock_and_cwd_changing_path_hook_fail_before_children(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, routing, authorization = self._prepare(root)
            hooks: list[str] = []

            class StatefulDigest(str):
                def __len__(self):
                    hooks.append("len")
                    return super().__len__()

                def __iter__(self):
                    hooks.append("iter")
                    return super().__iter__()

            with self.assertRaisesRegex(
                RoutingDrcFabricationReleaseError,
                "expected policy pack digest",
            ):
                self._evaluate(
                    sources,
                    routing,
                    authorization,
                    expected_digest=StatefulDigest(self.policy_digest),
                )
            self.assertEqual(hooks, [])
            self.assertFalse((root / "calls.json").exists())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, routing, authorization = self._prepare(root)
            samples = iter((10.0, 9.0))
            with self.assertRaisesRegex(
                RoutingDrcFabricationReleaseError, "clock moved backwards"
            ):
                self._evaluate(
                    sources,
                    routing,
                    authorization,
                    clock=lambda: next(samples),
                )
            self.assertFalse((root / "calls.json").exists())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, routing, authorization = self._prepare(root)
            changed = root / "changed-cwd"
            changed.mkdir()
            entry = Path.cwd()

            class ChangingPath:
                def __fspath__(self):
                    os.chdir(changed)
                    return os.fspath(sources["input"])

            sources["input"] = ChangingPath()
            with self.assertRaisesRegex(
                RoutingDrcFabricationReleaseError, "changed the working directory"
            ):
                self._evaluate(sources, routing, authorization)
            self.assertEqual(Path.cwd(), entry)
            self.assertFalse((root / "calls.json").exists())

    def test_renderer_rejects_policy_pin_binding_and_false_claim_forgery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, routing, authorization = self._prepare(root)
            result = self._evaluate(sources, routing, authorization)
            for mutate in (
                lambda value: value["policy_pin"].update(matched=False),
                lambda value: value.update(binding_sha256="0" * 64),
                lambda value: value.update(order_placed=True),
            ):
                forged = deepcopy(result)
                mutate(forged)
                with self.assertRaises(RoutingDrcFabricationReleaseError):
                    render_routing_drc_fabrication_release_report(forged)

    def test_schema_is_recursively_closed_and_bounded(self):
        schema = routing_drc_fabrication_release_report_json_schema()
        objects = arrays = 0
        stack = [schema]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                if value.get("type") == "object":
                    objects += 1
                    self.assertFalse(value.get("additionalProperties", True))
                if value.get("type") == "array":
                    arrays += 1
                    self.assertIn("maxItems", value)
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
        self.assertGreaterEqual(objects, 12)
        self.assertGreaterEqual(arrays, 3)

    def test_cli_retains_negative_before_require_authorized(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            sources, _routing_command, _authorization_command = self._prepare(
                root, fabrication_authorized=False
            )
            negative = {
                "release_authorized": False,
            }
            output = root / "release-report.json"
            rendered = b'{"retained":true}\n'
            argv = [
                "pcbex-agent",
                "replay-routing-drc-fabrication-release",
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
                "--expected-policy-pack-canonical-sha256",
                self.policy_digest,
                "--output",
                str(output),
                "--require-authorized",
            ]
            with mock.patch.object(
                cli, "evaluate_routing_drc_fabrication_release", return_value=negative
            ), mock.patch.object(
                cli, "render_routing_drc_fabrication_release_report", return_value=rendered
            ), mock.patch.object(sys, "argv", argv), self.assertRaisesRegex(
                SystemExit, "was retained but is not authorized"
            ):
                cli.main()
            self.assertEqual(output.read_bytes(), rendered)

    def test_schema_cli_stdout(self):
        stdout = io.StringIO()
        with mock.patch.object(
            sys,
            "argv",
            ["pcbex-agent", "routing-drc-fabrication-release-report-schema"],
        ), redirect_stdout(stdout):
            cli.main()
        self.assertEqual(
            json.loads(stdout.getvalue()),
            routing_drc_fabrication_release_report_json_schema(),
        )


if __name__ == "__main__":
    unittest.main()
