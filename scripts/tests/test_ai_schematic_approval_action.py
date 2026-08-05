"""Focused contract tests for the public AI schematic approval Action.

The Rust verifier owns signatures and the report schema.  These tests replace
the executable with a deterministic stand-in and exercise the Action's file,
argument, output, and final-gate boundaries without network or provider
access.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "actions" / "ai-schematic-approval" / "action.yml"
SCRIPT = ROOT / "scripts" / "ai-schematic-approval-action.sh"
GATE = ROOT / "scripts" / "ai-schematic-approval-action-gate.sh"


class AiSchematicApprovalActionTests(unittest.TestCase):
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

                arguments = Path(os.environ["PCBEX_TEST_ARGUMENTS"])
                arguments.parent.mkdir(parents=True, exist_ok=True)
                with arguments.open("a", encoding="utf-8") as stream:
                    stream.write("COMMAND=" + (sys.argv[1] if len(sys.argv) > 1 else "") + "\n")
                    stream.write("\n".join(sys.argv[1:]) + "\n")
                if len(sys.argv) < 2 or sys.argv[1] != "verify-ai-quorum":
                    raise SystemExit(2)
                if os.environ.get("PCBEX_TEST_MODE") == "fatal":
                    raise SystemExit(7)
                def option(name):
                    prefix = name + "="
                    return int(next(item[len(prefix):] for item in sys.argv if item.startswith(prefix)))
                def path_option(name):
                    prefix = name + "="
                    return Path(next(item[len(prefix):] for item in sys.argv if item.startswith(prefix)))
                output = path_option("--output")
                request_sha = os.environ["PCBEX_TEST_REQUEST_SHA"]
                quorum = os.environ.get("PCBEX_TEST_QUORUM", "true") == "true"
                report = {
                    "schema_version": 1,
                    "request_sha256": request_sha,
                    "policy": {
                        "minimum_approvals": option("--minimum-approvals"),
                        "minimum_distinct_providers": option("--minimum-distinct-providers"),
                        "minimum_distinct_models": option("--minimum-distinct-models"),
                    },
                    "counts": {
                        "members": 2,
                        "approvals": 2 if quorum else 1,
                        "rejections": 0 if quorum else 1,
                        "distinct_providers": 2 if quorum else 1,
                        "distinct_models": 2 if quorum else 1,
                    },
                    "members": [
                        {
                            "signer_id": "a",
                            "public_key": "c" * 64,
                            "response_sha256": "d" * 64,
                            "provider": "provider-a",
                            "model": "model-a",
                            "version": None,
                            "approved": True,
                            "gate_failures": [],
                        },
                        {
                            "signer_id": "b",
                            "public_key": "e" * 64,
                            "response_sha256": "f" * 64,
                            "provider": "provider-b",
                            "model": "model-b",
                            "version": None,
                            "approved": quorum,
                            "gate_failures": [] if quorum else ["manual_review_required"],
                        },
                    ],
                    "quorum_met": quorum,
                    "quorum_failures": [] if quorum else [
                        "insufficient_approvals:required=2:actual=1",
                        "insufficient_distinct_providers:required=2:actual=1",
                        "insufficient_distinct_models:required=2:actual=1",
                    ],
                }
                if os.environ.get("PCBEX_TEST_MODE") == "malformed":
                    report["unexpected"] = True
                if os.environ.get("PCBEX_TEST_MODE") == "schema-bool":
                    report["schema_version"] = True
                if os.environ.get("PCBEX_TEST_MODE") == "inconsistent-member":
                    report["members"][0]["gate_failures"] = ["forged"]
                if os.environ.get("PCBEX_TEST_MODE") == "blank-identity":
                    report["members"][0]["provider"] = " "
                if os.environ.get("PCBEX_TEST_MODE") == "blank-version":
                    report["members"][0]["version"] = " "
                if os.environ.get("PCBEX_TEST_MODE") == "out-of-order":
                    report["members"].reverse()
                if any(item.startswith("--session=") for item in sys.argv):
                    report = {
                        "schema_version": 1,
                        "session_sha256": "1" * 64,
                        "request_sha256": request_sha,
                        "issued_at_unix": 1,
                        "expires_at_unix": 3,
                        "evaluated_at_unix": 2,
                        "quorum": report,
                    }
                if os.environ.get("PCBEX_TEST_MUTATE"):
                    Path(os.environ["PCBEX_TEST_MUTATE"]).write_text(
                        "mutated during verifier\n", encoding="utf-8"
                    )
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps(report, separators=(",", ":")) + "\n", encoding="utf-8")
                # A verifier-provided summary must never be adopted by the
                # wrapper; leave an intentionally hostile candidate behind.
                output.with_name("ai-approval-quorum.md").write_text(
                    "# FAKE SUMMARY\n\n[untrusted](javascript:alert(1))\n",
                    encoding="utf-8",
                )
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    @staticmethod
    def _outputs(path: Path) -> dict[str, str]:
        if not path.exists():
            return {}
        return dict(
            line.split("=", 1)
            for line in path.read_text(encoding="utf-8").splitlines()
            if "=" in line
        )

    @staticmethod
    def _invocations(path: Path) -> list[list[str]]:
        if not path.exists():
            return []
        result: list[list[str]] = []
        current: list[str] | None = None
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("COMMAND="):
                if current is not None:
                    result.append(current)
                current = [] if line == "COMMAND=verify-ai-quorum" else None
            elif current is not None:
                current.append(line)
        if current is not None:
            result.append(current)
        return result

    def _prepare(self) -> tuple[Path, Path, dict[str, str]]:
        temporary = tempfile.TemporaryDirectory(prefix="pcbex-ai-approval-action-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fake = root / "fake-pcbex"
        self._write_fake_binary(fake)
        schematic = root / "design.kicad_sch"
        schematic.write_text("(kicad_sch)\n", encoding="utf-8")
        request = root / "request.json"
        request.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "request_sha256": "a" * 64,
                    "schematic": {},
                    "electrical_review": {"schematic_sha256": "b" * 64},
                }
            ),
            encoding="utf-8",
        )
        policy = root / "policy.json"
        policy.write_text("{}\n", encoding="utf-8")
        approvals: list[Path] = []
        responses: list[Path] = []
        for index in range(2):
            approval = root / f"approval-{index}.json"
            response = root / f"response-{index}.json"
            approval.write_text("{}\n", encoding="utf-8")
            response.write_text("{}\n", encoding="utf-8")
            approvals.append(approval)
            responses.append(response)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GITHUB_OUTPUT": str(root / "github-output"),
            "GITHUB_STEP_SUMMARY": str(root / "step-summary"),
            "PCBEX_BINARY": str(fake),
            "PCBEX_REPOSITORY_ROOT": str(ROOT),
            "PCBEX_AI_SCHEMATIC": str(schematic.relative_to(root)),
            "PCBEX_AI_REQUEST": str(request.relative_to(root)),
            "PCBEX_AI_APPROVAL_FILES": "\n".join(
                str(path.relative_to(root)) for path in approvals
            ),
            "PCBEX_AI_RESPONSE_FILES": "\n".join(
                str(path.relative_to(root)) for path in responses
            ),
            "PCBEX_AI_POLICY_PACK": str(policy.relative_to(root)),
            "PCBEX_AI_SESSION": "",
            "PCBEX_AI_MINIMUM_APPROVALS": "2",
            "PCBEX_AI_MINIMUM_DISTINCT_PROVIDERS": "2",
            "PCBEX_AI_MINIMUM_DISTINCT_MODELS": "2",
            "PCBEX_AI_REQUIRE_QUORUM": "false",
            "PCBEX_AI_UPLOAD_ARTIFACT": "false",
            "PCBEX_AI_ARTIFACT_NAME": "test-artifact",
            "PCBEX_AI_RETENTION_DAYS": "14",
            "PCBEX_OUTPUT_DIR": "artifacts",
            "PCBEX_TEST_ARGUMENTS": str(root / "arguments"),
            "PCBEX_TEST_REQUEST_SHA": "a" * 64,
        }
        return root, fake, env

    @staticmethod
    def _run(root: Path, env: dict[str, str], **overrides: str) -> subprocess.CompletedProcess[str]:
        merged = {**env, **overrides}
        return subprocess.run(
            ["bash", str(SCRIPT)],
            cwd=root,
            env=merged,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_manifest_declares_boardless_contract_and_pinned_upload(self):
        document = ACTION.read_text(encoding="utf-8")
        for name in (
            "schematic",
            "request",
            "approval-files",
            "response-files",
            "policy-pack",
            "session",
            "minimum-approvals",
            "minimum-distinct-providers",
            "minimum-distinct-models",
            "require-quorum",
            "output-dir",
            "upload-artifact",
            "artifact-name",
            "retention-days",
        ):
            self.assertIn(f"  {name}:\n", document)
        for name in (
            "status",
            "artifact-dir",
            "ai-approval-quorum",
            "ai-approval-quorum-summary",
            "ai-approval-quorum-met",
            "request-sha256",
            "schematic-ir-sha256",
            "input-snapshot-sha256",
        ):
            self.assertIn(f"  {name}:\n", document)
        self.assertNotIn("board", document.lower())
        self.assertIn("--schematic", SCRIPT.read_text(encoding="utf-8"))
        self.assertNotIn("--summary-output", SCRIPT.read_text(encoding="utf-8"))
        self.assertIn("if: ${{ always() }}", document)
        for forwarded in (
            "PCBEX_AI_ARTIFACT_NAME: ${{ inputs.artifact-name }}",
            "PCBEX_AI_RETENTION_DAYS: ${{ inputs.retention-days }}",
            "PCBEX_AI_UPLOAD_ARTIFACT: ${{ inputs.upload-artifact }}",
            "PCBEX_AI_REQUIRE_QUORUM: ${{ inputs.require-quorum }}",
        ):
            self.assertIn(forwarded, document)
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
            document,
        )
        self.assertLess(document.index("Upload AI approval evidence"), document.index("Enforce AI schematic approval gate"))
        supervised_timeouts = [
            int(value)
            for value in re.findall(r"--timeout-seconds ([0-9]+)", document)
        ]
        self.assertEqual(supervised_timeouts, [300, 1200, 60, 600])
        self.assertLessEqual(sum(supervised_timeouts), 45 * 60)
        self.assertGreaterEqual(document.count("--max-entries 2"), 1)
        self.assertEqual(document.count("steps.ai-approval.outcome == 'success'"), 3)
        self.assertIn(
            "PCBEX_EXPECTED_QUORUM_MET: ${{ steps.ai-approval.outputs.ai-approval-quorum-met }}",
            document,
        )
        self.assertIn(
            "PCBEX_PUBLICATION_QUORUM_MET: ${{ steps.publication-boundary.outputs.quorum-met }}",
            document,
        )

    def test_success_forwards_exact_pairs_and_publishes_outputs(self):
        root, _fake, env = self._prepare()
        env["PCBEX_AI_APPROVAL_FILES"] += "\n"
        env["PCBEX_AI_RESPONSE_FILES"] += "\n"
        result = self._run(root, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs["status"], "ok")
        self.assertEqual(outputs["artifact-dir"], "artifacts")
        self.assertEqual(outputs["ai-approval-quorum"], "artifacts/ai-approval-quorum.json")
        self.assertEqual(outputs["ai-approval-quorum-summary"], "artifacts/ai-approval-quorum.md")
        self.assertEqual(outputs["ai-approval-quorum-met"], "true")
        self.assertEqual(outputs["request-sha256"], "a" * 64)
        self.assertEqual(outputs["schematic-ir-sha256"], "b" * 64)
        invocations = self._invocations(root / "arguments")
        self.assertEqual(len(invocations), 1)
        invocation = invocations[0]
        self.assertEqual(invocation[0], "verify-ai-quorum")
        self.assertEqual(invocation[1], "request.json")
        self.assertTrue(any(item.startswith("--schematic=") for item in invocation))
        self.assertIn("--schematic=design.kicad_sch", invocation)
        self.assertEqual(sum(item.startswith("--approval=") for item in invocation), 2)
        self.assertEqual(sum(item.startswith("--response=") for item in invocation), 2)
        self.assertTrue((root / "artifacts/ai-approval-quorum.json").is_file())
        summary = (root / "artifacts/ai-approval-quorum.md").read_text(encoding="utf-8")
        self.assertIn("Result: quorum met", summary)
        self.assertNotIn("FAKE SUMMARY", summary)
        self.assertRegex(outputs["input-snapshot-sha256"], r"^[0-9a-f]{64}$")

    def test_threshold_failure_retains_authenticated_report_for_final_gate(self):
        root, _fake, env = self._prepare()
        result = self._run(root, env, PCBEX_TEST_QUORUM="false")
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs["status"], "ok")
        self.assertEqual(outputs["ai-approval-quorum-met"], "false")
        self.assertTrue((root / "artifacts/ai-approval-quorum.json").is_file())
        gate_env = {
            "PATH": os.environ.get("PATH", ""),
            "PCBEX_PREFLIGHT_VALID": "true",
            "PCBEX_AI_OUTCOME": "success",
            "PCBEX_AI_STATUS": "ok",
            "PCBEX_AI_REPORT": outputs["ai-approval-quorum"],
            "PCBEX_AI_SUMMARY": outputs["ai-approval-quorum-summary"],
            "PCBEX_AI_QUORUM_MET": "false",
            "PCBEX_ARTIFACT_SAFE": "true",
            "PCBEX_PUBLICATION_SAFE": "true",
            "PCBEX_PUBLICATION_QUORUM_MET": "false",
            "PCBEX_UPLOAD_ARTIFACT": "false",
            "PCBEX_UPLOAD_OUTCOME": "skipped",
            "PCBEX_REQUIRE_QUORUM": "false",
        }
        accepted = subprocess.run(["bash", str(GATE)], env=gate_env, check=False)
        self.assertEqual(accepted.returncode, 0)
        changed = subprocess.run(
            ["bash", str(GATE)],
            env={**gate_env, "PCBEX_PUBLICATION_QUORUM_MET": "true"},
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn("changed before publication", changed.stderr)
        rejected = subprocess.run(
            ["bash", str(GATE)],
            env={**gate_env, "PCBEX_REQUIRE_QUORUM": "true"},
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("did not meet", rejected.stderr)

    def test_invalid_verifier_result_clears_artifact_dir(self):
        root, _fake, env = self._prepare()
        result = self._run(root, env, PCBEX_TEST_MODE="fatal")
        self.assertNotEqual(result.returncode, 0)
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs.get("status"), "error")
        self.assertEqual(outputs.get("artifact-dir"), "")
        self.assertFalse((root / "artifacts/ai-approval-quorum.json").exists())

        for mode in (
            "malformed",
            "schema-bool",
            "inconsistent-member",
            "blank-identity",
            "blank-version",
        ):
            with self.subTest(mode=mode):
                root, _fake, env = self._prepare()
                result = self._run(root, env, PCBEX_TEST_MODE=mode)
                self.assertNotEqual(result.returncode, 0)
                outputs = self._outputs(root / "github-output")
                self.assertEqual(outputs.get("artifact-dir"), "")

    def test_preflight_rejects_schema_two_stale_output_symlink_and_unpaired_lists(self):
        for schema_version in (2, 3, 4):
            with self.subTest(schema_version=schema_version):
                root, _fake, env = self._prepare()
                request = root / "request.json"
                value = json.loads(request.read_text(encoding="utf-8"))
                value["schema_version"] = schema_version
                request.write_text(json.dumps(value), encoding="utf-8")
                result = self._run(root, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "arguments").exists())

        root, _fake, env = self._prepare()
        (root / "artifacts").mkdir()
        (root / "artifacts/sentinel").write_text("keep\n", encoding="utf-8")
        result = self._run(root, env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((root / "artifacts/sentinel").read_text(), "keep\n")
        self.assertFalse((root / "arguments").exists())

        root, _fake, env = self._prepare()
        external = root / "external"
        external.mkdir()
        (root / "artifacts").symlink_to(external, target_is_directory=True)
        result = self._run(root, env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(external.iterdir()), [])

        root, _fake, env = self._prepare()
        env["PCBEX_AI_RESPONSE_FILES"] = "response-0.json"
        result = self._run(root, env)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / "arguments").exists())

    def test_session_report_is_forwarded_and_retained(self):
        root, _fake, env = self._prepare()
        session = root / "session.json"
        session.write_text("{}\n", encoding="utf-8")
        env["PCBEX_AI_SESSION"] = "session.json"
        result = self._run(root, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs["status"], "ok")
        self.assertEqual(outputs["ai-approval-quorum-met"], "true")
        invocation = self._invocations(root / "arguments")[0]
        self.assertIn("--session=session.json", invocation)
        report = json.loads((root / "artifacts/ai-approval-quorum.json").read_text())
        self.assertEqual(report["request_sha256"], "a" * 64)
        self.assertEqual(report["quorum"]["quorum_met"], True)
        self.assertTrue(
            (root / "artifacts/ai-approval-quorum.md")
            .read_text(encoding="utf-8")
            .startswith("# Time-bound AI schematic approval quorum\n")
        )

    def test_input_limits_and_option_like_request_are_fail_closed(self):
        root, _fake, env = self._prepare()
        option_request = root / "-request.json"
        option_request.write_bytes((root / "request.json").read_bytes())
        env["PCBEX_AI_REQUEST"] = "-request.json"
        result = self._run(root, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        invocation = self._invocations(root / "arguments")[0]
        self.assertIn("--", invocation)
        self.assertEqual(invocation[-1], "-request.json")

        root, _fake, env = self._prepare()
        env["PCBEX_AI_MINIMUM_APPROVALS"] = "0"
        result = self._run(root, env)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / "arguments").exists())

    def test_oversize_symlink_and_aggregate_inputs_are_rejected(self):
        root, _fake, env = self._prepare()
        (root / "design.kicad_sch").write_bytes(b"x" * (32 * 1024 * 1024 + 1))
        result = self._run(root, env)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / "arguments").exists())

        root, _fake, env = self._prepare()
        external = root / "outside-policy.json"
        external.write_text("{}\n", encoding="utf-8")
        (root / "policy.json").unlink()
        (root / "policy.json").symlink_to(external)
        result = self._run(root, env)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / "arguments").exists())

        root, _fake, env = self._prepare()
        for path in (
            root / "design.kicad_sch",
            root / "request.json",
            root / "policy.json",
            root / "approval-0.json",
        ):
            path.write_bytes(b"x" * (32 * 1024 * 1024))
        result = self._run(root, env)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / "arguments").exists())

    def test_input_mutation_during_verifier_is_rejected(self):
        root, _fake, env = self._prepare()
        env["PCBEX_TEST_MUTATE"] = "approval-0.json"
        result = self._run(root, env)
        self.assertNotEqual(result.returncode, 0)
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs.get("status"), "error")
        self.assertEqual(outputs.get("artifact-dir"), "")
        self.assertFalse((root / "artifacts/ai-approval-quorum.json").exists())

    def test_report_members_must_follow_rust_signer_order(self):
        root, _fake, env = self._prepare()
        result = self._run(root, env, PCBEX_TEST_MODE="out-of-order")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._outputs(root / "github-output").get("artifact-dir"), "")

    def test_publication_revalidation_rejects_late_input_mutation(self):
        root, _fake, env = self._prepare()
        result = self._run(root, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = self._outputs(root / "github-output")
        (root / "approval-0.json").write_text("late mutation\n", encoding="utf-8")
        revalidate_output = root / "revalidate-output"
        revalidate_env = {
            **env,
            "GITHUB_OUTPUT": str(revalidate_output),
            "PCBEX_AI_REPORT": outputs["ai-approval-quorum"],
            "PCBEX_AI_SUMMARY": outputs["ai-approval-quorum-summary"],
            "PCBEX_EXPECTED_INPUT_SNAPSHOT": outputs["input-snapshot-sha256"],
            "PCBEX_EXPECTED_QUORUM_MET": outputs["ai-approval-quorum-met"],
        }
        revalidated = subprocess.run(
            ["bash", str(SCRIPT), "--revalidate"],
            cwd=root,
            env=revalidate_env,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(revalidated.returncode, 0)
        self.assertFalse(revalidate_output.exists())

    def test_publication_revalidation_rejects_an_extra_artifact(self):
        root, _fake, env = self._prepare()
        result = self._run(root, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = self._outputs(root / "github-output")
        (root / "artifacts/unexpected.txt").write_text("unexpected\n", encoding="utf-8")
        revalidate_output = root / "revalidate-output"
        revalidated = subprocess.run(
            ["bash", str(SCRIPT), "--revalidate"],
            cwd=root,
            env={
                **env,
                "GITHUB_OUTPUT": str(revalidate_output),
                "PCBEX_AI_REPORT": outputs["ai-approval-quorum"],
                "PCBEX_AI_SUMMARY": outputs["ai-approval-quorum-summary"],
                "PCBEX_EXPECTED_INPUT_SNAPSHOT": outputs["input-snapshot-sha256"],
                "PCBEX_EXPECTED_QUORUM_MET": outputs["ai-approval-quorum-met"],
            },
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(revalidated.returncode, 0)
        self.assertFalse(revalidate_output.exists())

    def test_publication_revalidation_rejects_changed_quorum_result(self):
        root, _fake, env = self._prepare()
        result = self._run(root, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = self._outputs(root / "github-output")
        report_path = root / outputs["ai-approval-quorum"]
        summary_path = root / outputs["ai-approval-quorum-summary"]
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["counts"] = {
            "members": 2,
            "approvals": 1,
            "rejections": 1,
            "distinct_providers": 1,
            "distinct_models": 1,
        }
        report["members"][1]["approved"] = False
        report["members"][1]["gate_failures"] = ["manual_review_required"]
        report["quorum_met"] = False
        report["quorum_failures"] = [
            "insufficient_approvals:required=2:actual=1",
            "insufficient_distinct_providers:required=2:actual=1",
            "insufficient_distinct_models:required=2:actual=1",
        ]
        report_path.write_text(
            json.dumps(report, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        summary_path.unlink()
        rendered = subprocess.run(
            [
                "python3",
                str(ROOT / "scripts/ai_schematic_approval_evidence.py"),
                "render",
                str(report_path),
                str(summary_path),
                "a" * 64,
                "2",
                "2",
                "2",
            ],
            cwd=root,
            env={**os.environ, "PYTHONPATH": str(ROOT / "scripts")},
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        revalidate_output = root / "revalidate-output"
        revalidated = subprocess.run(
            ["bash", str(SCRIPT), "--revalidate"],
            cwd=root,
            env={
                **env,
                "GITHUB_OUTPUT": str(revalidate_output),
                "PCBEX_AI_REPORT": outputs["ai-approval-quorum"],
                "PCBEX_AI_SUMMARY": outputs["ai-approval-quorum-summary"],
                "PCBEX_EXPECTED_INPUT_SNAPSHOT": outputs["input-snapshot-sha256"],
                "PCBEX_EXPECTED_QUORUM_MET": "true",
            },
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(revalidated.returncode, 0)
        self.assertIn("changed after verification", revalidated.stderr)
        self.assertFalse(revalidate_output.exists())


if __name__ == "__main__":
    unittest.main()
