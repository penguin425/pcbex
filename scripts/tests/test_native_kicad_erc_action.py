"""Contract tests for the standalone native KiCad ERC Action bridge.

The Rust runner owns normalization and the report schemas.  These tests keep
the Action boundary deterministic by replacing ``pcbex`` with a tiny executable
that records every invocation and emits a fixed report/summary pair.  No KiCad
installation or network access is needed for the Action tests.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "action.yml"
ANALYSIS_SCRIPT = ROOT / "scripts" / "github-analysis.sh"
BOARDLESS_ACTION = ROOT / "actions" / "native-kicad-erc" / "action.yml"
BOARDLESS_SCRIPT = ROOT / "scripts" / "native-kicad-erc-action.sh"
BOARDLESS_GATE = ROOT / "scripts" / "native-kicad-erc-action-gate.sh"

NATIVE_INPUTS = (
    "native-kicad-erc-schematic",
    "native-kicad-erc-warning-policy",
    "native-kicad-erc-kicad-cli",
    "native-kicad-erc-require-approved",
)
NATIVE_OUTPUTS = (
    "native-kicad-erc-report",
    "native-kicad-erc-schema-version",
    "native-kicad-erc-approved",
    "native-kicad-erc-error-count",
    "native-kicad-erc-warning-count",
    "native-kicad-erc-policy-failure-count",
    "native-kicad-erc-warning-policy-sha256",
    "native-kicad-erc-warning-policy-source-bytes",
    "native-kicad-erc-warning-policy-source-sha256",
    "native-kicad-erc-run-sha256",
    "native-kicad-erc-report-bytes",
    "native-kicad-erc-report-sha256",
)
BOARDLESS_INPUTS = (
    "schematic",
    "warning-policy",
    "kicad-cli",
    "require-approved",
    "output-dir",
    "upload-artifact",
    "artifact-name",
    "retention-days",
)


class NativeKicadErcActionTests(unittest.TestCase):
    """Exercise native ERC forwarding, retention, and fail-closed handling."""

    @staticmethod
    def _write_fake_binary(path: Path) -> None:
        """Write a deterministic fake pcbex executable.

        ``analyze-kicad`` creates the small set of artifacts needed by the
        existing analysis shell.  ``run-native-kicad-erc`` emits the same
        normalized report and hidden summary fields as the Rust CLI.  Modes
        used by the tests intentionally model malformed and missing evidence.
        """

        path.write_text(
            textwrap.dedent(
                r"""
                #!/usr/bin/env python3
                import hashlib
                import json
                import os
                from pathlib import Path
                import sys

                marker = Path(os.environ["PCBEX_TEST_ARGUMENTS"])
                argv = sys.argv[1:]
                command = argv[0] if argv else ""
                mode = os.environ.get("PCBEX_NATIVE_KICAD_ERC_TEST_MODE", "success-v1")
                with marker.open("a", encoding="utf-8") as stream:
                    stream.write("COMMAND=" + command + "\n")
                    stream.write("\n".join(argv) + "\n")

                def value(flag, default=""):
                    try:
                        return argv[argv.index(flag) + 1]
                    except (ValueError, IndexError):
                        prefix = flag + "="
                        return next(
                            (item[len(prefix):] for item in argv if item.startswith(prefix)),
                            default,
                        )

                if command == "analyze-kicad":
                    output_dir = Path(value("--output-dir"))
                    output_dir.mkdir(parents=True, exist_ok=True)
                    (output_dir / "run.json").write_text(
                        '{"result":{"violations":0}}\n', encoding="utf-8"
                    )
                    (output_dir / "report.sarif").write_text(
                        "{}\n", encoding="utf-8"
                    )
                    (output_dir / "summary.md").write_text(
                        "fake analysis\n", encoding="utf-8"
                    )
                    if mode == "plant-stale":
                        (output_dir.parent / "native-kicad-erc.json").write_bytes(
                            b"stale native ERC report\n"
                        )
                    raise SystemExit(0)

                if command != "run-native-kicad-erc":
                    raise SystemExit(0)

                if mode == "fatal":
                    print("synthetic native ERC failure", file=sys.stderr)
                    raise SystemExit(9)

                output = Path(value("--output"))
                source_path = next(
                    (Path(item) for item in argv[1:] if item.endswith(".kicad_sch")),
                    Path(os.environ["PCBEX_NATIVE_SOURCE"]),
                )
                source_bytes = source_path.read_bytes()
                source = {
                    "bytes": len(source_bytes),
                    "sha256": hashlib.sha256(source_bytes).hexdigest(),
                }

                def finding(severity, finding_type):
                    return {
                        "description": "Synthetic ERC finding",
                        "items": [{
                            "description": "Symbol U1 Pin 1",
                            "pos": {"x": 1.0, "y": 2.0},
                            "uuid": "00000000-0000-0000-0000-000000000001",
                        }],
                        "severity": severity,
                        "sheet_path": "/",
                        "sheet_uuid_path": "/root",
                        "type": finding_type,
                    }

                def canonical(payload):
                    return json.dumps(
                        payload, ensure_ascii=False, separators=(",", ":")
                    ).encode("utf-8")

                warning_mode = mode in {"success-v2", "reject-v2"}
                rejected = mode in {"reject-v1", "reject-v2"}
                if warning_mode:
                    policy_path = Path(value("--warning-policy"))
                    policy = json.loads(policy_path.read_text(encoding="utf-8"))
                    policy_bytes = policy_path.read_bytes()
                    policy_canonical = canonical(policy)
                    policy_sha = hashlib.sha256(
                        b"pcbex/native-kicad-erc-warning-policy/v1\0"
                        + policy_canonical
                    ).hexdigest()
                    findings = [finding("warning", "warning_type")]
                    ignored_checks = [{"description": "ignored", "key": "ignored"}]
                    failures = []
                    if rejected:
                        failures = [
                            {
                                "code": "ignored-not-allowed",
                                "subject": "ignored",
                                "actual_count": 1,
                                "maximum_count": 0,
                            },
                            {
                                "code": "total",
                                "subject": "total_warnings",
                                "actual_count": 1,
                                "maximum_count": 0,
                            },
                            {
                                "code": "type-limit",
                                "subject": "warning_type",
                                "actual_count": 1,
                                "maximum_count": 0,
                            },
                        ]
                    report = {
                        "schema_version": 2,
                        "engine": "pcbex",
                        "engine_version": "1.428.0-test",
                        "kicad_version": "10.0.5-test",
                        "source": source,
                        "invocation": {
                            "command": "sch erc",
                            "format": "json",
                            "units": "mm",
                            "severities": ["error", "warning"],
                            "exit_code_violations": True,
                        },
                        "ignored_checks": ignored_checks,
                        "findings": findings,
                        "error_count": 0,
                        "warning_count": 1,
                        "warning_counts": [{
                            "finding_type": "warning_type",
                            "count": 1,
                        }],
                        "warning_policy": {
                            "source": {
                                "bytes": len(policy_bytes),
                                "sha256": hashlib.sha256(policy_bytes).hexdigest(),
                            },
                            "policy_sha256": policy_sha,
                            "policy": policy,
                        },
                        "policy_failures": failures,
                        "approved": not failures,
                        "run_sha256": "",
                    }
                    identity = dict(report)
                    identity.pop("run_sha256")
                    report["run_sha256"] = hashlib.sha256(
                        b"pcbex/native-kicad-erc/v2\0" + canonical(identity)
                    ).hexdigest()
                else:
                    findings = []
                    if rejected:
                        findings = [finding("error", "pin_not_connected")]
                    report = {
                        "schema_version": 1,
                        "engine": "pcbex",
                        "engine_version": "1.428.0-test",
                        "kicad_version": "10.0.5-test",
                        "source": source,
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
                        "run_sha256": "",
                    }
                    identity = dict(report)
                    identity.pop("run_sha256")
                    report["run_sha256"] = hashlib.sha256(
                        b"pcbex/native-kicad-erc/v1\0" + canonical(identity)
                    ).hexdigest()

                if mode == "malformed":
                    report_bytes = b"not-json\n"
                else:
                    report_bytes = canonical(report) + b"\n"

                if mode != "no-report":
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(report_bytes)

                summary = {
                    "schema_version": report.get("schema_version", 1),
                    "approved": report.get("approved", False),
                    "error_count": report.get("error_count", 0),
                    "run_sha256": report.get("run_sha256", ""),
                    "report_bytes": len(report_bytes),
                    "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
                }
                if warning_mode:
                    summary.update({
                        "warning_count": report["warning_count"],
                        "policy_failure_count": len(report["policy_failures"]),
                        "warning_policy_sha256": report["warning_policy"]["policy_sha256"],
                        "warning_policy_source_bytes": report["warning_policy"]["source"]["bytes"],
                        "warning_policy_source_sha256": report["warning_policy"]["source"]["sha256"],
                    })
                if mode == "summary-digest-mismatch":
                    summary["report_sha256"] = "0" * 64
                if "--mcp-echo-report-summary" in argv:
                    print(json.dumps(summary, separators=(",", ":")))

                if rejected and "--require-approved" in argv:
                    raise SystemExit(1)
                raise SystemExit(0)
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
    def _invocations(path: Path, command: str) -> list[list[str]]:
        if not path.exists():
            return []
        lines = path.read_text(encoding="utf-8").splitlines()
        result: list[list[str]] = []
        current: list[str] | None = None
        for line in lines:
            if line.startswith("COMMAND="):
                if current is not None:
                    result.append(current)
                current = [] if line == f"COMMAND={command}" else None
            elif current is not None:
                current.append(line)
        if current is not None:
            result.append(current)
        return result

    @classmethod
    def _run(
        cls,
        root: Path,
        fake_binary: Path,
        *,
        schematic: str = "design.kicad_sch",
        warning_policy: str = "",
        require_approved: str = "false",
        kicad_cli: str = "fake-kicad-cli",
        mode: str = "success-v1",
        output_dir: str = "artifacts",
        policy_bytes: bytes | None = None,
        extra: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        board = root / "board.kicad_pcb"
        board.write_text("(kicad_pcb)\n", encoding="utf-8")
        source = root / "design.kicad_sch"
        source.write_text("(kicad_sch (version 20231120))\n", encoding="utf-8")
        if policy_bytes is None:
            if mode == "reject-v2":
                policy_bytes = (
                    b'{"schema_version":1,"id":"strict-test-policy",'
                    b'"maximum_total_warnings":0,"warning_limits":[{'
                    b'"finding_type":"warning_type","maximum_count":0}],'
                    b'"allowed_ignored_checks":[]}\n'
                )
            else:
                policy_bytes = (
                    b'{"schema_version":1,"id":"test-warning-policy",'
                    b'"maximum_total_warnings":1,"warning_limits":[{'
                    b'"finding_type":"warning_type","maximum_count":1}],'
                    b'"allowed_ignored_checks":["ignored"]}\n'
                )
        (root / "warning-policy.json").write_bytes(policy_bytes)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GITHUB_ACTION_PATH": str(ROOT),
            "GITHUB_OUTPUT": str(root / "github-output"),
            "GITHUB_STEP_SUMMARY": str(root / "step-summary"),
            "PCBEX_BINARY": str(fake_binary),
            "PCBEX_BOARD": "board.kicad_pcb",
            "PCBEX_OUTPUT_DIR": output_dir,
            "PCBEX_NATIVE_KICAD_ERC_SCHEMATIC": schematic,
            "PCBEX_NATIVE_KICAD_ERC_WARNING_POLICY": warning_policy,
            "PCBEX_NATIVE_KICAD_ERC_KICAD_CLI": kicad_cli,
            "PCBEX_NATIVE_KICAD_ERC_REQUIRE_APPROVED": require_approved,
            "PCBEX_NATIVE_KICAD_ERC_TEST_MODE": mode,
            "PCBEX_NATIVE_SOURCE": str(source),
            "PCBEX_TEST_ARGUMENTS": str(root / "arguments"),
        }
        if extra:
            env.update(extra)
        return subprocess.run(
            ["bash", str(ANALYSIS_SCRIPT)],
            cwd=root,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    @classmethod
    def _run_boardless(
        cls,
        root: Path,
        fake_binary: Path,
        *,
        schematic: str = "design.kicad_sch",
        warning_policy: str = "",
        require_approved: str = "false",
        kicad_cli: str = "fake-kicad-cli",
        mode: str = "success-v1",
        output_dir: str = "artifacts",
        policy_bytes: bytes | None = None,
        extra: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        source = root / "design.kicad_sch"
        source.write_text("(kicad_sch (version 20231120))\n", encoding="utf-8")
        if policy_bytes is None:
            if mode == "reject-v2":
                policy_bytes = (
                    b'{"schema_version":1,"id":"strict-test-policy",'
                    b'"maximum_total_warnings":0,"warning_limits":[{'
                    b'"finding_type":"warning_type","maximum_count":0}],'
                    b'"allowed_ignored_checks":[]}\n'
                )
            else:
                policy_bytes = (
                    b'{"schema_version":1,"id":"test-warning-policy",'
                    b'"maximum_total_warnings":1,"warning_limits":[{'
                    b'"finding_type":"warning_type","maximum_count":1}],'
                    b'"allowed_ignored_checks":["ignored"]}\n'
                )
        (root / "warning-policy.json").write_bytes(policy_bytes)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GITHUB_OUTPUT": str(root / "github-output"),
            "GITHUB_STEP_SUMMARY": str(root / "step-summary"),
            "PCBEX_BINARY": str(fake_binary),
            "PCBEX_OUTPUT_DIR": output_dir,
            "PCBEX_NATIVE_KICAD_ERC_SCHEMATIC": schematic,
            "PCBEX_NATIVE_KICAD_ERC_WARNING_POLICY": warning_policy,
            "PCBEX_NATIVE_KICAD_ERC_KICAD_CLI": kicad_cli,
            "PCBEX_NATIVE_KICAD_ERC_REQUIRE_APPROVED": require_approved,
            "PCBEX_NATIVE_KICAD_ERC_TEST_MODE": mode,
            "PCBEX_NATIVE_SOURCE": str(source),
            "PCBEX_TEST_ARGUMENTS": str(root / "arguments"),
        }
        if extra:
            env.update(extra)
        return subprocess.run(
            ["bash", str(BOARDLESS_SCRIPT)],
            cwd=root,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def _top_level_mapping_keys(document: str, section: str) -> tuple[str, ...]:
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
    def _run_boardless_gate(**overrides: str) -> subprocess.CompletedProcess[str]:
        values = {
            "PCBEX_PREFLIGHT_VALID": "true",
            "PCBEX_NATIVE_ERC_OUTCOME": "success",
            "PCBEX_NATIVE_ERC_STATUS": "ok",
            "PCBEX_NATIVE_ERC_REPORT": "artifacts/native-kicad-erc.json",
            "PCBEX_NATIVE_ERC_APPROVED": "true",
            "PCBEX_ARTIFACT_SAFE": "true",
            "PCBEX_UPLOAD_ARTIFACT": "false",
            "PCBEX_UPLOAD_OUTCOME": "skipped",
            "PCBEX_REQUIRE_APPROVED": "false",
        }
        values.update(overrides)
        return subprocess.run(
            ["bash", str(BOARDLESS_GATE)],
            env={"PATH": os.environ.get("PATH", ""), **values},
            check=False,
            capture_output=True,
            text=True,
        )

    def _prepare(self) -> tuple[Path, Path]:
        temporary = tempfile.TemporaryDirectory(prefix="pcbex-native-erc-action-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fake_binary = root / "fake-pcbex"
        self._write_fake_binary(fake_binary)
        return root, fake_binary

    def test_action_declares_native_contract_and_final_gate(self):
        document = ACTION.read_text(encoding="utf-8")
        for name in NATIVE_INPUTS:
            self.assertIn(f"  {name}:\n", document)
        for name in NATIVE_OUTPUTS:
            self.assertIn(f"  {name}:\n", document)
        self.assertIn(
            "PCBEX_NATIVE_KICAD_ERC_SCHEMATIC: ${{ inputs.native-kicad-erc-schematic }}",
            document,
        )
        self.assertIn(
            "PCBEX_NATIVE_KICAD_ERC_WARNING_POLICY: ${{ inputs.native-kicad-erc-warning-policy }}",
            document,
        )
        self.assertIn(
            "PCBEX_NATIVE_KICAD_ERC_KICAD_CLI: ${{ inputs.native-kicad-erc-kicad-cli }}",
            document,
        )
        self.assertIn(
            "PCBEX_NATIVE_KICAD_ERC_REQUIRE_APPROVED: ${{ inputs.native-kicad-erc-require-approved }}",
            document,
        )
        self.assertIn("output-dir/native-kicad-erc.json", document)
        self.assertIn("if: ${{ always() }}", document)
        self.assertIn("PCBEX_NATIVE_KICAD_ERC_APPROVED", document)
        self.assertIn("native KiCad ERC report is absent or not approved", document)

    def test_native_script_uses_supervised_command_and_hidden_summary(self):
        document = ANALYSIS_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("run-native-kicad-erc", document)
        self.assertIn("--mcp-echo-report-summary", document)
        self.assertIn('ci_runtime.py" exec', document)
        self.assertNotIn("eval ", document)
        self.assertNotIn("curl", document)
        self.assertNotIn("wget", document)

    def test_disabled_native_gate_does_not_call_runner_and_clears_outputs(self):
        root, fake_binary = self._prepare()
        result = self._run(root, fake_binary, schematic="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self._invocations(root / "arguments", "analyze-kicad"))
        self.assertFalse(self._invocations(root / "arguments", "run-native-kicad-erc"))
        outputs = self._outputs(root / "github-output")
        for name in NATIVE_OUTPUTS:
            self.assertEqual(outputs.get(name, ""), "", name)

    def test_v1_approved_report_and_identities_are_published(self):
        root, fake_binary = self._prepare()
        result = self._run(root, fake_binary)
        self.assertEqual(result.returncode, 0, result.stderr)
        invocations = self._invocations(root / "arguments", "run-native-kicad-erc")
        self.assertEqual(len(invocations), 1)
        self.assertIn("--mcp-echo-report-summary", invocations[0])
        outputs = self._outputs(root / "github-output")
        report_path = outputs["native-kicad-erc-report"]
        self.assertEqual(report_path, "artifacts/native-kicad-erc.json")
        report_bytes = (root / report_path).read_bytes()
        report = json.loads(report_bytes)
        self.assertEqual(report["schema_version"], 1)
        self.assertTrue(report["approved"])
        self.assertEqual(report["error_count"], 0)
        self.assertEqual(outputs["native-kicad-erc-schema-version"], "1")
        self.assertEqual(outputs["native-kicad-erc-approved"], "true")
        self.assertEqual(outputs["native-kicad-erc-error-count"], "0")
        self.assertEqual(outputs["native-kicad-erc-warning-count"], "")
        self.assertEqual(outputs["native-kicad-erc-policy-failure-count"], "")
        self.assertEqual(outputs["native-kicad-erc-report-bytes"], str(len(report_bytes)))
        self.assertEqual(
            outputs["native-kicad-erc-report-sha256"],
            hashlib.sha256(report_bytes).hexdigest(),
        )
        self.assertRegex(outputs["native-kicad-erc-run-sha256"], r"^[0-9a-f]{64}$")

    def test_v1_rejection_is_retained_without_enforcement(self):
        root, fake_binary = self._prepare()
        result = self._run(root, fake_binary, mode="reject-v1")
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = self._outputs(root / "github-output")
        report = json.loads((root / outputs["native-kicad-erc-report"]).read_text())
        self.assertFalse(report["approved"])
        self.assertEqual(report["error_count"], 1)
        self.assertEqual(outputs["native-kicad-erc-approved"], "false")
        self.assertEqual(outputs["native-kicad-erc-error-count"], "1")

    def test_v1_rejection_with_require_approved_retains_evidence_before_gate(self):
        root, fake_binary = self._prepare()
        result = self._run(
            root,
            fake_binary,
            mode="reject-v1",
            require_approved="true",
        )
        # The report-producing shell step retains evidence and publishes its
        # identities.  The composite Action's final ``always()`` enforcement
        # step owns the non-zero result for ``require-approved``.
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs["native-kicad-erc-report"], "artifacts/native-kicad-erc.json")
        self.assertEqual(outputs["native-kicad-erc-approved"], "false")
        self.assertTrue((root / outputs["native-kicad-erc-report"]).is_file())
        # The final Action gate, not the report-producing shell step, owns this
        # policy.  Keep the assertion static so a retained report is observable.
        document = ACTION.read_text(encoding="utf-8")
        self.assertIn('"$PCBEX_NATIVE_KICAD_ERC_REQUIRE_APPROVED" == "true"', document)

    def test_v2_policy_is_a_separate_argument_and_publishes_warning_identities(self):
        root, fake_binary = self._prepare()
        result = self._run(
            root,
            fake_binary,
            warning_policy="warning-policy.json",
            mode="success-v2",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        invocation = self._invocations(root / "arguments", "run-native-kicad-erc")[0]
        self.assertIn("--warning-policy", invocation)
        self.assertIn("warning-policy.json", invocation)
        self.assertNotIn("--warning-policy=warning-policy.json", invocation)
        self.assertIn("--kicad-cli", invocation)
        self.assertIn("fake-kicad-cli", invocation)
        outputs = self._outputs(root / "github-output")
        report = json.loads((root / outputs["native-kicad-erc-report"]).read_text())
        self.assertEqual(report["schema_version"], 2)
        self.assertTrue(report["approved"])
        self.assertEqual(report["warning_count"], 1)
        self.assertEqual(report["policy_failures"], [])
        self.assertEqual(outputs["native-kicad-erc-warning-count"], "1")
        self.assertEqual(outputs["native-kicad-erc-policy-failure-count"], "0")
        self.assertRegex(outputs["native-kicad-erc-warning-policy-sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            outputs["native-kicad-erc-warning-policy-source-bytes"],
            str((root / "warning-policy.json").stat().st_size),
        )

    def test_v2_rejection_is_retained_with_or_without_final_enforcement(self):
        for require_approved in ("false", "true"):
            with self.subTest(require_approved=require_approved):
                root, fake_binary = self._prepare()
                result = self._run(
                    root,
                    fake_binary,
                    warning_policy="warning-policy.json",
                    require_approved=require_approved,
                    mode="reject-v2",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs = self._outputs(root / "github-output")
                report_path = root / outputs["native-kicad-erc-report"]
                report = json.loads(report_path.read_text(encoding="utf-8"))
                self.assertFalse(report["approved"])
                self.assertEqual(len(report["policy_failures"]), 3)
                self.assertEqual(outputs["native-kicad-erc-approved"], "false")
                self.assertEqual(outputs["native-kicad-erc-warning-count"], "1")
                self.assertEqual(outputs["native-kicad-erc-policy-failure-count"], "3")

    def test_policy_requires_schematic_and_nonempty_cli(self):
        for kwargs in (
            {"schematic": "", "warning_policy": "warning-policy.json"},
            {"schematic": "", "require_approved": "true"},
            {"kicad_cli": ""},
            {"require_approved": "maybe"},
        ):
            with self.subTest(kwargs=kwargs):
                root, fake_binary = self._prepare()
                result = self._run(root, fake_binary, **kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "arguments").exists())

    def test_option_like_and_space_containing_schematic_paths_are_single_arguments(self):
        for schematic in ("-design.kicad_sch", "nested path/design file.kicad_sch"):
            with self.subTest(schematic=schematic):
                root, fake_binary = self._prepare()
                source = root / schematic
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text("(kicad_sch (version 20231120))\n", encoding="utf-8")
                result = self._run(root, fake_binary, schematic=schematic)
                self.assertEqual(result.returncode, 0, result.stderr)
                invocation = self._invocations(
                    root / "arguments", "run-native-kicad-erc"
                )[0]
                self.assertEqual(invocation[-2:], ["--", schematic])

    def test_report_planted_by_board_analysis_is_not_reused(self):
        root, fake_binary = self._prepare()
        result = self._run(root, fake_binary, mode="plant-stale")
        self.assertNotEqual(result.returncode, 0)
        planted = root / "artifacts" / "native-kicad-erc.json"
        self.assertEqual(planted.read_bytes(), b"stale native ERC report\n")
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs.get("native-kicad-erc-report", ""), "")
        self.assertFalse(
            self._invocations(root / "arguments", "run-native-kicad-erc")
        )

    def test_stale_and_symlink_output_roots_are_rejected_without_clobbering(self):
        root, fake_binary = self._prepare()
        output = root / "artifacts"
        output.mkdir()
        sentinel = output / "sentinel"
        sentinel.write_bytes(b"keep me\n")
        result = self._run(root, fake_binary)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_bytes(), b"keep me\n")
        self.assertFalse((root / "arguments").exists())

        root, fake_binary = self._prepare()
        external = root / "external"
        external.mkdir()
        os.symlink(external, root / "artifacts", target_is_directory=True)
        result = self._run(root, fake_binary)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(external.iterdir()), [])
        self.assertFalse((root / "arguments").exists())

    def test_output_root_is_validated_before_filesystem_or_github_output_writes(self):
        cases = ("../escape", "/absolute-output", "injected\nforged=value")
        for output_dir in cases:
            with self.subTest(output_dir=output_dir):
                root, fake_binary = self._prepare()
                result = self._run(
                    root,
                    fake_binary,
                    output_dir=output_dir,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "arguments").exists())
                self.assertFalse((root / "github-output").exists())

        root, fake_binary = self._prepare()
        outside = root / "outside"
        outside.mkdir()
        ancestor = root / "linked-parent"
        ancestor.symlink_to(outside, target_is_directory=True)
        result = self._run(
            root,
            fake_binary,
            output_dir="linked-parent/artifacts",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((root / "arguments").exists())
        self.assertFalse((root / "github-output").exists())

    def test_malformed_summary_digest_mismatch_and_missing_report_fail_closed(self):
        for mode in ("malformed", "summary-digest-mismatch", "no-report"):
            with self.subTest(mode=mode):
                root, fake_binary = self._prepare()
                result = self._run(root, fake_binary, mode=mode)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                outputs = self._outputs(root / "github-output")
                self.assertEqual(outputs.get("native-kicad-erc-report", ""), "")
                self.assertEqual(outputs.get("native-kicad-erc-approved", ""), "")

    def test_boardless_manifest_declares_exact_contract_and_ordered_final_gate(self):
        document = BOARDLESS_ACTION.read_text(encoding="utf-8")
        self.assertEqual(
            self._top_level_mapping_keys(document, "inputs"), BOARDLESS_INPUTS
        )
        self.assertEqual(
            set(self._top_level_mapping_keys(document, "outputs")),
            {"status", "artifact-dir", *NATIVE_OUTPUTS},
        )
        self.assertIn("  schematic:\n", document)
        self.assertIn("    required: true\n", document)
        self.assertNotIn("  board:\n", document)
        self.assertIn("if: ${{ always() }}", document)
        self.assertIn("native-kicad-erc-action-gate.sh", document)
        self.assertLess(
            document.index("Upload native ERC evidence"),
            document.index("Enforce native ERC gate"),
        )
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
            document,
        )

    def test_boardless_runner_is_bounded_and_never_analyzes_a_board(self):
        document = BOARDLESS_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("run-native-kicad-erc", document)
        self.assertIn("--mcp-echo-report-summary", document)
        self.assertIn('ci_runtime.py" exec', document)
        self.assertIn("native_kicad_erc_summary.py", document)
        self.assertIn('+=(-- "$PCBEX_NATIVE_KICAD_ERC_SCHEMATIC")', document)
        for forbidden in ("analyze-kicad", "PCBEX_BOARD", "eval ", "curl", "wget"):
            self.assertNotIn(forbidden, document)

    def test_boardless_v1_publishes_exact_identities_and_summary(self):
        root, fake_binary = self._prepare()
        result = self._run_boardless(root, fake_binary)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self._invocations(root / "arguments", "analyze-kicad"))
        invocation = self._invocations(
            root / "arguments", "run-native-kicad-erc"
        )[0]
        self.assertEqual(invocation[-2:], ["--", "design.kicad_sch"])
        self.assertNotIn("--require-approved", invocation)
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs["status"], "ok")
        self.assertEqual(outputs["artifact-dir"], "artifacts")
        self.assertEqual(
            outputs["native-kicad-erc-report"],
            "artifacts/native-kicad-erc.json",
        )
        report_bytes = (root / outputs["native-kicad-erc-report"]).read_bytes()
        self.assertEqual(outputs["native-kicad-erc-schema-version"], "1")
        self.assertEqual(outputs["native-kicad-erc-approved"], "true")
        self.assertEqual(outputs["native-kicad-erc-error-count"], "0")
        self.assertEqual(outputs["native-kicad-erc-warning-count"], "")
        self.assertEqual(
            outputs["native-kicad-erc-report-bytes"], str(len(report_bytes))
        )
        self.assertEqual(
            outputs["native-kicad-erc-report-sha256"],
            hashlib.sha256(report_bytes).hexdigest(),
        )
        summary = (root / "step-summary").read_text(encoding="utf-8")
        self.assertIn("boardless native KiCad ERC", summary)
        self.assertIn("Approved: `true`", summary)
        self.assertIn("Errors: `0`", summary)

    def test_boardless_valid_rejections_are_retained_before_optional_gate(self):
        for mode, policy in (("reject-v1", ""), ("reject-v2", "warning-policy.json")):
            with self.subTest(mode=mode):
                root, fake_binary = self._prepare()
                result = self._run_boardless(
                    root,
                    fake_binary,
                    mode=mode,
                    warning_policy=policy,
                    require_approved="true",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs = self._outputs(root / "github-output")
                self.assertEqual(outputs["status"], "ok")
                self.assertEqual(outputs["native-kicad-erc-approved"], "false")
                self.assertTrue(
                    (root / outputs["native-kicad-erc-report"]).is_file()
                )
                gate = self._run_boardless_gate(
                    PCBEX_NATIVE_ERC_REPORT=outputs["native-kicad-erc-report"],
                    PCBEX_NATIVE_ERC_APPROVED="false",
                    PCBEX_REQUIRE_APPROVED="true",
                )
                self.assertNotEqual(gate.returncode, 0)
                self.assertIn("absent or not approved", gate.stderr)

    def test_boardless_v2_uses_option_safe_policy_argv_and_outputs_policy_identity(self):
        root, fake_binary = self._prepare()
        result = self._run_boardless(
            root,
            fake_binary,
            warning_policy="warning-policy.json",
            mode="success-v2",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        invocation = self._invocations(
            root / "arguments", "run-native-kicad-erc"
        )[0]
        self.assertNotIn("--warning-policy", invocation)
        self.assertIn("--warning-policy=warning-policy.json", invocation)
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs["native-kicad-erc-schema-version"], "2")
        self.assertEqual(outputs["native-kicad-erc-warning-count"], "1")
        self.assertEqual(outputs["native-kicad-erc-policy-failure-count"], "0")
        self.assertRegex(
            outputs["native-kicad-erc-warning-policy-sha256"], r"^[0-9a-f]{64}$"
        )
        self.assertEqual(
            outputs["native-kicad-erc-warning-policy-source-bytes"],
            str((root / "warning-policy.json").stat().st_size),
        )

        root, fake_binary = self._prepare()
        policy_bytes = (
            b'{"schema_version":1,"id":"option-like-policy",'
            b'"maximum_total_warnings":1,"warning_limits":[{'
            b'"finding_type":"warning_type","maximum_count":1}],'
            b'"allowed_ignored_checks":["ignored"]}\n'
        )
        (root / "-policy.json").write_bytes(policy_bytes)
        result = self._run_boardless(
            root,
            fake_binary,
            warning_policy="-policy.json",
            mode="success-v2",
            policy_bytes=policy_bytes,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        invocation = self._invocations(
            root / "arguments", "run-native-kicad-erc"
        )[0]
        self.assertIn("--warning-policy=-policy.json", invocation)

    def test_boardless_invalid_inputs_fail_before_native_invocation(self):
        for kwargs in (
            {"schematic": ""},
            {"kicad_cli": ""},
            {"require_approved": "maybe"},
        ):
            with self.subTest(kwargs=kwargs):
                root, fake_binary = self._prepare()
                result = self._run_boardless(root, fake_binary, **kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "arguments").exists())

        root, fake_binary = self._prepare()
        result = self._run_boardless(
            root, fake_binary, schematic=str(root / "design.kicad_sch")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / "arguments").exists())

        root, fake_binary = self._prepare()
        result = self._run_boardless(
            root, fake_binary, schematic="../outside.kicad_sch"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / "arguments").exists())

        if hasattr(os, "symlink"):
            root, fake_binary = self._prepare()
            (root / "design.kicad_sch").write_text("(kicad_sch)\n")
            try:
                (root / "linked.kicad_sch").symlink_to(root / "design.kicad_sch")
            except OSError:
                pass
            else:
                result = self._run_boardless(
                    root, fake_binary, schematic="linked.kicad_sch"
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "arguments").exists())

    def test_boardless_option_like_and_space_paths_are_single_arguments(self):
        for schematic in ("-design.kicad_sch", "nested path/design file.kicad_sch"):
            with self.subTest(schematic=schematic):
                root, fake_binary = self._prepare()
                source = root / schematic
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(
                    "(kicad_sch (version 20231120))\n", encoding="utf-8"
                )
                result = self._run_boardless(
                    root, fake_binary, schematic=schematic
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                invocation = self._invocations(
                    root / "arguments", "run-native-kicad-erc"
                )[0]
                self.assertEqual(invocation[-2:], ["--", schematic])

        root, fake_binary = self._prepare()
        result = self._run_boardless(
            root,
            fake_binary,
            output_dir="-artifacts",
            kicad_cli="-fake-kicad-cli",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = self._outputs(root / "github-output")
        self.assertEqual(outputs["artifact-dir"], "-artifacts")
        self.assertTrue((root / "-artifacts" / "native-kicad-erc.json").is_file())
        invocation = self._invocations(
            root / "arguments", "run-native-kicad-erc"
        )[0]
        self.assertIn("--output=-artifacts/native-kicad-erc.json", invocation)
        self.assertIn("--kicad-cli=-fake-kicad-cli", invocation)

    def test_boardless_output_boundary_refuses_stale_links_and_escapes(self):
        root, fake_binary = self._prepare()
        output = root / "artifacts"
        output.mkdir()
        sentinel = output / "sentinel"
        sentinel.write_bytes(b"keep me\n")
        result = self._run_boardless(root, fake_binary)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_bytes(), b"keep me\n")
        self.assertFalse((root / "arguments").exists())

        root, fake_binary = self._prepare()
        outside = root / "outside"
        outside.mkdir()
        (root / "artifacts").symlink_to(outside, target_is_directory=True)
        result = self._run_boardless(root, fake_binary)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])

        for output_dir in (
            "../escape",
            "/absolute",
            "bad\nforged=value",
            "build/*",
            "build/result?",
            "build/[result]",
        ):
            with self.subTest(output_dir=output_dir):
                root, fake_binary = self._prepare()
                result = self._run_boardless(
                    root, fake_binary, output_dir=output_dir
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "arguments").exists())
                self.assertFalse((root / "github-output").exists())

    def test_boardless_malformed_missing_and_fatal_runs_fail_closed(self):
        for mode in ("malformed", "summary-digest-mismatch", "no-report", "fatal"):
            with self.subTest(mode=mode):
                root, fake_binary = self._prepare()
                result = self._run_boardless(root, fake_binary, mode=mode)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                outputs = self._outputs(root / "github-output")
                self.assertEqual(outputs.get("status", ""), "error")
                self.assertEqual(outputs.get("native-kicad-erc-report", ""), "")
                self.assertEqual(outputs.get("native-kicad-erc-approved", ""), "")

    def test_boardless_final_gate_enforces_every_publication_boundary(self):
        self.assertEqual(self._run_boardless_gate().returncode, 0)
        self.assertEqual(
            self._run_boardless_gate(
                PCBEX_NATIVE_ERC_APPROVED="false",
                PCBEX_REQUIRE_APPROVED="false",
            ).returncode,
            0,
        )
        failures = (
            {"PCBEX_PREFLIGHT_VALID": "false"},
            {"PCBEX_NATIVE_ERC_OUTCOME": "failure"},
            {"PCBEX_NATIVE_ERC_STATUS": "error"},
            {"PCBEX_ARTIFACT_SAFE": "false"},
            {
                "PCBEX_UPLOAD_ARTIFACT": "true",
                "PCBEX_UPLOAD_OUTCOME": "failure",
            },
            {
                "PCBEX_REQUIRE_APPROVED": "true",
                "PCBEX_NATIVE_ERC_APPROVED": "false",
            },
            {"PCBEX_REQUIRE_APPROVED": "maybe"},
            {"PCBEX_UPLOAD_ARTIFACT": "maybe"},
        )
        for values in failures:
            with self.subTest(values=values):
                self.assertNotEqual(
                    self._run_boardless_gate(**values).returncode, 0
                )


if __name__ == "__main__":
    unittest.main()
