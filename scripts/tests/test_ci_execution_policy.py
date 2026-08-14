"""Dependency-free regression tests for GitHub Actions execution ceilings."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTION = ROOT / "action.yml"
BOARDLESS_NATIVE_ERC_ACTION = ROOT / "actions" / "native-kicad-erc" / "action.yml"
FABRICATION_AUTHORIZATION_ACTION = (
    ROOT / "actions" / "fabrication-authorization" / "action.yml"
)
FABRICATION_AUTHORIZATION_FIXTURE = (
    ROOT / "scripts" / "fabrication_authorization_action_ci.py"
)
FABRICATION_AUTHORIZATION_SUMMARY_OUTPUTS = (
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

EXPECTED_TIMEOUTS = {
    "ci.yml": {
        "hardware-ci-action": 45,
        "deterministic-pipeline": 45,
        "rust": 45,
        "python": 20,
        "python-boundaries": 45,
        "rust-windows-boundaries": 30,
    },
    "codeql.yml": {"analyze": 30},
    "fuzz.yml": {"fuzz": 30},
    "kicad-e2e.yml": {"kicad": 45},
    "pr-comment-publisher.yml": {"publish": 10},
    "release.yml": {
        "verify": 45,
        "prepare": 10,
        "build": 45,
        "audit": 15,
        "publish": 10,
    },
}

EXPECTED_CONCURRENCY = {
    "ci.yml": ("group: ci-${{ github.workflow }}-${{ github.ref }}", "true"),
    "codeql.yml": (
        "group: codeql-${{ github.workflow }}-${{ github.ref }}",
        "true",
    ),
    "fuzz.yml": ("group: fuzz-${{ github.workflow }}-${{ github.ref }}", "true"),
    "kicad-e2e.yml": ("group: kicad-e2e-${{ github.ref }}", "true"),
    "pr-comment-publisher.yml": (
        "pcbex-pr-comment-${{ github.event.workflow_run.head_repository.full_name }}-${{ github.event.workflow_run.head_branch }}",
        "true",
    ),
    "release.yml": ("group: release-${{ github.ref }}", "false"),
}


def _job_blocks(document: str) -> dict[str, str]:
    lines = document.splitlines()
    try:
        jobs_index = lines.index("jobs:")
    except ValueError as error:
        raise AssertionError("workflow has no top-level jobs mapping") from error
    starts: list[tuple[int, str]] = []
    for index in range(jobs_index + 1, len(lines)):
        match = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", lines[index])
        if match:
            starts.append((index, match.group(1)))
    blocks: dict[str, str] = {}
    for offset, (start, name) in enumerate(starts):
        end = starts[offset + 1][0] if offset + 1 < len(starts) else len(lines)
        blocks[name] = "\n".join(lines[start:end])
    return blocks


def _direct_integer(block: str, key: str) -> int | None:
    match = re.search(rf"(?m)^    {re.escape(key)}:\s*([0-9]+)\s*$", block)
    return None if match is None else int(match.group(1))


class CiExecutionPolicyTests(unittest.TestCase):
    def test_ci_required_context_triggers_are_not_path_or_activity_filtered(self):
        document = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        header, separator, _ = document.partition("\npermissions:\n")
        self.assertTrue(separator, "CI workflow has no top-level permissions boundary")
        self.assertIn("  push:\n    branches: [main]\n  pull_request:\n", header)
        self.assertNotRegex(header, r"(?m)^\s+(?:paths|paths-ignore|types):")

    def test_every_workflow_job_has_the_reviewed_timeout(self):
        actual_files = {
            path.name
            for pattern in ("*.yml", "*.yaml")
            for path in WORKFLOWS.glob(pattern)
        }
        self.assertEqual(actual_files, set(EXPECTED_TIMEOUTS))
        for filename, expected_jobs in EXPECTED_TIMEOUTS.items():
            document = (WORKFLOWS / filename).read_text(encoding="utf-8")
            blocks = _job_blocks(document)
            self.assertEqual(set(blocks), set(expected_jobs), filename)
            for job, expected_timeout in expected_jobs.items():
                with self.subTest(workflow=filename, job=job):
                    timeout = _direct_integer(blocks[job], "timeout-minutes")
                    self.assertEqual(timeout, expected_timeout)
                    self.assertGreater(timeout, 0)
                    self.assertLessEqual(timeout, 60)

    def test_every_workflow_has_bounded_concurrency(self):
        for filename in EXPECTED_TIMEOUTS:
            document = (WORKFLOWS / filename).read_text(encoding="utf-8")
            blocks = _job_blocks(document)
            top_level = re.search(r"(?m)^concurrency:\s*$", document) is not None
            per_job = all(
                re.search(r"(?m)^    concurrency:\s*$", block) is not None
                for block in blocks.values()
            )
            with self.subTest(workflow=filename):
                self.assertTrue(top_level or per_job)
                group, cancellation = EXPECTED_CONCURRENCY[filename]
                self.assertIn(group, document)
                self.assertRegex(
                    document,
                    rf"(?m)^\s+cancel-in-progress:\s*{cancellation}\s*$",
                )

    def test_every_matrix_has_fail_fast_and_parallelism_ceiling(self):
        matrix_jobs = set()
        for filename in EXPECTED_TIMEOUTS:
            document = (WORKFLOWS / filename).read_text(encoding="utf-8")
            for job, block in _job_blocks(document).items():
                if re.search(r"(?m)^      matrix:\s*$", block) is None:
                    continue
                matrix_jobs.add((filename, job))
                with self.subTest(workflow=filename, job=job):
                    self.assertRegex(block, r"(?m)^      fail-fast:\s*false\s*$")
                    match = re.search(
                        r"(?m)^      max-parallel:\s*([0-9]+)\s*$", block
                    )
                    self.assertIsNotNone(match)
                    assert match is not None
                    self.assertGreater(int(match.group(1)), 0)
                    self.assertLessEqual(int(match.group(1)), 2)
        self.assertEqual(
            matrix_jobs,
            {
                ("ci.yml", "python-boundaries"),
                ("codeql.yml", "analyze"),
                ("fuzz.yml", "fuzz"),
                ("release.yml", "build"),
            },
        )

    def test_fuzz_has_time_memory_input_and_artifact_bounds(self):
        document = (WORKFLOWS / "fuzz.yml").read_text(encoding="utf-8")
        for required in (
            "-max_total_time=60",
            "-timeout=10",
            "-rss_limit_mb=2048",
            "-max_len=1048576",
            "-artifact_prefix=",
            "--max-entries 16",
            "--max-file-bytes 1048576",
            "--max-total-bytes 16777216",
            "steps.fuzz-artifact-boundary.outputs.safe == 'true'",
            "retention-days: 7",
        ):
            with self.subTest(required=required):
                self.assertIn(required, document)

    def test_release_runs_are_serial_and_never_cancelled_mid_publish(self):
        document = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        self.assertIn("group: release-${{ github.ref }}", document)
        self.assertRegex(document, r"(?m)^  cancel-in-progress:\s*false\s*$")

    def test_release_publication_requires_successful_required_check_runs(self):
        document = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        jobs = _job_blocks(document)
        audit = jobs["audit"]
        publish = jobs["publish"]
        self.assertRegex(audit, r"(?m)^      checks:\s*read\s*$")
        self.assertIn("--check-required-runs", audit)
        self.assertNotIn("--check-protection", audit)
        self.assertRegex(publish, r"(?m)^    needs:\s*audit\s*$")

    def test_composite_action_supervises_commands_and_gates_publication(self):
        document = ACTION.read_text(encoding="utf-8")
        self.assertGreaterEqual(document.count("scripts/ci_runtime.py\" exec"), 3)
        self.assertIn("--timeout-seconds 2400", document)
        self.assertIn("--max-total-bytes 536870912", document)
        self.assertIn("id: artifact-boundary", document)
        self.assertGreaterEqual(
            document.count("steps.artifact-boundary.outputs.safe == 'true'"), 3
        )

    def test_focused_fabrication_authorization_action_smoke_is_bounded_and_ordered(
        self,
    ):
        document = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        block = _job_blocks(document)["hardware-ci-action"]
        fixture_name = (
            "- name: Build real factory-bound fabrication authorization fixture"
        )
        authorized_name = "- name: Exercise authorized fabrication authorization action"
        insufficient_name = (
            "- name: Exercise insufficient fabrication authorization action"
        )
        verify_name = "- name: Verify focused fabrication authorization action outputs"
        following_name = "- name: Prepare deterministic pipeline plan fixture"
        fixture_index = block.index(fixture_name)
        authorized_index = block.index(authorized_name)
        insufficient_index = block.index(insufficient_name)
        verify_index = block.index(verify_name)
        following_index = block.index(following_name)
        self.assertLess(fixture_index, authorized_index)
        self.assertLess(authorized_index, insufficient_index)
        self.assertLess(insufficient_index, verify_index)
        self.assertLess(verify_index, following_index)

        fixture = block[fixture_index:authorized_index]
        authorized = block[authorized_index:insufficient_index]
        insufficient = block[insufficient_index:verify_index]
        verification = block[verify_index:following_index]
        for required in (
            "python3 scripts/ci_runtime.py exec",
            "--timeout-seconds 900",
            "--max-stdout-bytes 65536",
            "--max-stderr-bytes 1048576",
            "--output-root build/fabrication-authorization-action-fixture",
            "-- python3 scripts/fabrication_authorization_action_ci.py",
            "--pcbex target/release/pcbex",
            "--fixture-dir crates/pcbex-cli/tests/fixtures/deterministic-pipeline-ci",
            "--policy-template examples/acme-policy-pack.json",
            "--output-dir build/fabrication-authorization-action-fixture",
            "--timeout-seconds 300",
        ):
            with self.subTest(required=required):
                self.assertIn(required, fixture)
        self.assertEqual(
            block.count("uses: ./actions/fabrication-authorization"), 2
        )
        for action_case in (authorized, insufficient):
            self.assertIn("require-authorized: \"true\"", action_case)
            self.assertIn('upload-artifact: "false"', action_case)
            self.assertIn("approval-files:", action_case)
            self.assertNotRegex(action_case, r"(?m)^          approvals:")
            self.assertIn("factory-required-plan.json", action_case)
            self.assertIn("factory-required-report.json", action_case)
            self.assertIn("manufacturing.zip", action_case)
            self.assertIn("factory-receipt.json", action_case)
            self.assertIn("final-policy-pack.json", action_case)
        self.assertNotIn("continue-on-error", authorized)
        self.assertIn("continue-on-error: true", insufficient)
        self.assertIn("approval-b.json", authorized)
        self.assertNotIn("approval-b.json", insufficient)
        self.assertIn("if: ${{ always() }}", verification)
        for output in FABRICATION_AUTHORIZATION_SUMMARY_OUTPUTS:
            with self.subTest(summary_output=output):
                self.assertIn(
                    f"steps.fabrication-authorization-authorized.outputs.{output}",
                    verification,
                )
                self.assertIn(
                    f"steps.fabrication-authorization-insufficient.outputs.{output}",
                    verification,
                )
        for required in (
            "fixture-summary.json",
            'test "$AUTHORIZED_STATUS" = "ok"',
            'test "$AUTHORIZED_STATUS_VALUE" = "fabrication_authorized"',
            'test "$AUTHORIZED" = "true"',
            'test "$AUTHORIZED_APPROVALS" = "2"',
            'test "$AUTHORIZED_GATE_FAILURE_COUNT" = "0"',
            'test "$AUTHORIZED_REPORT_BYTES" -le 134217728',
            'test "$AUTHORIZED_REPORT_BYTES" =',
            'test "$AUTHORIZED_REPORT_SHA256" =',
            'test "$INSUFFICIENT_OUTCOME" = "failure"',
            'test "$INSUFFICIENT_STATUS_VALUE" = "not_authorized"',
            'test "$INSUFFICIENT_AUTHORIZED" = "false"',
            'test "$INSUFFICIENT_APPROVALS" = "1"',
            'test "$INSUFFICIENT_GATE_FAILURE_COUNT" = "1"',
            'test "$INSUFFICIENT_REPORT_BYTES" -le 134217728',
            'test "$INSUFFICIENT_REPORT_BYTES" =',
            'test "$INSUFFICIENT_REPORT_SHA256" =',
            "insufficient_fabrication_approvals:required=2:actual=1",
            "and .scope == {",
            "and .evaluated_at_unix == $evaluated_at",
            ".evidence.pipeline.plan_sha256",
            ".evidence.pipeline.run_sha256",
            ".evidence.manufacturing_package.sha256",
            ".evidence.factory_receipt.receipt.sha256",
            ".evidence.policy_pack.source.sha256",
        ):
            with self.subTest(required=required):
                self.assertIn(required, verification)

        fixture_source = FABRICATION_AUTHORIZATION_FIXTURE.read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "import deterministic_pipeline_ci as pipeline_fixture", fixture_source
        )
        self.assertIn("tempfile.TemporaryDirectory", fixture_source)
        self.assertIn('"require_factory": True', fixture_source)
        self.assertIn('"run-deterministic-pipeline"', fixture_source)
        self.assertIn('"--require-approved"', fixture_source)
        self.assertEqual(fixture_source.count('"sign-fabrication-approval"'), 1)
        self.assertIn("_validate_approvals(", fixture_source)
        self.assertIn("fixture-summary.json", fixture_source)

    def test_focused_fabrication_authorization_action_has_pinned_execution_and_gate_order(
        self,
    ):
        document = FABRICATION_AUTHORIZATION_ACTION.read_text(encoding="utf-8")
        inputs = document[
            document.index("\ninputs:\n") : document.index("\noutputs:\n")
        ]
        outputs = document[
            document.index("\noutputs:\n") : document.index("\nruns:\n")
        ]
        self.assertEqual(
            re.findall(r"(?m)^  ([a-z][a-z0-9-]*):\s*$", inputs),
            [
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
            ],
        )
        self.assertEqual(
            re.findall(r"(?m)^  ([a-z][a-z0-9-]*):\s*$", outputs),
            [
                "status",
                "artifact-dir",
                "fabrication-authorization-report",
                *FABRICATION_AUTHORIZATION_SUMMARY_OUTPUTS,
            ],
        )
        self.assertIn('scripts/ci_runtime.py" exec', document)
        for required in (
            "--timeout-seconds 600",
            "--timeout-seconds 1800",
            "--timeout-seconds 60",
            "--timeout-seconds 900",
            "--max-stdout-bytes 1048576",
            "--max-stderr-bytes 8388608",
            "--max-file-bytes 134217728",
            "--max-total-bytes 134217728",
            "cargo +stable build",
            "--locked",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "authorization-status",
            "report-bytes",
            "report-sha256",
        ):
            with self.subTest(required=required):
                self.assertIn(required, document)
        verify = document.index("- name: Verify fabrication authorization")
        artifact = document.index(
            "- name: Validate one-file bounded fabrication evidence"
        )
        publication = document.index(
            "- name: Revalidate fabrication authorization before publication"
        )
        upload = document.index("- name: Upload fabrication authorization evidence")
        gate = document.index("- name: Enforce fabrication authorization gate")
        self.assertLess(verify, artifact)
        self.assertLess(artifact, publication)
        self.assertLess(publication, upload)
        self.assertLess(upload, gate)
        self.assertIn("if: ${{ always() }}", document[gate:])

    def test_deterministic_pipeline_job_is_independent_and_fully_enforced(self):
        document = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        block = _job_blocks(document)["deterministic-pipeline"]
        self.assertIn("name: Deterministic Pipeline", block)
        self.assertNotRegex(block, r"(?m)^    (?:if|needs|strategy):")
        self.assertRegex(block, r"(?m)^    permissions:\s*$")
        self.assertRegex(block, r"(?m)^      contents:\s*read\s*$")
        self.assertNotRegex(block, r"(?m)^      (?!contents:)\S+:\s*")
        self.assertIn(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            block,
        )
        self.assertIn("persist-credentials: false", block)
        self.assertIn("rustup toolchain install stable --profile minimal", block)
        self.assertIn("cargo +stable build --package pcbex --release --locked", block)
        self.assertIn("continue-on-error: true", block)
        self.assertIn("python3 scripts/deterministic_pipeline_ci.py", block)
        self.assertIn("--pcbex target/release/pcbex", block)
        self.assertIn(
            "--fixture-dir crates/pcbex-cli/tests/fixtures/deterministic-pipeline-ci",
            block,
        )
        self.assertIn("--output-dir build/deterministic-pipeline-ci", block)
        self.assertIn("id: replay", block)
        self.assertIn(
            "python3 -m pcbex_agent.cli replay-deterministic-pipeline", block
        )
        self.assertIn(
            "build/deterministic-pipeline-ci/accepted-replay.json", block
        )
        self.assertIn(
            "build/deterministic-pipeline-ci/rejected-replay.json", block
        )
        self.assertIn("deterministic-pipeline-fresh-replay-v1", block)
        self.assertIn('result["report"]["identical"] is not True', block)
        self.assertIn("set(result[\"validation\"]) != expected_validation", block)
        for required in (
            "--timeout-seconds 1800",
            "--max-stdout-bytes 8388608",
            "--max-stderr-bytes 8388608",
            "--output-root build/deterministic-pipeline-ci",
            "--max-entries 64",
            "--max-depth 8",
            "--max-file-bytes 16777216",
            "--max-total-bytes 67108864",
        ):
            self.assertIn(required, block)
        self.assertIn(
            "SUMMARY_JSON: build/deterministic-pipeline-ci/summary.json", block
        )
        self.assertIn("id: summary", block)
        self.assertIn(
            '(keys | sort) == ["accepted", "rejected", "schema_version"]', block
        )
        self.assertIn("def integer_between($minimum; $maximum):", block)
        self.assertIn("def accepted_case:", block)
        self.assertIn("def rejected_case:", block)
        self.assertIn('"intent_source_sha256"', block)
        self.assertIn('"required_report_sha256"', block)
        self.assertIn("(.required_exit_code | integer_between(1; 255))", block)
        self.assertIn("(.required_report_sha256 | sha256)", block)
        self.assertIn(".approved == true", block)
        self.assertIn(".approved == false", block)
        self.assertIn("GITHUB_STEP_SUMMARY", block)
        self.assertIn("report_sha256", block)
        self.assertRegex(
            block,
            r"(?m)^\s*if: \$\{\{ always\(\) && steps\.scan\.outcome == 'success' \}\}$",
        )
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            block,
        )
        self.assertIn(
            "name: deterministic-pipeline-${{ github.run_id }}-${{ github.run_attempt }}",
            block,
        )
        self.assertIn("if-no-files-found: error", block)
        self.assertIn("retention-days: 7", block)
        self.assertRegex(
            block,
            r"(?m)^      - name: Enforce deterministic pipeline job$",
        )
        self.assertRegex(block, r"(?m)^        if: \$\{\{ always\(\) \}\}$")
        for outcome in (
            "PIPELINE_OUTCOME",
            "REPLAY_OUTCOME",
            "SCAN_OUTCOME",
            "SUMMARY_OUTCOME",
            "UPLOAD_OUTCOME",
        ):
            self.assertIn(f'test "${outcome}" = success', block)

    def test_boardless_native_erc_action_is_bounded_and_gates_after_upload(self):
        document = BOARDLESS_NATIVE_ERC_ACTION.read_text(encoding="utf-8")
        self.assertGreaterEqual(document.count('scripts/ci_runtime.py" exec'), 4)
        self.assertIn("--timeout-seconds 900", document)
        self.assertIn("--max-total-bytes 33554432", document)
        self.assertIn("id: artifact-boundary", document)
        self.assertIn("steps.artifact-boundary.outputs.safe == 'true'", document)
        self.assertIn("if: ${{ always() }}", document)
        self.assertLess(
            document.index("Upload native ERC evidence"),
            document.index("Enforce native ERC gate"),
        )

    def test_shared_runtime_boundaries_run_on_macos_and_windows(self):
        document = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        jobs = _job_blocks(document)
        boundaries = jobs["python-boundaries"]
        rust_windows = jobs["rust-windows-boundaries"]
        self.assertIn("macos-latest", boundaries)
        self.assertIn("windows-latest", boundaries)
        self.assertRegex(
            boundaries,
            r"(?m)^          - runner: macos-latest\n"
            r"            pcbex: target/release/pcbex$",
        )
        self.assertRegex(
            boundaries,
            r"(?m)^          - runner: windows-latest\n"
            r"            pcbex: target/release/pcbex\.exe$",
        )
        self.assertEqual(boundaries.count("- runner:"), 2)
        self.assertIn(
            "rustup toolchain install stable --profile minimal", boundaries
        )
        self.assertIn(
            "cargo +stable build --package pcbex --release --locked", boundaries
        )
        self.assertIn(
            "cargo +stable test --package pcbex --test capabilities --release --locked board_producer",
            boundaries,
        )
        self.assertIn(
            "cargo +stable test --package pcbex --test circuit_kicad_board_writer --release --locked",
            boundaries,
        )
        final_cpl_command = (
            "cargo +stable test --package pcbex --test final_cpl --release --locked"
        )
        self.assertIn(final_cpl_command, boundaries)
        self.assertNotIn(final_cpl_command, rust_windows)
        firmware_build_command = (
            "cargo +stable test --package pcbex --test firmware_build --release --locked"
        )
        self.assertEqual(document.count(firmware_build_command), 1)
        self.assertNotIn(firmware_build_command, rust_windows)
        assembly_evidence_command = (
            "python -m unittest\n"
            "          agent.tests.test_assembly_evidence_v1467\n"
            "          agent.tests.test_assembly_evidence_cli_v1467 -v"
        )
        self.assertEqual(document.count(assembly_evidence_command), 1)
        self.assertIn(assembly_evidence_command, boundaries)
        self.assertEqual(
            document.count("agent.tests.test_assembly_evidence_v1467"), 1
        )
        self.assertEqual(
            document.count("agent.tests.test_assembly_evidence_cli_v1467"), 1
        )
        supplier_offer_command = (
            "python -m unittest\n"
            "          agent.tests.test_supplier_offer_v1468\n"
            "          agent.tests.test_supplier_offer_cli_v1468 -v"
        )
        self.assertEqual(document.count(supplier_offer_command), 1)
        self.assertIn(supplier_offer_command, boundaries)
        self.assertNotIn(supplier_offer_command, rust_windows)
        self.assertEqual(
            document.count("agent.tests.test_supplier_offer_v1468"), 1
        )
        self.assertEqual(
            document.count("agent.tests.test_supplier_offer_cli_v1468"), 1
        )
        supplier_offer_acquisition_command = (
            "python -m unittest\n"
            "          agent.tests.test_supplier_offer_acquisition_v1469\n"
            "          agent.tests.test_supplier_offer_acquisition_cli_v1469 -v"
        )
        self.assertEqual(document.count(supplier_offer_acquisition_command), 1)
        self.assertIn(supplier_offer_acquisition_command, boundaries)
        self.assertNotIn(supplier_offer_acquisition_command, rust_windows)
        self.assertEqual(
            document.count("agent.tests.test_supplier_offer_acquisition_v1469"),
            1,
        )
        self.assertEqual(
            document.count(
                "agent.tests.test_supplier_offer_acquisition_cli_v1469"
            ),
            1,
        )
        assembly_supplier_offer_command = (
            "python -m unittest\n"
            "          agent.tests.test_assembly_supplier_offer_evidence_v1470\n"
            "          agent.tests.test_assembly_supplier_offer_evidence_cli_v1470 -v"
        )
        self.assertEqual(document.count(assembly_supplier_offer_command), 1)
        self.assertIn(assembly_supplier_offer_command, boundaries)
        self.assertNotIn(assembly_supplier_offer_command, rust_windows)
        self.assertEqual(
            document.count(
                "agent.tests.test_assembly_supplier_offer_evidence_v1470"
            ),
            1,
        )
        self.assertEqual(
            document.count(
                "agent.tests.test_assembly_supplier_offer_evidence_cli_v1470"
            ),
            1,
        )
        procurement_authorization_command = (
            "python -m unittest\n"
            "          agent.tests.test_procurement_release_authorization_v1471\n"
            "          agent.tests.test_procurement_release_authorization_cli_v1471 -v"
        )
        self.assertEqual(document.count(procurement_authorization_command), 1)
        self.assertIn(procurement_authorization_command, boundaries)
        self.assertNotIn(procurement_authorization_command, rust_windows)
        self.assertEqual(
            document.count(
                "agent.tests.test_procurement_release_authorization_v1471"
            ),
            1,
        )
        self.assertEqual(
            document.count(
                "agent.tests.test_procurement_release_authorization_cli_v1471"
            ),
            1,
        )
        procurement_reservation_command = (
            "python -m unittest\n"
            "          agent.tests.test_procurement_authorization_reservation_v1472\n"
            "          agent.tests.test_procurement_authorization_reservation_cli_v1472 -v"
        )
        procurement_reservation_rust_command = (
            "cargo +stable test --package pcbex\n"
            "          --test procurement_authorization_reservation --release --locked"
        )
        multi_unit_kicad_command = (
            "cargo +stable test --package pcbex\n"
            "          --test circuit_spec_v3 --release --locked"
        )
        self.assertEqual(document.count(procurement_reservation_command), 1)
        self.assertEqual(document.count(procurement_reservation_rust_command), 1)
        self.assertEqual(document.count(multi_unit_kicad_command), 1)
        self.assertIn(procurement_reservation_command, boundaries)
        self.assertIn(procurement_reservation_rust_command, boundaries)
        self.assertIn(multi_unit_kicad_command, boundaries)
        self.assertNotIn(procurement_reservation_command, rust_windows)
        self.assertNotIn(procurement_reservation_rust_command, rust_windows)
        self.assertNotIn(multi_unit_kicad_command, rust_windows)
        self.assertEqual(
            document.count(
                "agent.tests.test_procurement_authorization_reservation_v1472"
            ),
            1,
        )
        self.assertEqual(
            document.count(
                "agent.tests.test_procurement_authorization_reservation_cli_v1472"
            ),
            1,
        )
        self.assertIn(
            "cargo +stable test --package pcbex --bin pcbex --release --locked windows_",
            rust_windows,
        )
        self.assertIn("runs-on: windows-latest", rust_windows)
        self.assertIn("rustup toolchain install stable --profile minimal", rust_windows)
        toolchain_step = boundaries.index(
            "- name: Configure Windows GNU firmware toolchain"
        )
        firmware_build_step = boundaries.index(
            "- name: Run cross-platform v1.466 fresh firmware build boundaries"
        )
        assembly_evidence_step = boundaries.index(
            "- name: Run cross-platform v1.467 assembly-evidence boundaries"
        )
        supplier_offer_step = boundaries.index(
            "- name: Run cross-platform v1.468 supplier-offer coverage boundaries"
        )
        supplier_offer_acquisition_step = boundaries.index(
            "- name: Run cross-platform v1.469 supplier-offer acquisition boundaries"
        )
        assembly_supplier_offer_step = boundaries.index(
            "- name: Run cross-platform v1.470 assembly/supplier-offer boundaries"
        )
        procurement_authorization_step = boundaries.index(
            "- name: Run cross-platform v1.471 procurement-authorization boundaries"
        )
        procurement_reservation_step = boundaries.index(
            "- name: Run cross-platform v1.472 procurement-reservation boundaries"
        )
        procurement_reservation_rust_step = boundaries.index(
            "- name: Run cross-platform v1.472 local-ledger helper boundaries"
        )
        multi_unit_kicad_step = boundaries.index(
            "- name: Run cross-platform v1.473 multi-unit KiCad boundaries"
        )
        board_regressions_step = boundaries.index(
            "- name: Run cross-platform deterministic board producer regressions"
        )
        self.assertIn("if: ${{ runner.os == 'Windows' }}", boundaries)
        self.assertIn("C:\\mingw64\\bin", boundaries)
        self.assertIn("@('gcc.exe', 'g++.exe')", boundaries)
        self.assertIn("$env:GITHUB_PATH", boundaries)
        assembly_evidence_block = boundaries[
            assembly_evidence_step:supplier_offer_step
        ]
        self.assertIn("PYTHONPATH: agent/src", assembly_evidence_block)
        self.assertIn(assembly_evidence_command, assembly_evidence_block)
        supplier_offer_block = boundaries[
            supplier_offer_step:supplier_offer_acquisition_step
        ]
        self.assertIn("PYTHONPATH: agent/src", supplier_offer_block)
        self.assertIn(supplier_offer_command, supplier_offer_block)
        supplier_offer_acquisition_block = boundaries[
            supplier_offer_acquisition_step:assembly_supplier_offer_step
        ]
        self.assertIn(
            "PYTHONPATH: agent/src", supplier_offer_acquisition_block
        )
        self.assertIn(
            supplier_offer_acquisition_command,
            supplier_offer_acquisition_block,
        )
        assembly_supplier_offer_block = boundaries[
            assembly_supplier_offer_step:procurement_authorization_step
        ]
        self.assertIn("PYTHONPATH: agent/src", assembly_supplier_offer_block)
        self.assertIn(
            assembly_supplier_offer_command,
            assembly_supplier_offer_block,
        )
        procurement_authorization_block = boundaries[
            procurement_authorization_step:procurement_reservation_step
        ]
        self.assertIn("PYTHONPATH: agent/src", procurement_authorization_block)
        self.assertIn(
            procurement_authorization_command,
            procurement_authorization_block,
        )
        procurement_reservation_block = boundaries[
            procurement_reservation_step:procurement_reservation_rust_step
        ]
        self.assertIn("PYTHONPATH: agent/src", procurement_reservation_block)
        self.assertIn(
            procurement_reservation_command,
            procurement_reservation_block,
        )
        procurement_reservation_rust_block = boundaries[
            procurement_reservation_rust_step:multi_unit_kicad_step
        ]
        self.assertIn(
            procurement_reservation_rust_command,
            procurement_reservation_rust_block,
        )
        multi_unit_kicad_block = boundaries[multi_unit_kicad_step:toolchain_step]
        self.assertIn(multi_unit_kicad_command, multi_unit_kicad_block)
        self.assertLess(
            assembly_supplier_offer_step,
            procurement_authorization_step,
        )
        self.assertLess(procurement_authorization_step, procurement_reservation_step)
        self.assertLess(procurement_reservation_step, procurement_reservation_rust_step)
        self.assertLess(procurement_reservation_rust_step, multi_unit_kicad_step)
        self.assertLess(multi_unit_kicad_step, toolchain_step)
        self.assertIn("python scripts/deterministic_pipeline_ci.py", boundaries)
        self.assertIn("--pcbex ${{ matrix.pcbex }}", boundaries)
        self.assertIn(
            "--fixture-dir crates/pcbex-cli/tests/fixtures/deterministic-pipeline-ci",
            boundaries,
        )
        self.assertIn(
            "--output-dir build/deterministic-pipeline-portability", boundaries
        )
        self.assertEqual(
            boundaries.count(
                "python -m pcbex_agent.cli replay-deterministic-pipeline"
            ),
            2,
        )
        fixture_step = boundaries.index(
            "- name: Build real deterministic pipeline replay fixtures"
        )
        diagnostic_step = boundaries.index(
            "- name: Diagnose Windows firmware fixture failure"
        )
        accepted_step = boundaries.index(
            "- name: Replay accepted pipeline with the real release binary"
        )
        rejected_step = boundaries.index(
            "- name: Replay rejected pipeline with the real release binary"
        )
        boundary_tests_step = boundaries.index(
            "- name: Run cross-platform boundary tests"
        )
        self.assertLess(board_regressions_step, toolchain_step)
        self.assertLess(assembly_evidence_step, toolchain_step)
        self.assertLess(assembly_supplier_offer_step, toolchain_step)
        self.assertLess(multi_unit_kicad_step, toolchain_step)
        self.assertLess(toolchain_step, firmware_build_step)
        self.assertLess(firmware_build_step, fixture_step)
        self.assertLess(fixture_step, diagnostic_step)
        self.assertLess(diagnostic_step, accepted_step)
        self.assertIn(
            "if: ${{ failure() && runner.os == 'Windows' }}",
            boundaries[diagnostic_step:accepted_step],
        )
        self.assertIn(
            "build/deterministic-pipeline-portability/accepted/firmware",
            boundaries[diagnostic_step:accepted_step],
        )
        self.assertIn(
            "Get-Content -LiteralPath $manifest -Raw",
            boundaries[diagnostic_step:accepted_step],
        )
        self.assertLess(accepted_step, rejected_step)
        self.assertLess(rejected_step, boundary_tests_step)
        accepted_block = boundaries[accepted_step:rejected_step]
        rejected_block = boundaries[rejected_step:boundary_tests_step]
        self.assertIn(
            "build/deterministic-pipeline-portability/accepted/plan.json",
            boundaries,
        )
        self.assertIn(
            "build/deterministic-pipeline-portability/accepted/report.json",
            boundaries,
        )
        self.assertIn(
            "build/deterministic-pipeline-portability/rejected/plan.json",
            boundaries,
        )
        self.assertIn(
            "build/deterministic-pipeline-portability/rejected/report.json",
            boundaries,
        )
        self.assertIn("--require-approved", accepted_block)
        self.assertNotIn("--require-approved", rejected_block)
        self.assertEqual(boundaries.count("--require-approved"), 1)
        self.assertEqual(boundaries.count("--timeout-seconds 120"), 3)
        self.assertIn("scripts.tests.test_ci_runtime", boundaries)

    def test_ci_fixture_servers_are_registered_and_cleaned_up(self):
        document = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        self.assertEqual(document.count('printf \'%s\\n\' "$!" >> build/action-server-pids'), 3)
        self.assertEqual(document.count("nohup setsid python3"), 3)
        self.assertIn("- name: Stop fixture servers", document)
        self.assertIn("if: always()", document)
        self.assertIn('kill -TERM -- "-$server_pid"', document)
        self.assertIn('kill -KILL -- "-$server_pid"', document)
        self.assertIn("for attempt in {1..50}", document)


if __name__ == "__main__":
    unittest.main()
