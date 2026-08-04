"""Dependency-free regression tests for GitHub Actions execution ceilings."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTION = ROOT / "action.yml"
BOARDLESS_NATIVE_ERC_ACTION = ROOT / "actions" / "native-kicad-erc" / "action.yml"

EXPECTED_TIMEOUTS = {
    "ci.yml": {
        "hardware-ci-action": 45,
        "rust": 45,
        "python": 20,
        "python-boundaries": 20,
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

    def test_composite_action_supervises_commands_and_gates_publication(self):
        document = ACTION.read_text(encoding="utf-8")
        self.assertGreaterEqual(document.count("scripts/ci_runtime.py\" exec"), 3)
        self.assertIn("--timeout-seconds 2400", document)
        self.assertIn("--max-total-bytes 536870912", document)
        self.assertIn("id: artifact-boundary", document)
        self.assertGreaterEqual(
            document.count("steps.artifact-boundary.outputs.safe == 'true'"), 3
        )

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
        boundaries = _job_blocks(document)["python-boundaries"]
        self.assertIn("macos-latest", boundaries)
        self.assertIn("windows-latest", boundaries)
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
