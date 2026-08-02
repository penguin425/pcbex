"""Static trust-boundary checks for the pull-request comment workflows.

The comment body is produced by an untrusted pull-request run and is written
with a token only from a protected ``workflow_run`` job.  These tests are
deliberately dependency-free: the runner may not have PyYAML installed, so we
inspect the small subset of YAML structure needed for the security contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
PUBLISHER_WORKFLOW = ROOT / ".github" / "workflows" / "pr-comment-publisher.yml"


_MAPPING_KEY = re.compile(
    r"^(?P<indent> *)(?:(?P<sequence>-)[ \t]+)?"
    r"(?P<key>[A-Za-z0-9_.-]+):(?:[ \t]*(?P<value>.*))?$"
)


@dataclass
class _YamlScope:
    indent: int
    keys: set[str] = field(default_factory=set)


def _strip_yaml_comment(line: str) -> str:
    """Remove a comment when ``#`` starts an unquoted YAML comment.

    Workflow expressions and shell snippets are not parsed as YAML values by
    this helper.  Handling the common quote cases is enough to avoid treating
    a ``#`` inside a quoted value as the beginning of a comment.
    """

    single = double = False
    escaped = False
    for index, character in enumerate(line):
        if character == "\\" and double and not escaped:
            escaped = True
            continue
        if character == "'" and not double:
            single = not single
        elif character == '"' and not single and not escaped:
            double = not double
        elif character == "#" and not single and not double:
            if index == 0 or line[index - 1].isspace():
                return line[:index]
        escaped = False
    return line


def _duplicate_yaml_keys(document: str) -> list[str]:
    """Return duplicate mapping keys from the simple YAML subset in a file.

    A scope is tracked by indentation.  Sequence entries get a fresh mapping
    scope, so the repeated ``name`` and ``uses`` keys in normal workflow steps
    are not reported.  Block scalar contents are skipped because they are
    shell text, not YAML mappings.
    """

    scopes: list[_YamlScope] = []
    duplicates: list[str] = []
    scalar_parent_indent: int | None = None

    for raw_line in document.splitlines():
        if scalar_parent_indent is not None:
            if raw_line.strip() == "":
                continue
            if len(raw_line) - len(raw_line.lstrip(" ")) > scalar_parent_indent:
                continue
            scalar_parent_indent = None

        line = _strip_yaml_comment(raw_line).rstrip()
        if not line.strip():
            continue
        match = _MAPPING_KEY.match(line)
        if match is None:
            continue

        indent = len(match.group("indent"))
        is_sequence = match.group("sequence") is not None
        key = match.group("key")
        value = (match.group("value") or "").strip()

        # The keys of a sequence item are indented two spaces past the dash.
        # Sibling items therefore replace the previous item scope.
        key_indent = indent + 2 if is_sequence else indent
        if is_sequence:
            while scopes and scopes[-1].indent >= key_indent:
                scopes.pop()
        else:
            while scopes and scopes[-1].indent > key_indent:
                scopes.pop()

        if scopes and scopes[-1].indent == key_indent:
            scope = scopes[-1]
        else:
            scope = _YamlScope(key_indent)
            scopes.append(scope)

        if key in scope.keys:
            duplicates.append(f"indent {key_indent}: {key}")
        scope.keys.add(key)

        # A no-value mapping starts a child mapping.  Block scalar values do
        # not, and their indented shell text must not be interpreted as YAML.
        if value.startswith("|") or value.startswith(">"):
            scalar_parent_indent = key_indent
        elif not value or is_sequence:
            child_indent = key_indent + 2
            if not scopes or scopes[-1].indent < child_indent:
                scopes.append(_YamlScope(child_indent))

    return duplicates


def _job_block(document: str, job: str) -> str:
    """Extract one ``jobs.<job>`` mapping by indentation."""

    lines = document.splitlines()
    start = None
    for index, line in enumerate(lines):
        if re.fullmatch(rf"  {re.escape(job)}:\s*", line):
            start = index
            break
    if start is None:
        raise AssertionError(f"workflow job not found: {job}")

    selected = [lines[start]]
    for line in lines[start + 1 :]:
        if line.strip() and len(line) - len(line.lstrip(" ")) <= 2:
            break
        selected.append(line)
    return "\n".join(selected)


def _direct_mapping(document: str, key: str) -> dict[str, str]:
    """Read one indentation-level mapping from a job block."""

    lines = document.splitlines()
    start = None
    base_indent = None
    for index, line in enumerate(lines):
        match = re.match(r"^( *)" + re.escape(key) + r":\s*$", line)
        if match:
            start = index
            base_indent = len(match.group(1))
            break
    if start is None or base_indent is None:
        return {}

    values: dict[str, str] = {}
    for line in lines[start + 1 :]:
        if line.strip() and len(line) - len(line.lstrip(" ")) <= base_indent:
            break
        match = _MAPPING_KEY.match(line)
        if match is not None and len(match.group("indent")) == base_indent + 2:
            values[match.group("key")] = (match.group("value") or "").strip()
    return values


def _step_blocks(job_block: str) -> list[str]:
    """Extract the entries directly under a job's ``steps`` list."""

    lines = job_block.splitlines()
    steps_index = next(
        (index for index, line in enumerate(lines) if re.match(r"^\s*steps:\s*$", line)),
        None,
    )
    if steps_index is None:
        return []
    steps_indent = len(lines[steps_index]) - len(lines[steps_index].lstrip(" "))
    item_indent = None
    for line in lines[steps_index + 1 :]:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= steps_indent:
            break
        if re.match(r"^\s*-\s+", line):
            item_indent = indent
            break
    if item_indent is None:
        return []

    blocks: list[str] = []
    current: list[str] = []
    for line in lines[steps_index + 1 :]:
        if line.strip():
            indent = len(line) - len(line.lstrip(" "))
            if indent <= steps_indent:
                break
            if indent == item_indent and re.match(r"^\s*-\s+", line):
                if current:
                    blocks.append("\n".join(current))
                current = [line]
                continue
        if current:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


class PullRequestCommentWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ci = CI_WORKFLOW.read_text(encoding="utf-8")
        cls.publisher = PUBLISHER_WORKFLOW.read_text(encoding="utf-8")
        cls.hardware = _job_block(cls.ci, "hardware-ci-action")
        cls.publisher_job = _job_block(cls.publisher, "publish")

    def test_workflow_yaml_has_no_duplicate_mapping_keys(self):
        for path, document in (
            (CI_WORKFLOW, self.ci),
            (PUBLISHER_WORKFLOW, self.publisher),
        ):
            with self.subTest(path=path):
                self.assertEqual(_duplicate_yaml_keys(document), [])

    def test_untrusted_hardware_job_is_read_only_and_does_not_receive_token(self):
        permissions = _direct_mapping(self.hardware, "permissions")
        self.assertEqual(permissions.get("contents"), "read")
        self.assertNotEqual(permissions.get("pull-requests"), "write")
        self.assertNotRegex(
            self.hardware,
            r"(?m)^\s*pull-requests:\s*write\s*$",
        )
        self.assertNotRegex(
            self.hardware,
            r"(?m)^\s*(?:github-token|token):\s*",
        )

    def test_hardware_job_uses_safe_checkout_and_stages_run_attempt_artifact(self):
        hardware_steps = _step_blocks(self.hardware)
        checkout_steps = [
            step
            for step in hardware_steps
            if re.search(r"(?m)^\s*(?:-\s+)?uses:\s*actions/checkout@", step)
        ]
        self.assertTrue(checkout_steps, "hardware job must check out the repository")
        self.assertTrue(
            any(
                re.search(r"(?m)^\s*persist-credentials:\s*false\s*$", step)
                for step in checkout_steps
            ),
            "hardware checkout must not persist a writable credential",
        )

        local_actions = [
            step
            for step in hardware_steps
            if re.search(r"(?m)^\s*(?:-\s+)?uses:\s*\./(?:\s|$)", step)
        ]
        self.assertTrue(local_actions, "hardware job must exercise the local action")
        self.assertTrue(
            any(
                re.search(r"(?m)^\s*pr-comment:\s*[\"']?false[\"']?\s*$", step)
                for step in local_actions
            ),
            "the comment-capable local action invocation must opt out of publishing",
        )
        self.assertFalse(
            any(re.search(r"(?m)^\s*github-token:\s*", step) for step in local_actions)
        )

        self.assertRegex(self.hardware, r"scripts/stage-pr-comment\.py")
        upload_steps = [
            step
            for step in hardware_steps
            if re.search(
                r"(?m)^\s*(?:-\s+)?uses:\s*actions/upload-artifact@", step
            )
            and "pr-comment" in step
        ]
        self.assertTrue(upload_steps, "staged PR comment must be uploaded as an artifact")
        upload = "\n".join(upload_steps)
        self.assertRegex(upload, r"github\.run_id|GITHUB_RUN_ID")
        self.assertRegex(upload, r"github\.run_attempt|GITHUB_RUN_ATTEMPT")

    def test_publisher_is_completed_ci_workflow_run_with_minimal_permissions(self):
        self.assertRegex(self.publisher, r"(?m)^\s*workflow_run:\s*$")
        self.assertRegex(self.publisher, r"(?m)^\s*workflows:\s*\[?\s*[\"']?CI")
        self.assertRegex(self.publisher, r"(?m)^\s*types:\s*\[?\s*[\"']?completed")

        self.assertRegex(
            self.publisher_job,
            r"workflow_run\.event\s*==\s*['\"]pull_request['\"]",
        )
        self.assertRegex(
            self.publisher_job,
            r"workflow_run\.conclusion\s*==\s*['\"]success['\"]",
        )
        self.assertRegex(
            self.publisher_job,
            r"(?m)^\s*timeout-minutes:\s*10\s*$",
        )

        permissions = _direct_mapping(self.publisher_job, "permissions")
        self.assertEqual(
            permissions,
            {
                "actions": "read",
                "contents": "read",
                "pull-requests": "write",
            },
        )

    def test_publisher_checks_out_pinned_default_branch_and_runs_only_trusted_script(self):
        checkout_steps = [
            step
            for step in _step_blocks(self.publisher_job)
            if re.search(r"(?m)^\s*(?:-\s+)?uses:\s*actions/checkout@", step)
        ]
        self.assertEqual(len(checkout_steps), 1)
        checkout = checkout_steps[0]
        self.assertRegex(
            checkout,
            r"uses:\s*actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        )
        self.assertNotRegex(checkout, r"uses:\s*actions/checkout@v7\b")
        self.assertRegex(
            checkout,
            r"(?m)^\s*ref:\s*\$\{\{\s*github\.event\.repository\.default_branch\s*\}\}",
        )
        self.assertRegex(checkout, r"(?m)^\s*persist-credentials:\s*false\s*$")

        self.assertNotRegex(self.publisher, r"uses:\s*\./")
        self.assertNotRegex(self.publisher, r"actions/download-artifact")
        self.assertNotRegex(self.publisher, r"workflow_run\.head_sha")
        self.assertNotRegex(self.publisher, r"pull_request\.head\.sha")

        publish_steps = [
            step
            for step in _step_blocks(self.publisher_job)
            if "actions/checkout@" not in step
            and not re.search(r"(?i)\bpost[- ]", step)
        ]
        self.assertTrue(publish_steps)
        for step in publish_steps:
            self.assertRegex(step, r"python3\s+scripts/publish-pr-comment\.py")
            self.assertNotRegex(step, r"(?m)^\s*uses:\s*\./")

    def test_publisher_concurrency_is_scoped_to_head_repository_and_branch(self):
        self.assertRegex(self.publisher_job, r"(?m)^\s*concurrency:\s*$")
        self.assertIn(
            "github.event.workflow_run.head_repository.full_name", self.publisher_job
        )
        self.assertIn("github.event.workflow_run.head_branch", self.publisher_job)


if __name__ == "__main__":
    unittest.main()
