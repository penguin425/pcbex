"""Dependency-free checks for immutable GitHub Action references.

Every external ``uses:`` entry in repository workflows and composite actions
must point at a full, lower-case commit SHA and carry a human-readable version
comment.  This is intentionally a small YAML subset parser: adding a new
``uses`` form that is not understood by the policy fails closed rather than
silently bypassing the check.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
GITHUB_DIR = ROOT / ".github"


_USES_LINE = re.compile(
    r"^(?P<indent> *)?(?:-\s+)?uses\s*:\s*(?P<value>.*)$"
)
_EXTERNAL_REF = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
    r"(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$"
)
_VERSION_COMMENT = re.compile(
    r"^v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:[-+][0-9A-Za-z.-]+)?$"
)


def _yaml_scalar_and_comment(raw_value: str) -> tuple[str, str | None]:
    """Split a simple YAML scalar from its unquoted inline comment.

    Workflow ``uses`` values are plain scalars in practice, but handling
    quotes here prevents a ``#`` embedded in a quoted fixture from being
    treated as a version comment.  The returned comment excludes ``#``.
    """

    single = double = False
    escaped = False
    for index, character in enumerate(raw_value):
        if character == "\\" and double and not escaped:
            escaped = True
            continue
        if character == "'" and not double:
            single = not single
        elif character == '"' and not single and not escaped:
            double = not double
        elif character == "#" and not single and not double:
            if index == 0 or raw_value[index - 1].isspace():
                value = raw_value[:index].strip()
                comment = raw_value[index + 1 :].strip()
                return value, comment
        escaped = False
    return raw_value.strip(), None


def _unquote_scalar(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _policy_files() -> list[Path]:
    """Return workflows plus every repository composite-action manifest."""

    paths = {
        path
        for path in GITHUB_DIR.rglob("*")
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
    }
    ignored_directories = {".git", ".venv", "__pycache__", "build", "target"}
    for directory, directories, files in os.walk(ROOT):
        directories[:] = [
            name for name in directories if name not in ignored_directories
        ]
        for name in ("action.yml", "action.yaml"):
            if name in files:
                paths.add(Path(directory) / name)
    return sorted(paths)


def _uses_violations(document: str, path: str = "<document>") -> list[str]:
    """Return policy violations for external ``uses`` mappings.

    Local actions (``./...``) are intentionally out of scope.  Docker actions,
    expressions, malformed refs, mutable tags, short SHAs, and missing or
    malformed version comments are all rejected so a future syntax extension
    cannot weaken the policy accidentally.
    """

    violations: list[str] = []
    for line_number, raw_line in enumerate(document.splitlines(), start=1):
        match = _USES_LINE.match(raw_line)
        if match is None:
            continue
        value, comment = _yaml_scalar_and_comment(match.group("value"))
        value = _unquote_scalar(value)

        if not value:
            violations.append(f"{path}:{line_number}: empty uses value")
            continue
        if value.startswith("./"):
            continue
        if value.startswith("docker://"):
            violations.append(
                f"{path}:{line_number}: Docker uses refs are unsupported"
            )
            continue
        if value.startswith("${{") or "${{" in value:
            violations.append(
                f"{path}:{line_number}: expression uses refs are unsupported"
            )
            continue
        if _EXTERNAL_REF.fullmatch(value) is None:
            violations.append(
                f"{path}:{line_number}: external uses ref is not a full lower-case SHA: {value!r}"
            )
            continue
        if comment is None or _VERSION_COMMENT.fullmatch(comment) is None:
            violations.append(
                f"{path}:{line_number}: external uses ref needs a '# vX.Y.Z' comment"
            )
    return violations


class ActionPinningTests(unittest.TestCase):
    def test_all_external_action_refs_are_immutable_and_version_annotated(self):
        files = _policy_files()
        self.assertTrue(files, "expected at least one GitHub workflow/action YAML file")
        violations = [
            violation
            for path in files
            for violation in _uses_violations(
                path.read_text(encoding="utf-8"), str(path.relative_to(ROOT))
            )
        ]
        self.assertEqual(violations, [])

    def test_fixture_accepts_full_sha_and_ignores_local_actions(self):
        fixture = """
jobs:
  check:
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v7.0.1
      - uses: owner/repo/subpath@abcdef0123456789abcdef0123456789abcdef01 # v1.2.3
      - uses: ./local-action
"""
        self.assertEqual(_uses_violations(fixture), [])

    def test_fixture_rejects_mutable_short_and_expression_refs(self):
        fixtures = {
            "mutable tag": "      - uses: actions/checkout@v7 # v7.0.1\n",
            "short SHA": "      - uses: actions/checkout@0123456789abcdef # v7.0.1\n",
            "expression": "      - uses: actions/checkout@${{ inputs.ref }} # v7.0.1\n",
            "missing comment": (
                "      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n"
            ),
            "wrong comment": (
                "      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # pinned\n"
            ),
        }
        for name, fixture in fixtures.items():
            with self.subTest(name=name):
                violations = _uses_violations(fixture, name)
                self.assertTrue(violations)

    def test_docker_refs_fail_closed(self):
        fixture = "      - uses: docker://alpine:3.20 # v1\n"
        violations = _uses_violations(fixture, "docker-fixture")
        self.assertEqual(len(violations), 1)
        self.assertIn("Docker uses refs are unsupported", violations[0])


if __name__ == "__main__":
    unittest.main()
