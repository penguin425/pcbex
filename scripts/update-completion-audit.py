#!/usr/bin/env python3
"""Update or verify the generated completion-audit summary."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
import tomllib
import unittest

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from ci_runtime import (
    ExecutionBoundaryError,
    atomic_write_text,
    decode_utf8,
    read_text,
    run,
)

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "docs" / "COMPLETION_AUDIT.md"
START = "<!-- completion-audit:start -->"
END = "<!-- completion-audit:end -->"
MIB = 1024 * 1024
MAX_CONFIG_BYTES = MIB
MAX_AUDIT_BYTES = 2 * MIB
MAX_CARGO_STDOUT_BYTES = 32 * MIB
MAX_CARGO_STDERR_BYTES = 4 * MIB
CARGO_LIST_TIMEOUT_SECONDS = 10 * 60


class CompletionAuditError(RuntimeError):
    """The generated completion audit could not be produced safely."""


def rust_test_count() -> int:
    result = run(
        ["cargo", "test", "--workspace", "--locked", "--", "--list"],
        cwd=ROOT,
        timeout_seconds=CARGO_LIST_TIMEOUT_SECONDS,
        max_stdout_bytes=MAX_CARGO_STDOUT_BYTES,
        max_stderr_bytes=MAX_CARGO_STDERR_BYTES,
    )
    if result.returncode:
        detail = (result.stderr.strip() or result.stdout.strip()).decode(
            "utf-8", errors="replace"
        )[:2048]
        raise CompletionAuditError(
            f"cargo test --list failed with status {result.returncode}: {detail}"
        )
    output = decode_utf8(result.stdout, role="cargo test list output")
    return sum(line.endswith(": test") for line in output.splitlines())


def python_test_count() -> int:
    agent_src = str(ROOT / "agent" / "src")
    sys.path.insert(0, agent_src)
    previous = os.getcwd()
    try:
        os.chdir(ROOT)
        suite = unittest.defaultTestLoader.discover(str(ROOT / "agent" / "tests"))
        return suite.countTestCases()
    finally:
        os.chdir(previous)
        sys.path.remove(agent_src)


def generated_block() -> str:
    workspace = tomllib.loads(
        read_text(ROOT / "Cargo.toml", max_bytes=MAX_CONFIG_BYTES)
    )
    version = workspace["workspace"]["package"]["version"]
    agent = tomllib.loads(
        read_text(
            ROOT / "agent" / "pyproject.toml", max_bytes=MAX_CONFIG_BYTES
        )
    )
    agent_version = agent["project"]["version"]
    if agent_version != version:
        raise CompletionAuditError(
            "workspace and agent versions differ: "
            f"Rust {version}, Python {agent_version}"
        )
    return (
        f"{START}\n"
        f"Version {version} exposes {rust_test_count()} Rust tests and "
        f"{python_test_count()} Python tests. The release workflow\n"
        "also verifies formatting, Clippy, release builds, KiCad DRC fixtures, "
        "SBOMs,\n"
        "and build-provenance attestations.\n"
        f"{END}"
    )


def updated_document(document: str) -> str:
    pattern = re.compile(re.escape(START) + r".*?" + re.escape(END), re.DOTALL)
    if not pattern.search(document):
        raise CompletionAuditError(
            f"{AUDIT} does not contain generated audit markers"
        )
    return pattern.sub(generated_block(), document)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail instead of writing when the generated summary is stale",
    )
    args = parser.parse_args()

    try:
        original = read_text(AUDIT, max_bytes=MAX_AUDIT_BYTES)
        updated = updated_document(original)
        if len(updated.encode("utf-8")) > MAX_AUDIT_BYTES:
            raise CompletionAuditError(
                f"generated completion audit exceeds {MAX_AUDIT_BYTES} bytes"
            )
        if args.check:
            if updated != original:
                print(
                    "completion audit is stale; run "
                    "python3 scripts/update-completion-audit.py",
                    file=sys.stderr,
                )
                return 1
            print("completion audit is current")
            return 0
        atomic_write_text(AUDIT, updated, max_bytes=MAX_AUDIT_BYTES)
        print(f"updated {AUDIT.relative_to(ROOT)}")
        return 0
    except (CompletionAuditError, ExecutionBoundaryError, OSError, ValueError) as error:
        print(f"completion audit failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
