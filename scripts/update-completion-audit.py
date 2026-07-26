#!/usr/bin/env python3
"""Update or verify the generated completion-audit summary."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "docs" / "COMPLETION_AUDIT.md"
START = "<!-- completion-audit:start -->"
END = "<!-- completion-audit:end -->"


def rust_test_count() -> int:
    result = subprocess.run(
        ["cargo", "test", "--workspace", "--locked", "--", "--list"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return sum(line.endswith(": test") for line in result.stdout.splitlines())


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
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
    version = workspace["workspace"]["package"]["version"]
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
        raise SystemExit(f"{AUDIT} does not contain generated audit markers")
    return pattern.sub(generated_block(), document)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail instead of writing when the generated summary is stale",
    )
    args = parser.parse_args()

    original = AUDIT.read_text()
    updated = updated_document(original)
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
    AUDIT.write_text(updated)
    print(f"updated {AUDIT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
