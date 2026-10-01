#!/usr/bin/env python3
"""Bounded controller for the fresh, workflow-dispatch release recovery run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tomllib
from typing import Any

SCRIPT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SCRIPT_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import ci_runtime  # noqa: E402


PREDICATE_TYPE = "https://github.com/penguin425/pcbex/attestations/release-source/v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TAG_RE = re.compile(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)$")
RUST_TOOLCHAIN_RE = re.compile(r"^1\.[0-9]{1,3}\.[0-9]{1,3}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ARCHIVE_LIMIT = 128 * 1024 * 1024
PREDICATE_LIMIT = 64 * 1024
GH_JSON_LIMIT = 8 * 1024 * 1024
COMMAND_DEADLINE_SECONDS = 120
TARGETS = (
    ("x86_64-unknown-linux-gnu", "tar.gz"),
    ("x86_64-apple-darwin", "tar.gz"),
    ("aarch64-apple-darwin", "tar.gz"),
    ("x86_64-pc-windows-msvc", "zip"),
)


class RecoveryError(RuntimeError):
    """A recovery invariant failed closed."""


def _sha(value: str, name: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise RecoveryError(f"{name} must be exactly 40 lowercase hexadecimal characters")
    return value


def _tag(value: str) -> str:
    if not isinstance(value, str) or TAG_RE.fullmatch(value) is None:
        raise RecoveryError("tag must match vX.Y.Z")
    return value


def _repository(value: str) -> str:
    if not isinstance(value, str) or REPOSITORY_RE.fullmatch(value) is None:
        raise RecoveryError("repository must be OWNER/REPO")
    return value


def _rust_toolchain(value: str) -> str:
    if not isinstance(value, str) or len(value) > 32 or RUST_TOOLCHAIN_RE.fullmatch(value) is None:
        raise RecoveryError("rust-toolchain must be an explicit stable 1.x.y version")
    return value


def _deadline() -> ci_runtime.Deadline:
    return ci_runtime.Deadline.start(COMMAND_DEADLINE_SECONDS)


def _run(argv: list[str], deadline: ci_runtime.Deadline, *, limit: int = 64 * 1024) -> str:
    result = ci_runtime.run(
        argv,
        cwd=Path.cwd(),
        timeout_seconds=deadline.remaining(30),
        max_stdout_bytes=limit,
        max_stderr_bytes=64 * 1024,
        deadline=deadline,
    )
    if result.returncode != 0:
        detail = ci_runtime.decode_utf8(result.stderr, role="command stderr").strip()
        raise RecoveryError(f"command failed: {' '.join(argv)}{': ' + detail if detail else ''}")
    return ci_runtime.decode_utf8(result.stdout, role="command stdout").strip()


def _json_command(argv: list[str], deadline: ci_runtime.Deadline) -> Any:
    text = _run(argv, deadline, limit=GH_JSON_LIMIT)
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise RecoveryError("command returned invalid JSON") from error


def _versions(cargo_text: str, python_text: str) -> tuple[str, str]:
    try:
        cargo = tomllib.loads(cargo_text)
        python = tomllib.loads(python_text)
        cargo_version = cargo["workspace"]["package"]["version"]
        python_version = python["project"]["version"]
    except (KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        raise RecoveryError("release version metadata is invalid") from error
    if not isinstance(cargo_version, str) or not isinstance(python_version, str):
        raise RecoveryError("release versions must be strings")
    return cargo_version, python_version


def resolve(args: argparse.Namespace) -> None:
    repository = _repository(args.repository)
    tag = _tag(args.tag)
    expected_sha = _sha(args.expected_sha, "expected-sha")
    tag_object = _sha(args.expected_tag_object, "expected-tag-object")
    rust_toolchain = _rust_toolchain(args.rust_toolchain)
    workflow_sha = _sha(os.environ.get("GITHUB_SHA", ""), "GITHUB_SHA")
    if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise RecoveryError("resolve requires workflow_dispatch")
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise RecoveryError("resolve requires refs/heads/main")
    deadline = _deadline()
    if _run(["git", "rev-parse", "--verify", "HEAD"], deadline) != workflow_sha:
        raise RecoveryError("controller checkout HEAD does not match GITHUB_SHA")
    ref = f"refs/tags/{tag}"
    if _run(["git", "rev-parse", "--verify", f"{ref}^{{tag}}"], deadline) != tag_object:
        raise RecoveryError("annotated tag object does not match expected-tag-object")
    if _run(["git", "rev-parse", "--verify", f"{ref}^{{}}"], deadline) != expected_sha:
        raise RecoveryError("tag does not point to expected-sha")
    _run(["git", "merge-base", "--is-ancestor", expected_sha, "refs/remotes/origin/main"], deadline)
    cargo = _run(["git", "show", f"{expected_sha}:Cargo.toml"], deadline)
    python = _run(["git", "show", f"{expected_sha}:agent/pyproject.toml"], deadline)
    cargo_version, python_version = _versions(cargo, python)
    if cargo_version != python_version or tag != f"v{cargo_version}":
        raise RecoveryError("tag and Cargo/Python versions do not agree")
    # These are the only values intended for GITHUB_OUTPUT.
    print(f"tag={tag}\nsha={expected_sha}\ntag_object={tag_object}\nrust_toolchain={rust_toolchain}")


def check_remote(args: argparse.Namespace) -> None:
    repository = _repository(args.repository)
    tag = _tag(args.tag)
    expected_sha = _sha(args.expected_sha, "expected-sha")
    expected_tag_object = _sha(args.expected_tag_object, "expected-tag-object")
    deadline = _deadline()
    ref = _json_command(["gh", "api", f"repos/{repository}/git/ref/tags/{tag}"], deadline)
    if not isinstance(ref, dict) or ref.get("ref") != f"refs/tags/{tag}":
        raise RecoveryError("remote tag ref response is invalid")
    obj = ref.get("object")
    if not isinstance(obj, dict) or obj.get("type") != "tag" or obj.get("sha") != expected_tag_object:
        raise RecoveryError("remote tag ref is not the expected annotated tag object")
    tag_data = _json_command(["gh", "api", f"repos/{repository}/git/tags/{expected_tag_object}"], deadline)
    remote_obj = tag_data.get("object") if isinstance(tag_data, dict) else None
    if not isinstance(remote_obj, dict) or remote_obj.get("type") != "commit" or remote_obj.get("sha") != expected_sha:
        raise RecoveryError("remote annotated tag does not point to expected-sha")
    print(f"tag={tag}\nsha={expected_sha}\ntag_object={expected_tag_object}")


def _archive_path(raw: str, tag: str) -> Path:
    try:
        path = ci_runtime.validate_relative_input_file(raw, base=Path.cwd())
    except ci_runtime.ExecutionBoundaryError as error:
        raise RecoveryError(str(error)) from error
    names = {f"pcbex-{tag}-{target}.{extension}" for target, extension in TARGETS}
    if path.name not in names:
        raise RecoveryError("archive filename is not a release archive")
    return path


def _output_path(raw: str) -> Path:
    if not isinstance(raw, str) or not raw:
        raise RecoveryError("output path is required")
    try:
        return ci_runtime.validate_relative_output_root(raw, base=Path.cwd())
    except ci_runtime.ExecutionBoundaryError as error:
        raise RecoveryError(str(error)) from error


def predicate(args: argparse.Namespace) -> None:
    repository = _repository(args.repository)
    tag = _tag(args.tag)
    source_sha = _sha(args.expected_sha, "expected-sha")
    tag_object = _sha(args.expected_tag_object, "expected-tag-object")
    workflow_sha = _sha(args.workflow_sha, "workflow-sha")
    rust_toolchain = _rust_toolchain(args.rust_toolchain)
    if isinstance(args.run_id, bool) or not isinstance(args.run_id, int) or args.run_id <= 0:
        raise RecoveryError("run-id must be a positive integer")
    if isinstance(args.run_attempt, bool) or not isinstance(args.run_attempt, int) or args.run_attempt <= 0:
        raise RecoveryError("run-attempt must be a positive integer")
    archive = _archive_path(args.archive, tag)
    data = ci_runtime.read_bytes(archive, max_bytes=ARCHIVE_LIMIT)
    archive_sha = hashlib.sha256(data).hexdigest()
    output = _output_path(args.output)
    document = {
        "archive_name": archive.name,
        "archive_sha256": archive_sha,
        "repository": repository,
        "run_attempt": args.run_attempt,
        "run_id": args.run_id,
        "schema_version": 1,
        "source_sha": source_sha,
        "tag": tag,
        "tag_object": tag_object,
        "workflow_sha": workflow_sha,
        "rust_toolchain": rust_toolchain,
    }
    payload = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    try:
        ci_runtime.atomic_write_text(output, payload, max_bytes=PREDICATE_LIMIT)
    except ci_runtime.BoundedIOError as error:
        raise RecoveryError(str(error)) from error


def _strict_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            _strict_equal(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _strict_equal(item, value) for item, value in zip(actual, expected)
        )
    return actual == expected


def verify(args: argparse.Namespace) -> None:
    repository = _repository(args.repository)
    tag = _tag(args.tag)
    expected_sha = _sha(args.expected_sha, "expected-sha")
    expected_tag_object = _sha(args.expected_tag_object, "expected-tag-object")
    workflow_sha = _sha(args.workflow_sha, "workflow-sha")
    rust_toolchain = _rust_toolchain(args.rust_toolchain)
    if isinstance(args.run_id, bool) or not isinstance(args.run_id, int) or args.run_id <= 0:
        raise RecoveryError("run-id must be a positive integer")
    if isinstance(args.run_attempt, bool) or not isinstance(args.run_attempt, int) or args.run_attempt <= 0:
        raise RecoveryError("run-attempt must be a positive integer")
    archive = _archive_path(args.archive, tag)
    archive_sha = hashlib.sha256(ci_runtime.read_bytes(archive, max_bytes=ARCHIVE_LIMIT)).hexdigest()
    deadline = _deadline()
    cert_identity = f"https://github.com/{repository}/.github/workflows/release-recovery.yml@refs/heads/main"
    result = _json_command(
        [
            "gh", "attestation", "verify", str(archive), "--repo", repository,
            "--predicate-type", PREDICATE_TYPE,
            "--signer-digest", workflow_sha, "--source-digest", workflow_sha,
            "--source-ref", "refs/heads/main", "--cert-identity", cert_identity,
            "--deny-self-hosted-runners", "--limit", "30", "--format", "json",
        ],
        deadline,
    )
    expected = {
        "archive_name": archive.name,
        "archive_sha256": archive_sha,
        "repository": repository,
        "run_attempt": args.run_attempt,
        "run_id": args.run_id,
        "schema_version": 1,
        "source_sha": expected_sha,
        "tag": tag,
        "tag_object": expected_tag_object,
        "workflow_sha": workflow_sha,
        "rust_toolchain": rust_toolchain,
    }
    if not isinstance(result, list) or not 1 <= len(result) <= 30:
        raise RecoveryError("attestation verifier returned an invalid result list")
    for item in result:
        if not isinstance(item, dict) or not isinstance(item.get("verificationResult"), dict):
            continue
        verification_result = item["verificationResult"]
        statement = verification_result.get("statement")
        if not isinstance(statement, dict) or statement.get("predicateType") != PREDICATE_TYPE:
            continue
        if not _strict_equal(statement.get("predicate"), expected):
            continue
        subjects = statement.get("subject")
        if not isinstance(subjects, list):
            continue
        if any(
            isinstance(subject, dict)
            and subject.get("name") == archive.name
            and isinstance(subject.get("digest"), dict)
            and type(subject["digest"].get("sha256")) is str
            and subject["digest"].get("sha256") == archive_sha
            for subject in subjects
        ):
            return
    raise RecoveryError("no cryptographically verified matching release predicate was found")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("resolve", "check-remote"):
        command = sub.add_parser(name)
        _common(command)
        if name == "resolve":
            command.add_argument("--rust-toolchain", required=True)
        if name == "resolve":
            continue
    command = sub.add_parser("predicate")
    _common(command)
    command.add_argument("--archive", required=True)
    command.add_argument("--output", required=True)
    command.add_argument("--workflow-sha", required=True)
    command.add_argument("--rust-toolchain", required=True)
    command.add_argument("--run-id", required=True, type=int)
    command.add_argument("--run-attempt", required=True, type=int)
    command = sub.add_parser("verify")
    _common(command)
    command.add_argument("--archive", required=True)
    command.add_argument("--workflow-sha", required=True)
    command.add_argument("--rust-toolchain", required=True)
    command.add_argument("--run-id", required=True, type=int)
    command.add_argument("--run-attempt", required=True, type=int)
    return parser


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--expected-tag-object", required=True)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        {"resolve": resolve, "check-remote": check_remote, "predicate": predicate, "verify": verify}[args.command](args)
    except (RecoveryError, ci_runtime.ExecutionBoundaryError, ci_runtime.BoundedIOError) as error:
        print(f"release recovery failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
