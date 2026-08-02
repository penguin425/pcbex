#!/usr/bin/env python3
"""Stage a pull-request analysis comment and its immutable run binding.

This is the trust-boundary hand-off between an untrusted pull-request job and
the trusted comment publisher.  It intentionally accepts only the event
payload, the generated Markdown, and a small set of workflow identifiers.  A
successful invocation publishes a *new* directory containing exactly two
regular files; an existing destination is never overwritten.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = 1
BODY_FILE_NAME = "pr-comment.md"
BINDING_FILE_NAME = "binding.json"
# Leave room for the trusted publisher's visible provenance banner while
# staying below GitHub's 65,536-character comment limit.
MAX_BODY_CHARS = 60_000
MAX_BODY_BYTES = 262_144
MAX_EVENT_BYTES = 1_048_576
MAX_NAME_LENGTH = 255
MAX_PATH_LENGTH = 512
MAX_RUN_DIGITS = 20

REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_RE = re.compile(r"^[1-9][0-9]{0,19}$")
COMMENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

EXPECTED_BINDING_KEYS = frozenset(
    {
        "schema_version",
        "repository",
        "repository_id",
        "workflow_name",
        "workflow_path",
        "run_id",
        "run_attempt",
        "pr_number",
        "head_sha",
        "head_ref",
        "head_repository",
        "head_repository_id",
        "base_sha",
        "base_ref",
        "base_repository",
        "base_repository_id",
        "comment_id",
        "body_path",
        "body_bytes",
        "body_sha256",
    }
)


class StageError(ValueError):
    """An invalid event/input or an unsafe staging destination."""


class _DuplicateKeyError(ValueError):
    """Internal marker for duplicate JSON object members."""


def _error(message: str) -> StageError:
    return StageError(message)


def _reject_symlink_components(path: Path, label: str) -> None:
    """Reject symlinks in every existing component of ``path``.

    Checking the direct source/destination is not enough: a symlinked parent
    could redirect a supposedly private staging directory.  Missing final
    components are allowed so a new destination can be created safely.
    """

    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor) if absolute.anchor else Path()
    for component in absolute.parts[1:] if absolute.is_absolute() else absolute.parts:
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as failure:
            raise _error(f"unable to inspect {label} path component {current}: {failure}")
        if stat.S_ISLNK(metadata.st_mode):
            raise _error(f"{label} path contains a symlink component: {current}")


def _reject_lexical_dot_components(path: Path | str, label: str) -> None:
    """Reject explicit ``.``/``..`` path components before normalization."""

    raw = os.fspath(path)
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    # A workflow output path is deliberately platform-neutral.  Inspect both
    # separators so a Windows-style traversal cannot pass on a POSIX runner.
    components = re.split(r"[/\\]", raw)
    if any(component in {".", ".."} for component in components):
        raise _error(f"{label} path must not contain '.' or '..' components")


def _read_regular(path: Path, label: str, maximum: int) -> bytes:
    """Read a bounded regular file while checking for replacement races."""

    _reject_symlink_components(path, label)
    try:
        before = os.lstat(path)
    except OSError as failure:
        raise _error(f"unable to inspect {label} {path}: {failure}") from failure
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise _error(f"{label} must be a regular non-symlink file: {path}")
    if before.st_size <= 0 or before.st_size > maximum:
        raise _error(f"{label} must contain 1..={maximum} bytes: {path}")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as failure:
        raise _error(f"unable to open {label} {path}: {failure}") from failure
    try:
        opened = os.fstat(descriptor)
        if not _same_file(before, opened) or opened.st_size != before.st_size:
            raise _error(f"{label} changed while it was opened: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise _error(f"{label} exceeds {maximum} bytes: {path}")
        after = os.fstat(descriptor)
        if not _same_file(opened, after) or after.st_size != before.st_size:
            raise _error(f"{label} changed while it was read: {path}")
        data = b"".join(chunks)
        if len(data) != before.st_size:
            raise _error(f"{label} changed while it was read: {path}")
        return data
    finally:
        os.close(descriptor)


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    if hasattr(left, "st_dev") and hasattr(left, "st_ino"):
        return left.st_dev == right.st_dev and left.st_ino == right.st_ino
    return True


def _string(value: Any, label: str, *, maximum: int = MAX_NAME_LENGTH) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _error(f"{label} must be a non-blank string")
    if len(value) > maximum:
        raise _error(f"{label} exceeds {maximum} characters")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise _error(f"{label} contains a control character")
    return value


def _repository(value: Any, label: str) -> str:
    value = _string(value, label)
    if not REPOSITORY_RE.fullmatch(value):
        raise _error(f"{label} must use owner/name form")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        raise _error(f"{label} must be a lowercase 40-character SHA-1")
    return value


def _ref(value: Any, label: str) -> str:
    value = _string(value, label, maximum=MAX_PATH_LENGTH)
    # Git's check-ref-format restrictions relevant to a PR branch name.  Keep
    # the accepted language deliberately smaller than GitHub's full ref set:
    # this value is persisted into a trusted binding and is never a path.
    if (
        value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or ".." in value
        or "@{" in value
        or any(character in value for character in ("\\", "~", "^", ":", "?", "*", "["))
        or any(character.isspace() for character in value)
    ):
        raise _error(f"{label} is not a safe Git ref")
    return value


def _positive_run(value: str, label: str) -> int:
    if not isinstance(value, str) or not RUN_RE.fullmatch(value):
        raise _error(f"{label} must be a positive decimal integer")
    if len(value) > MAX_RUN_DIGITS:
        raise _error(f"{label} is too large")
    return int(value)


def _positive_number(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise _error(f"{label} must be a positive integer")
    if value > 2**63 - 1:
        raise _error(f"{label} is too large")
    return value


def _workflow_path(value: str) -> str:
    value = _string(value, "workflow path", maximum=MAX_PATH_LENGTH)
    if (
        value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or not value.startswith(".github/workflows/")
        or not value.endswith((".yml", ".yaml"))
    ):
        raise _error("workflow path must be a relative .github/workflows/*.yml/.yaml path")
    return value


def _comment_id(value: str) -> str:
    if not isinstance(value, str) or not COMMENT_ID_RE.fullmatch(value):
        raise _error(
            "comment id must be 1-64 ASCII letters, digits, dots, underscores, "
            "or hyphens and start with a letter or digit"
        )
    return value


def _event_value(event: dict[str, Any], key: str) -> Any:
    value = event.get(key)
    if value is None:
        raise _error(f"pull-request event is missing {key}")
    return value


def _nested_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _error(f"{label} must be an object")
    return value


def _closed_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def build_binding(
    event: dict[str, Any],
    *,
    workflow_name: str,
    workflow_path: str,
    run_id: str,
    run_attempt: str,
    comment_id: str,
    body: bytes,
) -> dict[str, Any]:
    """Validate a GitHub pull-request event and construct closed schema v1."""

    if not isinstance(event, dict):
        raise _error("GitHub event must be a JSON object")
    if not isinstance(event.get("pull_request"), dict):
        raise _error("GitHub event must be a pull_request event")
    repository_object = _nested_object(_event_value(event, "repository"), "repository")
    repository = _repository(
        repository_object.get("full_name"),
        "repository.full_name",
    )
    repository_id = _positive_number(
        _event_value(repository_object, "id"), "repository.id"
    )
    pull_request = _nested_object(event["pull_request"], "pull_request")
    event_number = _positive_number(_event_value(event, "number"), "event.number")
    pr_number = _positive_number(
        _event_value(pull_request, "number"), "pull_request.number"
    )
    if event_number != pr_number:
        raise _error("event.number and pull_request.number do not match")

    head = _nested_object(_event_value(pull_request, "head"), "pull_request.head")
    base = _nested_object(_event_value(pull_request, "base"), "pull_request.base")
    head_repo = _nested_object(_event_value(head, "repo"), "pull_request.head.repo")
    base_repo = _nested_object(_event_value(base, "repo"), "pull_request.base.repo")
    head_repository = _repository(
        _event_value(head_repo, "full_name"), "pull_request.head.repo.full_name"
    )
    head_repository_id = _positive_number(
        _event_value(head_repo, "id"), "pull_request.head.repo.id"
    )
    base_repository = _repository(
        _event_value(base_repo, "full_name"), "pull_request.base.repo.full_name"
    )
    base_repository_id = _positive_number(
        _event_value(base_repo, "id"), "pull_request.base.repo.id"
    )
    if base_repository != repository or base_repository_id != repository_id:
        raise _error(
            "pull_request.base.repo identity must match repository identity"
        )

    workflow_name = _string(workflow_name, "workflow name")
    workflow_path = _workflow_path(workflow_path)
    parsed_run_id = _positive_run(run_id, "GITHUB_RUN_ID")
    parsed_run_attempt = _positive_run(run_attempt, "GITHUB_RUN_ATTEMPT")
    comment_id = _comment_id(comment_id)
    if not isinstance(body, bytes):
        raise _error("comment body must be bytes")
    if not body:
        raise _error("pull-request comment body must not be empty")
    if len(body) > MAX_BODY_BYTES:
        raise _error(f"pull-request comment body exceeds {MAX_BODY_BYTES} bytes")
    try:
        body_text = body.decode("utf-8")
    except UnicodeDecodeError as failure:
        raise _error("pull-request comment body must be valid UTF-8") from failure
    if not body_text.strip():
        raise _error("pull-request comment body must not be blank")
    if len(body_text) > MAX_BODY_CHARS:
        raise _error(f"pull-request comment body exceeds {MAX_BODY_CHARS} characters")

    return {
        "schema_version": SCHEMA_VERSION,
        "repository": repository,
        "repository_id": repository_id,
        "workflow_name": workflow_name,
        "workflow_path": workflow_path,
        "run_id": parsed_run_id,
        "run_attempt": parsed_run_attempt,
        "pr_number": pr_number,
        "head_sha": _sha(_event_value(head, "sha"), "pull_request.head.sha"),
        "head_ref": _ref(_event_value(head, "ref"), "pull_request.head.ref"),
        "head_repository": head_repository,
        "head_repository_id": head_repository_id,
        "base_sha": _sha(_event_value(base, "sha"), "pull_request.base.sha"),
        "base_ref": _ref(_event_value(base, "ref"), "pull_request.base.ref"),
        "base_repository": base_repository,
        "base_repository_id": base_repository_id,
        "comment_id": comment_id,
        "body_path": BODY_FILE_NAME,
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }


def _validate_binding_shape(binding: dict[str, Any]) -> None:
    if frozenset(binding) != EXPECTED_BINDING_KEYS:
        raise _error("internal binding does not match the closed schema")


def _json_bytes(value: dict[str, Any]) -> bytes:
    _validate_binding_shape(value)
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as failure:
        raise _error(f"unable to render binding JSON: {failure}") from failure
    return (rendered + "\n").encode("ascii")


def _write_new_file(directory: Path, name: str, data: bytes) -> None:
    path = directory / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as failure:
        raise _error(f"unable to create staged {name}: {failure}") from failure
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise _error(f"unable to write staged {name}")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as failure:
        raise _error(f"unable to write staged {name}: {failure}") from failure
    finally:
        os.close(descriptor)


def _assert_exact_stage(directory: Path) -> None:
    names: list[str] = []
    try:
        entries = list(directory.iterdir())
    except OSError as failure:
        raise _error(f"unable to inspect temporary stage: {failure}") from failure
    for entry in entries:
        try:
            metadata = os.lstat(entry)
        except OSError as failure:
            raise _error(f"unable to inspect temporary stage entry {entry}: {failure}") from failure
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise _error(f"temporary stage contains a non-regular entry: {entry}")
        names.append(entry.name)
    if sorted(names) != sorted((BINDING_FILE_NAME, BODY_FILE_NAME)):
        raise _error("temporary stage does not contain the exact two expected files")


def _fsync_directory(directory: Path) -> None:
    if not hasattr(os, "O_DIRECTORY"):
        return
    try:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def stage(
    *,
    event_path: Path | str,
    body_path: Path | str,
    output_dir: Path | str,
    workflow_name: str,
    workflow_path: str,
    comment_id: str,
    run_id: str,
    run_attempt: str,
    event_name: str | None = None,
) -> dict[str, Any]:
    """Validate and atomically publish an exact two-file staging directory."""

    event_path = Path(event_path)
    body_path = Path(body_path)
    event_name = os.environ.get("GITHUB_EVENT_NAME", "") if event_name is None else event_name
    if event_name != "pull_request":
        raise _error("GITHUB_EVENT_NAME must be exactly pull_request")
    event_bytes = _read_regular(event_path, "GitHub event", MAX_EVENT_BYTES)
    try:
        event = json.loads(
            event_bytes.decode("utf-8"), object_pairs_hook=_closed_json_pairs
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKeyError) as failure:
        raise _error(f"GitHub event must be valid UTF-8 JSON: {failure}") from failure
    body = _read_regular(body_path, "pull-request comment body", MAX_BODY_BYTES)
    binding = build_binding(
        event,
        workflow_name=workflow_name,
        workflow_path=workflow_path,
        run_id=run_id,
        run_attempt=run_attempt,
        comment_id=comment_id,
        body=body,
    )
    binding_bytes = _json_bytes(binding)

    _reject_lexical_dot_components(output_dir, "staging output")
    output_dir = Path(output_dir)
    _reject_symlink_components(output_dir, "staging output")
    if output_dir.name in {"", ".", ".."}:
        raise _error("staging output must name a new directory")
    try:
        existing = os.lstat(output_dir)
    except FileNotFoundError:
        existing = None
    except OSError as failure:
        raise _error(f"unable to inspect staging output {output_dir}: {failure}") from failure
    if existing is not None:
        if stat.S_ISLNK(existing.st_mode):
            raise _error(f"staging output must not be a symlink: {output_dir}")
        raise _error(f"refusing to overwrite existing staging output: {output_dir}")

    parent = output_dir.parent if output_dir.parent != Path("") else Path(".")
    _reject_symlink_components(parent, "staging output parent")
    try:
        parent_metadata = os.lstat(parent)
    except OSError as failure:
        raise _error(f"unable to inspect staging output parent {parent}: {failure}") from failure
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise _error(f"staging output parent must be a real directory: {parent}")

    temporary = Path(tempfile.mkdtemp(prefix=".pcbex-pr-comment-stage-", dir=parent))
    try:
        _write_new_file(temporary, BODY_FILE_NAME, body)
        _write_new_file(temporary, BINDING_FILE_NAME, binding_bytes)
        _assert_exact_stage(temporary)
        _fsync_directory(temporary)
        # ``rename`` publishes the already-verified directory atomically after
        # the no-clobber destination preflight.  The destination is a unique
        # per-run path owned by this invocation.
        try:
            os.rename(temporary, output_dir)
        except OSError as failure:
            raise _error(f"unable to atomically publish staging output: {failure}") from failure
        temporary = None  # type: ignore[assignment]
        _fsync_directory(parent)
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)
    return binding


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a pull_request event and pr-comment.md, then atomically "
            "publish exactly binding.json and pr-comment.md."
        )
    )
    parser.add_argument("--event", required=True, help="GITHUB_EVENT_PATH JSON")
    parser.add_argument("--body", required=True, help="generated pr-comment.md")
    parser.add_argument("--output-dir", required=True, help="new staging directory")
    parser.add_argument("--workflow-name", required=True, help="GITHUB_WORKFLOW")
    parser.add_argument("--workflow-path", required=True, help="workflow file path")
    parser.add_argument("--comment-id", required=True, help="stable publisher comment marker id")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        binding = stage(
            event_path=Path(args.event),
            body_path=Path(args.body),
            # Keep the raw spelling until ``stage`` has rejected lexical
            # ``.``/``..`` components; ``Path`` normalizes ``.`` away.
            output_dir=args.output_dir,
            workflow_name=args.workflow_name,
            workflow_path=args.workflow_path,
            comment_id=args.comment_id,
            run_id=os.environ.get("GITHUB_RUN_ID", ""),
            run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        )
    except (OSError, StageError) as failure:
        print(f"pcbex PR comment stage error: {failure}", file=sys.stderr)
        return 2
    print(
        f"staged pull-request comment binding for run {binding['run_id']}/"
        f"{binding['run_attempt']} in {args.output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
