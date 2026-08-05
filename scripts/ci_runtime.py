#!/usr/bin/env python3
"""Shared bounded execution and filesystem checks for pcbex CI helpers.

The production Python agent already contains the cross-platform process-tree
supervisor and race-aware bounded file I/O used here.  This module is a small
repository-local facade so release scripts and the composite action can use
those primitives without requiring the agent package to be installed first.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import errno
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from collections.abc import Sequence
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
AGENT_SRC = ROOT / "agent" / "src"
if str(AGENT_SRC) not in sys.path:
    sys.path.insert(0, str(AGENT_SRC))

from pcbex_agent.bounded_io import (  # noqa: E402
    BoundedIOError,
    atomic_write_no_clobber,
    atomic_write_text,
    atomic_write_text_no_clobber,
    read_bytes,
    read_text,
)
from pcbex_agent.bounded_process import (  # noqa: E402
    BoundedProcessError,
    BoundedProcessResult,
    run_bounded,
)


MIB = 1024 * 1024
DEFAULT_TREE_ENTRIES = 4096
DEFAULT_TREE_DEPTH = 16
DEFAULT_FILE_BYTES = 128 * MIB
DEFAULT_TREE_BYTES = 512 * MIB
DEFAULT_STDOUT_BYTES = 16 * MIB
DEFAULT_STDERR_BYTES = 4 * MIB
PORTABLE_OUTPUT_COMPONENT = re.compile(r"^[A-Za-z0-9._-]+$")
ARTIFACT_GLOB_SYNTAX = re.compile(r"[*?\[\]{}]|(?:^|/)!|[+@!]\(")


class ExecutionBoundaryError(RuntimeError):
    """A CI deadline, byte ceiling, or filesystem boundary was crossed."""


@dataclass(frozen=True)
class Deadline:
    """One monotonic deadline shared by a sequence of child processes."""

    expires_at: float

    @classmethod
    def start(cls, seconds: float) -> "Deadline":
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise ExecutionBoundaryError("deadline must be a finite positive number")
        value = float(seconds)
        if not math.isfinite(value) or value <= 0:
            raise ExecutionBoundaryError("deadline must be a finite positive number")
        return cls(time.monotonic() + value)

    def remaining(self, per_call_seconds: float | None = None) -> float:
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0:
            raise ExecutionBoundaryError("aggregate execution deadline expired")
        if per_call_seconds is None:
            return remaining
        if (
            isinstance(per_call_seconds, bool)
            or not isinstance(per_call_seconds, (int, float))
            or not math.isfinite(float(per_call_seconds))
            or per_call_seconds <= 0
        ):
            raise ExecutionBoundaryError("per-call timeout must be finite and positive")
        return min(remaining, float(per_call_seconds))


@dataclass(frozen=True)
class TreeUsage:
    """Measured usage for one validated output tree."""

    entries: int
    files: int
    bytes: int
    maximum_depth: int


def run(
    argv: Sequence[str],
    *,
    input_bytes: bytes | bytearray | memoryview | None = None,
    cwd: str | os.PathLike[str] | None = ROOT,
    timeout_seconds: float = 300,
    max_stdin_bytes: int = 32 * MIB,
    max_stdout_bytes: int = DEFAULT_STDOUT_BYTES,
    max_stderr_bytes: int = DEFAULT_STDERR_BYTES,
    deadline: Deadline | None = None,
    env: dict[str, str] | None = None,
) -> BoundedProcessResult:
    """Run one shell-free command under independent and aggregate limits."""

    effective_timeout = (
        deadline.remaining(timeout_seconds) if deadline is not None else timeout_seconds
    )
    try:
        return run_bounded(
            argv,
            input_bytes=input_bytes,
            max_stdin_bytes=max_stdin_bytes,
            timeout_seconds=effective_timeout,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            cwd=cwd,
            env=env,
        )
    except BoundedProcessError as error:
        raise ExecutionBoundaryError(str(error)) from error


def decode_utf8(payload: bytes, *, role: str) -> str:
    """Decode command/API data strictly so malformed text fails closed."""

    try:
        return payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ExecutionBoundaryError(f"{role} is not valid UTF-8") from error


def read_response_bytes(response: Any, *, max_bytes: int) -> bytes:
    """Read at most ``max_bytes`` from an HTTP response-like object."""

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise ExecutionBoundaryError("HTTP response limit must be a non-negative integer")
    headers = getattr(response, "headers", None)
    content_length = None if headers is None else headers.get("Content-Length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except (TypeError, ValueError) as error:
            raise ExecutionBoundaryError("HTTP Content-Length is invalid") from error
        if declared < 0:
            raise ExecutionBoundaryError("HTTP Content-Length is invalid")
        if declared > max_bytes:
            raise ExecutionBoundaryError(
                f"HTTP response exceeds limit of {max_bytes} bytes"
            )
    payload = response.read(max_bytes + 1)
    if not isinstance(payload, bytes):
        raise ExecutionBoundaryError("HTTP response did not return bytes")
    if len(payload) > max_bytes:
        raise ExecutionBoundaryError(
            f"HTTP response exceeds limit of {max_bytes} bytes"
        )
    return payload


def append_text(
    path: str | os.PathLike[str], contents: str, *, max_bytes: int
) -> None:
    """Append UTF-8 text to one existing regular file under a total ceiling."""

    if not isinstance(contents, str):
        raise ExecutionBoundaryError("appended contents must be text")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ExecutionBoundaryError("append limit must be a positive integer")
    try:
        encoded = contents.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ExecutionBoundaryError("appended contents are not valid UTF-8") from error
    destination = Path(path)
    try:
        existing = read_bytes(destination, max_bytes=max_bytes)
        expected = os.lstat(destination)
    except BoundedIOError as error:
        if error.errno != errno.ENOENT:
            raise ExecutionBoundaryError(str(error)) from error
        try:
            atomic_write_text_no_clobber(
                destination, contents, max_bytes=max_bytes
            )
            return
        except BoundedIOError as create_error:
            if create_error.errno != errno.EEXIST:
                raise ExecutionBoundaryError(str(create_error)) from create_error
            try:
                existing = read_bytes(destination, max_bytes=max_bytes)
                expected = os.lstat(destination)
            except (BoundedIOError, OSError) as retry_error:
                raise ExecutionBoundaryError(str(retry_error)) from retry_error
    except OSError as error:
        raise ExecutionBoundaryError(str(error)) from error
    if len(existing) + len(encoded) > max_bytes:
        raise ExecutionBoundaryError(
            f"appended file exceeds limit of {max_bytes} bytes: {destination}"
        )

    flags = _append_open_flags()
    try:
        descriptor = os.open(destination, flags)
    except OSError as error:
        raise ExecutionBoundaryError(f"could not open append output: {destination}") from error
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(destination)
        identity = lambda value: (value.st_dev, value.st_ino)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_point(opened)
            or identity(expected) != identity(opened)
            or identity(expected) != identity(current)
            or opened.st_size != len(existing)
            or current.st_size != len(existing)
        ):
            raise ExecutionBoundaryError(
                f"append output changed while being opened: {destination}"
            )
        view = memoryview(encoded)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise ExecutionBoundaryError(
                    f"append output made no progress: {destination}"
                )
            offset += written
        os.fsync(descriptor)
        final_descriptor = os.fstat(descriptor)
        final_path = os.lstat(destination)
        expected_size = len(existing) + len(encoded)
        if (
            identity(opened) != identity(final_descriptor)
            or identity(opened) != identity(final_path)
            or final_descriptor.st_size != expected_size
            or final_path.st_size != expected_size
        ):
            raise ExecutionBoundaryError(
                f"append output changed while being written: {destination}"
            )
    except OSError as error:
        raise ExecutionBoundaryError(f"could not append output: {destination}") from error
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _append_open_flags() -> int:
    """Return binary, append-only, no-follow flags for GitHub output files."""

    return (
        os.O_WRONLY
        | os.O_APPEND
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0) or 0
    return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def _reject_link(metadata: os.stat_result, path: Path) -> None:
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        raise ExecutionBoundaryError(f"output tree contains a link: {path}")


def _inspect_path_without_links(path: Path) -> os.stat_result:
    """Inspect every existing lexical component and reject link traversal."""

    if ".." in path.parts:
        raise ExecutionBoundaryError(f"path must not contain parent traversal: {path}")
    current = Path(path.anchor) if path.anchor else Path(".")
    components = path.parts
    for index, part in enumerate(components):
        if part in ("", ".", path.anchor):
            continue
        current = current / part
        try:
            metadata = os.lstat(current)
        except OSError as error:
            raise ExecutionBoundaryError(f"could not inspect path: {path}") from error
        _reject_link(metadata, current)
        if index < len(components) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise ExecutionBoundaryError(
                f"path ancestor is not a directory: {current}"
            )
    try:
        return os.lstat(path)
    except OSError as error:
        raise ExecutionBoundaryError(f"could not inspect path: {path}") from error


def validate_relative_output_root(
    value: str | os.PathLike[str], *, base: Path | None = None
) -> Path:
    """Validate an action output path as a portable workspace-relative path."""

    raw = os.fspath(value)
    if not raw or "\x00" in raw:
        raise ExecutionBoundaryError("output root must not be empty or contain NUL")
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        raise ExecutionBoundaryError("output root must not contain control characters")
    if "\\" in raw or ":" in raw:
        raise ExecutionBoundaryError("output root must use portable relative path syntax")
    raw_components = raw.split("/")
    if any(part in ("", ".", "..") for part in raw_components):
        raise ExecutionBoundaryError("output root must not contain dot traversal")
    relative = Path(raw)
    if relative.is_absolute() or relative in (Path("."), Path("..")):
        raise ExecutionBoundaryError("output root must be relative to the workspace")
    if any(part in ("", ".", "..") for part in relative.parts):
        raise ExecutionBoundaryError("output root must not contain dot traversal")

    workspace = Path.cwd() if base is None else Path(base)
    workspace_metadata = _inspect_path_without_links(workspace)
    if not stat.S_ISDIR(workspace_metadata.st_mode):
        raise ExecutionBoundaryError(
            f"output root base is not a directory: {workspace}"
        )
    current = workspace
    for part in relative.parts:
        current = current / part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            break
        except OSError as error:
            raise ExecutionBoundaryError(f"could not inspect output root: {current}") from error
        _reject_link(metadata, current)
        if current != workspace / relative and not stat.S_ISDIR(metadata.st_mode):
            raise ExecutionBoundaryError(
                f"output root ancestor is not a directory: {current}"
            )
    return workspace / relative


def validate_literal_relative_output_root(
    value: str | os.PathLike[str], *, base: Path | None = None
) -> Path:
    """Validate a glob-safe literal output root for artifact publication."""

    path = validate_relative_output_root(value, base=base)
    raw_components = os.fspath(value).split("/")
    if any(PORTABLE_OUTPUT_COMPONENT.fullmatch(part) is None for part in raw_components):
        raise ExecutionBoundaryError(
            "literal output root components may contain only ASCII letters, digits, dot, underscore, and hyphen"
        )
    return path


def validate_artifact_relative_output_root(
    value: str | os.PathLike[str], *, base: Path | None = None
) -> Path:
    """Validate a relative output root without changing legacy space handling.

    ``upload-artifact`` treats its ``path`` input as a glob. The root Action
    historically accepted spaces and other ordinary filename characters, so
    preserve those while refusing syntax that could make upload escape the
    tree which was just scanned.
    """

    path = validate_relative_output_root(value, base=base)
    raw = os.fspath(value)
    if ARTIFACT_GLOB_SYNTAX.search(raw) is not None:
        raise ExecutionBoundaryError(
            "output root must not contain artifact glob syntax"
        )
    return path


def validate_relative_input_file(
    value: str | os.PathLike[str], *, base: Path | None = None
) -> Path:
    """Validate one caller-workspace-relative regular input without links."""

    raw = os.fspath(value)
    if not raw or "\x00" in raw:
        raise ExecutionBoundaryError("input path must not be empty or contain NUL")
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        raise ExecutionBoundaryError("input path must not contain control characters")
    if "\\" in raw or ":" in raw:
        raise ExecutionBoundaryError("input path must use portable relative path syntax")
    raw_components = raw.split("/")
    if any(part in ("", ".", "..") for part in raw_components):
        raise ExecutionBoundaryError("input path must not contain dot traversal")
    relative = Path(raw)
    if relative.is_absolute() or relative in (Path("."), Path("..")):
        raise ExecutionBoundaryError("input path must be relative to the workspace")
    if any(part in ("", ".", "..") for part in relative.parts):
        raise ExecutionBoundaryError("input path must not contain dot traversal")

    workspace = Path.cwd() if base is None else Path(base)
    workspace_metadata = _inspect_path_without_links(workspace)
    if not stat.S_ISDIR(workspace_metadata.st_mode):
        raise ExecutionBoundaryError(f"input path base is not a directory: {workspace}")
    path = workspace / relative
    metadata = _inspect_path_without_links(path)
    if not stat.S_ISREG(metadata.st_mode):
        raise ExecutionBoundaryError(f"input path is not a regular file: {path}")
    return path


def scan_tree(
    root: str | os.PathLike[str],
    *,
    max_entries: int = DEFAULT_TREE_ENTRIES,
    max_depth: int = DEFAULT_TREE_DEPTH,
    max_file_bytes: int = DEFAULT_FILE_BYTES,
    max_total_bytes: int = DEFAULT_TREE_BYTES,
) -> TreeUsage:
    """Validate and account for a regular-file-only output tree.

    File contents are read through the shared bounded I/O primitive.  This
    verifies descriptor/path identity and catches growth or replacement during
    the scan instead of trusting directory metadata alone.
    """

    limits = (max_entries, max_depth, max_file_bytes, max_total_bytes)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in limits):
        raise ExecutionBoundaryError("tree limits must be non-negative integers")
    path = Path(root)
    root_metadata = _inspect_path_without_links(path)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ExecutionBoundaryError(f"output tree root is not a directory: {path}")

    entries = files = total_bytes = maximum_depth = 0
    pending: list[tuple[Path, int]] = [(path, 0)]
    while pending:
        directory, parent_depth = pending.pop()
        try:
            iterator = os.scandir(directory)
        except OSError as error:
            raise ExecutionBoundaryError(
                f"could not enumerate output tree: {directory}"
            ) from error
        children: list[os.DirEntry[str]] = []
        with iterator:
            for child in iterator:
                entries += 1
                if entries > max_entries:
                    raise ExecutionBoundaryError(
                        f"output tree exceeds {max_entries} entries"
                    )
                children.append(child)
        children.sort(key=lambda entry: entry.name)
        for child in children:
            depth = parent_depth + 1
            maximum_depth = max(maximum_depth, depth)
            if depth > max_depth:
                raise ExecutionBoundaryError(
                    f"output tree exceeds depth limit of {max_depth}: {child.path}"
                )
            child_path = Path(child.path)
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                raise ExecutionBoundaryError(
                    f"could not inspect output entry: {child_path}"
                ) from error
            _reject_link(metadata, child_path)
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((child_path, depth))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ExecutionBoundaryError(
                    f"output tree entry is not a regular file: {child_path}"
                )
            if metadata.st_size > max_file_bytes:
                raise ExecutionBoundaryError(
                    f"output file exceeds {max_file_bytes} bytes: {child_path}"
                )
            if total_bytes + metadata.st_size > max_total_bytes:
                raise ExecutionBoundaryError(
                    f"output tree exceeds {max_total_bytes} aggregate bytes"
                )
            try:
                payload = read_bytes(child_path, max_bytes=max_file_bytes)
            except (BoundedIOError, OSError) as error:
                raise ExecutionBoundaryError(str(error)) from error
            total_bytes += len(payload)
            files += 1

    return TreeUsage(entries, files, total_bytes, maximum_depth)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)

    execute = subparsers.add_parser("exec", help="run one bounded command")
    execute.add_argument("--timeout-seconds", type=float, required=True)
    execute.add_argument(
        "--max-stdout-bytes", type=_positive_int, default=DEFAULT_STDOUT_BYTES
    )
    execute.add_argument(
        "--max-stderr-bytes", type=_positive_int, default=DEFAULT_STDERR_BYTES
    )
    execute.add_argument("--output-root")
    execute.add_argument("command", nargs=argparse.REMAINDER)

    scan = subparsers.add_parser("scan", help="validate one bounded output tree")
    scan.add_argument("--output-root", required=True)
    scan.add_argument("--max-entries", type=_positive_int, default=DEFAULT_TREE_ENTRIES)
    scan.add_argument("--max-depth", type=_positive_int, default=DEFAULT_TREE_DEPTH)
    scan.add_argument("--max-file-bytes", type=_positive_int, default=DEFAULT_FILE_BYTES)
    scan.add_argument("--max-total-bytes", type=_positive_int, default=DEFAULT_TREE_BYTES)

    validate_input = subparsers.add_parser(
        "validate-input", help="validate one workspace-relative regular input"
    )
    validate_input.add_argument("--path", required=True)

    validate_output = subparsers.add_parser(
        "validate-output", help="validate one literal workspace-relative output root"
    )
    validate_output.add_argument("--output-root", required=True)
    return parser


def _scan_cli(args: argparse.Namespace) -> TreeUsage:
    root = validate_relative_output_root(args.output_root)
    return scan_tree(
        root,
        max_entries=getattr(args, "max_entries", DEFAULT_TREE_ENTRIES),
        max_depth=getattr(args, "max_depth", DEFAULT_TREE_DEPTH),
        max_file_bytes=getattr(args, "max_file_bytes", DEFAULT_FILE_BYTES),
        max_total_bytes=getattr(args, "max_total_bytes", DEFAULT_TREE_BYTES),
    )


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.operation == "validate-input":
            validate_relative_input_file(args.path)
            print("workspace-relative input passed")
            return 0
        if args.operation == "validate-output":
            validate_literal_relative_output_root(args.output_root)
            print("literal workspace-relative output root passed")
            return 0
        if args.operation == "scan":
            usage = _scan_cli(args)
            print(
                "bounded output tree passed: "
                f"{usage.entries} entries, {usage.files} files, {usage.bytes} bytes"
            )
            return 0

        command = list(args.command)
        if command[:1] == ["--"]:
            command = command[1:]
        if not command:
            raise ExecutionBoundaryError("bounded command must not be empty")
        output_root = (
            validate_relative_output_root(args.output_root)
            if args.output_root is not None
            else None
        )
        result = run(
            command,
            cwd=Path.cwd(),
            timeout_seconds=args.timeout_seconds,
            max_stdout_bytes=args.max_stdout_bytes,
            max_stderr_bytes=args.max_stderr_bytes,
        )
        sys.stdout.buffer.write(result.stdout)
        sys.stdout.buffer.flush()
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
        if output_root is not None:
            scan_tree(output_root)
        return result.returncode
    except (ExecutionBoundaryError, BoundedIOError, OSError) as error:
        print(f"CI execution boundary failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
