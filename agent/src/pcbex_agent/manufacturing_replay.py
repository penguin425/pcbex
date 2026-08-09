"""Fresh, byte-exact replay of one retained manufacturing package.

The replay adapter captures every caller-controlled input before executing
``pcbex fabricate`` in a private workspace.  It then requires the freshly
generated ``manufacturing.zip`` to equal the retained archive byte for byte
and re-reads both the staged copies and original caller sources.  Returned
evidence contains content identities only; caller paths, executable paths,
temporary paths, subprocess output, and artifact payloads are never exposed.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
import hashlib
import math
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import tempfile
import time
from typing import Any

from .bounded_io import BoundedIOError, atomic_write_no_clobber, read_bytes
from .bounded_process import BoundedProcessError, run_bounded


MANUFACTURING_REPLAY_RESULT_SCHEMA_VERSION = 1
MANUFACTURING_REPLAY_SCOPE = "manufacturing-package-fresh-replay-v1"

MAXIMUM_BOARD_BYTES = 128 * 1024 * 1024
MAXIMUM_PROJECT_BYTES = 128 * 1024 * 1024
MAXIMUM_RULES_BYTES = 128 * 1024 * 1024
MAXIMUM_PACKAGE_BYTES = 128 * 1024 * 1024
MAXIMUM_PROFILE_BYTES = 4 * 1024 * 1024
MAXIMUM_TOTAL_INPUT_BYTES = 512 * 1024 * 1024
MAXIMUM_CHILD_STDOUT_BYTES = 1 * 1024 * 1024
MAXIMUM_CHILD_STDERR_BYTES = 1 * 1024 * 1024
MAXIMUM_TIMEOUT_SECONDS = 600.0
MAXIMUM_PORTABLE_NAME_BYTES = 255
MAXIMUM_ARGUMENT_BYTES = 32_768
MAXIMUM_COMMAND_ARGUMENTS = 256
MAXIMUM_WINDOWS_COMMAND_LINE_UTF16_UNITS = 32_767

_WINDOWS_RESERVED_NUMERIC_SUFFIXES = (
    "123456789\N{SUPERSCRIPT ONE}\N{SUPERSCRIPT TWO}\N{SUPERSCRIPT THREE}"
)
_WINDOWS_RESERVED_LEAF_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{suffix}" for suffix in _WINDOWS_RESERVED_NUMERIC_SUFFIXES}
    | {f"LPT{suffix}" for suffix in _WINDOWS_RESERVED_NUMERIC_SUFFIXES}
)
_BUILTIN_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")


class ManufacturingReplayError(ValueError):
    """A stable, path-free failure from manufacturing-package replay."""


def _fail(message: str) -> ManufacturingReplayError:
    return ManufacturingReplayError(message)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": _sha256(raw)}


def _freeze_path(value: str | os.PathLike[str], label: str) -> str:
    """Resolve one caller PathLike exactly once to immutable path text."""

    try:
        rendered = os.fspath(value)
    except (TypeError, ValueError, OSError):
        raise _fail(f"{label} is invalid") from None
    if not isinstance(rendered, str) or not rendered or "\x00" in rendered:
        raise _fail(f"{label} is invalid")
    # Drop a possible caller-defined ``str`` subclass without invoking its
    # conversion hooks again.  Every later read therefore uses immutable,
    # built-in text captured by this single ``os.fspath`` call.
    return str.__add__("", rendered)


def _argument(value: str | os.PathLike[str], label: str) -> str:
    rendered = _freeze_path(value, label)
    try:
        encoded = rendered.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise _fail(f"{label} is invalid") from None
    if len(encoded) > MAXIMUM_ARGUMENT_BYTES:
        raise _fail(f"{label} is invalid")
    return rendered


def _normalize_command(value: str | Sequence[str]) -> list[str]:
    if isinstance(value, str):
        command: list[Any] = [value]
    elif isinstance(value, (bytes, bytearray)):
        raise _fail("pcbex command is invalid")
    else:
        try:
            iterator = iter(value)
        except (TypeError, ValueError, OverflowError):
            raise _fail("pcbex command is invalid") from None
        command = []
        try:
            for item in iterator:
                if len(command) == MAXIMUM_COMMAND_ARGUMENTS:
                    raise _fail("pcbex command is invalid")
                command.append(item)
        except ManufacturingReplayError:
            raise
        except (TypeError, ValueError, OverflowError, RuntimeError):
            raise _fail("pcbex command is invalid") from None
    if not command:
        raise _fail("pcbex command is invalid")
    normalized: list[str] = []
    total = 0
    for item in command:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise _fail("pcbex command is invalid")
        try:
            encoded = item.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise _fail("pcbex command is invalid") from None
        if len(encoded) > MAXIMUM_ARGUMENT_BYTES:
            raise _fail("pcbex command is invalid")
        total += len(encoded)
        if total > MAXIMUM_ARGUMENT_BYTES:
            raise _fail("pcbex command is invalid")
        normalized.append(item)
    return normalized


def _validate_final_argv(argv: Sequence[str]) -> list[str]:
    """Bound the complete injected argv, including Windows command quoting."""

    if not argv or len(argv) > MAXIMUM_COMMAND_ARGUMENTS:
        raise _fail("manufacturing child argv is invalid")
    total = 0
    for item in argv:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise _fail("manufacturing child argv is invalid")
        try:
            encoded = item.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise _fail("manufacturing child argv is invalid") from None
        total += len(encoded)
        if total > MAXIMUM_ARGUMENT_BYTES:
            raise _fail("manufacturing child argv is invalid")
    try:
        windows_command_line = subprocess.list2cmdline(list(argv))
        windows_units = len(
            windows_command_line.encode("utf-16-le", errors="strict")
        ) // 2 + 1
    except (TypeError, ValueError, UnicodeEncodeError):
        raise _fail("manufacturing child argv is invalid") from None
    if windows_units > MAXIMUM_WINDOWS_COMMAND_LINE_UTF16_UNITS:
        raise _fail("manufacturing child argv is invalid")
    return list(argv)


def _portable_leaf(name: Any) -> bool:
    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or name[-1] in {" ", "."}
        or any(ord(character) < 32 for character in name)
        or any(character in '<>:"/\\|?*' for character in name)
    ):
        return False
    try:
        encoded = name.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    windows_name = PureWindowsPath(name)
    windows_stem = name.partition(".")[0].rstrip(" ").upper()
    return (
        len(encoded) <= MAXIMUM_PORTABLE_NAME_BYTES
        and not windows_name.drive
        and not windows_name.root
        and windows_name.parts == (name,)
        and windows_name.name == name
        and windows_stem not in _WINDOWS_RESERVED_LEAF_STEMS
    )


def _board_leaf(raw: str) -> str:
    leaf = Path(raw).name
    board_leaf = Path(leaf)
    if (
        not _portable_leaf(leaf)
        or board_leaf.suffix != ".kicad_pcb"
        or not board_leaf.stem
        or leaf == ".kicad_pcb"
    ):
        raise _fail("board basename must be one portable .kicad_pcb leaf")
    for derived in (
        str(Path(leaf).with_suffix(".kicad_pro")),
        str(Path(leaf).with_suffix(".kicad_dru")),
    ):
        if not _portable_leaf(derived):
            raise _fail("derived KiCad project basename is invalid")
    return leaf


def _source_leaf(raw: str, label: str) -> str:
    leaf = Path(raw).name
    if not _portable_leaf(leaf):
        raise _fail(f"{label} basename must be one portable leaf")
    return leaf


def _builtin_profile_id(value: Any) -> str:
    if not isinstance(value, str) or _BUILTIN_PROFILE_ID.fullmatch(value) is None:
        raise _fail("built-in fabrication profile is invalid")
    return value


def _remaining(deadline: float, clock: Callable[[], float]) -> float:
    try:
        remaining = deadline - float(clock())
    except (TypeError, ValueError, OverflowError):
        raise _fail("aggregate deadline clock is invalid") from None
    if not math.isfinite(remaining) or remaining <= 0:
        raise _fail("manufacturing replay exceeded its aggregate deadline")
    return min(remaining, MAXIMUM_TIMEOUT_SECONDS)


def _trusted_temporary_root() -> Path:
    try:
        return Path(tempfile.gettempdir()).resolve(strict=True)
    except (OSError, RuntimeError):
        raise _fail("trusted temporary root is invalid") from None


def _read_source(
    path: str,
    maximum: int,
    label: str,
) -> bytes:
    try:
        raw = read_bytes(path, max_bytes=maximum)
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail(f"{label} source is invalid") from None
    if not raw:
        raise _fail(f"{label} source is empty")
    return raw


def _profile_result(
    *,
    fab: str | None,
    fab_profile_identity: dict[str, Any] | None,
    fab_profile_name: str | None,
    physical_profile_identity: dict[str, Any] | None,
    physical_profile_name: str | None,
) -> dict[str, Any]:
    if fab is not None:
        return {"kind": "builtin", "id": fab}
    if fab_profile_identity is not None:
        assert fab_profile_name is not None
        return {
            "kind": "dfm-file",
            "source": {"name": fab_profile_name, **fab_profile_identity},
        }
    if physical_profile_identity is not None:
        assert physical_profile_name is not None
        return {
            "kind": "physical-file",
            "source": {
                "name": physical_profile_name,
                **physical_profile_identity,
            },
        }
    return {"kind": "none"}


def manufacturing_package_replay_result_json_schema() -> dict[str, Any]:
    """Return the closed schema-v1 manufacturing replay result schema."""

    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}

    def identity(maximum: int) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["bytes", "sha256"],
            "properties": {
                "bytes": {"type": "integer", "minimum": 1, "maximum": maximum},
                "sha256": digest,
            },
        }

    board_identity = identity(MAXIMUM_BOARD_BYTES)
    board_identity["required"] = ["name", "bytes", "sha256"]
    board_identity["properties"] = {
        "name": {
            "type": "string",
            "minLength": 11,
            "maxLength": MAXIMUM_PORTABLE_NAME_BYTES,
            "pattern": r"^[^<>:\"/\\|?*\u0000-\u001f]+\.kicad_pcb$",
        },
        **board_identity["properties"],
    }
    nullable_project = {
        "anyOf": [identity(MAXIMUM_PROJECT_BYTES), {"type": "null"}]
    }
    nullable_rules = {
        "anyOf": [identity(MAXIMUM_RULES_BYTES), {"type": "null"}]
    }
    package_identity = identity(MAXIMUM_PACKAGE_BYTES)
    profile_source = identity(MAXIMUM_PROFILE_BYTES)
    profile_source["required"] = ["name", "bytes", "sha256"]
    profile_source["properties"] = {
        "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": MAXIMUM_PORTABLE_NAME_BYTES,
            "pattern": r"^(?!.*[ .]$)[^<>:\"/\\|?*\u0000-\u001f]+$",
        },
        **profile_source["properties"],
    }
    profile = {
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind"],
                "properties": {"kind": {"const": "none"}},
            },
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "id"],
                "properties": {
                    "kind": {"const": "builtin"},
                    "id": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$",
                    },
                },
            },
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "source"],
                "properties": {
                    "kind": {"const": "dfm-file"},
                    "source": profile_source,
                },
            },
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "source"],
                "properties": {
                    "kind": {"const": "physical-file"},
                    "source": profile_source,
                },
            },
        ]
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/schemas/"
            "manufacturing-package-fresh-replay-result-v1.json"
        ),
        "title": "pcbex fresh manufacturing-package replay result",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "verification_scope",
            "verified",
            "board",
            "project",
            "rules",
            "profile",
            "package",
            "validation",
        ],
        "properties": {
            "schema_version": {"const": MANUFACTURING_REPLAY_RESULT_SCHEMA_VERSION},
            "verification_scope": {"const": MANUFACTURING_REPLAY_SCOPE},
            "verified": {"const": True},
            "board": board_identity,
            "project": nullable_project,
            "rules": nullable_rules,
            "profile": profile,
            "package": {
                "type": "object",
                "additionalProperties": False,
                "required": ["retained", "fresh", "identical"],
                "properties": {
                    "retained": package_identity,
                    "fresh": identity(MAXIMUM_PACKAGE_BYTES),
                    "identical": {"const": True},
                },
            },
            "validation": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "inputs_captured",
                    "package_reproduced",
                    "staged_inputs_unchanged",
                    "caller_inputs_unchanged",
                ],
                "properties": {
                    "inputs_captured": {"const": True},
                    "package_reproduced": {"const": True},
                    "staged_inputs_unchanged": {"const": True},
                    "caller_inputs_unchanged": {"const": True},
                },
            },
        },
    }


def replay_manufacturing_package(
    board: str | os.PathLike[str],
    retained_package: str | os.PathLike[str],
    pcbex: str | Sequence[str] = "pcbex",
    *,
    kicad_cli: str | os.PathLike[str] = "kicad-cli",
    kicad_project: str | os.PathLike[str] | None = None,
    kicad_rules: str | os.PathLike[str] | None = None,
    fab: str | None = None,
    fab_profile: str | os.PathLike[str] | None = None,
    physical_profile: str | os.PathLike[str] | None = None,
    timeout_seconds: float = 120.0,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Freshly regenerate and exactly compare one manufacturing ZIP."""

    try:
        timeout = float(timeout_seconds)
        start = float(_clock())
    except (TypeError, ValueError, OverflowError):
        raise _fail("aggregate timeout is invalid") from None
    if (
        isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > MAXIMUM_TIMEOUT_SECONDS
        or not math.isfinite(start)
    ):
        raise _fail("aggregate timeout is invalid")
    deadline = start + timeout
    if not math.isfinite(deadline):
        raise _fail("aggregate timeout is invalid")

    selections = sum(
        source is not None for source in (fab, fab_profile, physical_profile)
    )
    if selections > 1:
        raise _fail("manufacturing profile selections are mutually exclusive")
    if fab is not None:
        fab = _builtin_profile_id(fab)

    command = _normalize_command(pcbex)
    kicad_cli_argument = _argument(kicad_cli, "kicad-cli argument")
    board_source = _freeze_path(board, "board source")
    retained_package_source = _freeze_path(
        retained_package, "retained package source"
    )
    project_source = (
        None
        if kicad_project is None
        else _freeze_path(kicad_project, "KiCad project source")
    )
    rules_source = (
        None
        if kicad_rules is None
        else _freeze_path(kicad_rules, "KiCad rules source")
    )
    fab_profile_source = (
        None
        if fab_profile is None
        else _freeze_path(fab_profile, "DFM profile source")
    )
    physical_profile_source = (
        None
        if physical_profile is None
        else _freeze_path(physical_profile, "physical profile source")
    )
    board_name = _board_leaf(board_source)
    project_name = str(Path(board_name).with_suffix(".kicad_pro"))
    rules_name = str(Path(board_name).with_suffix(".kicad_dru"))
    fab_profile_name = (
        None
        if fab_profile_source is None
        else _source_leaf(fab_profile_source, "DFM profile")
    )
    physical_profile_name = (
        None
        if physical_profile_source is None
        else _source_leaf(physical_profile_source, "physical profile")
    )
    _remaining(deadline, _clock)

    sources: list[tuple[str, bytes, int, str]] = []
    board_raw = _read_source(board_source, MAXIMUM_BOARD_BYTES, "board")
    board_identity = _identity(board_raw)
    sources.append((board_source, board_raw, MAXIMUM_BOARD_BYTES, "board"))
    _remaining(deadline, _clock)
    retained_raw = _read_source(
        retained_package_source, MAXIMUM_PACKAGE_BYTES, "retained package"
    )
    retained_identity = _identity(retained_raw)
    sources.append(
        (
            retained_package_source,
            retained_raw,
            MAXIMUM_PACKAGE_BYTES,
            "retained package",
        )
    )
    _remaining(deadline, _clock)

    project_raw: bytes | None = None
    rules_raw: bytes | None = None
    fab_profile_raw: bytes | None = None
    physical_profile_raw: bytes | None = None
    project_identity: dict[str, Any] | None = None
    rules_identity: dict[str, Any] | None = None
    fab_profile_identity: dict[str, Any] | None = None
    physical_profile_identity: dict[str, Any] | None = None
    optional_sources = (
        (project_source, MAXIMUM_PROJECT_BYTES, "KiCad project"),
        (rules_source, MAXIMUM_RULES_BYTES, "KiCad rules"),
        (fab_profile_source, MAXIMUM_PROFILE_BYTES, "DFM profile"),
        (physical_profile_source, MAXIMUM_PROFILE_BYTES, "physical profile"),
    )
    captured_optional: list[bytes | None] = []
    captured_optional_identities: list[dict[str, Any] | None] = []
    for path, maximum, label in optional_sources:
        if path is None:
            captured_optional.append(None)
            captured_optional_identities.append(None)
            continue
        raw = _read_source(path, maximum, label)
        captured_optional.append(raw)
        captured_optional_identities.append(_identity(raw))
        sources.append((path, raw, maximum, label))
        _remaining(deadline, _clock)
    (
        project_raw,
        rules_raw,
        fab_profile_raw,
        physical_profile_raw,
    ) = captured_optional
    (
        project_identity,
        rules_identity,
        fab_profile_identity,
        physical_profile_identity,
    ) = captured_optional_identities
    if sum(len(raw) for _path, raw, _maximum, _label in sources) > MAXIMUM_TOTAL_INPUT_BYTES:
        raise _fail("manufacturing replay inputs exceed their aggregate bound")

    staged: list[tuple[Path, bytes, int]] = []
    fresh_raw: bytes | None = None
    fresh_identity: dict[str, Any] | None = None
    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-manufacturing-replay-",
            dir=_trusted_temporary_root(),
        ) as directory:
            root = Path(directory)
            board_path = root / board_name
            output_dir = root / "fresh-manufacturing"
            atomic_write_no_clobber(
                board_path, board_raw, max_bytes=MAXIMUM_BOARD_BYTES
            )
            staged.append((board_path, board_raw, MAXIMUM_BOARD_BYTES))
            _remaining(deadline, _clock)
            if project_raw is not None:
                project_path = root / project_name
                atomic_write_no_clobber(
                    project_path, project_raw, max_bytes=MAXIMUM_PROJECT_BYTES
                )
                staged.append((project_path, project_raw, MAXIMUM_PROJECT_BYTES))
                _remaining(deadline, _clock)
            if rules_raw is not None:
                rules_path = root / rules_name
                atomic_write_no_clobber(
                    rules_path, rules_raw, max_bytes=MAXIMUM_RULES_BYTES
                )
                staged.append((rules_path, rules_raw, MAXIMUM_RULES_BYTES))
                _remaining(deadline, _clock)

            profile_arguments: list[str] = []
            if fab is not None:
                profile_arguments.append(f"--fab={fab}")
            elif fab_profile_raw is not None:
                assert fab_profile_name is not None
                profile_directory = root / "profile-input"
                profile_directory.mkdir(mode=0o700)
                profile_path = profile_directory / fab_profile_name
                atomic_write_no_clobber(
                    profile_path,
                    fab_profile_raw,
                    max_bytes=MAXIMUM_PROFILE_BYTES,
                )
                staged.append((profile_path, fab_profile_raw, MAXIMUM_PROFILE_BYTES))
                profile_arguments.append(f"--fab-profile={profile_path}")
                _remaining(deadline, _clock)
            elif physical_profile_raw is not None:
                assert physical_profile_name is not None
                profile_directory = root / "profile-input"
                profile_directory.mkdir(mode=0o700)
                profile_path = profile_directory / physical_profile_name
                atomic_write_no_clobber(
                    profile_path,
                    physical_profile_raw,
                    max_bytes=MAXIMUM_PROFILE_BYTES,
                )
                staged.append(
                    (profile_path, physical_profile_raw, MAXIMUM_PROFILE_BYTES)
                )
                profile_arguments.append(f"--physical-profile={profile_path}")
                _remaining(deadline, _clock)

            outer_remaining = _remaining(deadline, _clock)
            cleanup_and_reread_reserve = min(15.0, outer_remaining / 2.0)
            process_timeout = outer_remaining - cleanup_and_reread_reserve
            if not math.isfinite(process_timeout) or process_timeout <= 0:
                raise _fail("manufacturing child has no execution budget")
            argv = _validate_final_argv(
                [
                    *command,
                    "fabricate",
                    str(board_path),
                    "--outer-process-tree-supervised",
                    f"--output-dir={output_dir}",
                    f"--kicad-cli={kicad_cli_argument}",
                    f"--timeout-seconds={process_timeout:.17g}",
                    *profile_arguments,
                ]
            )
            try:
                completed = run_bounded(
                    argv,
                    # The inner Rust deadline is deliberately shorter.  The
                    # Python supervisor retains time to let pcbex reap KiCad
                    # descendants and to perform its own post-child reads.
                    timeout_seconds=outer_remaining,
                    max_stdout_bytes=MAXIMUM_CHILD_STDOUT_BYTES,
                    max_stderr_bytes=MAXIMUM_CHILD_STDERR_BYTES,
                )
            except BoundedProcessError:
                raise _fail("manufacturing child process failed") from None
            if completed.returncode != 0:
                raise _fail("manufacturing child rejected the replay")
            _remaining(deadline, _clock)

            fresh_path = output_dir / "manufacturing.zip"
            fresh_raw = _read_source(
                fresh_path, MAXIMUM_PACKAGE_BYTES, "fresh package"
            )
            if fresh_raw != retained_raw:
                raise _fail(
                    "fresh manufacturing replay did not reproduce the retained package"
                )
            fresh_identity = _identity(fresh_raw)
            if fresh_identity != retained_identity:
                raise _fail("fresh manufacturing package identity is inconsistent")
            _remaining(deadline, _clock)

            for path, expected, maximum in staged:
                try:
                    observed = read_bytes(path, max_bytes=maximum)
                except (BoundedIOError, OSError, TypeError, ValueError):
                    raise _fail("staged manufacturing input changed during replay") from None
                if observed != expected:
                    raise _fail("staged manufacturing input changed during replay")
                _remaining(deadline, _clock)
            try:
                fresh_after = read_bytes(
                    fresh_path, max_bytes=MAXIMUM_PACKAGE_BYTES
                )
            except (BoundedIOError, OSError, TypeError, ValueError):
                raise _fail("fresh package changed during replay") from None
            if fresh_after != fresh_raw:
                raise _fail("fresh package changed during replay")
            _remaining(deadline, _clock)

            for path, expected, maximum, label in sources:
                try:
                    observed = read_bytes(path, max_bytes=maximum)
                except (BoundedIOError, OSError, TypeError, ValueError):
                    raise _fail(f"{label} source changed during replay") from None
                if observed != expected:
                    raise _fail(f"{label} source changed during replay")
                _remaining(deadline, _clock)
    except ManufacturingReplayError:
        raise
    except (BoundedIOError, BoundedProcessError, OSError, TypeError, ValueError):
        raise _fail("manufacturing replay workspace failed") from None

    assert fresh_raw is not None
    assert fresh_identity is not None
    _remaining(deadline, _clock)
    result = {
        "schema_version": MANUFACTURING_REPLAY_RESULT_SCHEMA_VERSION,
        "verification_scope": MANUFACTURING_REPLAY_SCOPE,
        "verified": True,
        "board": {"name": board_name, **board_identity},
        "project": project_identity,
        "rules": rules_identity,
        "profile": _profile_result(
            fab=fab,
            fab_profile_identity=fab_profile_identity,
            fab_profile_name=fab_profile_name,
            physical_profile_identity=physical_profile_identity,
            physical_profile_name=physical_profile_name,
        ),
        "package": {
            "retained": retained_identity,
            "fresh": fresh_identity,
            "identical": True,
        },
        "validation": {
            "inputs_captured": True,
            "package_reproduced": True,
            "staged_inputs_unchanged": True,
            "caller_inputs_unchanged": True,
        },
    }
    _remaining(deadline, _clock)
    return result


__all__ = [
    "ManufacturingReplayError",
    "manufacturing_package_replay_result_json_schema",
    "replay_manufacturing_package",
]
