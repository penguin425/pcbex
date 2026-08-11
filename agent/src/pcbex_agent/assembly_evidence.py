"""Exact, offline composition of one board's retained assembly evidence.

This adapter does not manufacture, order, reserve, or authorize anything.  It
captures every caller-controlled source, freshly replays the existing v6
handoff/manufacturing chain, the retained procurement intent, and the final
CPL verifier, then cross-binds their exact source identities.  Valid rejected
child reports remain evidence and make the outer result incomplete; malformed,
mutated, non-reproducible, or cross-boundary-inconsistent evidence fails hard.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
import copy
import hashlib
import json
import math
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import tempfile
import time
from typing import Any
import unicodedata
from types import SimpleNamespace

from .bounded_io import BoundedIOError, atomic_write_no_clobber, read_bytes
from .bounded_process import BoundedProcessError, run_bounded
from .catalog import MAX_CATALOG_RAW_BYTES, MAX_CATALOG_TTL_SECONDS
from . import circuit_handoff_bundle as _handoff
from . import manufacturing_replay as _manufacturing
from . import procurement_intent as _procurement


ASSEMBLY_EVIDENCE_SCHEMA_VERSION = 1
ASSEMBLY_EVIDENCE_SCOPE = "offline-exact-board-assembly-evidence-v1"
ASSEMBLY_EVIDENCE_BINDING_DOMAIN = (
    b"pcbex:offline-exact-board-assembly-evidence-v1\0"
)

MAXIMUM_HANDOFF_BYTES = _handoff.MAX_HANDOFF_ARCHIVE_BYTES
MAXIMUM_BOARD_BYTES = _manufacturing.MAXIMUM_BOARD_BYTES
MAXIMUM_PACKAGE_BYTES = _manufacturing.MAXIMUM_PACKAGE_BYTES
MAXIMUM_BOARD_BINDING_REPORT_BYTES = (
    _handoff.MAX_KICAD_BOARD_BINDING_RENDERED_REPORT_BYTES
)
MAXIMUM_BOARD_BINDING_POLICY_BYTES = _handoff.MAX_KICAD_BOARD_BINDING_POLICY_BYTES
MAXIMUM_PROCUREMENT_INTENT_BYTES = _procurement.MAXIMUM_PROCUREMENT_INTENT_BYTES
MAXIMUM_FINAL_CPL_REPORT_BYTES = 16 * 1024 * 1024
MAXIMUM_MANIFEST_BYTES = 1 * 1024 * 1024
MAXIMUM_PROJECT_BYTES = _manufacturing.MAXIMUM_PROJECT_BYTES
MAXIMUM_RULES_BYTES = _manufacturing.MAXIMUM_RULES_BYTES
MAXIMUM_PROFILE_BYTES = _manufacturing.MAXIMUM_PROFILE_BYTES
MAXIMUM_TOTAL_INPUT_BYTES = 768 * 1024 * 1024
MAXIMUM_ASSEMBLY_EVIDENCE_BYTES = 32 * 1024 * 1024
MAXIMUM_CHILD_STDOUT_BYTES = 1 * 1024 * 1024
MAXIMUM_CHILD_STDERR_BYTES = 1 * 1024 * 1024
MAXIMUM_TIMEOUT_SECONDS = 600.0
MINIMUM_TIMEOUT_SECONDS = 1.0
MAXIMUM_COMMAND_ARGUMENTS = 256
MAXIMUM_ARGUMENT_BYTES = 32_768
MAXIMUM_WINDOWS_COMMAND_LINE_UTF16_UNITS = 32_767
MAXIMUM_PARTS = 100_000
MAXIMUM_REFERENCES = 256
MAXIMUM_REFERENCE_BYTES = 4096
MAXIMUM_PORTABLE_NAME_BYTES = 255

FINAL_CPL_SCOPE = "final_cpl_source_and_canonical_placement_v1"
FINAL_BOM_SCOPE = "final_bom_source_and_canonical_bom_v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_BUILTIN_PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")
_WINDOWS_RESERVED_NUMERIC_SUFFIXES = (
    "123456789\N{SUPERSCRIPT ONE}\N{SUPERSCRIPT TWO}\N{SUPERSCRIPT THREE}"
)
_WINDOWS_RESERVED_LEAF_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{suffix}" for suffix in _WINDOWS_RESERVED_NUMERIC_SUFFIXES}
    | {f"LPT{suffix}" for suffix in _WINDOWS_RESERVED_NUMERIC_SUFFIXES}
)

_FINAL_CPL_KEYS = frozenset(
    {
        "schema_version",
        "scope",
        "engine_version",
        "board_basename",
        "sources",
        "counts",
        "in_pos_parts",
        "findings",
        "approved",
    }
)
_FINAL_CPL_SOURCE_KEYS = frozenset(
    {
        "board",
        "manufacturing_package",
        "manifest",
        "cpl",
        "canonical_cpl",
        "package_board_source",
    }
)
_FINAL_CPL_COUNT_KEYS = frozenset(
    {
        "board_parts",
        "board_in_pos_parts",
        "package_parts",
        "package_placement_parts",
        "findings",
    }
)
_FINAL_CPL_PART_KEYS = frozenset(
    {"reference", "x_nm", "y_nm", "rotation_mdeg", "layer"}
)
_FINAL_CPL_FINDING_MESSAGES = {
    "canonical_cpl_mismatch": (
        "manufacturing package cpl.csv does not equal the canonical CPL "
        "regenerated from the board"
    ),
    "package_board_source_mismatch": (
        "manufacturing package input identity does not equal the supplied board"
    ),
}
_ASSEMBLY_FINDING_MESSAGES = {
    "board_binding_rejected": (
        "the freshly replayed board-binding evidence is rejected"
    ),
    "final_cpl_rejected": "the freshly reproduced final-CPL evidence is rejected",
    "procurement_intent_rejected": (
        "the freshly replayed procurement-intent evidence is rejected"
    ),
}


class AssemblyEvidenceError(ValueError):
    """Stable, path-free failure from exact assembly-evidence composition."""


class _DuplicateJSONKey(ValueError):
    pass


@dataclass(frozen=True)
class _CapturedSource:
    path: str
    label: str
    maximum: int
    raw: bytes

    @property
    def identity(self) -> dict[str, Any]:
        return _identity(self.raw)


@dataclass(frozen=True)
class _AssemblyCapture:
    handoff: _CapturedSource
    board: _CapturedSource
    package: _CapturedSource
    board_binding_report: _CapturedSource
    procurement_intent: _CapturedSource
    catalog_snapshot: _CapturedSource
    final_cpl_report: _CapturedSource
    board_binding_policy: _CapturedSource | None
    manufacturing_project: _CapturedSource | None
    manufacturing_rules: _CapturedSource | None
    manufacturing_fab_profile: _CapturedSource | None
    manufacturing_physical_profile: _CapturedSource | None
    board_name: str
    catalog_name: str
    kicad_cli: str
    pcbex: tuple[str, ...]
    manufacturing_fab: str | None

    @property
    def sources(self) -> tuple[_CapturedSource, ...]:
        optional = (
            self.board_binding_policy,
            self.manufacturing_project,
            self.manufacturing_rules,
            self.manufacturing_fab_profile,
            self.manufacturing_physical_profile,
        )
        return (
            self.handoff,
            self.board,
            self.package,
            self.board_binding_report,
            self.procurement_intent,
            self.catalog_snapshot,
            self.final_cpl_report,
            *(source for source in optional if source is not None),
        )


def _fail(message: str) -> AssemblyEvidenceError:
    return AssemblyEvidenceError(message)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": _sha256(raw)}


def _strict_json_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _strict_json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _strict_json_equal(a, b) for a, b in zip(left, right)
        )
    return left == right


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ValueError


def _parse_json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateJSONKey,
        ValueError,
        RecursionError,
    ):
        raise _fail(f"{label} is not strict JSON") from None
    if not isinstance(value, dict):
        raise _fail(f"{label} must be a JSON object")
    return value


def _compact_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise _fail("assembly evidence cannot be serialized") from None


def render_assembly_evidence(value: Mapping[str, Any]) -> bytes:
    """Render bounded canonical JSON after structural/self-consistency checks.

    Rendering alone does not authenticate opaque child contents against their
    original source bytes.  Use :func:`validate_assembly_evidence` for fresh
    source authentication and replay.
    """

    try:
        # This helper performs one bounded traversal into exact built-in JSON
        # scalar/container types before serialization.  It precharges giant
        # integer/string subclasses and never asks a stateful Mapping for a
        # second view.
        snapshot_raw = _procurement._bounded_injected_json_bytes(
            value,
            maximum=MAXIMUM_ASSEMBLY_EVIDENCE_BYTES,
            label="assembly-evidence report",
        )
        snapshot = _parse_json_object(snapshot_raw, "assembly-evidence report")
        _validate_assembly_result(snapshot)
        encoder = json.JSONEncoder(
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        output = bytearray()
        for chunk in encoder.iterencode(snapshot):
            encoded = str.encode(chunk, "utf-8", "strict")
            if len(output) + len(encoded) + 1 > MAXIMUM_ASSEMBLY_EVIDENCE_BYTES:
                raise _fail("assembly evidence exceeds its byte bound")
            output.extend(encoded)
        output.append(0x0A)
        rendered = bytes(output)
    except AssemblyEvidenceError:
        raise
    except _procurement.CatalogGenerationProvenanceError as error:
        if "byte bound" in str(error):
            raise _fail("assembly evidence exceeds its byte bound") from None
        raise _fail("assembly evidence cannot be serialized") from None
    except (TypeError, ValueError, UnicodeError, RuntimeError, RecursionError):
        raise _fail("assembly evidence cannot be serialized") from None
    if len(rendered) > MAXIMUM_ASSEMBLY_EVIDENCE_BYTES:
        raise _fail("assembly evidence exceeds its byte bound")
    return rendered


def _freeze_path(value: str | os.PathLike[str], label: str) -> str:
    try:
        rendered = os.fspath(value)
    except (TypeError, ValueError, OSError, RuntimeError):
        raise _fail(f"{label} is invalid") from None
    if not isinstance(rendered, str):
        raise _fail(f"{label} is invalid")
    length = str.__len__(rendered)
    if (
        length == 0
        or length > MAXIMUM_ARGUMENT_BYTES
        or str.__contains__(rendered, "\x00")
    ):
        raise _fail(f"{label} is invalid")
    try:
        if len(str.encode(rendered, "utf-8", "strict")) > MAXIMUM_ARGUMENT_BYTES:
            raise _fail(f"{label} is invalid")
    except UnicodeEncodeError:
        raise _fail(f"{label} is invalid") from None
    return str.__str__(rendered)


def _portable_leaf(path: str, label: str, suffix: str | None = None) -> str:
    name = Path(path).name
    windows = PureWindowsPath(name)
    windows_stem = name.partition(".")[0].rstrip(" ").upper()
    if (
        not name
        or name in {".", ".."}
        or Path(name).parts != (name,)
        or any(unicodedata.category(character) == "Cc" for character in name)
        or any(character in '<>:"/\\|?*' for character in name)
        or name[-1] in {" ", "."}
        or windows.drive
        or windows.root
        or windows.parts != (name,)
        or windows.name != name
        or windows_stem in _WINDOWS_RESERVED_LEAF_STEMS
    ):
        raise _fail(f"{label} basename is invalid")
    try:
        encoded = name.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise _fail(f"{label} basename is invalid") from None
    if (
        len(encoded) > MAXIMUM_PORTABLE_NAME_BYTES
        or (suffix is not None and not name.endswith(suffix))
        or (suffix is not None and name == suffix)
    ):
        raise _fail(f"{label} basename is invalid")
    return name


def _ensure_distinct_sources(paths: Sequence[str]) -> None:
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            if left == right:
                raise _fail("assembly evidence input sources must be distinct")
            try:
                aliases = os.path.samefile(left, right)
            except (OSError, TypeError, ValueError):
                raise _fail("assembly evidence input identity is invalid") from None
            if aliases:
                raise _fail("assembly evidence input sources must be distinct")


def _read_source(path: str, maximum: int, label: str) -> bytes:
    try:
        raw = read_bytes(path, max_bytes=maximum)
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail(f"{label} source is invalid") from None
    if not raw:
        raise _fail(f"{label} source is empty")
    return raw


def _normalize_command(value: str | Sequence[str]) -> tuple[str, ...]:
    if isinstance(value, str):
        items: list[Any] = [value]
    elif isinstance(value, (bytes, bytearray)):
        raise _fail("pcbex command is invalid")
    else:
        try:
            iterator = iter(value)
        except (TypeError, ValueError, OverflowError):
            raise _fail("pcbex command is invalid") from None
        items = []
        try:
            for item in iterator:
                if len(items) == MAXIMUM_COMMAND_ARGUMENTS:
                    raise _fail("pcbex command is invalid")
                items.append(item)
        except AssemblyEvidenceError:
            raise
        except (TypeError, ValueError, OverflowError, RuntimeError):
            raise _fail("pcbex command is invalid") from None
    if not items:
        raise _fail("pcbex command is invalid")
    normalized: list[str] = []
    total = 0
    for item in items:
        if not isinstance(item, str):
            raise _fail("pcbex command is invalid")
        item_length = str.__len__(item)
        if (
            item_length == 0
            or item_length > MAXIMUM_ARGUMENT_BYTES
            or str.__contains__(item, "\x00")
        ):
            raise _fail("pcbex command is invalid")
        try:
            encoded = str.encode(item, "utf-8", "strict")
        except UnicodeEncodeError:
            raise _fail("pcbex command is invalid") from None
        total += len(encoded)
        if len(encoded) > MAXIMUM_ARGUMENT_BYTES or total > MAXIMUM_ARGUMENT_BYTES:
            raise _fail("pcbex command is invalid")
        normalized.append(str.__str__(item))
    return tuple(normalized)


def _validate_argv(argv: Sequence[str], label: str) -> list[str]:
    if not argv or len(argv) > MAXIMUM_COMMAND_ARGUMENTS:
        raise _fail(f"{label} argv is invalid")
    total = 0
    for item in argv:
        if not isinstance(item, str):
            raise _fail(f"{label} argv is invalid")
        item_length = str.__len__(item)
        if (
            item_length == 0
            or item_length > MAXIMUM_ARGUMENT_BYTES
            or str.__contains__(item, "\x00")
        ):
            raise _fail(f"{label} argv is invalid")
        try:
            encoded = str.encode(item, "utf-8", "strict")
        except UnicodeEncodeError:
            raise _fail(f"{label} argv is invalid") from None
        total += len(encoded)
        if total > MAXIMUM_ARGUMENT_BYTES:
            raise _fail(f"{label} argv is invalid")
    try:
        command_line = subprocess.list2cmdline(list(argv))
        windows_units = len(command_line.encode("utf-16-le", errors="strict")) // 2 + 1
    except (TypeError, ValueError, UnicodeEncodeError):
        raise _fail(f"{label} argv is invalid") from None
    if windows_units > MAXIMUM_WINDOWS_COMMAND_LINE_UTF16_UNITS:
        raise _fail(f"{label} argv is invalid")
    return list(argv)


def _timeout_deadline(
    timeout_seconds: float,
    clock: Callable[[], float],
) -> tuple[float, float]:
    try:
        timeout = float(timeout_seconds)
        start = float(clock())
    except (TypeError, ValueError, OverflowError):
        raise _fail("aggregate timeout is invalid") from None
    if (
        isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout)
        or timeout < MINIMUM_TIMEOUT_SECONDS
        or timeout > MAXIMUM_TIMEOUT_SECONDS
        or not math.isfinite(start)
    ):
        raise _fail("aggregate timeout is invalid")
    deadline = start + timeout
    if not math.isfinite(deadline):
        raise _fail("aggregate timeout is invalid")
    return timeout, deadline


def _remaining(deadline: float, clock: Callable[[], float]) -> float:
    try:
        value = deadline - float(clock())
    except (TypeError, ValueError, OverflowError):
        raise _fail("aggregate deadline clock is invalid") from None
    if not math.isfinite(value) or value <= 0:
        raise _fail("assembly evidence exceeded its aggregate deadline")
    return min(value, MAXIMUM_TIMEOUT_SECONDS)


def _trusted_temporary_root() -> Path:
    try:
        return Path(tempfile.gettempdir()).resolve(strict=True)
    except (OSError, RuntimeError):
        raise _fail("trusted temporary root is invalid") from None


def _capture_inputs(
    handoff_bundle: str | os.PathLike[str],
    board: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    retained_board_binding_report: str | os.PathLike[str],
    retained_procurement_intent: str | os.PathLike[str],
    catalog_snapshot: str | os.PathLike[str],
    retained_final_cpl: str | os.PathLike[str],
    pcbex: str | Sequence[str],
    *,
    board_binding_policy: str | os.PathLike[str] | None,
    kicad_cli: str | os.PathLike[str],
    manufacturing_kicad_project: str | os.PathLike[str] | None,
    manufacturing_kicad_rules: str | os.PathLike[str] | None,
    manufacturing_fab: str | None,
    manufacturing_fab_profile: str | os.PathLike[str] | None,
    manufacturing_physical_profile: str | os.PathLike[str] | None,
    deadline: float,
    clock: Callable[[], float],
    defer_commands: bool = False,
) -> tuple[_AssemblyCapture, _CapturedSource | None]:
    if (
        sum(
            choice is not None
            for choice in (
                manufacturing_fab,
                manufacturing_fab_profile,
                manufacturing_physical_profile,
            )
        )
        > 1
    ):
        raise _fail("manufacturing profile selections are mutually exclusive")
    frozen_fab: str | None = None
    if manufacturing_fab is not None:
        if not isinstance(manufacturing_fab, str):
            raise _fail("built-in manufacturing profile is invalid")
        fab_length = str.__len__(manufacturing_fab)
        if fab_length == 0 or fab_length > 128:
            raise _fail("built-in manufacturing profile is invalid")
        frozen_fab = str.__str__(manufacturing_fab)
        if _BUILTIN_PROFILE_RE.fullmatch(frozen_fab) is None:
            raise _fail("built-in manufacturing profile is invalid")

    specifications: list[tuple[str, str, int]] = [
        (_freeze_path(handoff_bundle, "circuit handoff bundle source"), "circuit handoff bundle", MAXIMUM_HANDOFF_BYTES),
        (_freeze_path(board, "board source"), "board", MAXIMUM_BOARD_BYTES),
        (_freeze_path(manufacturing_package, "manufacturing package source"), "manufacturing package", MAXIMUM_PACKAGE_BYTES),
        (_freeze_path(retained_board_binding_report, "board-binding report source"), "board-binding report", MAXIMUM_BOARD_BINDING_REPORT_BYTES),
        (_freeze_path(retained_procurement_intent, "procurement-intent source"), "procurement intent", MAXIMUM_PROCUREMENT_INTENT_BYTES),
        (_freeze_path(catalog_snapshot, "catalog snapshot source"), "catalog snapshot", MAX_CATALOG_RAW_BYTES),
        (_freeze_path(retained_final_cpl, "final-CPL report source"), "final-CPL report", MAXIMUM_FINAL_CPL_REPORT_BYTES),
    ]
    optional_specs: list[tuple[str, str, int] | None] = []
    for value, label, maximum in (
        (board_binding_policy, "board-binding policy", MAXIMUM_BOARD_BINDING_POLICY_BYTES),
        (manufacturing_kicad_project, "manufacturing KiCad project", MAXIMUM_PROJECT_BYTES),
        (manufacturing_kicad_rules, "manufacturing KiCad rules", MAXIMUM_RULES_BYTES),
        (manufacturing_fab_profile, "manufacturing DFM profile", MAXIMUM_PROFILE_BYTES),
        (manufacturing_physical_profile, "manufacturing physical profile", MAXIMUM_PROFILE_BYTES),
    ):
        optional_specs.append(
            None
            if value is None
            else (_freeze_path(value, f"{label} source"), label, maximum)
        )
    specifications.extend(spec for spec in optional_specs if spec is not None)
    _ensure_distinct_sources([spec[0] for spec in specifications])

    captured: list[_CapturedSource] = []
    total = 0
    for path, label, maximum in specifications:
        raw = _read_source(path, maximum, label)
        total += len(raw)
        if total > MAXIMUM_TOTAL_INPUT_BYTES:
            raise _fail("assembly evidence inputs exceed their aggregate bound")
        captured.append(_CapturedSource(path, label, maximum, raw))
        _remaining(deadline, clock)

    if defer_commands:
        kicad_argument = ""
        command: tuple[str, ...] = ()
    else:
        # Capture evidence before consuming stateful command values.  Mutations
        # performed by command conversion hooks are caught by the final reread.
        kicad_argument = _freeze_path(kicad_cli, "manufacturing kicad-cli argument")
        _validate_argv([kicad_argument], "manufacturing kicad-cli")
        command = _normalize_command(pcbex)
    board_name = _portable_leaf(captured[1].path, "board", ".kicad_pcb")
    catalog_name = _portable_leaf(captured[5].path, "catalog snapshot")
    optional_count = sum(spec is not None for spec in optional_specs)
    optional_captured = iter(captured[7 : 7 + optional_count])
    optional_values = tuple(
        None if spec is None else next(optional_captured) for spec in optional_specs
    )
    capture = _AssemblyCapture(
        handoff=captured[0],
        board=captured[1],
        package=captured[2],
        board_binding_report=captured[3],
        procurement_intent=captured[4],
        catalog_snapshot=captured[5],
        final_cpl_report=captured[6],
        board_binding_policy=optional_values[0],
        manufacturing_project=optional_values[1],
        manufacturing_rules=optional_values[2],
        manufacturing_fab_profile=optional_values[3],
        manufacturing_physical_profile=optional_values[4],
        board_name=board_name,
        catalog_name=catalog_name,
        kicad_cli=kicad_argument,
        pcbex=command,
        manufacturing_fab=frozen_fab,
    )
    return capture, None


def _finalize_capture_commands(
    capture: _AssemblyCapture,
    pcbex: str | Sequence[str],
    kicad_cli: str | os.PathLike[str],
) -> _AssemblyCapture:
    kicad_argument = _freeze_path(kicad_cli, "manufacturing kicad-cli argument")
    _validate_argv([kicad_argument], "manufacturing kicad-cli")
    return replace(
        capture,
        kicad_cli=kicad_argument,
        pcbex=_normalize_command(pcbex),
    )


def _reread_sources(
    capture: _AssemblyCapture,
    deadline: float,
    clock: Callable[[], float],
    additional: _CapturedSource | None = None,
) -> None:
    for source in (*capture.sources, *((additional,) if additional is not None else ())):
        observed = _read_source(source.path, source.maximum, source.label)
        if observed != source.raw:
            raise _fail(f"{source.label} changed during assembly-evidence evaluation")
        _remaining(deadline, clock)


def _integer(
    value: Any,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise _fail(f"{label} is invalid")
    return int(value)


def _text(value: Any, label: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise _fail(f"{label} is invalid")
    length = str.__len__(value)
    if length == 0 or str.__contains__(value, "\x00"):
        raise _fail(f"{label} is invalid")
    try:
        encoded = str.encode(value, "utf-8", "strict")
    except UnicodeEncodeError:
        raise _fail(f"{label} is invalid") from None
    if len(encoded) > maximum:
        raise _fail(f"{label} exceeds its byte bound")
    return str.__str__(value)


def _catalog_text(value: Any, label: str, *, maximum: int) -> str:
    """Validate text retained from the canonical catalog selection."""

    result = _text(value, label, maximum=maximum)
    if str.strip(result) != result or any(ord(character) < 0x20 for character in result):
        raise _fail(f"{label} is invalid")
    return result


def _engine_text(value: Any, label: str) -> str:
    result = _text(value, label, maximum=256)
    if result[0].isspace() or result[-1].isspace():
        raise _fail(f"{label} is invalid")
    return result


def _validate_identity(value: Any, label: str, maximum: int) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"bytes", "sha256"}:
        raise _fail(f"{label} identity is invalid")
    byte_count = _integer(
        value["bytes"], f"{label} byte count", minimum=1, maximum=maximum
    )
    digest = value["sha256"]
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise _fail(f"{label} digest is invalid")
    return {"bytes": byte_count, "sha256": digest}


def _validate_final_cpl_report(
    value: Any,
    capture: _AssemblyCapture,
    *,
    expected_engine: str | None,
) -> dict[str, Any]:
    """Validate the Rust final-CPL contract, including semantic correlations."""

    if not isinstance(value, Mapping) or set(value) != _FINAL_CPL_KEYS:
        raise _fail("final-CPL report does not match its closed shape")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise _fail("final-CPL report schema version is invalid")
    if value["scope"] != FINAL_CPL_SCOPE:
        raise _fail("final-CPL report scope is invalid")
    engine = _engine_text(value["engine_version"], "final-CPL engine version")
    if expected_engine is not None and engine != expected_engine:
        raise _fail("final-CPL engine identity does not match composed evidence")
    if value["board_basename"] != capture.board_name:
        raise _fail("final-CPL report board basename is invalid")

    raw_sources = value["sources"]
    if (
        not isinstance(raw_sources, Mapping)
        or set(raw_sources) != _FINAL_CPL_SOURCE_KEYS
    ):
        raise _fail("final-CPL report sources are invalid")
    sources = {
        "board": _validate_identity(
            raw_sources["board"], "final-CPL board", MAXIMUM_BOARD_BYTES
        ),
        "manufacturing_package": _validate_identity(
            raw_sources["manufacturing_package"],
            "final-CPL manufacturing package",
            MAXIMUM_PACKAGE_BYTES,
        ),
        "manifest": _validate_identity(
            raw_sources["manifest"], "final-CPL manifest", MAXIMUM_MANIFEST_BYTES
        ),
        "cpl": _validate_identity(
            raw_sources["cpl"], "final-CPL source CPL", MAXIMUM_PACKAGE_BYTES
        ),
        "canonical_cpl": _validate_identity(
            raw_sources["canonical_cpl"],
            "final-CPL canonical CPL",
            MAXIMUM_PACKAGE_BYTES,
        ),
        "package_board_source": _validate_identity(
            raw_sources["package_board_source"],
            "final-CPL package board source",
            MAXIMUM_BOARD_BYTES,
        ),
    }
    if sources["board"] != capture.board.identity:
        raise _fail("final-CPL report board identity is invalid")
    if sources["manufacturing_package"] != capture.package.identity:
        raise _fail("final-CPL report manufacturing-package identity is invalid")

    raw_counts = value["counts"]
    if not isinstance(raw_counts, Mapping) or set(raw_counts) != _FINAL_CPL_COUNT_KEYS:
        raise _fail("final-CPL report counts are invalid")
    counts = {
        "board_parts": _integer(
            raw_counts["board_parts"],
            "final-CPL board part count",
            minimum=0,
            maximum=MAXIMUM_PARTS,
        ),
        "board_in_pos_parts": _integer(
            raw_counts["board_in_pos_parts"],
            "final-CPL board placement count",
            minimum=0,
            maximum=MAXIMUM_REFERENCES,
        ),
        "package_parts": _integer(
            raw_counts["package_parts"],
            "final-CPL package part count",
            minimum=0,
            maximum=MAXIMUM_PARTS,
        ),
        "package_placement_parts": _integer(
            raw_counts["package_placement_parts"],
            "final-CPL package placement count",
            minimum=0,
            maximum=MAXIMUM_PARTS,
        ),
        "findings": _integer(
            raw_counts["findings"],
            "final-CPL finding count",
            minimum=0,
            maximum=2,
        ),
    }
    if (
        counts["board_in_pos_parts"] > counts["board_parts"]
        or counts["package_placement_parts"] > counts["package_parts"]
    ):
        raise _fail("final-CPL report counts are inconsistent")

    raw_parts = value["in_pos_parts"]
    if not isinstance(raw_parts, list) or len(raw_parts) > MAXIMUM_REFERENCES:
        raise _fail("final-CPL report placements are invalid")
    parts: list[dict[str, Any]] = []
    previous_reference: str | None = None
    for raw_part in raw_parts:
        if not isinstance(raw_part, Mapping) or set(raw_part) != _FINAL_CPL_PART_KEYS:
            raise _fail("final-CPL report placement is invalid")
        reference = _text(
            raw_part["reference"],
            "final-CPL placement reference",
            maximum=MAXIMUM_REFERENCE_BYTES,
        )
        if previous_reference is not None and reference <= previous_reference:
            raise _fail("final-CPL placement references are not strictly sorted")
        previous_reference = reference
        layer = raw_part["layer"]
        if layer not in {"F", "B"}:
            raise _fail("final-CPL placement layer is invalid")
        parts.append(
            {
                "reference": reference,
                "x_nm": _integer(
                    raw_part["x_nm"],
                    "final-CPL placement X coordinate",
                    minimum=-(2**63),
                    maximum=2**63 - 1,
                ),
                "y_nm": _integer(
                    raw_part["y_nm"],
                    "final-CPL placement Y coordinate",
                    minimum=-(2**63),
                    maximum=2**63 - 1,
                ),
                "rotation_mdeg": _integer(
                    raw_part["rotation_mdeg"],
                    "final-CPL placement rotation",
                    minimum=-(2**63),
                    maximum=2**63 - 1,
                ),
                "layer": layer,
            }
        )
    if len(parts) != counts["board_in_pos_parts"]:
        raise _fail("final-CPL report placement count is inconsistent")

    raw_findings = value["findings"]
    if not isinstance(raw_findings, list) or len(raw_findings) > 2:
        raise _fail("final-CPL report findings are invalid")
    findings: list[dict[str, str]] = []
    prior_code: str | None = None
    for raw_finding in raw_findings:
        if (
            not isinstance(raw_finding, Mapping)
            or set(raw_finding) != {"code", "message"}
        ):
            raise _fail("final-CPL report finding is invalid")
        code = raw_finding["code"]
        if code not in _FINAL_CPL_FINDING_MESSAGES:
            raise _fail("final-CPL report finding code is invalid")
        if raw_finding["message"] != _FINAL_CPL_FINDING_MESSAGES[code]:
            raise _fail("final-CPL report finding message is invalid")
        if prior_code is not None and code <= prior_code:
            raise _fail("final-CPL report findings are not strictly sorted")
        prior_code = code
        findings.append({"code": code, "message": raw_finding["message"]})
    if len(findings) != counts["findings"]:
        raise _fail("final-CPL report finding count is inconsistent")
    approved = value["approved"]
    if not isinstance(approved, bool) or approved != (not findings):
        raise _fail("final-CPL report approval state is inconsistent")
    codes = {finding["code"] for finding in findings}
    if (
        (sources["cpl"] != sources["canonical_cpl"])
        != ("canonical_cpl_mismatch" in codes)
    ):
        raise _fail("final-CPL canonical-CPL finding is inconsistent")
    if (
        (sources["board"] != sources["package_board_source"])
        != ("package_board_source_mismatch" in codes)
    ):
        raise _fail("final-CPL package-board-source finding is inconsistent")
    if (
        sources["cpl"] == sources["canonical_cpl"]
        and counts["board_in_pos_parts"] != counts["package_placement_parts"]
    ):
        raise _fail("final-CPL canonical-CPL placement count is inconsistent")
    if (
        sources["board"] == sources["package_board_source"]
        and counts["board_parts"] != counts["package_parts"]
    ):
        raise _fail("final-CPL package-board part count is inconsistent")

    return {
        "schema_version": 1,
        "scope": FINAL_CPL_SCOPE,
        "engine_version": engine,
        "board_basename": capture.board_name,
        "sources": sources,
        "counts": counts,
        "in_pos_parts": parts,
        "findings": findings,
        "approved": approved,
    }


def _render_normalized_final_cpl_report(value: Mapping[str, Any]) -> bytes:
    """Render the already-normalized report exactly like Rust serde_json pretty."""

    try:
        # ``_validate_final_cpl_report`` constructs this mapping in the Rust
        # struct field order, including every nested struct.  serde_json's
        # pretty formatter and this encoder both use two-space indentation and
        # retain UTF-8 rather than ASCII-escaping it.
        encoder = json.JSONEncoder(
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
        )
        output = bytearray()
        for chunk in encoder.iterencode(value):
            encoded = str.encode(chunk, "utf-8", "strict")
            if len(output) + len(encoded) + 1 > MAXIMUM_FINAL_CPL_REPORT_BYTES:
                raise _fail("final-CPL report exceeds its byte bound")
            output.extend(encoded)
        output.append(0x0A)
        return bytes(output)
    except AssemblyEvidenceError:
        raise
    except (TypeError, ValueError, UnicodeError, RuntimeError, RecursionError):
        raise _fail("final-CPL report cannot be serialized") from None


def _named_identity(value: Any, label: str, maximum: int) -> tuple[str, dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != {"name", "bytes", "sha256"}:
        raise _fail(f"{label} identity is invalid")
    name = value["name"]
    if not isinstance(name, str):
        raise _fail(f"{label} name is invalid")
    identity = _validate_identity(
        {"bytes": value["bytes"], "sha256": value["sha256"]}, label, maximum
    )
    return name, identity


def _cross_bind_and_compose(
    capture: _AssemblyCapture,
    generation_raw: bytes,
    circuit_manufacturing: Mapping[str, Any],
    procurement: Mapping[str, Any],
    final_cpl: Mapping[str, Any],
) -> dict[str, Any]:
    """Apply every hard H/G/B/M, count, basename, engine, and ref binding."""

    if (
        not isinstance(circuit_manufacturing, Mapping)
        or circuit_manufacturing.get("schema_version") != 6
        or circuit_manufacturing.get("verification_scope")
        != _handoff.CIRCUIT_HANDOFF_BUNDLE_MANUFACTURING_REPLAY_SCOPE
    ):
        raise _fail("circuit-manufacturing replay did not return exact v6 evidence")
    handoff_identity = _validate_identity(
        circuit_manufacturing.get("archive"),
        "circuit-manufacturing handoff archive",
        MAXIMUM_HANDOFF_BYTES,
    )
    if handoff_identity != capture.handoff.identity:
        raise _fail("circuit-manufacturing handoff archive is not cross-bound")
    artifacts = circuit_manufacturing.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise _fail("circuit-manufacturing artifacts are invalid")
    generation_name, replay_generation_identity = _named_identity(
        artifacts.get("generation_bundle"),
        "circuit-manufacturing generation bundle",
        _handoff.MAX_GENERATION_BUNDLE_BYTES,
    )
    generation_identity = _identity(generation_raw)
    if (
        generation_name != _handoff.GENERATION_BUNDLE_NAME
        or replay_generation_identity != generation_identity
    ):
        raise _fail("handoff generation bundle is not cross-bound")

    engine = _engine_text(
        circuit_manufacturing.get("engine_version"),
        "circuit-manufacturing engine version",
    )
    board_binding = circuit_manufacturing.get("board_binding")
    manufacturing = circuit_manufacturing.get("manufacturing_package")
    if not isinstance(board_binding, Mapping) or not isinstance(manufacturing, Mapping):
        raise _fail("circuit-manufacturing child evidence is invalid")
    if board_binding.get("engine_version") != engine:
        raise _fail("board-binding engine identity is not cross-bound")
    if board_binding.get("approval_required") is not False:
        raise _fail("board-binding replay unexpectedly applied an approval gate")
    board_binding_board = _validate_identity(
        board_binding.get("board"), "board-binding board", MAXIMUM_BOARD_BYTES
    )
    board_binding_report = _validate_identity(
        board_binding.get("report"),
        "board-binding report",
        MAXIMUM_BOARD_BINDING_REPORT_BYTES,
    )
    if board_binding_board != capture.board.identity:
        raise _fail("board-binding board is not cross-bound")
    if board_binding_report != capture.board_binding_report.identity:
        raise _fail("board-binding report is not cross-bound")

    manufacturing_board_name, manufacturing_board = _named_identity(
        manufacturing.get("board"),
        "manufacturing replay board",
        MAXIMUM_BOARD_BYTES,
    )
    package = manufacturing.get("package")
    if not isinstance(package, Mapping) or set(package) != {"retained", "fresh", "identical"}:
        raise _fail("manufacturing replay package identity is invalid")
    retained_package = _validate_identity(
        package["retained"], "manufacturing retained package", MAXIMUM_PACKAGE_BYTES
    )
    fresh_package = _validate_identity(
        package["fresh"], "manufacturing fresh package", MAXIMUM_PACKAGE_BYTES
    )
    if (
        manufacturing_board_name != capture.board_name
        or manufacturing_board != capture.board.identity
        or retained_package != capture.package.identity
        or fresh_package != capture.package.identity
        or package["identical"] is not True
    ):
        raise _fail("manufacturing replay sources are not cross-bound")

    if not isinstance(procurement, Mapping):
        raise _fail("procurement-intent replay result is invalid")
    procurement_sources = procurement.get("sources")
    final_bom = procurement.get("final_bom")
    if not isinstance(procurement_sources, Mapping) or not isinstance(final_bom, Mapping):
        raise _fail("procurement-intent source evidence is invalid")
    procurement_board_name, procurement_board = _named_identity(
        procurement_sources.get("board"), "procurement board", MAXIMUM_BOARD_BYTES
    )
    for key, observed, expected, maximum in (
        ("manufacturing_package", procurement_sources.get("manufacturing_package"), capture.package.identity, MAXIMUM_PACKAGE_BYTES),
        ("generation_bundle", procurement_sources.get("generation_bundle"), generation_identity, _handoff.MAX_GENERATION_BUNDLE_BYTES),
        ("catalog_snapshot", procurement_sources.get("catalog_snapshot"), capture.catalog_snapshot.identity, MAX_CATALOG_RAW_BYTES),
    ):
        if _validate_identity(observed, f"procurement {key}", maximum) != expected:
            raise _fail(f"procurement {key} is not cross-bound")
    if procurement_board_name != capture.board_name or procurement_board != capture.board.identity:
        raise _fail("procurement board is not cross-bound")
    if final_bom.get("scope") != FINAL_BOM_SCOPE:
        raise _fail("procurement final-BOM scope is invalid")
    if final_bom.get("engine_version") != engine:
        raise _fail("final-BOM engine identity is not cross-bound")
    if final_bom.get("board_basename") != capture.board_name:
        raise _fail("final-BOM board basename is not cross-bound")
    final_bom_sources = final_bom.get("sources")
    if not isinstance(final_bom_sources, Mapping):
        raise _fail("final-BOM sources are invalid")
    if _validate_identity(final_bom_sources.get("board"), "final-BOM board", MAXIMUM_BOARD_BYTES) != capture.board.identity:
        raise _fail("final-BOM board is not cross-bound")
    if _validate_identity(final_bom_sources.get("manufacturing_package"), "final-BOM package", MAXIMUM_PACKAGE_BYTES) != capture.package.identity:
        raise _fail("final-BOM package is not cross-bound")

    if final_cpl.get("engine_version") != engine:
        raise _fail("final-CPL engine identity is not cross-bound")
    if final_cpl.get("board_basename") != capture.board_name:
        raise _fail("final-CPL board basename is not cross-bound")
    final_cpl_sources = final_cpl["sources"]
    for key, maximum in (
        ("manifest", MAXIMUM_MANIFEST_BYTES),
        ("package_board_source", MAXIMUM_BOARD_BYTES),
    ):
        bom_value = _validate_identity(final_bom_sources.get(key), f"final-BOM {key}", maximum)
        cpl_value = _validate_identity(final_cpl_sources.get(key), f"final-CPL {key}", maximum)
        procurement_value = _validate_identity(procurement_sources.get(key), f"procurement {key}", maximum)
        if bom_value != cpl_value or bom_value != procurement_value:
            raise _fail(f"final-BOM and final-CPL {key} identities are not cross-bound")

    bom_counts = final_bom.get("counts")
    cpl_counts = final_cpl.get("counts")
    if not isinstance(bom_counts, Mapping) or not isinstance(cpl_counts, Mapping):
        raise _fail("final-BOM/final-CPL counts are invalid")
    if (
        bom_counts.get("board_parts") != cpl_counts.get("board_parts")
        or bom_counts.get("package_parts") != cpl_counts.get("package_parts")
    ):
        raise _fail("final-BOM and final-CPL part counts are not cross-bound")

    raw_bom_parts = final_bom.get("in_bom_parts")
    raw_cpl_parts = final_cpl.get("in_pos_parts")
    if (
        not isinstance(raw_bom_parts, list)
        or not isinstance(raw_cpl_parts, list)
        or len(raw_bom_parts) > MAXIMUM_REFERENCES
        or len(raw_cpl_parts) > MAXIMUM_REFERENCES
    ):
        raise _fail("final-BOM/final-CPL reference inventories are invalid")
    try:
        bom_parts = {part["reference"]: part for part in raw_bom_parts}
        cpl_parts = {part["reference"]: part for part in raw_cpl_parts}
    except (KeyError, TypeError):
        raise _fail("final-BOM/final-CPL reference inventories are invalid") from None
    if len(bom_parts) != len(raw_bom_parts) or len(cpl_parts) != len(raw_cpl_parts):
        raise _fail("final-BOM/final-CPL references are not unique")
    for reference in sorted(set(bom_parts) & set(cpl_parts)):
        bom_part = bom_parts[reference]
        cpl_part = cpl_parts[reference]
        if bom_part.get("type") != "SMD" or bom_part.get("layer") != cpl_part.get("layer"):
            raise _fail("common final-BOM/final-CPL assembly metadata is inconsistent")

    membership = {
        "both": sorted(set(bom_parts) & set(cpl_parts)),
        "bom_only": sorted(set(bom_parts) - set(cpl_parts)),
        "cpl_only": sorted(set(cpl_parts) - set(bom_parts)),
    }
    finding_codes: list[str] = []
    if board_binding.get("approved") is not True:
        if board_binding.get("approved") is not False:
            raise _fail("board-binding approval state is invalid")
        finding_codes.append("board_binding_rejected")
    if procurement.get("approved") is not True:
        if procurement.get("approved") is not False:
            raise _fail("procurement-intent approval state is invalid")
        finding_codes.append("procurement_intent_rejected")
    if final_cpl.get("approved") is not True:
        if final_cpl.get("approved") is not False:
            raise _fail("final-CPL approval state is invalid")
        finding_codes.append("final_cpl_rejected")
    findings = [
        {"code": code, "message": _ASSEMBLY_FINDING_MESSAGES[code]}
        for code in sorted(finding_codes)
    ]
    complete = not findings

    final_bom_projection = {
        key: copy.deepcopy(value)
        for key, value in final_bom.items()
        if key != "in_bom_parts"
    }
    procurement_projection = {
        key: copy.deepcopy(value)
        for key, value in procurement.items()
        if key not in {"final_bom", "binding_sha256"}
    }
    sources = {
        "circuit_handoff_bundle": capture.handoff.identity,
        "handoff_generation_bundle": generation_identity,
        "board": {"name": capture.board_name, **capture.board.identity},
        "manufacturing_package": capture.package.identity,
        "board_binding_report": capture.board_binding_report.identity,
        "procurement_intent": capture.procurement_intent.identity,
        "catalog_snapshot": capture.catalog_snapshot.identity,
        "final_cpl_report": capture.final_cpl_report.identity,
    }
    validation = {
        "handoff_archive_validated": True,
        "circuit_manufacturing_replayed": True,
        "procurement_intent_replayed": True,
        "final_cpl_replayed": True,
        "cross_bindings_matched": True,
        "membership_partitioned": True,
        "caller_inputs_unchanged": True,
    }
    result: dict[str, Any] = {
        "schema_version": ASSEMBLY_EVIDENCE_SCHEMA_VERSION,
        "scope": ASSEMBLY_EVIDENCE_SCOPE,
        "status": "complete" if complete else "incomplete",
        "complete": complete,
        "quantity_basis": "per_board",
        "assembly_ready": False,
        "assembly_authorized": False,
        "fabrication_authorized": False,
        "procurement_authorized": False,
        "order_placed": False,
        "adapter_network_performed": False,
        "machine_operation_performed": False,
        "sources": sources,
        "circuit_manufacturing": copy.deepcopy(dict(circuit_manufacturing)),
        "final_bom": final_bom_projection,
        "procurement": procurement_projection,
        "final_cpl": copy.deepcopy(dict(final_cpl)),
        "membership": membership,
        "findings": findings,
        "validation": validation,
    }
    result["binding_sha256"] = _sha256(
        ASSEMBLY_EVIDENCE_BINDING_DOMAIN + _compact_json(result)
    )
    return result


_ASSEMBLY_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "scope",
        "status",
        "complete",
        "quantity_basis",
        "assembly_ready",
        "assembly_authorized",
        "fabrication_authorized",
        "procurement_authorized",
        "order_placed",
        "adapter_network_performed",
        "machine_operation_performed",
        "sources",
        "circuit_manufacturing",
        "final_bom",
        "procurement",
        "final_cpl",
        "membership",
        "findings",
        "validation",
        "binding_sha256",
    }
)
_ASSEMBLY_VALIDATION_KEYS = frozenset(
    {
        "handoff_archive_validated",
        "circuit_manufacturing_replayed",
        "procurement_intent_replayed",
        "final_cpl_replayed",
        "cross_bindings_matched",
        "membership_partitioned",
        "caller_inputs_unchanged",
    }
)
_ASSEMBLY_SOURCE_KEYS = frozenset(
    {
        "circuit_handoff_bundle",
        "handoff_generation_bundle",
        "board",
        "manufacturing_package",
        "board_binding_report",
        "procurement_intent",
        "catalog_snapshot",
        "final_cpl_report",
    }
)


def _validate_structural_schema(value: Any, schema: Mapping[str, Any]) -> None:
    """Validate the bounded plain snapshot against our emitted schema subset.

    This avoids a runtime dependency on ``jsonschema`` while keeping the
    renderer closed over every nested child contract.  The input has already
    passed the 32 MiB/depth-bounded one-pass snapshotter.
    """

    visited = 0
    unique_bytes_used = 0

    def fail() -> None:
        raise _fail("assembly-evidence report violates its structural schema")

    def matches(item: Any, rule: Mapping[str, Any], depth: int) -> bool:
        try:
            check(item, rule, depth)
        except AssemblyEvidenceError:
            return False
        return True

    def check(item: Any, rule: Mapping[str, Any], depth: int) -> None:
        nonlocal visited, unique_bytes_used
        visited += 1
        if visited > 1_000_000 or depth > 256:
            fail()
        if "allOf" in rule:
            for child in rule["allOf"]:
                check(item, child, depth + 1)
        if "anyOf" in rule and not any(
            matches(item, child, depth + 1) for child in rule["anyOf"]
        ):
            fail()
        if "oneOf" in rule and sum(
            matches(item, child, depth + 1) for child in rule["oneOf"]
        ) != 1:
            fail()
        if "not" in rule and matches(item, rule["not"], depth + 1):
            fail()
        if "if" in rule and matches(item, rule["if"], depth + 1):
            then = rule.get("then")
            if isinstance(then, Mapping):
                check(item, then, depth + 1)

        expected_type = rule.get("type")
        if expected_type is not None:
            type_matches = {
                "object": isinstance(item, Mapping),
                "array": isinstance(item, list),
                "string": type(item) is str,
                "integer": type(item) is int,
                "boolean": type(item) is bool,
                "null": item is None,
                "number": type(item) in {int, float},
            }
            if isinstance(expected_type, list):
                if not any(type_matches.get(name, False) for name in expected_type):
                    fail()
            elif not type_matches.get(expected_type, False):
                fail()
        if "const" in rule and not _strict_json_equal(item, rule["const"]):
            fail()
        if "enum" in rule and not any(
            _strict_json_equal(item, choice) for choice in rule["enum"]
        ):
            fail()

        if isinstance(item, Mapping):
            required = rule.get("required", [])
            if any(key not in item for key in required):
                fail()
            properties = rule.get("properties", {})
            if rule.get("additionalProperties") is False and any(
                key not in properties for key in item
            ):
                fail()
            for key, child in properties.items():
                if key in item:
                    check(item[key], child, depth + 1)
        if isinstance(item, list):
            if len(item) < rule.get("minItems", 0):
                fail()
            maximum_items = rule.get("maxItems")
            if maximum_items is not None and len(item) > maximum_items:
                fail()
            if rule.get("uniqueItems") is True:
                seen: set[bytes] = set()
                for child in item:
                    encoded = _compact_json(child)
                    unique_bytes_used += len(encoded)
                    if unique_bytes_used > MAXIMUM_ASSEMBLY_EVIDENCE_BYTES:
                        fail()
                    if encoded in seen:
                        fail()
                    seen.add(encoded)
            child_rule = rule.get("items")
            if isinstance(child_rule, Mapping):
                for child in item:
                    check(child, child_rule, depth + 1)
        if type(item) is str:
            if len(item) < rule.get("minLength", 0):
                fail()
            maximum_length = rule.get("maxLength")
            if maximum_length is not None and len(item) > maximum_length:
                fail()
            pattern = rule.get("pattern")
            if pattern is not None:
                matched = (
                    re.fullmatch(pattern, item)
                    if pattern.startswith("^") and pattern.endswith("$")
                    else re.search(pattern, item)
                )
                if matched is None:
                    fail()
        if type(item) in {int, float}:
            minimum = rule.get("minimum")
            maximum = rule.get("maximum")
            if minimum is not None and item < minimum:
                fail()
            if maximum is not None and item > maximum:
                fail()

    check(value, schema, 0)


def _validate_final_bom_projection(
    value: Any,
    *,
    board_name: str,
    board_identity: Mapping[str, Any],
    package_identity: Mapping[str, Any],
    engine: str,
) -> dict[str, Any]:
    expected_keys = _procurement._FINAL_BOM_KEYS - {"in_bom_parts"}
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        raise _fail("assembly final-BOM projection is invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["scope"] != FINAL_BOM_SCOPE
        or value["engine_version"] != engine
        or value["board_basename"] != board_name
    ):
        raise _fail("assembly final-BOM identity is invalid")
    sources_value = value["sources"]
    if (
        not isinstance(sources_value, Mapping)
        or set(sources_value) != _procurement._FINAL_BOM_SOURCE_KEYS
    ):
        raise _fail("assembly final-BOM sources are invalid")
    sources = {
        "board": _validate_identity(sources_value["board"], "final-BOM board", MAXIMUM_BOARD_BYTES),
        "manufacturing_package": _validate_identity(sources_value["manufacturing_package"], "final-BOM package", MAXIMUM_PACKAGE_BYTES),
        "manifest": _validate_identity(sources_value["manifest"], "final-BOM manifest", MAXIMUM_MANIFEST_BYTES),
        "bom": _validate_identity(sources_value["bom"], "final-BOM BOM", MAXIMUM_PACKAGE_BYTES),
        "canonical_bom": _validate_identity(sources_value["canonical_bom"], "final-BOM canonical BOM", MAXIMUM_PACKAGE_BYTES),
        "package_board_source": _validate_identity(sources_value["package_board_source"], "final-BOM package board source", MAXIMUM_BOARD_BYTES),
    }
    if sources["board"] != board_identity or sources["manufacturing_package"] != package_identity:
        raise _fail("assembly final-BOM sources are not cross-bound")
    counts_value = value["counts"]
    if (
        not isinstance(counts_value, Mapping)
        or set(counts_value) != _procurement._FINAL_BOM_COUNT_KEYS
    ):
        raise _fail("assembly final-BOM counts are invalid")
    counts = {
        "board_parts": _integer(counts_value["board_parts"], "final-BOM board parts", minimum=0, maximum=MAXIMUM_PARTS),
        "board_in_bom_parts": _integer(counts_value["board_in_bom_parts"], "final-BOM board BOM parts", minimum=0, maximum=MAXIMUM_REFERENCES),
        "package_parts": _integer(counts_value["package_parts"], "final-BOM package parts", minimum=0, maximum=MAXIMUM_PARTS),
        "package_in_bom_parts": _integer(counts_value["package_in_bom_parts"], "final-BOM package BOM parts", minimum=0, maximum=MAXIMUM_PARTS),
        "findings": _integer(counts_value["findings"], "final-BOM findings", minimum=0, maximum=2),
    }
    if counts["board_in_bom_parts"] > counts["board_parts"] or counts["package_in_bom_parts"] > counts["package_parts"]:
        raise _fail("assembly final-BOM counts are inconsistent")
    raw_findings = value["findings"]
    if not isinstance(raw_findings, list) or len(raw_findings) > 2:
        raise _fail("assembly final-BOM findings are invalid")
    findings: list[dict[str, str]] = []
    prior: str | None = None
    for finding in raw_findings:
        if not isinstance(finding, Mapping) or set(finding) != {"code", "message"}:
            raise _fail("assembly final-BOM finding is invalid")
        code = finding["code"]
        if code not in _procurement._FINAL_BOM_FINDING_MESSAGES or finding["message"] != _procurement._FINAL_BOM_FINDING_MESSAGES[code]:
            raise _fail("assembly final-BOM finding is invalid")
        if prior is not None and code <= prior:
            raise _fail("assembly final-BOM findings are not strictly sorted")
        prior = code
        findings.append({"code": code, "message": finding["message"]})
    approved = value["approved"]
    if (
        not isinstance(approved, bool)
        or approved != (not findings)
        or counts["findings"] != len(findings)
    ):
        raise _fail("assembly final-BOM approval is inconsistent")
    codes = {finding["code"] for finding in findings}
    if (sources["bom"] != sources["canonical_bom"]) != ("canonical_bom_mismatch" in codes):
        raise _fail("assembly final-BOM canonical finding is inconsistent")
    if (sources["board"] != sources["package_board_source"]) != ("package_board_source_mismatch" in codes):
        raise _fail("assembly final-BOM board-source finding is inconsistent")
    if (
        sources["bom"] == sources["canonical_bom"]
        and counts["board_in_bom_parts"] != counts["package_in_bom_parts"]
    ):
        raise _fail("assembly final-BOM canonical-BOM part count is inconsistent")
    if (
        sources["board"] == sources["package_board_source"]
        and counts["board_parts"] != counts["package_parts"]
    ):
        raise _fail("assembly final-BOM package-board part count is inconsistent")
    return {
        "schema_version": 1,
        "scope": FINAL_BOM_SCOPE,
        "engine_version": engine,
        "board_basename": board_name,
        "sources": sources,
        "counts": counts,
        "findings": findings,
        "approved": approved,
    }


def _validate_assembly_result(value: Any) -> None:
    """Validate one bounded path-free report's structure and self-consistency."""

    _validate_structural_schema(value, assembly_evidence_json_schema())
    if not isinstance(value, Mapping) or set(value) != _ASSEMBLY_RESULT_KEYS:
        raise _fail("assembly-evidence report does not match its closed shape")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != ASSEMBLY_EVIDENCE_SCHEMA_VERSION
        or value["scope"] != ASSEMBLY_EVIDENCE_SCOPE
        or value["quantity_basis"] != "per_board"
    ):
        raise _fail("assembly-evidence report identity is invalid")
    for key in (
        "assembly_ready",
        "assembly_authorized",
        "fabrication_authorized",
        "procurement_authorized",
        "order_placed",
        "adapter_network_performed",
        "machine_operation_performed",
    ):
        if value[key] is not False:
            raise _fail("assembly-evidence report contains an invalid authority claim")
    validation = value["validation"]
    if (
        not isinstance(validation, Mapping)
        or set(validation) != _ASSEMBLY_VALIDATION_KEYS
        or any(validation[key] is not True for key in _ASSEMBLY_VALIDATION_KEYS)
    ):
        raise _fail("assembly-evidence validation state is invalid")

    sources_value = value["sources"]
    if not isinstance(sources_value, Mapping) or set(sources_value) != _ASSEMBLY_SOURCE_KEYS:
        raise _fail("assembly-evidence sources are invalid")
    handoff_identity = _validate_identity(sources_value["circuit_handoff_bundle"], "assembly handoff", MAXIMUM_HANDOFF_BYTES)
    generation_identity = _validate_identity(sources_value["handoff_generation_bundle"], "assembly generation bundle", _handoff.MAX_GENERATION_BUNDLE_BYTES)
    board_name, board_identity = _named_identity(sources_value["board"], "assembly board", MAXIMUM_BOARD_BYTES)
    if _portable_leaf(board_name, "assembly board", ".kicad_pcb") != board_name:
        raise _fail("assembly board basename is invalid")
    package_identity = _validate_identity(sources_value["manufacturing_package"], "assembly package", MAXIMUM_PACKAGE_BYTES)
    board_report_identity = _validate_identity(sources_value["board_binding_report"], "assembly board-binding report", MAXIMUM_BOARD_BINDING_REPORT_BYTES)
    _validate_identity(sources_value["procurement_intent"], "assembly procurement intent", MAXIMUM_PROCUREMENT_INTENT_BYTES)
    catalog_identity = _validate_identity(sources_value["catalog_snapshot"], "assembly catalog snapshot", MAX_CATALOG_RAW_BYTES)
    final_cpl_report_identity = _validate_identity(
        sources_value["final_cpl_report"],
        "assembly final-CPL report",
        MAXIMUM_FINAL_CPL_REPORT_BYTES,
    )

    circuit = value["circuit_manufacturing"]
    v6_schema = _handoff.circuit_handoff_bundle_manufacturing_replay_result_json_schema()
    if (
        not isinstance(circuit, Mapping)
        or set(circuit) != set(v6_schema["required"])
        or type(circuit.get("schema_version")) is not int
        or circuit.get("schema_version") != 6
        or circuit.get("verified") is not True
        or circuit.get("replayed") is not True
        or circuit.get("operation") != "replay"
        or circuit.get("verification_scope") != _handoff.CIRCUIT_HANDOFF_BUNDLE_MANUFACTURING_REPLAY_SCOPE
    ):
        raise _fail("assembly circuit-manufacturing evidence is invalid")
    if _validate_identity(circuit.get("archive"), "assembly nested handoff", MAXIMUM_HANDOFF_BYTES) != handoff_identity:
        raise _fail("assembly handoff identity is not cross-bound")
    artifacts = circuit.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise _fail("assembly circuit artifacts are invalid")
    artifact_identities: dict[str, dict[str, Any]] = {}
    for role, expected_name in _handoff._ARTIFACT_NAMES.items():
        artifact_name, artifact_identity = _named_identity(
            artifacts.get(role),
            f"assembly nested {role} artifact",
            _handoff._ARTIFACT_LIMITS[role],
        )
        if artifact_name != expected_name:
            raise _fail("assembly circuit artifact name is inconsistent")
        artifact_identities[role] = artifact_identity
    nested_generation = artifact_identities["generation_bundle"]
    if nested_generation != generation_identity:
        raise _fail("assembly generation identity is not cross-bound")
    manifest_name, manifest_identity = _named_identity(
        circuit.get("manifest"),
        "assembly nested handoff manifest",
        _handoff.MAX_NATIVE_CHECK_BYTES,
    )
    if manifest_name != _handoff.MANIFEST_NAME:
        raise _fail("assembly handoff manifest name is inconsistent")
    manifest_shape = {
        "schema_version": _handoff.CIRCUIT_HANDOFF_BUNDLE_SCHEMA_VERSION,
        "adapter": _handoff.CIRCUIT_HANDOFF_BUNDLE_ADAPTER,
        "engine_version": circuit.get("engine_version"),
        "artifacts": {
            role: {
                "name": expected_name,
                **artifact_identities[role],
            }
            for role, expected_name in _handoff._ARTIFACT_NAMES.items()
        },
        # These values are omitted from the v6 projection, but every valid
        # value is exactly 64 ASCII bytes, so placeholders reproduce the exact
        # canonical manifest byte length without claiming their identities.
        "circuit_spec_sha256": "0" * 64,
        "electrical_review_sha256": "0" * 64,
        "policy_sha256": "0" * 64,
        "approved": True,
        "bundle_sha256": circuit.get("bundle_sha256"),
    }
    try:
        expected_manifest_bytes = len(
            (
                json.dumps(
                    manifest_shape,
                    indent=2,
                    ensure_ascii=False,
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8", errors="strict")
        )
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise _fail("assembly handoff manifest cannot be serialized") from None
    if manifest_identity["bytes"] != expected_manifest_bytes:
        raise _fail("assembly handoff manifest size is inconsistent")
    archive_overhead = 22 + sum(
        76 + 2 * len(name.encode("ascii"))
        for name in _handoff._ARCHIVE_ENTRY_NAMES
    )
    expected_archive_bytes = (
        manifest_identity["bytes"]
        + sum(identity["bytes"] for identity in artifact_identities.values())
        + archive_overhead
    )
    if handoff_identity["bytes"] != expected_archive_bytes:
        raise _fail("assembly handoff archive size is inconsistent")
    engine = _engine_text(circuit.get("engine_version"), "assembly engine version")
    board_binding = circuit.get("board_binding")
    manufacturing = circuit.get("manufacturing_package")
    if not isinstance(board_binding, Mapping) or not isinstance(manufacturing, Mapping):
        raise _fail("assembly nested replay evidence is invalid")
    expected_board_binding_keys = set(v6_schema["properties"]["board_binding"]["required"])
    expected_manufacturing_keys = set(v6_schema["properties"]["manufacturing_package"]["required"])
    if set(board_binding) != expected_board_binding_keys or set(manufacturing) != expected_manufacturing_keys:
        raise _fail("assembly nested replay evidence is not closed")
    manufacturing_validation = manufacturing.get("validation")
    expected_manufacturing_validation = set(
        v6_schema["properties"]["manufacturing_package"]["properties"][
            "validation"
        ]["required"]
    )
    if (
        manufacturing.get("verified") is not True
        or not isinstance(manufacturing_validation, Mapping)
        or set(manufacturing_validation) != expected_manufacturing_validation
        or any(
            manufacturing_validation.get(key) is not True
            for key in expected_manufacturing_validation
        )
    ):
        raise _fail("assembly manufacturing replay validation is invalid")
    manufacturing_profile = manufacturing.get("profile")
    if (
        isinstance(manufacturing_profile, Mapping)
        and manufacturing_profile.get("kind") == "builtin"
        and (
            not isinstance(manufacturing_profile.get("id"), str)
            or _manufacturing._BUILTIN_PROFILE_ID.fullmatch(
                manufacturing_profile.get("id")
            )
            is None
        )
    ):
        raise _fail("assembly manufacturing built-in profile is invalid")
    if (
        isinstance(manufacturing_profile, Mapping)
        and manufacturing_profile.get("kind") in {"dfm-file", "physical-file"}
    ):
        profile_source = manufacturing_profile.get("source")
        if (
            not isinstance(profile_source, Mapping)
            or not _manufacturing._portable_leaf(profile_source.get("name"))
        ):
            raise _fail("assembly manufacturing profile basename is invalid")
    circuit_validation = circuit.get("validation")
    expected_circuit_validation = set(v6_schema["properties"]["validation"]["required"])
    if (
        not isinstance(circuit_validation, Mapping)
        or set(circuit_validation) != expected_circuit_validation
        or any(
            circuit_validation.get(key) is not True
            for key in (
                "internal_consistency",
                "archive_reproduced",
                "native_handoff_replayed",
                "board_binding_replayed",
                "manufacturing_package_replayed",
                "manufacturing_board_identity_matched",
            )
        )
    ):
        raise _fail("assembly circuit-manufacturing validation is invalid")
    expected = circuit.get("expected")
    if not isinstance(expected, Mapping):
        raise _fail("assembly expected handoff identity is invalid")
    expected_archive = expected.get("archive_sha256")
    expected_bundle = expected.get("bundle_sha256")
    expected_identity_matched = (
        expected_archive is not None or expected_bundle is not None
    )
    if (
        circuit_validation.get("expected_identity_matched")
        is not expected_identity_matched
        or (
            expected_archive is not None
            and expected_archive != handoff_identity["sha256"]
        )
        or (
            expected_bundle is not None
            and expected_bundle != circuit.get("bundle_sha256")
        )
    ):
        raise _fail("assembly expected handoff identity is inconsistent")
    if board_binding.get("engine_version") != engine or board_binding.get("approval_required") is not False:
        raise _fail("assembly board-binding engine/gate state is invalid")
    board_binding_counts = board_binding.get("counts")
    if (
        not isinstance(board_binding_counts, Mapping)
        or board_binding.get("approved")
        is not (board_binding_counts.get("errors") == 0)
    ):
        raise _fail("assembly board-binding approval is inconsistent")
    if _validate_identity(board_binding.get("board"), "assembly nested board", MAXIMUM_BOARD_BYTES) != board_identity:
        raise _fail("assembly board identity is not cross-bound")
    if _validate_identity(board_binding.get("report"), "assembly nested board report", MAXIMUM_BOARD_BINDING_REPORT_BYTES) != board_report_identity:
        raise _fail("assembly board-binding report is not cross-bound")
    nested_board_name, nested_board = _named_identity(manufacturing.get("board"), "assembly manufacturing board", MAXIMUM_BOARD_BYTES)
    package = manufacturing.get("package")
    if not isinstance(package, Mapping) or set(package) != {"retained", "fresh", "identical"}:
        raise _fail("assembly manufacturing package evidence is invalid")
    if (
        nested_board_name != board_name
        or nested_board != board_identity
        or _validate_identity(package["retained"], "assembly retained package", MAXIMUM_PACKAGE_BYTES) != package_identity
        or _validate_identity(package["fresh"], "assembly fresh package", MAXIMUM_PACKAGE_BYTES) != package_identity
        or package["identical"] is not True
    ):
        raise _fail("assembly manufacturing identities are not cross-bound")

    final_bom = _validate_final_bom_projection(
        value["final_bom"],
        board_name=board_name,
        board_identity=board_identity,
        package_identity=package_identity,
        engine=engine,
    )
    procurement = value["procurement"]
    procurement_required = set(_procurement.procurement_intent_json_schema()["required"]) - {
        "final_bom",
        "binding_sha256",
    }
    if not isinstance(procurement, Mapping) or set(procurement) != procurement_required:
        raise _fail("assembly procurement projection is invalid")
    if not isinstance(procurement.get("approved"), bool) or procurement.get("status") != ("approved" if procurement["approved"] else "rejected"):
        raise _fail("assembly procurement approval is inconsistent")
    if procurement.get("quantity_basis") != "per_board" or any(
        procurement.get(key) is not False
        for key in (
            "procurement_authorized",
            "network_performed",
            "order_placed",
            "current_availability_verified",
            "supplier_authenticity_verified",
        )
    ):
        raise _fail("assembly procurement nonclaim state is invalid")
    procurement_sources = procurement.get("sources")
    expected_procurement_source_keys = set(
        _procurement.procurement_intent_json_schema()["properties"]["sources"][
            "required"
        ]
    )
    if (
        not isinstance(procurement_sources, Mapping)
        or set(procurement_sources) != expected_procurement_source_keys
    ):
        raise _fail("assembly procurement sources are invalid")
    procurement_board_name, procurement_board = _named_identity(procurement_sources.get("board"), "assembly procurement board", MAXIMUM_BOARD_BYTES)
    if procurement_board_name != board_name or procurement_board != board_identity:
        raise _fail("assembly procurement board is not cross-bound")
    for key, expected, maximum in (
        ("manufacturing_package", package_identity, MAXIMUM_PACKAGE_BYTES),
        ("generation_bundle", generation_identity, _handoff.MAX_GENERATION_BUNDLE_BYTES),
        ("catalog_snapshot", catalog_identity, MAX_CATALOG_RAW_BYTES),
    ):
        if _validate_identity(procurement_sources.get(key), f"assembly procurement {key}", maximum) != expected:
            raise _fail(f"assembly procurement {key} is not cross-bound")
    procurement_catalog = procurement.get("catalog")
    if not isinstance(procurement_catalog, Mapping):
        raise _fail("assembly procurement catalog is invalid")
    catalog_supplier = _catalog_text(
        procurement_catalog.get("supplier"),
        "assembly procurement catalog supplier",
        maximum=64,
    )
    catalog_snapshot_id = _catalog_text(
        procurement_catalog.get("snapshot_id"),
        "assembly procurement catalog snapshot ID",
        maximum=128,
    )
    if (
        _procurement._SUPPLIER_RE.fullmatch(catalog_supplier) is None
        or _procurement._SNAPSHOT_ID_RE.fullmatch(catalog_snapshot_id) is None
        or catalog_snapshot_id in {".", ".."}
    ):
        raise _fail("assembly procurement catalog identity is invalid")
    if (
        not (
            procurement_catalog.get("captured_at_unix")
            <= procurement_catalog.get("evaluated_at_unix")
            <= procurement_catalog.get("expires_at_unix")
        )
        or (
            procurement_catalog.get("expires_at_unix")
            - procurement_catalog.get("captured_at_unix")
            > MAX_CATALOG_TTL_SECONDS
        )
    ):
        raise _fail("assembly procurement catalog timestamps are inconsistent")
    procurement_validation = procurement.get("validation")
    if not isinstance(procurement_validation, Mapping) or procurement_validation.get("final_bom_verified") != final_bom["approved"]:
        raise _fail("assembly procurement final-BOM state is inconsistent")
    raw_procurement_findings = procurement.get("findings")
    if not isinstance(raw_procurement_findings, list):
        raise _fail("assembly procurement findings are invalid")
    procurement_finding_codes: list[str] = []
    prior_procurement_code: str | None = None
    for finding in raw_procurement_findings:
        if not isinstance(finding, Mapping):
            raise _fail("assembly procurement finding is invalid")
        code = finding.get("code")
        if (
            code not in _procurement._PROCUREMENT_FINDING_MESSAGES
            or finding.get("message")
            != _procurement._PROCUREMENT_FINDING_MESSAGES[code]
            or (
                prior_procurement_code is not None
                and code <= prior_procurement_code
            )
        ):
            raise _fail("assembly procurement findings are not canonical")
        prior_procurement_code = code
        procurement_finding_codes.append(code)
    procurement_finding_set = set(procurement_finding_codes)
    if procurement["approved"] != (not procurement_finding_codes):
        raise _fail("assembly procurement approval/findings are inconsistent")
    if (
        ("final_bom_rejected" in procurement_finding_set)
        != (not procurement_validation.get("final_bom_verified"))
        or ("reference_set_mismatch" in procurement_finding_set)
        != (not procurement_validation.get("reference_sets_matched"))
    ):
        raise _fail("assembly procurement findings/validation are inconsistent")
    downstream_procurement_correlations = (
        ("part_value_mismatch", "part_values_matched"),
        ("footprint_mismatch", "part_footprints_matched"),
        ("mpn_mismatch", "part_mpns_matched"),
        ("supplier_part_number_missing", "supplier_part_numbers_present"),
        (
            "supplier_part_number_ambiguous",
            "supplier_part_numbers_unambiguous",
        ),
    )
    if procurement_validation.get("reference_sets_matched"):
        if any(
            (code in procurement_finding_set)
            != (not procurement_validation.get(flag))
            for code, flag in downstream_procurement_correlations
        ):
            raise _fail("assembly procurement findings/validation are inconsistent")
    elif any(
        procurement_validation.get(flag) is not False
        for _code, flag in downstream_procurement_correlations
    ):
        # The producer defines all downstream validation predicates as a
        # conjunction with exact reference-set equality.  Findings may still
        # be absent when only extra references caused that equality to fail.
        raise _fail("assembly procurement validation is inconsistent")
    for key, maximum in (
        ("final_bom_report", _procurement.MAXIMUM_FINAL_BOM_REPORT_BYTES),
        ("bom", MAXIMUM_PACKAGE_BYTES),
        ("canonical_bom", MAXIMUM_PACKAGE_BYTES),
    ):
        _validate_identity(
            procurement_sources.get(key), f"assembly procurement {key}", maximum
        )
    if (
        _validate_identity(
            procurement_sources.get("bom"),
            "assembly procurement BOM",
            MAXIMUM_PACKAGE_BYTES,
        )
        != final_bom["sources"]["bom"]
        or _validate_identity(
            procurement_sources.get("canonical_bom"),
            "assembly procurement canonical BOM",
            MAXIMUM_PACKAGE_BYTES,
        )
        != final_bom["sources"]["canonical_bom"]
    ):
        raise _fail("assembly procurement BOM identities are not cross-bound")

    fake_capture = SimpleNamespace(
        board_name=board_name,
        board=SimpleNamespace(identity=board_identity),
        package=SimpleNamespace(identity=package_identity),
    )
    final_cpl = _validate_final_cpl_report(
        value["final_cpl"], fake_capture, expected_engine=engine
    )
    if _identity(_render_normalized_final_cpl_report(final_cpl)) != final_cpl_report_identity:
        raise _fail("assembly final-CPL report identity is not cross-bound")
    for key, maximum in (
        ("manifest", MAXIMUM_MANIFEST_BYTES),
        ("package_board_source", MAXIMUM_BOARD_BYTES),
    ):
        identities = (
            final_bom["sources"][key],
            final_cpl["sources"][key],
            _validate_identity(procurement_sources.get(key), f"assembly procurement {key}", maximum),
        )
        if not (identities[0] == identities[1] == identities[2]):
            raise _fail(f"assembly {key} is not cross-bound")
    if (
        final_bom["counts"]["board_parts"] != final_cpl["counts"]["board_parts"]
        or final_bom["counts"]["package_parts"] != final_cpl["counts"]["package_parts"]
    ):
        raise _fail("assembly BOM/CPL part counts are not cross-bound")

    membership = value["membership"]
    if not isinstance(membership, Mapping) or set(membership) != {"both", "bom_only", "cpl_only"}:
        raise _fail("assembly membership partition is invalid")
    membership_sets: list[set[str]] = []
    for key in ("both", "bom_only", "cpl_only"):
        references = membership[key]
        if not isinstance(references, list) or len(references) > MAXIMUM_REFERENCES:
            raise _fail("assembly membership references are invalid")
        normalized = [
            _text(reference, "assembly membership reference", maximum=MAXIMUM_REFERENCE_BYTES)
            for reference in references
        ]
        if any(left >= right for left, right in zip(normalized, normalized[1:])):
            raise _fail("assembly membership references are not strictly sorted")
        membership_sets.append(set(normalized))
    if any(membership_sets[left] & membership_sets[right] for left, right in ((0, 1), (0, 2), (1, 2))):
        raise _fail("assembly membership partitions overlap")
    cpl_references = {
        part["reference"] for part in final_cpl["in_pos_parts"]
    }
    if membership_sets[0] | membership_sets[2] != cpl_references:
        raise _fail("assembly CPL membership partition is inconsistent")
    if (
        len(membership_sets[0]) + len(membership_sets[1])
        != final_bom["counts"]["board_in_bom_parts"]
        or len(membership_sets[0]) + len(membership_sets[2])
        != final_cpl["counts"]["board_in_pos_parts"]
    ):
        raise _fail("assembly membership counts are inconsistent")

    line_items = procurement.get("line_items")
    if not isinstance(line_items, list) or len(line_items) > MAXIMUM_REFERENCES:
        raise _fail("assembly procurement line items are invalid")
    line_references: set[str] = set()
    previous_line_key: tuple[str, str, str, str] | None = None
    supplier_part_mappings: dict[str, tuple[str, str]] = {}
    folded_mpns: set[str] = set()
    catalog_part_mappings: dict[str, tuple[str, str, str]] = {}
    for line in line_items:
        if not isinstance(line, Mapping) or set(line) != {
            "mpn",
            "supplier_part_number",
            "catalog_part_sha256",
            "footprint",
            "quantity",
            "references",
        }:
            raise _fail("assembly procurement line item is invalid")
        references = line.get("references")
        quantity = line.get("quantity")
        if (
            not isinstance(references, list)
            or len(references) > MAXIMUM_REFERENCES
            or type(quantity) is not int
            or quantity != len(references)
            or quantity <= 0
            or quantity > MAXIMUM_REFERENCES
        ):
            raise _fail("assembly procurement line-item quantity is invalid")
        normalized_references = [
            _catalog_text(
                reference, "assembly procurement reference", maximum=64
            )
            for reference in references
        ]
        if any(left >= right for left, right in zip(normalized_references, normalized_references[1:])):
            raise _fail("assembly procurement references are not strictly sorted")
        if line_references & set(normalized_references):
            raise _fail("assembly procurement references are duplicated")
        line_references.update(normalized_references)
        line_key_values = (
            _catalog_text(
                line.get("mpn"), "assembly procurement MPN", maximum=256
            ),
            _catalog_text(
                line.get("supplier_part_number"),
                "assembly procurement supplier part number",
                maximum=4096,
            ),
            _text(
                line.get("catalog_part_sha256"),
                "assembly procurement catalog-part digest",
                maximum=64,
            ),
            _catalog_text(
                line.get("footprint"),
                "assembly procurement footprint",
                maximum=512,
            ),
        )
        if _SHA256_RE.fullmatch(line_key_values[2]) is None:
            raise _fail("assembly procurement catalog-part digest is invalid")
        line_key = (
            line_key_values[0],
            line_key_values[1],
            line_key_values[2],
            line_key_values[3],
        )
        supplier_mapping = (line_key_values[0], line_key_values[2])
        prior_supplier_mapping = supplier_part_mappings.setdefault(
            line_key_values[1], supplier_mapping
        )
        if prior_supplier_mapping != supplier_mapping:
            raise _fail("assembly procurement supplier part number is ambiguous")
        folded_mpn = line_key_values[0].casefold()
        if folded_mpn in folded_mpns:
            raise _fail("assembly procurement MPN is duplicated case-insensitively")
        folded_mpns.add(folded_mpn)
        catalog_part_mapping = (
            line_key_values[0],
            line_key_values[1],
            line_key_values[3],
        )
        prior_catalog_part_mapping = catalog_part_mappings.setdefault(
            line_key_values[2], catalog_part_mapping
        )
        if prior_catalog_part_mapping != catalog_part_mapping:
            raise _fail("assembly procurement catalog-part identity is inconsistent")
        if previous_line_key is not None and line_key <= previous_line_key:
            raise _fail("assembly procurement line items are not strictly sorted")
        previous_line_key = line_key
    if procurement["approved"]:
        if not line_items or line_references != membership_sets[0] | membership_sets[1]:
            raise _fail("assembly procurement references do not match BOM membership")
    elif line_items:
        raise _fail("rejected assembly procurement evidence retains line items")

    raw_findings = value["findings"]
    if not isinstance(raw_findings, list) or len(raw_findings) > len(_ASSEMBLY_FINDING_MESSAGES):
        raise _fail("assembly findings are invalid")
    findings: list[str] = []
    for finding in raw_findings:
        if not isinstance(finding, Mapping) or set(finding) != {"code", "message"}:
            raise _fail("assembly finding is invalid")
        code = finding["code"]
        if code not in _ASSEMBLY_FINDING_MESSAGES or finding["message"] != _ASSEMBLY_FINDING_MESSAGES[code]:
            raise _fail("assembly finding is invalid")
        findings.append(code)
    if findings != sorted(set(findings)):
        raise _fail("assembly findings are not uniquely sorted")
    expected_findings = sorted(
        code
        for code, approved in (
            ("board_binding_rejected", board_binding.get("approved")),
            ("procurement_intent_rejected", procurement.get("approved")),
            ("final_cpl_rejected", final_cpl.get("approved")),
        )
        if approved is False
    )
    if any(
        type(approved) is not bool
        for approved in (
            board_binding.get("approved"),
            procurement.get("approved"),
            final_cpl.get("approved"),
        )
    ):
        raise _fail("assembly child approval state is invalid")
    complete = value["complete"]
    if (
        not isinstance(complete, bool)
        or complete != (not findings)
        or findings != expected_findings
        or value["status"] != ("complete" if complete else "incomplete")
    ):
        raise _fail("assembly completion state is inconsistent")
    binding = value["binding_sha256"]
    if not isinstance(binding, str) or _SHA256_RE.fullmatch(binding) is None:
        raise _fail("assembly binding digest is invalid")
    payload = dict(value)
    del payload["binding_sha256"]
    if binding != _sha256(ASSEMBLY_EVIDENCE_BINDING_DOMAIN + _compact_json(payload)):
        raise _fail("assembly binding digest is inconsistent")


def _expected_digest(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or str.__len__(value) != 64:
        raise _fail(f"{label} is invalid")
    frozen = str.__str__(value)
    if _SHA256_RE.fullmatch(frozen) is None:
        raise _fail(f"{label} is invalid")
    return frozen


def _stage_source(root: Path, leaf: str, source: _CapturedSource) -> Path:
    directory = root / leaf
    directory.mkdir(mode=0o700)
    destination = directory / Path(source.path).name
    try:
        atomic_write_no_clobber(destination, source.raw, max_bytes=source.maximum)
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail(f"could not stage {source.label}") from None
    return destination


def _evaluate_capture(
    capture: _AssemblyCapture,
    *,
    expected_archive_sha256: str | None,
    expected_bundle_sha256: str | None,
    deadline: float,
    clock: Callable[[], float],
) -> dict[str, Any]:
    # Authenticate and extract H/G before any child.  Pre-parse every retained
    # JSON artifact as well, so malformed evidence cannot trigger a process.
    try:
        _verification, entries = _handoff._validate_circuit_handoff_archive(
            capture.handoff.raw,
            operation="verify",
            expected_archive_sha256=expected_archive_sha256,
            expected_bundle_sha256=expected_bundle_sha256,
        )
    except _handoff.CircuitHandoffBundleError as error:
        raise _fail(f"circuit handoff bundle is invalid: {error}") from None
    generation_raw = entries[_handoff.GENERATION_BUNDLE_NAME]
    _parse_json_object(capture.board_binding_report.raw, "board-binding report")
    _parse_json_object(capture.procurement_intent.raw, "procurement-intent report")
    retained_final_cpl = _validate_final_cpl_report(
        _parse_json_object(capture.final_cpl_report.raw, "final-CPL report"),
        capture,
        expected_engine=None,
    )
    if (
        not capture.final_cpl_report.raw.endswith(b"\n")
        or capture.final_cpl_report.raw[:-1].endswith(b"\n")
    ):
        raise _fail("retained final-CPL report must have exactly one trailing LF")
    _remaining(deadline, clock)

    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-assembly-evidence-",
            dir=_trusted_temporary_root(),
        ) as directory:
            root = Path(directory)
            staged_handoff = _stage_source(root, "handoff", capture.handoff)
            _remaining(deadline, clock)
            staged_board = _stage_source(root, "board", capture.board)
            _remaining(deadline, clock)
            staged_package = _stage_source(root, "package", capture.package)
            _remaining(deadline, clock)
            staged_board_report = _stage_source(
                root, "board-report", capture.board_binding_report
            )
            _remaining(deadline, clock)
            staged_procurement = _stage_source(
                root, "procurement", capture.procurement_intent
            )
            _remaining(deadline, clock)
            staged_catalog = _stage_source(root, "catalog", capture.catalog_snapshot)
            _remaining(deadline, clock)
            staged_final_cpl = _stage_source(
                root, "retained-final-cpl", capture.final_cpl_report
            )
            _remaining(deadline, clock)

            generation_root = root / "generation"
            generation_root.mkdir(mode=0o700)
            staged_generation = generation_root / _handoff.GENERATION_BUNDLE_NAME
            atomic_write_no_clobber(
                staged_generation,
                generation_raw,
                max_bytes=_handoff.MAX_GENERATION_BUNDLE_BYTES,
            )
            _remaining(deadline, clock)

            staged_optionals: dict[str, Path | None] = {}
            for key, source in (
                ("policy", capture.board_binding_policy),
                ("project", capture.manufacturing_project),
                ("rules", capture.manufacturing_rules),
                ("fab_profile", capture.manufacturing_fab_profile),
                ("physical_profile", capture.manufacturing_physical_profile),
            ):
                staged_optionals[key] = (
                    None if source is None else _stage_source(root, key, source)
                )
                _remaining(deadline, clock)

            handoff_remaining = _remaining(deadline, clock)
            handoff_budget = handoff_remaining / 2.0
            if not math.isfinite(handoff_budget) or handoff_budget <= 0:
                raise _fail("circuit-manufacturing replay has no execution budget")
            try:
                circuit_manufacturing = _handoff.replay_circuit_handoff_bundle(
                    staged_handoff,
                    list(capture.pcbex),
                    kicad_board=staged_board,
                    retained_board_binding_report=staged_board_report,
                    board_binding_policy=staged_optionals["policy"],
                    require_board_binding_approved=False,
                    retained_manufacturing_package=staged_package,
                    manufacturing_kicad_cli=capture.kicad_cli,
                    manufacturing_kicad_project=staged_optionals["project"],
                    manufacturing_kicad_rules=staged_optionals["rules"],
                    manufacturing_fab=capture.manufacturing_fab,
                    manufacturing_fab_profile=staged_optionals["fab_profile"],
                    manufacturing_physical_profile=staged_optionals[
                        "physical_profile"
                    ],
                    timeout_seconds=handoff_budget,
                    expected_archive_sha256=expected_archive_sha256,
                    expected_bundle_sha256=expected_bundle_sha256,
                    _clock=clock,
                )
            except _handoff.CircuitHandoffBundleError as error:
                raise _fail(f"circuit-manufacturing replay failed: {error}") from None
            _remaining(deadline, clock)

            procurement_remaining = _remaining(deadline, clock)
            procurement_budget = procurement_remaining / 2.0
            if not math.isfinite(procurement_budget) or procurement_budget <= 0:
                raise _fail("procurement-intent replay has no execution budget")
            try:
                procurement = _procurement.validate_procurement_intent(
                    staged_procurement,
                    staged_board,
                    staged_package,
                    staged_generation,
                    staged_catalog,
                    list(capture.pcbex),
                    timeout_seconds=procurement_budget,
                    _clock=clock,
                )
            except _procurement.ProcurementIntentError as error:
                raise _fail(f"procurement-intent replay failed: {error}") from None
            _remaining(deadline, clock)

            fresh_root = root / "fresh-final-cpl"
            fresh_root.mkdir(mode=0o700)
            fresh_final_cpl_path = fresh_root / "final-cpl.json"
            argv = _validate_argv(
                [
                    *capture.pcbex,
                    "verify-final-cpl",
                    f"--output={fresh_final_cpl_path}",
                    "--",
                    str(staged_board),
                    str(staged_package),
                ],
                "final-CPL child",
            )
            final_remaining = _remaining(deadline, clock)
            reread_reserve = min(15.0, final_remaining / 2.0)
            cleanup_timeout = reread_reserve / 2.0
            process_timeout = final_remaining - reread_reserve
            if (
                not math.isfinite(process_timeout)
                or process_timeout <= 0
                or not math.isfinite(cleanup_timeout)
                or cleanup_timeout <= 0
            ):
                raise _fail("final-CPL child has no execution budget")
            try:
                completed = run_bounded(
                    argv,
                    timeout_seconds=process_timeout,
                    cleanup_timeout_seconds=cleanup_timeout,
                    max_stdout_bytes=MAXIMUM_CHILD_STDOUT_BYTES,
                    max_stderr_bytes=MAXIMUM_CHILD_STDERR_BYTES,
                )
            except BoundedProcessError:
                raise _fail("final-CPL child process failed") from None
            if completed.returncode != 0:
                raise _fail("final-CPL child rejected its inputs")
            fresh_final_cpl_raw = _read_source(
                str(fresh_final_cpl_path),
                MAXIMUM_FINAL_CPL_REPORT_BYTES,
                "fresh final-CPL report",
            )
            if fresh_final_cpl_raw != capture.final_cpl_report.raw:
                raise _fail(
                    "fresh final-CPL replay did not reproduce the retained report"
                )
            engine = _engine_text(
                circuit_manufacturing.get("engine_version"),
                "circuit-manufacturing engine version",
            )
            final_cpl = _validate_final_cpl_report(
                _parse_json_object(fresh_final_cpl_raw, "fresh final-CPL report"),
                capture,
                expected_engine=engine,
            )
            if not _strict_json_equal(retained_final_cpl, final_cpl):
                raise _fail("retained final-CPL report changed during replay")
            _remaining(deadline, clock)

            staged_pairs: list[tuple[Path, bytes, int, str]] = [
                (staged_handoff, capture.handoff.raw, capture.handoff.maximum, capture.handoff.label),
                (staged_board, capture.board.raw, capture.board.maximum, capture.board.label),
                (staged_package, capture.package.raw, capture.package.maximum, capture.package.label),
                (staged_board_report, capture.board_binding_report.raw, capture.board_binding_report.maximum, capture.board_binding_report.label),
                (staged_procurement, capture.procurement_intent.raw, capture.procurement_intent.maximum, capture.procurement_intent.label),
                (staged_catalog, capture.catalog_snapshot.raw, capture.catalog_snapshot.maximum, capture.catalog_snapshot.label),
                (staged_final_cpl, capture.final_cpl_report.raw, capture.final_cpl_report.maximum, capture.final_cpl_report.label),
                (staged_generation, generation_raw, _handoff.MAX_GENERATION_BUNDLE_BYTES, "staged generation bundle"),
                (fresh_final_cpl_path, fresh_final_cpl_raw, MAXIMUM_FINAL_CPL_REPORT_BYTES, "fresh final-CPL report"),
            ]
            for key, source in (
                ("policy", capture.board_binding_policy),
                ("project", capture.manufacturing_project),
                ("rules", capture.manufacturing_rules),
                ("fab_profile", capture.manufacturing_fab_profile),
                ("physical_profile", capture.manufacturing_physical_profile),
            ):
                path = staged_optionals[key]
                if source is not None and path is not None:
                    staged_pairs.append((path, source.raw, source.maximum, source.label))
            for path, expected, maximum, label in staged_pairs:
                if _read_source(str(path), maximum, label) != expected:
                    raise _fail(f"{label} changed in the private workspace")
                _remaining(deadline, clock)

            result = _cross_bind_and_compose(
                capture,
                generation_raw,
                circuit_manufacturing,
                procurement,
                final_cpl,
            )
            # Authenticate staged and caller sources again after composition and
            # digest calculation; final union reread is an observed-mutation
            # boundary, not a same-principal atomic snapshot claim.
            for path, expected, maximum, label in staged_pairs:
                if _read_source(str(path), maximum, label) != expected:
                    raise _fail(f"{label} changed in the private workspace")
                _remaining(deadline, clock)
    except AssemblyEvidenceError:
        raise
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail("assembly-evidence private workspace failed") from None

    render_assembly_evidence(result)
    _reread_sources(capture, deadline, clock)
    _remaining(deadline, clock)
    return result


def evaluate_assembly_evidence(
    handoff_bundle: str | os.PathLike[str],
    board: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    retained_board_binding_report: str | os.PathLike[str],
    retained_procurement_intent: str | os.PathLike[str],
    catalog_snapshot: str | os.PathLike[str],
    retained_final_cpl: str | os.PathLike[str],
    pcbex: str | Sequence[str] = "pcbex",
    *,
    board_binding_policy: str | os.PathLike[str] | None = None,
    kicad_cli: str | os.PathLike[str] = "kicad-cli",
    manufacturing_kicad_project: str | os.PathLike[str] | None = None,
    manufacturing_kicad_rules: str | os.PathLike[str] | None = None,
    manufacturing_fab: str | None = None,
    manufacturing_fab_profile: str | os.PathLike[str] | None = None,
    manufacturing_physical_profile: str | os.PathLike[str] | None = None,
    expected_archive_sha256: str | None = None,
    expected_bundle_sha256: str | None = None,
    timeout_seconds: float = 120.0,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Freshly compose exact per-board assembly evidence under one deadline."""

    _timeout, deadline = _timeout_deadline(timeout_seconds, _clock)
    expected_archive = _expected_digest(
        expected_archive_sha256, "expected handoff archive digest"
    )
    expected_bundle = _expected_digest(
        expected_bundle_sha256, "expected handoff bundle digest"
    )
    capture, _additional = _capture_inputs(
        handoff_bundle,
        board,
        manufacturing_package,
        retained_board_binding_report,
        retained_procurement_intent,
        catalog_snapshot,
        retained_final_cpl,
        pcbex,
        board_binding_policy=board_binding_policy,
        kicad_cli=kicad_cli,
        manufacturing_kicad_project=manufacturing_kicad_project,
        manufacturing_kicad_rules=manufacturing_kicad_rules,
        manufacturing_fab=manufacturing_fab,
        manufacturing_fab_profile=manufacturing_fab_profile,
        manufacturing_physical_profile=manufacturing_physical_profile,
        deadline=deadline,
        clock=_clock,
    )
    return _evaluate_capture(
        capture,
        expected_archive_sha256=expected_archive,
        expected_bundle_sha256=expected_bundle,
        deadline=deadline,
        clock=_clock,
    )


def _bounded_bytes_like(value: bytes | bytearray | memoryview, label: str) -> bytes:
    try:
        view = memoryview(value)
    except (TypeError, ValueError):
        raise _fail(f"{label} is invalid") from None
    try:
        size = view.nbytes
        if size == 0 or size > MAXIMUM_ASSEMBLY_EVIDENCE_BYTES:
            raise _fail(f"{label} is invalid")
        raw = view.tobytes()
    except AssemblyEvidenceError:
        raise
    except (TypeError, ValueError, BufferError, MemoryError):
        raise _fail(f"{label} is invalid") from None
    finally:
        try:
            view.release()
        except (ValueError, BufferError):
            pass
    if len(raw) != size:
        raise _fail(f"{label} is invalid")
    return raw


def validate_assembly_evidence(
    evidence: Mapping[str, Any] | bytes | bytearray | memoryview | str | os.PathLike[str],
    handoff_bundle: str | os.PathLike[str],
    board: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    retained_board_binding_report: str | os.PathLike[str],
    retained_procurement_intent: str | os.PathLike[str],
    catalog_snapshot: str | os.PathLike[str],
    retained_final_cpl: str | os.PathLike[str],
    pcbex: str | Sequence[str] = "pcbex",
    *,
    board_binding_policy: str | os.PathLike[str] | None = None,
    kicad_cli: str | os.PathLike[str] = "kicad-cli",
    manufacturing_kicad_project: str | os.PathLike[str] | None = None,
    manufacturing_kicad_rules: str | os.PathLike[str] | None = None,
    manufacturing_fab: str | None = None,
    manufacturing_fab_profile: str | os.PathLike[str] | None = None,
    manufacturing_physical_profile: str | os.PathLike[str] | None = None,
    expected_archive_sha256: str | None = None,
    expected_bundle_sha256: str | None = None,
    timeout_seconds: float = 120.0,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Freshly recompute and compare one retained assembly-evidence report."""

    _timeout, deadline = _timeout_deadline(timeout_seconds, _clock)
    capture, retained_source = _capture_inputs(
        handoff_bundle,
        board,
        manufacturing_package,
        retained_board_binding_report,
        retained_procurement_intent,
        catalog_snapshot,
        retained_final_cpl,
        pcbex,
        board_binding_policy=board_binding_policy,
        kicad_cli=kicad_cli,
        manufacturing_kicad_project=manufacturing_kicad_project,
        manufacturing_kicad_rules=manufacturing_kicad_rules,
        manufacturing_fab=manufacturing_fab,
        manufacturing_fab_profile=manufacturing_fab_profile,
        manufacturing_physical_profile=manufacturing_physical_profile,
        deadline=deadline,
        clock=_clock,
        defer_commands=True,
    )
    injected_mapping = False
    if isinstance(evidence, (str, os.PathLike)):
        retained_path = _freeze_path(evidence, "assembly-evidence report source")
        _ensure_distinct_sources(
            [*(source.path for source in capture.sources), retained_path]
        )
        retained_raw = _read_source(
            retained_path,
            MAXIMUM_ASSEMBLY_EVIDENCE_BYTES,
            "assembly-evidence report",
        )
        retained_source = _CapturedSource(
            retained_path,
            "assembly-evidence report",
            MAXIMUM_ASSEMBLY_EVIDENCE_BYTES,
            retained_raw,
        )
    elif isinstance(evidence, Mapping):
        injected_mapping = True
        try:
            retained_raw = render_assembly_evidence(evidence)
        except (AssemblyEvidenceError, TypeError, ValueError, RuntimeError, RecursionError):
            raise _fail("assembly-evidence report is invalid") from None
    elif isinstance(evidence, (bytes, bytearray, memoryview)):
        retained_raw = _bounded_bytes_like(evidence, "assembly-evidence report")
    else:
        raise _fail("assembly-evidence report is invalid")
    if (
        sum(len(source.raw) for source in capture.sources) + len(retained_raw)
        > MAXIMUM_TOTAL_INPUT_BYTES
    ):
        raise _fail("assembly evidence inputs exceed their aggregate bound")
    retained = _parse_json_object(retained_raw, "assembly-evidence report")
    if not injected_mapping and retained_raw != render_assembly_evidence(retained):
        raise _fail("assembly-evidence report is not canonical pretty JSON")
    capture = _finalize_capture_commands(capture, pcbex, kicad_cli)
    expected = _evaluate_capture(
        capture,
        expected_archive_sha256=_expected_digest(
            expected_archive_sha256, "expected handoff archive digest"
        ),
        expected_bundle_sha256=_expected_digest(
            expected_bundle_sha256, "expected handoff bundle digest"
        ),
        deadline=deadline,
        clock=_clock,
    )
    if not _strict_json_equal(retained, expected):
        raise _fail("assembly-evidence report does not match exact replayed evidence")
    if not injected_mapping and retained_raw != render_assembly_evidence(expected):
        raise _fail("assembly-evidence report is not canonical pretty JSON")
    _reread_sources(capture, deadline, _clock, retained_source)
    return expected


build_assembly_evidence = evaluate_assembly_evidence


def assembly_evidence_json_schema() -> dict[str, Any]:
    """Return the closed structural schema for assembly evidence v1."""

    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}

    def identity(maximum: int) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["bytes", "sha256"],
            "properties": {
                "bytes": {"type": "integer", "minimum": 1, "maximum": maximum},
                "sha256": copy.deepcopy(digest),
            },
        }

    board_identity = identity(MAXIMUM_BOARD_BYTES)
    board_identity["required"] = ["name", "bytes", "sha256"]
    board_identity["properties"] = {
        "name": {
            "type": "string",
            "minLength": 11,
            "maxLength": MAXIMUM_PORTABLE_NAME_BYTES,
            "pattern": r'^[^\u0000-\u001f<>:"/\\|?*]+\.kicad_pcb$',
        },
        **board_identity["properties"],
    }

    procurement_schema = _procurement.procurement_intent_json_schema()
    full_final_bom = copy.deepcopy(procurement_schema["properties"]["final_bom"])
    full_final_bom["required"].remove("in_bom_parts")
    del full_final_bom["properties"]["in_bom_parts"]
    procurement_projection = {
        key: copy.deepcopy(procurement_schema[key])
        for key in ("type", "additionalProperties", "required", "properties", "allOf")
    }
    procurement_projection["required"].remove("final_bom")
    del procurement_projection["properties"]["final_bom"]
    procurement_projection["required"].remove("binding_sha256")
    del procurement_projection["properties"]["binding_sha256"]

    final_cpl_finding = {
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["code", "message"],
                "properties": {
                    "code": {"const": code},
                    "message": {"const": message},
                },
            }
            for code, message in sorted(_FINAL_CPL_FINDING_MESSAGES.items())
        ]
    }
    final_cpl = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "scope",
            "engine_version",
            "board_basename",
            "sources",
            "counts",
            "in_pos_parts",
            "findings",
            "approved",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "scope": {"const": FINAL_CPL_SCOPE},
            "engine_version": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "pattern": r"^\S(?:[\s\S]*\S)?$",
            },
            "board_basename": copy.deepcopy(
                board_identity["properties"]["name"]
            ),
            "sources": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(_FINAL_CPL_SOURCE_KEYS),
                "properties": {
                    "board": identity(MAXIMUM_BOARD_BYTES),
                    "manufacturing_package": identity(MAXIMUM_PACKAGE_BYTES),
                    "manifest": identity(MAXIMUM_MANIFEST_BYTES),
                    "cpl": identity(MAXIMUM_PACKAGE_BYTES),
                    "canonical_cpl": identity(MAXIMUM_PACKAGE_BYTES),
                    "package_board_source": identity(MAXIMUM_BOARD_BYTES),
                },
            },
            "counts": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(_FINAL_CPL_COUNT_KEYS),
                "properties": {
                    "board_parts": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PARTS},
                    "board_in_pos_parts": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_REFERENCES},
                    "package_parts": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PARTS},
                    "package_placement_parts": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PARTS},
                    "findings": {"type": "integer", "minimum": 0, "maximum": 2},
                },
            },
            "in_pos_parts": {
                "type": "array",
                "maxItems": MAXIMUM_REFERENCES,
                "uniqueItems": True,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": sorted(_FINAL_CPL_PART_KEYS),
                    "properties": {
                        "reference": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_REFERENCE_BYTES},
                        "x_nm": {"type": "integer", "minimum": -(2**63), "maximum": 2**63 - 1},
                        "y_nm": {"type": "integer", "minimum": -(2**63), "maximum": 2**63 - 1},
                        "rotation_mdeg": {"type": "integer", "minimum": -(2**63), "maximum": 2**63 - 1},
                        "layer": {"enum": ["F", "B"]},
                    },
                },
            },
            "findings": {
                "type": "array",
                "maxItems": 2,
                "uniqueItems": True,
                "items": final_cpl_finding,
            },
            "approved": {"type": "boolean"},
        },
        "allOf": [
            {
                "if": {"properties": {"approved": {"const": True}}, "required": ["approved"]},
                "then": {
                    "properties": {
                        "findings": {"maxItems": 0},
                        "counts": {"properties": {"findings": {"const": 0}}},
                    }
                },
            },
            {
                "if": {"properties": {"approved": {"const": False}}, "required": ["approved"]},
                "then": {
                    "properties": {
                        "findings": {"minItems": 1},
                        "counts": {"properties": {"findings": {"minimum": 1}}},
                    }
                },
            },
        ],
    }

    v6_schema = _handoff.circuit_handoff_bundle_manufacturing_replay_result_json_schema()
    circuit_manufacturing = {
        key: copy.deepcopy(v6_schema[key])
        for key in (
            "type",
            "additionalProperties",
            "required",
            "properties",
            "allOf",
            "oneOf",
        )
        if key in v6_schema
    }
    outer_finding = {
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["code", "message"],
                "properties": {
                    "code": {"const": code},
                    "message": {"const": message},
                },
            }
            for code, message in sorted(_ASSEMBLY_FINDING_MESSAGES.items())
        ]
    }
    membership = {
        "type": "object",
        "additionalProperties": False,
        "required": ["both", "bom_only", "cpl_only"],
        "properties": {
            key: {
                "type": "array",
                "maxItems": MAXIMUM_REFERENCES,
                "uniqueItems": True,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAXIMUM_REFERENCE_BYTES,
                },
            }
            for key in ("both", "bom_only", "cpl_only")
        },
    }
    validation_keys = [
        "handoff_archive_validated",
        "circuit_manufacturing_replayed",
        "procurement_intent_replayed",
        "final_cpl_replayed",
        "cross_bindings_matched",
        "membership_partitioned",
        "caller_inputs_unchanged",
    ]
    required = [
        "schema_version",
        "scope",
        "status",
        "complete",
        "quantity_basis",
        "assembly_ready",
        "assembly_authorized",
        "fabrication_authorized",
        "procurement_authorized",
        "order_placed",
        "adapter_network_performed",
        "machine_operation_performed",
        "sources",
        "circuit_manufacturing",
        "final_bom",
        "procurement",
        "final_cpl",
        "membership",
        "findings",
        "validation",
        "binding_sha256",
    ]
    schema: dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/schemas/"
            "offline-exact-board-assembly-evidence-v1.json"
        ),
        "title": "pcbex exact offline per-board assembly evidence",
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": {
            "schema_version": {"const": ASSEMBLY_EVIDENCE_SCHEMA_VERSION},
            "scope": {"const": ASSEMBLY_EVIDENCE_SCOPE},
            "status": {"enum": ["complete", "incomplete"]},
            "complete": {"type": "boolean"},
            "quantity_basis": {"const": "per_board"},
            "assembly_ready": {"const": False},
            "assembly_authorized": {"const": False},
            "fabrication_authorized": {"const": False},
            "procurement_authorized": {"const": False},
            "order_placed": {"const": False},
            "adapter_network_performed": {"const": False},
            "machine_operation_performed": {"const": False},
            "sources": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "circuit_handoff_bundle",
                    "handoff_generation_bundle",
                    "board",
                    "manufacturing_package",
                    "board_binding_report",
                    "procurement_intent",
                    "catalog_snapshot",
                    "final_cpl_report",
                ],
                "properties": {
                    "circuit_handoff_bundle": identity(MAXIMUM_HANDOFF_BYTES),
                    "handoff_generation_bundle": identity(_handoff.MAX_GENERATION_BUNDLE_BYTES),
                    "board": board_identity,
                    "manufacturing_package": identity(MAXIMUM_PACKAGE_BYTES),
                    "board_binding_report": identity(MAXIMUM_BOARD_BINDING_REPORT_BYTES),
                    "procurement_intent": identity(MAXIMUM_PROCUREMENT_INTENT_BYTES),
                    "catalog_snapshot": identity(MAX_CATALOG_RAW_BYTES),
                    "final_cpl_report": identity(MAXIMUM_FINAL_CPL_REPORT_BYTES),
                },
            },
            "circuit_manufacturing": circuit_manufacturing,
            "final_bom": full_final_bom,
            "procurement": procurement_projection,
            "final_cpl": final_cpl,
            "membership": membership,
            "findings": {
                "type": "array",
                "maxItems": len(_ASSEMBLY_FINDING_MESSAGES),
                "uniqueItems": True,
                "items": outer_finding,
            },
            "validation": {
                "type": "object",
                "additionalProperties": False,
                "required": validation_keys,
                "properties": {key: {"const": True} for key in validation_keys},
            },
            "binding_sha256": digest,
        },
        "allOf": [
            {
                "if": {"properties": {"complete": {"const": True}}, "required": ["complete"]},
                "then": {
                    "properties": {
                        "status": {"const": "complete"},
                        "findings": {"maxItems": 0},
                    }
                },
            },
            {
                "if": {"properties": {"complete": {"const": False}}, "required": ["complete"]},
                "then": {
                    "properties": {
                        "status": {"const": "incomplete"},
                        "findings": {"minItems": 1},
                    }
                },
            },
        ],
        "$comment": (
            "Runtime validation additionally enforces exact replay/raw equality, "
            "UTF-8 byte bounds, strict ordering/count correlations, H/G/B/M and "
            "manifest/package-board-source cross-bindings, common-reference layer/SMD "
            "consistency, the membership partition, caller rereads, and the "
            "domain-separated binding digest. The schema is structural only."
        ),
    }
    return schema


__all__ = [
    "AssemblyEvidenceError",
    "MAXIMUM_ASSEMBLY_EVIDENCE_BYTES",
    "assembly_evidence_json_schema",
    "build_assembly_evidence",
    "evaluate_assembly_evidence",
    "render_assembly_evidence",
    "validate_assembly_evidence",
]
