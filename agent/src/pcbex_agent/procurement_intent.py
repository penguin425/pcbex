"""Offline, per-board final-BOM to catalog-selection reconciliation.

This module composes two existing authority boundaries without turning either
one into a purchasing authority:

* the caller-selected Rust ``pcbex`` executable validates one manufacturing
  ZIP, regenerates its canonical BOM from the exact board bytes, and returns a
  closed final-BOM report; and
* the Python catalog adapter fully recomputes the catalog selection embedded
  in the retained generation bundle against the exact retained snapshot.

The resulting report is historical, path-free evidence for one populated
board.  It never contacts a supplier, multiplies a batch quantity, reserves
stock, authorizes procurement, or places an order.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
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

from .bounded_io import BoundedIOError, atomic_write_no_clobber, read_bytes
from .bounded_process import BoundedProcessError, run_bounded
from .catalog import (
    MAX_CATALOG_RAW_BYTES,
    CatalogError,
    canonical_sha256,
    load_catalog_snapshot,
    validate_catalog_receipt,
)
from .catalog_provenance import (
    CatalogGenerationProvenanceError,
    MAX_PROVENANCE_BUNDLE_BYTES,
    _json_bytes as _bounded_injected_json_bytes,
    _parse_object,
    _reconstruct_input_spec,
    _validate_bundle,
)


PROCUREMENT_INTENT_SCHEMA_VERSION = 1
PROCUREMENT_INTENT_SCOPE = "offline-final-bom-catalog-selection-intent-v1"
PROCUREMENT_INTENT_BINDING_DOMAIN = b"pcbex:offline-procurement-intent-v1\0"

MAXIMUM_BOARD_BYTES = 128 * 1024 * 1024
MAXIMUM_PACKAGE_BYTES = 128 * 1024 * 1024
MAXIMUM_FINAL_BOM_REPORT_BYTES = 16 * 1024 * 1024
MAXIMUM_PROCUREMENT_INTENT_BYTES = 16 * 1024 * 1024
MAXIMUM_TOTAL_INPUT_BYTES = 384 * 1024 * 1024
MAXIMUM_CHILD_STDOUT_BYTES = 1 * 1024 * 1024
MAXIMUM_CHILD_STDERR_BYTES = 1 * 1024 * 1024
MAXIMUM_TIMEOUT_SECONDS = 600.0
MAXIMUM_ARGUMENT_BYTES = 32_768
MAXIMUM_COMMAND_ARGUMENTS = 256
MAXIMUM_WINDOWS_COMMAND_LINE_UTF16_UNITS = 32_767
MAXIMUM_BOM_PARTS = 256
MAXIMUM_FINAL_BOM_PART_TEXT_BYTES = 4096

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SUPPLIER_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
_SNAPSHOT_ID_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$")
_WINDOWS_RESERVED_NUMERIC_SUFFIXES = (
    "123456789\N{SUPERSCRIPT ONE}\N{SUPERSCRIPT TWO}\N{SUPERSCRIPT THREE}"
)
_WINDOWS_RESERVED_LEAF_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{suffix}" for suffix in _WINDOWS_RESERVED_NUMERIC_SUFFIXES}
    | {f"LPT{suffix}" for suffix in _WINDOWS_RESERVED_NUMERIC_SUFFIXES}
)


class ProcurementIntentError(ValueError):
    """A stable, path-free procurement-intent evaluation failure."""


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
class _ProcurementCapture:
    board: _CapturedSource
    package: _CapturedSource
    generation_bundle: _CapturedSource
    catalog_snapshot: _CapturedSource
    board_name: str
    snapshot_name: str

    @property
    def sources(self) -> tuple[_CapturedSource, ...]:
        return (
            self.board,
            self.package,
            self.generation_bundle,
            self.catalog_snapshot,
        )


class _DuplicateJSONKey(ValueError):
    pass


def _fail(message: str) -> ProcurementIntentError:
    return ProcurementIntentError(message)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": _sha256(raw)}


def _compact_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise _fail("procurement intent value cannot be serialized") from None


def _strict_json_equal(left: Any, right: Any) -> bool:
    """Compare parsed JSON values without Python's bool/number coercions."""

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _strict_json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _strict_json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return left == right


def _binding_digest(value: Mapping[str, Any]) -> str:
    try:
        canonical = json.dumps(
            dict(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise _fail("procurement intent binding cannot be serialized") from None
    return _sha256(PROCUREMENT_INTENT_BINDING_DOMAIN + canonical)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJSONKey
        value[key] = item
    return value


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


def _freeze_path(value: str | os.PathLike[str], label: str) -> str:
    try:
        rendered = os.fspath(value)
    except (TypeError, ValueError, OSError):
        raise _fail(f"{label} is invalid") from None
    if not isinstance(rendered, str) or not rendered or "\x00" in rendered:
        raise _fail(f"{label} is invalid")
    return str.__add__("", rendered)


def _read_source(path: str, maximum: int, label: str) -> bytes:
    try:
        raw = read_bytes(path, max_bytes=maximum)
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail(f"{label} source is invalid") from None
    if not raw:
        raise _fail(f"{label} source is empty")
    return raw


def _portable_leaf(path: str, label: str, suffix: str | None = None) -> str:
    name = Path(path).name
    windows_name = PureWindowsPath(name)
    windows_stem = name.partition(".")[0].rstrip(" ").upper()
    if (
        not name
        or name in {".", ".."}
        or Path(name).parts != (name,)
        or any(ord(character) < 0x20 for character in name)
        or any(character in '<>:"/\\|?*' for character in name)
        or name[-1] in {" ", "."}
        or windows_name.drive
        or windows_name.root
        or windows_name.parts != (name,)
        or windows_name.name != name
        or windows_stem in _WINDOWS_RESERVED_LEAF_STEMS
    ):
        raise _fail(f"{label} basename is invalid")
    try:
        encoded = name.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise _fail(f"{label} basename is invalid") from None
    if (
        len(encoded) > 255
        or (suffix is not None and not name.endswith(suffix))
        or (suffix is not None and name == suffix)
    ):
        raise _fail(f"{label} basename is invalid")
    return name


def _ensure_distinct_sources(paths: Sequence[str]) -> None:
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            try:
                if os.path.samefile(left, right):
                    raise _fail("procurement intent input sources must be distinct")
            except ProcurementIntentError:
                raise
            except (OSError, TypeError, ValueError):
                raise _fail("procurement intent input identity is invalid") from None


def _capture_inputs(
    board: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    generation_bundle: str | os.PathLike[str],
    catalog_snapshot: str | os.PathLike[str],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> _ProcurementCapture:
    frozen = (
        _freeze_path(board, "board source"),
        _freeze_path(manufacturing_package, "manufacturing package source"),
        _freeze_path(generation_bundle, "generation bundle source"),
        _freeze_path(catalog_snapshot, "catalog snapshot source"),
    )
    _ensure_distinct_sources(frozen)
    board_name = _portable_leaf(frozen[0], "board", ".kicad_pcb")
    snapshot_name = _portable_leaf(frozen[3], "catalog snapshot")
    specs = (
        (frozen[0], "board", MAXIMUM_BOARD_BYTES),
        (frozen[1], "manufacturing package", MAXIMUM_PACKAGE_BYTES),
        (frozen[2], "generation bundle", MAX_PROVENANCE_BUNDLE_BYTES),
        (frozen[3], "catalog snapshot", MAX_CATALOG_RAW_BYTES),
    )
    captured: list[_CapturedSource] = []
    total = 0
    for path, label, maximum in specs:
        raw = _read_source(path, maximum, label)
        total += len(raw)
        if total > MAXIMUM_TOTAL_INPUT_BYTES:
            raise _fail("procurement intent inputs exceed their aggregate bound")
        captured.append(_CapturedSource(path, label, maximum, raw))
        _remaining(deadline, clock)
    return _ProcurementCapture(
        board=captured[0],
        package=captured[1],
        generation_bundle=captured[2],
        catalog_snapshot=captured[3],
        board_name=board_name,
        snapshot_name=snapshot_name,
    )


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
        except ProcurementIntentError:
            raise
        except (TypeError, ValueError, OverflowError, RuntimeError):
            raise _fail("pcbex command is invalid") from None
    if not command:
        raise _fail("pcbex command is invalid")
    normalized: list[str] = []
    total = 0
    for item in command:
        if not isinstance(item, str):
            raise _fail("pcbex command is invalid")
        # Bound a caller-supplied ``str`` subclass through concrete base-type
        # operations before making the exact built-in snapshot.  Dynamic
        # ``encode``/length/membership hooks must not hide a huge backing
        # string until after it has been copied.
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
        normalized.append(_exact_command_string(item))
    return normalized


def _exact_command_string(value: str) -> str:
    return str.__str__(value)


def _bounded_bytes_like(
    value: bytes | bytearray | memoryview,
    *,
    maximum: int,
    label: str,
) -> bytes:
    try:
        view = memoryview(value)
    except (TypeError, ValueError):
        raise _fail(f"{label} is invalid") from None
    try:
        size = view.nbytes
        if size == 0 or size > maximum:
            raise _fail(f"{label} is invalid")
        raw = view.tobytes()
    except ProcurementIntentError:
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


def _validate_argv(argv: Sequence[str]) -> list[str]:
    if not argv or len(argv) > MAXIMUM_COMMAND_ARGUMENTS:
        raise _fail("final-BOM child argv is invalid")
    total = 0
    for item in argv:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise _fail("final-BOM child argv is invalid")
        try:
            total += len(item.encode("utf-8", errors="strict"))
        except UnicodeEncodeError:
            raise _fail("final-BOM child argv is invalid") from None
        if total > MAXIMUM_ARGUMENT_BYTES:
            raise _fail("final-BOM child argv is invalid")
    try:
        units = len(subprocess.list2cmdline(list(argv)).encode("utf-16-le")) // 2 + 1
    except (TypeError, ValueError, UnicodeError):
        raise _fail("final-BOM child argv is invalid") from None
    if units > MAXIMUM_WINDOWS_COMMAND_LINE_UTF16_UNITS:
        raise _fail("final-BOM child argv is invalid")
    return list(argv)


def _remaining(deadline: float, clock: Callable[[], float]) -> float:
    try:
        remaining = deadline - float(clock())
    except (TypeError, ValueError, OverflowError):
        raise _fail("aggregate deadline clock is invalid") from None
    if not math.isfinite(remaining) or remaining <= 0:
        raise _fail("procurement intent evaluation exceeded its aggregate deadline")
    return min(remaining, MAXIMUM_TIMEOUT_SECONDS)


def _trusted_temporary_root() -> Path:
    try:
        return Path(tempfile.gettempdir()).resolve(strict=True)
    except (OSError, RuntimeError):
        raise _fail("trusted temporary root is invalid") from None


def _catalog_selection_from_capture(
    capture: _ProcurementCapture,
    staged_snapshot: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        bundle = _parse_object(
            capture.generation_bundle.raw,
            label="generation bundle",
        )
        selection, resolved, _skidl = _validate_bundle(
            bundle,
            capture.generation_bundle.raw,
        )
        input_spec = _reconstruct_input_spec(resolved, selection)
        snapshot_source: Any = (
            staged_snapshot
            if selection.get("source", {}).get("kind") == "file"
            else capture.catalog_snapshot.raw
        )
        snapshot = load_catalog_snapshot(
            snapshot_source,
            evaluated_at_unix=selection["evaluated_at_unix"],
        )
        if snapshot.raw_bytes != capture.catalog_snapshot.raw:
            raise ValueError
        policy = selection["policy"]
        validate_catalog_receipt(
            copy.deepcopy(selection),
            input_spec,
            resolved,
            snapshot,
            require_available=policy["require_available"],
            require_basic=policy["require_basic"],
            allow_footprint_fallback=policy["allow_footprint_fallback"],
            evaluated_at_unix=selection["evaluated_at_unix"],
        )
    except (
        CatalogError,
        CatalogGenerationProvenanceError,
        KeyError,
        TypeError,
        ValueError,
    ):
        raise _fail("catalog selection cannot be fully replayed") from None
    return dict(selection), dict(resolved), dict(snapshot.normalized)


def _reread_inputs(capture: _ProcurementCapture, deadline: float, clock: Callable[[], float]) -> None:
    for source in capture.sources:
        observed = _read_source(source.path, source.maximum, source.label)
        if observed != source.raw:
            raise _fail(f"{source.label} source changed during evaluation")
        _remaining(deadline, clock)


# The strict Rust report validator and result composer are intentionally kept
# below the capture/replay primitives.  Their exact field set is shared with
# the Rust v1.464 schema and is completed together with that implementation.


_FINAL_BOM_SCOPE = "final_bom_source_and_canonical_bom_v1"
_FINAL_BOM_KEYS = frozenset(
    {
        "schema_version",
        "scope",
        "engine_version",
        "board_basename",
        "sources",
        "counts",
        "in_bom_parts",
        "findings",
        "approved",
    }
)
_FINAL_BOM_SOURCE_KEYS = frozenset(
    {
        "board",
        "manufacturing_package",
        "manifest",
        "bom",
        "canonical_bom",
        "package_board_source",
    }
)
_FINAL_BOM_COUNT_KEYS = frozenset(
    {
        "board_parts",
        "board_in_bom_parts",
        "package_parts",
        "package_in_bom_parts",
        "findings",
    }
)
_FINAL_BOM_PART_KEYS = frozenset(
    {"reference", "value", "footprint", "mpn", "layer", "type"}
)
_FINAL_BOM_FINDING_MESSAGES = {
    "canonical_bom_mismatch": (
        "manufacturing package bom.csv does not equal the canonical BOM regenerated from the board"
    ),
    "package_board_source_mismatch": (
        "manufacturing package input identity does not equal the supplied board"
    ),
}


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise _fail(f"{label} is invalid")
    return value


def _text(value: Any, label: str, *, maximum: int, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not value or value.strip() != value or "\x00" in value:
        raise _fail(f"{label} is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise _fail(f"{label} is invalid") from None
    if len(encoded) > maximum:
        raise _fail(f"{label} is invalid")
    return value


def _final_bom_text(value: Any, label: str, *, nullable: bool = False) -> str | None:
    """Validate the Rust report's deliberately broad manufacturing text."""

    if nullable and value is None:
        return None
    if not isinstance(value, str) or not value or "\x00" in value:
        raise _fail(f"{label} is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise _fail(f"{label} is invalid") from None
    if len(encoded) > MAXIMUM_FINAL_BOM_PART_TEXT_BYTES:
        raise _fail(f"{label} is invalid")
    return value


def _validate_identity(value: Any, label: str, maximum: int) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"bytes", "sha256"}:
        raise _fail(f"{label} identity is invalid")
    byte_count = _integer(value["bytes"], f"{label} byte count", minimum=1, maximum=maximum)
    digest = value["sha256"]
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise _fail(f"{label} digest is invalid")
    return {"bytes": byte_count, "sha256": digest}


def _validate_final_bom_report(
    value: Any,
    capture: _ProcurementCapture,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _FINAL_BOM_KEYS:
        raise _fail("final-BOM child report does not match its closed shape")
    if isinstance(value["schema_version"], bool) or value["schema_version"] != 1:
        raise _fail("final-BOM child report schema version is invalid")
    if value["scope"] != _FINAL_BOM_SCOPE:
        raise _fail("final-BOM child report scope is invalid")
    _text(value["engine_version"], "final-BOM engine version", maximum=256)
    if value["board_basename"] != capture.board_name:
        raise _fail("final-BOM child report board basename is invalid")

    sources = value["sources"]
    if not isinstance(sources, Mapping) or set(sources) != _FINAL_BOM_SOURCE_KEYS:
        raise _fail("final-BOM child report sources are invalid")
    normalized_sources = {
        "board": _validate_identity(sources["board"], "final-BOM board", MAXIMUM_BOARD_BYTES),
        "manufacturing_package": _validate_identity(
            sources["manufacturing_package"],
            "final-BOM manufacturing package",
            MAXIMUM_PACKAGE_BYTES,
        ),
        "manifest": _validate_identity(sources["manifest"], "final-BOM manifest", 1 * 1024 * 1024),
        "bom": _validate_identity(sources["bom"], "final-BOM BOM", MAXIMUM_PACKAGE_BYTES),
        "canonical_bom": _validate_identity(
            sources["canonical_bom"], "final-BOM canonical BOM", MAXIMUM_PACKAGE_BYTES
        ),
        "package_board_source": _validate_identity(
            sources["package_board_source"],
            "final-BOM package board source",
            MAXIMUM_BOARD_BYTES,
        ),
    }
    if normalized_sources["board"] != capture.board.identity:
        raise _fail("final-BOM child report board identity is invalid")
    if normalized_sources["manufacturing_package"] != capture.package.identity:
        raise _fail("final-BOM child report package identity is invalid")

    counts = value["counts"]
    if not isinstance(counts, Mapping) or set(counts) != _FINAL_BOM_COUNT_KEYS:
        raise _fail("final-BOM child report counts are invalid")
    normalized_counts = {
        "board_parts": _integer(
            counts["board_parts"], "final-BOM board part count", minimum=0, maximum=100_000
        ),
        "board_in_bom_parts": _integer(
            counts["board_in_bom_parts"],
            "final-BOM board BOM part count",
            minimum=0,
            maximum=MAXIMUM_BOM_PARTS,
        ),
        "package_parts": _integer(
            counts["package_parts"], "final-BOM package part count", minimum=0, maximum=100_000
        ),
        "package_in_bom_parts": _integer(
            counts["package_in_bom_parts"],
            "final-BOM package BOM part count",
            minimum=0,
            maximum=100_000,
        ),
        "findings": _integer(
            counts["findings"], "final-BOM finding count", minimum=0, maximum=2
        ),
    }
    if (
        normalized_counts["board_in_bom_parts"] > normalized_counts["board_parts"]
        or normalized_counts["package_in_bom_parts"] > normalized_counts["package_parts"]
    ):
        raise _fail("final-BOM child report counts are inconsistent")

    raw_parts = value["in_bom_parts"]
    if not isinstance(raw_parts, list) or len(raw_parts) > MAXIMUM_BOM_PARTS:
        raise _fail("final-BOM child report parts are invalid")
    parts: list[dict[str, Any]] = []
    previous_reference: str | None = None
    seen_references: set[str] = set()
    for raw_part in raw_parts:
        if not isinstance(raw_part, Mapping) or set(raw_part) != _FINAL_BOM_PART_KEYS:
            raise _fail("final-BOM child report part is invalid")
        reference = _final_bom_text(raw_part["reference"], "final-BOM reference")
        assert isinstance(reference, str)
        if reference in seen_references or (
            previous_reference is not None and reference < previous_reference
        ):
            raise _fail("final-BOM child report references are not uniquely sorted")
        seen_references.add(reference)
        previous_reference = reference
        value_text = _final_bom_text(raw_part["value"], "final-BOM value")
        footprint = _final_bom_text(raw_part["footprint"], "final-BOM footprint")
        mpn = _final_bom_text(raw_part["mpn"], "final-BOM MPN", nullable=True)
        if raw_part["layer"] not in {"F", "B"} or raw_part["type"] not in {"SMD", "THT"}:
            raise _fail("final-BOM child report assembly metadata is invalid")
        parts.append(
            {
                "reference": reference,
                "value": value_text,
                "footprint": footprint,
                "mpn": mpn,
                "layer": raw_part["layer"],
                "type": raw_part["type"],
            }
        )
    if len(parts) != normalized_counts["board_in_bom_parts"]:
        raise _fail("final-BOM child report part count is inconsistent")

    raw_findings = value["findings"]
    if not isinstance(raw_findings, list) or len(raw_findings) > 2:
        raise _fail("final-BOM child report findings are invalid")
    findings: list[dict[str, str]] = []
    prior_code: str | None = None
    for raw_finding in raw_findings:
        if not isinstance(raw_finding, Mapping) or set(raw_finding) != {"code", "message"}:
            raise _fail("final-BOM child report finding is invalid")
        code = raw_finding["code"]
        if code not in _FINAL_BOM_FINDING_MESSAGES:
            raise _fail("final-BOM child report finding code is invalid")
        if raw_finding["message"] != _FINAL_BOM_FINDING_MESSAGES[code]:
            raise _fail("final-BOM child report finding message is invalid")
        if prior_code is not None and code <= prior_code:
            raise _fail("final-BOM child report findings are not uniquely sorted")
        prior_code = code
        findings.append({"code": code, "message": raw_finding["message"]})
    if len(findings) != normalized_counts["findings"]:
        raise _fail("final-BOM child report finding count is inconsistent")
    approved = value["approved"]
    if not isinstance(approved, bool) or approved != (not findings):
        raise _fail("final-BOM child report approval is inconsistent")
    codes = {finding["code"] for finding in findings}
    if (
        (normalized_sources["package_board_source"] != normalized_sources["board"])
        != ("package_board_source_mismatch" in codes)
    ):
        raise _fail("final-BOM child report board-source finding is inconsistent")
    if (
        (normalized_sources["bom"] != normalized_sources["canonical_bom"])
        != ("canonical_bom_mismatch" in codes)
    ):
        raise _fail("final-BOM child report canonical-BOM finding is inconsistent")

    return {
        "schema_version": 1,
        "scope": _FINAL_BOM_SCOPE,
        "engine_version": value["engine_version"],
        "board_basename": value["board_basename"],
        "sources": normalized_sources,
        "counts": normalized_counts,
        "in_bom_parts": parts,
        "findings": findings,
        "approved": approved,
    }


_PROCUREMENT_FINDING_MESSAGES = {
    "final_bom_rejected": "the exact manufacturing package BOM is not approved for the supplied board",
    "mpn_mismatch": "one or more final-BOM MPNs do not match the replayed catalog selection",
    "part_value_mismatch": "one or more final-BOM values do not match the resolved circuit",
    "reference_set_mismatch": "the final-BOM and replayed catalog reference sets differ",
    "supplier_part_number_ambiguous": "one supplier part number maps to multiple catalog part identities",
    "supplier_part_number_missing": "one or more populated references have no supplier part number",
    "footprint_mismatch": "one or more final-BOM footprints do not match the replayed catalog selection",
}


def _compose_procurement_result(
    capture: _ProcurementCapture,
    final_bom_report: dict[str, Any],
    final_bom_report_raw: bytes,
    selection: dict[str, Any],
    resolved: dict[str, Any],
) -> dict[str, Any]:
    findings: set[str] = set()
    if not final_bom_report["approved"]:
        findings.add("final_bom_rejected")

    try:
        resolved_parts = {part["reference"]: part for part in resolved["parts"]}
        selections = {item["reference"]: item for item in selection["selections"]}
        bom_parts = {
            part["reference"]: part for part in final_bom_report["in_bom_parts"]
        }
    except (KeyError, TypeError, ValueError):
        raise _fail("catalog selection part inventory is invalid") from None
    if (
        len(resolved_parts) != len(resolved["parts"])
        or len(selections) != len(selection["selections"])
        or len(bom_parts) != len(final_bom_report["in_bom_parts"])
    ):
        raise _fail("procurement inventory contains duplicate references")

    reference_sets_match = set(resolved_parts) == set(selections) == set(bom_parts)
    if not reference_sets_match:
        findings.add("reference_set_mismatch")
    compared_values_match = all(
        reference in resolved_parts
        and bom_parts[reference]["value"] == resolved_parts[reference]["value"]
        for reference in sorted(bom_parts)
    )
    values_match = reference_sets_match and compared_values_match
    if not compared_values_match:
        findings.add("part_value_mismatch")
    compared_footprints_match = all(
        reference in resolved_parts
        and reference in selections
        and bom_parts[reference]["footprint"]
        == resolved_parts[reference]["footprint"]
        == selections[reference]["footprint"]
        for reference in sorted(bom_parts)
    )
    footprints_match = reference_sets_match and compared_footprints_match
    if not compared_footprints_match:
        findings.add("footprint_mismatch")
    compared_mpns_match = all(
        reference in resolved_parts
        and reference in selections
        and isinstance(resolved_parts[reference]["mpn"], str)
        and bom_parts[reference]["mpn"]
        == resolved_parts[reference]["mpn"]
        == selections[reference]["mpn"]
        for reference in sorted(bom_parts)
    )
    mpns_match = reference_sets_match and compared_mpns_match
    if not compared_mpns_match:
        findings.add("mpn_mismatch")
    compared_supplier_parts_present = all(
        reference in selections
        and isinstance(selections[reference]["supplier_part_number"], str)
        and bool(selections[reference]["supplier_part_number"])
        for reference in sorted(bom_parts)
    )
    selected_supplier_parts_present = all(
        isinstance(item["supplier_part_number"], str)
        and bool(item["supplier_part_number"])
        for item in selections.values()
    )
    complete_supplier_parts_present = (
        compared_supplier_parts_present and selected_supplier_parts_present
    )
    supplier_parts_present = reference_sets_match and complete_supplier_parts_present
    if not complete_supplier_parts_present:
        findings.add("supplier_part_number_missing")

    sku_mappings: dict[str, set[tuple[str, str]]] = {}
    for reference in sorted(selections):
        item = selections[reference]
        sku = item["supplier_part_number"]
        if isinstance(sku, str):
            sku_mappings.setdefault(sku, set()).add(
                (item["mpn"], item["catalog_part_sha256"])
            )
    selected_supplier_parts_unambiguous = all(
        len(values) == 1 for values in sku_mappings.values()
    )
    supplier_parts_unambiguous = (
        reference_sets_match and selected_supplier_parts_unambiguous
    )
    if not selected_supplier_parts_unambiguous:
        findings.add("supplier_part_number_ambiguous")

    approved = not findings
    line_items: list[dict[str, Any]] = []
    if approved:
        grouped: dict[tuple[str, str, str, str], list[str]] = {}
        for reference in sorted(bom_parts):
            selected = selections[reference]
            key = (
                selected["mpn"],
                selected["supplier_part_number"],
                selected["catalog_part_sha256"],
                selected["footprint"],
            )
            grouped.setdefault(key, []).append(reference)
        for (mpn, sku, digest, footprint), references in sorted(grouped.items()):
            line_items.append(
                {
                    "mpn": mpn,
                    "supplier_part_number": sku,
                    "catalog_part_sha256": digest,
                    "footprint": footprint,
                    "quantity": len(references),
                    "references": references,
                }
            )

    finding_records = [
        {"code": code, "message": _PROCUREMENT_FINDING_MESSAGES[code]}
        for code in sorted(findings)
    ]
    sources = {
        "board": {"name": capture.board_name, **capture.board.identity},
        "manufacturing_package": capture.package.identity,
        "generation_bundle": capture.generation_bundle.identity,
        "catalog_snapshot": capture.catalog_snapshot.identity,
        "final_bom_report": _identity(final_bom_report_raw),
        "manifest": final_bom_report["sources"]["manifest"],
        "bom": final_bom_report["sources"]["bom"],
        "canonical_bom": final_bom_report["sources"]["canonical_bom"],
        "package_board_source": final_bom_report["sources"]["package_board_source"],
    }
    catalog = {
        "supplier": selection["supplier"],
        "snapshot_id": selection["snapshot_id"],
        "captured_at_unix": selection["captured_at_unix"],
        "expires_at_unix": selection["expires_at_unix"],
        "evaluated_at_unix": selection["evaluated_at_unix"],
        "catalog_sha256": selection["catalog"]["sha256"],
        "selection_receipt_sha256": canonical_sha256(selection),
        "input_spec_sha256": selection["input_spec_sha256"],
        "resolved_spec_sha256": selection["resolved_spec_sha256"],
        "policy": dict(selection["policy"]),
    }
    validation = {
        "final_bom_verified": final_bom_report["approved"],
        "catalog_selection_replayed": True,
        "reference_sets_matched": reference_sets_match,
        "part_values_matched": values_match,
        "part_footprints_matched": footprints_match,
        "part_mpns_matched": mpns_match,
        "supplier_part_numbers_present": supplier_parts_present,
        "supplier_part_numbers_unambiguous": supplier_parts_unambiguous,
        "caller_inputs_unchanged": True,
    }
    binding_payload = {
        "scope": PROCUREMENT_INTENT_SCOPE,
        "approved": approved,
        "quantity_basis": "per_board",
        "sources": sources,
        "final_bom": final_bom_report,
        "catalog": catalog,
        "line_items": line_items,
        "findings": finding_records,
        "validation": validation,
    }
    return {
        "schema_version": PROCUREMENT_INTENT_SCHEMA_VERSION,
        "scope": PROCUREMENT_INTENT_SCOPE,
        "status": "approved" if approved else "rejected",
        "approved": approved,
        "procurement_authorized": False,
        "network_performed": False,
        "order_placed": False,
        "current_availability_verified": False,
        "supplier_authenticity_verified": False,
        "quantity_basis": "per_board",
        "sources": sources,
        "final_bom": final_bom_report,
        "catalog": catalog,
        "line_items": line_items,
        "findings": finding_records,
        "validation": validation,
        "binding_sha256": _binding_digest(binding_payload),
    }


def evaluate_procurement_intent(
    board: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    generation_bundle: str | os.PathLike[str],
    catalog_snapshot: str | os.PathLike[str],
    pcbex: str | Sequence[str] = "pcbex",
    *,
    timeout_seconds: float = 120.0,
    _clock: Callable[[], float] = time.monotonic,
    _deadline: float | None = None,
) -> dict[str, Any]:
    """Evaluate exact per-board BOM/SKU intent without external side effects."""

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
    computed_deadline = start + timeout
    if not math.isfinite(computed_deadline):
        raise _fail("aggregate timeout is invalid")
    if _deadline is None:
        deadline = computed_deadline
    else:
        try:
            deadline = float(_deadline)
        except (TypeError, ValueError, OverflowError):
            raise _fail("aggregate timeout is invalid") from None
        if (
            not math.isfinite(deadline)
            or deadline <= start
            or deadline > computed_deadline
        ):
            raise _fail("aggregate timeout is invalid")

    # Freeze and capture every mutable caller path before consuming a possibly
    # stateful command iterable.
    capture = _capture_inputs(
        board,
        manufacturing_package,
        generation_bundle,
        catalog_snapshot,
        deadline=deadline,
        clock=_clock,
    )
    command = _normalize_command(pcbex)
    _remaining(deadline, _clock)

    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-procurement-intent-",
            dir=_trusted_temporary_root(),
        ) as directory:
            root = Path(directory)
            board_root = root / "board"
            package_root = root / "package"
            snapshot_root = root / "snapshot"
            report_root = root / "report"
            for role_root in (board_root, package_root, snapshot_root, report_root):
                role_root.mkdir(mode=0o700)
            staged_board = board_root / capture.board_name
            staged_package = package_root / "manufacturing.zip"
            staged_snapshot = snapshot_root / capture.snapshot_name
            report_path = report_root / "final-bom-report.json"
            for path, raw, maximum in (
                (staged_board, capture.board.raw, MAXIMUM_BOARD_BYTES),
                (staged_package, capture.package.raw, MAXIMUM_PACKAGE_BYTES),
                (staged_snapshot, capture.catalog_snapshot.raw, MAX_CATALOG_RAW_BYTES),
            ):
                atomic_write_no_clobber(path, raw, max_bytes=maximum)
                _remaining(deadline, _clock)

            selection, resolved, _snapshot = _catalog_selection_from_capture(
                capture, staged_snapshot
            )
            _remaining(deadline, _clock)
            argv = _validate_argv(
                [
                    *command,
                    "verify-final-bom",
                    f"--output={report_path}",
                    "--",
                    str(staged_board),
                    str(staged_package),
                ]
            )
            outer_remaining = _remaining(deadline, _clock)
            cleanup_and_reread_reserve = min(15.0, outer_remaining / 2.0)
            process_cleanup_timeout = cleanup_and_reread_reserve / 2.0
            process_timeout = outer_remaining - cleanup_and_reread_reserve
            if (
                not math.isfinite(process_timeout)
                or process_timeout <= 0
                or not math.isfinite(process_cleanup_timeout)
                or process_cleanup_timeout <= 0
            ):
                raise _fail("final-BOM child has no execution budget")
            try:
                completed = run_bounded(
                    argv,
                    timeout_seconds=process_timeout,
                    cleanup_timeout_seconds=process_cleanup_timeout,
                    max_stdout_bytes=MAXIMUM_CHILD_STDOUT_BYTES,
                    max_stderr_bytes=MAXIMUM_CHILD_STDERR_BYTES,
                )
            except BoundedProcessError:
                raise _fail("final-BOM child process failed") from None
            if completed.returncode != 0:
                raise _fail("final-BOM child rejected its inputs")
            _remaining(deadline, _clock)
            report_raw = _read_source(
                str(report_path), MAXIMUM_FINAL_BOM_REPORT_BYTES, "final-BOM report"
            )
            report = _validate_final_bom_report(
                _parse_json_object(report_raw, "final-BOM report"), capture
            )
            _remaining(deadline, _clock)

            for path, expected, maximum, label in (
                (staged_board, capture.board.raw, MAXIMUM_BOARD_BYTES, "staged board"),
                (
                    staged_package,
                    capture.package.raw,
                    MAXIMUM_PACKAGE_BYTES,
                    "staged manufacturing package",
                ),
                (
                    staged_snapshot,
                    capture.catalog_snapshot.raw,
                    MAX_CATALOG_RAW_BYTES,
                    "staged catalog snapshot",
                ),
            ):
                observed = _read_source(str(path), maximum, label)
                if observed != expected:
                    raise _fail(f"{label} changed during evaluation")
                _remaining(deadline, _clock)
            report_after = _read_source(
                str(report_path), MAXIMUM_FINAL_BOM_REPORT_BYTES, "final-BOM report"
            )
            if report_after != report_raw:
                raise _fail("final-BOM report changed during evaluation")
            _remaining(deadline, _clock)
            _reread_inputs(capture, deadline, _clock)
            result = _compose_procurement_result(
                capture,
                report,
                report_raw,
                selection,
                resolved,
            )
            # Keep the final caller-source observation after every semantic
            # comparison and result digest computation.  The report itself is
            # caller-selected child output, so authenticate it once more at
            # the same final boundary as the four direct sources.
            report_final = _read_source(
                str(report_path), MAXIMUM_FINAL_BOM_REPORT_BYTES, "final-BOM report"
            )
            if report_final != report_raw:
                raise _fail("final-BOM report changed during evaluation")
            _remaining(deadline, _clock)
            _reread_inputs(capture, deadline, _clock)
    except ProcurementIntentError:
        raise
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail("procurement intent workspace failed") from None

    encoded = _compact_json(result) + b"\n"
    if len(encoded) > MAXIMUM_PROCUREMENT_INTENT_BYTES:
        raise _fail("procurement intent report exceeds its byte bound")
    _remaining(deadline, _clock)
    return result


def validate_procurement_intent(
    intent: Mapping[str, Any] | bytes | bytearray | memoryview | str | os.PathLike[str],
    board: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    generation_bundle: str | os.PathLike[str],
    catalog_snapshot: str | os.PathLike[str],
    pcbex: str | Sequence[str] = "pcbex",
    *,
    timeout_seconds: float = 120.0,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Freshly recompute and compare one retained procurement-intent report."""

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
    # Capture the evidence sources before evaluating an untrusted retained
    # mapping or PathLike.  The fresh evaluation below must still report these
    # original identities, closing mutation through conversion hooks.
    initial_capture = _capture_inputs(
        board,
        manufacturing_package,
        generation_bundle,
        catalog_snapshot,
        deadline=deadline,
        clock=_clock,
    )
    frozen_sources = tuple(source.path for source in initial_capture.sources)
    retained_path: str | None = None
    retained_raw: bytes | None = None

    if isinstance(intent, Mapping):
        try:
            retained_raw = _bounded_injected_json_bytes(
                intent,
                maximum=MAXIMUM_PROCUREMENT_INTENT_BYTES,
                label="procurement intent report",
            )
            retained = _parse_json_object(retained_raw, "procurement intent report")
        except (
            CatalogGenerationProvenanceError,
            TypeError,
            ValueError,
            RuntimeError,
            RecursionError,
        ):
            raise _fail("procurement intent report is invalid") from None
    elif isinstance(intent, (bytes, bytearray, memoryview)):
        retained_raw = _bounded_bytes_like(
            intent,
            maximum=MAXIMUM_PROCUREMENT_INTENT_BYTES,
            label="procurement intent report",
        )
        retained = _parse_json_object(retained_raw, "procurement intent report")
    elif isinstance(intent, (str, os.PathLike)):
        retained_path = _freeze_path(intent, "procurement intent report source")
        _ensure_distinct_sources([*frozen_sources, retained_path])
        retained_raw = _read_source(
            retained_path,
            MAXIMUM_PROCUREMENT_INTENT_BYTES,
            "procurement intent report",
        )
        retained = _parse_json_object(retained_raw, "procurement intent report")
    else:
        raise _fail("procurement intent report is invalid")
    expected = evaluate_procurement_intent(
        *frozen_sources,
        pcbex,
        timeout_seconds=_remaining(deadline, _clock),
        _clock=_clock,
        _deadline=deadline,
    )
    expected_sources = expected.get("sources", {})
    for key, source in zip(
        ("board", "manufacturing_package", "generation_bundle", "catalog_snapshot"),
        initial_capture.sources,
    ):
        observed = expected_sources.get(key)
        if key == "board" and isinstance(observed, Mapping):
            observed = {name: observed[name] for name in ("bytes", "sha256") if name in observed}
        if observed != source.identity:
            raise _fail("procurement intent evidence changed during retained replay")
    if not _strict_json_equal(retained, expected):
        raise _fail("procurement intent report does not match exact replayed evidence")
    # Reauthenticate the caller inputs first, then make the retained artifact
    # the last program-owned observation.  No sequence can make independent
    # paths atomic, but this order catches a retained-file mutation performed
    # during the final direct-input scan.
    _reread_inputs(initial_capture, deadline, _clock)
    if retained_path is not None:
        observed = _read_source(
            retained_path,
            MAXIMUM_PROCUREMENT_INTENT_BYTES,
            "procurement intent report",
        )
        if observed != retained_raw:
            raise _fail("procurement intent report changed during retained replay")
        _remaining(deadline, _clock)
    return expected


# ``build`` is the artifact-oriented spelling used by the public CLI and docs;
# ``evaluate`` emphasizes that approval remains technical evidence only.
build_procurement_intent = evaluate_procurement_intent


def procurement_intent_json_schema() -> dict[str, Any]:
    """Return the closed schema-v1 procurement-intent evaluation schema."""

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
        "name": {"type": "string", "minLength": 11, "maxLength": 255},
        **board_identity["properties"],
    }
    finding = {
        "type": "object",
        "additionalProperties": False,
        "required": ["code", "message"],
        "properties": {"code": {"type": "string"}, "message": {"type": "string"}},
        "oneOf": [
            {
                "properties": {
                    "code": {"const": code},
                    "message": {"const": _PROCUREMENT_FINDING_MESSAGES[code]},
                }
            }
            for code in sorted(_PROCUREMENT_FINDING_MESSAGES)
        ],
    }
    line_item = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "mpn",
            "supplier_part_number",
            "catalog_part_sha256",
            "footprint",
            "quantity",
            "references",
        ],
        "properties": {
            "mpn": {"type": "string", "minLength": 1, "maxLength": 256},
            "supplier_part_number": {"type": "string", "minLength": 1, "maxLength": 4096},
            "catalog_part_sha256": digest,
            "footprint": {"type": "string", "minLength": 1, "maxLength": 512},
            "quantity": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_BOM_PARTS},
            "references": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAXIMUM_BOM_PARTS,
                "uniqueItems": True,
                "items": {"type": "string", "minLength": 1, "maxLength": 64},
            },
        },
    }
    policy = {
        "type": "object",
        "additionalProperties": False,
        "required": ["require_available", "require_basic", "allow_footprint_fallback"],
        "properties": {
            "require_available": {"type": "boolean"},
            "require_basic": {"type": "boolean"},
            "allow_footprint_fallback": {"type": "boolean"},
        },
    }
    final_bom_finding = {
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
            for code, message in sorted(_FINAL_BOM_FINDING_MESSAGES.items())
        ],
    }
    final_bom_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "scope",
            "engine_version",
            "board_basename",
            "sources",
            "counts",
            "in_bom_parts",
            "findings",
            "approved",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "scope": {"const": _FINAL_BOM_SCOPE},
            "engine_version": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "pattern": r"^\S(?:[\s\S]*\S)?$",
            },
            "board_basename": {
                "type": "string",
                "minLength": 11,
                "maxLength": 255,
                "pattern": r'^[^\u0000-\u001f<>:"/\\|?*]+\.kicad_pcb$',
            },
            "sources": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(_FINAL_BOM_SOURCE_KEYS),
                "properties": {
                    "board": identity(MAXIMUM_BOARD_BYTES),
                    "manufacturing_package": identity(MAXIMUM_PACKAGE_BYTES),
                    "manifest": identity(1 * 1024 * 1024),
                    "bom": identity(MAXIMUM_PACKAGE_BYTES),
                    "canonical_bom": identity(MAXIMUM_PACKAGE_BYTES),
                    "package_board_source": identity(MAXIMUM_BOARD_BYTES),
                },
            },
            "counts": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(_FINAL_BOM_COUNT_KEYS),
                "properties": {
                    "board_parts": {"type": "integer", "minimum": 0, "maximum": 100_000},
                    "board_in_bom_parts": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": MAXIMUM_BOM_PARTS,
                    },
                    "package_parts": {"type": "integer", "minimum": 0, "maximum": 100_000},
                    "package_in_bom_parts": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 100_000,
                    },
                    "findings": {"type": "integer", "minimum": 0, "maximum": 2},
                },
            },
            "in_bom_parts": {
                "type": "array",
                "maxItems": MAXIMUM_BOM_PARTS,
                "uniqueItems": True,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": sorted(_FINAL_BOM_PART_KEYS),
                    "properties": {
                        "reference": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAXIMUM_FINAL_BOM_PART_TEXT_BYTES,
                        },
                        "value": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAXIMUM_FINAL_BOM_PART_TEXT_BYTES,
                        },
                        "footprint": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAXIMUM_FINAL_BOM_PART_TEXT_BYTES,
                        },
                        "mpn": {
                            "anyOf": [
                                {"type": "null"},
                                {
                                    "type": "string",
                                    "minLength": 1,
                                    "maxLength": MAXIMUM_FINAL_BOM_PART_TEXT_BYTES,
                                },
                            ]
                        },
                        "layer": {"enum": ["F", "B"]},
                        "type": {"enum": ["SMD", "THT"]},
                    },
                },
            },
            "findings": {
                "type": "array",
                "maxItems": 2,
                "uniqueItems": True,
                "items": final_bom_finding,
            },
            "approved": {"type": "boolean"},
        },
        "allOf": [
            {
                "if": {"properties": {"approved": {"const": True}}},
                "then": {"properties": {"findings": {"maxItems": 0}}},
            },
            {
                "if": {"properties": {"approved": {"const": False}}},
                "then": {"properties": {"findings": {"minItems": 1}}},
            },
        ],
    }
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/offline-procurement-intent-v1.json",
        "title": "pcbex offline per-board procurement-intent evaluation",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "scope",
            "status",
            "approved",
            "procurement_authorized",
            "network_performed",
            "order_placed",
            "current_availability_verified",
            "supplier_authenticity_verified",
            "quantity_basis",
            "sources",
            "final_bom",
            "catalog",
            "line_items",
            "findings",
            "validation",
            "binding_sha256",
        ],
        "properties": {
            "schema_version": {"const": PROCUREMENT_INTENT_SCHEMA_VERSION},
            "scope": {"const": PROCUREMENT_INTENT_SCOPE},
            "status": {"enum": ["approved", "rejected"]},
            "approved": {"type": "boolean"},
            "procurement_authorized": {"const": False},
            "network_performed": {"const": False},
            "order_placed": {"const": False},
            "current_availability_verified": {"const": False},
            "supplier_authenticity_verified": {"const": False},
            "quantity_basis": {"const": "per_board"},
            "sources": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "board",
                    "manufacturing_package",
                    "generation_bundle",
                    "catalog_snapshot",
                    "final_bom_report",
                    "manifest",
                    "bom",
                    "canonical_bom",
                    "package_board_source",
                ],
                "properties": {
                    "board": board_identity,
                    "manufacturing_package": identity(MAXIMUM_PACKAGE_BYTES),
                    "generation_bundle": identity(MAX_PROVENANCE_BUNDLE_BYTES),
                    "catalog_snapshot": identity(MAX_CATALOG_RAW_BYTES),
                    "final_bom_report": identity(MAXIMUM_FINAL_BOM_REPORT_BYTES),
                    "manifest": identity(1 * 1024 * 1024),
                    "bom": identity(MAXIMUM_PACKAGE_BYTES),
                    "canonical_bom": identity(MAXIMUM_PACKAGE_BYTES),
                    "package_board_source": identity(MAXIMUM_BOARD_BYTES),
                },
            },
            "final_bom": final_bom_schema,
            "catalog": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "supplier",
                    "snapshot_id",
                    "captured_at_unix",
                    "expires_at_unix",
                    "evaluated_at_unix",
                    "catalog_sha256",
                    "selection_receipt_sha256",
                    "input_spec_sha256",
                    "resolved_spec_sha256",
                    "policy",
                ],
                "properties": {
                    "supplier": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64,
                        "pattern": _SUPPLIER_RE.pattern,
                    },
                    "snapshot_id": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128,
                        "pattern": _SNAPSHOT_ID_RE.pattern,
                    },
                    "captured_at_unix": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 9_223_372_036_854_775_807,
                    },
                    "expires_at_unix": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 9_223_372_036_854_775_807,
                    },
                    "evaluated_at_unix": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 9_223_372_036_854_775_807,
                    },
                    "catalog_sha256": digest,
                    "selection_receipt_sha256": digest,
                    "input_spec_sha256": digest,
                    "resolved_spec_sha256": digest,
                    "policy": policy,
                },
            },
            "line_items": {
                "type": "array",
                "maxItems": MAXIMUM_BOM_PARTS,
                "uniqueItems": True,
                "items": line_item,
            },
            "findings": {
                "type": "array",
                "maxItems": len(_PROCUREMENT_FINDING_MESSAGES),
                "uniqueItems": True,
                "items": finding,
            },
            "validation": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "final_bom_verified",
                    "catalog_selection_replayed",
                    "reference_sets_matched",
                    "part_values_matched",
                    "part_footprints_matched",
                    "part_mpns_matched",
                    "supplier_part_numbers_present",
                    "supplier_part_numbers_unambiguous",
                    "caller_inputs_unchanged",
                ],
                "properties": {
                    "final_bom_verified": {"type": "boolean"},
                    "catalog_selection_replayed": {"const": True},
                    "reference_sets_matched": {"type": "boolean"},
                    "part_values_matched": {"type": "boolean"},
                    "part_footprints_matched": {"type": "boolean"},
                    "part_mpns_matched": {"type": "boolean"},
                    "supplier_part_numbers_present": {"type": "boolean"},
                    "supplier_part_numbers_unambiguous": {"type": "boolean"},
                    "caller_inputs_unchanged": {"const": True},
                },
            },
            "binding_sha256": digest,
        },
        "$comment": (
            "Runtime validation additionally enforces UTF-8 byte bounds, strict ordering, "
            "cross-field counts and identities, timestamp ordering/TTL, quantity-to-reference "
            "equality, cross-line reference uniqueness, finding correlations, and the "
            "domain-separated canonical binding digest."
        ),
    }
    approved_validation = {
        key: {"const": True}
        for key in (
            "final_bom_verified",
            "catalog_selection_replayed",
            "reference_sets_matched",
            "part_values_matched",
            "part_footprints_matched",
            "part_mpns_matched",
            "supplier_part_numbers_present",
            "supplier_part_numbers_unambiguous",
            "caller_inputs_unchanged",
        )
    }
    schema["allOf"] = [
        {
            "if": {
                "properties": {"approved": {"const": True}},
                "required": ["approved"],
            },
            "then": {
                "properties": {
                    "status": {"const": "approved"},
                    "line_items": {"minItems": 1},
                    "findings": {"maxItems": 0},
                    "validation": {"properties": approved_validation},
                }
            },
        },
        {
            "if": {
                "properties": {"approved": {"const": False}},
                "required": ["approved"],
            },
            "then": {
                "properties": {
                    "status": {"const": "rejected"},
                    "line_items": {"maxItems": 0},
                    "findings": {"minItems": 1},
                }
            },
        },
    ]
    return schema


__all__ = [
    "ProcurementIntentError",
    "build_procurement_intent",
    "evaluate_procurement_intent",
    "procurement_intent_json_schema",
    "validate_procurement_intent",
]
