"""Exact offline coverage of a freshly replayed procurement intent by one offer.

The adapter performs no network access, authenticates neither supplier nor
price, reserves no inventory, and grants no procurement or payment authority.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any

from .bounded_io import BoundedIOError, atomic_write_no_clobber, read_bytes
from .catalog import MAX_CATALOG_TTL_SECONDS
from . import procurement_intent as _procurement


SUPPLIER_OFFER_SCHEMA_VERSION = 1
SUPPLIER_OFFER_SCOPE = "offline-normalized-supplier-offer-v1"
SUPPLIER_OFFER_COVERAGE_SCHEMA_VERSION = 1
SUPPLIER_OFFER_COVERAGE_SCOPE = (
    "offline-procurement-supplier-offer-coverage-v1"
)
SUPPLIER_OFFER_COVERAGE_BINDING_DOMAIN = (
    b"pcbex:offline-procurement-supplier-offer-coverage-v1\0"
)

MAXIMUM_SUPPLIER_OFFER_BYTES = 4 * 1024 * 1024
MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES = 16 * 1024 * 1024
MAXIMUM_TOTAL_INPUT_BYTES = 384 * 1024 * 1024
MAXIMUM_TIMEOUT_SECONDS = 600.0
MINIMUM_TIMEOUT_SECONDS = 1.0
MAXIMUM_ARGUMENT_BYTES = 32_768
MAXIMUM_OFFER_LINES = 256
MAXIMUM_REQUESTED_BOARDS = 1_000_000
MAXIMUM_QUANTITY = 2_147_483_647
MAXIMUM_MONEY_MICROS = 9_007_199_254_740_991
MAXIMUM_TIMESTAMP = 9_223_372_036_854_775_807
MAXIMUM_MPN_BYTES = 256
MAXIMUM_SUPPLIER_PART_NUMBER_BYTES = 4096
MAXIMUM_OFFER_ID_BYTES = 128
MAXIMUM_SUPPLIER_BYTES = 64
MAXIMUM_FOOTPRINT_BYTES = 512
MAXIMUM_REFERENCE_BYTES = 64

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_CURRENCY_RE = re.compile(r"[A-Z]{3}")
_SUPPLIER_RE = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?")
_SNAPSHOT_ID_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?"
)

_FALSE_CLAIM_KEYS = (
    "adapter_network_performed",
    "current_availability_verified",
    "supplier_authenticity_verified",
    "offer_authenticity_verified",
    "price_authenticity_verified",
    "inventory_reserved",
    "procurement_authorized",
    "order_ready",
    "order_placed",
    "payment_performed",
    "trusted_time_verified",
)
_VALIDATION_KEYS = (
    "procurement_intent_replayed",
    "procurement_intent_approved",
    "procurement_intent_digest_matched",
    "offer_normalized",
    "supplier_matched",
    "line_set_matched",
    "line_identities_matched",
    "quantities_covered",
    "validity_window_matched",
    "component_subtotal_checked",
    "caller_inputs_unchanged",
)
_SOURCE_KEYS = frozenset(
    {
        "board",
        "manufacturing_package",
        "generation_bundle",
        "catalog_snapshot",
        "procurement_intent",
        "supplier_offer",
    }
)
_OFFER_KEYS = frozenset(
    {
        "schema_version",
        "scope",
        "procurement_intent_sha256",
        "supplier",
        "offer_id",
        "valid_from_unix",
        "valid_until_unix",
        "currency",
        "lines",
    }
)
_OFFER_LINE_KEYS = frozenset(
    {
        "mpn",
        "supplier_part_number",
        "catalog_part_sha256",
        "quoted_quantity",
        "line_subtotal_micros",
    }
)
_COVERAGE_LINE_KEYS = frozenset(
    {
        "mpn",
        "supplier_part_number",
        "catalog_part_sha256",
        "footprint",
        "references",
        "per_board_quantity",
        "requested_boards",
        "required_quantity",
        "quoted_quantity",
        "surplus_quantity",
        "line_subtotal_micros",
    }
)
_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "scope",
        "status",
        "covered",
        "requested_boards",
        "evaluated_at_unix",
        "quantity_basis",
        "cost_scope",
        *_FALSE_CLAIM_KEYS,
        "sources",
        "procurement",
        "supplier_offer",
        "coverage_lines",
        "component_subtotal_micros",
        "findings",
        "validation",
        "binding_sha256",
    }
)

_FINDING_MESSAGES = {
    "offer_line_identity_mismatch": (
        "one or more supplier-offer lines do not match the procurement line identity"
    ),
    "offer_line_set_mismatch": (
        "the supplier-offer SKU set does not equal the procurement-intent SKU set"
    ),
    "offer_outside_declared_window": (
        "the evaluation instant is outside the offer's declared half-open validity window"
    ),
    "procurement_intent_rejected": (
        "the freshly replayed procurement intent is rejected"
    ),
    "quoted_quantity_shortfall": (
        "one or more quoted quantities are below the explicit board requirement"
    ),
    "supplier_mismatch": (
        "the supplier offer does not match the procurement-intent catalog supplier"
    ),
}


class SupplierOfferError(ValueError):
    """Stable, path-free supplier-offer boundary failure."""


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
class _SupplierOfferCapture:
    board: _CapturedSource
    package: _CapturedSource
    generation_bundle: _CapturedSource
    catalog_snapshot: _CapturedSource
    procurement_intent: _CapturedSource
    supplier_offer: _CapturedSource
    board_name: str
    catalog_name: str

    @property
    def sources(self) -> tuple[_CapturedSource, ...]:
        return (
            self.board,
            self.package,
            self.generation_bundle,
            self.catalog_snapshot,
            self.procurement_intent,
            self.supplier_offer,
        )


def _fail(message: str) -> SupplierOfferError:
    return SupplierOfferError(message)


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
        raise _fail("supplier-offer coverage cannot be serialized") from None


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise _fail(f"{label} is invalid")
    return value


def _canonical_text(value: Any, label: str, *, maximum: int) -> str:
    if type(value) is not str:
        raise _fail(f"{label} is invalid")
    if (
        not value
        or str.strip(value) != value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise _fail(f"{label} is invalid")
    try:
        encoded = str.encode(value, "utf-8", "strict")
    except UnicodeEncodeError:
        raise _fail(f"{label} is invalid") from None
    if len(encoded) > maximum:
        raise _fail(f"{label} exceeds its byte bound")
    return str.__str__(value)


def _bounded_text(value: Any, label: str, *, maximum: int) -> str:
    """Validate a prior-boundary text value without imposing new trimming."""

    if type(value) is not str or not value or str.__contains__(value, "\x00"):
        raise _fail(f"{label} is invalid")
    try:
        encoded = str.encode(value, "utf-8", "strict")
    except UnicodeEncodeError:
        raise _fail(f"{label} is invalid") from None
    if len(encoded) > maximum:
        raise _fail(f"{label} exceeds its byte bound")
    return str.__str__(value)


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise _fail(f"{label} is invalid")
    return value


def _validate_identity(value: Any, label: str, maximum: int) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"bytes", "sha256"}:
        raise _fail(f"{label} identity is invalid")
    return {
        "bytes": _integer(
            value["bytes"], f"{label} byte count", minimum=1, maximum=maximum
        ),
        "sha256": _digest(value["sha256"], f"{label} digest"),
    }


def _named_identity(value: Any, label: str, maximum: int) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"name", "bytes", "sha256"}:
        raise _fail(f"{label} identity is invalid")
    name = _bounded_text(value["name"], f"{label} name", maximum=255)
    return {
        "name": name,
        **_validate_identity(
            {"bytes": value["bytes"], "sha256": value["sha256"]},
            label,
            maximum,
        ),
    }


def _timeout_deadline(
    timeout_seconds: float, clock: Callable[[], float]
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
        remaining = deadline - float(clock())
    except (TypeError, ValueError, OverflowError):
        raise _fail("aggregate deadline clock is invalid") from None
    if not math.isfinite(remaining) or remaining <= 0:
        raise _fail("supplier-offer coverage exceeded its aggregate deadline")
    return min(remaining, MAXIMUM_TIMEOUT_SECONDS)


def evaluate_supplier_offer_coverage(
    board: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    generation_bundle: str | os.PathLike[str],
    catalog_snapshot: str | os.PathLike[str],
    procurement_intent: str | os.PathLike[str],
    supplier_offer: str | os.PathLike[str],
    pcbex: str | Sequence[str] = "pcbex",
    *,
    requested_boards: int,
    evaluated_at_unix: int,
    timeout_seconds: float = 120.0,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Freshly replay an intent and evaluate exact offline offer coverage."""

    _timeout, deadline = _timeout_deadline(timeout_seconds, _clock)
    requested = _integer(
        requested_boards,
        "requested board quantity",
        minimum=1,
        maximum=MAXIMUM_REQUESTED_BOARDS,
    )
    evaluated = _integer(
        evaluated_at_unix,
        "evaluation timestamp",
        minimum=0,
        maximum=MAXIMUM_TIMESTAMP,
    )
    capture = _capture_inputs(
        board,
        manufacturing_package,
        generation_bundle,
        catalog_snapshot,
        procurement_intent,
        supplier_offer,
        deadline=deadline,
        clock=_clock,
    )
    return _evaluate_capture(
        capture,
        pcbex,
        requested_boards=requested,
        evaluated_at_unix=evaluated,
        deadline=deadline,
        clock=_clock,
    )


def validate_supplier_offer_coverage(
    evidence: Mapping[str, Any] | bytes | bytearray | memoryview | str | os.PathLike[str],
    board: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    generation_bundle: str | os.PathLike[str],
    catalog_snapshot: str | os.PathLike[str],
    procurement_intent: str | os.PathLike[str],
    supplier_offer: str | os.PathLike[str],
    pcbex: str | Sequence[str] = "pcbex",
    *,
    requested_boards: int,
    evaluated_at_unix: int,
    timeout_seconds: float = 120.0,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Freshly replay and compare one retained canonical coverage report."""

    return _validate_supplier_offer_coverage_impl(
        evidence,
        board,
        manufacturing_package,
        generation_bundle,
        catalog_snapshot,
        procurement_intent,
        supplier_offer,
        pcbex,
        requested_boards=requested_boards,
        evaluated_at_unix=evaluated_at_unix,
        timeout_seconds=timeout_seconds,
        _clock=_clock,
    )


build_supplier_offer_coverage = evaluate_supplier_offer_coverage


# Implementations and schemas follow below.  Public definitions live above so
# the CLI/facade can import the frozen surface while the module stays cohesive.


def render_supplier_offer_coverage(value: Mapping[str, Any]) -> bytes:
    """Render canonical coverage JSON after runtime self-consistency checks."""

    return _render_supplier_offer_coverage_impl(value)


def normalized_supplier_offer_json_schema() -> dict[str, Any]:
    """Return the closed schema for normalized offline supplier offers."""

    return _normalized_supplier_offer_json_schema_impl()


def supplier_offer_coverage_json_schema() -> dict[str, Any]:
    """Return the closed schema for retained supplier-offer coverage."""

    return _supplier_offer_coverage_json_schema_impl()


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
    try:
        return _procurement._portable_leaf(path, label, suffix)
    except _procurement.ProcurementIntentError:
        raise _fail(f"{label} basename is invalid") from None


def _ensure_distinct_sources(paths: Sequence[str]) -> None:
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            if left == right:
                raise _fail("supplier-offer coverage input sources must be distinct")
            try:
                aliases = os.path.samefile(left, right)
            except (OSError, TypeError, ValueError):
                raise _fail("supplier-offer coverage input identity is invalid") from None
            if aliases:
                raise _fail("supplier-offer coverage input sources must be distinct")


def _read_source(path: str, maximum: int, label: str) -> bytes:
    try:
        raw = read_bytes(path, max_bytes=maximum)
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail(f"{label} source is invalid") from None
    if not raw:
        raise _fail(f"{label} source is empty")
    return raw


def _capture_inputs(
    board: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    generation_bundle: str | os.PathLike[str],
    catalog_snapshot: str | os.PathLike[str],
    procurement_intent: str | os.PathLike[str],
    supplier_offer: str | os.PathLike[str],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> _SupplierOfferCapture:
    specifications = (
        (
            _freeze_path(board, "board source"),
            "board",
            _procurement.MAXIMUM_BOARD_BYTES,
        ),
        (
            _freeze_path(manufacturing_package, "manufacturing package source"),
            "manufacturing package",
            _procurement.MAXIMUM_PACKAGE_BYTES,
        ),
        (
            _freeze_path(generation_bundle, "generation bundle source"),
            "generation bundle",
            _procurement.MAX_PROVENANCE_BUNDLE_BYTES,
        ),
        (
            _freeze_path(catalog_snapshot, "catalog snapshot source"),
            "catalog snapshot",
            _procurement.MAX_CATALOG_RAW_BYTES,
        ),
        (
            _freeze_path(procurement_intent, "procurement-intent source"),
            "procurement intent",
            _procurement.MAXIMUM_PROCUREMENT_INTENT_BYTES,
        ),
        (
            _freeze_path(supplier_offer, "supplier-offer source"),
            "supplier offer",
            MAXIMUM_SUPPLIER_OFFER_BYTES,
        ),
    )
    _ensure_distinct_sources([item[0] for item in specifications])
    board_name = _portable_leaf(specifications[0][0], "board", ".kicad_pcb")
    catalog_name = _portable_leaf(specifications[3][0], "catalog snapshot")
    captured: list[_CapturedSource] = []
    total = 0
    for path, label, maximum in specifications:
        raw = _read_source(path, maximum, label)
        total += len(raw)
        if total > MAXIMUM_TOTAL_INPUT_BYTES:
            raise _fail("supplier-offer coverage inputs exceed their aggregate bound")
        captured.append(_CapturedSource(path, label, maximum, raw))
        _remaining(deadline, clock)
    return _SupplierOfferCapture(
        board=captured[0],
        package=captured[1],
        generation_bundle=captured[2],
        catalog_snapshot=captured[3],
        procurement_intent=captured[4],
        supplier_offer=captured[5],
        board_name=board_name,
        catalog_name=catalog_name,
    )


def _reread_sources(
    capture: _SupplierOfferCapture,
    deadline: float,
    clock: Callable[[], float],
    additional: _CapturedSource | None = None,
) -> None:
    sources = (
        *capture.sources,
        *((additional,) if additional is not None else ()),
    )
    for source in sources:
        observed = _read_source(source.path, source.maximum, source.label)
        if observed != source.raw:
            raise _fail(f"{source.label} changed during supplier-offer evaluation")
        _remaining(deadline, clock)


def _trusted_temporary_root() -> Path:
    try:
        return Path(tempfile.gettempdir()).resolve(strict=True)
    except (OSError, RuntimeError):
        raise _fail("trusted temporary root is invalid") from None


def _stage_source(
    root: Path, leaf: str, filename: str, source: _CapturedSource
) -> Path:
    directory = root / leaf
    directory.mkdir(mode=0o700)
    destination = directory / filename
    try:
        atomic_write_no_clobber(destination, source.raw, max_bytes=source.maximum)
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail(f"could not stage {source.label}") from None
    return destination


def _normalize_offer(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _OFFER_KEYS:
        raise _fail("supplier offer does not match its closed shape")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != SUPPLIER_OFFER_SCHEMA_VERSION
        or value["scope"] != SUPPLIER_OFFER_SCOPE
    ):
        raise _fail("supplier offer identity is invalid")
    procurement_digest = _digest(
        value["procurement_intent_sha256"],
        "supplier-offer procurement-intent digest",
    )
    supplier = _canonical_text(
        value["supplier"], "supplier-offer supplier", maximum=MAXIMUM_SUPPLIER_BYTES
    )
    if _SUPPLIER_RE.fullmatch(supplier) is None:
        raise _fail("supplier-offer supplier is invalid")
    offer_id = _canonical_text(
        value["offer_id"], "supplier-offer ID", maximum=MAXIMUM_OFFER_ID_BYTES
    )
    valid_from = _integer(
        value["valid_from_unix"],
        "supplier-offer valid-from timestamp",
        minimum=0,
        maximum=MAXIMUM_TIMESTAMP,
    )
    valid_until = _integer(
        value["valid_until_unix"],
        "supplier-offer valid-until timestamp",
        minimum=0,
        maximum=MAXIMUM_TIMESTAMP,
    )
    if valid_from >= valid_until:
        raise _fail("supplier-offer validity interval is invalid")
    currency = value["currency"]
    if type(currency) is not str or _CURRENCY_RE.fullmatch(currency) is None:
        raise _fail("supplier-offer currency is invalid")
    raw_lines = value["lines"]
    if not isinstance(raw_lines, list) or len(raw_lines) > MAXIMUM_OFFER_LINES:
        raise _fail("supplier-offer lines are invalid")
    lines: list[dict[str, Any]] = []
    prior_sku: str | None = None
    subtotal = 0
    for raw_line in raw_lines:
        if not isinstance(raw_line, Mapping) or set(raw_line) != _OFFER_LINE_KEYS:
            raise _fail("supplier-offer line is invalid")
        mpn = _canonical_text(
            raw_line["mpn"], "supplier-offer MPN", maximum=MAXIMUM_MPN_BYTES
        )
        sku = _canonical_text(
            raw_line["supplier_part_number"],
            "supplier-offer part number",
            maximum=MAXIMUM_SUPPLIER_PART_NUMBER_BYTES,
        )
        if prior_sku is not None and sku <= prior_sku:
            raise _fail("supplier-offer lines are not strictly SKU-sorted")
        prior_sku = sku
        digest = _digest(
            raw_line["catalog_part_sha256"],
            "supplier-offer catalog-part digest",
        )
        quoted = _integer(
            raw_line["quoted_quantity"],
            "supplier-offer quoted quantity",
            minimum=1,
            maximum=MAXIMUM_QUANTITY,
        )
        line_subtotal = _integer(
            raw_line["line_subtotal_micros"],
            "supplier-offer line subtotal",
            minimum=0,
            maximum=MAXIMUM_MONEY_MICROS,
        )
        if subtotal > MAXIMUM_MONEY_MICROS - line_subtotal:
            raise _fail("supplier-offer component subtotal overflows")
        subtotal += line_subtotal
        lines.append(
            {
                "mpn": mpn,
                "supplier_part_number": sku,
                "catalog_part_sha256": digest,
                "quoted_quantity": quoted,
                "line_subtotal_micros": line_subtotal,
            }
        )
    return {
        "schema_version": SUPPLIER_OFFER_SCHEMA_VERSION,
        "scope": SUPPLIER_OFFER_SCOPE,
        "procurement_intent_sha256": procurement_digest,
        "supplier": supplier,
        "offer_id": offer_id,
        "valid_from_unix": valid_from,
        "valid_until_unix": valid_until,
        "currency": currency,
        "lines": lines,
    }


_PROCUREMENT_PROJECTION_KEYS = frozenset(
    {
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
        "catalog",
        "line_items",
        "findings",
        "validation",
    }
)
_PROCUREMENT_SOURCE_KEYS = frozenset(
    {
        "board",
        "manufacturing_package",
        "generation_bundle",
        "catalog_snapshot",
        "final_bom_report",
        "manifest",
        "bom",
        "canonical_bom",
        "package_board_source",
    }
)
_PROCUREMENT_CATALOG_KEYS = frozenset(
    {
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
    }
)
_PROCUREMENT_POLICY_KEYS = frozenset(
    {"require_available", "require_basic", "allow_footprint_fallback"}
)
_PROCUREMENT_LINE_KEYS = frozenset(
    {
        "mpn",
        "supplier_part_number",
        "catalog_part_sha256",
        "footprint",
        "quantity",
        "references",
    }
)
_PROCUREMENT_VALIDATION_KEYS = frozenset(
    {
        "final_bom_verified",
        "catalog_selection_replayed",
        "reference_sets_matched",
        "part_values_matched",
        "part_footprints_matched",
        "part_mpns_matched",
        "supplier_part_numbers_present",
        "supplier_part_numbers_unambiguous",
        "caller_inputs_unchanged",
    }
)


def _normalize_procurement_projection(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _PROCUREMENT_PROJECTION_KEYS:
        raise _fail("procurement projection does not match its closed shape")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != _procurement.PROCUREMENT_INTENT_SCHEMA_VERSION
        or value["scope"] != _procurement.PROCUREMENT_INTENT_SCOPE
        or value["quantity_basis"] != "per_board"
    ):
        raise _fail("procurement projection identity is invalid")
    approved = value["approved"]
    if type(approved) is not bool or value["status"] != (
        "approved" if approved else "rejected"
    ):
        raise _fail("procurement projection approval is inconsistent")
    for key in (
        "procurement_authorized",
        "network_performed",
        "order_placed",
        "current_availability_verified",
        "supplier_authenticity_verified",
    ):
        if value[key] is not False:
            raise _fail("procurement projection contains an invalid authority claim")

    raw_sources = value["sources"]
    if not isinstance(raw_sources, Mapping) or set(raw_sources) != _PROCUREMENT_SOURCE_KEYS:
        raise _fail("procurement projection sources are invalid")
    sources = {
        "board": _named_identity(
            raw_sources["board"], "procurement board", _procurement.MAXIMUM_BOARD_BYTES
        ),
        "manufacturing_package": _validate_identity(
            raw_sources["manufacturing_package"],
            "procurement manufacturing package",
            _procurement.MAXIMUM_PACKAGE_BYTES,
        ),
        "generation_bundle": _validate_identity(
            raw_sources["generation_bundle"],
            "procurement generation bundle",
            _procurement.MAX_PROVENANCE_BUNDLE_BYTES,
        ),
        "catalog_snapshot": _validate_identity(
            raw_sources["catalog_snapshot"],
            "procurement catalog snapshot",
            _procurement.MAX_CATALOG_RAW_BYTES,
        ),
        "final_bom_report": _validate_identity(
            raw_sources["final_bom_report"],
            "procurement final-BOM report",
            _procurement.MAXIMUM_FINAL_BOM_REPORT_BYTES,
        ),
        "manifest": _validate_identity(
            raw_sources["manifest"], "procurement manifest", 1 * 1024 * 1024
        ),
        "bom": _validate_identity(
            raw_sources["bom"], "procurement BOM", _procurement.MAXIMUM_PACKAGE_BYTES
        ),
        "canonical_bom": _validate_identity(
            raw_sources["canonical_bom"],
            "procurement canonical BOM",
            _procurement.MAXIMUM_PACKAGE_BYTES,
        ),
        "package_board_source": _validate_identity(
            raw_sources["package_board_source"],
            "procurement package board source",
            _procurement.MAXIMUM_BOARD_BYTES,
        ),
    }
    board_name = sources["board"]["name"]
    if _portable_leaf(board_name, "procurement board", ".kicad_pcb") != board_name:
        raise _fail("procurement board basename is invalid")

    raw_catalog = value["catalog"]
    if not isinstance(raw_catalog, Mapping) or set(raw_catalog) != _PROCUREMENT_CATALOG_KEYS:
        raise _fail("procurement catalog projection is invalid")
    supplier = _canonical_text(
        raw_catalog["supplier"],
        "procurement catalog supplier",
        maximum=MAXIMUM_SUPPLIER_BYTES,
    )
    if _SUPPLIER_RE.fullmatch(supplier) is None:
        raise _fail("procurement catalog supplier is invalid")
    snapshot_id = _canonical_text(
        raw_catalog["snapshot_id"],
        "procurement snapshot ID",
        maximum=MAXIMUM_OFFER_ID_BYTES,
    )
    if _SNAPSHOT_ID_RE.fullmatch(snapshot_id) is None or snapshot_id in {".", ".."}:
        raise _fail("procurement snapshot ID is invalid")
    captured = _integer(
        raw_catalog["captured_at_unix"],
        "procurement catalog capture timestamp",
        minimum=0,
        maximum=MAXIMUM_TIMESTAMP,
    )
    expires = _integer(
        raw_catalog["expires_at_unix"],
        "procurement catalog expiry timestamp",
        minimum=0,
        maximum=MAXIMUM_TIMESTAMP,
    )
    evaluated = _integer(
        raw_catalog["evaluated_at_unix"],
        "procurement catalog evaluation timestamp",
        minimum=0,
        maximum=MAXIMUM_TIMESTAMP,
    )
    if (
        not captured <= evaluated <= expires
        or expires - captured > MAX_CATALOG_TTL_SECONDS
    ):
        raise _fail("procurement catalog timestamps are inconsistent")
    raw_policy = raw_catalog["policy"]
    if not isinstance(raw_policy, Mapping) or set(raw_policy) != _PROCUREMENT_POLICY_KEYS:
        raise _fail("procurement catalog policy is invalid")
    policy: dict[str, bool] = {}
    for key in sorted(_PROCUREMENT_POLICY_KEYS):
        if type(raw_policy[key]) is not bool:
            raise _fail("procurement catalog policy is invalid")
        policy[key] = raw_policy[key]
    catalog = {
        "supplier": supplier,
        "snapshot_id": snapshot_id,
        "captured_at_unix": captured,
        "expires_at_unix": expires,
        "evaluated_at_unix": evaluated,
        "catalog_sha256": _digest(
            raw_catalog["catalog_sha256"], "procurement catalog digest"
        ),
        "selection_receipt_sha256": _digest(
            raw_catalog["selection_receipt_sha256"],
            "procurement selection-receipt digest",
        ),
        "input_spec_sha256": _digest(
            raw_catalog["input_spec_sha256"], "procurement input-spec digest"
        ),
        "resolved_spec_sha256": _digest(
            raw_catalog["resolved_spec_sha256"],
            "procurement resolved-spec digest",
        ),
        "policy": policy,
    }

    raw_lines = value["line_items"]
    if not isinstance(raw_lines, list) or len(raw_lines) > MAXIMUM_OFFER_LINES:
        raise _fail("procurement line items are invalid")
    lines: list[dict[str, Any]] = []
    prior_key: tuple[str, str, str, str] | None = None
    seen_references: set[str] = set()
    sku_mappings: dict[str, tuple[str, str]] = {}
    folded_mpns: set[str] = set()
    digest_mappings: dict[str, tuple[str, str, str]] = {}
    for raw_line in raw_lines:
        if not isinstance(raw_line, Mapping) or set(raw_line) != _PROCUREMENT_LINE_KEYS:
            raise _fail("procurement line item is invalid")
        mpn = _canonical_text(
            raw_line["mpn"], "procurement MPN", maximum=MAXIMUM_MPN_BYTES
        )
        sku = _canonical_text(
            raw_line["supplier_part_number"],
            "procurement supplier part number",
            maximum=MAXIMUM_SUPPLIER_PART_NUMBER_BYTES,
        )
        digest = _digest(
            raw_line["catalog_part_sha256"], "procurement catalog-part digest"
        )
        footprint = _canonical_text(
            raw_line["footprint"],
            "procurement footprint",
            maximum=MAXIMUM_FOOTPRINT_BYTES,
        )
        quantity = _integer(
            raw_line["quantity"],
            "procurement per-board quantity",
            minimum=1,
            maximum=MAXIMUM_OFFER_LINES,
        )
        raw_references = raw_line["references"]
        if (
            not isinstance(raw_references, list)
            or len(raw_references) != quantity
            or len(raw_references) > MAXIMUM_OFFER_LINES
        ):
            raise _fail("procurement references are invalid")
        references = [
            _canonical_text(
                reference,
                "procurement reference",
                maximum=MAXIMUM_REFERENCE_BYTES,
            )
            for reference in raw_references
        ]
        if any(left >= right for left, right in zip(references, references[1:])):
            raise _fail("procurement references are not strictly sorted")
        if seen_references & set(references):
            raise _fail("procurement references are duplicated")
        seen_references.update(references)
        line_key = (mpn, sku, digest, footprint)
        if prior_key is not None and line_key <= prior_key:
            raise _fail("procurement line items are not strictly sorted")
        prior_key = line_key
        sku_identity = (mpn, digest)
        if sku in sku_mappings and sku_mappings[sku] != sku_identity:
            raise _fail("procurement supplier part number is ambiguous")
        sku_mappings[sku] = sku_identity
        folded = mpn.casefold()
        if folded in folded_mpns:
            raise _fail("procurement MPN is duplicated case-insensitively")
        folded_mpns.add(folded)
        digest_identity = (mpn, sku, footprint)
        if digest in digest_mappings and digest_mappings[digest] != digest_identity:
            raise _fail("procurement catalog-part identity is inconsistent")
        digest_mappings[digest] = digest_identity
        lines.append(
            {
                "mpn": mpn,
                "supplier_part_number": sku,
                "catalog_part_sha256": digest,
                "footprint": footprint,
                "quantity": quantity,
                "references": references,
            }
        )

    raw_findings = value["findings"]
    if (
        not isinstance(raw_findings, list)
        or len(raw_findings) > len(_procurement._PROCUREMENT_FINDING_MESSAGES)
    ):
        raise _fail("procurement findings are invalid")
    findings: list[dict[str, str]] = []
    prior_code: str | None = None
    for raw_finding in raw_findings:
        if not isinstance(raw_finding, Mapping) or set(raw_finding) != {"code", "message"}:
            raise _fail("procurement finding is invalid")
        code = raw_finding["code"]
        if (
            type(code) is not str
            or code not in _procurement._PROCUREMENT_FINDING_MESSAGES
            or raw_finding["message"]
            != _procurement._PROCUREMENT_FINDING_MESSAGES[code]
            or (prior_code is not None and code <= prior_code)
        ):
            raise _fail("procurement findings are not canonical")
        prior_code = code
        findings.append({"code": code, "message": raw_finding["message"]})
    if approved != (not findings) or (approved and not lines) or (not approved and lines):
        raise _fail("procurement approval and line inventory are inconsistent")

    raw_validation = value["validation"]
    if (
        not isinstance(raw_validation, Mapping)
        or set(raw_validation) != _PROCUREMENT_VALIDATION_KEYS
        or any(type(raw_validation[key]) is not bool for key in raw_validation)
        or raw_validation["catalog_selection_replayed"] is not True
        or raw_validation["caller_inputs_unchanged"] is not True
    ):
        raise _fail("procurement validation state is invalid")
    validation = {key: raw_validation[key] for key in raw_validation}
    codes = {finding["code"] for finding in findings}
    final_bom_approved = (
        {key: sources["board"][key] for key in ("bytes", "sha256")}
        == sources["package_board_source"]
        and sources["bom"] == sources["canonical_bom"]
    )
    if (
        validation["final_bom_verified"] is not final_bom_approved
        or ("final_bom_rejected" in codes) != (not final_bom_approved)
        or ("reference_set_mismatch" in codes)
        != (not validation["reference_sets_matched"])
    ):
        raise _fail("procurement findings and validation are inconsistent")
    correlations = (
        ("part_value_mismatch", "part_values_matched"),
        ("footprint_mismatch", "part_footprints_matched"),
        ("mpn_mismatch", "part_mpns_matched"),
        ("supplier_part_number_missing", "supplier_part_numbers_present"),
        (
            "supplier_part_number_ambiguous",
            "supplier_part_numbers_unambiguous",
        ),
    )
    if validation["reference_sets_matched"]:
        if any(
            (code in codes) != (not validation[flag])
            for code, flag in correlations
        ):
            raise _fail("procurement findings and validation are inconsistent")
    elif any(validation[flag] is not False for _code, flag in correlations):
        raise _fail("procurement validation state is inconsistent")
    if approved and any(validation[key] is not True for key in validation):
        raise _fail("approved procurement validation is inconsistent")

    return {
        "schema_version": value["schema_version"],
        "scope": value["scope"],
        "status": value["status"],
        "approved": approved,
        "procurement_authorized": False,
        "network_performed": False,
        "order_placed": False,
        "current_availability_verified": False,
        "supplier_authenticity_verified": False,
        "quantity_basis": "per_board",
        "sources": sources,
        "catalog": catalog,
        "line_items": lines,
        "findings": findings,
        "validation": validation,
    }


def _normalize_sources(
    value: Any,
    procurement: Mapping[str, Any],
    offer: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _SOURCE_KEYS:
        raise _fail("supplier-offer coverage sources are invalid")
    sources = {
        "board": _named_identity(
            value["board"], "coverage board", _procurement.MAXIMUM_BOARD_BYTES
        ),
        "manufacturing_package": _validate_identity(
            value["manufacturing_package"],
            "coverage manufacturing package",
            _procurement.MAXIMUM_PACKAGE_BYTES,
        ),
        "generation_bundle": _validate_identity(
            value["generation_bundle"],
            "coverage generation bundle",
            _procurement.MAX_PROVENANCE_BUNDLE_BYTES,
        ),
        "catalog_snapshot": _validate_identity(
            value["catalog_snapshot"],
            "coverage catalog snapshot",
            _procurement.MAX_CATALOG_RAW_BYTES,
        ),
        "procurement_intent": _validate_identity(
            value["procurement_intent"],
            "coverage procurement intent",
            _procurement.MAXIMUM_PROCUREMENT_INTENT_BYTES,
        ),
        "supplier_offer": _validate_identity(
            value["supplier_offer"],
            "coverage supplier offer",
            MAXIMUM_SUPPLIER_OFFER_BYTES,
        ),
    }
    board_name = sources["board"]["name"]
    if _portable_leaf(board_name, "coverage board", ".kicad_pcb") != board_name:
        raise _fail("coverage board basename is invalid")
    procurement_sources = procurement["sources"]
    for key in (
        "board",
        "manufacturing_package",
        "generation_bundle",
        "catalog_snapshot",
    ):
        if not _strict_json_equal(sources[key], procurement_sources[key]):
            raise _fail(f"coverage {key} identity is not cross-bound")
    if (
        sources["procurement_intent"]["sha256"]
        != offer["procurement_intent_sha256"]
    ):
        raise _fail("supplier offer is not bound to the retained procurement intent")
    return sources


def _compose_result(
    procurement: Mapping[str, Any],
    offer: Mapping[str, Any],
    sources: Mapping[str, Any],
    *,
    requested_boards: int,
    evaluated_at_unix: int,
) -> dict[str, Any]:
    intent_lines = {
        line["supplier_part_number"]: line for line in procurement["line_items"]
    }
    if len(intent_lines) != len(procurement["line_items"]):
        raise _fail("procurement supplier part numbers are duplicated")
    offer_lines = {
        line["supplier_part_number"]: line for line in offer["lines"]
    }
    if len(offer_lines) != len(offer["lines"]):
        raise _fail("supplier-offer part numbers are duplicated")

    procurement_approved = procurement["approved"] is True
    supplier_matched = offer["supplier"] == procurement["catalog"]["supplier"]
    line_set_matched = set(offer_lines) == set(intent_lines)
    observed_identity_mismatch = False
    observed_shortfall = False
    required_by_sku: dict[str, int] = {}
    for sku, intent_line in intent_lines.items():
        per_board = intent_line["quantity"]
        if per_board > MAXIMUM_QUANTITY // requested_boards:
            raise _fail("required supplier-offer quantity overflows")
        required = per_board * requested_boards
        if required > MAXIMUM_QUANTITY:
            raise _fail("required supplier-offer quantity overflows")
        required_by_sku[sku] = required
        quoted = offer_lines.get(sku)
        if quoted is None:
            continue
        if (
            quoted["mpn"] != intent_line["mpn"]
            or quoted["catalog_part_sha256"]
            != intent_line["catalog_part_sha256"]
        ):
            observed_identity_mismatch = True
        if quoted["quoted_quantity"] < required:
            observed_shortfall = True
    # Identity and quantity predicates describe the common SKU intersection.
    # Exact set equality is an independent gate, so a pure missing/extra SKU
    # finding does not invent an identity mismatch or quantity shortfall.
    line_identities_matched = not observed_identity_mismatch
    quantities_covered = not observed_shortfall
    validity_window_matched = (
        offer["valid_from_unix"]
        <= evaluated_at_unix
        < offer["valid_until_unix"]
    )
    covered = all(
        (
            procurement_approved,
            supplier_matched,
            line_set_matched,
            line_identities_matched,
            quantities_covered,
            validity_window_matched,
        )
    )

    finding_codes: set[str] = set()
    if not procurement_approved:
        finding_codes.add("procurement_intent_rejected")
    if not supplier_matched:
        finding_codes.add("supplier_mismatch")
    if not line_set_matched:
        finding_codes.add("offer_line_set_mismatch")
    if observed_identity_mismatch:
        finding_codes.add("offer_line_identity_mismatch")
    if observed_shortfall:
        finding_codes.add("quoted_quantity_shortfall")
    if not validity_window_matched:
        finding_codes.add("offer_outside_declared_window")
    findings = [
        {"code": code, "message": _FINDING_MESSAGES[code]}
        for code in sorted(finding_codes)
    ]
    if covered != (not findings):
        raise _fail("supplier-offer coverage decision is inconsistent")

    subtotal = 0
    for line in offer["lines"]:
        line_subtotal = line["line_subtotal_micros"]
        if subtotal > MAXIMUM_MONEY_MICROS - line_subtotal:
            raise _fail("supplier-offer component subtotal overflows")
        subtotal += line_subtotal

    coverage_lines: list[dict[str, Any]] = []
    if covered:
        for sku in sorted(intent_lines):
            intent_line = intent_lines[sku]
            quoted = offer_lines[sku]
            required = required_by_sku[sku]
            coverage_lines.append(
                {
                    "mpn": intent_line["mpn"],
                    "supplier_part_number": sku,
                    "catalog_part_sha256": intent_line["catalog_part_sha256"],
                    "footprint": intent_line["footprint"],
                    "references": copy.deepcopy(intent_line["references"]),
                    "per_board_quantity": intent_line["quantity"],
                    "requested_boards": requested_boards,
                    "required_quantity": required,
                    "quoted_quantity": quoted["quoted_quantity"],
                    "surplus_quantity": quoted["quoted_quantity"] - required,
                    "line_subtotal_micros": quoted["line_subtotal_micros"],
                }
            )

    validation = {
        "procurement_intent_replayed": True,
        "procurement_intent_approved": procurement_approved,
        "procurement_intent_digest_matched": True,
        "offer_normalized": True,
        "supplier_matched": supplier_matched,
        "line_set_matched": line_set_matched,
        "line_identities_matched": line_identities_matched,
        "quantities_covered": quantities_covered,
        "validity_window_matched": validity_window_matched,
        "component_subtotal_checked": True,
        "caller_inputs_unchanged": True,
    }
    result: dict[str, Any] = {
        "schema_version": SUPPLIER_OFFER_COVERAGE_SCHEMA_VERSION,
        "scope": SUPPLIER_OFFER_COVERAGE_SCOPE,
        "status": "covered" if covered else "not_covered",
        "covered": covered,
        "requested_boards": requested_boards,
        "evaluated_at_unix": evaluated_at_unix,
        "quantity_basis": "explicit_board_quantity",
        "cost_scope": "component_lines_only",
        **{key: False for key in _FALSE_CLAIM_KEYS},
        "sources": copy.deepcopy(dict(sources)),
        "procurement": copy.deepcopy(dict(procurement)),
        "supplier_offer": copy.deepcopy(dict(offer)),
        "coverage_lines": coverage_lines,
        "component_subtotal_micros": subtotal if covered else None,
        "findings": findings,
        "validation": validation,
    }
    result["binding_sha256"] = _sha256(
        SUPPLIER_OFFER_COVERAGE_BINDING_DOMAIN + _compact_json(result)
    )
    return result


def _validate_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _RESULT_KEYS:
        raise _fail("supplier-offer coverage report does not match its closed shape")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != SUPPLIER_OFFER_COVERAGE_SCHEMA_VERSION
        or value["scope"] != SUPPLIER_OFFER_COVERAGE_SCOPE
        or value["quantity_basis"] != "explicit_board_quantity"
        or value["cost_scope"] != "component_lines_only"
    ):
        raise _fail("supplier-offer coverage report identity is invalid")
    requested = _integer(
        value["requested_boards"],
        "coverage requested board quantity",
        minimum=1,
        maximum=MAXIMUM_REQUESTED_BOARDS,
    )
    evaluated = _integer(
        value["evaluated_at_unix"],
        "coverage evaluation timestamp",
        minimum=0,
        maximum=MAXIMUM_TIMESTAMP,
    )
    procurement = _normalize_procurement_projection(value["procurement"])
    offer = _normalize_offer(value["supplier_offer"])
    sources = _normalize_sources(value["sources"], procurement, offer)
    _digest(value["binding_sha256"], "supplier-offer coverage binding")
    expected = _compose_result(
        procurement,
        offer,
        sources,
        requested_boards=requested,
        evaluated_at_unix=evaluated,
    )
    if not _strict_json_equal(value, expected):
        raise _fail("supplier-offer coverage report is internally inconsistent")
    return expected


def _snapshot_mapping(value: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    try:
        raw = _procurement._bounded_injected_json_bytes(
            value,
            maximum=MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES,
            label=label,
        )
    except (
        _procurement.CatalogGenerationProvenanceError,
        TypeError,
        ValueError,
        RuntimeError,
        RecursionError,
    ):
        raise _fail(f"{label} is invalid") from None
    return _parse_json_object(raw, label)


def _render_supplier_offer_coverage_impl(value: Mapping[str, Any]) -> bytes:
    try:
        snapshot = _snapshot_mapping(value, label="supplier-offer coverage report")
        _validate_result(snapshot)
        encoder = json.JSONEncoder(
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        output = bytearray()
        for chunk in encoder.iterencode(snapshot):
            encoded = str.encode(chunk, "utf-8", "strict")
            if (
                len(output) + len(encoded) + 1
                > MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES
            ):
                raise _fail("supplier-offer coverage exceeds its byte bound")
            output.extend(encoded)
        output.append(0x0A)
        return bytes(output)
    except SupplierOfferError:
        raise
    except (TypeError, ValueError, UnicodeError, RuntimeError, RecursionError):
        raise _fail("supplier-offer coverage cannot be serialized") from None


def _snapshot_procurement(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        raw = _procurement._bounded_injected_json_bytes(
            value,
            maximum=_procurement.MAXIMUM_PROCUREMENT_INTENT_BYTES,
            label="fresh procurement-intent report",
        )
    except (
        _procurement.CatalogGenerationProvenanceError,
        TypeError,
        ValueError,
        RuntimeError,
        RecursionError,
    ):
        raise _fail("fresh procurement-intent replay result is invalid") from None
    return _parse_json_object(raw, "fresh procurement-intent report")


def _evaluate_capture(
    capture: _SupplierOfferCapture,
    pcbex: str | Sequence[str],
    *,
    requested_boards: int,
    evaluated_at_unix: int,
    deadline: float,
    clock: Callable[[], float],
) -> dict[str, Any]:
    # Authenticate the raw intent correlation and both retained JSON inputs
    # before any caller-selected child can execute.
    retained_intent = _parse_json_object(
        capture.procurement_intent.raw, "procurement-intent report"
    )
    offer = _normalize_offer(
        _parse_json_object(capture.supplier_offer.raw, "supplier-offer report")
    )
    if (
        offer["procurement_intent_sha256"]
        != capture.procurement_intent.identity["sha256"]
    ):
        raise _fail("supplier offer is not bound to the retained procurement intent")
    _remaining(deadline, clock)

    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-supplier-offer-", dir=_trusted_temporary_root()
        ) as directory:
            root = Path(directory)
            staged_board = _stage_source(
                root, "board", capture.board_name, capture.board
            )
            _remaining(deadline, clock)
            staged_package = _stage_source(
                root, "package", "manufacturing.zip", capture.package
            )
            _remaining(deadline, clock)
            staged_generation = _stage_source(
                root,
                "generation",
                "generation-bundle.json",
                capture.generation_bundle,
            )
            _remaining(deadline, clock)
            staged_catalog = _stage_source(
                root, "catalog", capture.catalog_name, capture.catalog_snapshot
            )
            _remaining(deadline, clock)
            staged_intent = _stage_source(
                root,
                "intent",
                "procurement-intent.json",
                capture.procurement_intent,
            )
            _remaining(deadline, clock)
            staged_offer = _stage_source(
                root, "offer", "supplier-offer.json", capture.supplier_offer
            )
            _remaining(deadline, clock)

            replay_remaining = _remaining(deadline, clock)
            replay_budget = replay_remaining / 2.0
            if not math.isfinite(replay_budget) or replay_budget <= 0:
                raise _fail("procurement-intent replay has no execution budget")
            try:
                fresh_full = _procurement.validate_procurement_intent(
                    staged_intent,
                    staged_board,
                    staged_package,
                    staged_generation,
                    staged_catalog,
                    pcbex,
                    timeout_seconds=replay_budget,
                    _clock=clock,
                )
            except _procurement.ProcurementIntentError as error:
                raise _fail(f"procurement-intent replay failed: {error}") from None
            _remaining(deadline, clock)
            fresh = _snapshot_procurement(fresh_full)
            if not _strict_json_equal(retained_intent, fresh):
                raise _fail(
                    "fresh procurement-intent replay did not reproduce the retained report"
                )
            if set(fresh) != set(_procurement.procurement_intent_json_schema()["required"]):
                raise _fail("fresh procurement-intent replay result is invalid")
            projection_value = {
                key: copy.deepcopy(item)
                for key, item in fresh.items()
                if key not in {"final_bom", "binding_sha256"}
            }
            procurement = _normalize_procurement_projection(projection_value)

            expected_direct = {
                "board": {"name": capture.board_name, **capture.board.identity},
                "manufacturing_package": capture.package.identity,
                "generation_bundle": capture.generation_bundle.identity,
                "catalog_snapshot": capture.catalog_snapshot.identity,
            }
            for key, expected in expected_direct.items():
                if not _strict_json_equal(procurement["sources"][key], expected):
                    raise _fail(f"fresh procurement {key} identity is not cross-bound")

            staged_pairs = (
                (staged_board, capture.board),
                (staged_package, capture.package),
                (staged_generation, capture.generation_bundle),
                (staged_catalog, capture.catalog_snapshot),
                (staged_intent, capture.procurement_intent),
                (staged_offer, capture.supplier_offer),
            )
            for path, source in staged_pairs:
                if _read_source(str(path), source.maximum, source.label) != source.raw:
                    raise _fail(f"{source.label} changed in the private workspace")
                _remaining(deadline, clock)
            _reread_sources(capture, deadline, clock)

            sources = {
                "board": {"name": capture.board_name, **capture.board.identity},
                "manufacturing_package": capture.package.identity,
                "generation_bundle": capture.generation_bundle.identity,
                "catalog_snapshot": capture.catalog_snapshot.identity,
                "procurement_intent": capture.procurement_intent.identity,
                "supplier_offer": capture.supplier_offer.identity,
            }
            result = _compose_result(
                procurement,
                offer,
                sources,
                requested_boards=requested_boards,
                evaluated_at_unix=evaluated_at_unix,
            )
            render_supplier_offer_coverage(result)
            for path, source in staged_pairs:
                if _read_source(str(path), source.maximum, source.label) != source.raw:
                    raise _fail(f"{source.label} changed in the private workspace")
                _remaining(deadline, clock)
            _reread_sources(capture, deadline, clock)
    except SupplierOfferError:
        raise
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail("supplier-offer private workspace failed") from None
    _remaining(deadline, clock)
    return result


def _bounded_bytes_like(
    value: bytes | bytearray | memoryview, *, maximum: int, label: str
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
    except SupplierOfferError:
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


def _validate_supplier_offer_coverage_impl(
    evidence: Mapping[str, Any] | bytes | bytearray | memoryview | str | os.PathLike[str],
    board: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    generation_bundle: str | os.PathLike[str],
    catalog_snapshot: str | os.PathLike[str],
    procurement_intent: str | os.PathLike[str],
    supplier_offer: str | os.PathLike[str],
    pcbex: str | Sequence[str],
    *,
    requested_boards: int,
    evaluated_at_unix: int,
    timeout_seconds: float,
    _clock: Callable[[], float],
) -> dict[str, Any]:
    _timeout, deadline = _timeout_deadline(timeout_seconds, _clock)
    requested = _integer(
        requested_boards,
        "requested board quantity",
        minimum=1,
        maximum=MAXIMUM_REQUESTED_BOARDS,
    )
    evaluated = _integer(
        evaluated_at_unix,
        "evaluation timestamp",
        minimum=0,
        maximum=MAXIMUM_TIMESTAMP,
    )
    # Capture all six direct sources before traversing/converting the retained
    # representation or consuming a stateful pcbex iterable.
    capture = _capture_inputs(
        board,
        manufacturing_package,
        generation_bundle,
        catalog_snapshot,
        procurement_intent,
        supplier_offer,
        deadline=deadline,
        clock=_clock,
    )
    injected_mapping = False
    retained_source: _CapturedSource | None = None
    if isinstance(evidence, Mapping):
        injected_mapping = True
        retained_raw = render_supplier_offer_coverage(evidence)
    elif isinstance(evidence, (bytes, bytearray, memoryview)):
        retained_raw = _bounded_bytes_like(
            evidence,
            maximum=MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES,
            label="supplier-offer coverage report",
        )
    elif isinstance(evidence, (str, os.PathLike)):
        retained_path = _freeze_path(
            evidence, "supplier-offer coverage report source"
        )
        _ensure_distinct_sources(
            [*(source.path for source in capture.sources), retained_path]
        )
        retained_raw = _read_source(
            retained_path,
            MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES,
            "supplier-offer coverage report",
        )
        retained_source = _CapturedSource(
            retained_path,
            "supplier-offer coverage report",
            MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES,
            retained_raw,
        )
    else:
        raise _fail("supplier-offer coverage report is invalid")
    if (
        sum(len(source.raw) for source in capture.sources) + len(retained_raw)
        > MAXIMUM_TOTAL_INPUT_BYTES
    ):
        raise _fail("supplier-offer coverage inputs exceed their aggregate bound")
    retained = _parse_json_object(retained_raw, "supplier-offer coverage report")
    if not injected_mapping and retained_raw != render_supplier_offer_coverage(retained):
        raise _fail("supplier-offer coverage report is not canonical pretty JSON")
    expected = _evaluate_capture(
        capture,
        pcbex,
        requested_boards=requested,
        evaluated_at_unix=evaluated,
        deadline=deadline,
        clock=_clock,
    )
    if not _strict_json_equal(retained, expected):
        raise _fail(
            "supplier-offer coverage report does not match exact replayed evidence"
        )
    if not injected_mapping and retained_raw != render_supplier_offer_coverage(expected):
        raise _fail("supplier-offer coverage report is not canonical pretty JSON")
    _reread_sources(capture, deadline, _clock, retained_source)
    _remaining(deadline, _clock)
    return expected


def _normalized_supplier_offer_json_schema_impl() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    line = {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(_OFFER_LINE_KEYS),
        "properties": {
            "mpn": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_MPN_BYTES,
            },
            "supplier_part_number": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_SUPPLIER_PART_NUMBER_BYTES,
            },
            "catalog_part_sha256": copy.deepcopy(digest),
            "quoted_quantity": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAXIMUM_QUANTITY,
            },
            "line_subtotal_micros": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAXIMUM_MONEY_MICROS,
            },
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/schemas/"
            "offline-normalized-supplier-offer-v1.json"
        ),
        "title": "pcbex normalized offline supplier offer",
        "type": "object",
        "additionalProperties": False,
        "required": sorted(_OFFER_KEYS),
        "properties": {
            "schema_version": {"const": SUPPLIER_OFFER_SCHEMA_VERSION},
            "scope": {"const": SUPPLIER_OFFER_SCOPE},
            "procurement_intent_sha256": copy.deepcopy(digest),
            "supplier": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_SUPPLIER_BYTES,
                "pattern": "^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$",
            },
            "offer_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_OFFER_ID_BYTES,
            },
            "valid_from_unix": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAXIMUM_TIMESTAMP,
            },
            "valid_until_unix": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAXIMUM_TIMESTAMP,
            },
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "lines": {
                "type": "array",
                "maxItems": MAXIMUM_OFFER_LINES,
                "uniqueItems": True,
                "items": line,
            },
        },
        "$comment": (
            "Runtime validation additionally enforces UTF-8 byte bounds, canonical "
            "text, valid_from_unix < valid_until_unix, strict SKU ordering and "
            "uniqueness, exact JSON integer types, and checked subtotal aggregation."
        ),
    }


def _supplier_offer_coverage_json_schema_impl() -> dict[str, Any]:
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

    board_identity = identity(_procurement.MAXIMUM_BOARD_BYTES)
    board_identity["required"] = ["name", "bytes", "sha256"]
    board_identity["properties"] = {
        "name": {
            "type": "string",
            "minLength": 11,
            "maxLength": 255,
            "pattern": r'^[^\u0000-\u001f<>:"/\\|?*]+\.kicad_pcb$',
        },
        **board_identity["properties"],
    }

    offer_schema = copy.deepcopy(normalized_supplier_offer_json_schema())
    for key in ("$schema", "$id", "title", "$comment"):
        offer_schema.pop(key, None)

    procurement_schema = copy.deepcopy(_procurement.procurement_intent_json_schema())
    procurement_schema["required"].remove("final_bom")
    procurement_schema["required"].remove("binding_sha256")
    del procurement_schema["properties"]["final_bom"]
    del procurement_schema["properties"]["binding_sha256"]
    for key in ("$schema", "$id", "title", "$comment"):
        procurement_schema.pop(key, None)

    coverage_line = {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(_COVERAGE_LINE_KEYS),
        "properties": {
            "mpn": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_MPN_BYTES,
            },
            "supplier_part_number": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_SUPPLIER_PART_NUMBER_BYTES,
            },
            "catalog_part_sha256": copy.deepcopy(digest),
            "footprint": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_FOOTPRINT_BYTES,
            },
            "references": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAXIMUM_OFFER_LINES,
                "uniqueItems": True,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAXIMUM_REFERENCE_BYTES,
                },
            },
            "per_board_quantity": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAXIMUM_OFFER_LINES,
            },
            "requested_boards": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAXIMUM_REQUESTED_BOARDS,
            },
            "required_quantity": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAXIMUM_QUANTITY,
            },
            "quoted_quantity": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAXIMUM_QUANTITY,
            },
            "surplus_quantity": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAXIMUM_QUANTITY,
            },
            "line_subtotal_micros": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAXIMUM_MONEY_MICROS,
            },
        },
    }
    finding = {
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
            for code, message in sorted(_FINDING_MESSAGES.items())
        ]
    }
    validation_properties = {
        key: (
            {"const": True}
            if key
            in {
                "procurement_intent_replayed",
                "procurement_intent_digest_matched",
                "offer_normalized",
                "component_subtotal_checked",
                "caller_inputs_unchanged",
            }
            else {"type": "boolean"}
        )
        for key in _VALIDATION_KEYS
    }
    properties: dict[str, Any] = {
        "schema_version": {"const": SUPPLIER_OFFER_COVERAGE_SCHEMA_VERSION},
        "scope": {"const": SUPPLIER_OFFER_COVERAGE_SCOPE},
        "status": {"enum": ["covered", "not_covered"]},
        "covered": {"type": "boolean"},
        "requested_boards": {
            "type": "integer",
            "minimum": 1,
            "maximum": MAXIMUM_REQUESTED_BOARDS,
        },
        "evaluated_at_unix": {
            "type": "integer",
            "minimum": 0,
            "maximum": MAXIMUM_TIMESTAMP,
        },
        "quantity_basis": {"const": "explicit_board_quantity"},
        "cost_scope": {"const": "component_lines_only"},
        **{key: {"const": False} for key in _FALSE_CLAIM_KEYS},
        "sources": {
            "type": "object",
            "additionalProperties": False,
            "required": sorted(_SOURCE_KEYS),
            "properties": {
                "board": board_identity,
                "manufacturing_package": identity(_procurement.MAXIMUM_PACKAGE_BYTES),
                "generation_bundle": identity(
                    _procurement.MAX_PROVENANCE_BUNDLE_BYTES
                ),
                "catalog_snapshot": identity(_procurement.MAX_CATALOG_RAW_BYTES),
                "procurement_intent": identity(
                    _procurement.MAXIMUM_PROCUREMENT_INTENT_BYTES
                ),
                "supplier_offer": identity(MAXIMUM_SUPPLIER_OFFER_BYTES),
            },
        },
        "procurement": procurement_schema,
        "supplier_offer": offer_schema,
        "coverage_lines": {
            "type": "array",
            "maxItems": MAXIMUM_OFFER_LINES,
            "uniqueItems": True,
            "items": coverage_line,
        },
        "component_subtotal_micros": {
            "anyOf": [
                {"type": "null"},
                {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAXIMUM_MONEY_MICROS,
                },
            ]
        },
        "findings": {
            "type": "array",
            "maxItems": len(_FINDING_MESSAGES),
            "uniqueItems": True,
            "items": finding,
        },
        "validation": {
            "type": "object",
            "additionalProperties": False,
            "required": list(_VALIDATION_KEYS),
            "properties": validation_properties,
        },
        "binding_sha256": copy.deepcopy(digest),
    }
    all_true = {key: {"const": True} for key in _VALIDATION_KEYS}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/schemas/"
            "offline-procurement-supplier-offer-coverage-v1.json"
        ),
        "title": "pcbex offline procurement supplier-offer coverage",
        "type": "object",
        "additionalProperties": False,
        "required": sorted(_RESULT_KEYS),
        "properties": properties,
        "allOf": [
            {
                "if": {
                    "properties": {"covered": {"const": True}},
                    "required": ["covered"],
                },
                "then": {
                    "properties": {
                        "status": {"const": "covered"},
                        "coverage_lines": {"minItems": 1},
                        "component_subtotal_micros": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": MAXIMUM_MONEY_MICROS,
                        },
                        "findings": {"maxItems": 0},
                        "validation": {"properties": all_true},
                        "procurement": {
                            "properties": {"approved": {"const": True}}
                        },
                    }
                },
            },
            {
                "if": {
                    "properties": {"covered": {"const": False}},
                    "required": ["covered"],
                },
                "then": {
                    "properties": {
                        "status": {"const": "not_covered"},
                        "coverage_lines": {"maxItems": 0},
                        "component_subtotal_micros": {"type": "null"},
                        "findings": {"minItems": 1},
                    }
                },
            },
        ],
        "$comment": (
            "Runtime validation additionally enforces exact built-in scalar types, "
            "canonical UTF-8 byte bounds, raw source cross-bindings, line ordering "
            "and functional identities, checked quantity/money arithmetic, the "
            "half-open offer window, decision/finding equivalence, and the "
            "domain-separated binding. Fresh validation additionally replays the "
            "retained procurement intent and rereads all sources."
        ),
    }


__all__ = [
    "MAXIMUM_SUPPLIER_OFFER_BYTES",
    "MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES",
    "SupplierOfferError",
    "build_supplier_offer_coverage",
    "evaluate_supplier_offer_coverage",
    "normalized_supplier_offer_json_schema",
    "render_supplier_offer_coverage",
    "supplier_offer_coverage_json_schema",
    "validate_supplier_offer_coverage",
]
