"""Exact offline composition of assembly and acquired supplier-offer evidence.

The composer freshly replays the retained v1.467 assembly evidence and v1.468
supplier-offer coverage against one privately staged source snapshot.  It
validates, but does not re-perform, the v1.469 HTTPS acquisition.  It performs
no network, manufacturing, ordering, payment, reservation, or authorization.
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
import tempfile
import time
from typing import Any

from .bounded_io import BoundedIOError, atomic_write_no_clobber
from . import assembly_evidence as _assembly
from . import circuit_handoff_bundle as _handoff
from . import procurement_intent as _procurement
from . import supplier_offer as _offer
from . import supplier_offer_acquisition as _acquisition


ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_SCHEMA_VERSION = 1
ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_SCOPE = (
    "offline-exact-board-assembly-supplier-offer-evidence-v1"
)
ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BINDING_DOMAIN = (
    b"pcbex:offline-exact-board-assembly-supplier-offer-evidence-v1\0"
)

MAXIMUM_HANDOFF_BYTES = _assembly.MAXIMUM_HANDOFF_BYTES
MAXIMUM_BOARD_BYTES = _assembly.MAXIMUM_BOARD_BYTES
MAXIMUM_PACKAGE_BYTES = _assembly.MAXIMUM_PACKAGE_BYTES
MAXIMUM_BOARD_BINDING_REPORT_BYTES = (
    _assembly.MAXIMUM_BOARD_BINDING_REPORT_BYTES
)
MAXIMUM_PROCUREMENT_INTENT_BYTES = _assembly.MAXIMUM_PROCUREMENT_INTENT_BYTES
MAXIMUM_CATALOG_SNAPSHOT_BYTES = _procurement.MAX_CATALOG_RAW_BYTES
MAXIMUM_FINAL_CPL_REPORT_BYTES = _assembly.MAXIMUM_FINAL_CPL_REPORT_BYTES
MAXIMUM_ASSEMBLY_EVIDENCE_BYTES = _assembly.MAXIMUM_ASSEMBLY_EVIDENCE_BYTES
MAXIMUM_SUPPLIER_OFFER_BYTES = _offer.MAXIMUM_SUPPLIER_OFFER_BYTES
MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES = (
    _offer.MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES
)
MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES = (
    _acquisition.MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES
)
MAXIMUM_HANDOFF_GENERATION_BYTES = _handoff.MAX_GENERATION_BUNDLE_BYTES
MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES = 128 * 1024 * 1024
MAXIMUM_TOTAL_INPUT_BYTES = 789 * 1024 * 1024
MAXIMUM_VALIDATION_TOTAL_INPUT_BYTES = 917 * 1024 * 1024
MINIMUM_TIMEOUT_SECONDS = 1.0
MAXIMUM_TIMEOUT_SECONDS = 600.0
DEFAULT_TIMEOUT_SECONDS = 300.0

_FALSE_CLAIM_KEYS = (
    "adapter_network_performed",
    "current_availability_verified",
    "supplier_authenticity_verified",
    "offer_authenticity_verified",
    "price_authenticity_verified",
    "trusted_time_verified",
    "inventory_reserved",
    "assembly_ready",
    "assembly_authorized",
    "fabrication_authorized",
    "procurement_authorized",
    "order_ready",
    "order_placed",
    "payment_performed",
    "machine_operation_performed",
)
_SOURCE_KEYS = frozenset(
    {
        "assembly_evidence",
        "board",
        "board_binding_report",
        "catalog_snapshot",
        "circuit_handoff_bundle",
        "final_cpl_report",
        "handoff_generation_bundle",
        "manufacturing_package",
        "procurement_intent",
        "supplier_offer",
        "supplier_offer_coverage",
        "supplier_offer_fetch_receipt",
    }
)
_VALIDATION_KEYS = (
    "assembly_evidence_replayed",
    "supplier_offer_coverage_replayed",
    "supplier_offer_fetch_receipt_validated",
    "board_identity_cross_bound",
    "manufacturing_package_identity_cross_bound",
    "handoff_generation_identity_cross_bound",
    "catalog_snapshot_identity_cross_bound",
    "procurement_intent_identity_cross_bound",
    "procurement_projection_cross_bound",
    "supplier_offer_identity_cross_bound",
    "receipt_request_binding_validated",
    "evaluation_timestamp_cross_bound",
    "network_semantics_preserved",
    "caller_inputs_unchanged",
)
_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "scope",
        "status",
        "complete",
        *_FALSE_CLAIM_KEYS,
        "sources",
        "assembly_evidence",
        "supplier_offer_fetch_receipt",
        "supplier_offer_coverage",
        "findings",
        "validation",
        "binding_sha256",
    }
)
_FINDING_MESSAGES = {
    "assembly_evidence_incomplete": (
        "the freshly replayed assembly evidence is incomplete"
    ),
    "supplier_offer_not_covered": (
        "the freshly replayed supplier-offer coverage is not covered"
    ),
}
_NO_RETAINED_OUTER = object()


class AssemblySupplierOfferEvidenceError(ValueError):
    """Stable, path-free failure from exact offline evidence composition."""


@dataclass(frozen=True)
class _Captured:
    path: str | None
    label: str
    maximum: int
    raw: bytes

    @property
    def identity(self) -> dict[str, Any]:
        return _identity(self.raw)


@dataclass(frozen=True)
class _Inputs:
    assembly: Any
    assembly_report: _Captured
    supplier_offer: _Captured
    receipt: _Captured
    coverage: _Captured
    retained_outer: _Captured | None

    @property
    def caller_sources(self) -> tuple[Any, ...]:
        return (
            *self.assembly.sources,
            self.assembly_report,
            self.supplier_offer,
            self.receipt,
            self.coverage,
            *((self.retained_outer,) if self.retained_outer is not None else ()),
        )


def evaluate_assembly_supplier_offer_evidence(
    handoff_bundle,
    board,
    manufacturing_package,
    retained_board_binding_report,
    retained_procurement_intent,
    catalog_snapshot,
    retained_final_cpl,
    retained_assembly_evidence,
    supplier_offer,
    retained_supplier_offer_fetch_receipt,
    retained_supplier_offer_coverage,
    pcbex="pcbex",
    *,
    requested_boards: int,
    evaluated_at_unix: int,
    board_binding_policy=None,
    kicad_cli="kicad-cli",
    manufacturing_kicad_project=None,
    manufacturing_kicad_rules=None,
    manufacturing_fab=None,
    manufacturing_fab_profile=None,
    manufacturing_physical_profile=None,
    expected_archive_sha256=None,
    expected_bundle_sha256=None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Freshly replay and compose one exact offline evidence graph."""

    return _evaluate_or_validate(
        _NO_RETAINED_OUTER,
        handoff_bundle,
        board,
        manufacturing_package,
        retained_board_binding_report,
        retained_procurement_intent,
        catalog_snapshot,
        retained_final_cpl,
        retained_assembly_evidence,
        supplier_offer,
        retained_supplier_offer_fetch_receipt,
        retained_supplier_offer_coverage,
        pcbex,
        requested_boards=requested_boards,
        evaluated_at_unix=evaluated_at_unix,
        board_binding_policy=board_binding_policy,
        kicad_cli=kicad_cli,
        manufacturing_kicad_project=manufacturing_kicad_project,
        manufacturing_kicad_rules=manufacturing_kicad_rules,
        manufacturing_fab=manufacturing_fab,
        manufacturing_fab_profile=manufacturing_fab_profile,
        manufacturing_physical_profile=manufacturing_physical_profile,
        expected_archive_sha256=expected_archive_sha256,
        expected_bundle_sha256=expected_bundle_sha256,
        timeout_seconds=timeout_seconds,
        _clock=_clock,
    )


build_assembly_supplier_offer_evidence = (
    evaluate_assembly_supplier_offer_evidence
)


def validate_assembly_supplier_offer_evidence(
    evidence,
    handoff_bundle,
    board,
    manufacturing_package,
    retained_board_binding_report,
    retained_procurement_intent,
    catalog_snapshot,
    retained_final_cpl,
    retained_assembly_evidence,
    supplier_offer,
    retained_supplier_offer_fetch_receipt,
    retained_supplier_offer_coverage,
    pcbex="pcbex",
    *,
    requested_boards: int,
    evaluated_at_unix: int,
    board_binding_policy=None,
    kicad_cli="kicad-cli",
    manufacturing_kicad_project=None,
    manufacturing_kicad_rules=None,
    manufacturing_fab=None,
    manufacturing_fab_profile=None,
    manufacturing_physical_profile=None,
    expected_archive_sha256=None,
    expected_bundle_sha256=None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Freshly recompute and compare one retained canonical outer report."""

    return _evaluate_or_validate(
        evidence,
        handoff_bundle,
        board,
        manufacturing_package,
        retained_board_binding_report,
        retained_procurement_intent,
        catalog_snapshot,
        retained_final_cpl,
        retained_assembly_evidence,
        supplier_offer,
        retained_supplier_offer_fetch_receipt,
        retained_supplier_offer_coverage,
        pcbex,
        requested_boards=requested_boards,
        evaluated_at_unix=evaluated_at_unix,
        board_binding_policy=board_binding_policy,
        kicad_cli=kicad_cli,
        manufacturing_kicad_project=manufacturing_kicad_project,
        manufacturing_kicad_rules=manufacturing_kicad_rules,
        manufacturing_fab=manufacturing_fab,
        manufacturing_fab_profile=manufacturing_fab_profile,
        manufacturing_physical_profile=manufacturing_physical_profile,
        expected_archive_sha256=expected_archive_sha256,
        expected_bundle_sha256=expected_bundle_sha256,
        timeout_seconds=timeout_seconds,
        _clock=_clock,
    )


def render_assembly_supplier_offer_evidence(value: Mapping[str, Any]) -> bytes:
    """Render one bounded canonical report after self-contained validation."""

    return _render_impl(value)


def assembly_supplier_offer_evidence_json_schema() -> dict[str, Any]:
    """Return the closed Draft 2020-12 schema for the composed evidence."""

    return _schema_impl()


def _fail(message: str) -> AssemblySupplierOfferEvidenceError:
    return AssemblySupplierOfferEvidenceError(message)


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


class _DuplicateJSONKey(ValueError):
    pass


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
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        raise _fail("assembly supplier-offer evidence cannot be serialized") from None


def _pretty_json(value: Mapping[str, Any], *, maximum: int, label: str) -> bytes:
    try:
        encoder = json.JSONEncoder(
            ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True
        )
        output = bytearray()
        for chunk in encoder.iterencode(dict(value)):
            encoded = str.encode(chunk, "utf-8", "strict")
            if len(output) + len(encoded) + 1 > maximum:
                raise _fail(f"{label} exceeds its byte bound")
            output.extend(encoded)
        output.append(0x0A)
        return bytes(output)
    except AssemblySupplierOfferEvidenceError:
        raise
    except (
        TypeError,
        ValueError,
        OverflowError,
        UnicodeError,
        RuntimeError,
        RecursionError,
    ):
        raise _fail(f"{label} cannot be serialized") from None


def _snapshot_mapping(
    value: Mapping[str, Any], *, maximum: int, label: str
) -> dict[str, Any]:
    try:
        raw = _procurement._bounded_injected_json_bytes(
            value, maximum=maximum, label=label
        )
    except Exception:
        raise _fail(f"{label} is invalid") from None
    return _parse_json_object(raw, label)


def _bounded_bytes_like(value: Any, *, maximum: int, label: str) -> bytes:
    try:
        view = memoryview(value)
    except (TypeError, ValueError, BufferError):
        raise _fail(f"{label} is invalid") from None
    try:
        size = view.nbytes
        if not 1 <= size <= maximum:
            raise _fail(f"{label} exceeds its byte bound")
        raw = view.tobytes()
    except AssemblySupplierOfferEvidenceError:
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


def _timeout_deadline(
    timeout_seconds: float, clock: Callable[[], float]
) -> tuple[float, float]:
    if type(timeout_seconds) not in {int, float}:
        raise _fail("aggregate timeout is invalid")
    try:
        timeout = float(timeout_seconds)
        start = float(clock())
    except Exception:
        raise _fail("aggregate timeout is invalid") from None
    if (
        isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout)
        or not MINIMUM_TIMEOUT_SECONDS <= timeout <= MAXIMUM_TIMEOUT_SECONDS
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
    except Exception:
        raise _fail("aggregate deadline clock is invalid") from None
    if not math.isfinite(remaining) or remaining <= 0:
        raise _fail("assembly supplier-offer evidence exceeded its aggregate deadline")
    return min(remaining, MAXIMUM_TIMEOUT_SECONDS)


def _child_budget(value: float, label: str) -> float:
    if not math.isfinite(value) or value < MINIMUM_TIMEOUT_SECONDS:
        raise _fail(f"{label} has no execution budget before the aggregate deadline")
    return min(value, MAXIMUM_TIMEOUT_SECONDS)


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _fail(f"{label} is invalid")
    return value


def _expected_digest(value: Any, label: str) -> str | None:
    if value is None:
        return None
    try:
        return _assembly._expected_digest(value, label)
    except _assembly.AssemblyEvidenceError:
        raise _fail(f"{label} is invalid") from None


def _canonical_offer(raw: bytes) -> tuple[dict[str, Any], bytes]:
    try:
        parsed = _offer._parse_json_object(raw, "supplier-offer report")
        normalized = _offer._normalize_offer(parsed)
    except _offer.SupplierOfferError:
        raise _fail("supplier-offer report is invalid") from None
    rendered = _pretty_json(
        normalized,
        maximum=MAXIMUM_SUPPLIER_OFFER_BYTES,
        label="supplier-offer report",
    )
    return normalized, rendered


def _canonical_representation(
    raw: bytes, *, kind: str, label: str
) -> tuple[dict[str, Any], bytes]:
    parsed = _parse_json_object(raw, label)
    try:
        if kind == "assembly":
            rendered = _assembly.render_assembly_evidence(parsed)
        elif kind == "coverage":
            rendered = _offer.render_supplier_offer_coverage(parsed)
        elif kind == "receipt":
            rendered = _pretty_json(
                parsed,
                maximum=MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
                label=label,
            )
        elif kind == "outer":
            rendered = _render_impl(parsed)
        else:
            raise AssertionError("unknown retained representation")
    except (
        _assembly.AssemblyEvidenceError,
        _offer.SupplierOfferError,
        _acquisition.SupplierOfferAcquisitionError,
    ):
        raise _fail(f"{label} is invalid") from None
    except Exception:
        raise _fail(f"{label} is invalid") from None
    return parsed, rendered


def _capture_representation(
    value: Any, *, kind: str, label: str, maximum: int
) -> _Captured:
    path: str | None = None
    if isinstance(value, Mapping):
        if kind == "assembly":
            try:
                raw = _assembly.render_assembly_evidence(value)
            except Exception:
                raise _fail(f"{label} is invalid") from None
        elif kind == "coverage":
            try:
                raw = _offer.render_supplier_offer_coverage(value)
            except Exception:
                raise _fail(f"{label} is invalid") from None
        elif kind == "receipt":
            snapshot = _snapshot_mapping(value, maximum=maximum, label=label)
            raw = _pretty_json(snapshot, maximum=maximum, label=label)
        elif kind == "outer":
            raw = _render_impl(value)
        else:
            raise AssertionError("unknown retained representation")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = _bounded_bytes_like(value, maximum=maximum, label=label)
    elif isinstance(value, (str, os.PathLike)):
        try:
            path = _assembly._freeze_path(value, f"{label} source")
            raw = _assembly._read_source(path, maximum, label)
        except Exception:
            raise _fail(f"{label} source is invalid") from None
    else:
        raise _fail(f"{label} is invalid")
    _parsed, canonical = _canonical_representation(raw, kind=kind, label=label)
    if raw != canonical:
        raise _fail(f"{label} is not canonical pretty JSON")
    return _Captured(path, label, maximum, raw)


def _capture_path_source(value: Any, *, label: str, maximum: int) -> _Captured:
    try:
        path = _assembly._freeze_path(value, f"{label} source")
        raw = _assembly._read_source(path, maximum, label)
    except Exception:
        raise _fail(f"{label} source is invalid") from None
    return _Captured(path, label, maximum, raw)


def _guard_cwd(root: str, operation: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    try:
        result = operation(*args, **kwargs)
    finally:
        try:
            observed = os.getcwd()
        except Exception:
            raise _fail("caller working directory became invalid") from None
        if observed != root:
            try:
                os.chdir(root)
            except Exception:
                raise _fail("caller working directory changed and could not be restored") from None
            raise _fail("caller-controlled hook changed the working directory")
    return result


def _freeze_against_root(value: Any, label: str, root: str) -> str:
    try:
        rendered = _guard_cwd(root, _assembly._freeze_path, value, label)
        drive, _tail = os.path.splitdrive(rendered)
        if drive and not os.path.isabs(rendered):
            raise _fail(f"{label} is invalid")
        # join preserves full POSIX/DOS/UNC/verbatim absolutes, resolves plain
        # relatives, and gives Windows root-relative ``\foo`` the caller
        # root's drive instead of a later process-current drive.
        absolute = os.path.join(root, rendered)
        return _assembly._freeze_path(absolute, label)
    except AssemblySupplierOfferEvidenceError:
        raise
    except Exception:
        raise _fail(f"{label} is invalid") from None


def _classify_retained(
    value: Any, label: str, caller_root: str
) -> tuple[str, Any]:
    mode = _retained_mode(value, label)
    if mode == "path":
        return "path", _freeze_against_root(
            value, f"{label} source", caller_root
        )
    return mode, value


def _retained_mode(value: Any, label: str) -> str:
    if isinstance(value, Mapping):
        return "mapping"
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "bytes"
    if isinstance(value, (str, os.PathLike)):
        return "path"
    raise _fail(f"{label} is invalid")


def _capture_inputs(
    retained_outer: Any | None,
    handoff_bundle: Any,
    board: Any,
    manufacturing_package: Any,
    retained_board_binding_report: Any,
    retained_procurement_intent: Any,
    catalog_snapshot: Any,
    retained_final_cpl: Any,
    retained_assembly_evidence: Any,
    supplier_offer: Any,
    retained_supplier_offer_fetch_receipt: Any,
    retained_supplier_offer_coverage: Any,
    pcbex: Any,
    *,
    board_binding_policy: Any,
    kicad_cli: Any,
    manufacturing_kicad_project: Any,
    manufacturing_kicad_rules: Any,
    manufacturing_fab: Any,
    manufacturing_fab_profile: Any,
    manufacturing_physical_profile: Any,
    deadline: float,
    clock: Callable[[], float],
    caller_root: str,
) -> _Inputs:
    # Freeze only the inherited v1.467 path union first.  Passing built-in
    # strings into its capture preserves its existing freeze-all/read-all
    # boundary while consuming each original PathLike exactly once.
    try:
        frozen_handoff = _freeze_against_root(
            handoff_bundle, "circuit handoff bundle source", caller_root
        )
        frozen_board = _freeze_against_root(
            board, "board source", caller_root
        )
        frozen_package = _freeze_against_root(
            manufacturing_package, "manufacturing package source", caller_root
        )
        frozen_board_report = _freeze_against_root(
            retained_board_binding_report,
            "board-binding report source",
            caller_root,
        )
        frozen_intent = _freeze_against_root(
            retained_procurement_intent,
            "procurement-intent source",
            caller_root,
        )
        frozen_catalog = _freeze_against_root(
            catalog_snapshot, "catalog snapshot source", caller_root
        )
        frozen_final_cpl = _freeze_against_root(
            retained_final_cpl, "final-CPL report source", caller_root
        )

        def optional_path(value: Any, label: str) -> str | None:
            return (
                None
                if value is None
                else _freeze_against_root(value, label, caller_root)
            )

        frozen_policy = optional_path(
            board_binding_policy, "board-binding policy source"
        )
        frozen_project = optional_path(
            manufacturing_kicad_project,
            "manufacturing KiCad project source",
        )
        frozen_rules = optional_path(
            manufacturing_kicad_rules, "manufacturing KiCad rules source"
        )
        frozen_fab_profile = optional_path(
            manufacturing_fab_profile, "manufacturing DFM profile source"
        )
        frozen_physical_profile = optional_path(
            manufacturing_physical_profile,
            "manufacturing physical profile source",
        )
    except Exception:
        raise _fail("direct composition source path is invalid") from None

    try:
        assembly_capture, _unused = _assembly._capture_inputs(
            frozen_handoff,
            frozen_board,
            frozen_package,
            frozen_board_report,
            frozen_intent,
            frozen_catalog,
            frozen_final_cpl,
            pcbex,
            board_binding_policy=frozen_policy,
            kicad_cli=kicad_cli,
            manufacturing_kicad_project=frozen_project,
            manufacturing_kicad_rules=frozen_rules,
            manufacturing_fab=manufacturing_fab,
            manufacturing_fab_profile=frozen_fab_profile,
            manufacturing_physical_profile=frozen_physical_profile,
            deadline=deadline,
            clock=clock,
            defer_commands=True,
        )
    except Exception:
        raise _fail("assembly source capture failed") from None
    _remaining(deadline, clock)

    # The raw offer is the next trust layer.  Its PathLike hook runs only after
    # the inherited assembly-side union is captured, so it cannot silently
    # choose the bytes of an original board/package/intent source.
    try:
        frozen_offer = _freeze_against_root(
            supplier_offer, "supplier-offer report source", caller_root
        )
    except Exception:
        raise _fail("supplier-offer source path is invalid") from None
    offer_source = _capture_path_source(
        frozen_offer,
        label="supplier-offer report",
        maximum=MAXIMUM_SUPPLIER_OFFER_BYTES,
    )

    # Retained child representations are classified only after all original
    # replay sources and the raw offer have been captured.  PathLike hooks can
    # therefore cause only a detectable post-capture mutation.
    raw_retained_specs = (
        (
            "assembly",
            "assembly-evidence report",
            MAXIMUM_ASSEMBLY_EVIDENCE_BYTES,
            retained_assembly_evidence,
        ),
        (
            "receipt",
            "supplier-offer fetch receipt",
            MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
            retained_supplier_offer_fetch_receipt,
        ),
        (
            "coverage",
            "supplier-offer coverage report",
            MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES,
            retained_supplier_offer_coverage,
        ),
    )
    retained: dict[str, _Captured] = {}
    retained_specs: list[tuple[str, str, int, str, Any]] = []
    # Freeze and capture each path-backed child immediately, in positional
    # order.  A later child PathLike hook can therefore cause only a detectable
    # mutation of an already authenticated earlier child.
    try:
        for kind, label, maximum, value in raw_retained_specs:
            mode = _retained_mode(value, label)
            frozen = value
            if mode == "path":
                _mode, frozen = _classify_retained(value, label, caller_root)
                retained[kind] = _capture_path_source(
                    frozen, label=label, maximum=maximum
                )
            retained_specs.append((kind, label, maximum, mode, frozen))
    except Exception:
        raise _fail("retained child representation is invalid") from None

    direct_path_sources = [*assembly_capture.sources, offer_source]
    direct_path_sources.extend(retained.values())
    try:
        _assembly._ensure_distinct_sources(
            [source.path for source in direct_path_sources]
        )
    except Exception:
        raise _fail(
            "assembly supplier-offer direct path sources must be distinct"
        ) from None

    # Copy every injected bytes-like child before any later outer hook can
    # mutate a mutable bytearray/memoryview that has no reread boundary.
    for kind, label, maximum, mode, frozen in retained_specs:
        if mode == "bytes":
            retained[kind] = _guard_cwd(
                caller_root,
                _capture_representation,
                frozen, kind=kind, label=label, maximum=maximum
            )
    for kind, label, maximum, mode, frozen in retained_specs:
        if mode == "mapping":
            retained[kind] = _guard_cwd(
                caller_root,
                _capture_representation,
                frozen, kind=kind, label=label, maximum=maximum
            )
    assembly_report = retained["assembly"]
    receipt = retained["receipt"]
    coverage = retained["coverage"]

    for source, kind in (
        (assembly_report, "assembly"),
        (receipt, "receipt"),
        (coverage, "coverage"),
    ):
        _parsed, canonical = _canonical_representation(
            source.raw, kind=kind, label=source.label
        )
        if source.raw != canonical:
            raise _fail(f"{source.label} is not canonical pretty JSON")

    # The retained outer representation is wholly last.  A PathLike hook runs
    # only after every direct path, bytes-like value, and Mapping snapshot has
    # been captured; any cwd change is restored and rejected before commands.
    if retained_outer is _NO_RETAINED_OUTER:
        outer_mode, frozen_outer = "absent", None
    else:
        outer_mode, frozen_outer = _classify_retained(
            retained_outer,
            "assembly supplier-offer evidence report",
            caller_root,
        )
    outer_source: _Captured | None = None
    if outer_mode == "path":
        outer_source = _capture_path_source(
            frozen_outer,
            label="assembly supplier-offer evidence report",
            maximum=MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES,
        )
        try:
            _assembly._ensure_distinct_sources(
                [
                    *(source.path for source in direct_path_sources),
                    outer_source.path,
                ]
            )
        except Exception:
            raise _fail(
                "retained outer report must not alias a direct source"
            ) from None
    if outer_mode not in {"absent", "path"}:
        outer_source = _guard_cwd(
            caller_root,
            _capture_representation,
            frozen_outer,
            kind="outer",
            label="assembly supplier-offer evidence report",
            maximum=MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES,
        )
    elif outer_source is not None:
        _parsed, canonical_outer = _canonical_representation(
            outer_source.raw,
            kind="outer",
            label=outer_source.label,
        )
        if outer_source.raw != canonical_outer:
            raise _fail(
                "assembly supplier-offer evidence report is not canonical pretty JSON"
            )
    _remaining(deadline, clock)

    inputs = _Inputs(
        assembly_capture,
        assembly_report,
        offer_source,
        receipt,
        coverage,
        outer_source,
    )
    paths = [
        source.path
        for source in inputs.caller_sources
        if source.path is not None
    ]
    try:
        _assembly._ensure_distinct_sources(paths)
    except Exception:
        raise _fail("assembly supplier-offer input sources must be distinct") from None

    assembly_union = sum(len(source.raw) for source in assembly_capture.sources)
    assembly_union += len(assembly_report.raw)
    if assembly_union > _assembly.MAXIMUM_TOTAL_INPUT_BYTES:
        raise _fail("assembly evidence inputs exceed their aggregate bound")
    additional = len(offer_source.raw) + len(receipt.raw) + len(coverage.raw)
    if additional > 21 * 1024 * 1024:
        raise _fail("supplier-offer evidence inputs exceed their aggregate bound")
    direct_total = assembly_union + additional
    if direct_total > MAXIMUM_TOTAL_INPUT_BYTES:
        raise _fail("assembly supplier-offer inputs exceed their aggregate bound")
    if (
        outer_source is not None
        and direct_total + len(outer_source.raw)
        > MAXIMUM_VALIDATION_TOTAL_INPUT_BYTES
    ):
        raise _fail("assembly supplier-offer validation inputs exceed their aggregate bound")

    # Source capture precedes consumption of caller-controlled command hooks.
    try:
        frozen_kicad = _guard_cwd(
            caller_root,
            _assembly._freeze_path,
            kicad_cli,
            "manufacturing kicad-cli argument",
        )
        normalized_pcbex = _guard_cwd(
            caller_root, _assembly._normalize_command, pcbex
        )
        finalized = _guard_cwd(
            caller_root,
            _assembly._finalize_capture_commands,
            assembly_capture,
            normalized_pcbex,
            frozen_kicad,
        )
    except Exception:
        raise _fail("child command is invalid") from None
    _remaining(deadline, clock)
    return _Inputs(
        finalized,
        assembly_report,
        offer_source,
        receipt,
        coverage,
        outer_source,
    )


def _preparse_and_extract(
    inputs: _Inputs,
    *,
    expected_archive_sha256: str | None,
    expected_bundle_sha256: str | None,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[bytes, dict[str, Any]]:
    capture = inputs.assembly
    try:
        _verification, entries = _handoff.validate_circuit_handoff_archive(
            capture.handoff.raw,
            expected_archive_sha256=expected_archive_sha256,
            expected_bundle_sha256=expected_bundle_sha256,
        )
    except Exception:
        raise _fail("circuit handoff bundle is invalid") from None
    try:
        generation_raw = entries[_handoff.GENERATION_BUNDLE_NAME]
    except (KeyError, TypeError):
        raise _fail("circuit handoff generation entry is missing") from None
    if not 1 <= len(generation_raw) <= MAXIMUM_HANDOFF_GENERATION_BYTES:
        raise _fail("handoff generation bundle exceeds its byte bound")

    # Strict-preparse the entire direct JSON union before any public child
    # validator can reach a caller-selected process.
    for raw, label in (
        (capture.board_binding_report.raw, "board-binding report"),
        (capture.procurement_intent.raw, "procurement-intent report"),
        (capture.catalog_snapshot.raw, "catalog snapshot"),
        (capture.final_cpl_report.raw, "final-CPL report"),
        (generation_raw, "handoff generation bundle"),
        (inputs.assembly_report.raw, "assembly-evidence report"),
        (inputs.receipt.raw, "supplier-offer fetch receipt"),
        (inputs.coverage.raw, "supplier-offer coverage report"),
    ):
        _parse_json_object(raw, label)
    offer, canonical_offer = _canonical_offer(inputs.supplier_offer.raw)
    if inputs.supplier_offer.raw != canonical_offer:
        raise _fail("supplier-offer report is not canonical pretty JSON")
    if (
        offer["procurement_intent_sha256"]
        != _sha256(capture.procurement_intent.raw)
    ):
        raise _fail("supplier offer is not bound to the procurement intent")
    _remaining(deadline, clock)
    return generation_raw, offer


def _stage_bytes(
    root: Path,
    directory: str,
    filename: str,
    raw: bytes,
    maximum: int,
    label: str,
) -> Path:
    destination_root = root / directory
    try:
        destination_root.mkdir(mode=0o700)
        destination = destination_root / filename
        atomic_write_no_clobber(destination, raw, max_bytes=maximum)
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail(f"could not stage {label}") from None
    return destination


def _stage_inputs(
    root: Path, inputs: _Inputs, generation_raw: bytes
) -> tuple[dict[str, Path | None], list[tuple[Path, bytes, int, str]]]:
    capture = inputs.assembly
    paths: dict[str, Path | None] = {
        "handoff": _stage_bytes(
            root,
            "handoff",
            "circuit-handoff.zip",
            capture.handoff.raw,
            capture.handoff.maximum,
            capture.handoff.label,
        ),
        "board": _stage_bytes(
            root,
            "board",
            capture.board_name,
            capture.board.raw,
            capture.board.maximum,
            capture.board.label,
        ),
        "package": _stage_bytes(
            root,
            "package",
            "manufacturing.zip",
            capture.package.raw,
            capture.package.maximum,
            capture.package.label,
        ),
        "board_report": _stage_bytes(
            root,
            "board-report",
            "board-binding.json",
            capture.board_binding_report.raw,
            capture.board_binding_report.maximum,
            capture.board_binding_report.label,
        ),
        "intent": _stage_bytes(
            root,
            "intent",
            "procurement-intent.json",
            capture.procurement_intent.raw,
            capture.procurement_intent.maximum,
            capture.procurement_intent.label,
        ),
        "catalog": _stage_bytes(
            root,
            "catalog",
            capture.catalog_name,
            capture.catalog_snapshot.raw,
            capture.catalog_snapshot.maximum,
            capture.catalog_snapshot.label,
        ),
        "final_cpl": _stage_bytes(
            root,
            "final-cpl",
            "final-cpl.json",
            capture.final_cpl_report.raw,
            capture.final_cpl_report.maximum,
            capture.final_cpl_report.label,
        ),
        "assembly_report": _stage_bytes(
            root,
            "assembly-report",
            "assembly-evidence.json",
            inputs.assembly_report.raw,
            inputs.assembly_report.maximum,
            inputs.assembly_report.label,
        ),
        "offer": _stage_bytes(
            root,
            "offer",
            "supplier-offer.json",
            inputs.supplier_offer.raw,
            inputs.supplier_offer.maximum,
            inputs.supplier_offer.label,
        ),
        "receipt": _stage_bytes(
            root,
            "receipt",
            "supplier-offer-fetch-receipt.json",
            inputs.receipt.raw,
            inputs.receipt.maximum,
            inputs.receipt.label,
        ),
        "coverage": _stage_bytes(
            root,
            "coverage",
            "supplier-offer-coverage.json",
            inputs.coverage.raw,
            inputs.coverage.maximum,
            inputs.coverage.label,
        ),
        "generation": _stage_bytes(
            root,
            "generation",
            _handoff.GENERATION_BUNDLE_NAME,
            generation_raw,
            MAXIMUM_HANDOFF_GENERATION_BYTES,
            "handoff generation bundle",
        ),
    }
    optionals = {
        "policy": capture.board_binding_policy,
        "project": capture.manufacturing_project,
        "rules": capture.manufacturing_rules,
        "fab_profile": capture.manufacturing_fab_profile,
        "physical_profile": capture.manufacturing_physical_profile,
    }
    for key, source in optionals.items():
        if source is None:
            paths[key] = None
        else:
            paths[key] = _stage_bytes(
                root,
                key,
                Path(source.path).name,
                source.raw,
                source.maximum,
                source.label,
            )
    if inputs.retained_outer is not None:
        paths["outer"] = _stage_bytes(
            root,
            "outer",
            "assembly-supplier-offer-evidence.json",
            inputs.retained_outer.raw,
            inputs.retained_outer.maximum,
            inputs.retained_outer.label,
        )
    else:
        paths["outer"] = None

    pairs: list[tuple[Path, bytes, int, str]] = []
    direct_by_key: dict[str, Any] = {
        "handoff": capture.handoff,
        "board": capture.board,
        "package": capture.package,
        "board_report": capture.board_binding_report,
        "intent": capture.procurement_intent,
        "catalog": capture.catalog_snapshot,
        "final_cpl": capture.final_cpl_report,
        "assembly_report": inputs.assembly_report,
        "offer": inputs.supplier_offer,
        "receipt": inputs.receipt,
        "coverage": inputs.coverage,
        **optionals,
        "outer": inputs.retained_outer,
    }
    for key, source in direct_by_key.items():
        path = paths[key]
        if source is not None and path is not None:
            pairs.append((path, source.raw, source.maximum, source.label))
    generation_path = paths["generation"]
    assert generation_path is not None
    pairs.append(
        (
            generation_path,
            generation_raw,
            MAXIMUM_HANDOFF_GENERATION_BYTES,
            "handoff generation bundle",
        )
    )
    return paths, pairs


def _reread_staged(
    pairs: Sequence[tuple[Path, bytes, int, str]],
    deadline: float,
    clock: Callable[[], float],
) -> None:
    for path, expected, maximum, label in pairs:
        try:
            observed = _assembly._read_source(str(path), maximum, label)
        except Exception:
            raise _fail("private staged source is invalid") from None
        if observed != expected:
            raise _fail(f"{label} changed in the private workspace")
        _remaining(deadline, clock)


def _reread_callers(
    inputs: _Inputs, deadline: float, clock: Callable[[], float]
) -> None:
    for source in inputs.caller_sources:
        if source.path is None:
            continue
        try:
            observed = _assembly._read_source(
                source.path, source.maximum, source.label
            )
        except Exception:
            raise _fail("caller source is invalid during final reread") from None
        if observed != source.raw:
            raise _fail(f"{source.label} changed during composition")
        _remaining(deadline, clock)


def _fresh_sources(
    inputs: _Inputs,
    generation_raw: bytes,
    assembly_raw: bytes,
    receipt_raw: bytes,
    coverage_raw: bytes,
) -> dict[str, Any]:
    capture = inputs.assembly
    return {
        "assembly_evidence": _identity(assembly_raw),
        "board": {"name": capture.board_name, **_identity(capture.board.raw)},
        "board_binding_report": _identity(capture.board_binding_report.raw),
        "catalog_snapshot": _identity(capture.catalog_snapshot.raw),
        "circuit_handoff_bundle": _identity(capture.handoff.raw),
        "final_cpl_report": _identity(capture.final_cpl_report.raw),
        "handoff_generation_bundle": _identity(generation_raw),
        "manufacturing_package": _identity(capture.package.raw),
        "procurement_intent": _identity(capture.procurement_intent.raw),
        "supplier_offer": _identity(inputs.supplier_offer.raw),
        "supplier_offer_coverage": _identity(coverage_raw),
        "supplier_offer_fetch_receipt": _identity(receipt_raw),
    }


def _evaluate_staged(
    inputs: _Inputs,
    generation_raw: bytes,
    paths: Mapping[str, Path | None],
    pairs: Sequence[tuple[Path, bytes, int, str]],
    *,
    requested_boards: int,
    evaluated_at_unix: int,
    expected_archive_sha256: str | None,
    expected_bundle_sha256: str | None,
    deadline: float,
    clock: Callable[[], float],
) -> dict[str, Any]:
    capture = inputs.assembly
    required_names = (
        "handoff",
        "board",
        "package",
        "board_report",
        "intent",
        "catalog",
        "final_cpl",
        "assembly_report",
        "offer",
        "receipt",
        "coverage",
        "generation",
    )
    if any(paths[name] is None for name in required_names):
        raise _fail("private staged source is missing")

    _remaining(deadline, clock)
    try:
        receipt_result = _acquisition.validate_supplier_offer_fetch_receipt(
            paths["receipt"], paths["offer"]
        )
    except Exception:
        raise _fail("supplier-offer fetch receipt validation failed") from None
    receipt_snapshot = _snapshot_mapping(
        receipt_result,
        maximum=MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
        label="validated supplier-offer fetch receipt",
    )
    try:
        receipt = _acquisition._validate_receipt_shape(
            receipt_snapshot, allow_insecure_loopback=False
        )
    except Exception:
        raise _fail("validated supplier-offer fetch receipt is invalid") from None
    if not _strict_json_equal(receipt_snapshot, receipt):
        raise _fail("validated supplier-offer fetch receipt is inconsistent")
    receipt_raw = _pretty_json(
        receipt,
        maximum=MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
        label="validated supplier-offer fetch receipt",
    )
    if receipt_raw != inputs.receipt.raw:
        raise _fail("validated receipt did not preserve the retained bytes")
    _remaining(deadline, clock)
    _reread_staged(pairs, deadline, clock)

    # Selector/timestamp mismatch is a receipt/retained-evidence hard failure;
    # reject it before the first caller-selected assembly child can execute.
    retained_coverage = _parse_json_object(
        inputs.coverage.raw, "supplier-offer coverage report"
    )
    if (
        retained_coverage.get("requested_boards") != requested_boards
        or retained_coverage.get("evaluated_at_unix") != evaluated_at_unix
        or receipt["fetched_at_unix"] != evaluated_at_unix
    ):
        raise _fail("retained evaluation selectors are not cross-bound")

    assembly_remaining = _remaining(deadline, clock)
    assembly_budget = _child_budget(
        assembly_remaining / 2.0, "assembly-evidence replay"
    )
    try:
        assembly_result = _assembly.validate_assembly_evidence(
            paths["assembly_report"],
            paths["handoff"],
            paths["board"],
            paths["package"],
            paths["board_report"],
            paths["intent"],
            paths["catalog"],
            paths["final_cpl"],
            list(capture.pcbex),
            board_binding_policy=paths["policy"],
            kicad_cli=capture.kicad_cli,
            manufacturing_kicad_project=paths["project"],
            manufacturing_kicad_rules=paths["rules"],
            manufacturing_fab=capture.manufacturing_fab,
            manufacturing_fab_profile=paths["fab_profile"],
            manufacturing_physical_profile=paths["physical_profile"],
            expected_archive_sha256=expected_archive_sha256,
            expected_bundle_sha256=expected_bundle_sha256,
            timeout_seconds=assembly_budget,
            _clock=clock,
        )
    except Exception:
        raise _fail("assembly-evidence replay failed") from None
    _remaining(deadline, clock)
    _reread_staged(pairs, deadline, clock)
    assembly_snapshot = _snapshot_mapping(
        assembly_result,
        maximum=MAXIMUM_ASSEMBLY_EVIDENCE_BYTES,
        label="fresh assembly-evidence result",
    )
    try:
        assembly_raw = _assembly.render_assembly_evidence(assembly_snapshot)
    except Exception:
        raise _fail("fresh assembly-evidence result is invalid") from None
    if assembly_raw != inputs.assembly_report.raw:
        raise _fail("fresh assembly replay did not preserve the retained report")
    assembly = _parse_json_object(assembly_raw, "fresh assembly-evidence result")

    coverage_remaining = _remaining(deadline, clock)
    final_reserve = min(15.0, coverage_remaining / 2.0)
    coverage_budget = _child_budget(
        coverage_remaining - final_reserve, "supplier-offer coverage replay"
    )
    try:
        coverage_result = _offer.validate_supplier_offer_coverage(
            paths["coverage"],
            paths["board"],
            paths["package"],
            paths["generation"],
            paths["catalog"],
            paths["intent"],
            paths["offer"],
            list(capture.pcbex),
            requested_boards=requested_boards,
            evaluated_at_unix=evaluated_at_unix,
            timeout_seconds=coverage_budget,
            _clock=clock,
        )
    except Exception:
        raise _fail("supplier-offer coverage replay failed") from None
    _remaining(deadline, clock)
    _reread_staged(pairs, deadline, clock)
    coverage_snapshot = _snapshot_mapping(
        coverage_result,
        maximum=MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES,
        label="fresh supplier-offer coverage result",
    )
    try:
        coverage_raw = _offer.render_supplier_offer_coverage(coverage_snapshot)
    except Exception:
        raise _fail("fresh supplier-offer coverage result is invalid") from None
    if coverage_raw != inputs.coverage.raw:
        raise _fail("fresh coverage replay did not preserve the retained report")
    coverage = _parse_json_object(
        coverage_raw, "fresh supplier-offer coverage result"
    )

    sources = _fresh_sources(
        inputs, generation_raw, assembly_raw, receipt_raw, coverage_raw
    )
    _cross_bind(
        assembly,
        receipt,
        coverage,
        sources,
        assembly_raw=assembly_raw,
        receipt_raw=receipt_raw,
        coverage_raw=coverage_raw,
        offer_raw=inputs.supplier_offer.raw,
        requested_boards=requested_boards,
        evaluated_at_unix=evaluated_at_unix,
    )
    result = _compose_result(assembly, receipt, coverage, sources)
    validated_result = _validate_outer_result(
        result, validated_receipt=receipt
    )
    rendered = _pretty_json(
        validated_result,
        maximum=MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES,
        label="assembly supplier-offer evidence report",
    )
    if len(rendered) > MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES:
        raise _fail("assembly supplier-offer evidence exceeds its byte bound")
    _remaining(deadline, clock)
    _reread_staged(pairs, deadline, clock)

    if inputs.retained_outer is not None:
        if inputs.retained_outer.raw != rendered:
            raise _fail(
                "retained outer report does not match exact replayed evidence"
            )
        retained_value = _parse_json_object(
            inputs.retained_outer.raw,
            "retained assembly supplier-offer evidence report",
        )
        if not _strict_json_equal(retained_value, result):
            raise _fail(
                "retained outer report does not match exact replayed evidence"
            )
    return result


def _evaluate_or_validate(
    retained_outer: Any,
    handoff_bundle: Any,
    board: Any,
    manufacturing_package: Any,
    retained_board_binding_report: Any,
    retained_procurement_intent: Any,
    catalog_snapshot: Any,
    retained_final_cpl: Any,
    retained_assembly_evidence: Any,
    supplier_offer: Any,
    retained_supplier_offer_fetch_receipt: Any,
    retained_supplier_offer_coverage: Any,
    pcbex: Any,
    *,
    requested_boards: Any,
    evaluated_at_unix: Any,
    board_binding_policy: Any,
    kicad_cli: Any,
    manufacturing_kicad_project: Any,
    manufacturing_kicad_rules: Any,
    manufacturing_fab: Any,
    manufacturing_fab_profile: Any,
    manufacturing_physical_profile: Any,
    expected_archive_sha256: Any,
    expected_bundle_sha256: Any,
    timeout_seconds: Any,
    _clock: Callable[[], float],
) -> dict[str, Any]:
    try:
        caller_root = os.getcwd()
    except Exception:
        raise _fail("caller working directory is invalid") from None
    if not isinstance(caller_root, str) or not os.path.isabs(caller_root):
        raise _fail("caller working directory is invalid")

    def guarded_clock() -> float:
        return _guard_cwd(caller_root, _clock)

    _timeout, deadline = _timeout_deadline(timeout_seconds, guarded_clock)
    inputs = _capture_inputs(
        retained_outer,
        handoff_bundle,
        board,
        manufacturing_package,
        retained_board_binding_report,
        retained_procurement_intent,
        catalog_snapshot,
        retained_final_cpl,
        retained_assembly_evidence,
        supplier_offer,
        retained_supplier_offer_fetch_receipt,
        retained_supplier_offer_coverage,
        pcbex,
        board_binding_policy=board_binding_policy,
        kicad_cli=kicad_cli,
        manufacturing_kicad_project=manufacturing_kicad_project,
        manufacturing_kicad_rules=manufacturing_kicad_rules,
        manufacturing_fab=manufacturing_fab,
        manufacturing_fab_profile=manufacturing_fab_profile,
        manufacturing_physical_profile=manufacturing_physical_profile,
        deadline=deadline,
        clock=guarded_clock,
        caller_root=caller_root,
    )
    requested = _integer(
        requested_boards,
        "requested board quantity",
        minimum=1,
        maximum=_offer.MAXIMUM_REQUESTED_BOARDS,
    )
    evaluated = _integer(
        evaluated_at_unix,
        "evaluation timestamp",
        minimum=0,
        maximum=_offer.MAXIMUM_TIMESTAMP,
    )
    expected_archive = _expected_digest(
        expected_archive_sha256, "expected handoff archive digest"
    )
    expected_bundle = _expected_digest(
        expected_bundle_sha256, "expected handoff bundle digest"
    )
    generation_raw, _normalized_offer = _preparse_and_extract(
        inputs,
        expected_archive_sha256=expected_archive,
        expected_bundle_sha256=expected_bundle,
        deadline=deadline,
        clock=guarded_clock,
    )

    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-assembly-supplier-offer-",
            dir=_assembly._trusted_temporary_root(),
        ) as directory:
            root = Path(directory)
            paths, pairs = _stage_inputs(root, inputs, generation_raw)
            _remaining(deadline, guarded_clock)
            result = _evaluate_staged(
                inputs,
                generation_raw,
                paths,
                pairs,
                requested_boards=requested,
                evaluated_at_unix=evaluated,
                expected_archive_sha256=expected_archive,
                expected_bundle_sha256=expected_bundle,
                deadline=deadline,
                clock=guarded_clock,
            )
    except AssemblySupplierOfferEvidenceError:
        raise
    except Exception:
        raise _fail("assembly supplier-offer private workspace failed") from None
    _remaining(deadline, guarded_clock)
    _reread_callers(inputs, deadline, guarded_clock)
    _remaining(deadline, guarded_clock)
    return result


__all__ = [
    "AssemblySupplierOfferEvidenceError",
    "MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES",
    "assembly_supplier_offer_evidence_json_schema",
    "build_assembly_supplier_offer_evidence",
    "evaluate_assembly_supplier_offer_evidence",
    "render_assembly_supplier_offer_evidence",
    "validate_assembly_supplier_offer_evidence",
]


def _embedded_schema(value: Mapping[str, Any]) -> dict[str, Any]:
    schema = copy.deepcopy(dict(value))
    for key in ("$schema", "$id", "title", "$comment"):
        schema.pop(key, None)
    return schema


def _schema_impl() -> dict[str, Any]:
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
            "maxLength": 255,
            "pattern": '^[^\\u0000-\\u001f<>:"/\\\\|?*]+\\.kicad_pcb$',
        },
        **board_identity["properties"],
    }
    required = [
        "schema_version",
        "scope",
        "status",
        "complete",
        *_FALSE_CLAIM_KEYS,
        "sources",
        "assembly_evidence",
        "supplier_offer_fetch_receipt",
        "supplier_offer_coverage",
        "findings",
        "validation",
        "binding_sha256",
    ]
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
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/schemas/"
            "offline-exact-board-assembly-supplier-offer-evidence-v1.json"
        ),
        "title": "pcbex exact offline assembly and supplier-offer evidence",
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": {
            "schema_version": {
                "const": ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_SCHEMA_VERSION
            },
            "scope": {"const": ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_SCOPE},
            "status": {"enum": ["complete", "incomplete"]},
            "complete": {"type": "boolean"},
            **{key: {"const": False} for key in _FALSE_CLAIM_KEYS},
            "sources": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(_SOURCE_KEYS),
                "properties": {
                    "assembly_evidence": identity(
                        MAXIMUM_ASSEMBLY_EVIDENCE_BYTES
                    ),
                    "board": board_identity,
                    "board_binding_report": identity(
                        MAXIMUM_BOARD_BINDING_REPORT_BYTES
                    ),
                    "catalog_snapshot": identity(
                        MAXIMUM_CATALOG_SNAPSHOT_BYTES
                    ),
                    "circuit_handoff_bundle": identity(MAXIMUM_HANDOFF_BYTES),
                    "final_cpl_report": identity(MAXIMUM_FINAL_CPL_REPORT_BYTES),
                    "handoff_generation_bundle": identity(
                        MAXIMUM_HANDOFF_GENERATION_BYTES
                    ),
                    "manufacturing_package": identity(MAXIMUM_PACKAGE_BYTES),
                    "procurement_intent": identity(
                        MAXIMUM_PROCUREMENT_INTENT_BYTES
                    ),
                    "supplier_offer": identity(MAXIMUM_SUPPLIER_OFFER_BYTES),
                    "supplier_offer_coverage": identity(
                        MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES
                    ),
                    "supplier_offer_fetch_receipt": identity(
                        MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES
                    ),
                },
            },
            "assembly_evidence": _embedded_schema(
                _assembly.assembly_evidence_json_schema()
            ),
            "supplier_offer_fetch_receipt": _embedded_schema(
                _acquisition.supplier_offer_fetch_receipt_json_schema()
            ),
            "supplier_offer_coverage": _embedded_schema(
                _offer.supplier_offer_coverage_json_schema()
            ),
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
                "properties": {
                    key: {"const": True} for key in _VALIDATION_KEYS
                },
            },
            "binding_sha256": digest,
        },
        "allOf": [
            {
                "if": {
                    "properties": {"complete": {"const": True}},
                    "required": ["complete"],
                },
                "then": {
                    "properties": {
                        "status": {"const": "complete"},
                        "findings": {"maxItems": 0},
                    }
                },
            },
            {
                "if": {
                    "properties": {"complete": {"const": False}},
                    "required": ["complete"],
                },
                "then": {
                    "properties": {
                        "status": {"const": "incomplete"},
                        "findings": {"minItems": 1},
                    }
                },
            },
        ],
        "$comment": (
            "Runtime validation additionally enforces canonical child bytes, "
            "fresh independent child replay, exact shared-source/procurement/offer/"
            "timestamp cross-bindings, network semantics, caller and staged source "
            "rereads, bounds, and the domain-separated outer binding. Timestamp "
            "equality is not trusted time; no current availability, authenticity, "
            "reservation, authorization, order, payment, or machine operation is "
            "claimed."
        ),
    }


def _normalize_identity(
    value: Any, label: str, maximum: int, *, named: bool = False
) -> dict[str, Any]:
    required = {"name", "bytes", "sha256"} if named else {"bytes", "sha256"}
    if not isinstance(value, Mapping) or set(value) != required:
        raise _fail(f"{label} identity is invalid")
    byte_count = value["bytes"]
    digest = value["sha256"]
    if type(byte_count) is not int or not 1 <= byte_count <= maximum:
        raise _fail(f"{label} identity is invalid")
    if (
        type(digest) is not str
        or str.__len__(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise _fail(f"{label} identity is invalid")
    result: dict[str, Any] = {}
    if named:
        name = value["name"]
        if type(name) is not str:
            raise _fail(f"{label} identity is invalid")
        try:
            portable = _assembly._portable_leaf(name, label, ".kicad_pcb")
        except Exception:
            raise _fail(f"{label} identity is invalid") from None
        if portable != name:
            raise _fail(f"{label} identity is invalid")
        result["name"] = str.__str__(name)
    result["bytes"] = byte_count
    result["sha256"] = str.__str__(digest)
    return result


def _normalize_outer_sources(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _SOURCE_KEYS:
        raise _fail("assembly supplier-offer sources are invalid")
    return {
        "assembly_evidence": _normalize_identity(
            value["assembly_evidence"],
            "assembly-evidence report",
            MAXIMUM_ASSEMBLY_EVIDENCE_BYTES,
        ),
        "board": _normalize_identity(
            value["board"], "board", MAXIMUM_BOARD_BYTES, named=True
        ),
        "board_binding_report": _normalize_identity(
            value["board_binding_report"],
            "board-binding report",
            MAXIMUM_BOARD_BINDING_REPORT_BYTES,
        ),
        "catalog_snapshot": _normalize_identity(
            value["catalog_snapshot"],
            "catalog snapshot",
            MAXIMUM_CATALOG_SNAPSHOT_BYTES,
        ),
        "circuit_handoff_bundle": _normalize_identity(
            value["circuit_handoff_bundle"],
            "circuit handoff bundle",
            MAXIMUM_HANDOFF_BYTES,
        ),
        "final_cpl_report": _normalize_identity(
            value["final_cpl_report"],
            "final-CPL report",
            MAXIMUM_FINAL_CPL_REPORT_BYTES,
        ),
        "handoff_generation_bundle": _normalize_identity(
            value["handoff_generation_bundle"],
            "handoff generation bundle",
            MAXIMUM_HANDOFF_GENERATION_BYTES,
        ),
        "manufacturing_package": _normalize_identity(
            value["manufacturing_package"],
            "manufacturing package",
            MAXIMUM_PACKAGE_BYTES,
        ),
        "procurement_intent": _normalize_identity(
            value["procurement_intent"],
            "procurement intent",
            MAXIMUM_PROCUREMENT_INTENT_BYTES,
        ),
        "supplier_offer": _normalize_identity(
            value["supplier_offer"],
            "supplier offer",
            MAXIMUM_SUPPLIER_OFFER_BYTES,
        ),
        "supplier_offer_coverage": _normalize_identity(
            value["supplier_offer_coverage"],
            "supplier-offer coverage",
            MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES,
        ),
        "supplier_offer_fetch_receipt": _normalize_identity(
            value["supplier_offer_fetch_receipt"],
            "supplier-offer fetch receipt",
            MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
        ),
    }


def _require_equal(left: Any, right: Any, message: str) -> None:
    if not _strict_json_equal(left, right):
        raise _fail(message)


def _cross_bind(
    assembly: Mapping[str, Any],
    receipt: Mapping[str, Any],
    coverage: Mapping[str, Any],
    sources: Mapping[str, Any],
    *,
    assembly_raw: bytes,
    receipt_raw: bytes,
    coverage_raw: bytes,
    offer_raw: bytes,
    requested_boards: int | None = None,
    evaluated_at_unix: int | None = None,
) -> None:
    assembly_sources = assembly["sources"]
    coverage_sources = coverage["sources"]

    _require_equal(
        assembly_sources["board"],
        sources["board"],
        "assembly board identity is not cross-bound",
    )
    _require_equal(
        coverage_sources["board"],
        sources["board"],
        "coverage board identity is not cross-bound",
    )
    for assembly_key, outer_key in (
        ("circuit_handoff_bundle", "circuit_handoff_bundle"),
        ("handoff_generation_bundle", "handoff_generation_bundle"),
        ("manufacturing_package", "manufacturing_package"),
        ("board_binding_report", "board_binding_report"),
        ("procurement_intent", "procurement_intent"),
        ("catalog_snapshot", "catalog_snapshot"),
        ("final_cpl_report", "final_cpl_report"),
    ):
        _require_equal(
            assembly_sources[assembly_key],
            sources[outer_key],
            f"assembly {outer_key} identity is not cross-bound",
        )
    for coverage_key, outer_key in (
        ("manufacturing_package", "manufacturing_package"),
        ("generation_bundle", "handoff_generation_bundle"),
        ("catalog_snapshot", "catalog_snapshot"),
        ("procurement_intent", "procurement_intent"),
        ("supplier_offer", "supplier_offer"),
    ):
        _require_equal(
            coverage_sources[coverage_key],
            sources[outer_key],
            f"coverage {outer_key} identity is not cross-bound",
        )
    _require_equal(
        assembly["procurement"],
        coverage["procurement"],
        "assembly and coverage procurement projections differ",
    )
    _require_equal(
        sources["assembly_evidence"],
        _identity(assembly_raw),
        "assembly child-report identity is not cross-bound",
    )
    _require_equal(
        sources["supplier_offer_fetch_receipt"],
        _identity(receipt_raw),
        "receipt child-report identity is not cross-bound",
    )
    _require_equal(
        sources["supplier_offer_coverage"],
        _identity(coverage_raw),
        "coverage child-report identity is not cross-bound",
    )
    offer_identity = _identity(offer_raw)
    _require_equal(
        sources["supplier_offer"],
        offer_identity,
        "canonical supplier-offer identity is not cross-bound",
    )
    if (
        receipt["offer_bytes"] != offer_identity["bytes"]
        or receipt["offer_sha256"] != offer_identity["sha256"]
        or receipt["supplier"] != coverage["supplier_offer"]["supplier"]
        or receipt["procurement_intent_sha256"]
        != sources["procurement_intent"]["sha256"]
    ):
        raise _fail("supplier-offer receipt bindings are inconsistent")
    if (
        coverage["requested_boards"] < 1
        or coverage["evaluated_at_unix"] != receipt["fetched_at_unix"]
        or (
            requested_boards is not None
            and coverage["requested_boards"] != requested_boards
        )
        or (
            evaluated_at_unix is not None
            and coverage["evaluated_at_unix"] != evaluated_at_unix
        )
    ):
        raise _fail("evaluation timestamp binding is inconsistent")
    if (
        assembly["adapter_network_performed"] is not False
        or coverage["adapter_network_performed"] is not False
        or receipt["adapter_network_performed"] is not True
    ):
        raise _fail("nested network semantics are inconsistent")


def _compose_result(
    assembly: Mapping[str, Any],
    receipt: Mapping[str, Any],
    coverage: Mapping[str, Any],
    sources: Mapping[str, Any],
) -> dict[str, Any]:
    complete = bool(assembly["complete"] and coverage["covered"])
    findings: list[dict[str, str]] = []
    if not assembly["complete"]:
        findings.append(
            {
                "code": "assembly_evidence_incomplete",
                "message": _FINDING_MESSAGES["assembly_evidence_incomplete"],
            }
        )
    if not coverage["covered"]:
        findings.append(
            {
                "code": "supplier_offer_not_covered",
                "message": _FINDING_MESSAGES["supplier_offer_not_covered"],
            }
        )
    findings.sort(key=lambda item: item["code"])
    result: dict[str, Any] = {
        "schema_version": ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_SCHEMA_VERSION,
        "scope": ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_SCOPE,
        "status": "complete" if complete else "incomplete",
        "complete": complete,
        **{key: False for key in _FALSE_CLAIM_KEYS},
        "sources": copy.deepcopy(dict(sources)),
        "assembly_evidence": copy.deepcopy(dict(assembly)),
        "supplier_offer_fetch_receipt": copy.deepcopy(dict(receipt)),
        "supplier_offer_coverage": copy.deepcopy(dict(coverage)),
        "findings": findings,
        "validation": {key: True for key in _VALIDATION_KEYS},
    }
    result["binding_sha256"] = _sha256(
        ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BINDING_DOMAIN
        + _compact_json(result)
    )
    return result


def _validate_outer_result(
    value: Any,
    *,
    validated_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _RESULT_KEYS:
        raise _fail("assembly supplier-offer evidence does not match its closed shape")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"]
        != ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_SCHEMA_VERSION
        or value["scope"] != ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_SCOPE
        or any(value[key] is not False for key in _FALSE_CLAIM_KEYS)
    ):
        raise _fail("assembly supplier-offer evidence identity is invalid")
    try:
        assembly_raw = _assembly.render_assembly_evidence(
            value["assembly_evidence"]
        )
        coverage_raw = _offer.render_supplier_offer_coverage(
            value["supplier_offer_coverage"]
        )
    except (_assembly.AssemblyEvidenceError, _offer.SupplierOfferError):
        raise _fail("nested child evidence is invalid") from None
    assembly = _parse_json_object(assembly_raw, "nested assembly evidence")
    coverage = _parse_json_object(coverage_raw, "nested supplier-offer coverage")
    try:
        normalized_offer = _offer._normalize_offer(coverage["supplier_offer"])
    except Exception:
        raise _fail("nested normalized supplier offer is invalid") from None
    offer_raw = _pretty_json(
        normalized_offer,
        maximum=MAXIMUM_SUPPLIER_OFFER_BYTES,
        label="nested normalized supplier offer",
    )
    if validated_receipt is None:
        try:
            receipt = _acquisition.validate_supplier_offer_fetch_receipt(
                value["supplier_offer_fetch_receipt"], offer_raw
            )
        except Exception:
            raise _fail("nested supplier-offer fetch receipt is invalid") from None
    else:
        receipt_snapshot = _snapshot_mapping(
            validated_receipt,
            maximum=MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
            label="validated nested supplier-offer fetch receipt",
        )
        try:
            receipt = _acquisition._validate_receipt_shape(
                receipt_snapshot, allow_insecure_loopback=False
            )
        except Exception:
            raise _fail("nested supplier-offer fetch receipt is invalid") from None
        if not _strict_json_equal(receipt_snapshot, receipt):
            raise _fail("nested supplier-offer fetch receipt is inconsistent")
    receipt_raw = _pretty_json(
        receipt,
        maximum=MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
        label="nested supplier-offer fetch receipt",
    )
    if not _strict_json_equal(value["supplier_offer_fetch_receipt"], receipt):
        raise _fail("nested supplier-offer fetch receipt is inconsistent")
    sources = _normalize_outer_sources(value["sources"])
    _cross_bind(
        assembly,
        receipt,
        coverage,
        sources,
        assembly_raw=assembly_raw,
        receipt_raw=receipt_raw,
        coverage_raw=coverage_raw,
        offer_raw=offer_raw,
    )
    expected = _compose_result(assembly, receipt, coverage, sources)
    if not _strict_json_equal(value, expected):
        raise _fail("assembly supplier-offer evidence is internally inconsistent")
    return expected


def _render_impl(value: Mapping[str, Any]) -> bytes:
    try:
        snapshot = _snapshot_mapping(
            value,
            maximum=MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES,
            label="assembly supplier-offer evidence report",
        )
        expected = _validate_outer_result(snapshot)
        rendered = _pretty_json(
            expected,
            maximum=MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES,
            label="assembly supplier-offer evidence report",
        )
    except AssemblySupplierOfferEvidenceError:
        raise
    except Exception:
        raise _fail("assembly supplier-offer evidence cannot be serialized") from None
    return rendered
