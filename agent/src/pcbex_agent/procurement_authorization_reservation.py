"""Local durable admission for one freshly replayed procurement challenge.

The public orchestrator remains responsible for fresh v1.471 verification.
This module only builds the compact path-free marker and asks the separate
trusted Rust helper to install it in a pre-existing local ledger. The marker
does not claim global one-time use, inventory reservation, ordering, or
payment.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
import time
from typing import Any

from . import assembly_evidence as _assembly
from .bounded_io import BoundedIOError, atomic_write_no_clobber, read_bytes
from .bounded_process import BoundedProcessError, run_bounded
from .procurement_release_authorization import (
    MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES,
    ProcurementReleaseAuthorizationError,
    render_procurement_authorization_report,
)


PROCUREMENT_AUTHORIZATION_RESERVATION_SCHEMA_VERSION = 1
PROCUREMENT_AUTHORIZATION_RESERVATION_SCOPE = (
    "pinned-local-procurement-authorization-ledger-at-most-once-v1"
)
PROCUREMENT_AUTHORIZATION_RESERVATION_STATUS = "local_reservation_committed"
MAXIMUM_PROCUREMENT_AUTHORIZATION_RESERVATION_BYTES = 16 * 1024
MAXIMUM_RESERVATION_CHILD_OUTPUT_BYTES = 64 * 1024
_MAXIMUM_TIMESTAMP = 9_223_372_036_854_775_807
_MAXIMUM_MONEY_MICROS = 9_007_199_254_740_991
_MAXIMUM_VALIDITY_SECONDS = 604_800
_MARKER_KEYS = (
    "schema_version",
    "reservation_scope",
    "status",
    "local_challenge_reserved",
    "adapter_network_performed",
    "global_challenge_one_time_use_enforced",
    "inventory_reserved",
    "order_placed",
    "payment_performed",
    "ledger_id",
    "authorization_report_summary",
)
_SUMMARY_KEYS = (
    "schema_version",
    "status",
    "procurement_authorized",
    "authorization_id",
    "challenge",
    "supplier",
    "offer_id",
    "requested_boards",
    "currency",
    "component_subtotal_micros",
    "maximum_component_subtotal_micros",
    "offer_valid_from_unix",
    "offer_valid_until_unix",
    "receipt_fetched_at_unix",
    "maximum_receipt_observation_age_seconds",
    "valid_from_unix",
    "expires_at_unix",
    "evaluated_at_unix",
    "approvals",
    "rejections",
    "gate_failure_count",
    "current_availability_verified",
    "supplier_authenticity_verified",
    "offer_authenticity_verified",
    "price_authenticity_verified",
    "receipt_observation_authenticity_verified",
    "policy_pack_authenticity_verified",
    "trusted_time_verified",
    "challenge_one_time_use_enforced",
    "report_bytes",
    "report_sha256",
    "report_binding_sha256",
)


class ProcurementAuthorizationReservationError(ValueError):
    """The local procurement reservation could not be safely committed."""


def _fail(message: str) -> ProcurementAuthorizationReservationError:
    return ProcurementAuthorizationReservationError(message)


def _digest(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise _fail(f"{label} must contain 64 lowercase hexadecimal digits")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _fail(f"{label} is outside its closed bound")
    return value


def _text(value: Any, label: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8", errors="strict")) > maximum
        or value.strip() != value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise _fail(f"{label} is invalid")
    return value


def _slug(value: Any, label: str) -> str:
    value = _text(value, label, 128)
    if (
        not value.isascii()
        or value[0] not in "abcdefghijklmnopqrstuvwxyz0123456789"
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for character in value)
    ):
        raise _fail(f"{label} is invalid")
    return value


def _render_marker(value: Mapping[str, Any]) -> bytes:
    try:
        raw = (
            json.dumps(
                dict(value),
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
                sort_keys=False,
            )
            + "\n"
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        raise _fail("procurement authorization reservation cannot be serialized") from None
    if not 1 <= len(raw) <= MAXIMUM_PROCUREMENT_AUTHORIZATION_RESERVATION_BYTES:
        raise _fail("procurement authorization reservation exceeds its byte bound")
    return raw


def build_procurement_authorization_reservation(
    report: Mapping[str, Any], ledger_id: str
) -> dict[str, Any]:
    """Build the canonical compact marker for one exact authorized report."""

    ledger_id = _digest(ledger_id, "procurement authorization reservation ledger id")
    try:
        report_raw = render_procurement_authorization_report(report)
        normalized = json.loads(report_raw.decode("utf-8", errors="strict"))
        commercial = normalized["evidence"]["commercial"]
        scope = normalized["authorization_scope"]
        policy = normalized["policy_pack"]["procurement_authorization_policy"]
    except (ProcurementReleaseAuthorizationError, KeyError, TypeError, ValueError, UnicodeError):
        raise _fail("procurement authorization report is invalid") from None
    if (
        normalized["status"] != "procurement_authorized"
        or normalized["procurement_authorized"] is not True
        or normalized["adapter_network_performed"] is not False
        or normalized["rejections"] != 0
        or normalized["gate_failures"] != []
        or normalized["challenge_one_time_use_enforced"] is not False
        or normalized["current_availability_verified"] is not False
        or normalized["supplier_authenticity_verified"] is not False
        or normalized["offer_authenticity_verified"] is not False
        or normalized["price_authenticity_verified"] is not False
        or normalized["receipt_observation_authenticity_verified"] is not False
        or normalized["policy_pack_authenticity_verified"] is not False
        or normalized["trusted_time_verified"] is not False
        or commercial["covered"] is not True
        or type(commercial["component_subtotal_micros"]) is not int
    ):
        raise _fail("only a freshly verified authorized procurement report may be reserved")
    summary = {
        "schema_version": normalized["schema_version"],
        "status": normalized["status"],
        "procurement_authorized": normalized["procurement_authorized"],
        "authorization_id": scope["authorization_id"],
        "challenge": scope["challenge"],
        "supplier": commercial["supplier"],
        "offer_id": commercial["offer_id"],
        "requested_boards": scope["requested_boards"],
        "currency": scope["currency"],
        "component_subtotal_micros": commercial["component_subtotal_micros"],
        "maximum_component_subtotal_micros": scope[
            "maximum_component_subtotal_micros"
        ],
        "offer_valid_from_unix": commercial["offer_valid_from_unix"],
        "offer_valid_until_unix": commercial["offer_valid_until_unix"],
        "receipt_fetched_at_unix": commercial["receipt_fetched_at_unix"],
        "maximum_receipt_observation_age_seconds": policy[
            "maximum_receipt_observation_age_seconds"
        ],
        "valid_from_unix": scope["valid_from_unix"],
        "expires_at_unix": scope["expires_at_unix"],
        "evaluated_at_unix": normalized["evaluated_at_unix"],
        "approvals": normalized["approvals"],
        "rejections": normalized["rejections"],
        "gate_failure_count": len(normalized["gate_failures"]),
        "current_availability_verified": normalized[
            "current_availability_verified"
        ],
        "supplier_authenticity_verified": normalized[
            "supplier_authenticity_verified"
        ],
        "offer_authenticity_verified": normalized["offer_authenticity_verified"],
        "price_authenticity_verified": normalized["price_authenticity_verified"],
        "receipt_observation_authenticity_verified": normalized[
            "receipt_observation_authenticity_verified"
        ],
        "policy_pack_authenticity_verified": normalized[
            "policy_pack_authenticity_verified"
        ],
        "trusted_time_verified": normalized["trusted_time_verified"],
        "challenge_one_time_use_enforced": normalized[
            "challenge_one_time_use_enforced"
        ],
        "report_bytes": len(report_raw),
        "report_sha256": hashlib.sha256(report_raw).hexdigest(),
        "report_binding_sha256": normalized["binding_sha256"],
    }
    marker = {
        "schema_version": PROCUREMENT_AUTHORIZATION_RESERVATION_SCHEMA_VERSION,
        "reservation_scope": PROCUREMENT_AUTHORIZATION_RESERVATION_SCOPE,
        "status": PROCUREMENT_AUTHORIZATION_RESERVATION_STATUS,
        "local_challenge_reserved": True,
        "adapter_network_performed": False,
        "global_challenge_one_time_use_enforced": False,
        "inventory_reserved": False,
        "order_placed": False,
        "payment_performed": False,
        "ledger_id": ledger_id,
        "authorization_report_summary": summary,
    }
    return validate_procurement_authorization_reservation(marker)


def validate_procurement_authorization_reservation(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate and normalize one path-free reservation marker."""

    if not isinstance(value, Mapping) or tuple(value.keys()) != _MARKER_KEYS:
        raise _fail("procurement authorization reservation does not match its closed shape")
    summary = value["authorization_report_summary"]
    if not isinstance(summary, Mapping) or tuple(summary.keys()) != _SUMMARY_KEYS:
        raise _fail("procurement authorization reservation summary is invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != PROCUREMENT_AUTHORIZATION_RESERVATION_SCHEMA_VERSION
        or value["reservation_scope"] != PROCUREMENT_AUTHORIZATION_RESERVATION_SCOPE
        or value["status"] != PROCUREMENT_AUTHORIZATION_RESERVATION_STATUS
        or value["local_challenge_reserved"] is not True
        or any(
            value[key] is not False
            for key in (
                "global_challenge_one_time_use_enforced",
                "adapter_network_performed",
                "inventory_reserved",
                "order_placed",
                "payment_performed",
            )
        )
    ):
        raise _fail("procurement authorization reservation identity or nonclaims are invalid")
    _digest(value["ledger_id"], "procurement authorization reservation ledger id")
    if (
        type(summary["schema_version"]) is not int
        or summary["schema_version"] != 1
        or summary["status"] != "procurement_authorized"
        or summary["procurement_authorized"] is not True
        or summary["rejections"] != 0
        or summary["gate_failure_count"] != 0
        or any(
            summary[key] is not False
            for key in (
                "current_availability_verified",
                "supplier_authenticity_verified",
                "offer_authenticity_verified",
                "price_authenticity_verified",
                "receipt_observation_authenticity_verified",
                "policy_pack_authenticity_verified",
                "trusted_time_verified",
                "challenge_one_time_use_enforced",
            )
        )
    ):
        raise _fail("procurement authorization reservation summary is not authorized")
    _digest(summary["challenge"], "procurement authorization challenge")
    _slug(summary["authorization_id"], "procurement authorization id")
    supplier = _text(summary["supplier"], "procurement supplier", 64)
    if (
        not supplier.isascii()
        or supplier[0] not in "abcdefghijklmnopqrstuvwxyz0123456789"
        or supplier[-1] not in "abcdefghijklmnopqrstuvwxyz0123456789"
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789._-"
            for character in supplier
        )
    ):
        raise _fail("procurement supplier is invalid")
    _text(summary["offer_id"], "procurement supplier offer id", 128)
    currency = summary["currency"]
    if (
        type(currency) is not str
        or len(currency) != 3
        or not currency.isascii()
        or not currency.isalpha()
        or not currency.isupper()
    ):
        raise _fail("procurement reservation currency is invalid")
    _digest(summary["report_sha256"], "procurement authorization report SHA-256")
    _digest(
        summary["report_binding_sha256"],
        "procurement authorization report binding SHA-256",
    )
    _integer(summary["requested_boards"], "requested boards", 1, 1_000_000)
    subtotal = _integer(
        summary["component_subtotal_micros"],
        "component subtotal",
        0,
        _MAXIMUM_MONEY_MICROS,
    )
    ceiling = _integer(
        summary["maximum_component_subtotal_micros"],
        "component subtotal ceiling",
        1,
        _MAXIMUM_MONEY_MICROS,
    )
    if subtotal > ceiling:
        raise _fail("component subtotal exceeds the reservation ceiling")
    for key in (
        "offer_valid_from_unix",
        "offer_valid_until_unix",
        "receipt_fetched_at_unix",
        "valid_from_unix",
        "expires_at_unix",
        "evaluated_at_unix",
    ):
        _integer(summary[key], key, 0, _MAXIMUM_TIMESTAMP)
    maximum_age = _integer(
        summary["maximum_receipt_observation_age_seconds"],
        "maximum receipt observation age",
        1,
        _MAXIMUM_VALIDITY_SECONDS,
    )
    _integer(summary["approvals"], "procurement approval count", 2, 100)
    _integer(
        summary["report_bytes"],
        "procurement authorization report byte count",
        1,
        MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES,
    )
    offer_start = summary["offer_valid_from_unix"]
    offer_end = summary["offer_valid_until_unix"]
    valid_from = summary["valid_from_unix"]
    expires_at = summary["expires_at_unix"]
    evaluated = summary["evaluated_at_unix"]
    fetched = summary["receipt_fetched_at_unix"]
    if (
        offer_start >= offer_end
        or valid_from >= expires_at
        or expires_at - valid_from > _MAXIMUM_VALIDITY_SECONDS
        or valid_from < offer_start
        or expires_at >= offer_end
        or evaluated < valid_from
        or evaluated > expires_at
        or evaluated < offer_start
        or evaluated >= offer_end
        or fetched > evaluated
        or evaluated - fetched > maximum_age
    ):
        raise _fail("procurement reservation timing is invalid")
    normalized = json.loads(_render_marker(value).decode("utf-8"))
    return normalized


def render_procurement_authorization_reservation(
    value: Mapping[str, Any],
) -> bytes:
    """Render one canonical marker for the trusted Rust ledger helper."""

    return _render_marker(validate_procurement_authorization_reservation(value))


def commit_procurement_authorization_reservation(
    marker: Mapping[str, Any],
    reservation_ledger: str | os.PathLike[str],
    expected_ledger_id: str,
    authorization_pcbex: str,
    protected_inputs: Sequence[str | os.PathLike[str]],
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Ask the trusted Unix helper to durably install one exact marker."""

    if os.name != "posix":
        raise _fail("local procurement authorization reservation is supported only on Unix")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise _fail("procurement reservation timeout is invalid")
    timeout = float(timeout_seconds)
    if not math.isfinite(timeout) or timeout <= 0:
        raise _fail("procurement reservation timeout is invalid")
    deadline = time.monotonic() + timeout
    expected = _digest(expected_ledger_id, "expected procurement reservation ledger id")
    try:
        ledger = Path(os.path.abspath(os.fspath(reservation_ledger)))
        if not ledger.is_absolute():
            raise ValueError
        command = os.fspath(authorization_pcbex)
        if not isinstance(command, str) or not command or "\x00" in command:
            raise ValueError
        protected = [Path(os.path.abspath(os.fspath(path))) for path in protected_inputs]
    except (OSError, TypeError, ValueError, UnicodeError):
        raise _fail("procurement reservation path or command is invalid") from None
    normalized = validate_procurement_authorization_reservation(marker)
    if normalized["ledger_id"] != expected:
        raise _fail("procurement reservation marker does not bind the expected ledger id")
    raw = render_procurement_authorization_reservation(normalized)
    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-procurement-reservation-",
            dir=_assembly._trusted_temporary_root(),
        ) as directory:
            stage = Path(directory) / "marker.json"
            atomic_write_no_clobber(
                stage,
                raw,
                max_bytes=MAXIMUM_PROCUREMENT_AUTHORIZATION_RESERVATION_BYTES,
            )
            argv = [
                command,
                "internal-reserve-procurement-authorization",
                str(stage),
                "--reservation-ledger",
                str(ledger),
                "--expected-ledger-id",
                expected,
                *(
                    argument
                    for path in protected
                    for argument in ("--protected-input", str(path))
                ),
            ]
            if read_bytes(
                stage,
                max_bytes=MAXIMUM_PROCUREMENT_AUTHORIZATION_RESERVATION_BYTES,
            ) != raw:
                raise _fail("trusted procurement reservation workspace changed")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _fail("procurement reservation deadline expired before ledger commit")
            completed = run_bounded(
                argv,
                timeout_seconds=remaining,
                cleanup_timeout_seconds=min(5.0, remaining),
                max_stdout_bytes=MAXIMUM_RESERVATION_CHILD_OUTPUT_BYTES,
                max_stderr_bytes=MAXIMUM_RESERVATION_CHILD_OUTPUT_BYTES,
            )
            if read_bytes(
                stage,
                max_bytes=MAXIMUM_PROCUREMENT_AUTHORIZATION_RESERVATION_BYTES,
            ) != raw:
                raise _fail("trusted procurement reservation workspace changed")
    except ProcurementAuthorizationReservationError:
        raise
    except (BoundedIOError, BoundedProcessError, OSError, TypeError, ValueError):
        raise _fail("trusted procurement reservation helper process failed") from None
    if completed.returncode != 0:
        if b"challenge is already reserved" in completed.stderr:
            raise _fail("procurement authorization challenge is already reserved")
        if b"challenge remains reserved" in completed.stderr:
            raise _fail("procurement reservation completion failed; the challenge remains reserved")
        raise _fail("trusted procurement reservation helper rejected its inputs")
    if completed.stdout or completed.stderr:
        raise _fail("trusted procurement reservation helper emitted unexpected output")
    if time.monotonic() > deadline:
        raise _fail("procurement reservation completion failed; the challenge remains reserved")
    return normalized


__all__ = [
    "ProcurementAuthorizationReservationError",
    "MAXIMUM_PROCUREMENT_AUTHORIZATION_RESERVATION_BYTES",
    "build_procurement_authorization_reservation",
    "validate_procurement_authorization_reservation",
    "render_procurement_authorization_reservation",
    "commit_procurement_authorization_reservation",
]
