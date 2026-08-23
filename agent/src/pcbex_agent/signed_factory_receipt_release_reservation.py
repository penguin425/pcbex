"""Durable local admission for one freshly authenticated signed receipt release.

The public CLI freshly replays v1.480 before this module builds a compact,
path-free marker. A separate trusted Rust helper installs that marker in one
pre-existing descriptor-pinned Unix ledger. The result is local at-most-once
admission only: it performs no network request, submission, capacity hold,
order, or payment.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from functools import wraps
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Callable

from . import assembly_evidence as _assembly
from . import signed_factory_receipt_release as _v1480
from .bounded_io import BoundedIOError, atomic_write_no_clobber, read_bytes
from .bounded_process import BoundedProcessError, run_bounded


SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCHEMA_VERSION = 1
SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCOPE = (
    "pinned-local-signed-factory-receipt-release-ledger-at-most-once-v1"
)
SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_STATUS = "local_reservation_committed"
MAXIMUM_SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_BYTES = 16 * 1024
MAXIMUM_RESERVATION_CHILD_OUTPUT_BYTES = 64 * 1024
_MAXIMUM_TIMESTAMP = 9_223_372_036_854_775_807
_SUBJECT_DOMAIN = b"pcbex:signed-factory-receipt-release-reservation-subject:v1\0"
_FALSE_KEYS = (
    "trusted_time_verified",
    "factory_legal_identity_verified",
    "endpoint_transport_authenticity_verified",
    "raw_response_authenticity_verified",
    "source_authenticity_verified",
    "executable_origin_authenticity_verified",
    "toolchain_authenticity_verified",
    "policy_pack_authenticity_verified",
    "manufacturability_verified",
    "external_submission_performed",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "challenge_one_time_use_enforced",
)
_MARKER_KEYS = (
    "schema_version",
    "reservation_scope",
    "status",
    "local_challenge_reserved",
    "adapter_network_performed",
    "global_challenge_one_time_use_enforced",
    "external_submission_performed",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "ledger_id",
    "release_report_summary",
)
_SUMMARY_KEYS = (
    "schema_version",
    "status",
    "release_authenticated",
    "executable_pinned_fabrication_release_authorized",
    "factory_receipt_attestation_verified",
    "factory_receipt_authenticity_verified",
    "attestation_id",
    "challenge",
    "issued_at_unix",
    "expires_at_unix",
    "evaluated_at_unix",
    "fabrication_authorization_id",
    "fabrication_authorization_challenge",
    "fabrication_valid_from_unix",
    "fabrication_expires_at_unix",
    "factory_id",
    "provider",
    "manufacturing_package_sha256",
    "factory_receipt_sha256",
    "policy_pack_sha256",
    "policy_pack_canonical_sha256",
    "signed_attestation_sha256",
    "attestation_verifier_sha256",
    "retained_report_bytes",
    "retained_report_sha256",
    "retained_report_binding_sha256",
    "fresh_report_bytes",
    "fresh_report_sha256",
    "fresh_report_binding_sha256",
    "release_subject_sha256",
    "gate_failure_count",
    *_FALSE_KEYS,
)


class SignedFactoryReceiptReleaseReservationError(ValueError):
    """A signed-receipt release could not be safely admitted locally."""


def _fail(message: str) -> SignedFactoryReceiptReleaseReservationError:
    return SignedFactoryReceiptReleaseReservationError(message)


def _public_root() -> str:
    try:
        root = os.getcwd()
    except Exception:
        raise _fail("caller working directory is invalid") from None
    if type(root) is not str or not os.path.isabs(root):
        raise _fail("caller working directory is invalid")
    return root


def _guard_cwd(
    root: str, operation: Callable[..., Any], *args: Any, **kwargs: Any
) -> Any:
    try:
        result = operation(*args, **kwargs)
    finally:
        try:
            observed = os.getcwd()
        except Exception:
            try:
                os.chdir(root)
            except Exception:
                raise _fail(
                    "caller working directory became invalid and could not be restored"
                ) from None
            raise _fail("caller working directory became invalid and was restored") from None
        if observed != root:
            try:
                os.chdir(root)
            except Exception:
                raise _fail(
                    "caller working directory changed and could not be restored"
                ) from None
            raise _fail("caller-controlled hook changed the working directory") from None
    return result


def _guard_public(function: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(function)
    def guarded(*args: Any, **kwargs: Any) -> Any:
        root = _public_root()
        return _guard_cwd(root, function, *args, **kwargs)

    return guarded


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


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


def _slug(value: Any, label: str) -> str:
    if type(value) is not str:
        raise _fail(f"{label} is invalid")
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeError:
        raise _fail(f"{label} is invalid") from None
    if (
        not 1 <= size <= 128
        or not value.isascii()
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
        raise _fail("signed factory receipt release reservation cannot be serialized") from None
    if not 1 <= len(raw) <= MAXIMUM_SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_BYTES:
        raise _fail("signed factory receipt release reservation exceeds its byte bound")
    return raw


@_guard_public
def normalize_retained_signed_factory_receipt_release(
    raw: bytes,
) -> dict[str, Any]:
    """Require one exact canonical retained v1.480 report."""

    if type(raw) is not bytes or not 1 <= len(raw) <= _v1480.MAXIMUM_SIGNED_FACTORY_RECEIPT_RELEASE_REPORT_BYTES:
        raise _fail("retained signed factory receipt release report is outside its byte bound")
    try:
        normalized = _v1480._normalize_report(
            _v1480._strict_object(raw, "retained signed factory receipt release report")
        )
        expected = _v1480.render_signed_factory_receipt_release_report(normalized)
    except _v1480.SignedFactoryReceiptReleaseError:
        raise _fail("retained signed factory receipt release report is invalid") from None
    if raw != expected:
        raise _fail("retained signed factory receipt release report is not canonical")
    return normalized


@_guard_public
def signed_factory_receipt_release_subject_sha256(
    report: Mapping[str, Any],
) -> str:
    """Bind the time-invariant v1.480 reservation subject."""

    try:
        normalized = _v1480._normalize_report(report)
        payload = {
            "schema_version": normalized["schema_version"],
            "verification_scope": normalized["verification_scope"],
            "sources": normalized["sources"],
            "executable_pinned_fabrication_release_subject_sha256": (
                _v1480._v1479_subject(
                    normalized["executable_pinned_fabrication_release"]
                )
            ),
            "signed_factory_receipt_attestation": normalized[
                "factory_receipt_attestation"
            ]["signed_attestation"],
            "attestation_verifier": normalized["attestation_verifier"],
        }
        raw = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (
        _v1480.SignedFactoryReceiptReleaseError,
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
    ):
        raise _fail("signed factory receipt release subject is invalid") from None
    return _sha(_SUBJECT_DOMAIN + raw)


@_guard_public
def build_signed_factory_receipt_release_reservation(
    retained_report: Mapping[str, Any],
    fresh_report: Mapping[str, Any],
    ledger_id: str,
) -> dict[str, Any]:
    """Build one compact marker from a retained subject and fresh positive replay."""

    ledger_id = _digest(ledger_id, "signed release reservation ledger id")
    try:
        retained = _v1480._normalize_report(retained_report)
        fresh = _v1480._normalize_report(fresh_report)
        retained_raw = _v1480.render_signed_factory_receipt_release_report(retained)
        fresh_raw = _v1480.render_signed_factory_receipt_release_report(fresh)
    except _v1480.SignedFactoryReceiptReleaseError:
        raise _fail("signed factory receipt release report is invalid") from None
    retained_subject = signed_factory_receipt_release_subject_sha256(retained)
    fresh_subject = signed_factory_receipt_release_subject_sha256(fresh)
    if retained_subject != fresh_subject:
        raise _fail("fresh signed factory receipt release changed the retained subject")
    if (
        fresh["status"] != "release_authenticated"
        or fresh["release_authenticated"] is not True
        or fresh["executable_pinned_fabrication_release_authorized"] is not True
        or fresh["factory_receipt_attestation_verified"] is not True
        or fresh["factory_receipt_authenticity_verified"] is not True
        or fresh["gate_failures"] != []
        or any(fresh[key] is not False for key in _FALSE_KEYS)
    ):
        raise _fail("only a freshly authenticated signed receipt release may be reserved")

    attestation_report = fresh["factory_receipt_attestation"]
    attestation = attestation_report["attestation"]
    signer = attestation_report["signer"]
    evidence = attestation_report["evidence"]
    fabrication_scope = fresh["executable_pinned_fabrication_release"][
        "routing_drc_fabrication_release"
    ]["fabrication_authorization"]["scope"]
    summary = {
        "schema_version": fresh["schema_version"],
        "status": fresh["status"],
        "release_authenticated": fresh["release_authenticated"],
        "executable_pinned_fabrication_release_authorized": fresh[
            "executable_pinned_fabrication_release_authorized"
        ],
        "factory_receipt_attestation_verified": fresh[
            "factory_receipt_attestation_verified"
        ],
        "factory_receipt_authenticity_verified": fresh[
            "factory_receipt_authenticity_verified"
        ],
        "attestation_id": attestation["attestation_id"],
        "challenge": attestation["challenge"],
        "issued_at_unix": attestation["issued_at_unix"],
        "expires_at_unix": attestation["expires_at_unix"],
        "evaluated_at_unix": attestation_report["evaluated_at_unix"],
        "fabrication_authorization_id": fabrication_scope["authorization_id"],
        "fabrication_authorization_challenge": fabrication_scope["challenge"],
        "fabrication_valid_from_unix": fabrication_scope["valid_from_unix"],
        "fabrication_expires_at_unix": fabrication_scope["expires_at_unix"],
        "factory_id": signer["factory_id"],
        "provider": signer["provider"],
        "manufacturing_package_sha256": evidence["manufacturing_package"]["sha256"],
        "factory_receipt_sha256": evidence["factory_receipt"]["sha256"],
        "policy_pack_sha256": evidence["policy_pack"]["source"]["sha256"],
        "policy_pack_canonical_sha256": evidence["policy_pack"]["canonical_sha256"],
        "signed_attestation_sha256": fresh["sources"][
            "signed_factory_receipt_attestation"
        ]["sha256"],
        "attestation_verifier_sha256": fresh["attestation_verifier"]["sha256"],
        "retained_report_bytes": len(retained_raw),
        "retained_report_sha256": _sha(retained_raw),
        "retained_report_binding_sha256": retained["binding_sha256"],
        "fresh_report_bytes": len(fresh_raw),
        "fresh_report_sha256": _sha(fresh_raw),
        "fresh_report_binding_sha256": fresh["binding_sha256"],
        "release_subject_sha256": fresh_subject,
        "gate_failure_count": len(fresh["gate_failures"]),
        **{key: fresh[key] for key in _FALSE_KEYS},
    }
    marker = {
        "schema_version": SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCHEMA_VERSION,
        "reservation_scope": SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCOPE,
        "status": SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_STATUS,
        "local_challenge_reserved": True,
        "adapter_network_performed": False,
        "global_challenge_one_time_use_enforced": False,
        "external_submission_performed": False,
        "capacity_reserved": False,
        "order_placed": False,
        "payment_performed": False,
        "ledger_id": ledger_id,
        "release_report_summary": summary,
    }
    return validate_signed_factory_receipt_release_reservation(marker)


@_guard_public
def validate_signed_factory_receipt_release_reservation(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate and normalize one path-free local reservation marker."""

    if not isinstance(value, Mapping) or tuple(value.keys()) != _MARKER_KEYS:
        raise _fail("signed factory receipt release reservation does not match its closed shape")
    summary = value["release_report_summary"]
    if not isinstance(summary, Mapping) or tuple(summary.keys()) != _SUMMARY_KEYS:
        raise _fail("signed factory receipt release reservation summary is invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["reservation_scope"] != SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_SCOPE
        or value["status"] != SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_STATUS
        or value["local_challenge_reserved"] is not True
        or any(
            value[key] is not False
            for key in (
                "adapter_network_performed",
                "global_challenge_one_time_use_enforced",
                "external_submission_performed",
                "capacity_reserved",
                "order_placed",
                "payment_performed",
            )
        )
    ):
        raise _fail("signed factory receipt release reservation identity or nonclaims are invalid")
    _digest(value["ledger_id"], "signed release reservation ledger id")
    if (
        type(summary["schema_version"]) is not int
        or summary["schema_version"] != 1
        or summary["status"] != "release_authenticated"
        or any(
            summary[key] is not True
            for key in (
                "release_authenticated",
                "executable_pinned_fabrication_release_authorized",
                "factory_receipt_attestation_verified",
                "factory_receipt_authenticity_verified",
            )
        )
        or summary["gate_failure_count"] != 0
        or any(summary[key] is not False for key in _FALSE_KEYS)
    ):
        raise _fail("signed factory receipt release reservation summary is not authenticated")
    _slug(summary["attestation_id"], "factory receipt attestation id")
    _digest(summary["challenge"], "factory receipt attestation challenge")
    _slug(summary["fabrication_authorization_id"], "fabrication authorization id")
    _digest(
        summary["fabrication_authorization_challenge"],
        "fabrication authorization challenge",
    )
    _slug(summary["factory_id"], "factory receipt signer id")
    if (
        type(summary["provider"]) is not str
        or summary["provider"] not in {"generic", "jlcpcb", "pcbway"}
    ):
        raise _fail("factory receipt signer provider is invalid")
    for key in (
        "manufacturing_package_sha256",
        "factory_receipt_sha256",
        "policy_pack_sha256",
        "policy_pack_canonical_sha256",
        "signed_attestation_sha256",
        "attestation_verifier_sha256",
        "retained_report_sha256",
        "retained_report_binding_sha256",
        "fresh_report_sha256",
        "fresh_report_binding_sha256",
        "release_subject_sha256",
    ):
        _digest(summary[key], key)
    _integer(summary["retained_report_bytes"], "retained report bytes", 1, 16 * 1024 * 1024)
    _integer(summary["fresh_report_bytes"], "fresh report bytes", 1, 16 * 1024 * 1024)
    for key in (
        "issued_at_unix",
        "expires_at_unix",
        "evaluated_at_unix",
        "fabrication_valid_from_unix",
        "fabrication_expires_at_unix",
    ):
        _integer(summary[key], key, 0, _MAXIMUM_TIMESTAMP)
    if (
        summary["issued_at_unix"] >= summary["expires_at_unix"]
        or summary["fabrication_valid_from_unix"]
        >= summary["fabrication_expires_at_unix"]
        or not summary["issued_at_unix"]
        <= summary["evaluated_at_unix"]
        <= summary["expires_at_unix"]
        or not summary["fabrication_valid_from_unix"]
        <= summary["evaluated_at_unix"]
        <= summary["fabrication_expires_at_unix"]
    ):
        raise _fail("signed factory receipt release reservation timing is invalid")
    return json.loads(_render_marker(value).decode("utf-8", errors="strict"))


@_guard_public
def render_signed_factory_receipt_release_reservation(
    value: Mapping[str, Any],
) -> bytes:
    return _render_marker(validate_signed_factory_receipt_release_reservation(value))


@_guard_public
def commit_signed_factory_receipt_release_reservation(
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
        raise _fail("local signed factory receipt release reservation is supported only on Unix")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise _fail("signed release reservation timeout is invalid")
    timeout = float(timeout_seconds)
    if not math.isfinite(timeout) or not 0 < timeout <= 600:
        raise _fail("signed release reservation timeout is invalid")
    deadline = time.monotonic() + timeout
    expected = _digest(expected_ledger_id, "expected signed release reservation ledger id")
    root = _public_root()
    try:
        ledger_value = _guard_cwd(root, os.fspath, reservation_ledger)
        if type(ledger_value) is not str or not os.path.isabs(ledger_value):
            raise ValueError
        ledger = Path(os.path.abspath(ledger_value))
        command = _guard_cwd(root, os.fspath, authorization_pcbex)
        if type(command) is not str or not command or "\x00" in command:
            raise ValueError
        if issubclass(type(protected_inputs), (str, bytes, bytearray)):
            raise TypeError
        iterator = _guard_cwd(root, iter, protected_inputs)
        protected = []
        while True:
            try:
                path = _guard_cwd(root, next, iterator)
            except StopIteration:
                break
            if len(protected) == 128:
                raise ValueError
            rendered = _guard_cwd(root, os.fspath, path)
            if type(rendered) is not str:
                raise TypeError
            protected.append(Path(os.path.abspath(rendered)))
    except (OSError, TypeError, ValueError, UnicodeError):
        raise _fail("signed release reservation path or command is invalid") from None
    normalized = validate_signed_factory_receipt_release_reservation(marker)
    if normalized["ledger_id"] != expected:
        raise _fail("signed release reservation marker does not bind the expected ledger id")
    raw = render_signed_factory_receipt_release_reservation(normalized)
    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-signed-release-reservation-",
            dir=_assembly._trusted_temporary_root(),
        ) as directory:
            stage = Path(directory) / "marker.json"
            atomic_write_no_clobber(
                stage,
                raw,
                max_bytes=MAXIMUM_SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_BYTES,
            )
            argv = [
                command,
                "internal-reserve-signed-factory-receipt-release",
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
                max_bytes=MAXIMUM_SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_BYTES,
            ) != raw:
                raise _fail("trusted signed release reservation workspace changed")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _fail("signed release reservation deadline expired before ledger commit")
            try:
                completed = run_bounded(
                    argv,
                    timeout_seconds=remaining,
                    cleanup_timeout_seconds=min(5.0, remaining),
                    max_stdout_bytes=MAXIMUM_RESERVATION_CHILD_OUTPUT_BYTES,
                    max_stderr_bytes=MAXIMUM_RESERVATION_CHILD_OUTPUT_BYTES,
                )
            except (BoundedProcessError, OSError, TypeError, ValueError):
                raise _fail(
                    "signed release reservation completion is uncertain; "
                    "the challenge may remain reserved"
                ) from None
            if read_bytes(
                stage,
                max_bytes=MAXIMUM_SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_BYTES,
            ) != raw:
                raise _fail(
                    "signed release reservation completion failed; "
                    "the challenge may remain reserved"
                )
    except SignedFactoryReceiptReleaseReservationError:
        raise
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail("trusted signed release reservation helper process failed") from None
    if completed.returncode != 0:
        if b"challenge is already reserved" in completed.stderr:
            raise _fail("signed factory receipt release challenge is already reserved")
        if b"challenge remains reserved" in completed.stderr:
            raise _fail("signed release reservation completion failed; the challenge remains reserved")
        raise _fail(
            "trusted signed release reservation helper failed; "
            "the challenge may remain reserved"
        )
    if completed.stdout or completed.stderr:
        raise _fail(
            "signed release reservation completion failed; the challenge remains reserved"
        )
    if time.monotonic() > deadline:
        raise _fail("signed release reservation completion failed; the challenge remains reserved")
    return normalized


__all__ = [
    "MAXIMUM_SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION_BYTES",
    "SignedFactoryReceiptReleaseReservationError",
    "build_signed_factory_receipt_release_reservation",
    "commit_signed_factory_receipt_release_reservation",
    "normalize_retained_signed_factory_receipt_release",
    "render_signed_factory_receipt_release_reservation",
    "signed_factory_receipt_release_subject_sha256",
    "validate_signed_factory_receipt_release_reservation",
]
