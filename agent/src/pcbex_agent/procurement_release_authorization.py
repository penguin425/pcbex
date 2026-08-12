"""Offline, exact procurement-release approval and authorization orchestration.

The public replay executable (``pcbex``) and the trusted cryptographic TCB
(``authorization_pcbex``) are deliberately separate commands.  Python never
opens, reads, copies, or stages a signing private key; after all public inputs
and the first fresh replay are validated it passes only the frozen key path to
the trusted signing helper.

Rendered and retained authorization reports are point-in-time snapshots, not
current authority.  ``validate_procurement_release_authorization`` performs an
exact historical audit at the retained evaluation time.  Consumers requiring
current authority must call ``evaluate_procurement_release_authorization`` so
the original v1.470 closure is freshly replayed, approvals are cryptographically
reverified, and a new local wall-clock instant is sampled.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import copy
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
from typing import Any

from . import assembly_supplier_offer_evidence as _v1470
from . import assembly_evidence as _assembly
from . import procurement_intent as _procurement
from . import supplier_offer as _offer
from .bounded_io import BoundedIOError, atomic_write_no_clobber, read_bytes
from .bounded_process import BoundedProcessError, run_bounded


PROCUREMENT_RELEASE_REQUEST_SCHEMA_VERSION = 1
PROCUREMENT_RELEASE_REQUEST_SCOPE = "offline-exact-procurement-release-request-v1"
SIGNED_PROCUREMENT_APPROVAL_SCHEMA_VERSION = 1
SIGNED_PROCUREMENT_APPROVAL_SCOPE = "offline-exact-procurement-release-approval-v1"
PROCUREMENT_AUTHORIZATION_REPORT_SCHEMA_VERSION = 1
PROCUREMENT_AUTHORIZATION_REPORT_SCOPE = "offline-exact-procurement-release-authorization-v1"
PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_SCOPE = (
    "offline-exact-procurement-release-cryptographic-assessment-v1"
)
PROCUREMENT_RELEASE_REQUEST_BINDING_DOMAIN = (
    b"pcbex:offline-exact-procurement-release-request-v1\0"
)
PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BINDING_DOMAIN = (
    b"pcbex:offline-exact-procurement-release-cryptographic-assessment-v1\0"
)
PROCUREMENT_AUTHORIZATION_REPORT_BINDING_DOMAIN = (
    b"pcbex:offline-exact-procurement-release-authorization-v1\0"
)

MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES = 1 * 1024 * 1024
MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES = 128 * 1024 * 1024
MAXIMUM_PROCUREMENT_POLICY_PACK_BYTES = 64 * 1024 * 1024
MAXIMUM_PROCUREMENT_APPROVAL_AGGREGATE_BYTES = 32 * 1024 * 1024
MAXIMUM_PROCUREMENT_RELEASE_REQUEST_BYTES = 1 * 1024 * 1024
MAXIMUM_PROCUREMENT_APPROVALS = 100
MAXIMUM_TOTAL_INPUT_BYTES = 1013 * 1024 * 1024
MAXIMUM_VALIDATION_TOTAL_INPUT_BYTES = 1141 * 1024 * 1024
MAXIMUM_PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BYTES = 128 * 1024 * 1024
MAXIMUM_CHILD_STDOUT_BYTES = 1 * 1024 * 1024
MAXIMUM_CHILD_STDERR_BYTES = 1 * 1024 * 1024
MINIMUM_TIMEOUT_SECONDS = 1.0
MAXIMUM_TIMEOUT_SECONDS = 600.0
DEFAULT_TIMEOUT_SECONDS = 300.0


class ProcurementReleaseAuthorizationError(ValueError):
    """Stable, path-free procurement-release authorization failure."""


_NO_RETAINED = object()
_DIGEST_LENGTH = 64
_MAXIMUM_TIMESTAMP = _offer.MAXIMUM_TIMESTAMP
_MAXIMUM_MONEY_MICROS = _offer.MAXIMUM_MONEY_MICROS
_MAXIMUM_REASON_BYTES = 4096
_MAXIMUM_TICKET_BYTES = 256
_MAXIMUM_VALIDITY_SECONDS = 604_800

_ASSEMBLY_PROJECTION_KEYS = (
    "source", "binding_sha256", "schema_version", "scope", "complete"
)
_COMMERCIAL_KEYS = (
    "requested_boards", "supplier", "offer_id", "currency", "covered",
    "component_subtotal_micros", "offer_valid_from_unix",
    "offer_valid_until_unix", "receipt_fetched_at_unix",
)
_POLICY_PROJECTION_KEYS = ("source", "canonical_sha256", "id", "revision")
_EVIDENCE_KEYS = (
    "assembly_supplier_offer_evidence", "commercial", "policy_pack"
)
_AUTHORIZATION_SCOPE_KEYS = (
    "authorization_id", "challenge", "requested_boards", "currency",
    "maximum_component_subtotal_micros", "valid_from_unix", "expires_at_unix",
)
_REQUEST_KEYS = (
    "schema_version", "scope", "evidence", "authorization_scope", "binding_sha256"
)
_SIGNED_APPROVAL_KEYS = (
    "schema_version", "scope", "evidence", "authorization_scope", "decision",
    "reason", "ticket", "signer_id", "algorithm", "public_key", "signature",
)
_MEMBER_KEYS = (
    "signer_id", "public_key", "approval_sha256", "decision", "reason", "ticket"
)
_ASSESSMENT_VALIDATION_KEYS = (
    "request_binding_validated", "commercial_scope_cross_bound",
    "policy_pack_validated", "approval_signatures_verified",
    "distinct_signers_verified",
)
_ASSESSMENT_KEYS = (
    "schema_version", "scope", "status", "policy_satisfied", "evidence",
    "authorization_scope", "policy_pack", "evaluated_at_unix", "approvals",
    "rejections", "members", "signed_approvals", "gate_failures", "validation",
    "binding_sha256",
)
_FALSE_CLAIM_KEYS = (
    "adapter_network_performed", "current_availability_verified",
    "supplier_authenticity_verified", "offer_authenticity_verified",
    "price_authenticity_verified", "receipt_observation_authenticity_verified",
    "policy_pack_authenticity_verified", "trusted_time_verified",
    "inventory_reserved", "assembly_ready", "assembly_authorized",
    "fabrication_authorized", "order_ready", "order_placed", "payment_performed",
    "machine_operation_performed", "challenge_one_time_use_enforced",
)
_REPORT_VALIDATION_KEYS = (
    "assembly_supplier_offer_evidence_replayed", "evidence_complete_checked",
    "request_binding_validated", "commercial_scope_cross_bound",
    "policy_pack_validated", "approval_signatures_verified",
    "distinct_signers_verified", "caller_inputs_unchanged",
)
_REPORT_KEYS = (
    "schema_version", "scope", "status", "procurement_authorized",
    *_FALSE_CLAIM_KEYS, "evidence", "authorization_scope", "policy_pack",
    "evaluated_at_unix", "approvals", "rejections", "members",
    "signed_approvals", "gate_failures", "validation", "binding_sha256",
)


@dataclass(frozen=True)
class _Captured:
    path: str | None
    raw: bytes
    maximum: int
    label: str

    @property
    def identity(self) -> dict[str, Any]:
        return _identity(self.raw)


@dataclass(frozen=True)
class _Context:
    root: str
    deadline: float
    clock: Callable[[], float]
    replay_command: tuple[str, ...]
    authorization_command: tuple[str, ...]
    frozen_replay_args: tuple[Any, ...]
    replay_options: dict[str, Any]
    path_sources: tuple[str, ...]
    source_captures: tuple[_Captured, ...]


@dataclass(frozen=True)
class _PreCaptured:
    """Immutable caller-input baseline captured before injected hooks run."""

    root: str
    frozen_replay_args: tuple[Any, ...]
    replay_options: dict[str, Any]
    source_captures: tuple[_Captured, ...]
    evidence: _Captured
    policy: _Captured
    approvals: tuple[_Captured, ...]
    retained: _Captured | None

    @property
    def all_captures(self) -> tuple[_Captured, ...]:
        return (
            *self.source_captures,
            self.evidence,
            self.policy,
            *self.approvals,
            *((self.retained,) if self.retained is not None else ()),
        )


@dataclass(frozen=True)
class _PrivateKey:
    path: str
    metadata: tuple[int, int, int, int, int, int]


def _fail(message: str) -> ProcurementReleaseAuthorizationError:
    return ProcurementReleaseAuthorizationError(message)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": _sha256(raw)}


def _strict_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _strict_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _strict_equal(a, b) for a, b in zip(left, right)
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


def _parse_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeError, json.JSONDecodeError, _DuplicateJSONKey, ValueError,
        RecursionError,
    ):
        raise _fail(f"{label} is not strict duplicate-free JSON") from None
    if not isinstance(value, dict):
        raise _fail(f"{label} must be a JSON object")
    return value


def _compact(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=False,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        raise _fail("procurement authorization value cannot be serialized") from None


def _pretty(value: Mapping[str, Any], maximum: int, label: str) -> bytes:
    try:
        encoder = json.JSONEncoder(
            ensure_ascii=False, allow_nan=False, indent=2, sort_keys=False
        )
        output = bytearray()
        for chunk in encoder.iterencode(dict(value)):
            encoded = str.encode(chunk, "utf-8", "strict")
            if len(output) + len(encoded) + 1 > maximum:
                raise _fail(f"{label} exceeds its byte bound")
            output.extend(encoded)
        output.append(0x0A)
        return bytes(output)
    except ProcurementReleaseAuthorizationError:
        raise
    except (
        TypeError, ValueError, OverflowError, UnicodeError, RuntimeError,
        RecursionError,
    ):
        raise _fail(f"{label} cannot be serialized") from None


def _snapshot_mapping(value: Mapping[str, Any], maximum: int, label: str) -> dict[str, Any]:
    try:
        raw = _procurement._bounded_injected_json_bytes(
            value, maximum=maximum, label=label
        )
    except Exception:
        raise _fail(f"{label} is invalid") from None
    return _parse_object(raw, label)


def _bounded_bytes(value: Any, maximum: int, label: str) -> bytes:
    try:
        view = memoryview(value)
    except (TypeError, ValueError, BufferError):
        raise _fail(f"{label} is invalid") from None
    try:
        size = view.nbytes
        if not 1 <= size <= maximum:
            raise _fail(f"{label} exceeds its byte bound")
        raw = view.tobytes()
    except ProcurementReleaseAuthorizationError:
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


def _guard_cwd(root: str, operation: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
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
                raise _fail("caller working directory changed and could not be restored") from None
            raise _fail("caller-controlled hook changed the working directory")
    return result


def _public_root() -> str:
    """Capture the entry CWD before touching any caller-provided object."""

    try:
        root = os.getcwd()
    except Exception:
        raise _fail("caller working directory is invalid") from None
    if type(root) is not str or not os.path.isabs(root):
        raise _fail("caller working directory is invalid")
    return root


def _freeze_path(value: Any, label: str, root: str) -> str:
    try:
        rendered = _guard_cwd(root, _assembly._freeze_path, value, label)
        drive, _tail = os.path.splitdrive(rendered)
        if drive and not os.path.isabs(rendered):
            raise _fail(f"{label} is invalid")
        return _assembly._freeze_path(os.path.join(root, rendered), label)
    except ProcurementReleaseAuthorizationError:
        raise
    except Exception:
        raise _fail(f"{label} is invalid") from None


def _normalize_command(value: Any, label: str, root: str) -> tuple[str, ...]:
    try:
        return _guard_cwd(root, _assembly._normalize_command, value)
    except Exception:
        raise _fail(f"{label} is invalid") from None


def _deadline(timeout_seconds: Any, clock: Callable[[], float]) -> tuple[float, float]:
    if type(timeout_seconds) not in {int, float}:
        raise _fail("aggregate timeout is invalid")
    try:
        timeout = float(timeout_seconds)
        start = float(clock())
    except Exception:
        raise _fail("aggregate timeout is invalid") from None
    if (
        isinstance(timeout_seconds, bool) or not math.isfinite(timeout)
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
        result = deadline - float(clock())
    except Exception:
        raise _fail("aggregate deadline clock is invalid") from None
    if not math.isfinite(result) or result <= 0:
        raise _fail("procurement authorization exceeded its aggregate deadline")
    return min(result, MAXIMUM_TIMEOUT_SECONDS)


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _fail(f"{label} is invalid")
    return value


def _text(value: Any, label: str, maximum: int, *, slug: bool = False) -> str:
    if type(value) is not str:
        raise _fail(f"{label} is invalid")
    try:
        encoded = str.encode(value, "utf-8", "strict")
    except UnicodeEncodeError:
        raise _fail(f"{label} is invalid") from None
    if not encoded or len(encoded) > maximum or "\x00" in value:
        raise _fail(f"{label} is invalid")
    if not slug and not value.strip():
        raise _fail(f"{label} is invalid")
    if slug and not (
        (value[0].islower() or value[0].isdigit())
        and value.isascii()
        and all(character.islower() or character.isdigit() or (
            index > 0 and character in ".-"
        ) for index, character in enumerate(value))
    ):
        raise _fail(f"{label} is invalid")
    return str.__str__(value)


def _digest(value: Any, label: str) -> str:
    if (
        type(value) is not str or len(value) != _DIGEST_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise _fail(f"{label} is invalid")
    return value


def _closed(value: Any, keys: Sequence[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or list(value) != list(keys):
        raise _fail(f"{label} does not match its closed ordered shape")
    return value


def _capture_representation(
    value: Any,
    *,
    maximum: int,
    label: str,
    root: str,
    renderer: Callable[[Mapping[str, Any]], bytes] | None = None,
) -> _Captured:
    path: str | None = None
    if isinstance(value, Mapping):
        snapshot = _guard_cwd(root, _snapshot_mapping, value, maximum, label)
        raw = (
            _guard_cwd(root, renderer, snapshot)
            if renderer is not None
            else _pretty(snapshot, maximum, label)
        )
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = _guard_cwd(root, _bounded_bytes, value, maximum, label)
    elif isinstance(value, (str, os.PathLike)):
        path = _freeze_path(value, f"{label} source", root)
        try:
            raw = read_bytes(path, max_bytes=maximum)
        except (BoundedIOError, OSError, TypeError, ValueError):
            raise _fail(f"{label} source is invalid") from None
        if not raw:
            raise _fail(f"{label} source is empty")
    else:
        raise _fail(f"{label} is invalid")
    return _Captured(path, raw, maximum, label)


def _reread(captures: Sequence[_Captured], deadline: float, clock: Callable[[], float]) -> None:
    for capture in captures:
        if capture.path is None:
            continue
        try:
            observed = read_bytes(capture.path, max_bytes=capture.maximum)
        except (BoundedIOError, OSError, TypeError, ValueError):
            raise _fail(f"{capture.label} source is invalid during final reread") from None
        if observed != capture.raw:
            raise _fail(f"{capture.label} changed during procurement authorization")
        _remaining(deadline, clock)


def _verify_path_captures(captures: Sequence[_Captured]) -> None:
    """Reread path inputs without invoking any caller-controlled hook."""

    for capture in captures:
        if capture.path is None:
            continue
        try:
            observed = read_bytes(capture.path, max_bytes=capture.maximum)
        except (BoundedIOError, OSError, TypeError, ValueError):
            raise _fail(f"{capture.label} source is invalid during stability check") from None
        if observed != capture.raw:
            raise _fail(f"{capture.label} changed during procurement authorization")


def _path_identity(path: str, label: str) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError:
        raise _fail(f"{label} is invalid") from None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise _fail(f"{label} must be a stable regular non-link path")
    return metadata


def _metadata_token(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_mode, metadata.st_dev, metadata.st_ino, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _same_path(left: str, right: str) -> bool:
    try:
        if os.path.normcase(os.path.realpath(left)) == os.path.normcase(os.path.realpath(right)):
            return True
        return os.path.samefile(left, right)
    except (OSError, TypeError, ValueError):
        return False


def _reject_aliases(paths: Sequence[str], label: str) -> None:
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            if _same_path(left, right):
                raise _fail(f"{label} paths must be distinct")


def _policy_projection(raw: bytes, expected_digest: str) -> tuple[dict[str, Any], dict[str, Any]]:
    value = _parse_object(raw, "organization policy pack")
    # Rust owns full semantic validation and canonical digest computation.  The
    # Python preflight extracts only the closed pack identity needed to bind the
    # request, while rejecting obviously non-closed identity fields.
    if set(value) - {
        "schema_version", "id", "revision", "verified_on", "description",
        "dfm_profile", "electrical_policy", "ai_requirements",
        "require_simulation_evidence", "trusted_approval_keys",
        "trusted_human_escalation_keys", "fabrication_authorization_policy",
        "procurement_authorization_policy",
    }:
        raise _fail("organization policy pack has unknown fields")
    if set(value) != {
        "schema_version", "id", "revision", "verified_on", "description",
        "dfm_profile", "electrical_policy", "ai_requirements",
        "require_simulation_evidence", "trusted_approval_keys",
        *(set(("trusted_human_escalation_keys",)) if "trusted_human_escalation_keys" in value else set()),
        *(set(("fabrication_authorization_policy",)) if "fabrication_authorization_policy" in value else set()),
        *(set(("procurement_authorization_policy",)) if "procurement_authorization_policy" in value else set()),
    }:
        raise _fail("organization policy pack does not match its closed shape")
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise _fail("organization policy pack identity is invalid")
    pack_id = _text(value.get("id"), "organization policy pack id", 128, slug=True)
    revision = _integer(value.get("revision"), "organization policy pack revision", 1, 2**32 - 1)
    policy = value.get("procurement_authorization_policy")
    if not isinstance(policy, Mapping) or set(policy) != {
        "minimum_approvals", "currency", "maximum_validity_seconds",
        "maximum_receipt_observation_age_seconds",
        "maximum_component_subtotal_micros", "trusted_keys",
    }:
        raise _fail("organization policy pack has no closed procurement authorization policy")
    projection = {
        "source": _identity(raw),
        "canonical_sha256": expected_digest,
        "id": pack_id,
        "revision": revision,
    }
    return value, projection


def _normalize_evidence(value: Any) -> dict[str, Any]:
    try:
        rendered = _v1470.render_assembly_supplier_offer_evidence(value)
    except Exception:
        raise _fail("assembly supplier-offer evidence is invalid") from None
    parsed = _parse_object(rendered, "assembly supplier-offer evidence")
    if not _strict_equal(parsed, value):
        raise _fail("assembly supplier-offer evidence is inconsistent")
    return parsed


def _extract_request_evidence(
    v1470: Mapping[str, Any], evidence_raw: bytes, policy_raw: bytes, expected_digest: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    policy, policy_projection = _policy_projection(policy_raw, expected_digest)
    try:
        coverage = v1470["supplier_offer_coverage"]
        offer = coverage["supplier_offer"]
        receipt = v1470["supplier_offer_fetch_receipt"]
        commercial = {
            "requested_boards": coverage["requested_boards"],
            "supplier": offer["supplier"],
            "offer_id": offer["offer_id"],
            "currency": offer["currency"],
            "covered": coverage["covered"],
            "component_subtotal_micros": coverage["component_subtotal_micros"],
            "offer_valid_from_unix": offer["valid_from_unix"],
            "offer_valid_until_unix": offer["valid_until_unix"],
            "receipt_fetched_at_unix": receipt["fetched_at_unix"],
        }
        assembly_projection = {
            "source": _identity(evidence_raw),
            "binding_sha256": v1470["binding_sha256"],
            "schema_version": v1470["schema_version"],
            "scope": v1470["scope"],
            "complete": v1470["complete"],
        }
    except (KeyError, TypeError):
        raise _fail("fresh assembly supplier-offer evidence lacks commercial projection") from None
    _validate_assembly_projection(assembly_projection)
    _validate_commercial(commercial)
    return {
        "assembly_supplier_offer_evidence": assembly_projection,
        "commercial": commercial,
        "policy_pack": policy_projection,
    }, policy


def _authorization_scope(
    commercial: Mapping[str, Any], *, authorization_id: Any, challenge: Any,
    maximum_component_subtotal_micros: Any, valid_from_unix: Any,
    expires_at_unix: Any,
) -> dict[str, Any]:
    scope = {
        "authorization_id": _text(
            authorization_id, "procurement authorization id", 128, slug=True
        ),
        "challenge": _digest(challenge, "procurement authorization challenge"),
        "requested_boards": commercial["requested_boards"],
        "currency": commercial["currency"],
        "maximum_component_subtotal_micros": _integer(
            maximum_component_subtotal_micros,
            "maximum component subtotal", 1, _MAXIMUM_MONEY_MICROS,
        ),
        "valid_from_unix": _integer(
            valid_from_unix, "authorization valid-from timestamp", 0,
            _MAXIMUM_TIMESTAMP,
        ),
        "expires_at_unix": _integer(
            expires_at_unix, "authorization expiry timestamp", 0,
            _MAXIMUM_TIMESTAMP,
        ),
    }
    _validate_scope(scope, commercial)
    return scope


def _request(evidence: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any]:
    value = {
        "schema_version": PROCUREMENT_RELEASE_REQUEST_SCHEMA_VERSION,
        "scope": PROCUREMENT_RELEASE_REQUEST_SCOPE,
        "evidence": copy.deepcopy(evidence),
        "authorization_scope": copy.deepcopy(scope),
    }
    value["binding_sha256"] = _sha256(
        PROCUREMENT_RELEASE_REQUEST_BINDING_DOMAIN + _compact(value)
    )
    rendered = _pretty(value, MAXIMUM_PROCUREMENT_RELEASE_REQUEST_BYTES, "procurement signing request")
    if len(rendered) > MAXIMUM_PROCUREMENT_RELEASE_REQUEST_BYTES:
        raise _fail("procurement signing request exceeds its byte bound")
    return value


def _validate_identity(value: Any, maximum: int, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"bytes", "sha256"}:
        raise _fail(f"{label} identity is invalid")
    return {
        "bytes": _integer(value["bytes"], f"{label} byte count", 1, maximum),
        "sha256": _digest(value["sha256"], f"{label} digest"),
    }


def _validate_assembly_projection(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_ASSEMBLY_PROJECTION_KEYS):
        raise _fail("assembly supplier-offer evidence projection is invalid")
    normalized = {
        "source": _validate_identity(
            value["source"], _v1470.MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES,
            "assembly supplier-offer evidence",
        ),
        "binding_sha256": _digest(value["binding_sha256"], "assembly evidence binding"),
        "schema_version": value["schema_version"],
        "scope": value["scope"],
        "complete": value["complete"],
    }
    if (
        type(normalized["schema_version"]) is not int
        or normalized["schema_version"] != _v1470.ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_SCHEMA_VERSION
        or normalized["scope"] != _v1470.ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_SCOPE
        or type(normalized["complete"]) is not bool
    ):
        raise _fail("assembly supplier-offer evidence projection identity is invalid")
    return normalized


def _validate_commercial(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_COMMERCIAL_KEYS):
        raise _fail("procurement commercial evidence is invalid")
    requested = _integer(
        value["requested_boards"], "commercial requested board quantity", 1,
        _offer.MAXIMUM_REQUESTED_BOARDS,
    )
    supplier = value["supplier"]
    if (
        type(supplier) is not str or not 1 <= len(supplier.encode("utf-8", "strict")) <= 64
        or not supplier.isascii() or supplier[0] not in "abcdefghijklmnopqrstuvwxyz0123456789"
        or supplier[-1] not in "abcdefghijklmnopqrstuvwxyz0123456789"
        or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for c in supplier)
    ):
        raise _fail("commercial supplier is invalid")
    offer_id = _text(value["offer_id"], "commercial offer id", 128)
    if offer_id.strip() != offer_id or any(ord(c) < 0x20 for c in offer_id):
        raise _fail("commercial offer id is invalid")
    currency = value["currency"]
    if type(currency) is not str or len(currency) != 3 or not currency.isascii() or not currency.isupper() or not currency.isalpha():
        raise _fail("commercial currency is invalid")
    covered = value["covered"]
    if type(covered) is not bool:
        raise _fail("commercial covered state is invalid")
    subtotal = value["component_subtotal_micros"]
    if subtotal is not None:
        subtotal = _integer(subtotal, "commercial component subtotal", 0, _MAXIMUM_MONEY_MICROS)
    if covered != (subtotal is not None):
        raise _fail("commercial covered state and subtotal disagree")
    start = _integer(value["offer_valid_from_unix"], "offer valid-from timestamp", 0, _MAXIMUM_TIMESTAMP)
    end = _integer(value["offer_valid_until_unix"], "offer valid-until timestamp", 0, _MAXIMUM_TIMESTAMP)
    fetched = _integer(value["receipt_fetched_at_unix"], "receipt fetched timestamp", 0, _MAXIMUM_TIMESTAMP)
    if start >= end:
        raise _fail("commercial offer validity interval is invalid")
    return {
        "requested_boards": requested, "supplier": supplier, "offer_id": offer_id,
        "currency": currency, "covered": covered,
        "component_subtotal_micros": subtotal,
        "offer_valid_from_unix": start, "offer_valid_until_unix": end,
        "receipt_fetched_at_unix": fetched,
    }


def _validate_policy_projection(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_POLICY_PROJECTION_KEYS):
        raise _fail("procurement policy pack projection is invalid")
    return {
        "source": _validate_identity(
            value["source"], MAXIMUM_PROCUREMENT_POLICY_PACK_BYTES,
            "procurement policy pack",
        ),
        "canonical_sha256": _digest(value["canonical_sha256"], "canonical policy pack digest"),
        "id": _text(value["id"], "procurement policy pack id", 128, slug=True),
        "revision": _integer(value["revision"], "procurement policy pack revision", 1, 2**32 - 1),
    }


def _validate_evidence_projection(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_EVIDENCE_KEYS):
        raise _fail("procurement authorization evidence is invalid")
    return {
        "assembly_supplier_offer_evidence": _validate_assembly_projection(
            value["assembly_supplier_offer_evidence"]
        ),
        "commercial": _validate_commercial(value["commercial"]),
        "policy_pack": _validate_policy_projection(value["policy_pack"]),
    }


def _validate_scope(value: Any, commercial: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_AUTHORIZATION_SCOPE_KEYS):
        raise _fail("procurement authorization scope is invalid")
    normalized = {
        "authorization_id": _text(value["authorization_id"], "procurement authorization id", 128, slug=True),
        "challenge": _digest(value["challenge"], "procurement authorization challenge"),
        "requested_boards": _integer(value["requested_boards"], "authorization requested boards", 1, _offer.MAXIMUM_REQUESTED_BOARDS),
        "currency": value["currency"],
        "maximum_component_subtotal_micros": _integer(value["maximum_component_subtotal_micros"], "authorization component subtotal ceiling", 1, _MAXIMUM_MONEY_MICROS),
        "valid_from_unix": _integer(value["valid_from_unix"], "authorization valid-from timestamp", 0, _MAXIMUM_TIMESTAMP),
        "expires_at_unix": _integer(value["expires_at_unix"], "authorization expiry timestamp", 0, _MAXIMUM_TIMESTAMP),
    }
    if (
        normalized["currency"] != commercial["currency"]
        or normalized["requested_boards"] != commercial["requested_boards"]
    ):
        raise _fail("authorization scope does not match commercial evidence")
    start = normalized["valid_from_unix"]
    end = normalized["expires_at_unix"]
    if end <= start or end - start > _MAXIMUM_VALIDITY_SECONDS:
        raise _fail("authorization validity interval is invalid")
    if start < commercial["offer_valid_from_unix"] or end >= commercial["offer_valid_until_unix"]:
        raise _fail("authorization interval is not contained in the supplier offer")
    return normalized


def _normalize_approval(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_SIGNED_APPROVAL_KEYS):
        raise _fail("signed procurement approval does not match its closed shape")
    evidence = _validate_evidence_projection(value["evidence"])
    scope = _validate_scope(value["authorization_scope"], evidence["commercial"])
    decision = value["decision"]
    if type(decision) is not str or decision not in {"approve", "reject"}:
        raise _fail("signed procurement approval decision is invalid")
    result = {
        "schema_version": value["schema_version"],
        "scope": value["scope"],
        "evidence": evidence,
        "authorization_scope": scope,
        "decision": decision,
        "reason": _text(value["reason"], "procurement approval reason", _MAXIMUM_REASON_BYTES),
        "ticket": _text(value["ticket"], "procurement approval ticket", _MAXIMUM_TICKET_BYTES),
        "signer_id": _text(value["signer_id"], "procurement approval signer", 128, slug=True),
        "algorithm": value["algorithm"],
        "public_key": value["public_key"],
        "signature": value["signature"],
    }
    if (
        type(result["schema_version"]) is not int
        or result["schema_version"] != SIGNED_PROCUREMENT_APPROVAL_SCHEMA_VERSION
        or result["scope"] != SIGNED_PROCUREMENT_APPROVAL_SCOPE
        or result["algorithm"] != "ed25519"
    ):
        raise _fail("signed procurement approval identity is invalid")
    _digest(result["public_key"], "procurement approval public key")
    if type(result["signature"]) is not str or len(result["signature"]) != 128 or any(c not in "0123456789abcdef" for c in result["signature"]):
        raise _fail("procurement approval signature is invalid")
    return result


def _approval_compact(value: Mapping[str, Any]) -> bytes:
    return _compact(_normalize_approval(value))


def _normalize_member(value: Any, signed: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_MEMBER_KEYS):
        raise _fail("procurement authorization member is invalid")
    expected = {
        "signer_id": signed["signer_id"],
        "public_key": signed["public_key"],
        "approval_sha256": _sha256(_approval_compact(signed)),
        "decision": signed["decision"],
        "reason": signed["reason"],
        "ticket": signed["ticket"],
    }
    if not _strict_equal(dict(value), expected):
        raise _fail("procurement authorization member is inconsistent")
    return expected


def _policy_constraints(policy: Mapping[str, Any]) -> Mapping[str, Any]:
    value = policy.get("procurement_authorization_policy")
    if not isinstance(value, Mapping) or set(value) != {
        "minimum_approvals", "currency", "maximum_validity_seconds",
        "maximum_receipt_observation_age_seconds",
        "maximum_component_subtotal_micros", "trusted_keys",
    }:
        raise _fail("retained policy pack lacks a closed procurement policy")
    return value


def _expected_gate_failures(
    evidence: Mapping[str, Any], scope: Mapping[str, Any], policy_pack: Mapping[str, Any],
    approvals: int, rejections: int, evaluated_at: int,
) -> list[str]:
    policy = _policy_constraints(policy_pack)
    commercial = evidence["commercial"]
    failures: list[str] = []
    if not evidence["assembly_supplier_offer_evidence"]["complete"]:
        failures.append("evidence_incomplete")
    if not commercial["covered"] or commercial["component_subtotal_micros"] is None:
        failures.append("supplier_offer_not_covered")
    if evaluated_at < scope["valid_from_unix"] or evaluated_at > scope["expires_at_unix"]:
        failures.append("approval_window_inactive")
    if evaluated_at < commercial["offer_valid_from_unix"] or evaluated_at >= commercial["offer_valid_until_unix"]:
        failures.append("offer_window_inactive")
    fetched = commercial["receipt_fetched_at_unix"]
    if fetched > evaluated_at:
        failures.append("receipt_observation_from_future")
    else:
        age = evaluated_at - fetched
        maximum_age = policy.get("maximum_receipt_observation_age_seconds")
        if type(maximum_age) is not int:
            raise _fail("retained procurement policy observation age is invalid")
        if age > maximum_age:
            failures.append(
                f"receipt_observation_too_old:maximum_seconds={maximum_age}:actual_seconds={age}"
            )
    subtotal = commercial["component_subtotal_micros"]
    if subtotal is not None and subtotal > scope["maximum_component_subtotal_micros"]:
        failures.append(
            "component_subtotal_exceeds_signed_ceiling:maximum_micros="
            f"{scope['maximum_component_subtotal_micros']}:actual_micros={subtotal}"
        )
    policy_ceiling = policy.get("maximum_component_subtotal_micros")
    if type(policy_ceiling) is not int:
        raise _fail("retained procurement policy subtotal ceiling is invalid")
    if scope["maximum_component_subtotal_micros"] > policy_ceiling:
        failures.append(
            "signed_component_subtotal_ceiling_exceeds_policy:maximum_micros="
            f"{policy_ceiling}:actual_micros={scope['maximum_component_subtotal_micros']}"
        )
    duration = scope["expires_at_unix"] - scope["valid_from_unix"]
    maximum_validity = policy.get("maximum_validity_seconds")
    minimum_approvals = policy.get("minimum_approvals")
    if type(maximum_validity) is not int or type(minimum_approvals) is not int:
        raise _fail("retained procurement policy bounds are invalid")
    if duration > maximum_validity:
        failures.append(
            f"procurement_validity_exceeds_policy:maximum_seconds={maximum_validity}:actual_seconds={duration}"
        )
    if approvals < minimum_approvals:
        failures.append(
            f"insufficient_procurement_approvals:required={minimum_approvals}:actual={approvals}"
        )
    if rejections > 0:
        failures.append(f"human_rejection:count={rejections}")
    failures.sort()
    return failures


def _normalize_assessment(
    value: Any,
    request: Mapping[str, Any],
    policy: Mapping[str, Any],
    evaluated_at: int,
    submitted_approvals: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_ASSESSMENT_KEYS):
        raise _fail("cryptographic assessment does not match its closed shape")
    evidence = _validate_evidence_projection(value["evidence"])
    scope = _validate_scope(value["authorization_scope"], evidence["commercial"])
    if not _strict_equal(evidence, request["evidence"]) or not _strict_equal(scope, request["authorization_scope"]):
        raise _fail("cryptographic assessment does not bind the exact request")
    assessment_policy = _ordered_policy_pack(value["policy_pack"])
    if not _strict_equal(assessment_policy, _policy_semantic(policy)):
        raise _fail("cryptographic assessment does not retain the exact policy pack")
    observed_time = _integer(value["evaluated_at_unix"], "assessment timestamp", 0, _MAXIMUM_TIMESTAMP)
    if observed_time != evaluated_at:
        raise _fail("cryptographic assessment timestamp is inconsistent")
    signed_raw = value["signed_approvals"]
    members_raw = value["members"]
    if (
        not isinstance(signed_raw, list) or not 1 <= len(signed_raw) <= MAXIMUM_PROCUREMENT_APPROVALS
        or not isinstance(members_raw, list) or len(members_raw) != len(signed_raw)
    ):
        raise _fail("cryptographic assessment approval inventory is invalid")
    signed = [_normalize_approval(item) for item in signed_raw]
    signer_ids = [item["signer_id"] for item in signed]
    public_keys = [item["public_key"] for item in signed]
    if signer_ids != sorted(signer_ids) or len(set(signer_ids)) != len(signer_ids) or len(set(public_keys)) != len(public_keys):
        raise _fail("cryptographic assessment approvals are not distinct and sorted")
    expected_signed = sorted(
        (copy.deepcopy(dict(item)) for item in submitted_approvals),
        key=lambda item: item["signer_id"],
    )
    if not _strict_equal(signed, expected_signed):
        raise _fail(
            "cryptographic assessment does not retain the exact submitted approvals"
        )
    if any(not _strict_equal(item["evidence"], evidence) or not _strict_equal(item["authorization_scope"], scope) for item in signed):
        raise _fail("cryptographic assessment approval scope is inconsistent")
    members = [_normalize_member(member, item) for member, item in zip(members_raw, signed, strict=True)]
    approvals = sum(item["decision"] == "approve" for item in signed)
    rejections = len(signed) - approvals
    if value["approvals"] != approvals or value["rejections"] != rejections:
        raise _fail("cryptographic assessment counts are inconsistent")
    validation = value["validation"]
    if not isinstance(validation, Mapping) or set(validation) != set(_ASSESSMENT_VALIDATION_KEYS) or any(validation[key] is not True for key in _ASSESSMENT_VALIDATION_KEYS):
        raise _fail("cryptographic assessment validation state is invalid")
    gate_failures = _expected_gate_failures(
        evidence, scope, assessment_policy, approvals, rejections, observed_time
    )
    if value["gate_failures"] != gate_failures:
        raise _fail("cryptographic assessment gate failures are inconsistent")
    satisfied = not gate_failures
    if (
        value["policy_satisfied"] is not satisfied
        or value["status"] != ("policy_satisfied" if satisfied else "not_satisfied")
        or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["scope"] != PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_SCOPE
    ):
        raise _fail("cryptographic assessment outcome is inconsistent")
    result = {
        "schema_version": 1,
        "scope": PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_SCOPE,
        "status": value["status"],
        "policy_satisfied": satisfied,
        "evidence": evidence,
        "authorization_scope": scope,
        # Preserve the TCB's serde-normalized field order for its binding.
        "policy_pack": assessment_policy,
        "evaluated_at_unix": observed_time,
        "approvals": approvals,
        "rejections": rejections,
        "members": members,
        "signed_approvals": signed,
        "gate_failures": gate_failures,
        "validation": {key: True for key in _ASSESSMENT_VALIDATION_KEYS},
    }
    result["binding_sha256"] = _sha256(
        PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BINDING_DOMAIN + _compact(result)
    )
    if value["binding_sha256"] != result["binding_sha256"]:
        raise _fail("cryptographic assessment binding is invalid")
    return result


def _compose_report(assessment: Mapping[str, Any]) -> dict[str, Any]:
    authorized = assessment["policy_satisfied"]
    result: dict[str, Any] = {
        "schema_version": PROCUREMENT_AUTHORIZATION_REPORT_SCHEMA_VERSION,
        "scope": PROCUREMENT_AUTHORIZATION_REPORT_SCOPE,
        "status": "procurement_authorized" if authorized else "not_authorized",
        "procurement_authorized": authorized,
        **{key: False for key in _FALSE_CLAIM_KEYS},
        "evidence": copy.deepcopy(assessment["evidence"]),
        "authorization_scope": copy.deepcopy(assessment["authorization_scope"]),
        "policy_pack": copy.deepcopy(assessment["policy_pack"]),
        "evaluated_at_unix": assessment["evaluated_at_unix"],
        "approvals": assessment["approvals"],
        "rejections": assessment["rejections"],
        "members": copy.deepcopy(assessment["members"]),
        "signed_approvals": copy.deepcopy(assessment["signed_approvals"]),
        "gate_failures": copy.deepcopy(assessment["gate_failures"]),
        "validation": {key: True for key in _REPORT_VALIDATION_KEYS},
    }
    result["binding_sha256"] = _sha256(
        PROCUREMENT_AUTHORIZATION_REPORT_BINDING_DOMAIN + _compact(result)
    )
    return result


def _policy_closed(value: Any, keys: Sequence[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(keys):
        raise _fail(f"{label} does not match its closed shape")
    return value


def _policy_date(value: Any, label: str) -> str:
    if type(value) is not str or len(value) != 10:
        raise _fail(f"{label} is invalid")
    try:
        if datetime.date.fromisoformat(value).isoformat() != value:
            raise ValueError
    except ValueError:
        raise _fail(f"{label} is invalid") from None
    return value


def _policy_description(value: Any, label: str, maximum: int) -> str:
    # Rust requires non-blank bounded UTF-8 but preserves surrounding
    # whitespace byte-for-byte in its typed serialization.
    return _text(value, label, maximum)


def _policy_trusted_keys(
    value: Any, label: str, *, minimum: int,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not minimum <= len(value) <= 100:
        raise _fail(f"{label} is invalid")
    result: list[dict[str, Any]] = []
    for item in value:
        source = _policy_closed(item, ("signer_id", "public_key"), label)
        result.append({
            "signer_id": _text(
                source["signer_id"], f"{label} signer", 128, slug=True
            ),
            "public_key": _digest(source["public_key"], f"{label} public key"),
        })
    return result


def _policy_dfm_profile(value: Any) -> dict[str, Any]:
    keys = (
        "schema_version", "id", "aliases", "revision", "verified_on",
        "description", "source_urls", "rules",
    )
    source = _policy_closed(value, keys, "retained DFM profile")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise _fail("retained DFM profile schema version is invalid")
    aliases = source["aliases"]
    if not isinstance(aliases, list) or len(aliases) > 64:
        raise _fail("retained DFM profile aliases are invalid")
    normalized_aliases = [
        _text(item, "retained DFM profile alias", 128, slug=True)
        for item in aliases
    ]
    if len(set(normalized_aliases)) != len(normalized_aliases):
        raise _fail("retained DFM profile aliases are not unique")
    urls = source["source_urls"]
    if not isinstance(urls, list) or not 1 <= len(urls) <= 32:
        raise _fail("retained DFM profile source URLs are invalid")
    normalized_urls: list[str] = []
    for item in urls:
        text = _text(item, "retained DFM profile source URL", 2048)
        if not text.startswith("https://") or any(character.isspace() for character in text):
            raise _fail("retained DFM profile source URL is invalid")
        normalized_urls.append(text)
    if len(set(normalized_urls)) != len(normalized_urls):
        raise _fail("retained DFM profile source URLs are not unique")
    rule_keys = (
        "minimum_track_width_nm", "minimum_clearance_nm", "minimum_drill_nm",
        "minimum_annular_ring_nm", "minimum_copper_to_edge_nm",
        "board_thickness_nm", "maximum_via_aspect_ratio",
        "minimum_drill_to_drill_nm", "allow_via_in_pad",
        "minimum_trace_angle_deg",
    )
    rules = _policy_closed(source["rules"], rule_keys, "retained DFM rules")
    positive = {
        "minimum_track_width_nm", "minimum_drill_nm",
        "minimum_annular_ring_nm", "board_thickness_nm",
    }
    normalized_rules: dict[str, Any] = {}
    for name in rule_keys:
        if name == "allow_via_in_pad":
            if type(rules[name]) is not bool:
                raise _fail("retained DFM via-in-pad rule is invalid")
            normalized_rules[name] = rules[name]
        elif name == "maximum_via_aspect_ratio":
            normalized_rules[name] = _integer(
                rules[name], "retained DFM via aspect ratio", 1, 100
            )
        elif name == "minimum_trace_angle_deg":
            normalized_rules[name] = _integer(
                rules[name], "retained DFM trace angle", 0, 180
            )
        else:
            normalized_rules[name] = _integer(
                rules[name], f"retained DFM {name}",
                1 if name in positive else 0, 1_000_000_000_000,
            )
    return {
        "schema_version": 1,
        "id": _text(source["id"], "retained DFM profile id", 128, slug=True),
        "aliases": normalized_aliases,
        "revision": _integer(
            source["revision"], "retained DFM profile revision", 1, 2**32 - 1
        ),
        "verified_on": _policy_date(
            source["verified_on"], "retained DFM profile date"
        ),
        "description": _policy_description(
            source["description"], "retained DFM profile description", 1024
        ),
        "source_urls": normalized_urls,
        "rules": normalized_rules,
    }


_ELECTRICAL_SAFETY_RULES = {
    "coverage_incomplete", "duplicate_reference_unit",
    "unannotated_reference", "no_connect_connected",
    "pin_type_no_connect_connected", "multiple_output_drivers",
    "multiple_power_outputs", "power_input_not_driven",
    "invalid_power_metadata", "power_rail_voltage_conflict",
    "power_input_voltage_exceeded", "missing_decoupling_capacitor",
}
_ELECTRICAL_CONFIGURABLE_RULES = {
    "missing_footprint", "unconnected_pin", "input_not_driven",
    "multiple_net_names",
}


def _policy_electrical(value: Any) -> dict[str, Any]:
    source = _policy_closed(
        value, ("schema_version", "id", "rules"),
        "retained electrical policy",
    )
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise _fail("retained electrical policy schema version is invalid")
    policy_id = _text(
        source["id"], "retained electrical policy id",
        MAXIMUM_PROCUREMENT_POLICY_PACK_BYTES,
    )
    rules = source["rules"]
    allowed = _ELECTRICAL_SAFETY_RULES | _ELECTRICAL_CONFIGURABLE_RULES
    if not isinstance(rules, Mapping) or set(rules) - allowed:
        raise _fail("retained electrical policy rules are invalid")
    normalized_rules: dict[str, Any] = {}
    for name in sorted(rules):
        item = _policy_closed(
            rules[name], ("enabled", "severity"),
            "retained electrical rule",
        )
        enabled = item["enabled"]
        severity = item["severity"]
        if (
            type(enabled) is not bool or type(severity) is not str
            or severity not in {"info", "warning", "error"}
        ):
            raise _fail("retained electrical rule setting is invalid")
        if name in _ELECTRICAL_SAFETY_RULES and (
            enabled is not True or severity != "error"
        ):
            raise _fail("retained electrical rule weakens the safety floor")
        normalized_rules[name] = {"enabled": enabled, "severity": severity}
    return {"schema_version": 1, "id": policy_id, "rules": normalized_rules}


def _policy_authorization(
    value: Any, *, procurement: bool,
) -> dict[str, Any]:
    label = "retained procurement policy" if procurement else "retained fabrication policy"
    keys = (
        (
            "minimum_approvals", "currency", "maximum_validity_seconds",
            "maximum_receipt_observation_age_seconds",
            "maximum_component_subtotal_micros", "trusted_keys",
        )
        if procurement else
        ("minimum_approvals", "maximum_validity_seconds", "trusted_keys")
    )
    source = _policy_closed(value, keys, label)
    trusted = _policy_trusted_keys(source["trusted_keys"], label, minimum=2)
    minimum = _integer(source["minimum_approvals"], f"{label} quorum", 2, 100)
    if minimum > len(trusted):
        raise _fail(f"{label} quorum exceeds its trusted key inventory")
    result: dict[str, Any] = {"minimum_approvals": minimum}
    if procurement:
        currency = source["currency"]
        if (
            type(currency) is not str or len(currency) != 3
            or not currency.isascii() or not currency.isalpha()
            or not currency.isupper()
        ):
            raise _fail("retained procurement policy currency is invalid")
        result["currency"] = currency
    result["maximum_validity_seconds"] = _integer(
        source["maximum_validity_seconds"], f"{label} validity", 1,
        _MAXIMUM_VALIDITY_SECONDS,
    )
    if procurement:
        result["maximum_receipt_observation_age_seconds"] = _integer(
            source["maximum_receipt_observation_age_seconds"],
            "retained procurement policy observation age", 1,
            _MAXIMUM_VALIDITY_SECONDS,
        )
        result["maximum_component_subtotal_micros"] = _integer(
            source["maximum_component_subtotal_micros"],
            "retained procurement policy subtotal ceiling", 1,
            _MAXIMUM_MONEY_MICROS,
        )
    result["trusted_keys"] = trusted
    return result


def _ordered_policy_pack(
    value: Any, *, allow_serde_defaults: bool = False,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("retained procurement policy pack is invalid")
    required = (
        "schema_version", "id", "revision", "verified_on", "description",
        "dfm_profile", "electrical_policy", "ai_requirements",
        "require_simulation_evidence", "trusted_approval_keys",
    )
    optional = (
        "trusted_human_escalation_keys", "fabrication_authorization_policy",
        "procurement_authorization_policy",
    )
    if not set(required).issubset(value) or set(value) - set((*required, *optional)):
        raise _fail("retained procurement policy pack does not match its closed shape")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise _fail("retained procurement policy pack identity is invalid")
    requirements = value["ai_requirements"]
    if not isinstance(requirements, list) or not 1 <= len(requirements) <= 1000:
        raise _fail("retained policy AI requirements are invalid")
    normalized_requirements: list[dict[str, Any]] = []
    for item in requirements:
        source = _policy_closed(
            item, ("id", "text"), "retained policy AI requirement"
        )
        normalized_requirements.append({
            "id": _text(
                source["id"], "retained policy AI requirement id", 128,
                slug=True,
            ),
            "text": _policy_description(
                source["text"], "retained policy AI requirement text", 4096
            ),
        })
    require_simulation = value["require_simulation_evidence"]
    if type(require_simulation) is not bool:
        raise _fail("retained policy simulation requirement is invalid")
    result: dict[str, Any] = {
        "schema_version": 1,
        "id": _text(
            value["id"], "retained procurement policy pack id", 128, slug=True
        ),
        "revision": _integer(
            value["revision"], "retained procurement policy pack revision",
            1, 2**32 - 1,
        ),
        "verified_on": _policy_date(
            value["verified_on"], "retained procurement policy pack date"
        ),
        "description": _policy_description(
            value["description"], "retained procurement policy pack description",
            1024,
        ),
        "dfm_profile": _policy_dfm_profile(value["dfm_profile"]),
        "electrical_policy": _policy_electrical(value["electrical_policy"]),
        "ai_requirements": normalized_requirements,
        "require_simulation_evidence": require_simulation,
        "trusted_approval_keys": _policy_trusted_keys(
            value["trusted_approval_keys"], "retained approval trust", minimum=1
        ),
    }
    if "trusted_human_escalation_keys" in value:
        human = value["trusted_human_escalation_keys"]
        if allow_serde_defaults and human in (None, []):
            pass
        else:
            normalized_human = _policy_trusted_keys(
                human, "retained human escalation trust", minimum=0
            )
            if normalized_human:
                result["trusted_human_escalation_keys"] = normalized_human
            elif not allow_serde_defaults:
                # Rust omits an empty vector, so it is never canonical report
                # output even though raw caller policy input may spell it.
                raise _fail("retained policy contains a noncanonical empty trust list")
    if "fabrication_authorization_policy" in value:
        fabrication = value["fabrication_authorization_policy"]
        if allow_serde_defaults and fabrication is None:
            pass
        elif fabrication is None:
            raise _fail("retained policy contains a noncanonical null fabrication policy")
        else:
            result["fabrication_authorization_policy"] = _policy_authorization(
                fabrication, procurement=False
            )
    procurement = value.get("procurement_authorization_policy")
    if procurement is None:
        raise _fail("retained procurement policy pack lacks a procurement policy")
    result["procurement_authorization_policy"] = _policy_authorization(
        procurement, procurement=True
    )
    return result


def _policy_semantic(value: Any) -> dict[str, Any]:
    return _ordered_policy_pack(value, allow_serde_defaults=True)


def _normalize_report(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_REPORT_KEYS):
        raise _fail("procurement authorization report does not match its closed shape")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != PROCUREMENT_AUTHORIZATION_REPORT_SCHEMA_VERSION
        or value["scope"] != PROCUREMENT_AUTHORIZATION_REPORT_SCOPE
        or any(value[key] is not False for key in _FALSE_CLAIM_KEYS)
    ):
        raise _fail("procurement authorization report identity or nonclaims are invalid")
    evidence = _validate_evidence_projection(value["evidence"])
    scope = _validate_scope(value["authorization_scope"], evidence["commercial"])
    policy = _ordered_policy_pack(value["policy_pack"])
    if (
        policy["id"] != evidence["policy_pack"]["id"]
        or policy["revision"] != evidence["policy_pack"]["revision"]
        or _policy_constraints(policy)["currency"] != evidence["commercial"]["currency"]
    ):
        raise _fail("procurement authorization policy binding is inconsistent")
    evaluated = _integer(value["evaluated_at_unix"], "authorization evaluation timestamp", 0, _MAXIMUM_TIMESTAMP)
    signed_raw = value["signed_approvals"]
    members_raw = value["members"]
    if not isinstance(signed_raw, list) or not 1 <= len(signed_raw) <= MAXIMUM_PROCUREMENT_APPROVALS or not isinstance(members_raw, list) or len(members_raw) != len(signed_raw):
        raise _fail("procurement authorization approval inventory is invalid")
    signed = [_normalize_approval(item) for item in signed_raw]
    if any(not _strict_equal(item["evidence"], evidence) or not _strict_equal(item["authorization_scope"], scope) for item in signed):
        raise _fail("procurement authorization signed approvals are not cross-bound")
    signer_ids = [item["signer_id"] for item in signed]
    public_keys = [item["public_key"] for item in signed]
    if signer_ids != sorted(signer_ids) or len(set(signer_ids)) != len(signer_ids) or len(set(public_keys)) != len(public_keys):
        raise _fail("procurement authorization approvals are not distinct and sorted")
    members = [_normalize_member(member, approval) for member, approval in zip(members_raw, signed, strict=True)]
    approvals = sum(item["decision"] == "approve" for item in signed)
    rejections = len(signed) - approvals
    if value["approvals"] != approvals or value["rejections"] != rejections:
        raise _fail("procurement authorization approval counts are inconsistent")
    failures = _expected_gate_failures(evidence, scope, policy, approvals, rejections, evaluated)
    if value["gate_failures"] != failures:
        raise _fail("procurement authorization gate failures are inconsistent")
    authorized = not failures
    if (
        value["procurement_authorized"] is not authorized
        or value["status"] != ("procurement_authorized" if authorized else "not_authorized")
    ):
        raise _fail("procurement authorization outcome is inconsistent")
    validation = value["validation"]
    if not isinstance(validation, Mapping) or set(validation) != set(_REPORT_VALIDATION_KEYS) or any(validation[key] is not True for key in _REPORT_VALIDATION_KEYS):
        raise _fail("procurement authorization validation state is invalid")
    result = {
        "schema_version": PROCUREMENT_AUTHORIZATION_REPORT_SCHEMA_VERSION,
        "scope": PROCUREMENT_AUTHORIZATION_REPORT_SCOPE,
        "status": value["status"],
        "procurement_authorized": authorized,
        **{key: False for key in _FALSE_CLAIM_KEYS},
        "evidence": evidence,
        "authorization_scope": scope,
        "policy_pack": policy,
        "evaluated_at_unix": evaluated,
        "approvals": approvals,
        "rejections": rejections,
        "members": members,
        "signed_approvals": signed,
        "gate_failures": failures,
        "validation": {key: True for key in _REPORT_VALIDATION_KEYS},
    }
    result["binding_sha256"] = _sha256(
        PROCUREMENT_AUTHORIZATION_REPORT_BINDING_DOMAIN + _compact(result)
    )
    if value["binding_sha256"] != result["binding_sha256"]:
        raise _fail("procurement authorization report binding is invalid")
    return result


def _pretty_sorted(value: Mapping[str, Any], maximum: int, label: str) -> bytes:
    try:
        raw = json.dumps(
            dict(value), ensure_ascii=False, allow_nan=False, indent=2,
            sort_keys=True,
        ).encode("utf-8", "strict") + b"\n"
    except Exception:
        raise _fail(f"{label} cannot be serialized") from None
    if not 1 <= len(raw) <= maximum:
        raise _fail(f"{label} exceeds its byte bound")
    return raw


def _capture_replay_value(
    value: Any, *, maximum: int, label: str, caller_root: str,
    renderer: Callable[[Mapping[str, Any]], bytes] | None = None,
) -> tuple[Any, _Captured]:
    if isinstance(value, Mapping):
        snapshot = _snapshot_mapping(value, maximum, label)
        raw = renderer(snapshot) if renderer is not None else _pretty_sorted(snapshot, maximum, label)
        return _parse_object(raw, label), _Captured(None, raw, maximum, label)
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = _bounded_bytes(value, maximum, label)
        return raw, _Captured(None, raw, maximum, label)
    path = _freeze_path(value, f"{label} source", caller_root)
    try:
        raw = read_bytes(path, max_bytes=maximum)
    except Exception:
        raise _fail(f"{label} source is invalid") from None
    if not raw:
        raise _fail(f"{label} source is empty")
    return path, _Captured(path, raw, maximum, label)


def _representation_mode(value: Any, label: str) -> str:
    if isinstance(value, Mapping):
        return "mapping"
    # Bytes-like values deliberately win over an object that also implements
    # PathLike.  This matches every retained-representation public API.
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "bytes"
    if isinstance(value, (str, os.PathLike)):
        return "path"
    raise _fail(f"{label} is invalid")


def _capture_path_only(
    value: Any, *, maximum: int, label: str, root: str,
) -> tuple[str, _Captured]:
    if not isinstance(value, (str, os.PathLike)) or isinstance(
        value, (bytes, bytearray, memoryview)
    ):
        raise _fail(f"{label} must be a path")
    selected, capture = _guard_cwd(
        root, _capture_replay_value, value, maximum=maximum, label=label,
        caller_root=root,
    )
    if not isinstance(selected, str) or capture.path is None:
        raise _fail(f"{label} must be a path")
    return selected, capture


_REPLAY_ORIGINAL_SPECS = (
    ("handoff_bundle", _v1470.MAXIMUM_HANDOFF_BYTES),
    ("board", _v1470.MAXIMUM_BOARD_BYTES),
    ("manufacturing_package", _v1470.MAXIMUM_PACKAGE_BYTES),
    ("retained_board_binding_report", _v1470.MAXIMUM_BOARD_BINDING_REPORT_BYTES),
    ("retained_procurement_intent", _v1470.MAXIMUM_PROCUREMENT_INTENT_BYTES),
    ("catalog_snapshot", _v1470.MAXIMUM_CATALOG_SNAPSHOT_BYTES),
    ("retained_final_cpl", _v1470.MAXIMUM_FINAL_CPL_REPORT_BYTES),
)
_REPLAY_OPTIONAL_PATH_SPECS = (
    ("board_binding_policy", _assembly.MAXIMUM_BOARD_BINDING_POLICY_BYTES),
    ("manufacturing_kicad_project", _assembly.MAXIMUM_PROJECT_BYTES),
    ("manufacturing_kicad_rules", _assembly.MAXIMUM_RULES_BYTES),
    ("manufacturing_fab_profile", _assembly.MAXIMUM_PROFILE_BYTES),
    ("manufacturing_physical_profile", _assembly.MAXIMUM_PROFILE_BYTES),
)
_REPLAY_RETAINED_SPECS = (
    (
        "retained_assembly_evidence", _v1470.MAXIMUM_ASSEMBLY_EVIDENCE_BYTES,
        _assembly.render_assembly_evidence,
    ),
    (
        "retained_supplier_offer_fetch_receipt",
        _v1470.MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES, None,
    ),
    (
        "retained_supplier_offer_coverage",
        _v1470.MAXIMUM_SUPPLIER_OFFER_COVERAGE_BYTES,
        _offer.render_supplier_offer_coverage,
    ),
)


def _pre_capture(
    values: Mapping[str, Any], *, with_approvals: bool,
    retained: Any = _NO_RETAINED,
) -> _PreCaptured:
    """Capture one immutable baseline before clock/command/provider hooks.

    This byte/count-bounded phase intentionally precedes the caller-injected
    aggregate clock.  It preserves v1.470's original-path -> raw-offer ->
    retained path/bytes/Mapping trust order while extending path-first capture
    across the v1.471 evidence, policy, approvals, and retained outer report.
    """

    try:
        root = os.getcwd()
    except Exception:
        raise _fail("caller working directory is invalid") from None
    if type(root) is not str or not os.path.isabs(root):
        raise _fail("caller working directory is invalid")

    replay_values: list[Any] = []
    source_captures: list[_Captured] = []
    replay_options: dict[str, Any] = {}

    # The inherited original closure and raw offer are path-only and captured
    # before any retained/public Mapping traversal.
    for name, maximum in _REPLAY_ORIGINAL_SPECS:
        selected, capture = _capture_path_only(
            values[name], maximum=maximum, label=name.replace("_", " "), root=root
        )
        replay_values.append(selected)
        source_captures.append(capture)
    for name, maximum in _REPLAY_OPTIONAL_PATH_SPECS:
        if values[name] is None:
            replay_options[name] = None
        else:
            selected, capture = _capture_path_only(
                values[name], maximum=maximum, label=name.replace("_", " "),
                root=root,
            )
            replay_options[name] = selected
            source_captures.append(capture)
    offer, offer_capture = _capture_path_only(
        values["supplier_offer"], maximum=_v1470.MAXIMUM_SUPPLIER_OFFER_BYTES,
        label="supplier offer", root=root,
    )
    source_captures.append(offer_capture)

    replay_retained: dict[str, Any] = {}
    replay_retained_captures: dict[str, _Captured] = {}
    classified_replay: list[
        tuple[str, int, Callable[[Mapping[str, Any]], bytes] | None, str, Any]
    ] = []
    for name, maximum, renderer in _REPLAY_RETAINED_SPECS:
        value = values[name]
        classified_replay.append((
            name, maximum, renderer,
            _representation_mode(value, name.replace("_", " ")), value,
        ))

    # Classify top-level public representations without traversing them, then
    # capture all path-backed values before any Mapping hook.
    public_specs = (
        (
            "evidence", values["evidence"],
            _v1470.MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES,
            "assembly supplier-offer evidence",
            _v1470.render_assembly_supplier_offer_evidence,
        ),
        (
            "policy", values["policy_pack"], MAXIMUM_PROCUREMENT_POLICY_PACK_BYTES,
            "organization policy pack", None,
        ),
    )
    classified_public = [
        (name, value, maximum, label, renderer, _representation_mode(value, label))
        for name, value, maximum, label, renderer in public_specs
    ]
    public_captures: dict[str, _Captured] = {}

    for name, maximum, renderer, mode, value in classified_replay:
        if mode == "path":
            selected, capture = _guard_cwd(
                root, _capture_replay_value, value, maximum=maximum,
                label=name.replace("_", " "), caller_root=root,
                renderer=renderer,
            )
            replay_retained[name] = selected
            replay_retained_captures[name] = capture
            source_captures.append(capture)
    for name, value, maximum, label, renderer, mode in classified_public:
        if mode == "path":
            public_captures[name] = _capture_representation(
                value, maximum=maximum, label=label, root=root, renderer=renderer
            )

    initial_paths = [
        capture.path for capture in (
            *source_captures, *public_captures.values()
        ) if capture.path is not None
    ]
    _reject_aliases(initial_paths, "procurement authorization input")
    _verify_path_captures((*source_captures, *public_captures.values()))

    # Copy every mutable bytes-like representation before Mapping traversal.
    for name, maximum, renderer, mode, value in classified_replay:
        if mode == "bytes":
            selected, capture = _guard_cwd(
                root, _capture_replay_value, value, maximum=maximum,
                label=name.replace("_", " "), caller_root=root,
                renderer=renderer,
            )
            replay_retained[name] = selected
            replay_retained_captures[name] = capture
            source_captures.append(capture)
    for name, value, maximum, label, renderer, mode in classified_public:
        if mode == "bytes":
            public_captures[name] = _capture_representation(
                value, maximum=maximum, label=label, root=root, renderer=renderer
            )

    # Retained v1.470 Mappings precede v1.471 Mappings, matching the inherited
    # layer while all earlier mutable inputs are already immutable snapshots.
    for name, maximum, renderer, mode, value in classified_replay:
        if mode == "mapping":
            selected, capture = _guard_cwd(
                root, _capture_replay_value, value, maximum=maximum,
                label=name.replace("_", " "), caller_root=root,
                renderer=renderer,
            )
            replay_retained[name] = selected
            replay_retained_captures[name] = capture
            source_captures.append(capture)
            _verify_path_captures((*source_captures, *public_captures.values()))
    for name, value, maximum, label, renderer, mode in classified_public:
        if mode == "mapping":
            public_captures[name] = _capture_representation(
                value, maximum=maximum, label=label, root=root, renderer=renderer
            )
            _verify_path_captures((*source_captures, *public_captures.values()))

    # The retained outer representation is part of the public immutable
    # baseline too.  Capture path/bytes/Mapping before an approval iterator can
    # mutate it; it remains logically the last retained trust layer.
    retained_capture: _Captured | None = None
    if retained is not _NO_RETAINED:
        retained_capture = _capture_representation(
            retained, maximum=MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES,
            label="retained procurement authorization report", root=root,
            renderer=render_procurement_authorization_report,
        )
        _verify_path_captures((
            *source_captures, *public_captures.values(), retained_capture,
        ))
        _reject_aliases(
            [
                item.path for item in (
                    *source_captures, *public_captures.values(), retained_capture,
                ) if item.path is not None
            ],
            "procurement authorization input",
        )

    approval_captures: list[_Captured] = []
    if with_approvals:
        raw_approvals = values["approvals"]
        if isinstance(
            raw_approvals,
            (str, bytes, bytearray, memoryview, os.PathLike, Mapping),
        ):
            raise _fail("procurement approvals must be a sequence")
        try:
            iterator = _guard_cwd(root, iter, raw_approvals)
        except ProcurementReleaseAuthorizationError:
            raise
        except Exception:
            raise _fail("procurement approvals must be a sequence") from None
        captured_by_position: list[tuple[int, _Captured]] = []
        deferred_mappings: list[tuple[int, Any]] = []
        position = 0
        while True:
            try:
                item = _guard_cwd(root, next, iterator)
            except StopIteration:
                break
            except ProcurementReleaseAuthorizationError:
                raise
            except Exception:
                raise _fail("procurement approval set is invalid") from None
            if position == MAXIMUM_PROCUREMENT_APPROVALS:
                raise _fail("procurement approval set exceeds its count bound")
            mode = _representation_mode(item, "signed procurement approval")
            if mode == "mapping":
                deferred_mappings.append((position, item))
            else:
                captured_by_position.append((position, _capture_representation(
                    item, maximum=MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES,
                    label="signed procurement approval", root=root,
                    renderer=render_signed_procurement_approval,
                )))
            position += 1
            _verify_path_captures((
                *source_captures, *public_captures.values(),
                *((retained_capture,) if retained_capture is not None else ()),
                *(capture for _index, capture in captured_by_position),
            ))
            _reject_aliases(
                [
                    capture.path for capture in (
                        *source_captures, *public_captures.values(),
                        *((retained_capture,) if retained_capture is not None else ()),
                        *(capture for _index, capture in captured_by_position),
                    ) if capture.path is not None
                ],
                "procurement authorization input",
            )
        if position == 0:
            raise _fail("procurement approval set is empty")
        current_paths = [
            capture.path for capture in (
                *source_captures, *public_captures.values(),
                *((retained_capture,) if retained_capture is not None else ()),
                *(capture for _index, capture in captured_by_position),
            ) if capture.path is not None
        ]
        _reject_aliases(current_paths, "procurement authorization input")
        for index, item in deferred_mappings:
            captured_by_position.append((index, _capture_representation(
                item, maximum=MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES,
                label="signed procurement approval", root=root,
                renderer=render_signed_procurement_approval,
            )))
            _verify_path_captures((
                *source_captures, *public_captures.values(),
                *((retained_capture,) if retained_capture is not None else ()),
                *(capture for _position, capture in captured_by_position),
            ))
        approval_captures = [
            capture for _position, capture in sorted(captured_by_position)
        ]
        if sum(len(item.raw) for item in approval_captures) > MAXIMUM_PROCUREMENT_APPROVAL_AGGREGATE_BYTES:
            raise _fail("procurement approvals exceed their aggregate byte bound")

    all_captures = (
        *source_captures, *public_captures.values(), *approval_captures,
        *((retained_capture,) if retained_capture is not None else ()),
    )
    paths = [item.path for item in all_captures if item.path is not None]
    _reject_aliases(paths, "procurement authorization input")
    _verify_path_captures(all_captures)

    def optional_text(value: Any, label: str) -> str | None:
        if value is None:
            return None
        if type(value) is not str:
            raise _fail(f"{label} is invalid")
        return str.__str__(value)

    replay_options.update(
        kicad_cli=values["kicad_cli"],
        manufacturing_fab=optional_text(
            values["manufacturing_fab"], "built-in manufacturing profile"
        ),
        expected_archive_sha256=optional_text(
            values["expected_archive_sha256"], "expected archive digest"
        ),
        expected_bundle_sha256=optional_text(
            values["expected_bundle_sha256"], "expected bundle digest"
        ),
    )
    replay_values.extend((
        replay_retained["retained_assembly_evidence"], offer,
        replay_retained["retained_supplier_offer_fetch_receipt"],
        replay_retained["retained_supplier_offer_coverage"],
    ))
    direct_total = (
        sum(len(item.raw) for item in source_captures)
        + len(public_captures["evidence"].raw)
        + len(public_captures["policy"].raw)
        + sum(len(item.raw) for item in approval_captures)
    )
    if direct_total > MAXIMUM_TOTAL_INPUT_BYTES:
        raise _fail("procurement authorization inputs exceed their aggregate byte bound")
    if (
        retained_capture is not None
        and direct_total + len(retained_capture.raw)
        > MAXIMUM_VALIDATION_TOTAL_INPUT_BYTES
    ):
        raise _fail("procurement authorization validation inputs exceed their aggregate byte bound")
    return _PreCaptured(
        root, tuple(replay_values), replay_options, tuple(source_captures),
        public_captures["evidence"], public_captures["policy"],
        tuple(approval_captures), retained_capture,
    )


def _command_path_candidates(
    command: Sequence[str], root: str,
) -> tuple[str, ...]:
    candidates: list[str] = []
    separators = tuple(
        separator for separator in (os.sep, os.altsep, "/", "\\") if separator
    )
    for argument in command:
        possible: list[str] = []
        if not argument.startswith(("-", "@")):
            possible.append(argument)
        if argument.startswith("@") and len(argument) > 1:
            possible.append(argument[1:])
        if "=" in argument:
            possible.append(argument.split("=", 1)[1])
        # Also catch compact option forms such as ``-I/secret/path``.  The
        # first separator begins the embedded absolute/relative pathname; the
        # exact option token itself is not a meaningful samefile candidate.
        if argument.startswith("-") and "=" not in argument:
            offsets = [
                argument.find(separator) for separator in separators
                if argument.find(separator) >= 0
            ]
            if offsets:
                possible.append(argument[min(offsets):])
                possible.append(argument.lstrip("-"))
                if argument.startswith("-") and not argument.startswith("--"):
                    # Conventional one-letter compact option, e.g.
                    # ``-Irelative/include``.
                    possible.append(argument[2:])
        seen: set[str] = set()
        for item in possible:
            if not item or item in seen:
                continue
            seen.add(item)
            looks_like_path = (
                os.path.isabs(item)
                or any(separator in item for separator in separators)
                or os.path.lexists(os.path.join(root, item))
            )
            if looks_like_path:
                candidates.append(
                    _freeze_path(item, "command path argument", root)
                )
    return tuple(candidates)


def _make_context(values: Mapping[str, Any], captured: _PreCaptured) -> _Context:
    root = captured.root
    last_clock: list[float | None] = [None]

    def guarded_clock() -> float:
        try:
            raw = _guard_cwd(root, values["_clock"])
        except ProcurementReleaseAuthorizationError:
            raise
        except Exception:
            raise _fail("aggregate deadline clock is invalid") from None
        if isinstance(raw, bool) or type(raw) not in {int, float}:
            raise _fail("aggregate deadline clock is invalid")
        numeric = float(raw)
        if not math.isfinite(numeric):
            raise _fail("aggregate deadline clock is invalid")
        previous = last_clock[0]
        if previous is not None and numeric < previous:
            raise _fail("aggregate deadline clock moved backwards")
        last_clock[0] = numeric
        return numeric

    _timeout, deadline = _deadline(values["timeout_seconds"], guarded_clock)
    _verify_path_captures(captured.all_captures)
    try:
        frozen_kicad = _guard_cwd(
            root, _assembly._freeze_path, captured.replay_options["kicad_cli"],
            "manufacturing kicad-cli argument",
        )
    except ProcurementReleaseAuthorizationError:
        raise
    except Exception:
        raise _fail("manufacturing kicad-cli argument is invalid") from None
    _verify_path_captures(captured.all_captures)
    replay_command = _normalize_command(values["pcbex"], "replay pcbex command", root)
    _verify_path_captures(captured.all_captures)
    authorization_command = _normalize_command(
        values["authorization_pcbex"], "authorization pcbex command", root
    )
    _verify_path_captures(captured.all_captures)
    replay_options = dict(captured.replay_options)
    replay_options["kicad_cli"] = frozen_kicad
    command_paths = (
        *_command_path_candidates((frozen_kicad,), root),
        *_command_path_candidates(replay_command, root),
        *_command_path_candidates(authorization_command, root),
    )
    public_paths = tuple(
        item.path for item in captured.all_captures if item.path is not None
    )
    for command_path in command_paths:
        if any(_same_path(command_path, public) for public in public_paths):
            raise _fail("command path must not alias a public input")
    return _Context(
        root, deadline, guarded_clock, replay_command, authorization_command,
        captured.frozen_replay_args, replay_options,
        (*public_paths, *command_paths), captured.source_captures,
    )


def _fresh_replay(
    context: _Context, evidence: Any, requested_boards: int, evaluated_at_unix: int
) -> tuple[dict[str, Any], bytes]:
    remaining = _remaining(context.deadline, context.clock)
    reserve = min(15.0, remaining / 3.0)
    budget = remaining - reserve
    if not math.isfinite(budget) or budget < MINIMUM_TIMEOUT_SECONDS:
        raise _fail("assembly supplier-offer replay has no execution budget")
    # Public validators receive fresh built-in copies so a malicious or simply
    # mutating first replay cannot influence the second replay's input graph.
    replay_args = tuple(copy.deepcopy(item) for item in context.frozen_replay_args)
    replay_options = copy.deepcopy(context.replay_options)
    try:
        result = _v1470.validate_assembly_supplier_offer_evidence(
            evidence,
            *replay_args,
            list(context.replay_command),
            requested_boards=requested_boards,
            evaluated_at_unix=evaluated_at_unix,
            **replay_options,
            timeout_seconds=budget,
            _clock=context.clock,
        )
    except Exception:
        raise _fail("fresh assembly supplier-offer evidence replay failed") from None
    _remaining(context.deadline, context.clock)
    try:
        raw = _v1470.render_assembly_supplier_offer_evidence(result)
    except Exception:
        raise _fail("fresh assembly supplier-offer evidence result is invalid") from None
    normalized = _normalize_evidence(_parse_object(raw, "fresh assembly supplier-offer evidence"))
    if raw != _v1470.render_assembly_supplier_offer_evidence(normalized):
        raise _fail("fresh assembly supplier-offer evidence is not canonical")
    return normalized, raw


def _stage(root: Path, name: str, raw: bytes, maximum: int, label: str) -> Path:
    path = root / name
    try:
        atomic_write_no_clobber(path, raw, max_bytes=maximum)
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail(f"could not stage {label}") from None
    return path


def _verify_staged_inputs(
    inputs: Sequence[tuple[Path, bytes, int]], label: str,
) -> None:
    """Verify immutable TCB inputs without invoking a caller-controlled hook."""

    for path, expected, maximum in inputs:
        try:
            observed = read_bytes(path, max_bytes=maximum)
        except (BoundedIOError, OSError, TypeError, ValueError):
            raise _fail(f"{label} input is invalid") from None
        if observed != expected:
            raise _fail(f"{label} input changed")


def _run_helper(
    context: _Context,
    argv: Sequence[str],
    output: Path,
    maximum: int,
    label: str,
    *,
    private_key: _PrivateKey | None = None,
    pre_exec_guard: Callable[[], None] | None = None,
) -> bytes:
    remaining = _remaining(context.deadline, context.clock)
    reserve = min(15.0, remaining / 3.0)
    cleanup = reserve / 2.0
    process_budget = remaining - reserve
    if process_budget < MINIMUM_TIMEOUT_SECONDS or cleanup <= 0:
        raise _fail(f"{label} has no execution budget")
    try:
        validated = _assembly._validate_argv(list(argv), label)
        if private_key is not None:
            _verify_private_key(private_key)
        # `_remaining` above invokes the injected monotonic clock.  This guard
        # must therefore be the last operation before process spawn that can
        # observe TCB inputs: no caller-controlled hook may run between this
        # exact reread and `run_bounded`.
        if pre_exec_guard is not None:
            pre_exec_guard()
        completed = run_bounded(
            validated,
            timeout_seconds=process_budget,
            cleanup_timeout_seconds=cleanup,
            max_stdout_bytes=MAXIMUM_CHILD_STDOUT_BYTES,
            max_stderr_bytes=MAXIMUM_CHILD_STDERR_BYTES,
        )
        if private_key is not None:
            _verify_private_key(private_key)
    except (BoundedProcessError, Exception) as error:
        # Never relay child output or exception text: signing failures can
        # mention private-key paths/material supplied only to the trusted TCB.
        if isinstance(error, ProcurementReleaseAuthorizationError):
            raise
        raise _fail(f"{label} process failed") from None
    if completed.returncode != 0:
        raise _fail(f"{label} rejected its inputs")
    if completed.stdout or completed.stderr:
        # Hidden helpers are file-output-only; unexpected output is rejected
        # and never reflected through this API.
        raise _fail(f"{label} emitted unexpected process output")
    try:
        raw = read_bytes(output, max_bytes=maximum)
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail(f"{label} output is invalid") from None
    if not raw:
        raise _fail(f"{label} output is empty")
    _remaining(context.deadline, context.clock)
    return raw


def _finalize_public_inputs(
    values: Mapping[str, Any], captured: _PreCaptured,
) -> tuple[_Captured, _Captured, tuple[_Captured, ...], _Captured | None, int, int, str]:
    requested = _integer(
        values["requested_boards"], "requested board quantity", 1,
        _offer.MAXIMUM_REQUESTED_BOARDS,
    )
    selected_evaluated = _integer(
        values["evaluated_at_unix"], "retained evidence evaluation timestamp", 0,
        _MAXIMUM_TIMESTAMP,
    )
    expected = _digest(
        values["expected_policy_pack_canonical_sha256"],
        "expected canonical policy pack digest",
    )
    return (
        captured.evidence, captured.policy, captured.approvals,
        captured.retained, requested, selected_evaluated, expected,
    )


def _freeze_private_key(value: Any, context: _Context) -> _PrivateKey:
    # Deliberately after every public injected representation and the first
    # replay.  This function performs metadata-only stability/alias checks;
    # it never opens, reads, copies, hashes, or stages key material.
    path = _freeze_path(value, "procurement approval private key", context.root)
    before = _path_identity(path, "procurement approval private key")
    for public in context.path_sources:
        if _same_path(path, public):
            raise _fail("procurement approval private key must not alias a public input")
    after = _path_identity(path, "procurement approval private key")
    before_token = _metadata_token(before)
    if before_token != _metadata_token(after):
        raise _fail("procurement approval private key path is unstable")
    return _PrivateKey(path, before_token)


def _verify_private_key(key: _PrivateKey) -> None:
    if _metadata_token(
        _path_identity(key.path, "procurement approval private key")
    ) != key.metadata:
        raise _fail("procurement approval private key path changed")


def _sample_wall_clock(
    values: Mapping[str, Any], context: _Context,
    captures: Sequence[_Captured],
) -> int:
    try:
        observed = _guard_cwd(context.root, values["_wall_clock"])
    except ProcurementReleaseAuthorizationError:
        raise
    except Exception:
        raise _fail("local wall clock is invalid") from None
    _verify_path_captures(captures)
    if isinstance(observed, bool) or type(observed) not in {int, float}:
        raise _fail("local wall clock is invalid")
    try:
        numeric = float(observed)
    except Exception:
        raise _fail("local wall clock is invalid") from None
    if not math.isfinite(numeric) or numeric < 0 or numeric > _MAXIMUM_TIMESTAMP:
        raise _fail("local wall clock is invalid")
    return int(numeric)


def sign_procurement_approval(
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
    policy_pack,
    private_key,
    pcbex="pcbex",
    authorization_pcbex="pcbex",
    *,
    requested_boards: int,
    evaluated_at_unix: int,
    expected_policy_pack_canonical_sha256: str,
    signer_id: str,
    decision: str,
    authorization_id: str,
    challenge: str,
    maximum_component_subtotal_micros: int,
    valid_from_unix: int,
    expires_at_unix: int,
    reason: str,
    ticket: str,
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
    """Freshly replay evidence, then ask the separate trusted TCB to sign."""

    values = locals()
    root = _public_root()
    return _guard_cwd(root, _sign_impl, values)


# Compatibility with the roadmap's longer descriptive spelling.
sign_procurement_release_approval = sign_procurement_approval


def evaluate_procurement_release_authorization(
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
    policy_pack,
    approvals,
    pcbex="pcbex",
    authorization_pcbex="pcbex",
    *,
    requested_boards: int,
    evaluated_at_unix: int,
    expected_policy_pack_canonical_sha256: str,
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
    _wall_clock: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Freshly replay and cryptographically assess approvals at sampled time."""

    values = locals()
    root = _public_root()
    return _guard_cwd(root, _evaluate_impl, _NO_RETAINED, values)


build_procurement_release_authorization = evaluate_procurement_release_authorization
verify_procurement_authorization = evaluate_procurement_release_authorization


def validate_procurement_release_authorization(
    retained_authorization,
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
    policy_pack,
    approvals,
    pcbex="pcbex",
    authorization_pcbex="pcbex",
    *,
    requested_boards: int,
    evaluated_at_unix: int,
    expected_policy_pack_canonical_sha256: str,
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
    """Freshly replay and exactly compare a retained authorization snapshot."""

    values = locals()
    root = _public_root()
    return _guard_cwd(root, _evaluate_impl, retained_authorization, values)


def render_signed_procurement_approval(value: Mapping[str, Any]) -> bytes:
    """Structurally validate and render one canonical signed approval."""

    root = _public_root()
    return _guard_cwd(root, _render_signed_approval_impl, value)


def render_procurement_authorization_report(value: Mapping[str, Any]) -> bytes:
    """Render a structural snapshot; this performs no cryptographic verification."""

    root = _public_root()
    return _guard_cwd(root, _render_report_impl, value)


def signed_procurement_approval_json_schema() -> dict[str, Any]:
    return _signed_approval_schema_impl()


def procurement_authorization_report_json_schema() -> dict[str, Any]:
    return _report_schema_impl()


def _sign_impl(values: Mapping[str, Any]) -> dict[str, Any]:
    captured = _pre_capture(values, with_approvals=False)
    context = _make_context(values, captured)
    evidence_capture, policy_capture, _approvals, _retained, requested, selected_time, expected = (
        _finalize_public_inputs(values, captured)
    )
    first, first_raw = _fresh_replay(
        context, _parse_object(evidence_capture.raw, "assembly supplier-offer evidence"),
        requested, selected_time,
    )
    if first_raw != evidence_capture.raw:
        raise _fail("fresh v1.470 replay did not preserve the retained evidence bytes")
    request_evidence, _policy = _extract_request_evidence(
        first, evidence_capture.raw, policy_capture.raw, expected
    )
    commercial = request_evidence["commercial"]
    scope = _authorization_scope(
        commercial,
        authorization_id=values["authorization_id"],
        challenge=values["challenge"],
        maximum_component_subtotal_micros=values["maximum_component_subtotal_micros"],
        valid_from_unix=values["valid_from_unix"],
        expires_at_unix=values["expires_at_unix"],
    )
    decision = values["decision"]
    if type(decision) is not str or decision not in {"approve", "reject"}:
        raise _fail("procurement approval decision is invalid")
    reason = _text(values["reason"], "procurement approval reason", _MAXIMUM_REASON_BYTES)
    ticket = _text(values["ticket"], "procurement approval ticket", _MAXIMUM_TICKET_BYTES)
    signer = _text(values["signer_id"], "procurement approval signer", 128, slug=True)
    if decision == "approve" and (
        not first["complete"] or not commercial["covered"]
        or commercial["component_subtotal_micros"] is None
    ):
        raise _fail("cannot approve incomplete or uncovered procurement evidence")
    request = _request(request_evidence, scope)
    request_raw = _pretty(
        request, MAXIMUM_PROCUREMENT_RELEASE_REQUEST_BYTES,
        "procurement approval signing request",
    )
    public_captures = (context.source_captures + (evidence_capture, policy_capture))
    _reread(public_captures, context.deadline, context.clock)
    private_key = _freeze_private_key(values["private_key"], context)
    _verify_path_captures(public_captures)
    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-procurement-approval-", dir=_assembly._trusted_temporary_root()
        ) as directory:
            root = Path(directory)
            request_path = _stage(root, "request.json", request_raw, MAXIMUM_PROCUREMENT_RELEASE_REQUEST_BYTES, "procurement request")
            policy_path = _stage(root, "policy.json", policy_capture.raw, MAXIMUM_PROCUREMENT_POLICY_PACK_BYTES, "policy pack")
            output = root / "approval.json"
            staged_inputs = (
                (request_path, request_raw, MAXIMUM_PROCUREMENT_RELEASE_REQUEST_BYTES),
                (policy_path, policy_capture.raw, MAXIMUM_PROCUREMENT_POLICY_PACK_BYTES),
            )
            _verify_staged_inputs(staged_inputs, "trusted signing workspace")
            argv = [
                *context.authorization_command,
                "internal-sign-procurement-approval", str(request_path),
                "--policy-pack", str(policy_path),
                "--expected-policy-pack-canonical-sha256", expected,
                "--private-key", private_key.path,
                "--signer-id", signer,
                "--decision", decision,
                "--reason", reason,
                "--ticket", ticket,
                "--output", str(output),
            ]
            approval_raw = _run_helper(
                context, argv, output, MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES,
                "trusted procurement signing helper", private_key=private_key,
                pre_exec_guard=lambda: _verify_staged_inputs(
                    staged_inputs, "trusted signing workspace"
                ),
            )
            _verify_staged_inputs(staged_inputs, "trusted signing workspace")
    except ProcurementReleaseAuthorizationError:
        raise
    except Exception:
        raise _fail("trusted procurement signing workspace failed") from None
    approval = _normalize_approval(_parse_object(approval_raw, "signed procurement approval"))
    if approval_raw != _pretty(approval, MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES, "signed procurement approval"):
        raise _fail("trusted signing helper output is not canonical")
    if (
        not _strict_equal(approval["evidence"], request["evidence"])
        or not _strict_equal(approval["authorization_scope"], request["authorization_scope"])
        or approval["decision"] != decision or approval["reason"] != reason
        or approval["ticket"] != ticket or approval["signer_id"] != signer
    ):
        raise _fail("trusted signing helper output does not bind the exact request")
    second, second_raw = _fresh_replay(
        context, _parse_object(evidence_capture.raw, "assembly supplier-offer evidence"),
        requested, selected_time,
    )
    if second_raw != evidence_capture.raw or not _strict_equal(second, first):
        raise _fail("second v1.470 replay did not preserve the exact evidence")
    _reread(public_captures, context.deadline, context.clock)
    _remaining(context.deadline, context.clock)
    _verify_private_key(private_key)
    return approval


def _evaluate_impl(retained: Any, values: Mapping[str, Any]) -> dict[str, Any]:
    captured = _pre_capture(
        values, with_approvals=True, retained=retained,
    )
    context = _make_context(values, captured)
    evidence_capture, policy_capture, approvals, retained_capture, requested, selected_time, expected = (
        _finalize_public_inputs(values, captured)
    )
    retained_report: dict[str, Any] | None = None
    if retained_capture is not None:
        retained_report = _normalize_report(
            _parse_object(retained_capture.raw, "retained procurement authorization report")
        )
        if retained_capture.raw != _pretty(
            retained_report, MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES,
            "retained procurement authorization report",
        ):
            raise _fail("retained procurement authorization report is not canonical")
        assessment_time = retained_report["evaluated_at_unix"]
    else:
        assessment_time = None
    first, first_raw = _fresh_replay(
        context, _parse_object(evidence_capture.raw, "assembly supplier-offer evidence"),
        requested, selected_time,
    )
    if first_raw != evidence_capture.raw:
        raise _fail("fresh v1.470 replay did not preserve the retained evidence bytes")
    request_evidence, policy = _extract_request_evidence(
        first, evidence_capture.raw, policy_capture.raw, expected
    )
    normalized_approvals = [
        _normalize_approval(_parse_object(item.raw, "signed procurement approval"))
        for item in approvals
    ]
    if any(item.raw != _pretty(value, MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES, "signed procurement approval") for item, value in zip(approvals, normalized_approvals, strict=True)):
        raise _fail("signed procurement approval is not canonical pretty JSON")
    common_scope = normalized_approvals[0]["authorization_scope"]
    request = _request(request_evidence, common_scope)
    if any(
        not _strict_equal(item["evidence"], request_evidence)
        or not _strict_equal(item["authorization_scope"], common_scope)
        for item in normalized_approvals
    ):
        raise _fail("signed procurement approvals do not bind one exact request")
    if retained_report is not None:
        if (
            not _strict_equal(retained_report["evidence"], request_evidence)
            or not _strict_equal(retained_report["authorization_scope"], common_scope)
        ):
            raise _fail("retained authorization does not bind the exact fresh request")
        evaluated = assessment_time
        assert isinstance(evaluated, int)
    else:
        _reread(
            context.source_captures + (evidence_capture, policy_capture, *approvals),
            context.deadline, context.clock,
        )
        evaluated = None
    request_raw = _pretty(request, MAXIMUM_PROCUREMENT_RELEASE_REQUEST_BYTES, "procurement request")
    public_captures = context.source_captures + (evidence_capture, policy_capture, *approvals)
    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-procurement-authorization-", dir=_assembly._trusted_temporary_root()
        ) as directory:
            root = Path(directory)
            request_path = _stage(root, "request.json", request_raw, MAXIMUM_PROCUREMENT_RELEASE_REQUEST_BYTES, "procurement request")
            policy_path = _stage(root, "policy.json", policy_capture.raw, MAXIMUM_PROCUREMENT_POLICY_PACK_BYTES, "policy pack")
            approval_paths = [
                _stage(root, f"approval-{index:03d}.json", item.raw, MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES, "signed procurement approval")
                for index, item in enumerate(approvals)
            ]
            output = root / "assessment.json"
            staged_inputs = (
                (request_path, request_raw, MAXIMUM_PROCUREMENT_RELEASE_REQUEST_BYTES),
                (policy_path, policy_capture.raw, MAXIMUM_PROCUREMENT_POLICY_PACK_BYTES),
                *(
                    (path, item.raw, MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES)
                    for path, item in zip(approval_paths, approvals, strict=True)
                ),
            )
            _verify_staged_inputs(staged_inputs, "trusted verification workspace")
            if evaluated is None:
                _reread(public_captures, context.deadline, context.clock)
                evaluated = _sample_wall_clock(
                    values, context, public_captures,
                )
            else:
                _reread(public_captures, context.deadline, context.clock)
            argv = [
                *context.authorization_command,
                "internal-verify-procurement-authorization", str(request_path),
                "--policy-pack", str(policy_path),
                "--expected-policy-pack-canonical-sha256", expected,
                *(argument for path in approval_paths for argument in ("--approval", str(path))),
                "--evaluated-at-unix", str(evaluated),
                "--output", str(output),
            ]
            assessment_raw = _run_helper(
                context, argv, output,
                MAXIMUM_PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BYTES,
                "trusted procurement verification helper",
                pre_exec_guard=lambda: _verify_staged_inputs(
                    staged_inputs, "trusted verification workspace"
                ),
            )
            _verify_staged_inputs(staged_inputs, "trusted verification workspace")
    except ProcurementReleaseAuthorizationError:
        raise
    except Exception:
        raise _fail("trusted procurement verification workspace failed") from None
    assessment = _normalize_assessment(
        _parse_object(assessment_raw, "procurement cryptographic assessment"),
        request, policy, evaluated, normalized_approvals,
    )
    if assessment_raw != _pretty(
        assessment, MAXIMUM_PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BYTES,
        "procurement cryptographic assessment",
    ):
        raise _fail("trusted verification helper output is not canonical")
    second, second_raw = _fresh_replay(
        context, _parse_object(evidence_capture.raw, "assembly supplier-offer evidence"),
        requested, selected_time,
    )
    if second_raw != evidence_capture.raw or not _strict_equal(second, first):
        raise _fail("second v1.470 replay did not preserve the exact evidence")
    report = _compose_report(assessment)
    report = _normalize_report(report)
    rendered = _pretty(
        report, MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES,
        "procurement authorization report",
    )
    if retained_capture is not None and retained_capture.raw != rendered:
        raise _fail("retained authorization does not match the exact fresh audit")
    _reread(
        public_captures + ((retained_capture,) if retained_capture is not None else ()),
        context.deadline, context.clock,
    )
    _remaining(context.deadline, context.clock)
    return report


def _render_signed_approval_impl(value: Mapping[str, Any]) -> bytes:
    try:
        snapshot = _snapshot_mapping(
            value, MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES,
            "signed procurement approval",
        )
        normalized = _normalize_approval(snapshot)
        return _pretty(
            normalized, MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES,
            "signed procurement approval",
        )
    except ProcurementReleaseAuthorizationError:
        raise
    except Exception:
        raise _fail("signed procurement approval is invalid") from None


def _render_report_impl(value: Mapping[str, Any]) -> bytes:
    try:
        snapshot = _snapshot_mapping(
            value, MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES,
            "procurement authorization report",
        )
        normalized = _normalize_report(snapshot)
        return _pretty(
            normalized, MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES,
            "procurement authorization report",
        )
    except ProcurementReleaseAuthorizationError:
        raise
    except Exception:
        raise _fail("procurement authorization report is invalid") from None


def _signed_approval_schema_impl() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    signature = {"type": "string", "pattern": "^[0-9a-f]{128}$"}

    def identity(maximum: int) -> dict[str, Any]:
        return {
            "type": "object", "additionalProperties": False,
            "required": ["bytes", "sha256"],
            "properties": {
                "bytes": {
                    "type": "integer", "minimum": 1, "maximum": maximum,
                },
                "sha256": copy.deepcopy(digest),
            },
        }

    assembly = {
        "type": "object", "additionalProperties": False,
        "required": list(_ASSEMBLY_PROJECTION_KEYS),
        "properties": {
            "source": identity(
                _v1470.MAXIMUM_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES
            ),
            "binding_sha256": copy.deepcopy(digest),
            "schema_version": {"const": 1},
            "scope": {"const": _v1470.ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_SCOPE},
            "complete": {"type": "boolean"},
        },
    }
    commercial = {
        "type": "object", "additionalProperties": False,
        "required": list(_COMMERCIAL_KEYS),
        "properties": {
            "requested_boards": {"type": "integer", "minimum": 1, "maximum": _offer.MAXIMUM_REQUESTED_BOARDS},
            "supplier": {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$"},
            "offer_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "covered": {"type": "boolean"},
            "component_subtotal_micros": {"type": ["integer", "null"], "minimum": 0, "maximum": _MAXIMUM_MONEY_MICROS},
            "offer_valid_from_unix": {"type": "integer", "minimum": 0, "maximum": _MAXIMUM_TIMESTAMP},
            "offer_valid_until_unix": {"type": "integer", "minimum": 0, "maximum": _MAXIMUM_TIMESTAMP},
            "receipt_fetched_at_unix": {"type": "integer", "minimum": 0, "maximum": _MAXIMUM_TIMESTAMP},
        },
        "allOf": [{
            "if": {
                "properties": {"covered": {"const": True}},
                "required": ["covered"],
            },
            "then": {
                "properties": {
                    "component_subtotal_micros": {
                        "type": "integer", "minimum": 0,
                        "maximum": _MAXIMUM_MONEY_MICROS,
                    },
                },
            },
            "else": {
                "properties": {
                    "component_subtotal_micros": {"type": "null"},
                },
            },
        }],
    }
    policy_projection = {
        "type": "object", "additionalProperties": False,
        "required": list(_POLICY_PROJECTION_KEYS),
        "properties": {
            "source": identity(MAXIMUM_PROCUREMENT_POLICY_PACK_BYTES),
            "canonical_sha256": copy.deepcopy(digest),
            "id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "revision": {
                "type": "integer", "minimum": 1, "maximum": 2**32 - 1,
            },
        },
    }
    evidence = {
        "type": "object", "additionalProperties": False,
        "required": list(_EVIDENCE_KEYS),
        "properties": {
            "assembly_supplier_offer_evidence": assembly,
            "commercial": commercial,
            "policy_pack": policy_projection,
        },
    }
    scope = {
        "type": "object", "additionalProperties": False,
        "required": list(_AUTHORIZATION_SCOPE_KEYS),
        "properties": {
            "authorization_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "challenge": copy.deepcopy(digest),
            "requested_boards": {"type": "integer", "minimum": 1, "maximum": _offer.MAXIMUM_REQUESTED_BOARDS},
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "maximum_component_subtotal_micros": {"type": "integer", "minimum": 1, "maximum": _MAXIMUM_MONEY_MICROS},
            "valid_from_unix": {"type": "integer", "minimum": 0, "maximum": _MAXIMUM_TIMESTAMP},
            "expires_at_unix": {"type": "integer", "minimum": 0, "maximum": _MAXIMUM_TIMESTAMP},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/signed-procurement-approval-v1.json",
        "title": "pcbex signed exact procurement approval",
        "type": "object", "additionalProperties": False,
        "required": list(_SIGNED_APPROVAL_KEYS),
        "properties": {
            "schema_version": {"const": SIGNED_PROCUREMENT_APPROVAL_SCHEMA_VERSION},
            "scope": {"const": SIGNED_PROCUREMENT_APPROVAL_SCOPE},
            "evidence": evidence,
            "authorization_scope": scope,
            "decision": {"enum": ["approve", "reject"]},
            "reason": {"type": "string", "minLength": 1, "maxLength": _MAXIMUM_REASON_BYTES},
            "ticket": {"type": "string", "minLength": 1, "maxLength": _MAXIMUM_TICKET_BYTES},
            "signer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "algorithm": {"const": "ed25519"},
            "public_key": copy.deepcopy(digest),
            "signature": signature,
        },
        "$comment": "Structural only: cryptographic verification is performed by the separate trusted Rust TCB during evaluate/validate.",
    }


def _organization_policy_pack_schema() -> dict[str, Any]:
    """Closed, recursively bounded schema for the retained typed Rust pack."""

    slug = {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"}
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    revision = {"type": "integer", "minimum": 1, "maximum": 2**32 - 1}
    date = {"type": "string", "format": "date"}

    def trusted_key() -> dict[str, Any]:
        return {
            "type": "object", "additionalProperties": False,
            "required": ["signer_id", "public_key"],
            "properties": {
                "signer_id": copy.deepcopy(slug),
                "public_key": copy.deepcopy(digest),
            },
        }

    positive_nm = {
        "type": "integer", "minimum": 1, "maximum": 1_000_000_000_000,
    }
    nonnegative_nm = {
        "type": "integer", "minimum": 0, "maximum": 1_000_000_000_000,
    }
    dfm_rules = {
        "type": "object", "additionalProperties": False,
        "required": [
            "minimum_track_width_nm", "minimum_clearance_nm",
            "minimum_drill_nm", "minimum_annular_ring_nm",
            "minimum_copper_to_edge_nm", "board_thickness_nm",
            "maximum_via_aspect_ratio", "minimum_drill_to_drill_nm",
            "allow_via_in_pad", "minimum_trace_angle_deg",
        ],
        "properties": {
            "minimum_track_width_nm": copy.deepcopy(positive_nm),
            "minimum_clearance_nm": copy.deepcopy(nonnegative_nm),
            "minimum_drill_nm": copy.deepcopy(positive_nm),
            "minimum_annular_ring_nm": copy.deepcopy(positive_nm),
            "minimum_copper_to_edge_nm": copy.deepcopy(nonnegative_nm),
            "board_thickness_nm": copy.deepcopy(positive_nm),
            "maximum_via_aspect_ratio": {
                "type": "integer", "minimum": 1, "maximum": 100,
            },
            "minimum_drill_to_drill_nm": copy.deepcopy(nonnegative_nm),
            "allow_via_in_pad": {"type": "boolean"},
            "minimum_trace_angle_deg": {
                "type": "integer", "minimum": 0, "maximum": 180,
            },
        },
    }
    dfm_profile = {
        "type": "object", "additionalProperties": False,
        "required": [
            "schema_version", "id", "aliases", "revision", "verified_on",
            "description", "source_urls", "rules",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "id": copy.deepcopy(slug),
            "aliases": {
                "type": "array", "maxItems": 64, "uniqueItems": True,
                "items": copy.deepcopy(slug),
            },
            "revision": copy.deepcopy(revision),
            "verified_on": copy.deepcopy(date),
            "description": {
                "type": "string", "minLength": 1, "maxLength": 1024,
            },
            "source_urls": {
                "type": "array", "minItems": 1, "maxItems": 32,
                "uniqueItems": True,
                "items": {
                    "type": "string", "format": "uri", "pattern": "^https://",
                    "maxLength": 2048,
                },
            },
            "rules": dfm_rules,
        },
    }

    def electrical_rule(*, safety_floor: bool) -> dict[str, Any]:
        return {
            "type": "object", "additionalProperties": False,
            "required": ["enabled", "severity"],
            "properties": {
                "enabled": {"const": True} if safety_floor else {"type": "boolean"},
                "severity": {"const": "error"} if safety_floor else {
                    "enum": ["info", "warning", "error"],
                },
            },
        }

    safety_floor_rules = (
        "coverage_incomplete", "duplicate_reference_unit",
        "unannotated_reference", "no_connect_connected",
        "pin_type_no_connect_connected", "multiple_output_drivers",
        "multiple_power_outputs", "power_input_not_driven",
        "invalid_power_metadata", "power_rail_voltage_conflict",
        "power_input_voltage_exceeded", "missing_decoupling_capacitor",
    )
    configurable_rules = (
        "missing_footprint", "unconnected_pin", "input_not_driven",
        "multiple_net_names",
    )
    electrical_policy = {
        "type": "object", "additionalProperties": False,
        "required": ["schema_version", "id", "rules"],
        "properties": {
            "schema_version": {"const": 1},
            "id": {"type": "string", "minLength": 1},
            "rules": {
                "type": "object", "additionalProperties": False,
                "properties": {
                    **{
                        name: electrical_rule(safety_floor=True)
                        for name in safety_floor_rules
                    },
                    **{
                        name: electrical_rule(safety_floor=False)
                        for name in configurable_rules
                    },
                },
            },
        },
    }

    ai_requirement = {
        "type": "object", "additionalProperties": False,
        "required": ["id", "text"],
        "properties": {
            "id": copy.deepcopy(slug),
            "text": {"type": "string", "minLength": 1, "maxLength": 4096},
        },
    }
    fabrication_policy = {
        "type": "object", "additionalProperties": False,
        "required": [
            "minimum_approvals", "maximum_validity_seconds", "trusted_keys",
        ],
        "properties": {
            "minimum_approvals": {
                "type": "integer", "minimum": 2, "maximum": 100,
            },
            "maximum_validity_seconds": {
                "type": "integer", "minimum": 1,
                "maximum": _MAXIMUM_VALIDITY_SECONDS,
            },
            "trusted_keys": {
                "type": "array", "minItems": 2, "maxItems": 100,
                "items": trusted_key(),
            },
        },
    }
    procurement_policy = {
        "type": "object", "additionalProperties": False,
        "required": [
            "minimum_approvals", "currency", "maximum_validity_seconds",
            "maximum_receipt_observation_age_seconds",
            "maximum_component_subtotal_micros", "trusted_keys",
        ],
        "properties": {
            "minimum_approvals": {
                "type": "integer", "minimum": 2, "maximum": 100,
            },
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "maximum_validity_seconds": {
                "type": "integer", "minimum": 1,
                "maximum": _MAXIMUM_VALIDITY_SECONDS,
            },
            "maximum_receipt_observation_age_seconds": {
                "type": "integer", "minimum": 1,
                "maximum": _MAXIMUM_VALIDITY_SECONDS,
            },
            "maximum_component_subtotal_micros": {
                "type": "integer", "minimum": 1,
                "maximum": _MAXIMUM_MONEY_MICROS,
            },
            "trusted_keys": {
                "type": "array", "minItems": 2, "maxItems": 100,
                "items": trusted_key(),
            },
        },
    }
    required = [
        "schema_version", "id", "revision", "verified_on", "description",
        "dfm_profile", "electrical_policy", "ai_requirements",
        "require_simulation_evidence", "trusted_approval_keys",
        "procurement_authorization_policy",
    ]
    return {
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "schema_version": {"const": 1},
            "id": copy.deepcopy(slug),
            "revision": copy.deepcopy(revision),
            "verified_on": copy.deepcopy(date),
            "description": {
                "type": "string", "minLength": 1, "maxLength": 1024,
            },
            "dfm_profile": dfm_profile,
            "electrical_policy": electrical_policy,
            "ai_requirements": {
                "type": "array", "minItems": 1, "maxItems": 1000,
                "items": ai_requirement,
            },
            "require_simulation_evidence": {"type": "boolean"},
            "trusted_approval_keys": {
                "type": "array", "minItems": 1, "maxItems": 100,
                "items": trusted_key(),
            },
            "trusted_human_escalation_keys": {
                "type": "array", "minItems": 1, "maxItems": 100,
                "items": trusted_key(),
            },
            "fabrication_authorization_policy": fabrication_policy,
            "procurement_authorization_policy": procurement_policy,
        },
    }


def _report_schema_impl() -> dict[str, Any]:
    approval = _signed_approval_schema_impl()
    for key in ("$schema", "$id", "title", "$comment"):
        approval.pop(key, None)
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    evidence = copy.deepcopy(approval["properties"]["evidence"])
    scope = copy.deepcopy(approval["properties"]["authorization_scope"])
    member = {
        "type": "object", "additionalProperties": False,
        "required": list(_MEMBER_KEYS),
        "properties": {
            "signer_id": copy.deepcopy(approval["properties"]["signer_id"]),
            "public_key": copy.deepcopy(digest),
            "approval_sha256": copy.deepcopy(digest),
            "decision": {"enum": ["approve", "reject"]},
            "reason": copy.deepcopy(approval["properties"]["reason"]),
            "ticket": copy.deepcopy(approval["properties"]["ticket"]),
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/procurement-authorization-report-v1.json",
        "title": "pcbex offline exact procurement release authorization",
        "type": "object", "additionalProperties": False,
        "required": list(_REPORT_KEYS),
        "properties": {
            "schema_version": {"const": PROCUREMENT_AUTHORIZATION_REPORT_SCHEMA_VERSION},
            "scope": {"const": PROCUREMENT_AUTHORIZATION_REPORT_SCOPE},
            "status": {"enum": ["procurement_authorized", "not_authorized"]},
            "procurement_authorized": {"type": "boolean"},
            **{key: {"const": False} for key in _FALSE_CLAIM_KEYS},
            "evidence": evidence,
            "authorization_scope": scope,
            "policy_pack": _organization_policy_pack_schema(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0, "maximum": _MAXIMUM_TIMESTAMP},
            "approvals": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PROCUREMENT_APPROVALS},
            "rejections": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PROCUREMENT_APPROVALS},
            "members": {"type": "array", "minItems": 1, "maxItems": MAXIMUM_PROCUREMENT_APPROVALS, "uniqueItems": True, "items": member},
            "signed_approvals": {"type": "array", "minItems": 1, "maxItems": MAXIMUM_PROCUREMENT_APPROVALS, "uniqueItems": True, "items": approval},
            "gate_failures": {"type": "array", "maxItems": 9, "uniqueItems": True, "items": {"type": "string", "minLength": 1, "maxLength": 111}},
            "validation": {
                "type": "object", "additionalProperties": False,
                "required": list(_REPORT_VALIDATION_KEYS),
                "properties": {key: {"const": True} for key in _REPORT_VALIDATION_KEYS},
            },
            "binding_sha256": digest,
        },
        "allOf": [{
            "if": {"properties": {"procurement_authorized": {"const": True}}, "required": ["procurement_authorized"]},
            "then": {"properties": {"status": {"const": "procurement_authorized"}, "gate_failures": {"maxItems": 0}}},
            "else": {"properties": {"status": {"const": "not_authorized"}, "gate_failures": {"minItems": 1}}},
        }],
        "$comment": "A point-in-time structural snapshot, never current authority; rerun evaluation to resample local time and cryptographically reverify approvals.",
    }


__all__ = [
    "ProcurementReleaseAuthorizationError",
    "MAXIMUM_SIGNED_PROCUREMENT_APPROVAL_BYTES",
    "MAXIMUM_PROCUREMENT_AUTHORIZATION_REPORT_BYTES",
    "MAXIMUM_PROCUREMENT_POLICY_PACK_BYTES",
    "MAXIMUM_PROCUREMENT_APPROVAL_AGGREGATE_BYTES",
    "sign_procurement_approval",
    "evaluate_procurement_release_authorization",
    "build_procurement_release_authorization",
    "verify_procurement_authorization",
    "validate_procurement_release_authorization",
    "render_signed_procurement_approval",
    "render_procurement_authorization_report",
    "signed_procurement_approval_json_schema",
    "procurement_authorization_report_json_schema",
]
