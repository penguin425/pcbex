"""Freshly replay a v1.479 release and authenticate its exact factory receipt.

The public boundary requires one policy-pinned Ed25519 attestation over the
exact normalized factory receipt and manufacturing package selected by a
fresh v1.479 executable-pinned release.  The selected native verifier remains
digest-pinned by v1.479 and is invoked without a shell.

The signature authenticates a configured key, not a legal entity, TLS
session, raw HTTP response, live capacity, order placement, or payment.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
import time
from typing import Any

from .bounded_io import BoundedIOError, atomic_write_no_clobber, read_bytes
from .bounded_process import BoundedProcessError, run_bounded
from . import deterministic_pipeline_replay as _pipeline
from . import executable_pinned_fabrication_release as _v1479


SIGNED_FACTORY_RECEIPT_RELEASE_SCHEMA_VERSION = 1
SIGNED_FACTORY_RECEIPT_RELEASE_SCOPE = "fresh-exact-signed-factory-receipt-release-v1"

MAXIMUM_FACTORY_RECEIPT_BYTES = 64 * 1024 * 1024
MAXIMUM_POLICY_PACK_BYTES = 64 * 1024 * 1024
MAXIMUM_SIGNED_FACTORY_RECEIPT_ATTESTATION_BYTES = 1 * 1024 * 1024
MAXIMUM_FACTORY_RECEIPT_ATTESTATION_REPORT_BYTES = 4 * 1024 * 1024
MAXIMUM_SIGNED_FACTORY_RECEIPT_RELEASE_REPORT_BYTES = 16 * 1024 * 1024
MAXIMUM_TOTAL_INPUT_BYTES = (
    _v1479.MAXIMUM_TOTAL_INPUT_BYTES
    + _v1479.MAXIMUM_EXECUTABLE_PINNED_FABRICATION_RELEASE_REPORT_BYTES
    + MAXIMUM_FACTORY_RECEIPT_BYTES
    + MAXIMUM_POLICY_PACK_BYTES
    + MAXIMUM_SIGNED_FACTORY_RECEIPT_ATTESTATION_BYTES
)
DEFAULT_TIMEOUT_SECONDS = 300.0
MAXIMUM_TIMEOUT_SECONDS = 600.0
MINIMUM_TIMEOUT_SECONDS = 1.0
MAXIMUM_CHILD_STDOUT_BYTES = 1 * 1024 * 1024
MAXIMUM_CHILD_STDERR_BYTES = 1 * 1024 * 1024

_REPORT_BINDING_DOMAIN = b"pcbex:fresh-exact-signed-factory-receipt-release:v1\0"
_REPLAY_SUBJECT_DOMAIN = b"pcbex:executable-pinned-fabrication-release-subject:v1\0"
_ATTESTATION_REPORT_BINDING_DOMAIN = b"pcbex:factory-receipt-attestation-report:v1\0"
_HEX = frozenset("0123456789abcdef")
_PROVIDERS = frozenset(("jlcpcb", "pcbway", "generic"))
_NATIVE_FORMATS = frozenset(("elf", "mach-o", "pe"))

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
_VALIDATION_KEYS = (
    "executable_pinned_fabrication_release_replayed_twice",
    "retained_executable_pinned_release_subject_matched",
    "manufacturing_package_cross_bound",
    "factory_receipt_cross_bound",
    "policy_pack_cross_bound",
    "policy_pack_pin_matched",
    "signed_attestation_verified",
    "attestation_verifier_executable_pinned",
    "fabrication_and_receipt_windows_overlap_at_attestation",
    "caller_inputs_unchanged",
)
_REPORT_KEYS = (
    "schema_version",
    "verification_scope",
    "status",
    "executable_pinned_fabrication_release_authorized",
    "factory_receipt_attestation_verified",
    "factory_receipt_authenticity_verified",
    "release_authenticated",
    *_FALSE_KEYS,
    "sources",
    "executable_pinned_fabrication_release",
    "factory_receipt_attestation",
    "attestation_verifier",
    "gate_failures",
    "validation",
    "binding_sha256",
)


class SignedFactoryReceiptReleaseError(ValueError):
    """Stable, path-free failure from the signed-receipt release boundary."""


def _fail(message: str) -> SignedFactoryReceiptReleaseError:
    return SignedFactoryReceiptReleaseError(message)


def _root() -> str:
    try:
        value = os.getcwd()
    except Exception:
        raise _fail("caller working directory is invalid") from None
    if type(value) is not str or not os.path.isabs(value):
        raise _fail("caller working directory is invalid")
    return value


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
                raise _fail(
                    "caller working directory changed and could not be restored"
                ) from None
            raise _fail("caller-controlled hook changed the working directory") from None
    return result


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_digest(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(c in _HEX for c in value)


def _digest(value: Any, label: str) -> str:
    if not _is_digest(value):
        raise _fail(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _strict_int(value: Any, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _fail(f"{label} is outside its integer bound")
    return value


def _text(value: Any, maximum: int, label: str) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or "\0" in value
        or not 1 <= len(value.encode("utf-8")) <= maximum
    ):
        raise _fail(f"{label} is invalid")
    return value


def _slug(value: Any, label: str) -> str:
    value = _text(value, 128, label)
    if (
        not value[0].isalnum()
        or value.lower() != value
        or any(not (character.isascii() and (character.isalnum() or character in ".-")) for character in value)
    ):
        raise _fail(f"{label} is invalid")
    return value


def _exact_keys(value: Mapping[str, Any], keys: Sequence[str], label: str) -> None:
    if set(value) != set(keys):
        raise _fail(f"{label} has an unexpected shape")


def _strict_object(raw: bytes, label: str) -> dict[str, Any]:
    class DuplicateKey(ValueError):
        pass

    def build(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DuplicateKey(key)
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=build)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise _fail(f"{label} is not strict JSON") from None
    if not isinstance(value, dict):
        raise _fail(f"{label} must be an object")
    return value


def _identity(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": _sha(raw)}


def _normalize_identity(value: Any, maximum: int, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail(f"{label} identity is invalid")
    try:
        snapshot = dict(value.items())
    except Exception:
        raise _fail(f"{label} identity is invalid") from None
    _exact_keys(snapshot, ("bytes", "sha256"), f"{label} identity")
    return {
        "bytes": _strict_int(snapshot["bytes"], 1, maximum, f"{label} bytes"),
        "sha256": _digest(snapshot["sha256"], f"{label} digest"),
    }


def _freeze_path(value: Any, label: str, root: str) -> str:
    # This boundary intentionally accepts only built-in strings and pathlib
    # values.  Arbitrary PathLike hooks are outside the public representation
    # contract and therefore cannot run before the initial capture.
    if type(value) is str:
        raw = value
    elif type(value) is type(Path()):
        raw = str(value)
    else:
        raise _fail(f"{label} must be a built-in path representation")
    if not raw or "\0" in raw:
        raise _fail(f"{label} is invalid")
    return os.path.abspath(raw if os.path.isabs(raw) else os.path.join(root, raw))


def _freeze_optional_path(value: Any, label: str, root: str) -> str | None:
    return None if value is None else _freeze_path(value, label, root)


def _freeze_command(value: Any, label: str) -> tuple[str, ...]:
    if type(value) is str:
        command = (value,)
    elif type(value) in {list, tuple}:
        command = tuple(value)
    else:
        raise _fail(f"{label} must be a built-in command representation")
    if len(command) != 1 or type(command[0]) is not str or not command[0] or "\0" in command[0]:
        raise _fail(f"{label} must contain exactly one executable")
    return command


def _capture(path: str, maximum: int, label: str) -> bytes:
    try:
        raw = read_bytes(path, max_bytes=maximum)
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail(f"{label} could not be captured") from None
    if not raw:
        raise _fail(f"{label} is empty")
    return raw


def _reread(captures: Sequence[tuple[str, bytes, int, str]]) -> None:
    for path, expected, maximum, label in captures:
        if _capture(path, maximum, label) != expected:
            raise _fail(f"{label} changed during signed factory receipt replay")


def _clock(root: str, source: Callable[[], float]) -> Callable[[], float]:
    previous: list[float | None] = [None]

    def read() -> float:
        try:
            value = _guard_cwd(root, source)
        except SignedFactoryReceiptReleaseError:
            raise
        except Exception:
            raise _fail("aggregate deadline clock is invalid") from None
        if isinstance(value, bool) or type(value) not in {int, float}:
            raise _fail("aggregate deadline clock is invalid")
        number = float(value)
        if not math.isfinite(number):
            raise _fail("aggregate deadline clock is invalid")
        if previous[0] is not None and number < previous[0]:
            raise _fail("aggregate deadline clock moved backwards")
        previous[0] = number
        return number

    return read


def _deadline(timeout_seconds: Any, clock: Callable[[], float]) -> float:
    if isinstance(timeout_seconds, bool) or type(timeout_seconds) not in {int, float}:
        raise _fail("timeout_seconds must be a finite number between 1 and 600")
    timeout = float(timeout_seconds)
    if not math.isfinite(timeout) or not MINIMUM_TIMEOUT_SECONDS <= timeout <= MAXIMUM_TIMEOUT_SECONDS:
        raise _fail("timeout_seconds must be a finite number between 1 and 600")
    return clock() + timeout


def _remaining(deadline: float, clock: Callable[[], float]) -> float:
    remaining = deadline - clock()
    if not math.isfinite(remaining) or remaining <= 0:
        raise _fail("signed factory receipt replay exceeded its aggregate deadline")
    return remaining


def _normalize_policy_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("factory receipt policy evidence is invalid")
    snapshot = dict(value.items())
    _exact_keys(snapshot, ("source", "canonical_sha256", "id", "revision"), "factory receipt policy evidence")
    return {
        "source": _normalize_identity(snapshot["source"], MAXIMUM_POLICY_PACK_BYTES, "organization policy pack"),
        "canonical_sha256": _digest(snapshot["canonical_sha256"], "canonical policy pack digest"),
        "id": _slug(snapshot["id"], "policy pack id"),
        "revision": _strict_int(snapshot["revision"], 1, (1 << 32) - 1, "policy pack revision"),
    }


def _normalize_evidence(value: Any) -> dict[str, Any]:
    keys = (
        "manufacturing_package", "factory_receipt", "provider", "adapter", "endpoint",
        "response_sha256", "response_bytes", "http_status", "status", "accepted",
        "dfm_passed", "quote_sha256", "policy_pack",
    )
    if not isinstance(value, Mapping):
        raise _fail("factory receipt attestation evidence is invalid")
    snapshot = dict(value.items())
    _exact_keys(snapshot, keys, "factory receipt attestation evidence")
    provider = snapshot["provider"]
    if type(provider) is not str or provider not in _PROVIDERS:
        raise _fail("factory receipt provider is invalid")
    adapter = _text(snapshot["adapter"], 128, "factory receipt adapter")
    expected_adapter = {
        "jlcpcb": "jlcpcb-http-v1",
        "pcbway": "pcbway-http-v1",
        "generic": "generic-factory-http-v1",
    }[provider]
    endpoint = _text(snapshot["endpoint"], 2048, "factory receipt endpoint")
    if adapter != expected_adapter or not endpoint.startswith("https://"):
        raise _fail("factory receipt transport projection is invalid")
    if snapshot["accepted"] is not True or snapshot["dfm_passed"] is not True:
        raise _fail("factory receipt does not retain accepted passing DFM evidence")
    return {
        "manufacturing_package": _normalize_identity(snapshot["manufacturing_package"], 128 * 1024 * 1024, "manufacturing package"),
        "factory_receipt": _normalize_identity(snapshot["factory_receipt"], MAXIMUM_FACTORY_RECEIPT_BYTES, "factory receipt"),
        "provider": provider,
        "adapter": adapter,
        "endpoint": endpoint,
        "response_sha256": _digest(snapshot["response_sha256"], "factory response digest"),
        "response_bytes": _strict_int(snapshot["response_bytes"], 1, 64 * 1024 * 1024, "factory response bytes"),
        "http_status": _strict_int(snapshot["http_status"], 200, 299, "factory HTTP status"),
        "status": _text(snapshot["status"], 4096, "factory receipt status"),
        "accepted": True,
        "dfm_passed": True,
        "quote_sha256": _digest(snapshot["quote_sha256"], "canonical factory quote digest"),
        "policy_pack": _normalize_policy_evidence(snapshot["policy_pack"]),
    }


def _normalize_window(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("factory receipt attestation window is invalid")
    snapshot = dict(value.items())
    _exact_keys(snapshot, ("attestation_id", "challenge", "issued_at_unix", "expires_at_unix"), "factory receipt attestation window")
    issued = _strict_int(snapshot["issued_at_unix"], 0, (1 << 64) - 1, "attestation issuance time")
    expires = _strict_int(snapshot["expires_at_unix"], 1, (1 << 64) - 1, "attestation expiry time")
    if not 1 <= expires - issued <= 604_800:
        raise _fail("factory receipt attestation window is invalid")
    return {
        "attestation_id": _slug(snapshot["attestation_id"], "factory receipt attestation id"),
        "challenge": _digest(snapshot["challenge"], "factory receipt attestation challenge"),
        "issued_at_unix": issued,
        "expires_at_unix": expires,
    }


def _normalize_signed(value: Any) -> dict[str, Any]:
    keys = ("schema_version", "verification_scope", "evidence", "attestation", "factory_id", "algorithm", "public_key", "signature")
    if not isinstance(value, Mapping):
        raise _fail("signed factory receipt attestation is invalid")
    snapshot = dict(value.items())
    _exact_keys(snapshot, keys, "signed factory receipt attestation")
    if snapshot["schema_version"] != 1 or snapshot["verification_scope"] != "policy-pinned-signed-factory-receipt-v1" or snapshot["algorithm"] != "ed25519":
        raise _fail("signed factory receipt attestation header is invalid")
    signature = snapshot["signature"]
    if type(signature) is not str or len(signature) != 128 or any(c not in _HEX for c in signature):
        raise _fail("factory receipt signature is invalid")
    return {
        "schema_version": 1,
        "verification_scope": "policy-pinned-signed-factory-receipt-v1",
        "evidence": _normalize_evidence(snapshot["evidence"]),
        "attestation": _normalize_window(snapshot["attestation"]),
        "factory_id": _slug(snapshot["factory_id"], "factory receipt signer id"),
        "algorithm": "ed25519",
        "public_key": _digest(snapshot["public_key"], "factory receipt public key"),
        "signature": signature,
    }


def _attestation_binding(report: Mapping[str, Any]) -> str:
    payload = {key: report[key] for key in report if key != "binding_sha256"}
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return _sha(_ATTESTATION_REPORT_BINDING_DOMAIN + raw)


def _normalize_attestation_report(value: Any) -> dict[str, Any]:
    keys = (
        "schema_version", "verification_scope", "status", "signature_verified",
        "policy_pack_pin_matched", "attestation_active", "factory_receipt_authenticity_verified",
        "trusted_time_verified", "factory_legal_identity_verified",
        "endpoint_transport_authenticity_verified", "raw_response_authenticity_verified",
        "external_submission_performed", "capacity_reserved", "order_placed",
        "payment_performed", "challenge_one_time_use_enforced", "evidence", "attestation",
        "evaluated_at_unix", "signer", "signed_attestation", "gate_failures", "binding_sha256",
    )
    if not isinstance(value, Mapping):
        raise _fail("factory receipt attestation report is invalid")
    snapshot = dict(value.items())
    _exact_keys(snapshot, keys, "factory receipt attestation report")
    if snapshot["schema_version"] != 1 or snapshot["verification_scope"] != "policy-pinned-signed-factory-receipt-v1":
        raise _fail("factory receipt attestation report header is invalid")
    for key in (
        "signature_verified", "policy_pack_pin_matched"
    ):
        if snapshot[key] is not True:
            raise _fail("factory receipt attestation verifier did not validate its trust boundary")
    for key in (
        "trusted_time_verified", "factory_legal_identity_verified",
        "endpoint_transport_authenticity_verified", "raw_response_authenticity_verified",
        "external_submission_performed", "capacity_reserved", "order_placed",
        "payment_performed", "challenge_one_time_use_enforced",
    ):
        if snapshot[key] is not False:
            raise _fail(f"{key} must remain false")
    evidence = _normalize_evidence(snapshot["evidence"])
    window = _normalize_window(snapshot["attestation"])
    signed = _normalize_signed(snapshot["signed_attestation"])
    signer_value = snapshot["signer"]
    if not isinstance(signer_value, Mapping):
        raise _fail("factory receipt attestation signer is invalid")
    signer_snapshot = dict(signer_value.items())
    _exact_keys(signer_snapshot, ("factory_id", "provider", "public_key", "attestation_sha256"), "factory receipt attestation signer")
    provider = signer_snapshot["provider"]
    if type(provider) is not str or provider not in _PROVIDERS:
        raise _fail("factory receipt signer provider is invalid")
    signer = {
        "factory_id": _slug(signer_snapshot["factory_id"], "factory receipt signer id"),
        "provider": provider,
        "public_key": _digest(signer_snapshot["public_key"], "factory receipt signer public key"),
        "attestation_sha256": _digest(signer_snapshot["attestation_sha256"], "signed factory receipt attestation digest"),
    }
    gates_value = snapshot["gate_failures"]
    if (
        type(gates_value) is not list
        or len(gates_value) > 2
        or any(
            type(item) is not str or not item or len(item.encode("utf-8")) > 256
            for item in gates_value
        )
        or len(set(gates_value)) != len(gates_value)
        or gates_value != sorted(gates_value)
    ):
        raise _fail("factory receipt attestation gate failures are invalid")
    gates = list(gates_value)
    evaluated_at = _strict_int(
        snapshot["evaluated_at_unix"],
        0,
        (1 << 64) - 1,
        "factory receipt evaluation time",
    )
    inactive_gate = "factory_receipt_attestation_window_inactive"
    inactive = (
        evaluated_at < window["issued_at_unix"]
        or evaluated_at > window["expires_at_unix"]
    )
    if (inactive_gate in gates) is not inactive:
        raise _fail("factory receipt attestation window gate is invalid")
    duration = window["expires_at_unix"] - window["issued_at_unix"]
    validity_prefix = "factory_receipt_validity_exceeds_policy:maximum_seconds="
    for gate in gates:
        if gate == inactive_gate:
            continue
        if not gate.startswith(validity_prefix) or ":actual_seconds=" not in gate:
            raise _fail("factory receipt attestation gate failure is unknown")
        maximum_text, actual_text = gate[len(validity_prefix) :].split(
            ":actual_seconds=", 1
        )
        if (
            not maximum_text.isascii()
            or not maximum_text.isdigit()
            or not actual_text.isascii()
            or not actual_text.isdigit()
        ):
            raise _fail("factory receipt attestation validity gate is invalid")
        maximum = int(maximum_text)
        actual = int(actual_text)
        if not 1 <= maximum <= 604_800 or actual != duration or actual <= maximum:
            raise _fail("factory receipt attestation validity gate is invalid")
    active = snapshot["attestation_active"]
    authenticated = snapshot["factory_receipt_authenticity_verified"]
    if type(active) is not bool or authenticated is not active or active != (not gates):
        raise _fail("factory receipt attestation decision is inconsistent")
    if snapshot["status"] != ("receipt_authenticated" if active else "not_authenticated"):
        raise _fail("factory receipt attestation status is inconsistent")
    if signed["evidence"] != evidence or signed["attestation"] != window:
        raise _fail("factory receipt attestation report changed its signed subject")
    if signer["factory_id"] != signed["factory_id"] or signer["provider"] != evidence["provider"] or signer["public_key"] != signed["public_key"]:
        raise _fail("factory receipt attestation signer is inconsistent")
    canonical_signed = json.dumps(signed, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    if signer["attestation_sha256"] != _sha(canonical_signed):
        raise _fail("signed factory receipt attestation digest is invalid")
    normalized: dict[str, Any] = {
        "schema_version": 1,
        "verification_scope": "policy-pinned-signed-factory-receipt-v1",
        "status": "receipt_authenticated" if active else "not_authenticated",
        "signature_verified": True,
        "policy_pack_pin_matched": True,
        "attestation_active": active,
        "factory_receipt_authenticity_verified": active,
        "trusted_time_verified": False,
        "factory_legal_identity_verified": False,
        "endpoint_transport_authenticity_verified": False,
        "raw_response_authenticity_verified": False,
        "external_submission_performed": False,
        "capacity_reserved": False,
        "order_placed": False,
        "payment_performed": False,
        "challenge_one_time_use_enforced": False,
        "evidence": evidence,
        "attestation": window,
        "evaluated_at_unix": evaluated_at,
        "signer": signer,
        "signed_attestation": signed,
        "gate_failures": gates,
        "binding_sha256": _digest(snapshot["binding_sha256"], "factory receipt attestation report binding"),
    }
    if normalized["binding_sha256"] != _attestation_binding(normalized):
        raise _fail("factory receipt attestation report binding is invalid")
    return normalized


def _v1479_subject(report: Mapping[str, Any]) -> str:
    payload = {
        "schema_version": report["schema_version"],
        "verification_scope": report["verification_scope"],
        "sources": report["sources"],
        "executable_pins": report["executable_pins"],
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return _sha(_REPLAY_SUBJECT_DOMAIN + raw)


def _binding(report: Mapping[str, Any]) -> str:
    payload = {key: report[key] for key in _REPORT_KEYS if key != "binding_sha256"}
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return _sha(_REPORT_BINDING_DOMAIN + raw)


def _attestation_inside_fabrication_window(
    nested: Mapping[str, Any], attestation: Mapping[str, Any]
) -> bool:
    scope = nested["routing_drc_fabrication_release"]["fabrication_authorization"][
        "scope"
    ]
    evaluated_at = attestation["evaluated_at_unix"]
    return scope["valid_from_unix"] <= evaluated_at <= scope["expires_at_unix"]


def _normalize_report(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("signed factory receipt release report is invalid")
    snapshot = dict(value.items())
    _exact_keys(snapshot, _REPORT_KEYS, "signed factory receipt release report")
    if snapshot["schema_version"] != SIGNED_FACTORY_RECEIPT_RELEASE_SCHEMA_VERSION or snapshot["verification_scope"] != SIGNED_FACTORY_RECEIPT_RELEASE_SCOPE:
        raise _fail("signed factory receipt release report header is invalid")
    try:
        nested = _v1479._normalize_report(deepcopy(snapshot["executable_pinned_fabrication_release"]))
    except Exception:
        raise _fail("nested executable-pinned fabrication release is invalid") from None
    attestation = _normalize_attestation_report(snapshot["factory_receipt_attestation"])
    sources_value = snapshot["sources"]
    if not isinstance(sources_value, Mapping):
        raise _fail("signed factory receipt release sources are invalid")
    sources_snapshot = dict(sources_value.items())
    _exact_keys(sources_snapshot, ("executable_pinned_fabrication_release_report", "manufacturing_package", "factory_receipt", "policy_pack", "signed_factory_receipt_attestation"), "signed factory receipt release sources")
    retained_value = sources_snapshot["executable_pinned_fabrication_release_report"]
    if not isinstance(retained_value, Mapping):
        raise _fail("retained executable-pinned release source is invalid")
    retained_snapshot = dict(retained_value.items())
    _exact_keys(retained_snapshot, ("bytes", "sha256", "replay_subject_sha256"), "retained executable-pinned release source")
    retained_identity = _normalize_identity(
        {
            "bytes": retained_snapshot["bytes"],
            "sha256": retained_snapshot["sha256"],
        },
        _v1479.MAXIMUM_EXECUTABLE_PINNED_FABRICATION_RELEASE_REPORT_BYTES,
        "retained executable-pinned release report",
    )
    retained = {**retained_identity, "replay_subject_sha256": _digest(retained_snapshot["replay_subject_sha256"], "retained executable-pinned release subject digest")}
    sources = {
        "executable_pinned_fabrication_release_report": retained,
        "manufacturing_package": _normalize_identity(sources_snapshot["manufacturing_package"], 128 * 1024 * 1024, "manufacturing package"),
        "factory_receipt": _normalize_identity(sources_snapshot["factory_receipt"], MAXIMUM_FACTORY_RECEIPT_BYTES, "factory receipt"),
        "policy_pack": _normalize_identity(sources_snapshot["policy_pack"], MAXIMUM_POLICY_PACK_BYTES, "organization policy pack"),
        "signed_factory_receipt_attestation": _normalize_identity(sources_snapshot["signed_factory_receipt_attestation"], MAXIMUM_SIGNED_FACTORY_RECEIPT_ATTESTATION_BYTES, "signed factory receipt attestation"),
    }
    verifier_value = snapshot["attestation_verifier"]
    if not isinstance(verifier_value, Mapping):
        raise _fail("factory receipt attestation verifier pin is invalid")
    verifier_snapshot = dict(verifier_value.items())
    _exact_keys(verifier_snapshot, ("format", "bytes", "sha256", "expected_sha256", "matched"), "factory receipt attestation verifier pin")
    verifier_format = verifier_snapshot["format"]
    if type(verifier_format) is not str or verifier_format not in _NATIVE_FORMATS:
        raise _fail("factory receipt attestation verifier format is invalid")
    verifier = {
        "format": verifier_format,
        "bytes": _strict_int(verifier_snapshot["bytes"], 1, _v1479.MAXIMUM_PINNED_EXECUTABLE_BYTES, "factory receipt attestation verifier bytes"),
        "sha256": _digest(verifier_snapshot["sha256"], "factory receipt attestation verifier digest"),
        "expected_sha256": _digest(verifier_snapshot["expected_sha256"], "expected factory receipt attestation verifier digest"),
        "matched": verifier_snapshot["matched"],
    }
    if verifier["matched"] is not True or verifier["sha256"] != verifier["expected_sha256"] or verifier != nested["executable_pins"]["authorization_pcbex"]:
        raise _fail("factory receipt attestation verifier pin is not cross-bound")
    nested_authorized = nested["release_authorized"] is True
    attested = attestation["factory_receipt_authenticity_verified"] is True
    windows_overlap = _attestation_inside_fabrication_window(nested, attestation)
    authenticated = nested_authorized and attested and windows_overlap
    if snapshot["executable_pinned_fabrication_release_authorized"] is not nested_authorized or snapshot["factory_receipt_attestation_verified"] is not True or snapshot["factory_receipt_authenticity_verified"] is not attested or snapshot["release_authenticated"] is not authenticated:
        raise _fail("signed factory receipt release decision is inconsistent")
    if snapshot["status"] != ("release_authenticated" if authenticated else "not_authenticated"):
        raise _fail("signed factory receipt release status is inconsistent")
    for key in _FALSE_KEYS:
        if snapshot[key] is not False:
            raise _fail(f"{key} must remain false")
    expected_gates = []
    if not nested_authorized:
        expected_gates.append("executable_pinned_fabrication_release_not_authorized")
    if not attested:
        expected_gates.append("factory_receipt_attestation_not_authenticated")
    if nested_authorized and attested and not windows_overlap:
        expected_gates.append(
            "factory_receipt_attestation_outside_fabrication_authorization_window"
        )
    expected_gates.sort()
    if snapshot["gate_failures"] != expected_gates:
        raise _fail("signed factory receipt release gate failures are invalid")
    validation_value = snapshot["validation"]
    if not isinstance(validation_value, Mapping):
        raise _fail("signed factory receipt release validation is invalid")
    validation = dict(validation_value.items())
    if set(validation) != set(_VALIDATION_KEYS) or any(validation[key] is not True for key in _VALIDATION_KEYS):
        raise _fail("signed factory receipt release validation is incomplete")
    if retained["replay_subject_sha256"] != _v1479_subject(nested):
        raise _fail("retained executable-pinned release subject is inconsistent")
    if attestation["evidence"]["manufacturing_package"] != sources["manufacturing_package"] or attestation["evidence"]["factory_receipt"] != sources["factory_receipt"] or attestation["evidence"]["policy_pack"]["source"] != sources["policy_pack"]:
        raise _fail("factory receipt attestation sources are not cross-bound")
    normalized: dict[str, Any] = {
        "schema_version": SIGNED_FACTORY_RECEIPT_RELEASE_SCHEMA_VERSION,
        "verification_scope": SIGNED_FACTORY_RECEIPT_RELEASE_SCOPE,
        "status": "release_authenticated" if authenticated else "not_authenticated",
        "executable_pinned_fabrication_release_authorized": nested_authorized,
        "factory_receipt_attestation_verified": True,
        "factory_receipt_authenticity_verified": attested,
        "release_authenticated": authenticated,
        **{key: False for key in _FALSE_KEYS},
        "sources": sources,
        "executable_pinned_fabrication_release": nested,
        "factory_receipt_attestation": attestation,
        "attestation_verifier": verifier,
        "gate_failures": expected_gates,
        "validation": {key: True for key in _VALIDATION_KEYS},
        "binding_sha256": _digest(snapshot["binding_sha256"], "signed factory receipt release binding"),
    }
    if normalized["binding_sha256"] != _binding(normalized):
        raise _fail("signed factory receipt release binding is invalid")
    return normalized


def _render(report: Mapping[str, Any]) -> bytes:
    normalized = _normalize_report(deepcopy(report))
    try:
        raw = (json.dumps(normalized, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise _fail("signed factory receipt release report cannot be rendered") from None
    if len(raw) > MAXIMUM_SIGNED_FACTORY_RECEIPT_RELEASE_REPORT_BYTES:
        raise _fail("signed factory receipt release report exceeds its byte limit")
    return raw


def _evaluate_impl(values: Mapping[str, Any], root: str) -> dict[str, Any]:
    path_names = (
        "input_board", "routed_board", "convergence_report", "routing_verification_report",
        "manufacturing_package", "routing_manufacturing_handoff_report", "native_kicad_drc_report",
        "routing_drc_manufacturing_handoff_report", "deterministic_pipeline_plan",
        "deterministic_pipeline_report", "routing_drc_fabrication_release_report",
        "executable_pinned_fabrication_release_report", "factory_receipt", "policy_pack",
        "signed_factory_receipt_attestation",
    )
    frozen = {name: _freeze_path(values[name], name.replace("_", " "), root) for name in path_names}
    optional = {
        "kicad_project": _freeze_optional_path(values["kicad_project"], "KiCad project", root),
        "kicad_rules": _freeze_optional_path(values["kicad_rules"], "KiCad rules", root),
        "fab_profile": _freeze_optional_path(values["fab_profile"], "fabrication profile", root),
        "physical_profile": _freeze_optional_path(values["physical_profile"], "physical profile", root),
    }
    if type(values["signed_approvals"]) not in {list, tuple} or not 1 <= len(values["signed_approvals"]) <= 100:
        raise _fail("signed fabrication approvals must be a built-in sequence of 1 to 100 paths")
    approvals = tuple(_freeze_path(item, f"signed fabrication approval {index}", root) for index, item in enumerate(values["signed_approvals"]))
    routing_command = _freeze_command(values["pcbex"], "routing pcbex command")
    authorization_command = _freeze_command(values["authorization_pcbex"], "authorization pcbex command")
    kicad_cli = _freeze_path(values["kicad_cli"], "KiCad CLI", root) if type(values["kicad_cli"]) is type(Path()) or (type(values["kicad_cli"]) is str and (os.sep in values["kicad_cli"] or (os.altsep and os.altsep in values["kicad_cli"]))) else values["kicad_cli"]
    if type(kicad_cli) is not str:
        raise _fail("KiCad CLI must be a built-in path or command name")

    captures = (
        (frozen["factory_receipt"], _capture(frozen["factory_receipt"], MAXIMUM_FACTORY_RECEIPT_BYTES, "factory receipt"), MAXIMUM_FACTORY_RECEIPT_BYTES, "factory receipt"),
        (frozen["policy_pack"], _capture(frozen["policy_pack"], MAXIMUM_POLICY_PACK_BYTES, "organization policy pack"), MAXIMUM_POLICY_PACK_BYTES, "organization policy pack"),
        (frozen["signed_factory_receipt_attestation"], _capture(frozen["signed_factory_receipt_attestation"], MAXIMUM_SIGNED_FACTORY_RECEIPT_ATTESTATION_BYTES, "signed factory receipt attestation"), MAXIMUM_SIGNED_FACTORY_RECEIPT_ATTESTATION_BYTES, "signed factory receipt attestation"),
        (frozen["executable_pinned_fabrication_release_report"], _capture(frozen["executable_pinned_fabrication_release_report"], _v1479.MAXIMUM_EXECUTABLE_PINNED_FABRICATION_RELEASE_REPORT_BYTES, "retained executable-pinned fabrication release report"), _v1479.MAXIMUM_EXECUTABLE_PINNED_FABRICATION_RELEASE_REPORT_BYTES, "retained executable-pinned fabrication release report"),
    )
    if sum(len(item[1]) for item in captures) > (
        MAXIMUM_FACTORY_RECEIPT_BYTES + MAXIMUM_POLICY_PACK_BYTES
        + MAXIMUM_SIGNED_FACTORY_RECEIPT_ATTESTATION_BYTES
        + _v1479.MAXIMUM_EXECUTABLE_PINNED_FABRICATION_RELEASE_REPORT_BYTES
    ):
        raise _fail("signed factory receipt release additions exceed their aggregate bound")
    retained_raw = captures[3][1]
    try:
        retained = _v1479._normalize_report(_strict_object(retained_raw, "retained executable-pinned fabrication release report"))
        if _v1479.render_executable_pinned_fabrication_release_report(retained) != retained_raw:
            raise _fail("retained executable-pinned fabrication release report is not canonical")
    except SignedFactoryReceiptReleaseError:
        raise
    except Exception:
        raise _fail("retained executable-pinned fabrication release report is invalid") from None
    signed_input = _normalize_signed(_strict_object(captures[2][1], "signed factory receipt attestation"))

    guarded_clock = _clock(root, values["_clock"])
    deadline = _deadline(values["timeout_seconds"], guarded_clock)

    def replay(budget: float) -> dict[str, Any]:
        try:
            result = _v1479.evaluate_executable_pinned_fabrication_release(
                frozen["input_board"], frozen["routed_board"], frozen["convergence_report"],
                frozen["routing_verification_report"], frozen["manufacturing_package"],
                frozen["routing_manufacturing_handoff_report"], frozen["native_kicad_drc_report"],
                frozen["routing_drc_manufacturing_handoff_report"], frozen["deterministic_pipeline_plan"],
                frozen["deterministic_pipeline_report"], list(approvals),
                frozen["routing_drc_fabrication_release_report"], values["expected_policy_pack_canonical_sha256"],
                values["expected_routing_pcbex_sha256"], values["expected_authorization_pcbex_sha256"],
                values["expected_kicad_cli_sha256"], list(routing_command), list(authorization_command),
                kicad_cli=kicad_cli, kicad_project=optional["kicad_project"], kicad_rules=optional["kicad_rules"],
                grid_mm=values["grid_mm"], width_mm=values["width_mm"], clearance_mm=values["clearance_mm"],
                via_diameter_mm=values["via_diameter_mm"], via_drill_mm=values["via_drill_mm"],
                bend_cost=values["bend_cost"], via_cost=values["via_cost"], fab=values["fab"],
                fab_profile=optional["fab_profile"], physical_profile=optional["physical_profile"],
                timeout_seconds=budget, _clock=guarded_clock,
            )
            return _v1479._normalize_report(result)
        except SignedFactoryReceiptReleaseError:
            raise
        except Exception:
            raise _fail("fresh executable-pinned fabrication release replay failed") from None

    first_remaining = _remaining(deadline, guarded_clock)
    first = replay(min(_v1479.MAXIMUM_TIMEOUT_SECONDS, max(MINIMUM_TIMEOUT_SECONDS, first_remaining * 0.40)))
    if _v1479_subject(first) != _v1479_subject(retained):
        raise _fail("retained executable-pinned fabrication release subject does not match the fresh replay")
    _reread(captures)

    nested_sources = first["routing_drc_fabrication_release"]["sources"]
    package_raw = _capture(
        frozen["manufacturing_package"],
        128 * 1024 * 1024,
        "manufacturing package",
    )
    package_capture = (
        frozen["manufacturing_package"],
        package_raw,
        128 * 1024 * 1024,
        "manufacturing package",
    )
    stable_captures = (*captures, package_capture)
    if _identity(package_raw) != nested_sources["manufacturing_package"]:
        raise _fail("factory receipt release does not bind the nested manufacturing package")
    if _identity(captures[0][1]) != nested_sources["factory_receipt"] or _identity(captures[1][1]) != nested_sources["policy_pack"]:
        raise _fail("factory receipt release does not bind the nested receipt and policy pack")
    if signed_input["evidence"]["manufacturing_package"] != nested_sources["manufacturing_package"] or signed_input["evidence"]["factory_receipt"] != nested_sources["factory_receipt"] or signed_input["evidence"]["policy_pack"]["source"] != nested_sources["policy_pack"]:
        raise _fail("signed factory receipt attestation does not bind the fresh release sources")
    expected_policy_digest = _digest(values["expected_policy_pack_canonical_sha256"], "expected canonical policy pack digest")
    if signed_input["evidence"]["policy_pack"]["canonical_sha256"] != expected_policy_digest:
        raise _fail("signed factory receipt attestation does not bind the expected policy pack")

    try:
        verifier_path = _v1479._resolve_entrypoint(authorization_command, root, "factory receipt attestation verifier")
        verifier_raw = _capture(verifier_path, _v1479.MAXIMUM_PINNED_EXECUTABLE_BYTES, "factory receipt attestation verifier executable")
        verifier_format = _v1479._native_format(verifier_raw)
    except SignedFactoryReceiptReleaseError:
        raise
    except Exception:
        raise _fail("factory receipt attestation verifier executable is invalid") from None
    expected_verifier = first["executable_pins"]["authorization_pcbex"]
    verifier_pin = {
        "format": verifier_format,
        "bytes": len(verifier_raw),
        "sha256": _sha(verifier_raw),
        "expected_sha256": expected_verifier["expected_sha256"],
        "matched": _sha(verifier_raw) == expected_verifier["expected_sha256"],
    }
    if verifier_pin != expected_verifier:
        raise _fail("factory receipt attestation verifier does not match the v1.479 executable pin")

    with tempfile.TemporaryDirectory(
        prefix="pcbex-signed-receipt-", dir=_pipeline._trusted_temporary_root()
    ) as directory:
        stage = Path(directory).resolve(strict=True)
        staged = (
            (stage / "manufacturing-package.zip", package_raw, 128 * 1024 * 1024),
            (stage / "factory-receipt.json", captures[0][1], MAXIMUM_FACTORY_RECEIPT_BYTES),
            (stage / "policy-pack.json", captures[1][1], MAXIMUM_POLICY_PACK_BYTES),
            (stage / "signed-attestation.json", captures[2][1], MAXIMUM_SIGNED_FACTORY_RECEIPT_ATTESTATION_BYTES),
        )
        for path, raw, maximum in staged:
            try:
                atomic_write_no_clobber(path, raw, max_bytes=maximum)
            except (BoundedIOError, OSError, TypeError, ValueError):
                raise _fail("could not stage factory receipt attestation inputs") from None
        output = stage / "attestation-report.json"
        remaining = _remaining(deadline, guarded_clock)
        helper_total = remaining * 0.35
        cleanup_budget = min(15.0, helper_total / 3.0)
        execution_budget = helper_total - cleanup_budget
        if execution_budget < MINIMUM_TIMEOUT_SECONDS or remaining - helper_total < MINIMUM_TIMEOUT_SECONDS:
            raise _fail("factory receipt attestation verifier has no execution budget")
        _reread(stable_captures)
        if _capture(verifier_path, _v1479.MAXIMUM_PINNED_EXECUTABLE_BYTES, "factory receipt attestation verifier executable") != verifier_raw:
            raise _fail("factory receipt attestation verifier executable changed")
        for path, raw, maximum in staged:
            if _capture(os.fspath(path), maximum, "staged factory receipt attestation input") != raw:
                raise _fail("staged factory receipt attestation input changed")
        argv = [
            verifier_path, "verify-factory-receipt-attestation", os.fspath(staged[0][0]),
            "--factory-receipt", os.fspath(staged[1][0]), "--policy-pack", os.fspath(staged[2][0]),
            "--expected-policy-pack-canonical-sha256", expected_policy_digest,
            "--signed-attestation", os.fspath(staged[3][0]), "--output", os.fspath(output),
        ]
        try:
            completed = run_bounded(
                argv,
                timeout_seconds=execution_budget,
                cleanup_timeout_seconds=max(1.0, cleanup_budget),
                max_stdout_bytes=MAXIMUM_CHILD_STDOUT_BYTES,
                max_stderr_bytes=MAXIMUM_CHILD_STDERR_BYTES,
            )
        except (BoundedProcessError, Exception):
            raise _fail("factory receipt attestation verifier process failed") from None
        if completed.returncode != 0:
            raise _fail("factory receipt attestation verifier rejected its inputs")
        if completed.stdout:
            raise _fail("factory receipt attestation verifier emitted unexpected standard output")
        report_raw = _capture(os.fspath(output), MAXIMUM_FACTORY_RECEIPT_ATTESTATION_REPORT_BYTES, "factory receipt attestation report")
        attestation_report = _normalize_attestation_report(_strict_object(report_raw, "factory receipt attestation report"))
        for path, raw, maximum in staged:
            if _capture(os.fspath(path), maximum, "staged factory receipt attestation input") != raw:
                raise _fail("staged factory receipt attestation input changed")

    second_remaining = _remaining(deadline, guarded_clock)
    second = replay(min(_v1479.MAXIMUM_TIMEOUT_SECONDS, second_remaining))
    _remaining(deadline, guarded_clock)
    if _v1479_subject(second) != _v1479_subject(first) or _v1479_subject(second) != _v1479_subject(retained):
        raise _fail("executable-pinned fabrication release subject changed across receipt verification")
    _reread(stable_captures)
    if _capture(verifier_path, _v1479.MAXIMUM_PINNED_EXECUTABLE_BYTES, "factory receipt attestation verifier executable") != verifier_raw:
        raise _fail("factory receipt attestation verifier executable changed")

    nested_sources = second["routing_drc_fabrication_release"]["sources"]
    evidence = attestation_report["evidence"]
    if evidence["manufacturing_package"] != nested_sources["manufacturing_package"] or evidence["factory_receipt"] != nested_sources["factory_receipt"] or evidence["policy_pack"]["source"] != nested_sources["policy_pack"] or evidence["policy_pack"]["canonical_sha256"] != expected_policy_digest:
        raise _fail("verified factory receipt attestation is not cross-bound to the fresh release")
    if attestation_report["signed_attestation"] != signed_input:
        raise _fail("factory receipt verifier did not retain the exact submitted attestation")

    nested_authorized = second["release_authorized"] is True
    attested = attestation_report["factory_receipt_authenticity_verified"] is True
    windows_overlap = _attestation_inside_fabrication_window(
        second, attestation_report
    )
    authenticated = nested_authorized and attested and windows_overlap
    gates = []
    if not nested_authorized:
        gates.append("executable_pinned_fabrication_release_not_authorized")
    if not attested:
        gates.append("factory_receipt_attestation_not_authenticated")
    if nested_authorized and attested and not windows_overlap:
        gates.append(
            "factory_receipt_attestation_outside_fabrication_authorization_window"
        )
    gates.sort()
    result: dict[str, Any] = {
        "schema_version": SIGNED_FACTORY_RECEIPT_RELEASE_SCHEMA_VERSION,
        "verification_scope": SIGNED_FACTORY_RECEIPT_RELEASE_SCOPE,
        "status": "release_authenticated" if authenticated else "not_authenticated",
        "executable_pinned_fabrication_release_authorized": nested_authorized,
        "factory_receipt_attestation_verified": True,
        "factory_receipt_authenticity_verified": attested,
        "release_authenticated": authenticated,
        **{key: False for key in _FALSE_KEYS},
        "sources": {
            "executable_pinned_fabrication_release_report": {
                **_identity(retained_raw),
                "replay_subject_sha256": _v1479_subject(retained),
            },
            "manufacturing_package": evidence["manufacturing_package"],
            "factory_receipt": _identity(captures[0][1]),
            "policy_pack": _identity(captures[1][1]),
            "signed_factory_receipt_attestation": _identity(captures[2][1]),
        },
        "executable_pinned_fabrication_release": second,
        "factory_receipt_attestation": attestation_report,
        "attestation_verifier": verifier_pin,
        "gate_failures": gates,
        "validation": {key: True for key in _VALIDATION_KEYS},
        "binding_sha256": "",
    }
    result["binding_sha256"] = _binding(result)
    normalized = _normalize_report(result)
    _remaining(deadline, guarded_clock)
    _reread(stable_captures)
    if _capture(verifier_path, _v1479.MAXIMUM_PINNED_EXECUTABLE_BYTES, "factory receipt attestation verifier executable") != verifier_raw:
        raise _fail("factory receipt attestation verifier executable changed")
    return normalized


def evaluate_signed_factory_receipt_release(
    input_board: str | Path,
    routed_board: str | Path,
    convergence_report: str | Path,
    routing_verification_report: str | Path,
    manufacturing_package: str | Path,
    routing_manufacturing_handoff_report: str | Path,
    native_kicad_drc_report: str | Path,
    routing_drc_manufacturing_handoff_report: str | Path,
    deterministic_pipeline_plan: str | Path,
    deterministic_pipeline_report: str | Path,
    signed_approvals: Sequence[str | Path],
    routing_drc_fabrication_release_report: str | Path,
    executable_pinned_fabrication_release_report: str | Path,
    factory_receipt: str | Path,
    policy_pack: str | Path,
    signed_factory_receipt_attestation: str | Path,
    expected_policy_pack_canonical_sha256: str,
    expected_routing_pcbex_sha256: str,
    expected_authorization_pcbex_sha256: str,
    expected_kicad_cli_sha256: str,
    pcbex: str | Sequence[str] = "pcbex",
    authorization_pcbex: str | Sequence[str] = "pcbex",
    *,
    kicad_cli: str | Path = "kicad-cli",
    kicad_project: str | Path | None = None,
    kicad_rules: str | Path | None = None,
    grid_mm: float = 0.25,
    width_mm: float = 0.25,
    clearance_mm: float = 0.20,
    via_diameter_mm: float = 0.60,
    via_drill_mm: float = 0.30,
    bend_cost: int = 5,
    via_cost: int = 20,
    fab: str | None = None,
    fab_profile: str | Path | None = None,
    physical_profile: str | Path | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Freshly reassess v1.479 and authenticate its exact factory receipt."""

    root = _root()
    values = dict(locals())
    try:
        return _guard_cwd(root, _evaluate_impl, values, root)
    except SignedFactoryReceiptReleaseError:
        raise
    except Exception:
        raise _fail("signed factory receipt release inputs are invalid") from None


def render_signed_factory_receipt_release_report(report: Mapping[str, Any]) -> bytes:
    root = _root()
    try:
        return _guard_cwd(root, _render, report)
    except SignedFactoryReceiptReleaseError:
        raise
    except Exception:
        raise _fail("signed factory receipt release report is invalid") from None


def _factory_receipt_attestation_report_schema() -> dict[str, Any]:
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

    policy = {
        "type": "object",
        "additionalProperties": False,
        "required": ["source", "canonical_sha256", "id", "revision"],
        "properties": {
            "source": identity(MAXIMUM_POLICY_PACK_BYTES),
            "canonical_sha256": digest,
            "id": {
                "type": "string",
                "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$",
            },
            "revision": {
                "type": "integer",
                "minimum": 1,
                "maximum": (1 << 32) - 1,
            },
        },
    }
    evidence = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "manufacturing_package",
            "factory_receipt",
            "provider",
            "adapter",
            "endpoint",
            "response_sha256",
            "response_bytes",
            "http_status",
            "status",
            "accepted",
            "dfm_passed",
            "quote_sha256",
            "policy_pack",
        ],
        "properties": {
            "manufacturing_package": identity(128 * 1024 * 1024),
            "factory_receipt": identity(MAXIMUM_FACTORY_RECEIPT_BYTES),
            "provider": {"enum": sorted(_PROVIDERS)},
            "adapter": {"type": "string", "minLength": 1, "maxLength": 128},
            "endpoint": {
                "type": "string",
                "pattern": "^https://",
                "maxLength": 2048,
            },
            "response_sha256": digest,
            "response_bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": 64 * 1024 * 1024,
            },
            "http_status": {"type": "integer", "minimum": 200, "maximum": 299},
            "status": {"type": "string", "minLength": 1, "maxLength": 4096},
            "accepted": {"const": True},
            "dfm_passed": {"const": True},
            "quote_sha256": digest,
            "policy_pack": policy,
        },
    }
    window = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "attestation_id",
            "challenge",
            "issued_at_unix",
            "expires_at_unix",
        ],
        "properties": {
            "attestation_id": {
                "type": "string",
                "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$",
            },
            "challenge": digest,
            "issued_at_unix": {
                "type": "integer",
                "minimum": 0,
                "maximum": (1 << 64) - 1,
            },
            "expires_at_unix": {
                "type": "integer",
                "minimum": 1,
                "maximum": (1 << 64) - 1,
            },
        },
    }
    signed = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "verification_scope",
            "evidence",
            "attestation",
            "factory_id",
            "algorithm",
            "public_key",
            "signature",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "verification_scope": {
                "const": "policy-pinned-signed-factory-receipt-v1"
            },
            "evidence": evidence,
            "attestation": window,
            "factory_id": {
                "type": "string",
                "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$",
            },
            "algorithm": {"const": "ed25519"},
            "public_key": digest,
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"},
        },
    }
    false_claims = (
        "trusted_time_verified",
        "factory_legal_identity_verified",
        "endpoint_transport_authenticity_verified",
        "raw_response_authenticity_verified",
        "external_submission_performed",
        "capacity_reserved",
        "order_placed",
        "payment_performed",
        "challenge_one_time_use_enforced",
    )
    properties: dict[str, Any] = {
        "schema_version": {"const": 1},
        "verification_scope": {
            "const": "policy-pinned-signed-factory-receipt-v1"
        },
        "status": {"enum": ["receipt_authenticated", "not_authenticated"]},
        "signature_verified": {"const": True},
        "policy_pack_pin_matched": {"const": True},
        "attestation_active": {"type": "boolean"},
        "factory_receipt_authenticity_verified": {"type": "boolean"},
        **{key: {"const": False} for key in false_claims},
        "evidence": evidence,
        "attestation": window,
        "evaluated_at_unix": {
            "type": "integer",
            "minimum": 0,
            "maximum": (1 << 64) - 1,
        },
        "signer": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "factory_id",
                "provider",
                "public_key",
                "attestation_sha256",
            ],
            "properties": {
                "factory_id": {
                    "type": "string",
                    "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$",
                },
                "provider": {"enum": sorted(_PROVIDERS)},
                "public_key": digest,
                "attestation_sha256": digest,
            },
        },
        "signed_attestation": signed,
        "gate_failures": {
            "type": "array",
            "maxItems": 2,
            "uniqueItems": True,
            "items": {
                "oneOf": [
                    {"const": "factory_receipt_attestation_window_inactive"},
                    {
                        "type": "string",
                        "pattern": "^factory_receipt_validity_exceeds_policy:maximum_seconds=[0-9]+:actual_seconds=[0-9]+$",
                        "maxLength": 256,
                    },
                ]
            },
        },
        "binding_sha256": digest,
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(properties),
        "properties": properties,
    }


def signed_factory_receipt_release_report_json_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}

    def identity(maximum: int) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["bytes", "sha256"],
            "properties": {
                "bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": maximum,
                },
                "sha256": digest,
            },
        }

    retained = {
        "type": "object", "additionalProperties": False,
        "required": ["bytes", "sha256", "replay_subject_sha256"],
        "properties": {
            **identity(
                _v1479.MAXIMUM_EXECUTABLE_PINNED_FABRICATION_RELEASE_REPORT_BYTES
            )["properties"],
            "replay_subject_sha256": digest,
        },
    }
    sources = {
        "type": "object", "additionalProperties": False,
        "required": ["executable_pinned_fabrication_release_report", "manufacturing_package", "factory_receipt", "policy_pack", "signed_factory_receipt_attestation"],
        "properties": {
            "executable_pinned_fabrication_release_report": retained,
            "manufacturing_package": identity(128 * 1024 * 1024),
            "factory_receipt": identity(MAXIMUM_FACTORY_RECEIPT_BYTES),
            "policy_pack": identity(MAXIMUM_POLICY_PACK_BYTES),
            "signed_factory_receipt_attestation": identity(
                MAXIMUM_SIGNED_FACTORY_RECEIPT_ATTESTATION_BYTES
            ),
        },
    }
    verifier = {
        "type": "object", "additionalProperties": False,
        "required": ["format", "bytes", "sha256", "expected_sha256", "matched"],
        "properties": {"format": {"enum": sorted(_NATIVE_FORMATS)}, "bytes": {"type": "integer", "minimum": 1, "maximum": _v1479.MAXIMUM_PINNED_EXECUTABLE_BYTES}, "sha256": digest, "expected_sha256": digest, "matched": {"const": True}},
    }
    validation = {
        "type": "object", "additionalProperties": False,
        "required": list(_VALIDATION_KEYS),
        "properties": {key: {"const": True} for key in _VALIDATION_KEYS},
    }
    properties: dict[str, Any] = {
        "schema_version": {"const": SIGNED_FACTORY_RECEIPT_RELEASE_SCHEMA_VERSION},
        "verification_scope": {"const": SIGNED_FACTORY_RECEIPT_RELEASE_SCOPE},
        "status": {"enum": ["release_authenticated", "not_authenticated"]},
        "executable_pinned_fabrication_release_authorized": {"type": "boolean"},
        "factory_receipt_attestation_verified": {"const": True},
        "factory_receipt_authenticity_verified": {"type": "boolean"},
        "release_authenticated": {"type": "boolean"},
        **{key: {"const": False} for key in _FALSE_KEYS},
        "sources": sources,
        "executable_pinned_fabrication_release": _v1479.executable_pinned_fabrication_release_report_json_schema(),
        "factory_receipt_attestation": _factory_receipt_attestation_report_schema(),
        "attestation_verifier": verifier,
        "gate_failures": {
            "type": "array",
            "maxItems": 2,
            "uniqueItems": True,
            "items": {
                "enum": [
                    "executable_pinned_fabrication_release_not_authorized",
                    "factory_receipt_attestation_not_authenticated",
                    "factory_receipt_attestation_outside_fabrication_authorization_window",
                ]
            },
        },
        "validation": validation,
        "binding_sha256": digest,
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-receipt-release-v1.json",
        "title": "pcbex fresh exact signed factory receipt release",
        "type": "object", "additionalProperties": False,
        "required": list(_REPORT_KEYS), "properties": properties,
    }


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "MAXIMUM_FACTORY_RECEIPT_ATTESTATION_REPORT_BYTES",
    "MAXIMUM_FACTORY_RECEIPT_BYTES",
    "MAXIMUM_POLICY_PACK_BYTES",
    "MAXIMUM_SIGNED_FACTORY_RECEIPT_ATTESTATION_BYTES",
    "MAXIMUM_SIGNED_FACTORY_RECEIPT_RELEASE_REPORT_BYTES",
    "MAXIMUM_TIMEOUT_SECONDS",
    "MAXIMUM_TOTAL_INPUT_BYTES",
    "SIGNED_FACTORY_RECEIPT_RELEASE_SCHEMA_VERSION",
    "SIGNED_FACTORY_RECEIPT_RELEASE_SCOPE",
    "SignedFactoryReceiptReleaseError",
    "evaluate_signed_factory_receipt_release",
    "render_signed_factory_receipt_release_report",
    "signed_factory_receipt_release_report_json_schema",
]
