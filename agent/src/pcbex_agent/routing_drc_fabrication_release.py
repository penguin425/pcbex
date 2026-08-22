"""Freshly compose routing/DRC readiness with fabrication authorization.

This module owns only the outer composition.  The v1.477 Python boundary
remains authoritative for routing, manufacturing-package, and native-DRC
replay.  The selected Rust ``pcbex`` binary remains authoritative for the
factory-bound deterministic pipeline, policy, Ed25519 signatures, quorum, and
current authorization window.
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
from . import manufacturing_replay as _manufacturing
from . import routing_drc_manufacturing_handoff as _routing


ROUTING_DRC_FABRICATION_RELEASE_SCHEMA_VERSION = 1
ROUTING_DRC_FABRICATION_RELEASE_SCOPE = (
    "fresh-exact-routing-drc-fabrication-release-v1"
)

MAXIMUM_ROUTING_DRC_FABRICATION_RELEASE_REPORT_BYTES = 4 * 1024 * 1024
MAXIMUM_FABRICATION_AUTHORIZATION_REPORT_BYTES = 128 * 1024 * 1024
MAXIMUM_SIGNED_FABRICATION_APPROVAL_BYTES = 1024 * 1024
MAXIMUM_FABRICATION_APPROVALS = 100
MAXIMUM_FABRICATION_APPROVAL_AGGREGATE_BYTES = 100 * 1024 * 1024
MAXIMUM_TOTAL_INPUT_BYTES = 1469 * 1024 * 1024
MAXIMUM_CHILD_STDOUT_BYTES = 64 * 1024
MAXIMUM_CHILD_STDERR_BYTES = 1024 * 1024
MAXIMUM_TIMEOUT_SECONDS = 600.0
DEFAULT_TIMEOUT_SECONDS = 300.0

_REPORT_BINDING_DOMAIN = (
    b"pcbex:fresh-exact-routing-drc-fabrication-release:v1\0"
)
_RETAINED_REPLAY_SUBJECT_DOMAIN = (
    b"pcbex:routing-drc-fabrication-release:retained-replay-subject:v1\0"
)
_HEX = frozenset("0123456789abcdef")

_REPORT_KEYS = (
    "schema_version",
    "verification_scope",
    "status",
    "routing_drc_manufacturing_ready",
    "fabrication_authorized",
    "release_authorized",
    "source_authenticity_verified",
    "toolchain_authenticity_verified",
    "policy_pack_authenticity_verified",
    "factory_receipt_authenticity_verified",
    "manufacturability_verified",
    "external_submission_performed",
    "capacity_reserved",
    "order_placed",
    "payment_performed",
    "challenge_one_time_use_enforced",
    "sources",
    "routing_drc_manufacturing",
    "fabrication_authorization",
    "policy_pin",
    "gate_failures",
    "validation",
    "binding_sha256",
)
_SOURCE_KEYS = (
    "routing_drc_manufacturing_handoff_report",
    "deterministic_pipeline_plan",
    "deterministic_pipeline_report",
    "manufacturing_package",
    "factory_receipt",
    "policy_pack",
    "signed_approvals",
)
_ROUTING_PROJECTION_KEYS = (
    "retained_report",
    "schema_version",
    "verification_scope",
    "status",
    "ready",
    "native_kicad_drc_verified",
    "manufacturing_package",
    "binding_sha256",
)
_FABRICATION_PROJECTION_KEYS = (
    "report",
    "schema_version",
    "status",
    "fabrication_authorized",
    "evaluated_at_unix",
    "approvals",
    "rejections",
    "gate_failures",
    "scope",
    "pipeline",
    "manufacturing_package",
    "factory_receipt",
    "policy_pack",
    "quote_authenticity_verified",
    "challenge_one_time_use_enforced",
)
_SCOPE_KEYS = (
    "authorization_id",
    "challenge",
    "quantity",
    "currency",
    "maximum_total_minor_units",
    "valid_from_unix",
    "expires_at_unix",
)
_PIPELINE_KEYS = (
    "plan_source",
    "plan_sha256",
    "retained_report",
    "run_sha256",
)
_POLICY_KEYS = ("source", "canonical_sha256", "id", "revision")
_PIN_KEYS = ("expected_canonical_sha256", "matched")
_VALIDATION_KEYS = (
    "source_closures_captured",
    "routing_drc_manufacturing_replayed",
    "retained_routing_drc_manufacturing_exact",
    "fabrication_authorization_replayed",
    "manufacturing_package_cross_bound",
    "policy_pack_pin_matched",
    "staged_inputs_unchanged",
    "caller_inputs_unchanged",
)
_FABRICATION_REPORT_KEYS = (
    "schema_version",
    "status",
    "evidence",
    "scope",
    "policy_pack",
    "evaluated_at_unix",
    "approvals",
    "rejections",
    "members",
    "signed_approvals",
    "fabrication_authorized",
    "gate_failures",
    "challenge_one_time_use_enforced",
)
_FABRICATION_SUMMARY_KEYS = (
    "schema_version",
    "status",
    "fabrication_authorized",
    "authorization_id",
    "challenge",
    "quantity",
    "currency",
    "maximum_total_minor_units",
    "valid_from_unix",
    "expires_at_unix",
    "evaluated_at_unix",
    "approvals",
    "rejections",
    "gate_failure_count",
    "plan_sha256",
    "run_sha256",
    "manufacturing_package_sha256",
    "factory_receipt_sha256",
    "policy_pack_sha256",
    "quote_authenticity_verified",
    "challenge_one_time_use_enforced",
    "report_bytes",
    "report_sha256",
)


class RoutingDrcFabricationReleaseError(ValueError):
    """Stable, path-free failure from the release composition boundary."""


def _fail(message: str) -> RoutingDrcFabricationReleaseError:
    return RoutingDrcFabricationReleaseError(message)


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
            raise _fail("caller-controlled hook changed the working directory")
    return result


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": _sha256(raw)}


def _is_digest(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _digest(value: Any, label: str) -> str:
    if not _is_digest(value):
        raise _fail(f"{label} is not a lowercase SHA-256")
    return value


def _strict_object(raw: bytes, label: str) -> dict[str, Any]:
    class DuplicateKey(ValueError):
        pass

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise DuplicateKey(key)
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(value)

    try:
        value = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except (DuplicateKey, UnicodeError, ValueError, TypeError, RecursionError):
        raise _fail(f"{label} is invalid JSON") from None
    if not isinstance(value, dict):
        raise _fail(f"{label} must be a JSON object")
    return value


def _exact_keys(value: Mapping[str, Any], keys: Sequence[str], label: str) -> None:
    if set(value) != set(keys):
        raise _fail(f"{label} has an invalid closed shape")


def _strict_int(value: Any, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise _fail(f"{label} is invalid")
    return value


def _strict_text(value: Any, minimum: int, maximum: int, label: str) -> str:
    if type(value) is not str or "\0" in value:
        raise _fail(f"{label} is invalid")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise _fail(f"{label} is invalid") from None
    if size < minimum or size > maximum:
        raise _fail(f"{label} is invalid")
    return value


def _normalize_identity(value: Any, maximum: int, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail(f"{label} identity is invalid")
    _exact_keys(value, ("bytes", "sha256"), f"{label} identity")
    return {
        "bytes": _strict_int(value.get("bytes"), 1, maximum, f"{label} byte count"),
        "sha256": _digest(value.get("sha256"), f"{label} digest"),
    }


def _freeze_path(value: str | os.PathLike[str], label: str, root: str) -> str:
    try:
        rendered = _guard_cwd(root, os.fspath, value)
        if type(rendered) is not str or not rendered:
            raise TypeError
        drive, _tail = os.path.splitdrive(rendered)
        if drive and not os.path.isabs(rendered):
            raise ValueError
        return os.path.abspath(os.path.join(root, rendered))
    except RoutingDrcFabricationReleaseError:
        raise
    except Exception:
        raise _fail(f"{label} path is invalid") from None


def _read_source(path: str | Path, maximum: int, label: str) -> bytes:
    try:
        raw = read_bytes(path, max_bytes=maximum)
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail(f"{label} source is invalid") from None
    if not raw:
        raise _fail(f"{label} source is empty")
    return raw


def _same_path(left: str, right: str) -> bool:
    try:
        if os.path.samefile(left, right):
            return True
    except OSError:
        pass
    try:
        left_key = os.path.normcase(os.path.realpath(left)).casefold()
        right_key = os.path.normcase(os.path.realpath(right)).casefold()
    except (OSError, TypeError, ValueError):
        raise _fail("release input path identity is invalid") from None
    return left_key == right_key


def _reject_aliases(paths: Sequence[tuple[str, str]]) -> None:
    for index, (left_label, left) in enumerate(paths):
        for right_label, right in paths[index + 1 :]:
            if _same_path(left, right):
                raise _fail(f"{left_label} and {right_label} must not alias")


def _reread(paths: Sequence[tuple[str | Path, bytes, int, str]]) -> None:
    for path, expected, maximum, label in paths:
        if _read_source(path, maximum, label) != expected:
            raise _fail(f"{label} source changed during release verification")


def _verify_staged(paths: Sequence[tuple[Path, bytes, int, str]]) -> None:
    for path, expected, maximum, label in paths:
        if _read_source(path, maximum, label) != expected:
            raise _fail("trusted release workspace input changed")


def _command_path_candidates(command: Sequence[str], root: str) -> tuple[str, ...]:
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
        if argument.startswith("-") and "=" not in argument:
            offsets = [
                argument.find(separator)
                for separator in separators
                if argument.find(separator) >= 0
            ]
            if offsets:
                possible.append(argument[min(offsets) :])
                possible.append(argument.lstrip("-"))
                if not argument.startswith("--"):
                    possible.append(argument[2:])
        for item in dict.fromkeys(possible):
            if not item:
                continue
            if (
                os.path.isabs(item)
                or any(separator in item for separator in separators)
                or os.path.lexists(os.path.join(root, item))
            ):
                candidates.append(_freeze_path(item, "command argument", root))
    return tuple(candidates)


def _guarded_clock(
    root: str, clock: Callable[[], float]
) -> tuple[Callable[[], float], list[float | None]]:
    last: list[float | None] = [None]

    def sample() -> float:
        try:
            raw = _guard_cwd(root, clock)
        except RoutingDrcFabricationReleaseError:
            raise
        except Exception:
            raise _fail("aggregate deadline clock is invalid") from None
        if isinstance(raw, bool) or type(raw) not in {int, float}:
            raise _fail("aggregate deadline clock is invalid")
        value = float(raw)
        if not math.isfinite(value):
            raise _fail("aggregate deadline clock is invalid")
        if last[0] is not None and value < last[0]:
            raise _fail("aggregate deadline clock moved backwards")
        last[0] = value
        return value

    return sample, last


def _deadline(timeout_seconds: float, clock: Callable[[], float]) -> float:
    if isinstance(timeout_seconds, bool) or type(timeout_seconds) not in {int, float}:
        raise _fail("aggregate timeout is invalid")
    timeout = float(timeout_seconds)
    start = clock()
    if not math.isfinite(timeout) or timeout <= 0 or timeout > MAXIMUM_TIMEOUT_SECONDS:
        raise _fail("aggregate timeout is invalid")
    result = start + timeout
    if not math.isfinite(result):
        raise _fail("aggregate timeout is invalid")
    return result


def _remaining(deadline: float, clock: Callable[[], float]) -> float:
    remaining = deadline - clock()
    if not math.isfinite(remaining) or remaining <= 0:
        raise _fail("release verification exceeded its aggregate deadline")
    return min(remaining, MAXIMUM_TIMEOUT_SECONDS)


def _normalize_scope(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("fabrication authorization scope is invalid")
    _exact_keys(value, _SCOPE_KEYS, "fabrication authorization scope")
    authorization_id = _strict_text(
        value.get("authorization_id"), 1, 128, "fabrication authorization id"
    )
    challenge = _digest(value.get("challenge"), "fabrication authorization challenge")
    quantity = _strict_int(
        value.get("quantity"), 1, 1_000_000, "fabrication quantity"
    )
    currency = value.get("currency")
    if (
        not isinstance(currency, str)
        or len(currency) != 3
        or not currency.isascii()
        or not currency.isupper()
    ):
        raise _fail("fabrication currency is invalid")
    maximum_total = _strict_int(
        value.get("maximum_total_minor_units"),
        1,
        9_007_199_254_740_991,
        "fabrication maximum total",
    )
    valid_from = _strict_int(
        value.get("valid_from_unix"), 0, (1 << 64) - 1, "fabrication valid-from"
    )
    expires_at = _strict_int(
        value.get("expires_at_unix"), 0, (1 << 64) - 1, "fabrication expiry"
    )
    if expires_at <= valid_from or expires_at - valid_from > 604_800:
        raise _fail("fabrication authorization window is invalid")
    return {
        "authorization_id": authorization_id,
        "challenge": challenge,
        "quantity": quantity,
        "currency": currency,
        "maximum_total_minor_units": maximum_total,
        "valid_from_unix": valid_from,
        "expires_at_unix": expires_at,
    }


def _normalize_pipeline(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("fabrication pipeline evidence is invalid")
    _exact_keys(value, _PIPELINE_KEYS, "fabrication pipeline evidence")
    return {
        "plan_source": _normalize_identity(
            value.get("plan_source"),
            _pipeline.MAXIMUM_PLAN_BYTES,
            "deterministic pipeline plan",
        ),
        "plan_sha256": _digest(value.get("plan_sha256"), "pipeline plan digest"),
        "retained_report": _normalize_identity(
            value.get("retained_report"),
            _pipeline.MAXIMUM_REPORT_BYTES,
            "deterministic pipeline report",
        ),
        "run_sha256": _digest(value.get("run_sha256"), "pipeline run digest"),
    }


def _normalize_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("fabrication policy evidence is invalid")
    _exact_keys(value, _POLICY_KEYS, "fabrication policy evidence")
    return {
        "source": _normalize_identity(
            value.get("source"), 64 * 1024 * 1024, "organization policy pack"
        ),
        "canonical_sha256": _digest(
            value.get("canonical_sha256"), "canonical policy pack digest"
        ),
        "id": _strict_text(value.get("id"), 1, 128, "policy pack id"),
        "revision": _strict_int(
            value.get("revision"), 1, 4_294_967_295, "policy pack revision"
        ),
    }


def _normalize_fabrication_summary(raw: bytes) -> dict[str, Any]:
    if (
        not raw.endswith(b"\n")
        or b"\r" in raw
        or b"\n" in raw[:-1]
        or len(raw) > MAXIMUM_CHILD_STDOUT_BYTES
    ):
        raise _fail("fabrication authorization child summary is not canonical")
    value = _strict_object(raw[:-1], "fabrication authorization child summary")
    _exact_keys(value, _FABRICATION_SUMMARY_KEYS, "fabrication authorization summary")
    try:
        canonical = (
            json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise _fail("fabrication authorization child summary is invalid") from None
    if canonical != raw:
        raise _fail("fabrication authorization child summary is not canonical")
    return value


def _normalize_fabrication_projection(
    report_raw: bytes,
    summary_raw: bytes,
    *,
    plan_identity: Mapping[str, Any],
    retained_pipeline_identity: Mapping[str, Any],
    package_identity: Mapping[str, Any],
    receipt_identity: Mapping[str, Any],
    policy_identity: Mapping[str, Any],
    policy_pack_value: Mapping[str, Any],
    approval_count: int,
    submitted_approvals: Sequence[Mapping[str, Any]],
    expected_policy_digest: str,
) -> dict[str, Any]:
    if (
        not report_raw.endswith(b"\n")
        or b"\r" in report_raw
        or len(report_raw) > MAXIMUM_FABRICATION_AUTHORIZATION_REPORT_BYTES
    ):
        raise _fail("fabrication authorization child report is not canonical")
    value = _strict_object(report_raw, "fabrication authorization child report")
    _exact_keys(value, _FABRICATION_REPORT_KEYS, "fabrication authorization report")
    summary = _normalize_fabrication_summary(summary_raw)

    evidence = value.get("evidence")
    if not isinstance(evidence, Mapping):
        raise _fail("fabrication authorization evidence is invalid")
    _exact_keys(
        evidence,
        ("pipeline", "manufacturing_package", "factory_receipt", "policy_pack"),
        "fabrication authorization evidence",
    )
    pipeline = _normalize_pipeline(evidence.get("pipeline"))
    manufacturing_package = _normalize_identity(
        evidence.get("manufacturing_package"),
        _routing._handoff.MAXIMUM_MANUFACTURING_PACKAGE_BYTES,
        "fabrication manufacturing package",
    )
    receipt_value = evidence.get("factory_receipt")
    if not isinstance(receipt_value, Mapping):
        raise _fail("fabrication factory receipt evidence is invalid")
    _exact_keys(
        receipt_value,
        ("receipt", "provider", "endpoint", "quote_sha256", "quote_authenticity_verified"),
        "fabrication factory receipt evidence",
    )
    receipt = _normalize_identity(
        receipt_value.get("receipt"), 64 * 1024 * 1024, "factory receipt"
    )
    provider = receipt_value.get("provider")
    endpoint = receipt_value.get("endpoint")
    if provider not in {"jlcpcb", "pcbway", "generic"}:
        raise _fail("factory receipt provider is invalid")
    _strict_text(endpoint, 1, 4096, "factory receipt endpoint")
    quote_sha256 = _digest(
        receipt_value.get("quote_sha256"), "canonical factory quote digest"
    )
    if receipt_value.get("quote_authenticity_verified") is not False:
        raise _fail("fabrication report overclaims quote authenticity")
    policy = _normalize_policy(evidence.get("policy_pack"))

    scope = _normalize_scope(value.get("scope"))
    status = value.get("status")
    authorized = value.get("fabrication_authorized")
    if (
        value.get("schema_version") != 1
        or status not in {"fabrication_authorized", "not_authorized"}
        or type(authorized) is not bool
        or authorized != (status == "fabrication_authorized")
        or value.get("challenge_one_time_use_enforced") is not False
        or not isinstance(value.get("policy_pack"), Mapping)
        or value.get("policy_pack") != policy_pack_value
    ):
        raise _fail("fabrication authorization report governance is invalid")
    evaluated_at = _strict_int(
        value.get("evaluated_at_unix"),
        0,
        (1 << 64) - 1,
        "fabrication evaluation time",
    )
    approvals = _strict_int(
        value.get("approvals"), 0, MAXIMUM_FABRICATION_APPROVALS, "approval count"
    )
    rejections = _strict_int(
        value.get("rejections"), 0, MAXIMUM_FABRICATION_APPROVALS, "rejection count"
    )
    members = value.get("members")
    signed = value.get("signed_approvals")
    if (
        not isinstance(members, list)
        or not isinstance(signed, list)
        or len(members) != approval_count
        or len(signed) != approval_count
        or approvals + rejections != approval_count
    ):
        raise _fail("fabrication authorization approval set is inconsistent")
    try:
        normalized_submitted = sorted(
            (deepcopy(dict(approval)) for approval in submitted_approvals),
            key=lambda approval: approval["signer_id"],
        )
    except (KeyError, TypeError, ValueError, RecursionError):
        raise _fail("submitted fabrication approvals are invalid") from None
    if any(
        not isinstance(approval.get("signer_id"), str)
        for approval in normalized_submitted
    ) or signed != normalized_submitted:
        raise _fail(
            "fabrication authorization does not retain the exact submitted approvals"
        )
    gate_value = value.get("gate_failures")
    if (
        not isinstance(gate_value, list)
        or len(gate_value) > 4
        or any(
            not isinstance(item, str)
            or not 1 <= len(item.encode("utf-8")) <= 256
            for item in gate_value
        )
    ):
        raise _fail("fabrication authorization gate failures are invalid")
    gates = list(gate_value)
    if authorized != (not gates):
        raise _fail("fabrication authorization decision is inconsistent")

    expected_sources = (
        (pipeline["plan_source"], plan_identity, "plan"),
        (pipeline["retained_report"], retained_pipeline_identity, "pipeline report"),
        (manufacturing_package, package_identity, "manufacturing package"),
        (receipt, receipt_identity, "factory receipt"),
        (policy["source"], policy_identity, "policy pack"),
    )
    for observed, expected, label in expected_sources:
        if observed != expected:
            raise _fail(f"fabrication authorization does not bind the captured {label}")
    if policy["canonical_sha256"] != expected_policy_digest:
        raise _fail("fabrication authorization policy does not match the expected pin")

    report_identity = _identity(report_raw)
    summary_checks = {
        "schema_version": 1,
        "status": status,
        "fabrication_authorized": authorized,
        "authorization_id": scope["authorization_id"],
        "challenge": scope["challenge"],
        "quantity": scope["quantity"],
        "currency": scope["currency"],
        "maximum_total_minor_units": scope["maximum_total_minor_units"],
        "valid_from_unix": scope["valid_from_unix"],
        "expires_at_unix": scope["expires_at_unix"],
        "evaluated_at_unix": evaluated_at,
        "approvals": approvals,
        "rejections": rejections,
        "gate_failure_count": len(gates),
        "plan_sha256": pipeline["plan_sha256"],
        "run_sha256": pipeline["run_sha256"],
        "manufacturing_package_sha256": manufacturing_package["sha256"],
        "factory_receipt_sha256": receipt["sha256"],
        "policy_pack_sha256": policy["source"]["sha256"],
        "quote_authenticity_verified": False,
        "challenge_one_time_use_enforced": False,
        "report_bytes": report_identity["bytes"],
        "report_sha256": report_identity["sha256"],
    }
    if summary != summary_checks:
        raise _fail("fabrication authorization summary does not match its report")

    return {
        "report": report_identity,
        "schema_version": 1,
        "status": status,
        "fabrication_authorized": authorized,
        "evaluated_at_unix": evaluated_at,
        "approvals": approvals,
        "rejections": rejections,
        "gate_failures": gates,
        "scope": scope,
        "pipeline": pipeline,
        "manufacturing_package": manufacturing_package,
        "factory_receipt": {
            "receipt": receipt,
            "provider": provider,
            "endpoint": endpoint,
            "quote_sha256": quote_sha256,
        },
        "policy_pack": policy,
        "quote_authenticity_verified": False,
        "challenge_one_time_use_enforced": False,
    }


def _routing_projection(
    report: Mapping[str, Any], retained_raw: bytes
) -> dict[str, Any]:
    return {
        "retained_report": _identity(retained_raw),
        "schema_version": report["schema_version"],
        "verification_scope": report["verification_scope"],
        "status": report["status"],
        "ready": report["ready"],
        "native_kicad_drc_verified": report["native_kicad_drc_verified"],
        "manufacturing_package": deepcopy(report["sources"]["manufacturing_package"]),
        "binding_sha256": report["binding_sha256"],
    }


def _binding(report: Mapping[str, Any]) -> str:
    payload = {key: report[key] for key in _REPORT_KEYS if key != "binding_sha256"}
    try:
        canonical = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise _fail("release report binding input is invalid") from None
    return _sha256(_REPORT_BINDING_DOMAIN + canonical)


def _normalize_routing_projection(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("routing/DRC/manufacturing projection is invalid")
    _exact_keys(value, _ROUTING_PROJECTION_KEYS, "routing/DRC/manufacturing projection")
    status = value.get("status")
    ready = value.get("ready")
    if (
        value.get("schema_version") != _routing.ROUTING_DRC_MANUFACTURING_HANDOFF_SCHEMA_VERSION
        or value.get("verification_scope") != _routing.ROUTING_DRC_MANUFACTURING_HANDOFF_SCOPE
        or status not in {"verified_ready", "not_ready"}
        or type(ready) is not bool
        or ready != (status == "verified_ready")
        or value.get("native_kicad_drc_verified") is not ready
    ):
        raise _fail("routing/DRC/manufacturing projection is inconsistent")
    return {
        "retained_report": _normalize_identity(
            value.get("retained_report"),
            _routing.MAXIMUM_ROUTING_DRC_MANUFACTURING_HANDOFF_REPORT_BYTES,
            "retained routing/DRC/manufacturing report",
        ),
        "schema_version": _routing.ROUTING_DRC_MANUFACTURING_HANDOFF_SCHEMA_VERSION,
        "verification_scope": _routing.ROUTING_DRC_MANUFACTURING_HANDOFF_SCOPE,
        "status": status,
        "ready": ready,
        "native_kicad_drc_verified": ready,
        "manufacturing_package": _normalize_identity(
            value.get("manufacturing_package"),
            _routing._handoff.MAXIMUM_MANUFACTURING_PACKAGE_BYTES,
            "routing manufacturing package",
        ),
        "binding_sha256": _digest(
            value.get("binding_sha256"), "routing/DRC/manufacturing binding"
        ),
    }


def _normalize_fabrication_projection_value(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("fabrication authorization projection is invalid")
    _exact_keys(value, _FABRICATION_PROJECTION_KEYS, "fabrication authorization projection")
    status = value.get("status")
    authorized = value.get("fabrication_authorized")
    if (
        value.get("schema_version") != 1
        or status not in {"fabrication_authorized", "not_authorized"}
        or type(authorized) is not bool
        or authorized != (status == "fabrication_authorized")
        or value.get("quote_authenticity_verified") is not False
        or value.get("challenge_one_time_use_enforced") is not False
    ):
        raise _fail("fabrication authorization projection is inconsistent")
    approvals = _strict_int(
        value.get("approvals"), 0, MAXIMUM_FABRICATION_APPROVALS, "approval count"
    )
    rejections = _strict_int(
        value.get("rejections"), 0, MAXIMUM_FABRICATION_APPROVALS, "rejection count"
    )
    if not 1 <= approvals + rejections <= MAXIMUM_FABRICATION_APPROVALS:
        raise _fail("fabrication authorization approval counts are invalid")
    gates_value = value.get("gate_failures")
    if (
        not isinstance(gates_value, list)
        or len(gates_value) > 4
        or any(
            not isinstance(item, str)
            or not 1 <= len(item.encode("utf-8")) <= 256
            for item in gates_value
        )
    ):
        raise _fail("fabrication authorization gate failures are invalid")
    gates = list(gates_value)
    if authorized != (not gates):
        raise _fail("fabrication authorization gate outcome is inconsistent")
    receipt_value = value.get("factory_receipt")
    if not isinstance(receipt_value, Mapping):
        raise _fail("fabrication factory receipt projection is invalid")
    _exact_keys(
        receipt_value,
        ("receipt", "provider", "endpoint", "quote_sha256"),
        "fabrication factory receipt projection",
    )
    provider = receipt_value.get("provider")
    if provider not in {"jlcpcb", "pcbway", "generic"}:
        raise _fail("factory receipt provider is invalid")
    endpoint = _strict_text(
        receipt_value.get("endpoint"), 1, 4096, "factory receipt endpoint"
    )
    return {
        "report": _normalize_identity(
            value.get("report"),
            MAXIMUM_FABRICATION_AUTHORIZATION_REPORT_BYTES,
            "fabrication authorization report",
        ),
        "schema_version": 1,
        "status": status,
        "fabrication_authorized": authorized,
        "evaluated_at_unix": _strict_int(
            value.get("evaluated_at_unix"),
            0,
            (1 << 64) - 1,
            "fabrication evaluation time",
        ),
        "approvals": approvals,
        "rejections": rejections,
        "gate_failures": gates,
        "scope": _normalize_scope(value.get("scope")),
        "pipeline": _normalize_pipeline(value.get("pipeline")),
        "manufacturing_package": _normalize_identity(
            value.get("manufacturing_package"),
            _routing._handoff.MAXIMUM_MANUFACTURING_PACKAGE_BYTES,
            "fabrication manufacturing package",
        ),
        "factory_receipt": {
            "receipt": _normalize_identity(
                receipt_value.get("receipt"), 64 * 1024 * 1024, "factory receipt"
            ),
            "provider": provider,
            "endpoint": endpoint,
            "quote_sha256": _digest(
                receipt_value.get("quote_sha256"), "canonical factory quote digest"
            ),
        },
        "policy_pack": _normalize_policy(value.get("policy_pack")),
        "quote_authenticity_verified": False,
        "challenge_one_time_use_enforced": False,
    }


def _normalize_report(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("routing/DRC/fabrication release report is invalid")
    _exact_keys(value, _REPORT_KEYS, "routing/DRC/fabrication release report")
    status = value.get("status")
    routing_ready = value.get("routing_drc_manufacturing_ready")
    fabrication_authorized = value.get("fabrication_authorized")
    release_authorized = value.get("release_authorized")
    if (
        value.get("schema_version") != ROUTING_DRC_FABRICATION_RELEASE_SCHEMA_VERSION
        or value.get("verification_scope") != ROUTING_DRC_FABRICATION_RELEASE_SCOPE
        or status not in {"release_authorized", "not_authorized"}
        or type(routing_ready) is not bool
        or type(fabrication_authorized) is not bool
        or type(release_authorized) is not bool
        or release_authorized != (routing_ready and fabrication_authorized)
        or release_authorized != (status == "release_authorized")
    ):
        raise _fail("routing/DRC/fabrication release decision is inconsistent")
    for claim in (
        "source_authenticity_verified",
        "toolchain_authenticity_verified",
        "policy_pack_authenticity_verified",
        "factory_receipt_authenticity_verified",
        "manufacturability_verified",
        "external_submission_performed",
        "capacity_reserved",
        "order_placed",
        "payment_performed",
        "challenge_one_time_use_enforced",
    ):
        if value.get(claim) is not False:
            raise _fail("routing/DRC/fabrication report contains unsupported claims")

    sources_value = value.get("sources")
    if not isinstance(sources_value, Mapping):
        raise _fail("routing/DRC/fabrication release sources are invalid")
    _exact_keys(sources_value, _SOURCE_KEYS, "routing/DRC/fabrication release sources")
    approvals_value = sources_value.get("signed_approvals")
    if (
        not isinstance(approvals_value, list)
        or not 1 <= len(approvals_value) <= MAXIMUM_FABRICATION_APPROVALS
    ):
        raise _fail("signed approval source identities are invalid")
    approval_sources = [
        _normalize_identity(
            item,
            MAXIMUM_SIGNED_FABRICATION_APPROVAL_BYTES,
            f"signed approval {index}",
        )
        for index, item in enumerate(approvals_value)
    ]
    sources = {
        "routing_drc_manufacturing_handoff_report": _normalize_identity(
            sources_value.get("routing_drc_manufacturing_handoff_report"),
            _routing.MAXIMUM_ROUTING_DRC_MANUFACTURING_HANDOFF_REPORT_BYTES,
            "retained routing/DRC/manufacturing report",
        ),
        "deterministic_pipeline_plan": _normalize_identity(
            sources_value.get("deterministic_pipeline_plan"),
            _pipeline.MAXIMUM_PLAN_BYTES,
            "deterministic pipeline plan",
        ),
        "deterministic_pipeline_report": _normalize_identity(
            sources_value.get("deterministic_pipeline_report"),
            _pipeline.MAXIMUM_REPORT_BYTES,
            "deterministic pipeline report",
        ),
        "manufacturing_package": _normalize_identity(
            sources_value.get("manufacturing_package"),
            _routing._handoff.MAXIMUM_MANUFACTURING_PACKAGE_BYTES,
            "manufacturing package",
        ),
        "factory_receipt": _normalize_identity(
            sources_value.get("factory_receipt"),
            64 * 1024 * 1024,
            "factory receipt",
        ),
        "policy_pack": _normalize_identity(
            sources_value.get("policy_pack"),
            64 * 1024 * 1024,
            "organization policy pack",
        ),
        "signed_approvals": approval_sources,
    }
    routing = _normalize_routing_projection(value.get("routing_drc_manufacturing"))
    fabrication = _normalize_fabrication_projection_value(
        value.get("fabrication_authorization")
    )
    pin_value = value.get("policy_pin")
    if not isinstance(pin_value, Mapping):
        raise _fail("fabrication policy pin is invalid")
    _exact_keys(pin_value, _PIN_KEYS, "fabrication policy pin")
    pin = {
        "expected_canonical_sha256": _digest(
            pin_value.get("expected_canonical_sha256"), "expected policy pack digest"
        ),
        "matched": pin_value.get("matched"),
    }
    if pin["matched"] is not True:
        raise _fail("fabrication policy pin did not match")

    if (
        routing["ready"] is not routing_ready
        or fabrication["fabrication_authorized"] is not fabrication_authorized
        or routing["retained_report"]
        != sources["routing_drc_manufacturing_handoff_report"]
        or routing["manufacturing_package"] != sources["manufacturing_package"]
        or fabrication["manufacturing_package"] != sources["manufacturing_package"]
        or fabrication["pipeline"]["plan_source"]
        != sources["deterministic_pipeline_plan"]
        or fabrication["pipeline"]["retained_report"]
        != sources["deterministic_pipeline_report"]
        or fabrication["factory_receipt"]["receipt"] != sources["factory_receipt"]
        or fabrication["policy_pack"]["source"] != sources["policy_pack"]
        or fabrication["policy_pack"]["canonical_sha256"]
        != pin["expected_canonical_sha256"]
        or fabrication["approvals"] + fabrication["rejections"]
        != len(approval_sources)
    ):
        raise _fail("routing/DRC/fabrication release sources are not cross-bound")

    expected_gates: list[str] = []
    if not routing_ready:
        expected_gates.append("routing_drc_manufacturing_not_ready")
    if not fabrication_authorized:
        expected_gates.append("fabrication_not_authorized")
    gates_value = value.get("gate_failures")
    if not isinstance(gates_value, list) or gates_value != expected_gates:
        raise _fail("routing/DRC/fabrication release gate failures are inconsistent")

    validation_value = value.get("validation")
    if not isinstance(validation_value, Mapping):
        raise _fail("routing/DRC/fabrication release validation is invalid")
    _exact_keys(validation_value, _VALIDATION_KEYS, "release validation")
    if any(validation_value.get(key) is not True for key in _VALIDATION_KEYS):
        raise _fail("routing/DRC/fabrication release validation is incomplete")
    validation = {key: True for key in _VALIDATION_KEYS}

    normalized = {
        "schema_version": ROUTING_DRC_FABRICATION_RELEASE_SCHEMA_VERSION,
        "verification_scope": ROUTING_DRC_FABRICATION_RELEASE_SCOPE,
        "status": status,
        "routing_drc_manufacturing_ready": routing_ready,
        "fabrication_authorized": fabrication_authorized,
        "release_authorized": release_authorized,
        "source_authenticity_verified": False,
        "toolchain_authenticity_verified": False,
        "policy_pack_authenticity_verified": False,
        "factory_receipt_authenticity_verified": False,
        "manufacturability_verified": False,
        "external_submission_performed": False,
        "capacity_reserved": False,
        "order_placed": False,
        "payment_performed": False,
        "challenge_one_time_use_enforced": False,
        "sources": sources,
        "routing_drc_manufacturing": routing,
        "fabrication_authorization": fabrication,
        "policy_pin": pin,
        "gate_failures": expected_gates,
        "validation": validation,
        "binding_sha256": value.get("binding_sha256"),
    }
    if (
        not _is_digest(normalized["binding_sha256"])
        or normalized["binding_sha256"] != _binding(normalized)
    ):
        raise _fail("routing/DRC/fabrication release binding is invalid")
    return normalized


def _retained_replay_subject(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the time-invariant subject shared by retained and fresh reports."""

    normalized = _normalize_report(deepcopy(value))
    fabrication = normalized["fabrication_authorization"]
    return {
        "schema_version": normalized["schema_version"],
        "verification_scope": normalized["verification_scope"],
        "sources": deepcopy(normalized["sources"]),
        "routing_drc_manufacturing": deepcopy(
            normalized["routing_drc_manufacturing"]
        ),
        "fabrication_authorization": {
            key: deepcopy(fabrication[key])
            for key in (
                "schema_version",
                "approvals",
                "rejections",
                "scope",
                "pipeline",
                "manufacturing_package",
                "factory_receipt",
                "policy_pack",
                "quote_authenticity_verified",
                "challenge_one_time_use_enforced",
            )
        },
        "policy_pin": deepcopy(normalized["policy_pin"]),
    }


def _retained_replay_subject_sha256(value: Mapping[str, Any]) -> str:
    try:
        canonical = json.dumps(
            _retained_replay_subject(value),
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise _fail("retained release replay subject is invalid") from None
    return _sha256(_RETAINED_REPLAY_SUBJECT_DOMAIN + canonical)


def _evaluate_impl(
    input_board: str | os.PathLike[str],
    routed_board: str | os.PathLike[str],
    convergence_report: str | os.PathLike[str],
    routing_verification_report: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    routing_manufacturing_handoff_report: str | os.PathLike[str],
    native_kicad_drc_report: str | os.PathLike[str],
    routing_drc_manufacturing_handoff_report: str | os.PathLike[str],
    deterministic_pipeline_plan: str | os.PathLike[str],
    deterministic_pipeline_report: str | os.PathLike[str],
    signed_approvals: Sequence[str | os.PathLike[str]],
    expected_policy_pack_canonical_sha256: str,
    pcbex: str | Sequence[str],
    authorization_pcbex: str | Sequence[str],
    *,
    kicad_cli: str | os.PathLike[str],
    kicad_project: str | os.PathLike[str] | None,
    kicad_rules: str | os.PathLike[str] | None,
    grid_mm: float,
    width_mm: float,
    clearance_mm: float,
    via_diameter_mm: float,
    via_drill_mm: float,
    bend_cost: int,
    via_cost: int,
    fab: str | None,
    fab_profile: str | os.PathLike[str] | None,
    physical_profile: str | os.PathLike[str] | None,
    timeout_seconds: float,
    _clock: Callable[[], float],
    _root: str,
    _retained_outer: str | os.PathLike[str] | None = None,
    _command_observer: Callable[
        [tuple[str, ...], tuple[str, ...], str],
        tuple[tuple[str, ...], tuple[str, ...], str],
    ]
    | None = None,
    _retained_outer_subject_only: bool = False,
    _retained_outer_capture: list[tuple[str, bytes]] | None = None,
) -> dict[str, Any]:
    if sum(source is not None for source in (fab, fab_profile, physical_profile)) > 1:
        raise _fail("manufacturing profile selections are mutually exclusive")
    expected_policy_digest = _digest(
        expected_policy_pack_canonical_sha256, "expected policy pack digest"
    )
    if _retained_outer_capture is not None and (
        type(_retained_outer_capture) is not list or _retained_outer_capture
    ):
        raise _fail("retained outer capture sink is invalid")

    caller_sources: list[tuple[str | Path, bytes, int, str]] = []
    top_level_paths: list[tuple[str, str]] = []

    def capture(
        value: str | os.PathLike[str], maximum: int, label: str
    ) -> tuple[str, bytes]:
        path = _freeze_path(value, label, _root)
        raw = _read_source(path, maximum, label)
        caller_sources.append((path, raw, maximum, label))
        top_level_paths.append((label, path))
        return path, raw

    input_source, input_raw = capture(
        input_board, _routing._handoff.MAXIMUM_ROUTING_INPUT_BYTES, "routing input board"
    )
    routed_source, routed_raw = capture(
        routed_board, _routing._handoff.MAXIMUM_ROUTED_BOARD_BYTES, "routed board"
    )
    convergence_source, convergence_raw = capture(
        convergence_report,
        _routing._handoff.MAXIMUM_CONVERGENCE_REPORT_BYTES,
        "routing convergence report",
    )
    verification_source, verification_raw = capture(
        routing_verification_report,
        _routing._handoff.MAXIMUM_ROUTING_VERIFICATION_REPORT_BYTES,
        "routing verification report",
    )
    package_source, package_raw = capture(
        manufacturing_package,
        _routing._handoff.MAXIMUM_MANUFACTURING_PACKAGE_BYTES,
        "manufacturing package",
    )
    handoff_source, handoff_raw = capture(
        routing_manufacturing_handoff_report,
        _routing._handoff.MAXIMUM_ROUTING_MANUFACTURING_HANDOFF_REPORT_BYTES,
        "routing/manufacturing handoff report",
    )
    native_source, native_raw = capture(
        native_kicad_drc_report,
        _routing.MAXIMUM_NATIVE_KICAD_DRC_REPORT_BYTES,
        "native KiCad DRC report",
    )
    retained_release_source, retained_release_raw = capture(
        routing_drc_manufacturing_handoff_report,
        _routing.MAXIMUM_ROUTING_DRC_MANUFACTURING_HANDOFF_REPORT_BYTES,
        "retained routing/DRC/manufacturing report",
    )

    def capture_optional(
        value: str | os.PathLike[str] | None, maximum: int, label: str
    ) -> tuple[str | None, bytes | None]:
        if value is None:
            return None, None
        return capture(value, maximum, label)

    project_source, project_raw = capture_optional(
        kicad_project, _manufacturing.MAXIMUM_PROJECT_BYTES, "KiCad project"
    )
    rules_source, rules_raw = capture_optional(
        kicad_rules, _manufacturing.MAXIMUM_RULES_BYTES, "KiCad rules"
    )
    fab_profile_source, fab_profile_raw = capture_optional(
        fab_profile, _manufacturing.MAXIMUM_PROFILE_BYTES, "DFM profile"
    )
    physical_profile_source, physical_profile_raw = capture_optional(
        physical_profile,
        _manufacturing.MAXIMUM_PROFILE_BYTES,
        "physical profile",
    )
    plan_source, plan_raw = capture(
        deterministic_pipeline_plan,
        _pipeline.MAXIMUM_PLAN_BYTES,
        "deterministic pipeline plan",
    )
    pipeline_report_source, pipeline_report_raw = capture(
        deterministic_pipeline_report,
        _pipeline.MAXIMUM_REPORT_BYTES,
        "deterministic pipeline report",
    )

    # Capture the complete plan-selected closure before invoking the approval
    # container or any selected executable/clock hook. An approval iterator
    # must not be able to repair or select the pipeline evidence baseline.
    try:
        pipeline_capture = _pipeline._capture_deterministic_pipeline_replay_inputs(
            plan_source,
            pipeline_report_source,
            deadline=1.0,
            clock=lambda: 0.0,
        )
    except Exception:
        raise _fail("deterministic pipeline closure capture failed") from None
    if (
        pipeline_capture.plan_raw != plan_raw
        or pipeline_capture.retained_raw != pipeline_report_raw
    ):
        raise _fail("deterministic pipeline sources changed during capture")
    plan_roles = dict(pipeline_capture.role_sources)
    if (
        pipeline_capture.plan_value.get("require_factory") is not True
        or "factory_receipt" not in plan_roles
        or "analysis_policy_pack" not in plan_roles
    ):
        raise _fail("deterministic pipeline is not factory-authorized")
    if plan_roles.get("manufacturing_package") != package_raw:
        raise _fail(
            "routing and deterministic pipeline closures do not bind the same manufacturing package"
        )
    factory_receipt_raw = plan_roles["factory_receipt"]
    policy_pack_raw = plan_roles["analysis_policy_pack"]
    policy_pack_value = _strict_object(policy_pack_raw, "organization policy pack")

    if isinstance(signed_approvals, (str, bytes, bytearray, memoryview, os.PathLike)):
        raise _fail("signed fabrication approvals must be a bounded sequence")
    try:
        approval_values = _guard_cwd(_root, tuple, signed_approvals)
    except RoutingDrcFabricationReleaseError:
        raise
    except Exception:
        raise _fail("signed fabrication approvals are invalid") from None
    if not 1 <= len(approval_values) <= MAXIMUM_FABRICATION_APPROVALS:
        raise _fail("signed fabrication approvals must contain 1 to 100 entries")
    approval_sources: list[tuple[str, bytes]] = []
    approval_values_parsed: list[dict[str, Any]] = []
    approval_total = 0
    for index, item in enumerate(approval_values):
        path, raw = capture(
            item,
            MAXIMUM_SIGNED_FABRICATION_APPROVAL_BYTES,
            f"signed fabrication approval {index}",
        )
        approval_total += len(raw)
        if approval_total > MAXIMUM_FABRICATION_APPROVAL_AGGREGATE_BYTES:
            raise _fail("signed fabrication approvals exceed their aggregate bound")
        approval_sources.append((path, raw))
        approval_values_parsed.append(
            _strict_object(raw, f"signed fabrication approval {index}")
        )
    retained_outer_raw: bytes | None = None
    retained_outer_value: dict[str, Any] | None = None
    retained_outer_source: str | None = None
    if _retained_outer is not None:
        retained_outer_source, retained_outer_raw = capture(
            _retained_outer,
            MAXIMUM_ROUTING_DRC_FABRICATION_RELEASE_REPORT_BYTES,
            "retained routing/DRC/fabrication release report",
        )
        try:
            retained_outer_value = _normalize_report(
                _strict_object(
                    retained_outer_raw,
                    "retained routing/DRC/fabrication release report",
                )
            )
            if (
                render_routing_drc_fabrication_release_report(retained_outer_value)
                != retained_outer_raw
            ):
                raise _fail(
                    "retained routing/DRC/fabrication release report is not canonical"
                )
        except RoutingDrcFabricationReleaseError:
            raise
        except Exception:
            raise _fail(
                "retained routing/DRC/fabrication release report is invalid"
            ) from None
        if _retained_outer_capture is not None:
            _retained_outer_capture.append(
                (retained_outer_source, bytes(retained_outer_raw))
            )

    _reject_aliases(top_level_paths)
    for approval_path, _raw in approval_sources:
        for internal_path, _expected, _maximum, _label in (
            pipeline_capture.caller_sources[2:]
        ):
            if _same_path(approval_path, os.fspath(internal_path)):
                raise _fail(
                    "signed fabrication approval must not alias a pipeline input"
                )

    try:
        retained_routing = _routing._normalize_report(
            _routing._strict_object(
                retained_release_raw,
                "retained routing/DRC/manufacturing handoff report",
            )
        )
        if (
            _routing.render_routing_drc_manufacturing_handoff_report(retained_routing)
            != retained_release_raw
        ):
            raise _fail("retained routing/DRC/manufacturing report is not canonical")
    except RoutingDrcFabricationReleaseError:
        raise
    except Exception:
        raise _fail("retained routing/DRC/manufacturing report is invalid") from None

    total_input = sum(len(raw) for _path, raw, _maximum, _label in caller_sources)
    total_input += sum(
        len(raw)
        for _relative, _path, raw, _maximum, _label, _identity_value in (
            pipeline_capture.staged_sources
        )
    )
    maximum_total_input = MAXIMUM_TOTAL_INPUT_BYTES
    if retained_outer_raw is not None:
        maximum_total_input += MAXIMUM_ROUTING_DRC_FABRICATION_RELEASE_REPORT_BYTES
    if total_input > maximum_total_input:
        raise _fail("routing/DRC/fabrication release inputs exceed their aggregate bound")

    try:
        routing_command = _guard_cwd(
            _root, _manufacturing._normalize_command, pcbex
        )
        authorization_command = _guard_cwd(
            _root, _manufacturing._normalize_command, authorization_pcbex
        )
        kicad_argument = _guard_cwd(
            _root, _manufacturing._argument, kicad_cli, "kicad-cli argument"
        )
    except RoutingDrcFabricationReleaseError:
        raise
    except Exception:
        raise _fail("release verification command is invalid") from None
    if _command_observer is not None:
        observed = _guard_cwd(
            _root,
            _command_observer,
            tuple(routing_command),
            tuple(authorization_command),
            kicad_argument,
        )
        if (
            type(observed) is not tuple
            or len(observed) != 3
            or type(observed[0]) is not tuple
            or type(observed[1]) is not tuple
            or type(observed[2]) is not str
            or not observed[0]
            or not observed[1]
            or any(type(item) is not str or not item for item in observed[0])
            or any(type(item) is not str or not item for item in observed[1])
            or not observed[2]
        ):
            raise _fail("release verification command observer returned invalid commands")
        routing_command, authorization_command, kicad_argument = observed
    protected_paths = [path for _label, path in top_level_paths]
    protected_paths.extend(os.fspath(path) for path, _raw, _max, _label in pipeline_capture.caller_sources)
    for candidate in (
        *_command_path_candidates(routing_command, _root),
        *_command_path_candidates(authorization_command, _root),
        *_command_path_candidates((kicad_argument,), _root),
    ):
        if any(_same_path(candidate, source) for source in protected_paths):
            raise _fail("release verification command must not alias an evidence input")
    _reread(caller_sources)
    _reread(pipeline_capture.caller_sources)

    guarded_clock, _last_clock = _guarded_clock(_root, _clock)
    deadline = _deadline(timeout_seconds, guarded_clock)
    _reread(caller_sources)
    _reread(pipeline_capture.caller_sources)

    routing_result: dict[str, Any] | None = None
    fabrication_projection: dict[str, Any] | None = None
    staged: list[tuple[Path, bytes, int, str]] = []
    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-v1478-", dir=_pipeline._trusted_temporary_root()
        ) as directory:
            workspace = Path(directory)

            def stage(
                relative: str, raw: bytes, maximum: int, label: str
            ) -> Path:
                target = workspace.joinpath(*Path(relative).parts)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                atomic_write_no_clobber(target, raw, max_bytes=maximum)
                staged.append((target, raw, maximum, label))
                return target

            staged_input = stage(
                f"routing/input/{Path(input_source).name}",
                input_raw,
                _routing._handoff.MAXIMUM_ROUTING_INPUT_BYTES,
                "staged routing input board",
            )
            staged_routed = stage(
                f"routing/routed/{Path(routed_source).name}",
                routed_raw,
                _routing._handoff.MAXIMUM_ROUTED_BOARD_BYTES,
                "staged routed board",
            )
            staged_convergence = stage(
                "routing/reports/convergence.json",
                convergence_raw,
                _routing._handoff.MAXIMUM_CONVERGENCE_REPORT_BYTES,
                "staged convergence report",
            )
            staged_verification = stage(
                "routing/reports/verification.json",
                verification_raw,
                _routing._handoff.MAXIMUM_ROUTING_VERIFICATION_REPORT_BYTES,
                "staged routing verification report",
            )
            staged_package = stage(
                "routing/package/manufacturing.zip",
                package_raw,
                _routing._handoff.MAXIMUM_MANUFACTURING_PACKAGE_BYTES,
                "staged manufacturing package",
            )
            staged_handoff = stage(
                "routing/reports/routing-manufacturing.json",
                handoff_raw,
                _routing._handoff.MAXIMUM_ROUTING_MANUFACTURING_HANDOFF_REPORT_BYTES,
                "staged routing/manufacturing report",
            )
            staged_native = stage(
                "routing/reports/native-drc.json",
                native_raw,
                _routing.MAXIMUM_NATIVE_KICAD_DRC_REPORT_BYTES,
                "staged native DRC report",
            )
            staged_project = (
                None
                if project_raw is None
                else stage(
                    f"routing/routed/{Path(project_source or 'input.kicad_pro').name}",
                    project_raw,
                    _manufacturing.MAXIMUM_PROJECT_BYTES,
                    "staged KiCad project",
                )
            )
            staged_rules = (
                None
                if rules_raw is None
                else stage(
                    f"routing/routed/{Path(rules_source or 'input.kicad_dru').name}",
                    rules_raw,
                    _manufacturing.MAXIMUM_RULES_BYTES,
                    "staged KiCad rules",
                )
            )
            staged_fab_profile = (
                None
                if fab_profile_raw is None
                else stage(
                    f"routing/profile/{Path(fab_profile_source or 'dfm.json').name}",
                    fab_profile_raw,
                    _manufacturing.MAXIMUM_PROFILE_BYTES,
                    "staged DFM profile",
                )
            )
            staged_physical_profile = (
                None
                if physical_profile_raw is None
                else stage(
                    f"routing/profile/{Path(physical_profile_source or 'physical.json').name}",
                    physical_profile_raw,
                    _manufacturing.MAXIMUM_PROFILE_BYTES,
                    "staged physical profile",
                )
            )
            stage(
                "routing/reports/retained-release.json",
                retained_release_raw,
                _routing.MAXIMUM_ROUTING_DRC_MANUFACTURING_HANDOFF_REPORT_BYTES,
                "staged retained routing/DRC/manufacturing report",
            )

            pipeline_root = workspace / "pipeline"
            pipeline_root.mkdir(mode=0o700)
            staged_plan = pipeline_root / pipeline_capture.plan_stage_name
            atomic_write_no_clobber(
                staged_plan,
                pipeline_capture.plan_raw,
                max_bytes=_pipeline.MAXIMUM_PLAN_BYTES,
            )
            staged.append(
                (
                    staged_plan,
                    pipeline_capture.plan_raw,
                    _pipeline.MAXIMUM_PLAN_BYTES,
                    "staged deterministic pipeline plan",
                )
            )
            staged_by_relative: dict[str, Path] = {}
            for relative, _caller, raw, maximum, label, _expected in (
                pipeline_capture.staged_sources
            ):
                target = _pipeline._source_path(pipeline_root, relative)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                atomic_write_no_clobber(target, raw, max_bytes=maximum)
                staged.append((target, raw, maximum, f"staged {label}"))
                staged_by_relative[relative] = target
            descriptor_map = dict(pipeline_capture.descriptors)
            staged_role_paths = {
                role: staged_by_relative[descriptor["path"]]
                for role, descriptor in descriptor_map.items()
            }
            staged_pipeline_report = stage(
                "authorization/retained-pipeline-report.json",
                pipeline_report_raw,
                _pipeline.MAXIMUM_REPORT_BYTES,
                "staged retained deterministic pipeline report",
            )
            staged_approvals = [
                stage(
                    f"authorization/approval-{index:03d}.json",
                    raw,
                    MAXIMUM_SIGNED_FABRICATION_APPROVAL_BYTES,
                    f"staged signed fabrication approval {index}",
                )
                for index, (_path, raw) in enumerate(approval_sources)
            ]
            _verify_staged(staged)
            _reread(caller_sources)
            _reread(pipeline_capture.caller_sources)

            routing_remaining = _remaining(deadline, guarded_clock)
            routing_timeout = routing_remaining / 2.0
            if not math.isfinite(routing_timeout) or routing_timeout <= 0:
                raise _fail("routing/DRC/manufacturing replay has no execution budget")
            try:
                routing_result = _routing.evaluate_routing_drc_manufacturing_handoff(
                    staged_input,
                    staged_routed,
                    staged_convergence,
                    staged_verification,
                    staged_package,
                    staged_handoff,
                    staged_native,
                    routing_command,
                    kicad_cli=kicad_argument,
                    kicad_project=staged_project,
                    kicad_rules=staged_rules,
                    grid_mm=grid_mm,
                    width_mm=width_mm,
                    clearance_mm=clearance_mm,
                    via_diameter_mm=via_diameter_mm,
                    via_drill_mm=via_drill_mm,
                    bend_cost=bend_cost,
                    via_cost=via_cost,
                    fab=fab,
                    fab_profile=staged_fab_profile,
                    physical_profile=staged_physical_profile,
                    timeout_seconds=routing_timeout,
                    _clock=guarded_clock,
                )
                fresh_routing_raw = (
                    _routing.render_routing_drc_manufacturing_handoff_report(
                        routing_result
                    )
                )
            except Exception:
                raise _fail("routing/DRC/manufacturing replay failed") from None
            if fresh_routing_raw != retained_release_raw:
                raise _fail(
                    "fresh routing/DRC/manufacturing replay did not reproduce the retained report"
                )
            _remaining(deadline, guarded_clock)
            _verify_staged(staged)
            _reread(caller_sources)
            _reread(pipeline_capture.caller_sources)

            authorization_remaining = _remaining(deadline, guarded_clock)
            reserve = min(30.0, authorization_remaining / 2.0)
            authorization_timeout = authorization_remaining - reserve
            cleanup_timeout = reserve / 2.0
            if (
                not math.isfinite(authorization_timeout)
                or authorization_timeout <= 0
                or not math.isfinite(cleanup_timeout)
                or cleanup_timeout <= 0
            ):
                raise _fail("fabrication authorization replay has no execution budget")
            authorization_output = workspace / "authorization" / "fresh-authorization.json"
            argv = [
                *authorization_command,
                "verify-fabrication-authorization",
                str(staged_plan),
                "--report",
                str(staged_pipeline_report),
                "--manufacturing-package",
                str(staged_role_paths["manufacturing_package"]),
                "--factory-receipt",
                str(staged_role_paths["factory_receipt"]),
                "--policy-pack",
                str(staged_role_paths["analysis_policy_pack"]),
            ]
            for approval in staged_approvals:
                argv.extend(("--approval", str(approval)))
            argv.extend(
                (
                    "--output",
                    str(authorization_output),
                    "--mcp-echo-report-summary",
                )
            )
            try:
                argv = _manufacturing._validate_final_argv(argv)
                # No caller-controlled operation occurs between this final
                # staged-input reread and process spawn.
                _verify_staged(staged)
                completed = run_bounded(
                    argv,
                    timeout_seconds=authorization_timeout,
                    cleanup_timeout_seconds=cleanup_timeout,
                    max_stdout_bytes=MAXIMUM_CHILD_STDOUT_BYTES,
                    max_stderr_bytes=MAXIMUM_CHILD_STDERR_BYTES,
                )
            except RoutingDrcFabricationReleaseError:
                raise
            except (BoundedProcessError, OSError, TypeError, ValueError):
                raise _fail("fabrication authorization child failed") from None
            if completed.returncode != 0:
                raise _fail("fabrication authorization child rejected the evidence")
            authorization_raw = _read_source(
                authorization_output,
                MAXIMUM_FABRICATION_AUTHORIZATION_REPORT_BYTES,
                "fresh fabrication authorization report",
            )
            fabrication_projection = _normalize_fabrication_projection(
                authorization_raw,
                completed.stdout,
                plan_identity=_identity(plan_raw),
                retained_pipeline_identity=_identity(pipeline_report_raw),
                package_identity=_identity(package_raw),
                receipt_identity=_identity(factory_receipt_raw),
                policy_identity=_identity(policy_pack_raw),
                policy_pack_value=policy_pack_value,
                approval_count=len(approval_sources),
                submitted_approvals=approval_values_parsed,
                expected_policy_digest=expected_policy_digest,
            )
            _remaining(deadline, guarded_clock)
            _verify_staged(staged)
            if (
                _read_source(
                    authorization_output,
                    MAXIMUM_FABRICATION_AUTHORIZATION_REPORT_BYTES,
                    "fresh fabrication authorization report",
                )
                != authorization_raw
            ):
                raise _fail("fresh fabrication authorization report changed")
            _reread(caller_sources)
            _reread(pipeline_capture.caller_sources)
    except RoutingDrcFabricationReleaseError:
        raise
    except (BoundedIOError, BoundedProcessError, OSError, TypeError, ValueError):
        raise _fail("routing/DRC/fabrication release workspace failed") from None

    assert routing_result is not None
    assert fabrication_projection is not None
    _remaining(deadline, guarded_clock)
    _reread(caller_sources)
    _reread(pipeline_capture.caller_sources)

    routing_ready = routing_result["ready"] is True
    fabrication_authorized = fabrication_projection["fabrication_authorized"] is True
    release_authorized = routing_ready and fabrication_authorized
    gates: list[str] = []
    if not routing_ready:
        gates.append("routing_drc_manufacturing_not_ready")
    if not fabrication_authorized:
        gates.append("fabrication_not_authorized")
    result: dict[str, Any] = {
        "schema_version": ROUTING_DRC_FABRICATION_RELEASE_SCHEMA_VERSION,
        "verification_scope": ROUTING_DRC_FABRICATION_RELEASE_SCOPE,
        "status": "release_authorized" if release_authorized else "not_authorized",
        "routing_drc_manufacturing_ready": routing_ready,
        "fabrication_authorized": fabrication_authorized,
        "release_authorized": release_authorized,
        "source_authenticity_verified": False,
        "toolchain_authenticity_verified": False,
        "policy_pack_authenticity_verified": False,
        "factory_receipt_authenticity_verified": False,
        "manufacturability_verified": False,
        "external_submission_performed": False,
        "capacity_reserved": False,
        "order_placed": False,
        "payment_performed": False,
        "challenge_one_time_use_enforced": False,
        "sources": {
            "routing_drc_manufacturing_handoff_report": _identity(
                retained_release_raw
            ),
            "deterministic_pipeline_plan": _identity(plan_raw),
            "deterministic_pipeline_report": _identity(pipeline_report_raw),
            "manufacturing_package": _identity(package_raw),
            "factory_receipt": _identity(factory_receipt_raw),
            "policy_pack": _identity(policy_pack_raw),
            "signed_approvals": [
                _identity(raw) for _path, raw in approval_sources
            ],
        },
        "routing_drc_manufacturing": _routing_projection(
            routing_result, retained_release_raw
        ),
        "fabrication_authorization": fabrication_projection,
        "policy_pin": {
            "expected_canonical_sha256": expected_policy_digest,
            "matched": True,
        },
        "gate_failures": gates,
        "validation": {key: True for key in _VALIDATION_KEYS},
        "binding_sha256": "",
    }
    result["binding_sha256"] = _binding(result)
    normalized_result = _normalize_report(result)
    if retained_outer_raw is not None:
        if _retained_outer_subject_only:
            retained_outer_value = _normalize_report(
                _strict_object(
                    retained_outer_raw,
                    "retained routing/DRC/fabrication release report",
                )
            )
            if _retained_replay_subject_sha256(
                normalized_result
            ) != _retained_replay_subject_sha256(retained_outer_value):
                raise _fail(
                    "fresh routing/DRC/fabrication release does not match the retained replay subject"
                )
        elif (
            render_routing_drc_fabrication_release_report(normalized_result)
            != retained_outer_raw
        ):
            raise _fail(
                "fresh routing/DRC/fabrication release did not reproduce the retained report"
            )
        if _retained_outer_capture is not None and _retained_outer_capture != [
            (retained_outer_source, retained_outer_raw)
        ]:
            raise _fail("retained outer capture changed during release replay")
    return normalized_result


def evaluate_routing_drc_fabrication_release(
    input_board: str | os.PathLike[str],
    routed_board: str | os.PathLike[str],
    convergence_report: str | os.PathLike[str],
    routing_verification_report: str | os.PathLike[str],
    manufacturing_package: str | os.PathLike[str],
    routing_manufacturing_handoff_report: str | os.PathLike[str],
    native_kicad_drc_report: str | os.PathLike[str],
    routing_drc_manufacturing_handoff_report: str | os.PathLike[str],
    deterministic_pipeline_plan: str | os.PathLike[str],
    deterministic_pipeline_report: str | os.PathLike[str],
    signed_approvals: Sequence[str | os.PathLike[str]],
    expected_policy_pack_canonical_sha256: str,
    pcbex: str | Sequence[str] = "pcbex",
    authorization_pcbex: str | Sequence[str] = "pcbex",
    *,
    kicad_cli: str | os.PathLike[str] = "kicad-cli",
    kicad_project: str | os.PathLike[str] | None = None,
    kicad_rules: str | os.PathLike[str] | None = None,
    grid_mm: float = 0.25,
    width_mm: float = 0.25,
    clearance_mm: float = 0.20,
    via_diameter_mm: float = 0.60,
    via_drill_mm: float = 0.30,
    bend_cost: int = 5,
    via_cost: int = 20,
    fab: str | None = None,
    fab_profile: str | os.PathLike[str] | None = None,
    physical_profile: str | os.PathLike[str] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Freshly verify one exact ready-and-authorized fabrication release."""

    root = _public_root()
    try:
        return _guard_cwd(
            root,
            _evaluate_impl,
            input_board,
            routed_board,
            convergence_report,
            routing_verification_report,
            manufacturing_package,
            routing_manufacturing_handoff_report,
            native_kicad_drc_report,
            routing_drc_manufacturing_handoff_report,
            deterministic_pipeline_plan,
            deterministic_pipeline_report,
            signed_approvals,
            expected_policy_pack_canonical_sha256,
            pcbex,
            authorization_pcbex,
            kicad_cli=kicad_cli,
            kicad_project=kicad_project,
            kicad_rules=kicad_rules,
            grid_mm=grid_mm,
            width_mm=width_mm,
            clearance_mm=clearance_mm,
            via_diameter_mm=via_diameter_mm,
            via_drill_mm=via_drill_mm,
            bend_cost=bend_cost,
            via_cost=via_cost,
            fab=fab,
            fab_profile=fab_profile,
            physical_profile=physical_profile,
            timeout_seconds=timeout_seconds,
            _clock=_clock,
            _root=root,
        )
    except RoutingDrcFabricationReleaseError:
        raise
    except Exception:
        raise _fail("routing/DRC/fabrication release inputs are invalid") from None


def render_routing_drc_fabrication_release_report(
    report: Mapping[str, Any],
) -> bytes:
    root = _public_root()

    def render() -> bytes:
        normalized = _normalize_report(deepcopy(report))
        try:
            raw = (
                json.dumps(normalized, indent=2, ensure_ascii=False) + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise _fail("routing/DRC/fabrication release report cannot be rendered") from None
        if len(raw) > MAXIMUM_ROUTING_DRC_FABRICATION_RELEASE_REPORT_BYTES:
            raise _fail("routing/DRC/fabrication release report exceeds its byte limit")
        return raw

    try:
        return _guard_cwd(root, render)
    except RoutingDrcFabricationReleaseError:
        raise
    except Exception:
        raise _fail("routing/DRC/fabrication release report is invalid") from None


def routing_drc_fabrication_release_report_json_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}

    def identity(maximum: int) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["bytes", "sha256"],
            "properties": {
                "bytes": {"type": "integer", "minimum": 1, "maximum": maximum},
                "sha256": dict(digest),
            },
        }

    scope = {
        "type": "object",
        "additionalProperties": False,
        "required": list(_SCOPE_KEYS),
        "properties": {
            "authorization_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
            },
            "challenge": dict(digest),
            "quantity": {"type": "integer", "minimum": 1, "maximum": 1_000_000},
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "maximum_total_minor_units": {
                "type": "integer",
                "minimum": 1,
                "maximum": 9_007_199_254_740_991,
            },
            "valid_from_unix": {"type": "integer", "minimum": 0},
            "expires_at_unix": {"type": "integer", "minimum": 1},
        },
    }
    pipeline = {
        "type": "object",
        "additionalProperties": False,
        "required": list(_PIPELINE_KEYS),
        "properties": {
            "plan_source": identity(_pipeline.MAXIMUM_PLAN_BYTES),
            "plan_sha256": dict(digest),
            "retained_report": identity(_pipeline.MAXIMUM_REPORT_BYTES),
            "run_sha256": dict(digest),
        },
    }
    policy = {
        "type": "object",
        "additionalProperties": False,
        "required": list(_POLICY_KEYS),
        "properties": {
            "source": identity(64 * 1024 * 1024),
            "canonical_sha256": dict(digest),
            "id": {"type": "string", "minLength": 1, "maxLength": 128},
            "revision": {
                "type": "integer",
                "minimum": 1,
                "maximum": 4_294_967_295,
            },
        },
    }
    receipt = {
        "type": "object",
        "additionalProperties": False,
        "required": ["receipt", "provider", "endpoint", "quote_sha256"],
        "properties": {
            "receipt": identity(64 * 1024 * 1024),
            "provider": {"enum": ["jlcpcb", "pcbway", "generic"]},
            "endpoint": {"type": "string", "minLength": 1, "maxLength": 4096},
            "quote_sha256": dict(digest),
        },
    }
    routing = {
        "type": "object",
        "additionalProperties": False,
        "required": list(_ROUTING_PROJECTION_KEYS),
        "properties": {
            "retained_report": identity(
                _routing.MAXIMUM_ROUTING_DRC_MANUFACTURING_HANDOFF_REPORT_BYTES
            ),
            "schema_version": {
                "const": _routing.ROUTING_DRC_MANUFACTURING_HANDOFF_SCHEMA_VERSION
            },
            "verification_scope": {
                "const": _routing.ROUTING_DRC_MANUFACTURING_HANDOFF_SCOPE
            },
            "status": {"enum": ["verified_ready", "not_ready"]},
            "ready": {"type": "boolean"},
            "native_kicad_drc_verified": {"type": "boolean"},
            "manufacturing_package": identity(
                _routing._handoff.MAXIMUM_MANUFACTURING_PACKAGE_BYTES
            ),
            "binding_sha256": dict(digest),
        },
        "allOf": [
            {
                "if": {"properties": {"ready": {"const": True}}, "required": ["ready"]},
                "then": {
                    "properties": {
                        "status": {"const": "verified_ready"},
                        "native_kicad_drc_verified": {"const": True},
                    }
                },
                "else": {
                    "properties": {
                        "status": {"const": "not_ready"},
                        "native_kicad_drc_verified": {"const": False},
                    }
                },
            }
        ],
    }
    fabrication = {
        "type": "object",
        "additionalProperties": False,
        "required": list(_FABRICATION_PROJECTION_KEYS),
        "properties": {
            "report": identity(MAXIMUM_FABRICATION_AUTHORIZATION_REPORT_BYTES),
            "schema_version": {"const": 1},
            "status": {"enum": ["fabrication_authorized", "not_authorized"]},
            "fabrication_authorized": {"type": "boolean"},
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "approvals": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAXIMUM_FABRICATION_APPROVALS,
            },
            "rejections": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAXIMUM_FABRICATION_APPROVALS,
            },
            "gate_failures": {
                "type": "array",
                "maxItems": 4,
                "items": {"type": "string", "minLength": 1, "maxLength": 256},
            },
            "scope": scope,
            "pipeline": pipeline,
            "manufacturing_package": identity(
                _routing._handoff.MAXIMUM_MANUFACTURING_PACKAGE_BYTES
            ),
            "factory_receipt": receipt,
            "policy_pack": policy,
            "quote_authenticity_verified": {"const": False},
            "challenge_one_time_use_enforced": {"const": False},
        },
        "allOf": [
            {
                "if": {
                    "properties": {"fabrication_authorized": {"const": True}},
                    "required": ["fabrication_authorized"],
                },
                "then": {
                    "properties": {
                        "status": {"const": "fabrication_authorized"},
                        "gate_failures": {"maxItems": 0},
                    }
                },
                "else": {
                    "properties": {
                        "status": {"const": "not_authorized"},
                        "gate_failures": {"minItems": 1},
                    }
                },
            }
        ],
    }
    sources = {
        "type": "object",
        "additionalProperties": False,
        "required": list(_SOURCE_KEYS),
        "properties": {
            "routing_drc_manufacturing_handoff_report": identity(
                _routing.MAXIMUM_ROUTING_DRC_MANUFACTURING_HANDOFF_REPORT_BYTES
            ),
            "deterministic_pipeline_plan": identity(_pipeline.MAXIMUM_PLAN_BYTES),
            "deterministic_pipeline_report": identity(_pipeline.MAXIMUM_REPORT_BYTES),
            "manufacturing_package": identity(
                _routing._handoff.MAXIMUM_MANUFACTURING_PACKAGE_BYTES
            ),
            "factory_receipt": identity(64 * 1024 * 1024),
            "policy_pack": identity(64 * 1024 * 1024),
            "signed_approvals": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAXIMUM_FABRICATION_APPROVALS,
                "items": identity(MAXIMUM_SIGNED_FABRICATION_APPROVAL_BYTES),
            },
        },
    }
    gate = {
        "type": "string",
        "enum": [
            "routing_drc_manufacturing_not_ready",
            "fabrication_not_authorized",
        ],
    }
    report: dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/schemas/"
            "routing-drc-fabrication-release-report-v1.json"
        ),
        "title": "pcbex fresh routing/DRC fabrication release report",
        "type": "object",
        "additionalProperties": False,
        "required": list(_REPORT_KEYS),
        "properties": {
            "schema_version": {
                "const": ROUTING_DRC_FABRICATION_RELEASE_SCHEMA_VERSION
            },
            "verification_scope": {"const": ROUTING_DRC_FABRICATION_RELEASE_SCOPE},
            "status": {"enum": ["release_authorized", "not_authorized"]},
            "routing_drc_manufacturing_ready": {"type": "boolean"},
            "fabrication_authorized": {"type": "boolean"},
            "release_authorized": {"type": "boolean"},
            **{
                claim: {"const": False}
                for claim in (
                    "source_authenticity_verified",
                    "toolchain_authenticity_verified",
                    "policy_pack_authenticity_verified",
                    "factory_receipt_authenticity_verified",
                    "manufacturability_verified",
                    "external_submission_performed",
                    "capacity_reserved",
                    "order_placed",
                    "payment_performed",
                    "challenge_one_time_use_enforced",
                )
            },
            "sources": sources,
            "routing_drc_manufacturing": routing,
            "fabrication_authorization": fabrication,
            "policy_pin": {
                "type": "object",
                "additionalProperties": False,
                "required": list(_PIN_KEYS),
                "properties": {
                    "expected_canonical_sha256": dict(digest),
                    "matched": {"const": True},
                },
            },
            "gate_failures": {
                "type": "array",
                "maxItems": 2,
                "items": gate,
            },
            "validation": {
                "type": "object",
                "additionalProperties": False,
                "required": list(_VALIDATION_KEYS),
                "properties": {key: {"const": True} for key in _VALIDATION_KEYS},
            },
            "binding_sha256": dict(digest),
        },
        "allOf": [],
    }
    combinations = (
        (True, True, "release_authorized", True, []),
        (False, True, "not_authorized", False, ["routing_drc_manufacturing_not_ready"]),
        (True, False, "not_authorized", False, ["fabrication_not_authorized"]),
        (
            False,
            False,
            "not_authorized",
            False,
            ["routing_drc_manufacturing_not_ready", "fabrication_not_authorized"],
        ),
    )
    for ready, authorized, status, release, gates in combinations:
        report["allOf"].append(
            {
                "if": {
                    "properties": {
                        "routing_drc_manufacturing_ready": {"const": ready},
                        "fabrication_authorized": {"const": authorized},
                    },
                    "required": [
                        "routing_drc_manufacturing_ready",
                        "fabrication_authorized",
                    ],
                },
                "then": {
                    "properties": {
                        "status": {"const": status},
                        "release_authorized": {"const": release},
                        "gate_failures": {
                            "minItems": len(gates),
                            "maxItems": len(gates),
                            "prefixItems": [{"const": item} for item in gates],
                        },
                    }
                },
            }
        )
    return report


__all__ = [
    "MAXIMUM_ROUTING_DRC_FABRICATION_RELEASE_REPORT_BYTES",
    "RoutingDrcFabricationReleaseError",
    "evaluate_routing_drc_fabrication_release",
    "render_routing_drc_fabrication_release_report",
    "routing_drc_fabrication_release_report_json_schema",
]
