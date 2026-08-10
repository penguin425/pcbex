#!/usr/bin/env python3
"""Authenticate the fabrication-authorization Action's compact bridge.

The Rust verifier is the authority that freshly replays the input artifacts
and verifies every Ed25519 approval.  This helper deliberately does not claim
to perform that work again.  It verifies that the verifier's closed 23-field
stdout summary describes the exact, bounded retained report bytes and that the
report is internally closed and semantically correspondent before an Action
publishes outputs.

Only the authenticated compact summary is written to stdout.  Policy content,
signed approvals, reasons, tickets, and the full retained report stay on disk.
"""

from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ci_runtime import ExecutionBoundaryError, decode_utf8, read_bytes  # noqa: E402


MIB = 1024 * 1024
REPORT_MAX_BYTES = 128 * MIB
SUMMARY_MAX_BYTES = 4 * 1024
PLAN_MAX_BYTES = 4 * MIB
PIPELINE_REPORT_MAX_BYTES = 128 * MIB
MANUFACTURING_PACKAGE_MAX_BYTES = 128 * MIB
FACTORY_RECEIPT_MAX_BYTES = 64 * MIB
POLICY_PACK_MAX_BYTES = 64 * MIB
MAXIMUM_APPROVALS = 100
MAXIMUM_QUANTITY = 1_000_000
MAXIMUM_TOTAL_MINOR_UNITS = 9_007_199_254_740_991
MAXIMUM_VALIDITY_SECONDS = 604_800
MAXIMUM_GATE_FAILURES = 4
U32_MAX = 2**32 - 1
U64_MAX = 2**64 - 1
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SIGNATURE_RE = re.compile(r"^[0-9a-f]{128}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")

SUMMARY_FIELDS = (
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
REPORT_FIELDS = (
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
EVIDENCE_FIELDS = ("pipeline", "manufacturing_package", "factory_receipt", "policy_pack")
PIPELINE_FIELDS = ("plan_source", "plan_sha256", "retained_report", "run_sha256")
FACTORY_FIELDS = (
    "receipt",
    "provider",
    "endpoint",
    "quote_sha256",
    "quote_authenticity_verified",
)
POLICY_EVIDENCE_FIELDS = ("source", "canonical_sha256", "id", "revision")
SCOPE_FIELDS = (
    "authorization_id",
    "challenge",
    "quantity",
    "currency",
    "maximum_total_minor_units",
    "valid_from_unix",
    "expires_at_unix",
)
MEMBER_FIELDS = ("signer_id", "public_key", "approval_sha256", "decision", "reason", "ticket")
SIGNED_APPROVAL_FIELDS = (
    "schema_version",
    "evidence",
    "scope",
    "decision",
    "reason",
    "ticket",
    "signer_id",
    "algorithm",
    "public_key",
    "signature",
)
POLICY_FIELDS = (
    "schema_version",
    "id",
    "revision",
    "verified_on",
    "description",
    "dfm_profile",
    "electrical_policy",
    "ai_requirements",
    "require_simulation_evidence",
    "trusted_approval_keys",
    "fabrication_authorization_policy",
)
POLICY_OPTIONAL_FIELDS = ("trusted_human_escalation_keys",)
DFM_FIELDS = (
    "schema_version",
    "id",
    "aliases",
    "revision",
    "verified_on",
    "description",
    "source_urls",
    "rules",
)
DFM_RULE_FIELDS = (
    "minimum_track_width_nm",
    "minimum_clearance_nm",
    "minimum_drill_nm",
    "minimum_annular_ring_nm",
    "minimum_copper_to_edge_nm",
    "board_thickness_nm",
    "maximum_via_aspect_ratio",
    "minimum_drill_to_drill_nm",
    "allow_via_in_pad",
    "minimum_trace_angle_deg",
)
ELECTRICAL_RULES = frozenset(
    {
        "coverage_incomplete",
        "duplicate_reference_unit",
        "unannotated_reference",
        "missing_footprint",
        "no_connect_connected",
        "pin_type_no_connect_connected",
        "unconnected_pin",
        "multiple_output_drivers",
        "multiple_power_outputs",
        "power_input_not_driven",
        "input_not_driven",
        "multiple_net_names",
        "invalid_power_metadata",
        "power_rail_voltage_conflict",
        "power_input_voltage_exceeded",
        "missing_decoupling_capacitor",
    }
)
ELECTRICAL_SAFETY_FLOOR = frozenset(
    ELECTRICAL_RULES
    - {
        "missing_footprint",
        "unconnected_pin",
        "input_not_driven",
        "multiple_net_names",
    }
)


class SummaryValidationError(ValueError):
    """A malformed or unauthenticated fabrication summary/report value."""


def _reject_constant(value: str) -> Any:
    raise SummaryValidationError(f"non-standard JSON number {value!r}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SummaryValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_json(payload: bytes, *, role: str) -> Any:
    try:
        return json.loads(
            decode_utf8(payload, role=role),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (ExecutionBoundaryError, SummaryValidationError) as error:
        raise SummaryValidationError(str(error)) from error
    except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError) as error:
        raise SummaryValidationError(f"{role} is not valid JSON") from error


def _exact_object(value: Any, fields: tuple[str, ...], label: str) -> dict[str, Any]:
    expected = set(fields)
    if type(value) is not dict or len(value) != len(expected) or set(value) != expected:
        raise SummaryValidationError(
            f"{label} must have exactly the closed key set {sorted(expected)!r}"
        )
    return value


def _object_with_optional(
    value: Any,
    required: tuple[str, ...],
    optional: tuple[str, ...],
    label: str,
) -> dict[str, Any]:
    if type(value) is not dict:
        raise SummaryValidationError(f"{label} must be an object")
    keys = set(value)
    required_keys = set(required)
    optional_keys = set(optional)
    if not required_keys <= keys or not keys <= required_keys | optional_keys:
        raise SummaryValidationError(f"{label} does not have its closed key set")
    return value


def _integer(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = U64_MAX,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SummaryValidationError(
            f"{label} must be an integer from {minimum} through {maximum}"
        )
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise SummaryValidationError(f"{label} must be a boolean")
    return value


def _utf8_size(value: str, label: str) -> int:
    try:
        return len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as error:
        raise SummaryValidationError(f"{label} is not valid UTF-8 text") from error


def _text(
    value: Any,
    label: str,
    *,
    maximum: int,
    nonblank: bool = True,
) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise SummaryValidationError(f"{label} is not bounded text")
    if (nonblank and not value.strip()) or _utf8_size(value, label) > maximum:
        raise SummaryValidationError(f"{label} is not bounded text")
    return value


def _unbounded_text(value: Any, label: str, *, nonblank: bool = True) -> str:
    if not isinstance(value, str) or (nonblank and not value.strip()):
        raise SummaryValidationError(f"{label} must be text")
    _utf8_size(value, label)
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise SummaryValidationError(f"{label} must be a lowercase SHA-256")
    return value


def _slug(value: Any, label: str) -> str:
    if not isinstance(value, str) or SLUG_RE.fullmatch(value) is None:
        raise SummaryValidationError(f"{label} must be a bounded lowercase identifier")
    return value


def _date(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 10:
        raise SummaryValidationError(f"{label} must be a YYYY-MM-DD date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise SummaryValidationError(f"{label} must be a YYYY-MM-DD date") from error
    if parsed.isoformat() != value or parsed.year == 0:
        raise SummaryValidationError(f"{label} must be a YYYY-MM-DD date")
    return value


def _canonical_bytes(value: Any, label: str) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as error:
        raise SummaryValidationError(f"could not canonicalize {label}") from error


def _ordered(value: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: value[field] for field in fields}


def _identity(value: Any, label: str, *, maximum: int) -> dict[str, Any]:
    _exact_object(value, ("bytes", "sha256"), label)
    _integer(value["bytes"], f"{label}.bytes", minimum=1, maximum=maximum)
    _sha(value["sha256"], f"{label}.sha256")
    return value


def _ordered_identity(value: dict[str, Any]) -> dict[str, Any]:
    return _ordered(value, ("bytes", "sha256"))


def _validate_endpoint(value: Any, label: str) -> str:
    endpoint = _text(value, label, maximum=2048)
    if any(ord(character) < 128 and character.isspace() for character in endpoint):
        raise SummaryValidationError(f"{label} must be a bounded HTTPS endpoint")
    if any(ord(character) < 32 or ord(character) == 127 for character in endpoint):
        raise SummaryValidationError(f"{label} must be a bounded HTTPS endpoint")
    if not endpoint.startswith("https://"):
        raise SummaryValidationError(f"{label} must use HTTPS")
    authority = endpoint[len("https://") :].split("/", 1)[0]
    if not authority or "@" in authority:
        raise SummaryValidationError(f"{label} has an invalid authority")
    return endpoint


def _validate_evidence(value: Any, label: str = "evidence") -> dict[str, Any]:
    _exact_object(value, EVIDENCE_FIELDS, label)
    pipeline = value["pipeline"]
    _exact_object(pipeline, PIPELINE_FIELDS, f"{label}.pipeline")
    _identity(
        pipeline["plan_source"],
        f"{label}.pipeline.plan_source",
        maximum=PLAN_MAX_BYTES,
    )
    _sha(pipeline["plan_sha256"], f"{label}.pipeline.plan_sha256")
    _identity(
        pipeline["retained_report"],
        f"{label}.pipeline.retained_report",
        maximum=PIPELINE_REPORT_MAX_BYTES,
    )
    _sha(pipeline["run_sha256"], f"{label}.pipeline.run_sha256")
    _identity(
        value["manufacturing_package"],
        f"{label}.manufacturing_package",
        maximum=MANUFACTURING_PACKAGE_MAX_BYTES,
    )

    receipt = value["factory_receipt"]
    _exact_object(receipt, FACTORY_FIELDS, f"{label}.factory_receipt")
    _identity(
        receipt["receipt"],
        f"{label}.factory_receipt.receipt",
        maximum=FACTORY_RECEIPT_MAX_BYTES,
    )
    if receipt["provider"] not in ("jlcpcb", "pcbway", "generic"):
        raise SummaryValidationError(f"{label}.factory_receipt.provider is unsupported")
    _validate_endpoint(receipt["endpoint"], f"{label}.factory_receipt.endpoint")
    _sha(receipt["quote_sha256"], f"{label}.factory_receipt.quote_sha256")
    if _boolean(
        receipt["quote_authenticity_verified"],
        f"{label}.factory_receipt.quote_authenticity_verified",
    ):
        raise SummaryValidationError("factory quote authenticity must remain false")

    policy = value["policy_pack"]
    _exact_object(policy, POLICY_EVIDENCE_FIELDS, f"{label}.policy_pack")
    _identity(
        policy["source"],
        f"{label}.policy_pack.source",
        maximum=POLICY_PACK_MAX_BYTES,
    )
    _sha(policy["canonical_sha256"], f"{label}.policy_pack.canonical_sha256")
    _slug(policy["id"], f"{label}.policy_pack.id")
    _integer(policy["revision"], f"{label}.policy_pack.revision", minimum=1, maximum=U32_MAX)
    return value


def _ordered_evidence(value: dict[str, Any]) -> dict[str, Any]:
    pipeline = value["pipeline"]
    receipt = value["factory_receipt"]
    policy = value["policy_pack"]
    return {
        "pipeline": {
            "plan_source": _ordered_identity(pipeline["plan_source"]),
            "plan_sha256": pipeline["plan_sha256"],
            "retained_report": _ordered_identity(pipeline["retained_report"]),
            "run_sha256": pipeline["run_sha256"],
        },
        "manufacturing_package": _ordered_identity(value["manufacturing_package"]),
        "factory_receipt": {
            "receipt": _ordered_identity(receipt["receipt"]),
            "provider": receipt["provider"],
            "endpoint": receipt["endpoint"],
            "quote_sha256": receipt["quote_sha256"],
            "quote_authenticity_verified": receipt["quote_authenticity_verified"],
        },
        "policy_pack": {
            "source": _ordered_identity(policy["source"]),
            "canonical_sha256": policy["canonical_sha256"],
            "id": policy["id"],
            "revision": policy["revision"],
        },
    }


def _validate_scope(value: Any, label: str = "scope") -> int:
    _exact_object(value, SCOPE_FIELDS, label)
    _slug(value["authorization_id"], f"{label}.authorization_id")
    _sha(value["challenge"], f"{label}.challenge")
    _integer(value["quantity"], f"{label}.quantity", minimum=1, maximum=MAXIMUM_QUANTITY)
    currency = value["currency"]
    if (
        not isinstance(currency, str)
        or len(currency) != 3
        or not currency.isascii()
        or not currency.isupper()
        or not currency.isalpha()
    ):
        raise SummaryValidationError(f"{label}.currency must be three uppercase ASCII letters")
    _integer(
        value["maximum_total_minor_units"],
        f"{label}.maximum_total_minor_units",
        minimum=1,
        maximum=MAXIMUM_TOTAL_MINOR_UNITS,
    )
    start = _integer(value["valid_from_unix"], f"{label}.valid_from_unix")
    end = _integer(value["expires_at_unix"], f"{label}.expires_at_unix")
    duration = end - start
    if not 1 <= duration <= MAXIMUM_VALIDITY_SECONDS:
        raise SummaryValidationError(f"{label} validity window is outside its closed bounds")
    return duration


def _ordered_scope(value: dict[str, Any]) -> dict[str, Any]:
    return _ordered(value, SCOPE_FIELDS)


def _validate_dfm_profile(value: Any) -> None:
    _exact_object(value, DFM_FIELDS, "policy_pack.dfm_profile")
    if _integer(value["schema_version"], "policy_pack.dfm_profile.schema_version") != 1:
        raise SummaryValidationError("policy_pack.dfm_profile.schema_version must be 1")
    profile_id = _slug(value["id"], "policy_pack.dfm_profile.id")
    aliases = value["aliases"]
    if type(aliases) is not list or len(aliases) > 64:
        raise SummaryValidationError("policy_pack.dfm_profile.aliases is not a bounded array")
    names = {profile_id}
    for index, alias in enumerate(aliases):
        name = _slug(alias, f"policy_pack.dfm_profile.aliases[{index}]")
        if name in names:
            raise SummaryValidationError("policy_pack.dfm_profile names are not unique")
        names.add(name)
    _integer(value["revision"], "policy_pack.dfm_profile.revision", minimum=1, maximum=U32_MAX)
    _date(value["verified_on"], "policy_pack.dfm_profile.verified_on")
    _text(value["description"], "policy_pack.dfm_profile.description", maximum=1024)
    urls = value["source_urls"]
    if type(urls) is not list or not 1 <= len(urls) <= 32:
        raise SummaryValidationError("policy_pack.dfm_profile.source_urls is not a bounded array")
    seen_urls: set[str] = set()
    for index, raw_url in enumerate(urls):
        url = _text(raw_url, f"policy_pack.dfm_profile.source_urls[{index}]", maximum=2048)
        authority = url.removeprefix("https://").split("/", 1)[0]
        if (
            not url.startswith("https://")
            or not authority
            or any(ord(character) < 128 and character.isspace() for character in url)
            or url in seen_urls
        ):
            raise SummaryValidationError("policy_pack.dfm_profile.source_urls is invalid")
        seen_urls.add(url)

    rules = value["rules"]
    _exact_object(rules, DFM_RULE_FIELDS, "policy_pack.dfm_profile.rules")
    positive = (
        "minimum_track_width_nm",
        "minimum_drill_nm",
        "minimum_annular_ring_nm",
        "board_thickness_nm",
    )
    nonnegative = (
        "minimum_clearance_nm",
        "minimum_copper_to_edge_nm",
        "minimum_drill_to_drill_nm",
    )
    for field in positive:
        _integer(rules[field], f"policy_pack.dfm_profile.rules.{field}", minimum=1, maximum=10**12)
    for field in nonnegative:
        _integer(rules[field], f"policy_pack.dfm_profile.rules.{field}", maximum=10**12)
    _integer(
        rules["maximum_via_aspect_ratio"],
        "policy_pack.dfm_profile.rules.maximum_via_aspect_ratio",
        minimum=1,
        maximum=100,
    )
    _boolean(rules["allow_via_in_pad"], "policy_pack.dfm_profile.rules.allow_via_in_pad")
    _integer(
        rules["minimum_trace_angle_deg"],
        "policy_pack.dfm_profile.rules.minimum_trace_angle_deg",
        maximum=180,
    )


def _ordered_dfm(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": value["schema_version"],
        "id": value["id"],
        "aliases": value["aliases"],
        "revision": value["revision"],
        "verified_on": value["verified_on"],
        "description": value["description"],
        "source_urls": value["source_urls"],
        "rules": _ordered(value["rules"], DFM_RULE_FIELDS),
    }


def _validate_electrical_policy(value: Any) -> None:
    _exact_object(value, ("schema_version", "id", "rules"), "policy_pack.electrical_policy")
    if _integer(value["schema_version"], "policy_pack.electrical_policy.schema_version") != 1:
        raise SummaryValidationError("policy_pack.electrical_policy.schema_version must be 1")
    _unbounded_text(value["id"], "policy_pack.electrical_policy.id")
    rules = value["rules"]
    if type(rules) is not dict or not set(rules) <= ELECTRICAL_RULES:
        raise SummaryValidationError("policy_pack.electrical_policy.rules is not closed")
    for rule_id, setting in rules.items():
        _exact_object(setting, ("enabled", "severity"), f"electrical rule {rule_id}")
        enabled = _boolean(setting["enabled"], f"electrical rule {rule_id}.enabled")
        severity = setting["severity"]
        if severity not in ("info", "warning", "error"):
            raise SummaryValidationError(f"electrical rule {rule_id}.severity is unsupported")
        if rule_id in ELECTRICAL_SAFETY_FLOOR and (not enabled or severity != "error"):
            raise SummaryValidationError(f"electrical rule {rule_id} weakens the safety floor")


def _ordered_electrical(value: dict[str, Any]) -> dict[str, Any]:
    rules = {
        rule_id: _ordered(value["rules"][rule_id], ("enabled", "severity"))
        for rule_id in sorted(value["rules"])
    }
    return {"schema_version": value["schema_version"], "id": value["id"], "rules": rules}


def _validate_trusted_keys(value: Any, label: str, *, minimum: int) -> dict[str, str]:
    if type(value) is not list or not minimum <= len(value) <= MAXIMUM_APPROVALS:
        raise SummaryValidationError(f"{label} is not a bounded array")
    signers: dict[str, str] = {}
    public_keys: set[str] = set()
    for index, trusted in enumerate(value):
        item_label = f"{label}[{index}]"
        _exact_object(trusted, ("signer_id", "public_key"), item_label)
        signer = _slug(trusted["signer_id"], f"{item_label}.signer_id")
        key = _sha(trusted["public_key"], f"{item_label}.public_key")
        if signer in signers or key in public_keys:
            raise SummaryValidationError(f"{label} contains duplicate signers or keys")
        signers[signer] = key
        public_keys.add(key)
    return signers


def _validate_policy_pack(value: Any, evidence: dict[str, Any]) -> dict[str, str]:
    _object_with_optional(value, POLICY_FIELDS, POLICY_OPTIONAL_FIELDS, "policy_pack")
    if _integer(value["schema_version"], "policy_pack.schema_version") != 1:
        raise SummaryValidationError("policy_pack.schema_version must be 1")
    _slug(value["id"], "policy_pack.id")
    _integer(value["revision"], "policy_pack.revision", minimum=1, maximum=U32_MAX)
    _date(value["verified_on"], "policy_pack.verified_on")
    _text(value["description"], "policy_pack.description", maximum=1024)
    _validate_dfm_profile(value["dfm_profile"])
    _validate_electrical_policy(value["electrical_policy"])

    requirements = value["ai_requirements"]
    if type(requirements) is not list or not 1 <= len(requirements) <= 1000:
        raise SummaryValidationError("policy_pack.ai_requirements is not a bounded array")
    requirement_ids: set[str] = set()
    for index, requirement in enumerate(requirements):
        label = f"policy_pack.ai_requirements[{index}]"
        _exact_object(requirement, ("id", "text"), label)
        requirement_id = _slug(requirement["id"], f"{label}.id")
        _text(requirement["text"], f"{label}.text", maximum=4096)
        if requirement_id in requirement_ids:
            raise SummaryValidationError("policy_pack.ai_requirements IDs are not unique")
        requirement_ids.add(requirement_id)
    _boolean(value["require_simulation_evidence"], "policy_pack.require_simulation_evidence")

    ai_keys = _validate_trusted_keys(
        value["trusted_approval_keys"], "policy_pack.trusted_approval_keys", minimum=1
    )
    all_signers = set(ai_keys)
    all_keys = set(ai_keys.values())
    human = value.get("trusted_human_escalation_keys", [])
    human_keys = _validate_trusted_keys(
        human, "policy_pack.trusted_human_escalation_keys", minimum=0
    )
    if all_signers & set(human_keys) or all_keys & set(human_keys.values()):
        raise SummaryValidationError("policy_pack trust roles overlap")
    all_signers.update(human_keys)
    all_keys.update(human_keys.values())

    fabrication = value["fabrication_authorization_policy"]
    _exact_object(
        fabrication,
        ("minimum_approvals", "maximum_validity_seconds", "trusted_keys"),
        "policy_pack.fabrication_authorization_policy",
    )
    minimum = _integer(
        fabrication["minimum_approvals"],
        "policy_pack.fabrication_authorization_policy.minimum_approvals",
        minimum=2,
        maximum=MAXIMUM_APPROVALS,
    )
    _integer(
        fabrication["maximum_validity_seconds"],
        "policy_pack.fabrication_authorization_policy.maximum_validity_seconds",
        minimum=1,
        maximum=MAXIMUM_VALIDITY_SECONDS,
    )
    fabrication_keys = _validate_trusted_keys(
        fabrication["trusted_keys"],
        "policy_pack.fabrication_authorization_policy.trusted_keys",
        minimum=2,
    )
    if minimum > len(fabrication_keys):
        raise SummaryValidationError("fabrication minimum approvals exceeds trusted keys")
    if all_signers & set(fabrication_keys) or all_keys & set(fabrication_keys.values()):
        raise SummaryValidationError("policy_pack fabrication trust overlaps another role")

    policy_evidence = evidence["policy_pack"]
    if value["id"] != policy_evidence["id"] or value["revision"] != policy_evidence["revision"]:
        raise SummaryValidationError("retained policy does not match its nested evidence identity")
    canonical = _canonical_bytes(_ordered_policy(value), "organization policy pack")
    if hashlib.sha256(canonical).hexdigest() != policy_evidence["canonical_sha256"]:
        raise SummaryValidationError("retained policy canonical digest does not match evidence")
    return fabrication_keys


def _ordered_trusted_keys(value: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_ordered(item, ("signer_id", "public_key")) for item in value]


def _ordered_policy(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": value["schema_version"],
        "id": value["id"],
        "revision": value["revision"],
        "verified_on": value["verified_on"],
        "description": value["description"],
        "dfm_profile": _ordered_dfm(value["dfm_profile"]),
        "electrical_policy": _ordered_electrical(value["electrical_policy"]),
        "ai_requirements": [
            _ordered(requirement, ("id", "text")) for requirement in value["ai_requirements"]
        ],
        "require_simulation_evidence": value["require_simulation_evidence"],
        "trusted_approval_keys": _ordered_trusted_keys(value["trusted_approval_keys"]),
    }
    human = value.get("trusted_human_escalation_keys", [])
    if human:
        result["trusted_human_escalation_keys"] = _ordered_trusted_keys(human)
    fabrication = value["fabrication_authorization_policy"]
    result["fabrication_authorization_policy"] = {
        "minimum_approvals": fabrication["minimum_approvals"],
        "maximum_validity_seconds": fabrication["maximum_validity_seconds"],
        "trusted_keys": _ordered_trusted_keys(fabrication["trusted_keys"]),
    }
    return result


def _ordered_signed_approval(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": value["schema_version"],
        "evidence": _ordered_evidence(value["evidence"]),
        "scope": _ordered_scope(value["scope"]),
        "decision": value["decision"],
        "reason": value["reason"],
        "ticket": value["ticket"],
        "signer_id": value["signer_id"],
        "algorithm": value["algorithm"],
        "public_key": value["public_key"],
        "signature": value["signature"],
    }


def _validate_signed_approval(
    value: Any,
    *,
    index: int,
    evidence: dict[str, Any],
    scope: dict[str, Any],
    trusted_keys: dict[str, str],
) -> dict[str, Any]:
    label = f"signed_approvals[{index}]"
    _exact_object(value, SIGNED_APPROVAL_FIELDS, label)
    if _integer(value["schema_version"], f"{label}.schema_version") != 1:
        raise SummaryValidationError(f"{label}.schema_version must be 1")
    _validate_evidence(value["evidence"], f"{label}.evidence")
    _validate_scope(value["scope"], f"{label}.scope")
    if value["evidence"] != evidence or value["scope"] != scope:
        raise SummaryValidationError(f"{label} does not bind the common evidence and scope")
    if value["decision"] not in ("approve", "reject"):
        raise SummaryValidationError(f"{label}.decision is unsupported")
    _text(value["reason"], f"{label}.reason", maximum=4096)
    _text(value["ticket"], f"{label}.ticket", maximum=256)
    signer = _slug(value["signer_id"], f"{label}.signer_id")
    if value["algorithm"] != "ed25519":
        raise SummaryValidationError(f"{label}.algorithm must be ed25519")
    public_key = _sha(value["public_key"], f"{label}.public_key")
    if not isinstance(value["signature"], str) or SIGNATURE_RE.fullmatch(value["signature"]) is None:
        raise SummaryValidationError(f"{label}.signature must be lowercase Ed25519 signature hex")
    if trusted_keys.get(signer) != public_key:
        raise SummaryValidationError(f"{label} signer/key is not retained fabrication trust")
    return value


def _expected_gate_failures(
    scope: dict[str, Any],
    *,
    duration: int,
    policy: dict[str, Any],
    approvals: int,
    rejections: int,
    evaluated_at_unix: int,
) -> list[str]:
    failures: list[str] = []
    maximum = policy["maximum_validity_seconds"]
    if duration > maximum:
        failures.append(
            f"fabrication_validity_exceeds_policy:maximum_seconds={maximum}:actual_seconds={duration}"
        )
    if not scope["valid_from_unix"] <= evaluated_at_unix <= scope["expires_at_unix"]:
        failures.append("approval_window_inactive")
    minimum = policy["minimum_approvals"]
    if approvals < minimum:
        failures.append(
            f"insufficient_fabrication_approvals:required={minimum}:actual={approvals}"
        )
    if rejections:
        failures.append(f"human_rejection:count={rejections}")
    return sorted(failures)


def _validate_summary_shape(value: Any) -> dict[str, Any]:
    summary = _exact_object(value, SUMMARY_FIELDS, "fabrication authorization summary")
    if _integer(summary["schema_version"], "summary.schema_version") != 1:
        raise SummaryValidationError("summary.schema_version must be 1")
    if summary["status"] not in ("fabrication_authorized", "not_authorized"):
        raise SummaryValidationError("summary.status is unsupported")
    authorized = _boolean(summary["fabrication_authorized"], "summary.fabrication_authorized")
    _slug(summary["authorization_id"], "summary.authorization_id")
    _sha(summary["challenge"], "summary.challenge")
    _integer(summary["quantity"], "summary.quantity", minimum=1, maximum=MAXIMUM_QUANTITY)
    currency = summary["currency"]
    if (
        not isinstance(currency, str)
        or len(currency) != 3
        or not currency.isascii()
        or not currency.isalpha()
        or not currency.isupper()
    ):
        raise SummaryValidationError("summary.currency must be three uppercase ASCII letters")
    _integer(
        summary["maximum_total_minor_units"],
        "summary.maximum_total_minor_units",
        minimum=1,
        maximum=MAXIMUM_TOTAL_MINOR_UNITS,
    )
    start = _integer(summary["valid_from_unix"], "summary.valid_from_unix")
    end = _integer(summary["expires_at_unix"], "summary.expires_at_unix")
    if not 1 <= end - start <= MAXIMUM_VALIDITY_SECONDS:
        raise SummaryValidationError("summary validity window is outside its closed bounds")
    _integer(summary["evaluated_at_unix"], "summary.evaluated_at_unix")
    approvals = _integer(
        summary["approvals"], "summary.approvals", maximum=MAXIMUM_APPROVALS
    )
    rejections = _integer(
        summary["rejections"], "summary.rejections", maximum=MAXIMUM_APPROVALS
    )
    if not 1 <= approvals + rejections <= MAXIMUM_APPROVALS:
        raise SummaryValidationError("summary approval count is outside its closed bounds")
    failure_count = _integer(
        summary["gate_failure_count"],
        "summary.gate_failure_count",
        maximum=MAXIMUM_GATE_FAILURES,
    )
    for field in (
        "plan_sha256",
        "run_sha256",
        "manufacturing_package_sha256",
        "factory_receipt_sha256",
        "policy_pack_sha256",
        "report_sha256",
    ):
        _sha(summary[field], f"summary.{field}")
    if _boolean(summary["quote_authenticity_verified"], "summary.quote_authenticity_verified"):
        raise SummaryValidationError("summary.quote_authenticity_verified must be false")
    if _boolean(
        summary["challenge_one_time_use_enforced"],
        "summary.challenge_one_time_use_enforced",
    ):
        raise SummaryValidationError("summary.challenge_one_time_use_enforced must be false")
    _integer(
        summary["report_bytes"],
        "summary.report_bytes",
        minimum=1,
        maximum=REPORT_MAX_BYTES,
    )
    expected_status = "fabrication_authorized" if authorized else "not_authorized"
    if (
        summary["status"] != expected_status
        or authorized != (failure_count == 0)
        or (authorized and rejections != 0)
    ):
        raise SummaryValidationError("summary status, counts, and authorization disagree")
    return summary


def _validate_report(value: Any, report_bytes: bytes) -> dict[str, Any]:
    report = _exact_object(value, REPORT_FIELDS, "retained fabrication authorization report")
    if _integer(report["schema_version"], "report.schema_version") != 1:
        raise SummaryValidationError("report.schema_version must be 1")
    if report["status"] not in ("fabrication_authorized", "not_authorized"):
        raise SummaryValidationError("report.status is unsupported")
    evidence = _validate_evidence(report["evidence"])
    scope = report["scope"]
    duration = _validate_scope(scope)
    trusted_keys = _validate_policy_pack(report["policy_pack"], evidence)
    evaluated = _integer(report["evaluated_at_unix"], "report.evaluated_at_unix")
    reported_approvals = _integer(
        report["approvals"], "report.approvals", maximum=MAXIMUM_APPROVALS
    )
    reported_rejections = _integer(
        report["rejections"], "report.rejections", maximum=MAXIMUM_APPROVALS
    )
    authorized = _boolean(report["fabrication_authorized"], "report.fabrication_authorized")
    if _boolean(
        report["challenge_one_time_use_enforced"],
        "report.challenge_one_time_use_enforced",
    ):
        raise SummaryValidationError("report challenge one-time-use claim must remain false")

    signed = report["signed_approvals"]
    members = report["members"]
    if type(signed) is not list or not 1 <= len(signed) <= MAXIMUM_APPROVALS:
        raise SummaryValidationError("report.signed_approvals is not a bounded array")
    if type(members) is not list or len(members) != len(signed):
        raise SummaryValidationError("report.members does not correspond to signed approvals")
    actual_approvals = 0
    signer_ids: set[str] = set()
    public_keys: set[str] = set()
    previous_signer: str | None = None
    for index, approval in enumerate(signed):
        _validate_signed_approval(
            approval,
            index=index,
            evidence=evidence,
            scope=scope,
            trusted_keys=trusted_keys,
        )
        signer = approval["signer_id"]
        key = approval["public_key"]
        if previous_signer is not None and signer <= previous_signer:
            raise SummaryValidationError("report.signed_approvals is not signer-sorted")
        if signer in signer_ids or key in public_keys:
            raise SummaryValidationError("report.signed_approvals is not independent")
        previous_signer = signer
        signer_ids.add(signer)
        public_keys.add(key)
        actual_approvals += int(approval["decision"] == "approve")

        member = members[index]
        _exact_object(member, MEMBER_FIELDS, f"members[{index}]")
        expected_member = {
            "signer_id": signer,
            "public_key": key,
            "approval_sha256": hashlib.sha256(
                _canonical_bytes(_ordered_signed_approval(approval), f"signed approval {index}")
            ).hexdigest(),
            "decision": approval["decision"],
            "reason": approval["reason"],
            "ticket": approval["ticket"],
        }
        if member != expected_member:
            raise SummaryValidationError(f"members[{index}] does not match its signed approval")

    actual_rejections = len(signed) - actual_approvals
    if (
        reported_approvals != actual_approvals
        or reported_rejections != actual_rejections
        or reported_approvals + reported_rejections != len(signed)
    ):
        raise SummaryValidationError("report approval counts do not match signed decisions")

    failures = report["gate_failures"]
    if type(failures) is not list or len(failures) > MAXIMUM_GATE_FAILURES:
        raise SummaryValidationError("report.gate_failures is not a bounded array")
    for index, failure in enumerate(failures):
        _text(failure, f"report.gate_failures[{index}]", maximum=4096)
    expected_failures = _expected_gate_failures(
        scope,
        duration=duration,
        policy=report["policy_pack"]["fabrication_authorization_policy"],
        approvals=actual_approvals,
        rejections=actual_rejections,
        evaluated_at_unix=evaluated,
    )
    expected_authorized = not expected_failures
    expected_status = "fabrication_authorized" if expected_authorized else "not_authorized"
    if (
        failures != expected_failures
        or authorized != expected_authorized
        or report["status"] != expected_status
    ):
        raise SummaryValidationError("report gate status does not match its retained semantics")

    return {
        "schema_version": report["schema_version"],
        "status": report["status"],
        "fabrication_authorized": authorized,
        "authorization_id": scope["authorization_id"],
        "challenge": scope["challenge"],
        "quantity": scope["quantity"],
        "currency": scope["currency"],
        "maximum_total_minor_units": scope["maximum_total_minor_units"],
        "valid_from_unix": scope["valid_from_unix"],
        "expires_at_unix": scope["expires_at_unix"],
        "evaluated_at_unix": evaluated,
        "approvals": reported_approvals,
        "rejections": reported_rejections,
        "gate_failure_count": len(failures),
        "plan_sha256": evidence["pipeline"]["plan_sha256"],
        "run_sha256": evidence["pipeline"]["run_sha256"],
        "manufacturing_package_sha256": evidence["manufacturing_package"]["sha256"],
        "factory_receipt_sha256": evidence["factory_receipt"]["receipt"]["sha256"],
        "policy_pack_sha256": evidence["policy_pack"]["source"]["sha256"],
        "quote_authenticity_verified": evidence["factory_receipt"][
            "quote_authenticity_verified"
        ],
        "challenge_one_time_use_enforced": report["challenge_one_time_use_enforced"],
        "report_bytes": len(report_bytes),
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }


def _stable_read(path: str | Path, *, maximum: int, role: str) -> bytes:
    try:
        first = read_bytes(path, max_bytes=maximum)
        second = read_bytes(path, max_bytes=maximum)
    except OSError as error:
        raise SummaryValidationError(f"invalid {role}: {error}") from error
    if first != second:
        raise SummaryValidationError(f"{role} changed between bounded reads")
    return first


def _read_summary_stdin() -> bytes:
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = sys.stdin.buffer.read(SUMMARY_MAX_BYTES + 1 - total)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > SUMMARY_MAX_BYTES:
                raise SummaryValidationError(
                    f"fabrication authorization summary exceeds {SUMMARY_MAX_BYTES} bytes"
                )
    except OSError as error:
        raise SummaryValidationError("could not read fabrication authorization summary") from error


def verify(report: str | Path) -> dict[str, Any]:
    """Authenticate stdin's compact summary against one retained report."""

    summary_bytes = _read_summary_stdin()
    summary_value = _parse_json(summary_bytes, role="fabrication authorization summary")
    summary = _validate_summary_shape(summary_value)
    try:
        canonical_summary = (
            json.dumps(
                {field: summary[field] for field in SUMMARY_FIELDS},
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as error:
        raise SummaryValidationError("fabrication authorization summary is not compact JSON") from error
    if summary_bytes != canonical_summary:
        raise SummaryValidationError(
            "fabrication authorization summary must be one compact JSON object followed by one LF"
        )
    retained = _stable_read(
        report,
        maximum=REPORT_MAX_BYTES,
        role="retained fabrication authorization report",
    )
    expected = _validate_report(
        _parse_json(retained, role="retained fabrication authorization report"), retained
    )
    for field in SUMMARY_FIELDS:
        if summary[field] != expected[field] or type(summary[field]) is not type(expected[field]):
            raise SummaryValidationError(f"summary field {field} does not match retained report")
    return {field: expected[field] for field in SUMMARY_FIELDS}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", required=True)
    parser.add_argument("--report", required=True, metavar="PATH")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = verify(args.report)
        encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > SUMMARY_MAX_BYTES:
            raise SummaryValidationError("validated fabrication summary exceeds its byte bound")
        sys.stdout.write(encoded + "\n")
        return 0
    except (SummaryValidationError, ExecutionBoundaryError, OSError) as error:
        print(f"fabrication authorization summary validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
