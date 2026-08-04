#!/usr/bin/env python3
"""Verify the bounded native KiCad ERC Action bridge.

``pcbex run-native-kicad-erc --mcp-echo-report-summary`` keeps the complete
normalized report on disk and emits a compact summary on stdout.  This helper
is the shell/Action trust boundary: it authenticates that summary against the
retained report, the schematic source, and (for schema v2) the warning policy
source before any Action output is published.

Verification mode emits one compact JSON object and no report contents.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
import sys
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ci_runtime import ExecutionBoundaryError, decode_utf8, read_bytes  # noqa: E402


SCHEMATIC_MAX_BYTES = 64 * 1024 * 1024
POLICY_MAX_BYTES = 1 * 1024 * 1024
REPORT_MAX_BYTES = 32 * 1024 * 1024
SUMMARY_MAX_BYTES = 4 * 1024
MAX_TEXT_BYTES = 4096
MAX_VERSION_BYTES = 256
MAX_UUID_BYTES = 128
MAX_IGNORED_CHECKS = 1024
MAX_FINDINGS = 100_000
MAX_ITEMS_PER_FINDING = 1024
MAX_POLICY_FAILURES = MAX_FINDINGS + MAX_IGNORED_CHECKS + 1
MAX_COORDINATE_MM = 1_000_000_000.0
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
WARNING_POLICY_DOMAIN = b"pcbex/native-kicad-erc-warning-policy/v1\0"
NATIVE_ERC_DOMAIN = b"pcbex/native-kicad-erc/v1\0"
NATIVE_ERC_WARNING_DOMAIN = b"pcbex/native-kicad-erc/v2\0"

V1_SUMMARY_FIELDS = (
    "schema_version",
    "approved",
    "error_count",
    "run_sha256",
    "report_bytes",
    "report_sha256",
)
V2_SUMMARY_FIELDS = (
    "schema_version",
    "approved",
    "error_count",
    "warning_count",
    "policy_failure_count",
    "run_sha256",
    "report_bytes",
    "report_sha256",
    "warning_policy_sha256",
    "warning_policy_source_bytes",
    "warning_policy_source_sha256",
)
BASE_REPORT_FIELDS = {
    "schema_version",
    "engine",
    "engine_version",
    "kicad_version",
    "source",
    "invocation",
    "ignored_checks",
    "findings",
    "error_count",
    "approved",
    "run_sha256",
}
POLICY_FIELDS = {
    "schema_version",
    "id",
    "maximum_total_warnings",
    "warning_limits",
    "allowed_ignored_checks",
}


class SummaryValidationError(ValueError):
    """A malformed, unauthenticated, or unsafe native ERC bridge value."""


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
        text = decode_utf8(payload, role=role)
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (ExecutionBoundaryError, SummaryValidationError) as error:
        raise SummaryValidationError(str(error)) from error
    except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError) as error:
        raise SummaryValidationError(f"{role} is not valid JSON") from error


def _exact_object(value: Any, fields: set[str] | tuple[str, ...], label: str) -> dict[str, Any]:
    expected = set(fields)
    if type(value) is not dict or set(value) != expected or len(value) != len(expected):
        raise SummaryValidationError(f"{label} must have exactly the closed key set {sorted(expected)!r}")
    return value


def _text(value: Any, label: str, *, maximum: int = MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SummaryValidationError(f"{label} is not bounded text")
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as error:
        raise SummaryValidationError(f"{label} is not valid UTF-8 text") from error
    if size > maximum:
        raise SummaryValidationError(f"{label} exceeds {maximum} UTF-8 bytes")
    return value


def _integer(value: Any, label: str, *, maximum: int, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if type(value) is not int or value < minimum or value > maximum:
        raise SummaryValidationError(f"{label} is not an integer from {minimum} through {maximum}")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise SummaryValidationError(f"{label} is not a lowercase SHA-256")
    return value


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
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > SUMMARY_MAX_BYTES:
                raise SummaryValidationError(f"native KiCad ERC summary exceeds {SUMMARY_MAX_BYTES} bytes")
    except OSError as error:
        raise SummaryValidationError("could not read native KiCad ERC summary") from error
    return b"".join(chunks)


def _source_identity(value: Any, label: str, *, maximum: int) -> dict[str, Any]:
    _exact_object(value, ("bytes", "sha256"), label)
    _integer(value["bytes"], f"{label}.bytes", maximum=maximum, positive=True)
    _sha(value["sha256"], f"{label}.sha256")
    return value


def _validate_invocation(value: Any, version: int) -> None:
    if version == 1:
        _exact_object(value, ("command", "format", "units", "severity", "exit_code_violations"), "invocation")
        for field in ("command", "format", "units", "severity"):
            _text(value[field], f"invocation.{field}")
        if (value["command"], value["format"], value["units"], value["severity"]) != (
            "sch erc",
            "json",
            "mm",
            "error",
        ):
            raise SummaryValidationError("v1 invocation is not the fixed native KiCad ERC invocation")
    else:
        _exact_object(value, ("command", "format", "units", "severities", "exit_code_violations"), "invocation")
        for field in ("command", "format", "units"):
            _text(value[field], f"invocation.{field}")
        if (value["command"], value["format"], value["units"]) != ("sch erc", "json", "mm"):
            raise SummaryValidationError("v2 invocation is not the fixed native KiCad ERC invocation")
        severities = value["severities"]
        if type(severities) is not list or severities != ["error", "warning"]:
            raise SummaryValidationError("v2 invocation severities are not fixed")
        for index, severity in enumerate(severities):
            _text(severity, f"invocation.severities[{index}]")
    if type(value["exit_code_violations"]) is not bool or not value["exit_code_violations"]:
        raise SummaryValidationError("invocation.exit_code_violations must be true")


def _validate_ignored_checks(value: Any) -> None:
    if type(value) is not list or len(value) > MAX_IGNORED_CHECKS:
        raise SummaryValidationError("ignored_checks is not a bounded array")
    for index, item in enumerate(value):
        _exact_object(item, ("description", "key"), f"ignored_checks[{index}]")
        _text(item["description"], f"ignored_checks[{index}].description")
        _text(item["key"], f"ignored_checks[{index}].key")


def _coordinate(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SummaryValidationError(f"{label} is not numeric")
    converted = float(value)
    if not math.isfinite(converted) or abs(converted) > MAX_COORDINATE_MM:
        raise SummaryValidationError(f"{label} is not finite or bounded")
    return converted


def _validate_findings(value: Any) -> None:
    if type(value) is not list or len(value) > MAX_FINDINGS:
        raise SummaryValidationError("findings is not a bounded array")
    for finding_index, finding in enumerate(value):
        label = f"findings[{finding_index}]"
        _exact_object(finding, ("description", "items", "severity", "sheet_path", "sheet_uuid_path", "type"), label)
        for field in ("description", "severity", "sheet_path", "type"):
            _text(finding[field], f"{label}.{field}")
        _text(finding["sheet_uuid_path"], f"{label}.sheet_uuid_path", maximum=MAX_UUID_BYTES)
        if finding["severity"] not in ("error", "warning"):
            raise SummaryValidationError(f"{label}.severity is unsupported")
        items = finding["items"]
        if type(items) is not list or len(items) > MAX_ITEMS_PER_FINDING:
            raise SummaryValidationError(f"{label}.items is not a bounded array")
        for item_index, item in enumerate(items):
            item_label = f"{label}.items[{item_index}]"
            _exact_object(item, ("description", "pos", "uuid"), item_label)
            _text(item["description"], f"{item_label}.description")
            _text(item["uuid"], f"{item_label}.uuid", maximum=MAX_UUID_BYTES)
            _exact_object(item["pos"], ("x", "y"), f"{item_label}.pos")
            _coordinate(item["pos"]["x"], f"{item_label}.pos.x")
            _coordinate(item["pos"]["y"], f"{item_label}.pos.y")


def _f64_total_key(value: float) -> int:
    """Return the IEEE-754 ordering used by Rust ``f64::total_cmp``."""

    bits = struct.unpack(">Q", struct.pack(">d", value))[0]
    if bits >> 63:
        return (~bits) & ((1 << 64) - 1)
    return bits | (1 << 63)


def _item_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        item["uuid"],
        item["description"],
        _f64_total_key(float(item["pos"]["x"])),
        _f64_total_key(float(item["pos"]["y"])),
    )


def _finding_sort_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        finding["sheet_path"],
        finding["sheet_uuid_path"],
        finding["type"],
        finding["severity"],
        finding["description"],
        tuple(_item_sort_key(item) for item in finding["items"]),
    )


def _validate_canonical_order(
    ignored: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    *,
    require_unique_ignored_keys: bool,
) -> None:
    ignored_keys = [item["key"] for item in ignored]
    if require_unique_ignored_keys and len(set(ignored_keys)) != len(ignored_keys):
        raise SummaryValidationError("native KiCad ERC warning ignored-check keys are not unique")
    ignored_order = [(item["key"], item["description"]) for item in ignored]
    if ignored_order != sorted(ignored_order):
        raise SummaryValidationError("native KiCad ERC warning ignored checks are not canonically sorted")
    for finding in findings:
        items = finding["items"]
        if items != sorted(items, key=_item_sort_key):
            raise SummaryValidationError("native KiCad ERC warning finding items are not canonically sorted")
    if findings != sorted(findings, key=_finding_sort_key):
        raise SummaryValidationError("native KiCad ERC warning findings are not canonically sorted")


def _canonical_policy(value: Any) -> bytes:
    _exact_object(value, POLICY_FIELDS, "warning_policy.policy")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise SummaryValidationError("warning policy schema_version must be 1")
    _text(value["id"], "warning_policy.policy.id")
    _integer(value["maximum_total_warnings"], "warning_policy.policy.maximum_total_warnings", maximum=MAX_FINDINGS)
    limits = value["warning_limits"]
    if type(limits) is not list or len(limits) > MAX_FINDINGS:
        raise SummaryValidationError("warning policy warning_limits is not bounded")
    previous: str | None = None
    for index, item in enumerate(limits):
        label = f"warning_policy.policy.warning_limits[{index}]"
        _exact_object(item, ("finding_type", "maximum_count"), label)
        _text(item["finding_type"], f"{label}.finding_type")
        _integer(item["maximum_count"], f"{label}.maximum_count", maximum=MAX_FINDINGS)
        if previous is not None and item["finding_type"] <= previous:
            raise SummaryValidationError("warning policy warning_limits are not sorted and unique")
        previous = item["finding_type"]
    ignored = value["allowed_ignored_checks"]
    if type(ignored) is not list or len(ignored) > MAX_IGNORED_CHECKS:
        raise SummaryValidationError("warning policy allowed_ignored_checks is not bounded")
    previous = None
    for index, item in enumerate(ignored):
        _text(item, f"warning_policy.policy.allowed_ignored_checks[{index}]")
        if previous is not None and item <= previous:
            raise SummaryValidationError("warning policy allowed_ignored_checks are not sorted and unique")
        previous = item
    ordered = {
        "schema_version": value["schema_version"],
        "id": value["id"],
        "maximum_total_warnings": value["maximum_total_warnings"],
        "warning_limits": [
            {"finding_type": item["finding_type"], "maximum_count": item["maximum_count"]}
            for item in limits
        ],
        "allowed_ignored_checks": list(ignored),
    }
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _validate_warning_counts(value: Any) -> None:
    if type(value) is not list or len(value) > MAX_FINDINGS:
        raise SummaryValidationError("warning_counts is not a bounded array")
    previous: str | None = None
    for index, item in enumerate(value):
        label = f"warning_counts[{index}]"
        _exact_object(item, ("finding_type", "count"), label)
        _text(item["finding_type"], f"{label}.finding_type")
        _integer(item["count"], f"{label}.count", maximum=MAX_FINDINGS, positive=True)
        if previous is not None and item["finding_type"] <= previous:
            raise SummaryValidationError("warning_counts are not sorted and unique")
        previous = item["finding_type"]


def _validate_policy_failures(value: Any) -> None:
    if type(value) is not list or len(value) > MAX_POLICY_FAILURES:
        raise SummaryValidationError("policy_failures is not a bounded array")
    for index, item in enumerate(value):
        label = f"policy_failures[{index}]"
        _exact_object(item, ("code", "subject", "actual_count", "maximum_count"), label)
        if item["code"] not in ("total", "type-not-allowed", "type-limit", "ignored-not-allowed"):
            raise SummaryValidationError(f"{label}.code is unsupported")
        _text(item["subject"], f"{label}.subject")
        _integer(item["actual_count"], f"{label}.actual_count", maximum=MAX_FINDINGS, positive=True)
        _integer(item["maximum_count"], f"{label}.maximum_count", maximum=MAX_FINDINGS)


def _canonical_float(value: float) -> str:
    if not math.isfinite(value):
        raise SummaryValidationError("native KiCad ERC identity contains a non-finite coordinate")
    rendered = repr(value)
    if "e" not in rendered and "E" not in rendered:
        return rendered
    mantissa, exponent_text = rendered.lower().split("e", 1)
    exponent = int(exponent_text)
    # serde_json's current zmij f64 formatter uses fixed notation through e-5;
    # e-6 and smaller use exponent notation. Keep this explicit so the Python
    # authentication bytes exactly match Rust's f64 serialization boundary.
    if -6 < exponent < 0:
        sign = ""
        if mantissa.startswith("-"):
            sign, mantissa = "-", mantissa[1:]
        digits = mantissa.replace(".", "")
        decimal_position = mantissa.find(".")
        if decimal_position < 0:
            decimal_position = len(mantissa)
        decimal_position += exponent
        if decimal_position <= 0:
            return f"{sign}0.{('0' * -decimal_position)}{digits}"
        if decimal_position >= len(digits):
            return f"{sign}{digits}{('0' * (decimal_position - len(digits)))}.0"
        return f"{sign}{digits[:decimal_position]}.{digits[decimal_position:]}"
    return f"{mantissa}e{exponent:+d}" if exponent >= 0 else f"{mantissa}e{exponent}"


def _canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if type(value) is float:
        return _canonical_float(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if type(value) is list:
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    if type(value) is dict:
        return "{" + ",".join(
            json.dumps(key, ensure_ascii=False, separators=(",", ":")) + ":" + _canonical_json(item)
            for key, item in value.items()
        ) + "}"
    raise SummaryValidationError("native KiCad ERC identity contains an unsupported JSON value")


def _v1_identity(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": value["schema_version"],
        "engine": value["engine"],
        "engine_version": value["engine_version"],
        "kicad_version": value["kicad_version"],
        "source": {"bytes": value["source"]["bytes"], "sha256": value["source"]["sha256"]},
        "invocation": {
            "command": value["invocation"]["command"],
            "format": value["invocation"]["format"],
            "units": value["invocation"]["units"],
            "severity": value["invocation"]["severity"],
            "exit_code_violations": value["invocation"]["exit_code_violations"],
        },
        "ignored_checks": [
            {"description": item["description"], "key": item["key"]}
            for item in value["ignored_checks"]
        ],
        "findings": [
            {
                "description": finding["description"],
                "items": [
                    {
                        "description": item["description"],
                        "pos": {"x": float(item["pos"]["x"]), "y": float(item["pos"]["y"])},
                        "uuid": item["uuid"],
                    }
                    for item in finding["items"]
                ],
                "severity": finding["severity"],
                "sheet_path": finding["sheet_path"],
                "sheet_uuid_path": finding["sheet_uuid_path"],
                "type": finding["type"],
            }
            for finding in value["findings"]
        ],
        "error_count": value["error_count"],
        "approved": value["approved"],
    }


def _v2_identity(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": value["schema_version"],
        "engine": value["engine"],
        "engine_version": value["engine_version"],
        "kicad_version": value["kicad_version"],
        "source": {"bytes": value["source"]["bytes"], "sha256": value["source"]["sha256"]},
        "invocation": {
            "command": value["invocation"]["command"],
            "format": value["invocation"]["format"],
            "units": value["invocation"]["units"],
            "severities": list(value["invocation"]["severities"]),
            "exit_code_violations": value["invocation"]["exit_code_violations"],
        },
        "ignored_checks": [
            {"description": item["description"], "key": item["key"]}
            for item in value["ignored_checks"]
        ],
        "findings": [
            {
                "description": finding["description"],
                "items": [
                    {
                        "description": item["description"],
                        "pos": {"x": float(item["pos"]["x"]), "y": float(item["pos"]["y"])},
                        "uuid": item["uuid"],
                    }
                    for item in finding["items"]
                ],
                "severity": finding["severity"],
                "sheet_path": finding["sheet_path"],
                "sheet_uuid_path": finding["sheet_uuid_path"],
                "type": finding["type"],
            }
            for finding in value["findings"]
        ],
        "error_count": value["error_count"],
        "warning_count": value["warning_count"],
        "warning_counts": [
            {"finding_type": item["finding_type"], "count": item["count"]}
            for item in value["warning_counts"]
        ],
        "warning_policy": {
            "source": {
                "bytes": value["warning_policy"]["source"]["bytes"],
                "sha256": value["warning_policy"]["source"]["sha256"],
            },
            "policy_sha256": value["warning_policy"]["policy_sha256"],
            "policy": {
                "schema_version": value["warning_policy"]["policy"]["schema_version"],
                "id": value["warning_policy"]["policy"]["id"],
                "maximum_total_warnings": value["warning_policy"]["policy"]["maximum_total_warnings"],
                "warning_limits": [
                    {"finding_type": item["finding_type"], "maximum_count": item["maximum_count"]}
                    for item in value["warning_policy"]["policy"]["warning_limits"]
                ],
                "allowed_ignored_checks": list(value["warning_policy"]["policy"]["allowed_ignored_checks"]),
            },
        },
        "policy_failures": [
            {
                "code": item["code"],
                "subject": item["subject"],
                "actual_count": item["actual_count"],
                "maximum_count": item["maximum_count"],
            }
            for item in value["policy_failures"]
        ],
        "approved": value["approved"],
    }


def _run_sha256(value: dict[str, Any], version: int) -> str:
    identity = _v1_identity(value) if version == 1 else _v2_identity(value)
    domain = NATIVE_ERC_DOMAIN if version == 1 else NATIVE_ERC_WARNING_DOMAIN
    return hashlib.sha256(domain + _canonical_json(identity).encode("utf-8")).hexdigest()


def _canonical_report_bytes(value: dict[str, Any], version: int) -> bytes:
    """Render the closed report in the same field order as Rust serde_json."""

    document = _v1_identity(value) if version == 1 else _v2_identity(value)
    document["run_sha256"] = value["run_sha256"]
    return (_canonical_json(document) + "\n").encode("utf-8")


def _expected_policy_failures(policy: dict[str, Any], ignored: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    limits = {item["finding_type"]: item["maximum_count"] for item in policy["warning_limits"]}
    warning_counts: dict[str, int] = {}
    for finding in findings:
        if finding["severity"] == "warning":
            warning_counts[finding["type"]] = warning_counts.get(finding["type"], 0) + 1
    failures: list[dict[str, Any]] = []
    total = sum(warning_counts.values())
    if total > policy["maximum_total_warnings"]:
        failures.append({"code": "total", "subject": "total_warnings", "actual_count": total, "maximum_count": policy["maximum_total_warnings"]})
    for finding_type, count in sorted(warning_counts.items()):
        maximum = limits.get(finding_type)
        if maximum is None:
            failures.append({"code": "type-not-allowed", "subject": finding_type, "actual_count": count, "maximum_count": 0})
        elif count > maximum:
            failures.append({"code": "type-limit", "subject": finding_type, "actual_count": count, "maximum_count": maximum})
    allowed = set(policy["allowed_ignored_checks"])
    for check in ignored:
        if check["key"] not in allowed:
            failures.append({"code": "ignored-not-allowed", "subject": check["key"], "actual_count": 1, "maximum_count": 0})
    failures.sort(key=lambda item: (item["code"], item["subject"], item["actual_count"], item["maximum_count"]))
    return failures


def _validate_report(report: Any, *, schematic: bytes, policy_bytes: bytes | None, report_bytes: bytes) -> dict[str, Any]:
    if type(report) is not dict:
        raise SummaryValidationError("retained native KiCad ERC report must be an object")
    version = report.get("schema_version")
    if type(version) is not int or version not in (1, 2):
        raise SummaryValidationError("native KiCad ERC report schema_version must be 1 or 2")
    expected_fields = BASE_REPORT_FIELDS if version == 1 else BASE_REPORT_FIELDS | {"warning_count", "warning_counts", "warning_policy", "policy_failures"}
    _exact_object(report, expected_fields, "native KiCad ERC report")
    for field in ("engine", "engine_version", "kicad_version"):
        _text(report[field], f"native KiCad ERC report.{field}", maximum=MAX_VERSION_BYTES if field != "engine" else MAX_TEXT_BYTES)
    if report["engine"] != "pcbex":
        raise SummaryValidationError("native KiCad ERC report engine must be pcbex")
    _source_identity(report["source"], "source", maximum=SCHEMATIC_MAX_BYTES)
    expected_source = {"bytes": len(schematic), "sha256": hashlib.sha256(schematic).hexdigest()}
    if report["source"] != expected_source:
        raise SummaryValidationError("native KiCad ERC report source does not match schematic")
    _validate_invocation(report["invocation"], version)
    _validate_ignored_checks(report["ignored_checks"])
    _validate_findings(report["findings"])
    _validate_canonical_order(
        report["ignored_checks"],
        report["findings"],
        require_unique_ignored_keys=version == 2,
    )
    if version == 1 and any(item["severity"] != "error" for item in report["findings"]):
        raise SummaryValidationError("v1 native KiCad ERC findings must be errors")
    _integer(report["error_count"], "error_count", maximum=MAX_FINDINGS)
    if type(report["approved"]) is not bool:
        raise SummaryValidationError("approved is not boolean")
    _sha(report["run_sha256"], "run_sha256")
    expected_errors = sum(item["severity"] == "error" for item in report["findings"])
    if report["error_count"] != expected_errors:
        raise SummaryValidationError("native KiCad ERC error_count does not match findings")
    if version == 1:
        if policy_bytes is not None:
            raise SummaryValidationError("schema-v1 native ERC reports cannot be used with a warning policy")
        if len(report["findings"]) != report["error_count"] or report["approved"] != (report["error_count"] == 0):
            raise SummaryValidationError("v1 native KiCad ERC approval does not match findings")
        if report["run_sha256"] != _run_sha256(report, version):
            raise SummaryValidationError("v1 native KiCad ERC run SHA-256 does not match its contents")
        if _canonical_report_bytes(report, version) != report_bytes:
            raise SummaryValidationError("v1 native KiCad ERC report is not canonical Rust JSON")
        return {
            "schema_version": 1,
            "approved": report["approved"],
            "error_count": report["error_count"],
            "run_sha256": report["run_sha256"],
            "report_bytes": len(report_bytes),
            "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        }

    if policy_bytes is None:
        raise SummaryValidationError("schema-v2 native ERC reports require a trusted warning policy")
    _integer(report["warning_count"], "warning_count", maximum=MAX_FINDINGS)
    _validate_warning_counts(report["warning_counts"])
    _validate_policy_failures(report["policy_failures"])
    expected_warnings = sum(item["severity"] == "warning" for item in report["findings"])
    if report["warning_count"] != expected_warnings:
        raise SummaryValidationError("v2 warning_count does not match findings")
    expected_counts: dict[str, int] = {}
    for finding in report["findings"]:
        if finding["severity"] == "warning":
            expected_counts[finding["type"]] = expected_counts.get(finding["type"], 0) + 1
    observed_counts = {item["finding_type"]: item["count"] for item in report["warning_counts"]}
    if observed_counts != expected_counts:
        raise SummaryValidationError("v2 warning_counts do not match findings")
    evidence = _exact_object(report["warning_policy"], ("source", "policy_sha256", "policy"), "warning_policy")
    _source_identity(evidence["source"], "warning_policy.source", maximum=POLICY_MAX_BYTES)
    _sha(evidence["policy_sha256"], "warning_policy.policy_sha256")
    policy_value = _parse_json(policy_bytes, role="trusted native KiCad ERC warning policy")
    trusted_policy_bytes = _canonical_policy(policy_value)
    if evidence["source"] != {"bytes": len(policy_bytes), "sha256": hashlib.sha256(policy_bytes).hexdigest()}:
        raise SummaryValidationError("native KiCad ERC warning policy source does not match trusted policy")
    _canonical_policy(evidence["policy"])
    if evidence["policy"] != policy_value:
        raise SummaryValidationError("native KiCad ERC warning policy does not match trusted policy")
    expected_policy_sha = hashlib.sha256(WARNING_POLICY_DOMAIN + trusted_policy_bytes).hexdigest()
    if evidence["policy_sha256"] != expected_policy_sha:
        raise SummaryValidationError("warning policy SHA-256 does not match its normalized contents")
    expected_failures = _expected_policy_failures(policy_value, report["ignored_checks"], report["findings"])
    if report["policy_failures"] != expected_failures:
        raise SummaryValidationError("warning policy failures do not match findings")
    if report["approved"] != (report["error_count"] == 0 and not report["policy_failures"]):
        raise SummaryValidationError("v2 approval does not match findings and policy failures")
    if report["run_sha256"] != _run_sha256(report, version):
        raise SummaryValidationError("v2 native KiCad ERC run SHA-256 does not match its contents")
    if _canonical_report_bytes(report, version) != report_bytes:
        raise SummaryValidationError("v2 native KiCad ERC report is not canonical Rust JSON")
    return {
        "schema_version": 2,
        "approved": report["approved"],
        "error_count": report["error_count"],
        "warning_count": report["warning_count"],
        "policy_failure_count": len(report["policy_failures"]),
        "run_sha256": report["run_sha256"],
        "report_bytes": len(report_bytes),
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "warning_policy_sha256": evidence["policy_sha256"],
        "warning_policy_source_bytes": evidence["source"]["bytes"],
        "warning_policy_source_sha256": evidence["source"]["sha256"],
    }


def _verify_summary(summary: Any, expected: dict[str, Any]) -> dict[str, Any]:
    if type(summary) is not dict:
        raise SummaryValidationError("native KiCad ERC summary must be an object")
    version = summary.get("schema_version")
    if type(version) is not int or version not in (1, 2):
        raise SummaryValidationError("summary schema_version must be 1 or 2")
    fields = V1_SUMMARY_FIELDS if version == 1 else V2_SUMMARY_FIELDS
    _exact_object(summary, fields, "native KiCad ERC summary")
    for key, value in expected.items():
        if summary.get(key) != value:
            raise SummaryValidationError(f"summary field {key} does not match retained report")
    return expected


def verify(schematic: str | Path, report: str | Path, policy: str | Path | None = None) -> dict[str, Any]:
    summary = _parse_json(_read_summary_stdin(), role="native KiCad ERC summary")
    schematic_bytes = _stable_read(schematic, maximum=SCHEMATIC_MAX_BYTES, role="schematic")
    policy_bytes = None if policy is None else _stable_read(policy, maximum=POLICY_MAX_BYTES, role="warning policy")
    report_bytes = _stable_read(report, maximum=REPORT_MAX_BYTES, role="retained native KiCad ERC report")
    report_value = _parse_json(report_bytes, role="retained native KiCad ERC report")
    expected = _validate_report(report_value, schematic=schematic_bytes, policy_bytes=policy_bytes, report_bytes=report_bytes)
    return _verify_summary(summary, expected)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", required=True)
    parser.add_argument("--schematic", required=True, metavar="PATH")
    parser.add_argument("--report", required=True, metavar="PATH")
    parser.add_argument("--warning-policy", metavar="PATH")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = verify(args.schematic, args.report, args.warning_policy)
        encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > SUMMARY_MAX_BYTES:
            raise SummaryValidationError("validated native KiCad ERC summary exceeds its byte bound")
        sys.stdout.write(encoded + "\n")
        return 0
    except (SummaryValidationError, ExecutionBoundaryError, OSError) as error:
        print(f"native KiCad ERC summary validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
