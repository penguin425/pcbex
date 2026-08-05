#!/usr/bin/env python3
"""Authenticate a normalized native KiCad PCB DRC evidence report.

The native DRC command intentionally leaves the complete JSON report in the
caller-provided evidence directory and emits only a compact summary on
stdout.  This helper is the second, independent side of that boundary: it
checks the report's closed schema, canonical ordering, source identities and
digest before the composite Action publishes any outputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ci_runtime import ExecutionBoundaryError, decode_utf8, read_bytes  # noqa: E402


BOARD_MAX_BYTES = 128 * 1024 * 1024
PROJECT_MAX_BYTES = 128 * 1024 * 1024
RULES_MAX_BYTES = 128 * 1024 * 1024
REPORT_MAX_BYTES = 32 * 1024 * 1024
SUMMARY_MAX_BYTES = 4 * 1024
MAX_TEXT_BYTES = 4096
MAX_VERSION_BYTES = 256
MAX_FINDINGS = 100_000
MAX_ITEMS_PER_FINDING = 1024
MAX_IGNORED_CHECKS = 1024
MAX_COORDINATE_NM = 1_000_000_000_000_000
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NATIVE_DRC_DOMAIN = b"pcbex/native-kicad-pcb-drc/v1\0"


REPORT_FIELDS = (
    "schema_version",
    "engine",
    "engine_version",
    "kicad_version",
    "source",
    "project",
    "rules_file",
    "invocation",
    "ignored_checks",
    "findings",
    "violation_count",
    "unconnected_item_count",
    "schematic_parity_count",
    "error_count",
    "warning_count",
    "approved",
    "run_sha256",
)
SUMMARY_FIELDS = (
    "schema_version",
    "approved",
    "violation_count",
    "unconnected_item_count",
    "schematic_parity_count",
    "error_count",
    "warning_count",
    "ignored_check_count",
    "run_sha256",
    "report_bytes",
    "report_sha256",
    "board_bytes",
    "board_sha256",
    "project_bytes",
    "project_sha256",
    "rules_file_bytes",
    "rules_file_sha256",
)


class SummaryValidationError(ValueError):
    """A malformed, unauthenticated or unsafe native DRC value."""


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


def _integer(value: Any, label: str, *, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise SummaryValidationError(f"{label} is not an integer from {minimum} through {maximum}")
    return value


def _sha(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return value
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
                raise SummaryValidationError(f"native KiCad DRC summary exceeds {SUMMARY_MAX_BYTES} bytes")
    except OSError as error:
        raise SummaryValidationError("could not read native KiCad DRC summary") from error
    return b"".join(chunks)


def _identity(value: Any, label: str, *, maximum: int, nullable: bool = False) -> dict[str, Any] | None:
    if nullable and value is None:
        return None
    _exact_object(value, ("bytes", "sha256"), label)
    _integer(value["bytes"], f"{label}.bytes", minimum=1, maximum=maximum)
    _sha(value["sha256"], f"{label}.sha256")
    return value


def _validate_invocation(value: Any) -> None:
    _exact_object(
        value,
        (
            "command",
            "format",
            "units",
            "severities",
            "exit_code_violations",
            "all_track_errors",
            "schematic_parity",
            "refill_zones",
            "save_board",
        ),
        "invocation",
    )
    for field in ("command", "format", "units"):
        _text(value[field], f"invocation.{field}")
    if (value["command"], value["format"], value["units"]) != ("pcb drc", "json", "mm"):
        raise SummaryValidationError("invocation is not the fixed native KiCad PCB DRC invocation")
    if value["severities"] != ["error", "warning"]:
        raise SummaryValidationError("invocation severities are not fixed")
    for index, severity in enumerate(value["severities"]):
        _text(severity, f"invocation.severities[{index}]")
    for field in ("exit_code_violations", "all_track_errors", "schematic_parity", "refill_zones", "save_board"):
        if type(value[field]) is not bool:
            raise SummaryValidationError(f"invocation.{field} must be boolean")
    if not value["exit_code_violations"]:
        raise SummaryValidationError("invocation.exit_code_violations must be true")
    if any(value[field] for field in ("all_track_errors", "schematic_parity", "refill_zones", "save_board")):
        raise SummaryValidationError("native KiCad DRC invocation must not enable side effects")


def _validate_ignored_checks(value: Any) -> None:
    if type(value) is not list or len(value) > MAX_IGNORED_CHECKS:
        raise SummaryValidationError("ignored_checks is not a bounded array")
    previous: tuple[str, str] | None = None
    seen_keys: set[str] = set()
    for index, item in enumerate(value):
        label = f"ignored_checks[{index}]"
        _exact_object(item, ("description", "key"), label)
        _text(item["description"], f"{label}.description")
        _text(item["key"], f"{label}.key")
        if item["key"] in seen_keys:
            raise SummaryValidationError("ignored_checks keys are not unique")
        seen_keys.add(item["key"])
        current = (item["key"], item["description"])
        if previous is not None and current <= previous:
            raise SummaryValidationError("ignored_checks are not canonically sorted")
        previous = current


def _validate_position(value: Any, label: str) -> None:
    _exact_object(value, ("x", "y"), label)
    _integer(value["x"], f"{label}.x", minimum=-MAX_COORDINATE_NM, maximum=MAX_COORDINATE_NM)
    _integer(value["y"], f"{label}.y", minimum=-MAX_COORDINATE_NM, maximum=MAX_COORDINATE_NM)


def _item_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (item["description"], item["position_nm"]["x"], item["position_nm"]["y"])


def _finding_sort_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        finding["category"],
        finding["severity"],
        finding["type"],
        finding["description"],
        tuple(_item_sort_key(item) for item in finding["items"]),
    )


def _validate_findings(value: Any) -> None:
    if type(value) is not list or len(value) > MAX_FINDINGS:
        raise SummaryValidationError("findings is not a bounded array")
    previous_finding: tuple[Any, ...] | None = None
    for finding_index, finding in enumerate(value):
        label = f"findings[{finding_index}]"
        # `type` is retained because it is the stable KiCad rule identifier;
        # UUIDs are deliberately omitted from normalized items.
        _exact_object(finding, ("category", "description", "items", "severity", "type"), label)
        _text(finding["category"], f"{label}.category")
        if finding["category"] not in ("violation", "unconnected-item", "schematic-parity"):
            raise SummaryValidationError(f"{label}.category is unsupported")
        _text(finding["description"], f"{label}.description")
        _text(finding["severity"], f"{label}.severity")
        if finding["severity"] not in ("error", "warning"):
            raise SummaryValidationError(f"{label}.severity is unsupported")
        _text(finding["type"], f"{label}.type")
        items = finding["items"]
        if type(items) is not list or len(items) > MAX_ITEMS_PER_FINDING:
            raise SummaryValidationError(f"{label}.items is not a bounded array")
        previous_item: tuple[Any, ...] | None = None
        for item_index, item in enumerate(items):
            item_label = f"{label}.items[{item_index}]"
            _exact_object(item, ("description", "position_nm"), item_label)
            _text(item["description"], f"{item_label}.description")
            _validate_position(item["position_nm"], f"{item_label}.position_nm")
            key = _item_sort_key(item)
            if previous_item is not None and key < previous_item:
                raise SummaryValidationError(f"{label}.items are not canonically sorted")
            previous_item = key
        key = _finding_sort_key(finding)
        if previous_finding is not None and key < previous_finding:
            raise SummaryValidationError("findings are not canonically sorted")
        previous_finding = key


def _canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if type(value) is float:
        if not math.isfinite(value):
            raise SummaryValidationError("non-finite value in native DRC identity")
        raise SummaryValidationError("floating-point value in native DRC identity")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if type(value) is list:
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    if type(value) is dict:
        return "{" + ",".join(
            json.dumps(key, ensure_ascii=False, separators=(",", ":")) + ":" + _canonical_json(item)
            for key, item in value.items()
        ) + "}"
    raise SummaryValidationError("unsupported value in native DRC identity")


def _identity_document(value: dict[str, Any]) -> dict[str, Any]:
    return {field: value[field] for field in REPORT_FIELDS if field != "run_sha256"}


def _run_sha256(value: dict[str, Any]) -> str:
    return hashlib.sha256(NATIVE_DRC_DOMAIN + _canonical_json(_identity_document(value)).encode("utf-8")).hexdigest()


def _canonical_report_bytes(value: dict[str, Any]) -> bytes:
    return (_canonical_json(value) + "\n").encode("utf-8")


def _validate_report(
    report: Any,
    *,
    board: bytes,
    project: bytes | None,
    rules_file: bytes | None,
    report_bytes: bytes,
) -> dict[str, Any]:
    _exact_object(report, REPORT_FIELDS, "native KiCad DRC report")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise SummaryValidationError("native KiCad DRC report schema_version must be 1")
    if report["engine"] != "pcbex":
        raise SummaryValidationError("native KiCad DRC report engine must be pcbex")
    _text(report["engine"], "engine")
    _text(report["engine_version"], "engine_version", maximum=MAX_VERSION_BYTES)
    _text(report["kicad_version"], "kicad_version", maximum=MAX_VERSION_BYTES)
    expected_source = {"bytes": len(board), "sha256": hashlib.sha256(board).hexdigest()}
    if _identity(report["source"], "source", maximum=BOARD_MAX_BYTES) != expected_source:
        raise SummaryValidationError("native KiCad DRC board source does not match board")
    expected_project = None if project is None else {"bytes": len(project), "sha256": hashlib.sha256(project).hexdigest()}
    expected_rules = None if rules_file is None else {"bytes": len(rules_file), "sha256": hashlib.sha256(rules_file).hexdigest()}
    if _identity(report["project"], "project", maximum=PROJECT_MAX_BYTES, nullable=True) != expected_project:
        raise SummaryValidationError("native KiCad DRC project source does not match project")
    if _identity(report["rules_file"], "rules_file", maximum=RULES_MAX_BYTES, nullable=True) != expected_rules:
        raise SummaryValidationError("native KiCad DRC rules source does not match rules file")
    _validate_invocation(report["invocation"])
    _validate_ignored_checks(report["ignored_checks"])
    _validate_findings(report["findings"])
    for field in (
        "violation_count",
        "unconnected_item_count",
        "schematic_parity_count",
        "error_count",
        "warning_count",
    ):
        _integer(report[field], field, maximum=MAX_FINDINGS)
    counts = {
        "violation": sum(f["category"] == "violation" for f in report["findings"]),
        "unconnected-item": sum(f["category"] == "unconnected-item" for f in report["findings"]),
        "schematic-parity": sum(f["category"] == "schematic-parity" for f in report["findings"]),
        "error": sum(f["severity"] == "error" for f in report["findings"]),
        "warning": sum(f["severity"] == "warning" for f in report["findings"]),
    }
    if report["violation_count"] != counts["violation"]:
        raise SummaryValidationError("violation_count does not match findings")
    if report["unconnected_item_count"] != counts["unconnected-item"]:
        raise SummaryValidationError("unconnected_item_count does not match findings")
    if report["schematic_parity_count"] != counts["schematic-parity"]:
        raise SummaryValidationError("schematic_parity_count does not match findings")
    if report["schematic_parity_count"] != 0:
        raise SummaryValidationError("schematic-parity findings are not accepted by the fixed invocation")
    if report["error_count"] != counts["error"] or report["warning_count"] != counts["warning"]:
        raise SummaryValidationError("severity counts do not match findings")
    if type(report["approved"]) is not bool:
        raise SummaryValidationError("approved is not boolean")
    if report["approved"] != (report["error_count"] == 0 and report["warning_count"] == 0):
        raise SummaryValidationError("approval does not match findings")
    _sha(report["run_sha256"], "run_sha256")
    if report["run_sha256"] != _run_sha256(report):
        raise SummaryValidationError("run_sha256 does not match report contents")
    if _canonical_report_bytes(report) != report_bytes:
        raise SummaryValidationError("native KiCad DRC report is not canonical Rust JSON")
    result: dict[str, Any] = {
        "schema_version": report["schema_version"],
        "approved": report["approved"],
        "violation_count": report["violation_count"],
        "unconnected_item_count": report["unconnected_item_count"],
        "schematic_parity_count": report["schematic_parity_count"],
        "error_count": report["error_count"],
        "warning_count": report["warning_count"],
        "ignored_check_count": len(report["ignored_checks"]),
        "board_bytes": len(board),
        "board_sha256": expected_source["sha256"],
        "project_bytes": "" if project is None else len(project),
        "project_sha256": "" if project is None else expected_project["sha256"],
        "rules_file_bytes": "" if rules_file is None else len(rules_file),
        "rules_file_sha256": "" if rules_file is None else expected_rules["sha256"],
        "run_sha256": report["run_sha256"],
        "report_bytes": len(report_bytes),
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }
    return result


def _verify_summary(summary: Any, expected: dict[str, Any]) -> dict[str, Any]:
    _exact_object(summary, SUMMARY_FIELDS, "native KiCad DRC summary")
    if summary != expected:
        for field in SUMMARY_FIELDS:
            if summary.get(field) != expected.get(field):
                raise SummaryValidationError(f"summary field {field} does not match retained report")
        raise SummaryValidationError("summary does not match retained report")
    return expected


def verify(
    board: str | Path,
    report: str | Path,
    project: str | Path | None = None,
    rules_file: str | Path | None = None,
) -> dict[str, Any]:
    summary = _parse_json(_read_summary_stdin(), role="native KiCad DRC summary")
    board_bytes = _stable_read(board, maximum=BOARD_MAX_BYTES, role="board")
    project_bytes = None if project is None else _stable_read(project, maximum=PROJECT_MAX_BYTES, role="project")
    rules_bytes = None if rules_file is None else _stable_read(rules_file, maximum=RULES_MAX_BYTES, role="rules file")
    report_bytes = _stable_read(report, maximum=REPORT_MAX_BYTES, role="retained native KiCad DRC report")
    report_value = _parse_json(report_bytes, role="retained native KiCad DRC report")
    expected = _validate_report(
        report_value,
        board=board_bytes,
        project=project_bytes,
        rules_file=rules_bytes,
        report_bytes=report_bytes,
    )
    return _verify_summary(summary, expected)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", required=True)
    parser.add_argument("--board", required=True, metavar="PATH")
    parser.add_argument("--report", required=True, metavar="PATH")
    parser.add_argument("--project", metavar="PATH")
    parser.add_argument("--rules-file", metavar="PATH")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = verify(args.board, args.report, args.project, args.rules_file)
        encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > SUMMARY_MAX_BYTES:
            raise SummaryValidationError("validated native KiCad DRC summary exceeds its byte bound")
        sys.stdout.write(encoded + "\n")
        return 0
    except (SummaryValidationError, ExecutionBoundaryError, OSError) as error:
        print(f"native KiCad DRC summary validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
