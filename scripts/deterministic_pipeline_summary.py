#!/usr/bin/env python3
"""Validate the bounded deterministic-pipeline Action bridge.

The Rust runner retains the complete report and prints only a compact summary
when ``--mcp-echo-report-summary`` is selected.  This helper is the Action
boundary for that bridge: it validates the caller-supplied plan path before a
runner is started, then authenticates the summary against the retained report
before the shell publishes any Action outputs.  It also authenticates the
five-field summary emitted by the closed intent compiler.

No report bytes are written to stdout.  Verification mode emits only the
validated seven-field summary as one compact JSON object.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ci_runtime import (  # noqa: E402
    ExecutionBoundaryError,
    decode_utf8,
    read_bytes,
    validate_relative_input_file,
    validate_relative_output_root,
)


PLAN_MAX_BYTES = 4 * 1024 * 1024
REPORT_MAX_BYTES = 128 * 1024 * 1024
SUMMARY_MAX_BYTES = 4 * 1024
MAX_FAILURE_COUNT = 128
MAX_PLAN_PATH_CHARS = 4096
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PORTABLE_PATH_PUNCTUATION = set(":/\\*?<>\"|")
RESERVED_WINDOWS_STEMS = {"CON", "PRN", "AUX", "NUL"}
SUMMARY_FIELDS = (
    "schema_version",
    "approved",
    "plan_sha256",
    "run_sha256",
    "failure_count",
    "report_bytes",
    "report_sha256",
)
COMPILE_SUMMARY_FIELDS = (
    "schema_version",
    "intent_source_bytes",
    "intent_source_sha256",
    "plan_source_bytes",
    "plan_source_sha256",
)
PLAN_FIELDS = (
    "schema_version",
    "circuit_spec",
    "schematic",
    "electrical_policy",
    "electrical_review",
    "board",
    "analysis_manifest",
    "analysis_checks",
    "quality",
    "analysis_project",
    "analysis_rules",
    "analysis_dfm_profile",
    "analysis_policy_pack",
    "analysis_physical_profile",
    "manufacturing_package",
    "firmware_manifest",
    "factory_receipt",
    "require_factory",
)
OPTIONAL_PLAN_FIELDS = {
    "electrical_policy",
    "analysis_project",
    "analysis_rules",
    "analysis_dfm_profile",
    "analysis_policy_pack",
    "analysis_physical_profile",
    "factory_receipt",
}
DESCRIPTOR_FIELDS = ("path", "bytes", "sha256")


class SummaryValidationError(ValueError):
    """A malformed or unauthenticated deterministic-pipeline bridge value."""


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


def _is_lowercase_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _require_bool(value: Any, *, field: str) -> bool:
    if type(value) is not bool:
        raise SummaryValidationError(f"{field} must be a boolean")
    return value


def _require_int(value: Any, *, field: str, minimum: int, maximum: int) -> int:
    # bool is an int subclass, but accepting it would make the compact bridge
    # ambiguous and would not match the Rust Value::as_u64 checks.
    if type(value) is not int or not minimum <= value <= maximum:
        raise SummaryValidationError(
            f"{field} must be an integer from {minimum} through {maximum}"
        )
    return value


def _portable_plan_path(raw: str | os.PathLike[str]) -> Path:
    """Resolve one workspace-relative plan without following links."""

    try:
        spelling = os.fspath(raw)
    except TypeError as error:
        raise SummaryValidationError("deterministic pipeline plan path must be text") from error
    if isinstance(spelling, bytes):
        raise SummaryValidationError("deterministic pipeline plan path must be UTF-8 text")
    try:
        spelling.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise SummaryValidationError(
            "deterministic pipeline plan path must be valid UTF-8 text"
        ) from error
    if not spelling or len(spelling) > MAX_PLAN_PATH_CHARS:
        raise SummaryValidationError(
            f"deterministic pipeline plan path must contain 1 through {MAX_PLAN_PATH_CHARS} characters"
        )
    for segment in spelling.split("/"):
        if any(ord(character) < 32 or ord(character) == 127 for character in segment):
            raise SummaryValidationError(
                f"deterministic pipeline plan path contains a control character: {segment!r}"
            )
        if any(character in PORTABLE_PATH_PUNCTUATION for character in segment):
            raise SummaryValidationError(
                f"deterministic pipeline plan path contains a non-portable segment: {segment!r}"
            )
        try:
            segment_bytes = len(segment.encode("utf-8", errors="strict"))
        except UnicodeEncodeError as error:
            raise SummaryValidationError(
                f"deterministic pipeline plan path segment is not valid UTF-8: {segment!r}"
            ) from error
        if segment_bytes > 255:
            raise SummaryValidationError(
                f"deterministic pipeline plan path segment exceeds 255 bytes: {segment!r}"
            )
        if segment.endswith((" ", ".")):
            raise SummaryValidationError(
                f"deterministic pipeline plan path segment ends in a space or dot: {segment!r}"
            )
        device_stem = segment.split(".", 1)[0].rstrip(" .").upper()
        numbered_device = (
            len(device_stem) == 4
            and device_stem[:3] in {"COM", "LPT"}
            and device_stem[3] in "123456789"
        )
        if device_stem in RESERVED_WINDOWS_STEMS or numbered_device:
            raise SummaryValidationError(
                f"deterministic pipeline plan path uses a reserved Windows device name: {segment!r}"
            )
    try:
        return validate_relative_output_root(raw, base=Path.cwd())
    except (ExecutionBoundaryError, OSError, ValueError, TypeError) as error:
        raise SummaryValidationError(f"invalid deterministic pipeline plan path: {error}") from error


def _portable_intent_path(raw: str | os.PathLike[str]) -> Path:
    """Resolve one workspace-relative regular intent without following links."""

    try:
        # Reuse the compiler's portable spelling checks (length, reserved
        # device names, separators, and component punctuation) before the
        # regular-file check, so Action inputs cannot be accepted here and
        # rejected later by the Rust compiler for a different reason.
        _portable_plan_path(raw)
        return validate_relative_input_file(raw, base=Path.cwd())
    except (ExecutionBoundaryError, OSError, ValueError, TypeError) as error:
        raise SummaryValidationError(f"invalid deterministic pipeline intent path: {error}") from error


def validate_plan(path: str | os.PathLike[str]) -> Path:
    """Validate a plan's portable path, regular-file identity, and byte bound."""

    resolved = _portable_plan_path(path)
    try:
        # read_bytes performs a race-aware lstat/open/fstat/lstat sequence.  It
        # rejects direct and ancestor symlinks, Windows reparse points, and
        # every non-regular file while enforcing the 4 MiB ceiling.
        read_bytes(resolved, max_bytes=PLAN_MAX_BYTES)
    except OSError as error:
        raise SummaryValidationError(
            f"invalid deterministic pipeline plan file: {error}"
        ) from error
    return resolved


def validate_intent(path: str | os.PathLike[str]) -> Path:
    """Validate one portable workspace-relative regular intent source."""

    resolved = _portable_intent_path(path)
    try:
        read_bytes(resolved, max_bytes=PLAN_MAX_BYTES)
    except OSError as error:
        raise SummaryValidationError(
            f"invalid deterministic pipeline intent file: {error}"
        ) from error
    return resolved


def validate_compile_output(path: str | os.PathLike[str]) -> Path:
    """Validate a new portable plan destination and reject stale output."""

    resolved = _portable_plan_path(path)
    try:
        os.lstat(resolved)
    except FileNotFoundError:
        return resolved
    except OSError as error:
        raise SummaryValidationError(
            f"could not inspect deterministic pipeline plan output: {error}"
        ) from error
    raise SummaryValidationError(
        f"refusing to overwrite existing deterministic pipeline plan output: {resolved}"
    )


def _read_report(path: str | os.PathLike[str]) -> bytes:
    try:
        return read_bytes(path, max_bytes=REPORT_MAX_BYTES)
    except OSError as error:
        raise SummaryValidationError(
            f"invalid retained deterministic pipeline report: {error}"
        ) from error


def _read_stable(path: Path, *, max_bytes: int, role: str) -> bytes:
    """Read one bounded source twice and reject a concurrent replacement."""

    try:
        first = read_bytes(path, max_bytes=max_bytes)
        second = read_bytes(path, max_bytes=max_bytes)
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
                raise SummaryValidationError(
                    f"deterministic pipeline summary exceeds {SUMMARY_MAX_BYTES} bytes"
                )
    except OSError as error:
        raise SummaryValidationError("could not read deterministic pipeline summary") from error
    return b"".join(chunks)


def _expected_source_identity(
    expected_bytes: Any,
    expected_sha256: Any,
    *,
    label: str,
) -> tuple[int, str] | None:
    """Validate one optional compiler-authenticated source identity."""

    if (expected_bytes is None) != (expected_sha256 is None):
        raise SummaryValidationError(
            f"expected {label} bytes and SHA-256 must be supplied together"
        )
    if expected_bytes is None:
        return None
    if isinstance(expected_bytes, str):
        if not re.fullmatch(r"[0-9]+", expected_bytes):
            raise SummaryValidationError(
                f"expected {label} bytes must be a positive decimal integer"
            )
        try:
            expected_bytes = int(expected_bytes, 10)
        except ValueError as error:
            raise SummaryValidationError(
                f"expected {label} bytes must be a positive decimal integer"
            ) from error
    expected_bytes = _require_int(
        expected_bytes,
        field=f"expected {label} bytes",
        minimum=1,
        maximum=PLAN_MAX_BYTES,
    )
    if not _is_lowercase_sha256(expected_sha256):
        raise SummaryValidationError(
            f"expected {label} SHA-256 must be lowercase hexadecimal SHA-256"
        )
    return expected_bytes, expected_sha256


def _verify_summary(
    summary: Any,
    report: Any,
    report_bytes: bytes,
    *,
    expected_plan_source: tuple[int, str] | None = None,
) -> dict[str, Any]:
    if not isinstance(summary, dict):
        raise SummaryValidationError("deterministic pipeline summary must be a JSON object")
    if set(summary) != set(SUMMARY_FIELDS) or len(summary) != len(SUMMARY_FIELDS):
        raise SummaryValidationError("deterministic pipeline summary fields are not exact")

    schema_version = _require_int(
        summary["schema_version"], field="schema_version", minimum=1, maximum=1
    )
    approved = _require_bool(summary["approved"], field="approved")
    plan_sha256 = summary["plan_sha256"]
    run_sha256 = summary["run_sha256"]
    report_sha256 = summary["report_sha256"]
    if not _is_lowercase_sha256(plan_sha256):
        raise SummaryValidationError("plan_sha256 must be lowercase hexadecimal SHA-256")
    if not _is_lowercase_sha256(run_sha256):
        raise SummaryValidationError("run_sha256 must be lowercase hexadecimal SHA-256")
    if not _is_lowercase_sha256(report_sha256):
        raise SummaryValidationError("report_sha256 must be lowercase hexadecimal SHA-256")
    failure_count = _require_int(
        summary["failure_count"],
        field="failure_count",
        minimum=0,
        maximum=MAX_FAILURE_COUNT,
    )
    expected_report_bytes = _require_int(
        summary["report_bytes"],
        field="report_bytes",
        minimum=1,
        maximum=REPORT_MAX_BYTES,
    )

    if len(report_bytes) != expected_report_bytes:
        raise SummaryValidationError("retained report byte count does not match summary")
    if hashlib.sha256(report_bytes).hexdigest() != report_sha256:
        raise SummaryValidationError("retained report SHA-256 does not match summary")
    if not isinstance(report, dict):
        raise SummaryValidationError("retained deterministic pipeline report must be an object")

    report_schema = report.get("schema_version")
    if type(report_schema) is not int or report_schema != schema_version:
        raise SummaryValidationError("retained report schema_version does not match summary")
    if type(report.get("approved")) is not bool or report["approved"] != approved:
        raise SummaryValidationError("retained report approved value does not match summary")
    if report.get("plan_sha256") != plan_sha256 or not _is_lowercase_sha256(
        report.get("plan_sha256")
    ):
        raise SummaryValidationError("retained report plan_sha256 does not match summary")
    if report.get("run_sha256") != run_sha256 or not _is_lowercase_sha256(
        report.get("run_sha256")
    ):
        raise SummaryValidationError("retained report run_sha256 does not match summary")
    failures = report.get("failures")
    if not isinstance(failures, list) or len(failures) != failure_count:
        raise SummaryValidationError("retained report failures count does not match summary")
    if approved != (failure_count == 0):
        raise SummaryValidationError("approved must be true exactly when failure_count is zero")
    if expected_plan_source is not None:
        expected_plan_source_bytes, expected_plan_source_sha256 = expected_plan_source
        report_plan_source_bytes = report.get("plan_source_bytes")
        if (
            type(report_plan_source_bytes) is not int
            or report_plan_source_bytes != expected_plan_source_bytes
        ):
            raise SummaryValidationError(
                "retained report plan source byte count does not match compiler metadata"
            )
        report_plan_source_sha256 = report.get("plan_source_sha256")
        if report_plan_source_sha256 != expected_plan_source_sha256:
            raise SummaryValidationError(
                "retained report plan source SHA-256 does not match compiler metadata"
            )

    return {
        "schema_version": schema_version,
        "approved": approved,
        "plan_sha256": plan_sha256,
        "run_sha256": run_sha256,
        "failure_count": failure_count,
        "report_bytes": expected_report_bytes,
        "report_sha256": report_sha256,
    }


def verify(
    plan: str | os.PathLike[str],
    report: str | os.PathLike[str],
    *,
    intent: str | os.PathLike[str] | None = None,
    expected_intent_source_bytes: Any = None,
    expected_intent_source_sha256: Any = None,
    expected_plan_source_bytes: Any = None,
    expected_plan_source_sha256: Any = None,
) -> dict[str, Any]:
    """Validate plan and authenticate summary stdin against the retained report."""

    # Read stdin to EOF before opening the retained report.  The Action pipes
    # the bounded supervisor directly into this verifier; EOF therefore means
    # the runner has finished atomically publishing (or rejecting) its report.
    summary = _parse_json(_read_summary_stdin(), role="deterministic pipeline summary")
    expected_values = (
        expected_intent_source_bytes,
        expected_intent_source_sha256,
        expected_plan_source_bytes,
        expected_plan_source_sha256,
    )
    if any(value is not None for value in expected_values) and not all(
        value is not None for value in expected_values
    ):
        raise SummaryValidationError(
            "expected compiler source bytes and SHA-256 values must be supplied as one complete group"
        )
    if (intent is None) != (not all(value is not None for value in expected_values)):
        raise SummaryValidationError(
            "compiler source expectations require an intent path and one complete source-identity group"
        )
    expected_intent_source = _expected_source_identity(
        expected_intent_source_bytes,
        expected_intent_source_sha256,
        label="intent source",
    )
    expected_plan_source = _expected_source_identity(
        expected_plan_source_bytes,
        expected_plan_source_sha256,
        label="plan source",
    )
    if expected_intent_source is None:
        validate_plan(plan)
    else:
        if intent is None:
            raise SummaryValidationError(
                "compiler source expectations require an intent path"
            )
        intent_path = _portable_intent_path(intent)
        intent_bytes = _read_stable(
            intent_path,
            max_bytes=PLAN_MAX_BYTES,
            role="deterministic pipeline intent",
        )
        expected_intent_bytes, expected_intent_sha256 = expected_intent_source
        if len(intent_bytes) != expected_intent_bytes:
            raise SummaryValidationError(
                "current deterministic pipeline intent byte count does not match compiler metadata"
            )
        if hashlib.sha256(intent_bytes).hexdigest() != expected_intent_sha256:
            raise SummaryValidationError(
                "current deterministic pipeline intent SHA-256 does not match compiler metadata"
            )
    if expected_plan_source is not None:
        plan_path = _portable_plan_path(plan)
        plan_bytes = _read_stable(
            plan_path,
            max_bytes=PLAN_MAX_BYTES,
            role="deterministic pipeline plan",
        )
        expected_plan_bytes, expected_plan_sha256 = expected_plan_source
        if len(plan_bytes) != expected_plan_bytes:
            raise SummaryValidationError(
                "current deterministic pipeline plan byte count does not match compiler metadata"
            )
        if hashlib.sha256(plan_bytes).hexdigest() != expected_plan_sha256:
            raise SummaryValidationError(
                "current deterministic pipeline plan SHA-256 does not match compiler metadata"
            )
    report_bytes = _read_report(report)
    report_value = _parse_json(report_bytes, role="retained deterministic pipeline report")
    return _verify_summary(
        summary,
        report_value,
        report_bytes,
        expected_plan_source=expected_plan_source,
    )


def _canonical_descriptor(value: Any, *, role: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(DESCRIPTOR_FIELDS):
        raise SummaryValidationError(f"compiled {role} descriptor fields are not exact")
    path = value["path"]
    if not isinstance(path, str) or not path:
        raise SummaryValidationError(f"compiled {role} descriptor path is invalid")
    bytes_value = value["bytes"]
    if type(bytes_value) is not int or bytes_value <= 0:
        raise SummaryValidationError(f"compiled {role} descriptor bytes is invalid")
    sha256 = value["sha256"]
    if not _is_lowercase_sha256(sha256):
        raise SummaryValidationError(
            f"compiled {role} descriptor SHA-256 is not lowercase hexadecimal"
        )
    return {
        "path": path,
        "bytes": bytes_value,
        "sha256": sha256,
    }


def _canonical_plan(payload: bytes) -> dict[str, Any]:
    """Parse and require the exact canonical plan-v1 JSON emitted by Rust."""

    if not payload.endswith(b"\n") or payload.endswith(b"\n\n"):
        raise SummaryValidationError(
            "compiled deterministic pipeline plan must end with one trailing newline"
        )
    value = _parse_json(payload, role="compiled deterministic pipeline plan")
    if not isinstance(value, dict) or set(value) != set(PLAN_FIELDS):
        raise SummaryValidationError("compiled deterministic pipeline plan fields are not exact")
    if _require_int(value["schema_version"], field="plan schema_version", minimum=1, maximum=1) != 1:
        raise SummaryValidationError("compiled deterministic pipeline plan schema_version is invalid")
    if type(value["require_factory"]) is not bool:
        raise SummaryValidationError("compiled deterministic pipeline plan require_factory is invalid")

    canonical: dict[str, Any] = {
        "schema_version": 1,
    }
    for role in PLAN_FIELDS[1:-1]:
        descriptor = value[role]
        if role in OPTIONAL_PLAN_FIELDS and descriptor is None:
            canonical[role] = None
        else:
            canonical[role] = _canonical_descriptor(descriptor, role=role)
    canonical["require_factory"] = value["require_factory"]
    expected = json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if expected + b"\n" != payload:
        raise SummaryValidationError(
            "compiled deterministic pipeline plan is not canonical JSON"
        )
    return canonical


def _verify_compile_summary(summary: Any, intent_bytes: bytes, plan_bytes: bytes) -> dict[str, Any]:
    if not isinstance(summary, dict):
        raise SummaryValidationError("compiler summary must be a JSON object")
    if set(summary) != set(COMPILE_SUMMARY_FIELDS) or len(summary) != len(COMPILE_SUMMARY_FIELDS):
        raise SummaryValidationError("compiler summary fields are not exact")
    schema_version = _require_int(
        summary["schema_version"], field="compiler schema_version", minimum=1, maximum=1
    )
    intent_source_bytes = _require_int(
        summary["intent_source_bytes"],
        field="intent_source_bytes",
        minimum=1,
        maximum=PLAN_MAX_BYTES,
    )
    plan_source_bytes = _require_int(
        summary["plan_source_bytes"],
        field="plan_source_bytes",
        minimum=1,
        maximum=PLAN_MAX_BYTES,
    )
    intent_source_sha256 = summary["intent_source_sha256"]
    plan_source_sha256 = summary["plan_source_sha256"]
    if not _is_lowercase_sha256(intent_source_sha256):
        raise SummaryValidationError(
            "intent_source_sha256 must be lowercase hexadecimal SHA-256"
        )
    if not _is_lowercase_sha256(plan_source_sha256):
        raise SummaryValidationError(
            "plan_source_sha256 must be lowercase hexadecimal SHA-256"
        )
    if len(intent_bytes) != intent_source_bytes:
        raise SummaryValidationError("intent source byte count does not match compiler summary")
    if hashlib.sha256(intent_bytes).hexdigest() != intent_source_sha256:
        raise SummaryValidationError("intent source SHA-256 does not match compiler summary")
    if len(plan_bytes) != plan_source_bytes:
        raise SummaryValidationError("compiled plan byte count does not match compiler summary")
    if hashlib.sha256(plan_bytes).hexdigest() != plan_source_sha256:
        raise SummaryValidationError("compiled plan SHA-256 does not match compiler summary")
    _canonical_plan(plan_bytes)
    return {
        "schema_version": schema_version,
        "intent_source_bytes": intent_source_bytes,
        "intent_source_sha256": intent_source_sha256,
        "plan_source_bytes": plan_source_bytes,
        "plan_source_sha256": plan_source_sha256,
    }


def verify_compile(
    intent: str | os.PathLike[str], plan: str | os.PathLike[str]
) -> dict[str, Any]:
    """Authenticate compiler stdout against the stable intent and plan files."""

    summary_bytes = _read_summary_stdin()
    if not summary_bytes.endswith(b"\n") or summary_bytes.endswith(b"\n\n"):
        raise SummaryValidationError("compiler summary must contain one trailing newline")
    summary = _parse_json(summary_bytes, role="deterministic pipeline compiler summary")
    # The summary itself is a closed canonical bridge, not an arbitrary JSON
    # document that happens to contain the five expected keys.
    encoded_summary = json.dumps(summary, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if encoded_summary + b"\n" != summary_bytes:
        raise SummaryValidationError("compiler summary is not canonical JSON")
    intent_path = validate_intent(intent)
    plan_path = _portable_plan_path(plan)
    intent_bytes = _read_stable(intent_path, max_bytes=PLAN_MAX_BYTES, role="compiler intent")
    plan_bytes = _read_stable(plan_path, max_bytes=PLAN_MAX_BYTES, role="compiled plan")
    return _verify_compile_summary(summary, intent_bytes, plan_bytes)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument(
        "--validate-plan",
        metavar="PLAN",
        help="validate one portable workspace-relative plan and exit",
    )
    modes.add_argument(
        "--verify",
        action="store_true",
        help="verify summary stdin against the retained report",
    )
    modes.add_argument(
        "--verify-compile",
        action="store_true",
        help="verify compiler summary stdin against the retained intent and plan",
    )
    modes.add_argument(
        "--validate-intent",
        metavar="INTENT",
        help="validate one portable workspace-relative intent and exit",
    )
    modes.add_argument(
        "--validate-compile-output",
        metavar="PLAN",
        help="validate a new portable compiled-plan destination and exit",
    )
    parser.add_argument("--intent", metavar="INTENT", help="workspace-relative intent path")
    parser.add_argument("--plan", metavar="PLAN", help="workspace-relative plan path")
    parser.add_argument("--report", metavar="REPORT", help="retained report path")
    parser.add_argument(
        "--expected-intent-source-bytes",
        metavar="BYTES",
        help="compiler-authenticated intent source byte count for race-safe verification",
    )
    parser.add_argument(
        "--expected-intent-source-sha256",
        metavar="SHA256",
        help="compiler-authenticated intent source SHA-256 for race-safe verification",
    )
    parser.add_argument(
        "--expected-plan-source-bytes",
        metavar="BYTES",
        help="compiler-authenticated plan source byte count for race-safe verification",
    )
    parser.add_argument(
        "--expected-plan-source-sha256",
        metavar="SHA256",
        help="compiler-authenticated plan source SHA-256 for race-safe verification",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.validate_plan is not None:
            validate_plan(args.validate_plan)
            return 0
        if args.validate_intent is not None:
            validate_intent(args.validate_intent)
            return 0
        if args.validate_compile_output is not None:
            validate_compile_output(args.validate_compile_output)
            return 0
        if args.verify_compile:
            if not args.intent or not args.plan:
                raise SummaryValidationError(
                    "--verify-compile requires --intent and --plan"
                )
            summary = verify_compile(args.intent, args.plan)
            encoded = json.dumps(summary, ensure_ascii=True, separators=(",", ":"))
            if len(encoded.encode("utf-8")) > SUMMARY_MAX_BYTES:
                raise SummaryValidationError("validated compiler summary exceeds its byte bound")
            sys.stdout.write(encoded)
            sys.stdout.write("\n")
            return 0
        if not args.plan or not args.report:
            raise SummaryValidationError("--verify requires --plan and --report")
        summary = verify(
            args.plan,
            args.report,
            intent=args.intent,
            expected_intent_source_bytes=args.expected_intent_source_bytes,
            expected_intent_source_sha256=args.expected_intent_source_sha256,
            expected_plan_source_bytes=args.expected_plan_source_bytes,
            expected_plan_source_sha256=args.expected_plan_source_sha256,
        )
        # Keep this output compact and bounded.  It is intentionally the only
        # data emitted by verification mode; the retained report is never
        # printed or copied into a GitHub log/summary.
        encoded = json.dumps(summary, ensure_ascii=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > SUMMARY_MAX_BYTES:
            raise SummaryValidationError("validated summary exceeds its byte bound")
        sys.stdout.write(encoded)
        sys.stdout.write("\n")
        return 0
    except (SummaryValidationError, ExecutionBoundaryError, OSError) as error:
        print(f"deterministic pipeline summary validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
