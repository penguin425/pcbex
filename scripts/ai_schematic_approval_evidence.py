#!/usr/bin/env python3
"""Bounded evidence helpers for the AI schematic approval Action.

The verifier owns signature checking and report production.  This module owns
the Action's stable input snapshot and the small, fixed summary that is safe to
publish as a GitHub artifact or step summary.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from typing import Any

from ci_runtime import (
    ExecutionBoundaryError,
    atomic_write_text_no_clobber,
    read_bytes,
)


MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 128 * 1024 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_SUMMARY_BYTES = 64 * 1024
MAX_MEMBERS = 100


class EvidenceError(RuntimeError):
    """An evidence file crossed a schema, size, or publication boundary."""


def stable_input_snapshot(paths: list[str]) -> str:
    """Read every input twice and return a deterministic aggregate digest."""

    if not paths:
        raise EvidenceError("AI approval input set must not be empty")
    digest = hashlib.sha256()
    total = 0
    for index, raw_path in enumerate(paths):
        try:
            first = read_bytes(raw_path, max_bytes=MAX_INPUT_BYTES)
            second = read_bytes(raw_path, max_bytes=MAX_INPUT_BYTES)
        except (ExecutionBoundaryError, OSError) as error:
            raise EvidenceError(f"could not snapshot AI approval input: {error}") from error
        if first != second:
            raise EvidenceError("AI approval input changed during a stable read")
        if not first or len(first) > MAX_INPUT_BYTES:
            raise EvidenceError(
                f"AI approval input must be between 1 and {MAX_INPUT_BYTES} bytes"
            )
        total += len(first)
        if total > MAX_TOTAL_INPUT_BYTES:
            raise EvidenceError(
                f"AI approval inputs exceed {MAX_TOTAL_INPUT_BYTES} aggregate bytes"
            )
        digest.update(index.to_bytes(8, "big"))
        digest.update(len(first).to_bytes(8, "big"))
        digest.update(hashlib.sha256(first).digest())
    return digest.hexdigest()


def _malformed(message: str) -> None:
    raise EvidenceError(message)


def _is_schema_one(value: Any) -> bool:
    return type(value) is int and value == 1


def _parse_report(
    report_path: str,
    expected_request: str,
    minimum_approvals: str,
    minimum_distinct_providers: str,
    minimum_distinct_models: str,
) -> tuple[dict[str, Any], bytes, str, bool]:
    """Parse and recompute the complete verifier report contract."""

    try:
        report_bytes = read_bytes(report_path, max_bytes=MAX_REPORT_BYTES)
        report = json.loads(report_bytes.decode("utf-8"))
    except (ExecutionBoundaryError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"invalid AI quorum report: {error}") from error

    quorum_keys = {
        "schema_version",
        "request_sha256",
        "policy",
        "counts",
        "members",
        "quorum_met",
        "quorum_failures",
    }
    session_keys = {
        "schema_version",
        "session_sha256",
        "request_sha256",
        "issued_at_unix",
        "expires_at_unix",
        "evaluated_at_unix",
        "quorum",
    }
    if type(report) is not dict:
        _malformed("AI quorum report must be an object")
    time_bound = "quorum" in report
    if time_bound:
        if set(report) != session_keys or not _is_schema_one(report.get("schema_version")):
            _malformed("AI session quorum report has an unexpected schema")
        session_sha = report.get("session_sha256")
        if not isinstance(session_sha, str) or re.fullmatch(r"[0-9a-f]{64}", session_sha) is None:
            _malformed("AI session quorum report session digest is malformed")
        if report.get("request_sha256") != expected_request:
            _malformed("AI session quorum report is bound to a different request")
        timestamps = {
            field: report.get(field)
            for field in ("issued_at_unix", "evaluated_at_unix", "expires_at_unix")
        }
        if any(type(value) is not int or value < 0 for value in timestamps.values()):
            _malformed("AI session quorum report timestamps are malformed")
        if not (
            timestamps["issued_at_unix"]
            <= timestamps["evaluated_at_unix"]
            <= timestamps["expires_at_unix"]
        ) or timestamps["expires_at_unix"] == 0:
            _malformed("AI session quorum report timestamps are inconsistent")
        quorum = report["quorum"]
    else:
        if set(report) != quorum_keys or not _is_schema_one(report.get("schema_version")):
            _malformed("AI quorum report has an unexpected schema")
        quorum = report
    if (
        type(quorum) is not dict
        or set(quorum) != quorum_keys
        or not _is_schema_one(quorum.get("schema_version"))
    ):
        _malformed("AI quorum report has an unexpected schema")
    if quorum.get("request_sha256") != expected_request:
        _malformed("AI quorum report is bound to a different request")

    try:
        expected_policy = {
            "minimum_approvals": int(minimum_approvals),
            "minimum_distinct_providers": int(minimum_distinct_providers),
            "minimum_distinct_models": int(minimum_distinct_models),
        }
    except ValueError as error:
        raise EvidenceError("AI quorum Action thresholds are malformed") from error
    policy = quorum.get("policy")
    if type(policy) is not dict or set(policy) != set(expected_policy):
        _malformed("AI quorum policy is malformed")
    if policy != expected_policy or any(
        type(value) is not int or value < 1 or value > MAX_MEMBERS
        for value in policy.values()
    ) or policy["minimum_distinct_providers"] > policy["minimum_approvals"] or policy[
        "minimum_distinct_models"
    ] > policy["minimum_approvals"]:
        _malformed("AI quorum report policy does not match Action inputs")

    counts = quorum.get("counts")
    members = quorum.get("members")
    count_keys = {
        "members",
        "approvals",
        "rejections",
        "distinct_providers",
        "distinct_models",
    }
    if type(counts) is not dict or set(counts) != count_keys:
        _malformed("AI quorum counts are malformed")
    if any(type(value) is not int or value < 0 for value in counts.values()):
        _malformed("AI quorum counts are malformed")
    if type(members) is not list or not members or len(members) > MAX_MEMBERS:
        _malformed("AI quorum counts or members are malformed")

    member_keys = {
        "signer_id",
        "public_key",
        "response_sha256",
        "provider",
        "model",
        "version",
        "approved",
        "gate_failures",
    }
    signers: set[str] = set()
    public_keys: set[str] = set()
    response_digests: set[str] = set()
    approved_providers: set[str] = set()
    approved_models: set[str] = set()
    approved_count = 0
    previous_signer_id: str | None = None
    for member in members:
        if type(member) is not dict or set(member) != member_keys:
            _malformed("AI quorum member is malformed")
        if any(
            type(member[field]) is not str or not member[field].strip()
            for field in ("signer_id", "provider", "model")
        ):
            _malformed("AI quorum member identity is malformed")
        if any(
            not isinstance(member[field], str)
            or re.fullmatch(r"[0-9a-f]{64}", member[field]) is None
            for field in ("public_key", "response_sha256")
        ):
            _malformed("AI quorum member digest is malformed")
        if member["version"] is not None and (
            type(member["version"]) is not str or not member["version"].strip()
        ):
            _malformed("AI quorum member version is malformed")
        if type(member["approved"]) is not bool or type(member["gate_failures"]) is not list:
            _malformed("AI quorum member result is malformed")
        if any(type(item) is not str or not item.strip() for item in member["gate_failures"]):
            _malformed("AI quorum member gate failure is malformed")
        if member["approved"] != (len(member["gate_failures"]) == 0):
            _malformed("AI quorum member approval does not match its gate failures")
        signer_id = member["signer_id"]
        public_key = member["public_key"]
        response_digest = member["response_sha256"]
        if previous_signer_id is not None and signer_id <= previous_signer_id:
            _malformed("AI quorum members are not in strict signer_id order")
        previous_signer_id = signer_id
        if signer_id in signers or public_key in public_keys or response_digest in response_digests:
            _malformed("AI quorum member identity is duplicated")
        signers.add(signer_id)
        public_keys.add(public_key)
        response_digests.add(response_digest)
        if member["approved"]:
            approved_count += 1
            provider = member["provider"].strip().lower()
            model = member["model"].strip().lower()
            if not provider or not model:
                _malformed("AI quorum approved member identity is blank")
            approved_providers.add(provider)
            version = member["version"]
            approved_models.add(
                f"{provider}/{model}@{version.strip().lower() if version is not None else '-'}"
            )
    expected_counts = {
        "members": len(members),
        "approvals": approved_count,
        "rejections": len(members) - approved_count,
        "distinct_providers": len(approved_providers),
        "distinct_models": len(approved_models),
    }
    if counts != expected_counts:
        _malformed("AI quorum counts do not match members")
    if type(quorum.get("quorum_met")) is not bool or type(quorum.get("quorum_failures")) is not list:
        _malformed("AI quorum result is malformed")
    if any(type(item) is not str or not item for item in quorum["quorum_failures"]):
        _malformed("AI quorum failure is malformed")
    expected_failures = []
    for label, required, actual in (
        ("insufficient_approvals", policy["minimum_approvals"], approved_count),
        (
            "insufficient_distinct_providers",
            policy["minimum_distinct_providers"],
            len(approved_providers),
        ),
        (
            "insufficient_distinct_models",
            policy["minimum_distinct_models"],
            len(approved_models),
        ),
    ):
        if actual < required:
            expected_failures.append(f"{label}:required={required}:actual={actual}")
    if quorum["quorum_failures"] != expected_failures:
        _malformed("AI quorum failures do not match policy and members")
    if quorum["quorum_met"] != (len(expected_failures) == 0):
        _malformed("AI quorum result does not match its failures")

    return quorum, report_bytes, _canonical_summary(quorum, time_bound=time_bound), time_bound


def _canonical_summary(quorum: dict[str, Any], *, time_bound: bool) -> str:
    """Render only fixed labels and validated integers; never report free text."""

    policy = quorum["policy"]
    counts = quorum["counts"]
    result = "quorum met" if quorum["quorum_met"] else "quorum not met"
    heading = (
        "# Time-bound AI schematic approval quorum"
        if time_bound
        else "# pcbex AI schematic approval quorum"
    )
    summary = (
        f"{heading}\n\n"
        f"Result: {result}\n\n"
        "| Metric | Actual | Required |\n"
        "| --- | ---: | ---: |\n"
        f"| Signed approvals | {counts['approvals']} | {policy['minimum_approvals']} |\n"
        f"| Distinct providers | {counts['distinct_providers']} | {policy['minimum_distinct_providers']} |\n"
        f"| Distinct models | {counts['distinct_models']} | {policy['minimum_distinct_models']} |\n"
    )
    if len(summary.encode("utf-8")) > MAX_SUMMARY_BYTES:
        raise EvidenceError("canonical AI quorum summary exceeds its byte limit")
    return summary


def render_summary(
    report_path: str,
    summary_path: str,
    expected_request: str,
    minimum_approvals: str,
    minimum_distinct_providers: str,
    minimum_distinct_models: str,
) -> tuple[bool, int, int]:
    quorum, report_bytes, summary, _time_bound = _parse_report(
        report_path,
        expected_request,
        minimum_approvals,
        minimum_distinct_providers,
        minimum_distinct_models,
    )
    try:
        atomic_write_text_no_clobber(
            summary_path,
            summary,
            max_bytes=MAX_SUMMARY_BYTES,
        )
    except (ExecutionBoundaryError, OSError) as error:
        raise EvidenceError(f"could not publish canonical AI quorum summary: {error}") from error
    return bool(quorum["quorum_met"]), len(report_bytes), len(summary.encode("utf-8"))


def revalidate_evidence(
    report_path: str,
    summary_path: str,
    expected_request: str,
    minimum_approvals: str,
    minimum_distinct_providers: str,
    minimum_distinct_models: str,
) -> bool:
    quorum, _report_bytes, summary, _time_bound = _parse_report(
        report_path,
        expected_request,
        minimum_approvals,
        minimum_distinct_providers,
        minimum_distinct_models,
    )
    try:
        observed = read_bytes(summary_path, max_bytes=MAX_SUMMARY_BYTES)
    except (ExecutionBoundaryError, OSError) as error:
        raise EvidenceError(f"could not read AI quorum summary for publication: {error}") from error
    expected = summary.encode("utf-8")
    if observed != expected:
        raise EvidenceError("AI quorum summary is not the canonical report-derived summary")
    return bool(quorum["quorum_met"])


def _usage() -> None:
    print(
        "usage: ai_schematic_approval_evidence.py "
        "snapshot PATH... | render REPORT SUMMARY REQUEST MIN_APPROVALS "
        "MIN_PROVIDERS MIN_MODELS | revalidate REPORT SUMMARY REQUEST "
        "MIN_APPROVALS MIN_PROVIDERS MIN_MODELS",
        file=sys.stderr,
    )


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        _usage()
        return 2
    command = argv[1]
    try:
        if command == "snapshot":
            if len(argv) < 3:
                _usage()
                return 2
            print(stable_input_snapshot(argv[2:]))
            return 0
        if command in ("render", "revalidate") and len(argv) == 8:
            arguments = argv[2:]
            if command == "render":
                met, report_bytes, summary_bytes = render_summary(*arguments)
                print(f"quorum-met={'true' if met else 'false'}")
                print(f"report-bytes={report_bytes}")
                print(f"summary-bytes={summary_bytes}")
            else:
                met = revalidate_evidence(*arguments)
                print(f"quorum-met={'true' if met else 'false'}")
            return 0
    except (EvidenceError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
    _usage()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
