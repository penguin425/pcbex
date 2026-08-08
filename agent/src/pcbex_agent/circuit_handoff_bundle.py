"""Atomic circuit-generation to KiCad handoff bundles.

This module consumes one retained ``generate-circuit`` bundle, replays the
native immutable ERC check, writes a deterministic KiCad schematic, and
re-runs the semantic handoff gate.  The complete evidence set is published as
one deterministic ZIP file so no consumer can observe a partially completed
multi-file handoff.

The bundle is an electrical handoff artifact.  It deliberately does not claim
AI-signature/quorum approval, PCB layout approval, or manufacturing approval;
those remain explicit downstream gates.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
import errno
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import time
from typing import Any, Callable
import zipfile

from .bounded_io import (
    BoundedIOError,
    atomic_write_no_clobber,
    atomic_write_text_no_clobber,
    create_safe_parent,
    read_bytes,
    validate_no_clobber_path,
)
from .bounded_process import BoundedProcessError, run_bounded
from .catalog import (
    CatalogError,
    canonical_sha256,
    validate_catalog_receipt_shape,
)
from .circuit_generation import (
    MAX_CORRECTION_BYTES,
    MAX_HISTORY_ITEMS,
    MAX_NATIVE_CHECK_BYTES,
    MAX_REQUIREMENTS_BYTES,
    MAXIMUM_PROVIDER_OUTPUT_BYTES,
    MAXIMUM_TIMEOUT_SECONDS,
    CircuitGenerationError,
    _compact_json,
    _normalize_command,
    _provider_descriptor,
    _render_skidl,
    _validate_catalog_selections,
    _validate_check_envelope,
    _validate_review,
    _validate_v2_spec,
)


CIRCUIT_HANDOFF_BUNDLE_SCHEMA_VERSION = 1
CIRCUIT_HANDOFF_BUNDLE_ADAPTER = "circuit-generation-kicad-handoff-v1"
CIRCUIT_HANDOFF_BUNDLE_RESULT_SCHEMA_VERSION = 1
CIRCUIT_HANDOFF_BUNDLE_VERIFICATION_SCOPE = (
    "deterministic-electrical-handoff-archive-v1"
)
CIRCUIT_HANDOFF_BUNDLE_REPLAY_RESULT_SCHEMA_VERSION = 1
CIRCUIT_HANDOFF_BUNDLE_REPLAY_SCOPE = (
    "deterministic-electrical-handoff-chain-replay-v1"
)
CIRCUIT_HANDOFF_BUNDLE_NATIVE_ERC_REPLAY_RESULT_SCHEMA_VERSION = 2
CIRCUIT_HANDOFF_BUNDLE_NATIVE_ERC_REPLAY_SCOPE = (
    "deterministic-electrical-handoff-chain-native-kicad-erc-replay-v2"
)
MAX_GENERATION_BUNDLE_BYTES = MAX_NATIVE_CHECK_BYTES
MAX_CIRCUIT_SPEC_BYTES = 16 * 1024 * 1024
MAX_SCHEMATIC_BYTES = 64 * 1024 * 1024
MAX_HANDOFF_REPORT_BYTES = 64 * 1024 * 1024
MAX_HANDOFF_ARCHIVE_BYTES = 224 * 1024 * 1024
MAX_NATIVE_KICAD_ERC_REPORT_BYTES = 32 * 1024 * 1024
MAX_NATIVE_KICAD_ERC_WARNING_POLICY_BYTES = 1 * 1024 * 1024
MAX_CHILD_STDOUT_BYTES = 1 * 1024 * 1024
MAX_CHILD_STDERR_BYTES = 1 * 1024 * 1024

GENERATION_BUNDLE_NAME = "generation-bundle.json"
CIRCUIT_SPEC_NAME = "circuit-spec-v2.json"
CIRCUIT_CHECK_NAME = "circuit-spec-check.json"
SCHEMATIC_NAME = "circuit-spec.kicad_sch"
HANDOFF_REPORT_NAME = "circuit-kicad-handoff.json"
MANIFEST_NAME = "manifest.json"

_BUNDLE_IDENTITY_DOMAIN = b"pcbex:circuit-generation-kicad-handoff-bundle-v1\0"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_JSON_DEPTH = 128
_MAX_JSON_NODES = 1_000_000
_GENERATION_KEYS = frozenset(
    {
        "schema_version",
        "requirements",
        "provider",
        "attempts",
        "attempt_history",
        "repaired",
        "spec",
        "check",
        "circuit_spec_sha256",
        "electrical_review_sha256",
        "catalog_receipt",
        "catalog_receipt_sha256",
        "skidl",
        "skidl_sha256",
    }
)
_HISTORY_REQUIRED = frozenset(
    {
        "attempt",
        "prompt_bytes",
        "prompt_sha256",
        "response_bytes",
        "response_sha256",
        "outcome",
        "spec_sha256",
        "check_sha256",
        "circuit_spec_sha256",
        "electrical_review_sha256",
        "resolved_spec_sha256",
        "resolved_check_sha256",
        "resolved_circuit_spec_sha256",
        "resolved_electrical_review_sha256",
        "catalog_receipt_sha256",
        "errors",
        "warnings",
        "error_count",
    }
)
_HISTORY_DIGESTS = (
    "prompt_sha256",
    "response_sha256",
    "spec_sha256",
    "check_sha256",
    "circuit_spec_sha256",
    "electrical_review_sha256",
    "resolved_spec_sha256",
    "resolved_check_sha256",
    "resolved_circuit_spec_sha256",
    "resolved_electrical_review_sha256",
    "catalog_receipt_sha256",
)
_HISTORY_RESOLVED = (
    "resolved_spec_sha256",
    "resolved_check_sha256",
    "resolved_circuit_spec_sha256",
    "resolved_electrical_review_sha256",
    "catalog_receipt_sha256",
)
_ARTIFACT_NAMES = {
    "generation_bundle": GENERATION_BUNDLE_NAME,
    "circuit_spec": CIRCUIT_SPEC_NAME,
    "circuit_check": CIRCUIT_CHECK_NAME,
    "schematic": SCHEMATIC_NAME,
    "handoff_report": HANDOFF_REPORT_NAME,
}
_ARTIFACT_LIMITS = {
    "generation_bundle": MAX_GENERATION_BUNDLE_BYTES,
    "circuit_spec": MAX_CIRCUIT_SPEC_BYTES,
    "circuit_check": MAX_NATIVE_CHECK_BYTES,
    "schematic": MAX_SCHEMATIC_BYTES,
    "handoff_report": MAX_HANDOFF_REPORT_BYTES,
}
_ARCHIVE_ENTRY_NAMES = (
    GENERATION_BUNDLE_NAME,
    CIRCUIT_SPEC_NAME,
    CIRCUIT_CHECK_NAME,
    SCHEMATIC_NAME,
    HANDOFF_REPORT_NAME,
    MANIFEST_NAME,
)
_ARCHIVE_ENTRY_LIMITS = {
    GENERATION_BUNDLE_NAME: MAX_GENERATION_BUNDLE_BYTES,
    CIRCUIT_SPEC_NAME: MAX_CIRCUIT_SPEC_BYTES,
    CIRCUIT_CHECK_NAME: MAX_NATIVE_CHECK_BYTES,
    SCHEMATIC_NAME: MAX_SCHEMATIC_BYTES,
    HANDOFF_REPORT_NAME: MAX_HANDOFF_REPORT_BYTES,
    MANIFEST_NAME: MAX_NATIVE_CHECK_BYTES,
}
_EXPECTED_CENTRAL_DIRECTORY_BYTES = sum(
    46 + len(name.encode("ascii")) for name in _ARCHIVE_ENTRY_NAMES
)
_EOCD = struct.Struct("<4s4H2LH")


class CircuitHandoffBundleError(ValueError):
    """Raised when a generation bundle cannot become an approved handoff."""


class _DuplicateJSONKey(ValueError):
    pass


def _fail(message: str) -> CircuitHandoffBundleError:
    # Errors intentionally omit untrusted values and temporary paths.
    return CircuitHandoffBundleError(message)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise _fail(f"{label} digest is invalid")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> Any:
    raise ValueError


def _validate_json_tree(value: Any, label: str) -> None:
    """Reject JSON values that cannot safely cross the retained boundary."""

    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise _fail(f"{label} exceeds its JSON structure bound")
        if isinstance(current, Mapping):
            for key, child in current.items():
                if not isinstance(key, str):
                    raise _fail(f"{label} contains a non-string JSON key")
                try:
                    key.encode("utf-8", errors="strict")
                except UnicodeEncodeError:
                    raise _fail(f"{label} contains invalid Unicode") from None
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str):
            try:
                current.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                raise _fail(f"{label} contains invalid Unicode") from None
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise _fail(f"{label} contains a non-finite JSON number")
        elif isinstance(current, int):
            if not isinstance(current, bool) and current.bit_length() > 128:
                raise _fail(f"{label} contains an oversized JSON integer")
        elif current is not None and not isinstance(current, bool):
            raise _fail(f"{label} contains an unsupported JSON value")


def _strict_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateJSONKey,
        ValueError,
        RecursionError,
    ):
        raise _fail(f"{label} is not strict JSON") from None
    if not isinstance(value, dict):
        raise _fail(f"{label} must be a JSON object")
    _validate_json_tree(value, label)
    return value


def _pretty_json(value: Any, label: str, maximum: int) -> bytes:
    try:
        rendered = (
            json.dumps(
                value,
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        raise _fail(f"{label} is not bounded JSON") from None
    if not rendered or len(rendered) > maximum:
        raise _fail(f"{label} exceeds its byte bound")
    return rendered


def _descriptor(value: Any, label: str, maximum: int) -> None:
    if not isinstance(value, Mapping) or set(value) != {"bytes", "sha256"}:
        raise _fail(f"{label} descriptor is invalid")
    byte_count = value["bytes"]
    if (
        isinstance(byte_count, bool)
        or not isinstance(byte_count, int)
        or byte_count <= 0
        or byte_count > maximum
    ):
        raise _fail(f"{label} byte count is invalid")
    _digest(value["sha256"], f"{label} sha256")


def _validate_history(
    history: Any,
    attempts: Any,
    *,
    spec: Mapping[str, Any],
    check: Mapping[str, Any],
    catalog_receipt_sha256: str | None,
    catalog_input_spec: Mapping[str, Any] | None,
    catalog_initial_check: Mapping[str, Any] | None,
    allow_unverified_catalog_history: bool,
) -> None:
    if (
        not isinstance(history, list)
        or not history
        or len(history) > MAX_HISTORY_ITEMS
        or isinstance(attempts, bool)
        or not isinstance(attempts, int)
        or attempts != len(history)
    ):
        raise _fail("generation attempt history is invalid")
    approved_count = 0
    for index, record in enumerate(history, 1):
        if not isinstance(record, Mapping):
            raise _fail("generation history record is invalid")
        fields = set(record)
        if fields - (_HISTORY_REQUIRED | {"error"}) or not _HISTORY_REQUIRED <= fields:
            raise _fail("generation history record fields are invalid")
        if (
            isinstance(record["attempt"], bool)
            or not isinstance(record["attempt"], int)
            or record["attempt"] != index
        ):
            raise _fail("generation history attempts are not ordered")
        for key, maximum in (
            ("prompt_bytes", MAX_NATIVE_CHECK_BYTES),
            ("response_bytes", MAXIMUM_PROVIDER_OUTPUT_BYTES),
        ):
            count = record[key]
            if (
                isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
                or count > maximum
            ):
                raise _fail("generation history byte count is invalid")
        for key in _HISTORY_DIGESTS:
            _digest(
                record[key],
                f"generation history {key}",
                nullable=key not in {"prompt_sha256", "response_sha256"},
            )
        outcome = record["outcome"]
        if not isinstance(outcome, str) or not outcome or len(outcome) > 128:
            raise _fail("generation history outcome is invalid")
        if "error" in record:
            error = record["error"]
            if not isinstance(error, str) or not error or len(error) > MAX_CORRECTION_BYTES:
                raise _fail("generation history error is invalid")
            try:
                if len(error.encode("utf-8", errors="strict")) > MAX_CORRECTION_BYTES:
                    raise _fail("generation history error is invalid")
            except UnicodeEncodeError:
                raise _fail("generation history error is invalid") from None
        for key in ("errors", "warnings", "error_count"):
            count = record[key]
            if count is not None and (
                isinstance(count, bool) or not isinstance(count, int) or count < 0
            ):
                raise _fail("generation history finding count is invalid")
        if outcome == "approved":
            if record["prompt_bytes"] == 0 or record["response_bytes"] == 0:
                raise _fail("approved generation history has empty provider evidence")
            approved_count += 1
        elif any(record[key] is not None for key in _HISTORY_RESOLVED):
            raise _fail("non-approved generation history has resolved artifacts")
    if approved_count != 1 or history[-1]["outcome"] != "approved":
        raise _fail("generation history has no unique final approval")

    final = history[-1]
    if any(
        final[key] is None
        for key in (
            "prompt_sha256",
            "response_sha256",
            "spec_sha256",
            "check_sha256",
            "circuit_spec_sha256",
            "electrical_review_sha256",
        )
    ):
        raise _fail("generation history final approval is missing native evidence")
    if final["errors"] != 0 or final["error_count"] != 0:
        raise _fail("generation history final approval retains errors")
    if final["warnings"] != check["electrical_review"]["counts"]["warnings"]:
        raise _fail("generation history final warning count is inconsistent")
    if catalog_receipt_sha256 is None:
        if catalog_initial_check is not None:
            raise _fail("generation history unexpectedly has a catalog input check")
        expected = {
            "spec_sha256": _sha256(_compact_json(spec)),
            "check_sha256": _sha256(_compact_json(check)),
            "circuit_spec_sha256": check["circuit_spec_sha256"],
            "electrical_review_sha256": check["electrical_review_sha256"],
        }
        if any(final[key] != value for key, value in expected.items()):
            raise _fail("generation history final native artifacts are inconsistent")
        if any(final[key] is not None for key in _HISTORY_RESOLVED):
            raise _fail("generation history unexpectedly contains catalog artifacts")
    else:
        if catalog_input_spec is None:
            raise _fail("generation history catalog input is missing")
        expected = {
            "resolved_spec_sha256": _sha256(_compact_json(spec)),
            "resolved_check_sha256": _sha256(_compact_json(check)),
            "resolved_circuit_spec_sha256": check["circuit_spec_sha256"],
            "resolved_electrical_review_sha256": check["electrical_review_sha256"],
            "catalog_receipt_sha256": catalog_receipt_sha256,
        }
        if any(final[key] != value for key, value in expected.items()):
            raise _fail("generation history final catalog artifacts are inconsistent")

        if catalog_initial_check is None:
            if allow_unverified_catalog_history:
                return
            raise _fail("generation history catalog input check was not replayed")
        try:
            initial_normalized, initial_errors = _validate_check_envelope(
                catalog_initial_check
            )
        except CircuitGenerationError:
            raise _fail("generation history catalog input check is invalid") from None
        if (
            initial_normalized != catalog_input_spec
            or initial_errors != 0
            or not catalog_initial_check["electrical_review"]["approved"]
        ):
            raise _fail("generation history catalog input check is not approved")
        initial_expected = {
            "spec_sha256": _sha256(_compact_json(initial_normalized)),
            "check_sha256": _sha256(_compact_json(catalog_initial_check)),
            "circuit_spec_sha256": catalog_initial_check["circuit_spec_sha256"],
            "electrical_review_sha256": catalog_initial_check[
                "electrical_review_sha256"
            ],
        }
        if any(final[key] != value for key, value in initial_expected.items()):
            raise _fail("generation history catalog input artifacts are inconsistent")


def _validate_circuit_generation_bundle(
    value: Any,
    *,
    catalog_initial_check: Mapping[str, Any] | None,
    allow_unverified_catalog_history: bool,
) -> tuple[dict[str, Any], dict[str, Any] | None]:

    if not isinstance(value, Mapping) or set(value) != _GENERATION_KEYS:
        raise _fail("generation bundle does not match its closed shape")
    if value["schema_version"] != 2 or isinstance(value["schema_version"], bool):
        raise _fail("generation bundle schema version is invalid")
    _descriptor(value["requirements"], "generation requirements", MAX_REQUIREMENTS_BYTES)
    try:
        if _provider_descriptor(value["provider"]) != value["provider"]:
            raise ValueError
        normalized, error_count = _validate_check_envelope(value["check"])
        spec = _validate_v2_spec(value["spec"])
    except (CircuitGenerationError, TypeError, ValueError):
        raise _fail("generation bundle native artifacts are invalid") from None
    if normalized != spec:
        raise _fail("generation bundle spec and native check differ")
    check = value["check"]
    if (
        error_count != 0
        or not check["electrical_review"]["approved"]
        or value["circuit_spec_sha256"] != check["circuit_spec_sha256"]
        or value["electrical_review_sha256"] != check["electrical_review_sha256"]
    ):
        raise _fail("generation bundle native approval binding is invalid")
    _digest(value["circuit_spec_sha256"], "generation circuit specification")
    _digest(value["electrical_review_sha256"], "generation electrical review")

    attempts = value["attempts"]
    if (
        isinstance(attempts, bool)
        or not isinstance(attempts, int)
        or not 1 <= attempts <= MAX_HISTORY_ITEMS
        or not isinstance(value["repaired"], bool)
        or value["repaired"] != (attempts > 1)
    ):
        raise _fail("generation attempt summary is invalid")

    catalog_receipt = value["catalog_receipt"]
    catalog_sha = value["catalog_receipt_sha256"]
    catalog_input_spec: Mapping[str, Any] | None = None
    if catalog_receipt is None:
        if catalog_sha is not None:
            raise _fail("generation catalog receipt binding is incomplete")
    else:
        if not isinstance(catalog_receipt, Mapping):
            raise _fail("generation catalog receipt is invalid")
        try:
            catalog_receipt = validate_catalog_receipt_shape(catalog_receipt)
        except (CatalogError, TypeError, ValueError):
            raise _fail("generation catalog receipt is invalid") from None
        expected_catalog_sha = canonical_sha256(catalog_receipt)
        if catalog_sha != expected_catalog_sha:
            raise _fail("generation catalog receipt digest is invalid")
        _digest(catalog_sha, "generation catalog receipt")
        if catalog_receipt["resolved_spec_sha256"] != canonical_sha256(spec):
            raise _fail("generation catalog receipt is bound to another resolved spec")
        input_spec = copy.deepcopy(spec)
        by_reference = {part["reference"]: part for part in input_spec["parts"]}
        for selection in catalog_receipt["selections"]:
            part = by_reference.get(selection["reference"])
            if part is None:
                raise _fail("generation catalog selection coverage is invalid")
            if selection["status"] == "assigned":
                part["mpn"] = None
        if catalog_receipt["input_spec_sha256"] != canonical_sha256(input_spec):
            raise _fail("generation catalog receipt is bound to another input spec")
        try:
            _validate_catalog_selections(input_spec, spec, catalog_receipt)
        except (CircuitGenerationError, TypeError, ValueError):
            raise _fail("generation catalog selections are inconsistent") from None
        catalog_input_spec = input_spec

    _validate_history(
        value["attempt_history"],
        attempts,
        spec=spec,
        check=check,
        catalog_receipt_sha256=catalog_sha,
        catalog_input_spec=catalog_input_spec,
        catalog_initial_check=catalog_initial_check,
        allow_unverified_catalog_history=allow_unverified_catalog_history,
    )
    skidl = value["skidl"]
    if not isinstance(skidl, str) or not skidl:
        raise _fail("generation SKiDL source is invalid")
    try:
        skidl_raw = skidl.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise _fail("generation SKiDL source is not valid UTF-8") from None
    if len(skidl_raw) > MAXIMUM_PROVIDER_OUTPUT_BYTES:
        raise _fail("generation SKiDL source exceeds its byte bound")
    if value["skidl_sha256"] != _sha256(skidl_raw):
        raise _fail("generation SKiDL source digest is invalid")
    try:
        expected_skidl = _render_skidl(
            spec,
            check["circuit_spec_sha256"],
            check["electrical_review_sha256"],
            catalog_sha,
        )
    except CircuitGenerationError:
        raise _fail("generation SKiDL source cannot be revalidated") from None
    if skidl != expected_skidl:
        raise _fail("generation SKiDL source does not match the checked circuit")
    return copy.deepcopy(dict(value)), copy.deepcopy(catalog_input_spec)


def validate_circuit_generation_bundle(
    value: Any,
    *,
    catalog_initial_check: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a retained generation bundle and return an isolated copy.

    Catalog-resolved bundles require the freshly replayed pre-selection native
    check because schema v2 retains only its digests, not its original bytes.
    """

    generation, _catalog_input_spec = _validate_circuit_generation_bundle(
        value,
        catalog_initial_check=catalog_initial_check,
        allow_unverified_catalog_history=False,
    )
    return generation


def _remaining(deadline: float, clock: Callable[[], float]) -> float:
    try:
        remaining = deadline - float(clock())
    except (TypeError, ValueError, OverflowError):
        raise _fail("aggregate deadline clock is invalid") from None
    if not math.isfinite(remaining) or remaining <= 0:
        raise _fail("circuit handoff exceeded its aggregate deadline")
    return min(remaining, MAXIMUM_TIMEOUT_SECONDS)


def _run_native(
    argv: Sequence[str],
    *,
    step: str,
    deadline: float,
    clock: Callable[[], float],
) -> bytes:
    try:
        result = run_bounded(
            argv,
            timeout_seconds=_remaining(deadline, clock),
            max_stdout_bytes=MAX_CHILD_STDOUT_BYTES,
            max_stderr_bytes=MAX_CHILD_STDERR_BYTES,
        )
    except BoundedProcessError:
        raise _fail(f"native {step} process failed") from None
    if result.returncode != 0:
        raise _fail(f"native {step} rejected the handoff")
    _remaining(deadline, clock)
    return result.stdout


def _path_argument(value: str | os.PathLike[str], label: str) -> str:
    try:
        rendered = os.fspath(value)
    except TypeError:
        raise _fail(f"{label} is invalid") from None
    if (
        not isinstance(rendered, str)
        or not rendered
        or "\x00" in rendered
        or len(rendered) > 32_768
    ):
        raise _fail(f"{label} is invalid")
    return rendered


def _trusted_temporary_root() -> Path:
    # macOS exposes its process-selected temporary area through the
    # system-managed ``/var`` symlink. Canonicalize only that trusted root so
    # strict descendant checks still reject caller-controlled symlinks.
    try:
        return Path(tempfile.gettempdir()).resolve(strict=True)
    except (OSError, RuntimeError):
        raise _fail("trusted temporary root is invalid") from None


def _summary_count(value: Any, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value.bit_length() > 63
    ):
        raise _fail(f"native KiCad ERC {label} is invalid")
    return value


def _native_kicad_erc_replay_evidence(
    summary: Mapping[str, Any],
    *,
    report_raw: bytes,
    warning_policy_raw: bytes | None,
    approval_required: bool,
) -> dict[str, Any]:
    common = {
        "schema_version",
        "approved",
        "error_count",
        "run_sha256",
        "report_bytes",
        "report_sha256",
    }
    warning = {
        "warning_count",
        "policy_failure_count",
        "warning_policy_sha256",
        "warning_policy_source_bytes",
        "warning_policy_source_sha256",
    }
    expected = common if warning_policy_raw is None else common | warning
    if set(summary) != expected:
        raise _fail("native KiCad ERC replay summary fields are invalid")

    expected_schema = 1 if warning_policy_raw is None else 2
    if summary["schema_version"] != expected_schema:
        raise _fail("native KiCad ERC replay summary schema is invalid")
    approved = summary["approved"]
    if not isinstance(approved, bool):
        raise _fail("native KiCad ERC replay decision is invalid")
    error_count = _summary_count(summary["error_count"], "error count")
    report_bytes = _summary_count(summary["report_bytes"], "report byte count")
    report_sha256 = _digest(summary["report_sha256"], "native KiCad ERC report")
    run_sha256 = _digest(summary["run_sha256"], "native KiCad ERC run")
    if (
        report_bytes != len(report_raw)
        or report_bytes == 0
        or report_bytes > MAX_NATIVE_KICAD_ERC_REPORT_BYTES
        or report_sha256 != _sha256(report_raw)
    ):
        raise _fail("native KiCad ERC replay report identity is invalid")

    warning_count: int | None = None
    policy_failure_count: int | None = None
    warning_policy: dict[str, Any] | None = None
    if warning_policy_raw is not None:
        warning_count = _summary_count(summary["warning_count"], "warning count")
        policy_failure_count = _summary_count(
            summary["policy_failure_count"],
            "policy failure count",
        )
        policy_source_bytes = _summary_count(
            summary["warning_policy_source_bytes"],
            "warning policy byte count",
        )
        policy_source_sha256 = _digest(
            summary["warning_policy_source_sha256"],
            "native KiCad ERC warning policy source",
        )
        policy_sha256 = _digest(
            summary["warning_policy_sha256"],
            "native KiCad ERC warning policy",
        )
        if (
            policy_source_bytes != len(warning_policy_raw)
            or policy_source_bytes == 0
            or policy_source_bytes > MAX_NATIVE_KICAD_ERC_WARNING_POLICY_BYTES
            or policy_source_sha256 != _sha256(warning_policy_raw)
        ):
            raise _fail("native KiCad ERC warning policy identity is invalid")
        warning_policy = {
            "source": {
                "bytes": policy_source_bytes,
                "sha256": policy_source_sha256,
            },
            "policy_sha256": policy_sha256,
        }

    expected_approved = error_count == 0 and (
        policy_failure_count is None or policy_failure_count == 0
    )
    if approved != expected_approved or (approval_required and not approved):
        raise _fail("native KiCad ERC replay decision is inconsistent")
    return {
        "schema_version": expected_schema,
        "approved": approved,
        "approval_required": approval_required,
        "error_count": error_count,
        "warning_count": warning_count,
        "policy_failure_count": policy_failure_count,
        "run_sha256": run_sha256,
        "report": {
            "bytes": report_bytes,
            "sha256": report_sha256,
        },
        "warning_policy": warning_policy,
    }


def _replay_native_kicad_erc(
    schematic_raw: bytes,
    report_raw: bytes,
    warning_policy_raw: bytes | None,
    command: Sequence[str],
    kicad_cli: str,
    *,
    require_approved: bool,
    deadline: float,
    clock: Callable[[], float],
) -> dict[str, Any]:
    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-handoff-native-erc-",
            dir=_trusted_temporary_root(),
        ) as directory:
            root = Path(directory)
            schematic_path = root / SCHEMATIC_NAME
            report_path = root / "native-kicad-erc.json"
            policy_path = root / "native-kicad-erc-warning-policy.json"
            atomic_write_no_clobber(
                schematic_path,
                schematic_raw,
                max_bytes=MAX_SCHEMATIC_BYTES,
            )
            _remaining(deadline, clock)
            atomic_write_no_clobber(
                report_path,
                report_raw,
                max_bytes=MAX_NATIVE_KICAD_ERC_REPORT_BYTES,
            )
            _remaining(deadline, clock)
            argv = [
                *command,
                "verify-native-kicad-erc-report",
                f"--kicad-cli={kicad_cli}",
            ]
            if warning_policy_raw is not None:
                atomic_write_no_clobber(
                    policy_path,
                    warning_policy_raw,
                    max_bytes=MAX_NATIVE_KICAD_ERC_WARNING_POLICY_BYTES,
                )
                _remaining(deadline, clock)
                argv.append(f"--warning-policy={policy_path}")
            if require_approved:
                argv.append("--require-approved")
            argv.append("--mcp-echo-report-summary")
            outer_remaining = _remaining(deadline, clock)
            cleanup_reserve = min(5.0, outer_remaining / 2.0)
            native_timeout = outer_remaining - cleanup_reserve
            argv.append(f"--timeout-seconds={native_timeout:.17g}")
            argv.extend(["--", str(schematic_path), str(report_path)])
            stdout = _run_native(
                argv,
                step="KiCad ERC report replay",
                deadline=deadline,
                clock=clock,
            )
            summary = _strict_object(stdout, "native KiCad ERC replay summary")
            return _native_kicad_erc_replay_evidence(
                summary,
                report_raw=report_raw,
                warning_policy_raw=warning_policy_raw,
                approval_required=require_approved,
            )
    except BoundedIOError:
        raise _fail("native KiCad ERC replay staging failed") from None
    except OSError:
        raise _fail("native KiCad ERC replay workspace failed") from None


def _artifact(name: str, raw: bytes) -> dict[str, Any]:
    return {"name": name, "bytes": len(raw), "sha256": _sha256(raw)}


def _validate_handoff(
    handoff: Mapping[str, Any],
    *,
    circuit_raw: bytes,
    check: Mapping[str, Any],
    schematic_raw: bytes,
) -> None:
    required = {
        "schema_version",
        "engine_version",
        "circuit_source_bytes",
        "circuit_source_sha256",
        "schematic_source_bytes",
        "schematic_source_sha256",
        "circuit_spec_sha256",
        "circuit_check_sha256",
        "circuit_review",
        "schematic_sha256",
        "schematic_review",
        "policy_sha256",
        "findings",
        "counts",
        "approved",
    }
    if (
        set(handoff) != required
        or isinstance(handoff["schema_version"], bool)
        or handoff["schema_version"] != 1
    ):
        raise _fail("native handoff report has an unexpected shape")
    if (
        not isinstance(handoff["engine_version"], str)
        or not handoff["engine_version"]
        or len(handoff["engine_version"]) > 256
    ):
        raise _fail("native handoff engine identity is invalid")
    try:
        if len(handoff["engine_version"].encode("utf-8", errors="strict")) > 256:
            raise _fail("native handoff engine identity is invalid")
    except UnicodeEncodeError:
        raise _fail("native handoff engine identity is invalid") from None
    if (
        isinstance(handoff["circuit_source_bytes"], bool)
        or not isinstance(handoff["circuit_source_bytes"], int)
        or isinstance(handoff["schematic_source_bytes"], bool)
        or not isinstance(handoff["schematic_source_bytes"], int)
    ):
        raise _fail("native handoff source byte counts are invalid")
    if handoff["circuit_source_bytes"] != len(circuit_raw) or handoff[
        "circuit_source_sha256"
    ] != _sha256(circuit_raw):
        raise _fail("native handoff circuit source binding is invalid")
    if handoff["schematic_source_bytes"] != len(schematic_raw) or handoff[
        "schematic_source_sha256"
    ] != _sha256(schematic_raw):
        raise _fail("native handoff schematic source binding is invalid")
    if (
        handoff["circuit_spec_sha256"] != check["circuit_spec_sha256"]
        or handoff["circuit_check_sha256"] != _sha256(_compact_json(check))
        or handoff["circuit_review"] != check["electrical_review"]
    ):
        raise _fail("native handoff immutable ERC binding is invalid")
    if handoff["approved"] is not True or handoff["findings"] != []:
        raise _fail("native handoff is not approved")
    try:
        schematic_review = _validate_review(handoff["schematic_review"])
    except (CircuitGenerationError, TypeError, ValueError):
        raise _fail("native handoff schematic review is invalid") from None
    if (
        not schematic_review["approved"]
        or schematic_review["counts"]["errors"] != 0
        or handoff["schematic_sha256"] != schematic_review["schematic_sha256"]
        or handoff["policy_sha256"] != schematic_review["policy_sha256"]
    ):
        raise _fail("native handoff schematic review binding is invalid")
    counts = handoff["counts"]
    if (
        not isinstance(counts, Mapping)
        or set(counts) != {"errors", "warnings", "info"}
        or counts["errors"] != 0
    ):
        raise _fail("native handoff finding counts are invalid")
    for key in ("errors", "warnings", "info"):
        if isinstance(counts[key], bool) or not isinstance(counts[key], int) or counts[key] < 0:
            raise _fail("native handoff finding counts are invalid")
    circuit_counts = check["electrical_review"]["counts"]
    schematic_counts = schematic_review["counts"]
    if any(
        counts[key] != circuit_counts[key] + schematic_counts[key]
        for key in ("errors", "warnings", "info")
    ):
        raise _fail("native handoff finding counts are inconsistent")
    for key in (
        "circuit_source_sha256",
        "schematic_source_sha256",
        "circuit_spec_sha256",
        "circuit_check_sha256",
        "schematic_sha256",
        "policy_sha256",
    ):
        _digest(handoff[key], f"native handoff {key}")


def _zip_entry(name: str, raw: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.create_version = 20
    info.extract_version = 20
    info.flag_bits = 0
    info.external_attr = 0o100644 << 16
    info.internal_attr = 0
    info.volume = 0
    info.extra = b""
    info.comment = b""
    return info, raw


def _archive(entries: Sequence[tuple[str, bytes]]) -> bytes:
    total = sum(len(raw) for _name, raw in entries)
    if total > MAX_HANDOFF_ARCHIVE_BYTES:
        raise _fail("circuit handoff artifacts exceed the archive byte bound")
    output = io.BytesIO()
    try:
        with zipfile.ZipFile(output, "w", allowZip64=True) as archive:
            archive.comment = b""
            for name, raw in entries:
                info, contents = _zip_entry(name, raw)
                archive.writestr(info, contents)
        rendered = output.getvalue()
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile):
        raise _fail("could not build deterministic handoff archive") from None
    if len(rendered) > MAX_HANDOFF_ARCHIVE_BYTES:
        raise _fail("circuit handoff archive exceeds its byte bound")
    return rendered


def circuit_handoff_bundle_json_schema() -> dict[str, Any]:
    """Return the closed manifest schema embedded in every handoff ZIP."""

    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}

    def artifact(name: str, maximum: int) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "bytes", "sha256"],
            "properties": {
                "name": {"const": name},
                "bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": maximum,
                },
                "sha256": digest,
            },
        }

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/schemas/"
            "circuit-generation-kicad-handoff-bundle-v1.json"
        ),
        "title": "pcbex circuit-generation to KiCad handoff bundle manifest",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "adapter",
            "engine_version",
            "artifacts",
            "circuit_spec_sha256",
            "electrical_review_sha256",
            "policy_sha256",
            "bundle_sha256",
            "approved",
        ],
        "properties": {
            "schema_version": {"const": CIRCUIT_HANDOFF_BUNDLE_SCHEMA_VERSION},
            "adapter": {"const": CIRCUIT_HANDOFF_BUNDLE_ADAPTER},
            "engine_version": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
            },
            "artifacts": {
                "type": "object",
                "additionalProperties": False,
                "required": list(_ARTIFACT_NAMES),
                "properties": {
                    key: artifact(name, _ARTIFACT_LIMITS[key])
                    for key, name in _ARTIFACT_NAMES.items()
                },
            },
            "circuit_spec_sha256": digest,
            "electrical_review_sha256": digest,
            "policy_sha256": digest,
            "bundle_sha256": digest,
            "approved": {"const": True},
        },
    }


def circuit_handoff_bundle_result_json_schema() -> dict[str, Any]:
    """Return the closed verify/extract stdout result schema."""

    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}

    def artifact(name: str, maximum: int) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "bytes", "sha256"],
            "properties": {
                "name": {"const": name},
                "bytes": {"type": "integer", "minimum": 1, "maximum": maximum},
                "sha256": digest,
            },
        }

    nullable_digest = {"anyOf": [digest, {"type": "null"}]}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/schemas/"
            "circuit-generation-kicad-handoff-bundle-result-v1.json"
        ),
        "title": "pcbex circuit handoff bundle verification result",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "operation",
            "verified",
            "extracted",
            "verification_scope",
            "archive",
            "manifest",
            "expected",
            "validation",
            "adapter",
            "engine_version",
            "bundle_sha256",
            "artifacts",
        ],
        "properties": {
            "schema_version": {
                "const": CIRCUIT_HANDOFF_BUNDLE_RESULT_SCHEMA_VERSION
            },
            "operation": {"enum": ["verify", "extract"]},
            "verified": {"const": True},
            "extracted": {"type": "boolean"},
            "verification_scope": {
                "const": CIRCUIT_HANDOFF_BUNDLE_VERIFICATION_SCOPE
            },
            "archive": {
                "type": "object",
                "additionalProperties": False,
                "required": ["bytes", "sha256"],
                "properties": {
                    "bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_HANDOFF_ARCHIVE_BYTES,
                    },
                    "sha256": digest,
                },
            },
            "manifest": artifact(MANIFEST_NAME, MAX_NATIVE_CHECK_BYTES),
            "expected": {
                "type": "object",
                "additionalProperties": False,
                "required": ["archive_sha256", "bundle_sha256"],
                "properties": {
                    "archive_sha256": nullable_digest,
                    "bundle_sha256": nullable_digest,
                },
            },
            "validation": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "internal_consistency",
                    "expected_identity_matched",
                    "native_handoff_replayed",
                    "catalog_input_erc_replayed",
                ],
                "properties": {
                    "internal_consistency": {"const": True},
                    "expected_identity_matched": {"type": "boolean"},
                    "native_handoff_replayed": {"const": False},
                    "catalog_input_erc_replayed": {"const": False},
                },
            },
            "adapter": {"const": CIRCUIT_HANDOFF_BUNDLE_ADAPTER},
            "engine_version": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
            },
            "bundle_sha256": digest,
            "artifacts": {
                "type": "object",
                "additionalProperties": False,
                "required": list(_ARTIFACT_NAMES),
                "properties": {
                    key: artifact(name, _ARTIFACT_LIMITS[key])
                    for key, name in _ARTIFACT_NAMES.items()
                },
            },
        },
        "oneOf": [
            {
                "properties": {
                    "operation": {"const": "verify"},
                    "extracted": {"const": False},
                }
            },
            {
                "properties": {
                    "operation": {"const": "extract"},
                    "extracted": {"const": True},
                }
            },
        ],
    }


def circuit_handoff_bundle_replay_result_json_schema() -> dict[str, Any]:
    """Return the closed fresh handoff-chain replay stdout result schema."""

    schema = copy.deepcopy(circuit_handoff_bundle_result_json_schema())
    schema["$id"] = (
        "https://github.com/penguin425/pcbex/schemas/"
        "circuit-generation-kicad-handoff-bundle-replay-result-v1.json"
    )
    schema["title"] = "pcbex circuit handoff bundle chain replay result"
    required = schema["required"]
    required.remove("extracted")
    required.append("replayed")
    properties = schema["properties"]
    del properties["extracted"]
    properties["operation"] = {"const": "replay"}
    properties["replayed"] = {"const": True}
    properties["verification_scope"] = {
        "const": CIRCUIT_HANDOFF_BUNDLE_REPLAY_SCOPE
    }
    properties["validation"] = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "internal_consistency",
            "expected_identity_matched",
            "archive_reproduced",
            "native_handoff_replayed",
            "catalog_input_erc_required",
            "catalog_input_erc_replayed",
            "native_kicad_erc_replayed",
        ],
        "properties": {
            "internal_consistency": {"const": True},
            "expected_identity_matched": {"type": "boolean"},
            "archive_reproduced": {"const": True},
            "native_handoff_replayed": {"const": True},
            "catalog_input_erc_required": {"type": "boolean"},
            "catalog_input_erc_replayed": {"type": "boolean"},
            "native_kicad_erc_replayed": {"const": False},
        },
    }
    schema["oneOf"] = [
        {
            "properties": {
                "validation": {
                    "properties": {
                        "catalog_input_erc_required": {"const": False},
                        "catalog_input_erc_replayed": {"const": False},
                    }
                }
            }
        },
        {
            "properties": {
                "validation": {
                    "properties": {
                        "catalog_input_erc_required": {"const": True},
                        "catalog_input_erc_replayed": {"const": True},
                    }
                }
            }
        },
    ]
    properties["schema_version"] = {
        "const": CIRCUIT_HANDOFF_BUNDLE_REPLAY_RESULT_SCHEMA_VERSION
    }
    return schema


def circuit_handoff_bundle_native_erc_replay_result_json_schema() -> dict[str, Any]:
    """Return the closed exact-chain plus native KiCad ERC replay schema."""

    schema = copy.deepcopy(circuit_handoff_bundle_replay_result_json_schema())
    schema["$id"] = (
        "https://github.com/penguin425/pcbex/schemas/"
        "circuit-generation-kicad-handoff-bundle-native-erc-replay-result-v2.json"
    )
    schema["title"] = "pcbex circuit handoff bundle native KiCad ERC replay result"
    schema["required"].append("native_kicad_erc")
    properties = schema["properties"]
    properties["schema_version"] = {
        "const": CIRCUIT_HANDOFF_BUNDLE_NATIVE_ERC_REPLAY_RESULT_SCHEMA_VERSION
    }
    properties["verification_scope"] = {
        "const": CIRCUIT_HANDOFF_BUNDLE_NATIVE_ERC_REPLAY_SCOPE
    }
    properties["validation"]["properties"]["native_kicad_erc_replayed"] = {
        "const": True
    }

    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    count = {
        "type": "integer",
        "minimum": 0,
        "maximum": (1 << 63) - 1,
    }
    nullable_count = {"anyOf": [count, {"type": "null"}]}
    warning_policy = {
        "type": "object",
        "additionalProperties": False,
        "required": ["source", "policy_sha256"],
        "properties": {
            "source": {
                "type": "object",
                "additionalProperties": False,
                "required": ["bytes", "sha256"],
                "properties": {
                    "bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_NATIVE_KICAD_ERC_WARNING_POLICY_BYTES,
                    },
                    "sha256": digest,
                },
            },
            "policy_sha256": digest,
        },
    }
    properties["native_kicad_erc"] = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "approved",
            "approval_required",
            "error_count",
            "warning_count",
            "policy_failure_count",
            "run_sha256",
            "report",
            "warning_policy",
        ],
        "properties": {
            "schema_version": {"enum": [1, 2]},
            "approved": {"type": "boolean"},
            "approval_required": {"type": "boolean"},
            "error_count": count,
            "warning_count": nullable_count,
            "policy_failure_count": nullable_count,
            "run_sha256": digest,
            "report": {
                "type": "object",
                "additionalProperties": False,
                "required": ["bytes", "sha256"],
                "properties": {
                    "bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_NATIVE_KICAD_ERC_REPORT_BYTES,
                    },
                    "sha256": digest,
                },
            },
            "warning_policy": {"anyOf": [{"type": "null"}, warning_policy]},
        },
        "oneOf": [
            {
                "properties": {
                    "schema_version": {"const": 1},
                    "warning_count": {"type": "null"},
                    "policy_failure_count": {"type": "null"},
                    "warning_policy": {"type": "null"},
                }
            },
            {
                "properties": {
                    "schema_version": {"const": 2},
                    "warning_count": count,
                    "policy_failure_count": count,
                    "warning_policy": warning_policy,
                }
            },
        ],
    }
    return schema


def _preflight_archive_directory(archive_raw: bytes) -> None:
    """Bound the central directory before ``zipfile`` allocates its records."""

    if (
        not isinstance(archive_raw, bytes)
        or not archive_raw
        or len(archive_raw) > MAX_HANDOFF_ARCHIVE_BYTES
        or len(archive_raw) < _EOCD.size
    ):
        raise _fail("circuit handoff archive exceeds its byte bound")
    offset = len(archive_raw) - _EOCD.size
    try:
        (
            signature,
            disk_number,
            directory_disk,
            disk_entries,
            total_entries,
            directory_bytes,
            directory_offset,
            comment_bytes,
        ) = _EOCD.unpack_from(archive_raw, offset)
    except struct.error:
        raise _fail("circuit handoff archive has no canonical central directory") from None
    if (
        signature != b"PK\x05\x06"
        or disk_number != 0
        or directory_disk != 0
        or disk_entries != len(_ARCHIVE_ENTRY_NAMES)
        or total_entries != len(_ARCHIVE_ENTRY_NAMES)
        or directory_bytes != _EXPECTED_CENTRAL_DIRECTORY_BYTES
        or comment_bytes != 0
        or directory_offset + directory_bytes != offset
    ):
        raise _fail("circuit handoff archive has no canonical central directory")


def _validate_archive_entry(info: zipfile.ZipInfo, expected_name: str) -> None:
    maximum = _ARCHIVE_ENTRY_LIMITS[expected_name]
    if (
        info.filename != expected_name
        or info.orig_filename != expected_name
        or info.date_time != (1980, 1, 1, 0, 0, 0)
        or info.compress_type != zipfile.ZIP_STORED
        or info.create_system != 3
        or info.create_version != 20
        or info.extract_version != 20
        or info.flag_bits != 0
        or info.external_attr != 0o100644 << 16
        or info.internal_attr != 0
        or info.volume != 0
        or info.extra != b""
        or info.comment != b""
        or info.is_dir()
        or info.file_size <= 0
        or info.file_size > maximum
        or info.compress_size != info.file_size
    ):
        raise _fail("circuit handoff archive entry metadata is not canonical")


def _read_archive_entry(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    maximum: int,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    try:
        with archive.open(info, "r") as stream:
            while True:
                allowance = maximum - total
                chunk = stream.read(min(1024 * 1024, allowance + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise _fail("circuit handoff archive entry exceeds its byte bound")
                chunks.append(chunk)
    except CircuitHandoffBundleError:
        raise
    except (OSError, EOFError, RuntimeError, NotImplementedError, zipfile.BadZipFile):
        raise _fail("circuit handoff archive entry is corrupt") from None
    raw = b"".join(chunks)
    if not raw or len(raw) != info.file_size or len(raw) != info.compress_size:
        raise _fail("circuit handoff archive entry size is inconsistent")
    return raw


def _validate_circuit_handoff_manifest(
    manifest: Mapping[str, Any],
    entries: Mapping[str, bytes],
) -> None:
    field_order = (
        "schema_version",
        "adapter",
        "engine_version",
        "artifacts",
        "circuit_spec_sha256",
        "electrical_review_sha256",
        "policy_sha256",
        "approved",
        "bundle_sha256",
    )
    if list(manifest) != list(field_order):
        raise _fail("circuit handoff manifest does not match its closed shape")
    if (
        isinstance(manifest["schema_version"], bool)
        or manifest["schema_version"] != CIRCUIT_HANDOFF_BUNDLE_SCHEMA_VERSION
        or manifest["adapter"] != CIRCUIT_HANDOFF_BUNDLE_ADAPTER
        or manifest["approved"] is not True
        or not isinstance(manifest["engine_version"], str)
        or not manifest["engine_version"]
        or len(manifest["engine_version"]) > 256
    ):
        raise _fail("circuit handoff manifest identity is invalid")
    try:
        if len(manifest["engine_version"].encode("utf-8", errors="strict")) > 256:
            raise _fail("circuit handoff manifest engine identity is invalid")
    except UnicodeEncodeError:
        raise _fail("circuit handoff manifest engine identity is invalid") from None

    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, Mapping) or list(artifacts) != list(_ARTIFACT_NAMES):
        raise _fail("circuit handoff manifest artifacts are invalid")
    for role, name in _ARTIFACT_NAMES.items():
        descriptor = artifacts[role]
        if not isinstance(descriptor, Mapping) or list(descriptor) != [
            "name",
            "bytes",
            "sha256",
        ]:
            raise _fail("circuit handoff manifest artifact descriptor is invalid")
        byte_count = descriptor["bytes"]
        if (
            descriptor["name"] != name
            or isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or byte_count <= 0
            or byte_count > _ARTIFACT_LIMITS[role]
        ):
            raise _fail("circuit handoff manifest artifact descriptor is invalid")
        digest = _digest(descriptor["sha256"], "circuit handoff artifact")
        raw = entries[name]
        if byte_count != len(raw) or digest != _sha256(raw):
            raise _fail("circuit handoff manifest artifact binding is invalid")

    for key in (
        "circuit_spec_sha256",
        "electrical_review_sha256",
        "policy_sha256",
        "bundle_sha256",
    ):
        _digest(manifest[key], f"circuit handoff manifest {key}")
    identity = {
        "schema_version": manifest["schema_version"],
        "adapter": manifest["adapter"],
        "engine_version": manifest["engine_version"],
        "artifacts": artifacts,
        "circuit_spec_sha256": manifest["circuit_spec_sha256"],
        "electrical_review_sha256": manifest["electrical_review_sha256"],
        "policy_sha256": manifest["policy_sha256"],
        "approved": manifest["approved"],
    }
    expected_identity = _sha256(_BUNDLE_IDENTITY_DOMAIN + _compact_json(identity))
    if manifest["bundle_sha256"] != expected_identity:
        raise _fail("circuit handoff manifest aggregate identity is invalid")


def _validate_circuit_handoff_artifact_graph(
    entries: Mapping[str, bytes],
    manifest: Mapping[str, Any],
) -> None:
    generation_raw = entries[GENERATION_BUNDLE_NAME]
    circuit_raw = entries[CIRCUIT_SPEC_NAME]
    check_raw = entries[CIRCUIT_CHECK_NAME]
    schematic_raw = entries[SCHEMATIC_NAME]
    handoff_raw = entries[HANDOFF_REPORT_NAME]

    generation_value = _strict_object(generation_raw, "generation bundle")
    generation, _catalog_input_spec = _validate_circuit_generation_bundle(
        generation_value,
        catalog_initial_check=None,
        allow_unverified_catalog_history=True,
    )
    circuit_value = _strict_object(circuit_raw, "normalized circuit specification")
    try:
        circuit = _validate_v2_spec(circuit_value)
    except CircuitGenerationError:
        raise _fail("normalized circuit specification is invalid") from None
    if circuit != generation["spec"] or circuit_raw != _pretty_json(
        generation["spec"],
        "normalized circuit specification",
        MAX_CIRCUIT_SPEC_BYTES,
    ):
        raise _fail("normalized circuit specification binding is invalid")

    check = _strict_object(check_raw, "native circuit check")
    try:
        normalized, error_count = _validate_check_envelope(check)
    except CircuitGenerationError:
        raise _fail("native circuit check is invalid") from None
    if (
        normalized != circuit
        or error_count != 0
        or not check["electrical_review"]["approved"]
        or check != generation["check"]
    ):
        raise _fail("native circuit check binding is invalid")
    if not schematic_raw:
        raise _fail("KiCad schematic artifact is empty")

    handoff = _strict_object(handoff_raw, "native handoff report")
    _validate_handoff(
        handoff,
        circuit_raw=circuit_raw,
        check=check,
        schematic_raw=schematic_raw,
    )
    if (
        manifest["engine_version"] != handoff["engine_version"]
        or manifest["circuit_spec_sha256"] != check["circuit_spec_sha256"]
        or manifest["electrical_review_sha256"]
        != check["electrical_review_sha256"]
        or manifest["policy_sha256"] != handoff["policy_sha256"]
    ):
        raise _fail("circuit handoff manifest evidence graph is inconsistent")


def _circuit_handoff_result(
    archive_raw: bytes,
    manifest_raw: bytes,
    manifest: Mapping[str, Any],
    *,
    operation: str,
    expected_archive_sha256: str | None,
    expected_bundle_sha256: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": CIRCUIT_HANDOFF_BUNDLE_RESULT_SCHEMA_VERSION,
        "operation": operation,
        "verified": True,
        "extracted": operation == "extract",
        "verification_scope": CIRCUIT_HANDOFF_BUNDLE_VERIFICATION_SCOPE,
        "archive": {"bytes": len(archive_raw), "sha256": _sha256(archive_raw)},
        "manifest": _artifact(MANIFEST_NAME, manifest_raw),
        "expected": {
            "archive_sha256": expected_archive_sha256,
            "bundle_sha256": expected_bundle_sha256,
        },
        "validation": {
            "internal_consistency": True,
            "expected_identity_matched": (
                expected_archive_sha256 is not None
                or expected_bundle_sha256 is not None
            ),
            "native_handoff_replayed": False,
            "catalog_input_erc_replayed": False,
        },
        "adapter": manifest["adapter"],
        "engine_version": manifest["engine_version"],
        "bundle_sha256": manifest["bundle_sha256"],
        "artifacts": copy.deepcopy(manifest["artifacts"]),
    }


def _validate_circuit_handoff_archive(
    archive_raw: bytes,
    *,
    operation: str,
    expected_archive_sha256: str | None,
    expected_bundle_sha256: str | None,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    if operation not in {"verify", "extract"}:
        raise _fail("circuit handoff verification operation is invalid")
    expected_archive = _digest(
        expected_archive_sha256,
        "expected circuit handoff archive",
        nullable=True,
    )
    expected_bundle = _digest(
        expected_bundle_sha256,
        "expected circuit handoff bundle",
        nullable=True,
    )
    _preflight_archive_directory(archive_raw)
    archive_sha = _sha256(archive_raw)
    if expected_archive is not None and expected_archive != archive_sha:
        raise _fail("circuit handoff archive does not match the expected digest")

    entries: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(archive_raw), "r", allowZip64=False) as archive:
            infos = archive.infolist()
            if archive.comment != b"" or [info.filename for info in infos] != list(
                _ARCHIVE_ENTRY_NAMES
            ):
                raise _fail("circuit handoff archive entries are not the exact set")
            if len(infos) != len(_ARCHIVE_ENTRY_NAMES):
                raise _fail("circuit handoff archive entries are not the exact set")
            for info, expected_name in zip(infos, _ARCHIVE_ENTRY_NAMES, strict=True):
                _validate_archive_entry(info, expected_name)
                entries[expected_name] = _read_archive_entry(
                    archive,
                    info,
                    _ARCHIVE_ENTRY_LIMITS[expected_name],
                )
    except CircuitHandoffBundleError:
        raise
    except (
        OSError,
        EOFError,
        RuntimeError,
        NotImplementedError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ):
        raise _fail("circuit handoff archive is not a valid canonical ZIP") from None

    if sum(len(raw) for raw in entries.values()) > MAX_HANDOFF_ARCHIVE_BYTES:
        raise _fail("circuit handoff archive entries exceed their aggregate bound")
    if _archive([(name, entries[name]) for name in _ARCHIVE_ENTRY_NAMES]) != archive_raw:
        raise _fail("circuit handoff archive container is not canonical")

    manifest_raw = entries[MANIFEST_NAME]
    manifest = _strict_object(manifest_raw, "circuit handoff manifest")
    if manifest_raw != _pretty_json(
        manifest,
        "circuit handoff manifest",
        MAX_NATIVE_CHECK_BYTES,
    ):
        raise _fail("circuit handoff manifest serialization is not canonical")
    try:
        _validate_circuit_handoff_manifest(manifest, entries)
        _validate_circuit_handoff_artifact_graph(entries, manifest)
    except CircuitHandoffBundleError:
        raise
    except (
        CatalogError,
        CircuitGenerationError,
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
        OverflowError,
    ):
        raise _fail("circuit handoff artifact graph is invalid") from None
    if expected_bundle is not None and expected_bundle != manifest["bundle_sha256"]:
        raise _fail("circuit handoff bundle does not match the expected identity")
    return (
        _circuit_handoff_result(
            archive_raw,
            manifest_raw,
            manifest,
            operation=operation,
            expected_archive_sha256=expected_archive,
            expected_bundle_sha256=expected_bundle,
        ),
        entries,
    )


def validate_circuit_handoff_archive(
    archive_raw: bytes,
    *,
    expected_archive_sha256: str | None = None,
    expected_bundle_sha256: str | None = None,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Validate immutable ZIP bytes and return a summary plus exact entries."""

    return _validate_circuit_handoff_archive(
        archive_raw,
        operation="verify",
        expected_archive_sha256=expected_archive_sha256,
        expected_bundle_sha256=expected_bundle_sha256,
    )


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _sync_directory(path: Path) -> None:
    if not hasattr(os, "O_DIRECTORY"):
        return
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
        )
        os.fsync(descriptor)
    except OSError as error:
        if error.errno in {
            errno.EINVAL,
            getattr(errno, "ENOTSUP", errno.EINVAL),
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        }:
            return
        raise _fail("could not synchronize extracted circuit handoff directory") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _rollback_owned_extraction(
    output_dir: Path,
    directory_identity: os.stat_result,
    created: Mapping[str, os.stat_result],
) -> bool:
    try:
        current = os.lstat(output_dir)
        if (
            not _same_identity(current, directory_identity)
            or stat.S_ISLNK(current.st_mode)
            or not stat.S_ISDIR(current.st_mode)
        ):
            return False
        with os.scandir(output_dir) as scanner:
            entries = {entry.name: entry for entry in scanner}
        if set(entries) != set(created):
            return False
        for name, expected in created.items():
            metadata = os.lstat(output_dir / name)
            if (
                not _same_identity(metadata, expected)
                or stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size != expected.st_size
            ):
                return False
        for name in reversed(_ARCHIVE_ENTRY_NAMES):
            if name in created:
                os.unlink(output_dir / name)
        os.rmdir(output_dir)
        return True
    except OSError:
        return False


def _reserved_directory_identity(output_dir: Path) -> os.stat_result:
    metadata = os.lstat(output_dir)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError(errno.ENOTDIR, "reserved output is not a directory")
    return metadata


def _publish_verified_entries(output_dir: Path, entries: Mapping[str, bytes]) -> None:
    parent = create_safe_parent(output_dir)
    validate_no_clobber_path(output_dir)
    try:
        os.mkdir(output_dir, 0o700)
    except OSError:
        raise _fail("could not reserve the circuit handoff extraction directory") from None
    try:
        directory_identity = _reserved_directory_identity(output_dir)
    except OSError:
        # Without a captured identity, even an apparently empty path may be a
        # concurrent replacement.  Leave it untouched rather than deleting an
        # object this invocation cannot prove it owns.
        raise _fail(
            "could not inspect the reserved extraction directory; safe rollback "
            "was not possible"
        ) from None
    created: dict[str, os.stat_result] = {}
    try:
        for name in _ARCHIVE_ENTRY_NAMES:
            atomic_write_no_clobber(
                output_dir / name,
                entries[name],
                max_bytes=_ARCHIVE_ENTRY_LIMITS[name],
            )
            created[name] = os.lstat(output_dir / name)

        with os.scandir(output_dir) as scanner:
            actual_names = [entry.name for entry in scanner]
        if set(actual_names) != set(_ARCHIVE_ENTRY_NAMES) or len(actual_names) != len(
            _ARCHIVE_ENTRY_NAMES
        ):
            raise _fail("extracted circuit handoff directory has unexpected entries")
        for name in _ARCHIVE_ENTRY_NAMES:
            metadata = os.lstat(output_dir / name)
            if (
                not _same_identity(metadata, created[name])
                or stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or read_bytes(
                    output_dir / name,
                    max_bytes=_ARCHIVE_ENTRY_LIMITS[name],
                )
                != entries[name]
            ):
                raise _fail("extracted circuit handoff artifact changed before commit")
        _sync_directory(output_dir)
        _sync_directory(parent)
    except Exception as error:
        if not _rollback_owned_extraction(output_dir, directory_identity, created):
            raise _fail(
                "circuit handoff extraction failed and safe rollback was not possible"
            ) from error
        if isinstance(error, CircuitHandoffBundleError):
            raise
        if isinstance(error, BoundedIOError):
            raise _fail("circuit handoff extraction output is invalid") from None
        raise _fail("could not publish extracted circuit handoff artifacts") from None


def verify_circuit_handoff_bundle(
    bundle: str | os.PathLike[str],
    *,
    expected_archive_sha256: str | None = None,
    expected_bundle_sha256: str | None = None,
) -> dict[str, Any]:
    """Stable-read and verify one retained handoff ZIP without writing files."""

    try:
        archive_raw = read_bytes(bundle, max_bytes=MAX_HANDOFF_ARCHIVE_BYTES)
    except BoundedIOError:
        raise _fail("circuit handoff archive input path is invalid") from None
    result, _entries = _validate_circuit_handoff_archive(
        archive_raw,
        operation="verify",
        expected_archive_sha256=expected_archive_sha256,
        expected_bundle_sha256=expected_bundle_sha256,
    )
    return result


def extract_circuit_handoff_bundle(
    bundle: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    *,
    expected_archive_sha256: str | None = None,
    expected_bundle_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify once, then publish the exact six bound entries to a new directory."""

    try:
        output_path = Path(os.fspath(output_dir))
        validate_no_clobber_path(output_path)
        archive_raw = read_bytes(bundle, max_bytes=MAX_HANDOFF_ARCHIVE_BYTES)
    except (BoundedIOError, TypeError, ValueError):
        raise _fail("circuit handoff archive input or output path is invalid") from None
    result, entries = _validate_circuit_handoff_archive(
        archive_raw,
        operation="extract",
        expected_archive_sha256=expected_archive_sha256,
        expected_bundle_sha256=expected_bundle_sha256,
    )
    try:
        _publish_verified_entries(output_path, entries)
    except BoundedIOError:
        raise _fail("circuit handoff extraction output is invalid") from None
    return result


def _circuit_handoff_replay_result(
    verification: Mapping[str, Any],
    *,
    catalog_input_erc_required: bool,
) -> dict[str, Any]:
    result = copy.deepcopy(dict(verification))
    result["schema_version"] = CIRCUIT_HANDOFF_BUNDLE_REPLAY_RESULT_SCHEMA_VERSION
    result["operation"] = "replay"
    result.pop("extracted")
    result["replayed"] = True
    result["verification_scope"] = CIRCUIT_HANDOFF_BUNDLE_REPLAY_SCOPE
    result["validation"] = {
        "internal_consistency": True,
        "expected_identity_matched": verification["validation"][
            "expected_identity_matched"
        ],
        "archive_reproduced": True,
        "native_handoff_replayed": True,
        "catalog_input_erc_required": catalog_input_erc_required,
        "catalog_input_erc_replayed": catalog_input_erc_required,
        "native_kicad_erc_replayed": False,
    }
    return result


def _circuit_handoff_native_erc_replay_result(
    verification: Mapping[str, Any],
    *,
    catalog_input_erc_required: bool,
    native_kicad_erc: Mapping[str, Any],
) -> dict[str, Any]:
    result = _circuit_handoff_replay_result(
        verification,
        catalog_input_erc_required=catalog_input_erc_required,
    )
    result["schema_version"] = (
        CIRCUIT_HANDOFF_BUNDLE_NATIVE_ERC_REPLAY_RESULT_SCHEMA_VERSION
    )
    result["verification_scope"] = CIRCUIT_HANDOFF_BUNDLE_NATIVE_ERC_REPLAY_SCOPE
    result["validation"]["native_kicad_erc_replayed"] = True
    result["native_kicad_erc"] = copy.deepcopy(dict(native_kicad_erc))
    return result


def replay_circuit_handoff_bundle(
    bundle: str | os.PathLike[str],
    pcbex: str | Sequence[str],
    *,
    retained_native_kicad_erc_report: str | os.PathLike[str] | None = None,
    kicad_cli: str | os.PathLike[str] = "kicad-cli",
    native_kicad_erc_warning_policy: str | os.PathLike[str] | None = None,
    require_native_kicad_erc_approved: bool = False,
    timeout_seconds: float = 120.0,
    expected_archive_sha256: str | None = None,
    expected_bundle_sha256: str | None = None,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Verify a bundle and require its complete native chain to reproduce it."""

    try:
        timeout = float(timeout_seconds)
        start = float(_clock())
    except (TypeError, ValueError, OverflowError):
        raise _fail("aggregate timeout is invalid") from None
    if (
        isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > MAXIMUM_TIMEOUT_SECONDS
        or not math.isfinite(start)
    ):
        raise _fail("aggregate timeout is invalid")
    deadline = start + timeout
    if not math.isfinite(deadline):
        raise _fail("aggregate timeout is invalid")
    if not isinstance(require_native_kicad_erc_approved, bool):
        raise _fail("native KiCad ERC approval requirement is invalid")
    kicad_cli_argument = _path_argument(kicad_cli, "kicad-cli argument")
    native_erc_requested = retained_native_kicad_erc_report is not None
    if not native_erc_requested and (
        native_kicad_erc_warning_policy is not None
        or require_native_kicad_erc_approved
        or kicad_cli_argument != "kicad-cli"
    ):
        raise _fail("native KiCad ERC options require a retained report")
    try:
        command = _normalize_command(pcbex, label="pcbex command")
        archive_raw = read_bytes(bundle, max_bytes=MAX_HANDOFF_ARCHIVE_BYTES)
    except (BoundedIOError, CircuitGenerationError, TypeError, ValueError):
        raise _fail("circuit handoff archive input or pcbex command is invalid") from None
    _remaining(deadline, _clock)

    verification, entries = _validate_circuit_handoff_archive(
        archive_raw,
        operation="verify",
        expected_archive_sha256=expected_archive_sha256,
        expected_bundle_sha256=expected_bundle_sha256,
    )
    _remaining(deadline, _clock)
    generation = _strict_object(entries[GENERATION_BUNDLE_NAME], "generation bundle")
    catalog_input_erc_required = generation["catalog_receipt"] is not None
    _remaining(deadline, _clock)

    native_report_raw: bytes | None = None
    warning_policy_raw: bytes | None = None
    if native_erc_requested:
        assert retained_native_kicad_erc_report is not None
        try:
            native_report_raw = read_bytes(
                retained_native_kicad_erc_report,
                max_bytes=MAX_NATIVE_KICAD_ERC_REPORT_BYTES,
            )
        except BoundedIOError:
            raise _fail("retained native KiCad ERC report path is invalid") from None
        if not native_report_raw:
            raise _fail("retained native KiCad ERC report is empty")
        _remaining(deadline, _clock)
        if native_kicad_erc_warning_policy is not None:
            try:
                warning_policy_raw = read_bytes(
                    native_kicad_erc_warning_policy,
                    max_bytes=MAX_NATIVE_KICAD_ERC_WARNING_POLICY_BYTES,
                )
            except BoundedIOError:
                raise _fail("native KiCad ERC warning policy path is invalid") from None
            if not warning_policy_raw:
                raise _fail("native KiCad ERC warning policy is empty")
            _remaining(deadline, _clock)

    replayed_archive, replayed_manifest = build_circuit_handoff_archive(
        entries[GENERATION_BUNDLE_NAME],
        command,
        timeout_seconds=timeout,
        _clock=_clock,
        _deadline=deadline,
    )
    retained_manifest = _strict_object(entries[MANIFEST_NAME], "handoff manifest")
    if replayed_archive != archive_raw or replayed_manifest != retained_manifest:
        raise _fail(
            "fresh handoff-chain replay did not reproduce the retained archive"
        )
    _remaining(deadline, _clock)
    if native_report_raw is not None:
        native_kicad_erc = _replay_native_kicad_erc(
            entries[SCHEMATIC_NAME],
            native_report_raw,
            warning_policy_raw,
            command,
            kicad_cli_argument,
            require_approved=require_native_kicad_erc_approved,
            deadline=deadline,
            clock=_clock,
        )
        _remaining(deadline, _clock)
        try:
            report_after = read_bytes(
                retained_native_kicad_erc_report,
                max_bytes=MAX_NATIVE_KICAD_ERC_REPORT_BYTES,
            )
        except BoundedIOError:
            raise _fail("retained native KiCad ERC report changed during replay") from None
        if report_after != native_report_raw:
            raise _fail("retained native KiCad ERC report changed during replay")
        _remaining(deadline, _clock)
        if native_kicad_erc_warning_policy is not None:
            assert warning_policy_raw is not None
            try:
                warning_policy_after = read_bytes(
                    native_kicad_erc_warning_policy,
                    max_bytes=MAX_NATIVE_KICAD_ERC_WARNING_POLICY_BYTES,
                )
            except BoundedIOError:
                raise _fail("native KiCad ERC warning policy changed during replay") from None
            if warning_policy_after != warning_policy_raw:
                raise _fail("native KiCad ERC warning policy changed during replay")
            _remaining(deadline, _clock)
        return _circuit_handoff_native_erc_replay_result(
            verification,
            catalog_input_erc_required=catalog_input_erc_required,
            native_kicad_erc=native_kicad_erc,
        )
    return _circuit_handoff_replay_result(
        verification,
        catalog_input_erc_required=catalog_input_erc_required,
    )


def build_circuit_handoff_archive(
    generation_bundle_raw: bytes,
    pcbex: str | Sequence[str],
    *,
    timeout_seconds: float = 120.0,
    _clock: Callable[[], float] = time.monotonic,
    _deadline: float | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Build, but do not publish, one approved deterministic handoff ZIP."""

    if (
        not isinstance(generation_bundle_raw, bytes)
        or not generation_bundle_raw
        or len(generation_bundle_raw) > MAX_GENERATION_BUNDLE_BYTES
    ):
        raise _fail("generation bundle source exceeds its byte bound")
    try:
        timeout = float(timeout_seconds)
        start = float(_clock())
    except (TypeError, ValueError, OverflowError):
        raise _fail("aggregate timeout is invalid") from None
    if (
        isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > MAXIMUM_TIMEOUT_SECONDS
        or not math.isfinite(start)
    ):
        raise _fail("aggregate timeout is invalid")
    deadline = start + timeout if _deadline is None else float(_deadline)
    if not math.isfinite(deadline) or deadline <= start:
        raise _fail("aggregate deadline is invalid")
    try:
        command = _normalize_command(pcbex, label="pcbex command")
    except (CircuitGenerationError, TypeError, ValueError):
        raise _fail("pcbex command is invalid") from None
    generation_value = _strict_object(generation_bundle_raw, "generation bundle")
    generation, catalog_input_spec = _validate_circuit_generation_bundle(
        generation_value,
        catalog_initial_check=None,
        allow_unverified_catalog_history=True,
    )
    circuit_raw = _pretty_json(
        generation["spec"], "normalized circuit specification", MAX_CIRCUIT_SPEC_BYTES
    )

    with tempfile.TemporaryDirectory(
        prefix="pcbex-handoff-",
        dir=_trusted_temporary_root(),
    ) as directory:
        root = Path(directory)
        circuit_path = root / CIRCUIT_SPEC_NAME
        check_path = root / CIRCUIT_CHECK_NAME
        schematic_path = root / SCHEMATIC_NAME
        handoff_path = root / HANDOFF_REPORT_NAME
        if catalog_input_spec is not None:
            catalog_input_path = root / "catalog-input-circuit-spec-v2.json"
            catalog_check_path = root / "catalog-input-circuit-spec-check.json"
            catalog_input_raw = _pretty_json(
                catalog_input_spec,
                "catalog input circuit specification",
                MAX_CIRCUIT_SPEC_BYTES,
            )
            atomic_write_text_no_clobber(
                catalog_input_path,
                catalog_input_raw.decode("utf-8", errors="strict"),
                max_bytes=MAX_CIRCUIT_SPEC_BYTES,
            )
            _run_native(
                [
                    *command,
                    "check-circuit-spec",
                    str(catalog_input_path),
                    "--output",
                    str(catalog_check_path),
                    "--require-approved",
                ],
                step="catalog input circuit ERC",
                deadline=deadline,
                clock=_clock,
            )
            catalog_check_raw = read_bytes(
                catalog_check_path,
                max_bytes=MAX_NATIVE_CHECK_BYTES,
            )
            catalog_initial_check = _strict_object(
                catalog_check_raw,
                "native catalog input circuit check",
            )
            generation, _catalog_input_spec = _validate_circuit_generation_bundle(
                generation_value,
                catalog_initial_check=catalog_initial_check,
                allow_unverified_catalog_history=False,
            )

        atomic_write_text_no_clobber(
            circuit_path,
            circuit_raw.decode("utf-8", errors="strict"),
            max_bytes=MAX_CIRCUIT_SPEC_BYTES,
        )
        _run_native(
            [
                *command,
                "check-circuit-spec",
                str(circuit_path),
                "--output",
                str(check_path),
                "--require-approved",
            ],
            step="circuit ERC",
            deadline=deadline,
            clock=_clock,
        )
        check_raw = read_bytes(check_path, max_bytes=MAX_NATIVE_CHECK_BYTES)
        native_check = _strict_object(check_raw, "native circuit check")
        try:
            normalized, error_count = _validate_check_envelope(native_check)
        except CircuitGenerationError:
            raise _fail("native circuit check output is invalid") from None
        if (
            normalized != generation["spec"]
            or error_count != 0
            or native_check != generation["check"]
        ):
            raise _fail("native circuit check does not match the retained generation bundle")

        _run_native(
            [
                *command,
                "write-circuit-spec-kicad-schematic",
                str(circuit_path),
                "--output",
                str(schematic_path),
            ],
            step="KiCad schematic writer",
            deadline=deadline,
            clock=_clock,
        )
        schematic_raw = read_bytes(schematic_path, max_bytes=MAX_SCHEMATIC_BYTES)
        if not schematic_raw:
            raise _fail("native KiCad schematic writer produced an empty document")

        _run_native(
            [
                *command,
                "verify-circuit-kicad-handoff",
                str(circuit_path),
                str(schematic_path),
                "--output",
                str(handoff_path),
                "--require-approved",
            ],
            step="KiCad handoff verifier",
            deadline=deadline,
            clock=_clock,
        )
        handoff_raw = read_bytes(handoff_path, max_bytes=MAX_HANDOFF_REPORT_BYTES)
        handoff = _strict_object(handoff_raw, "native handoff report")
        _validate_handoff(
            handoff,
            circuit_raw=circuit_raw,
            check=native_check,
            schematic_raw=schematic_raw,
        )

    artifacts = {
        "generation_bundle": _artifact(GENERATION_BUNDLE_NAME, generation_bundle_raw),
        "circuit_spec": _artifact(CIRCUIT_SPEC_NAME, circuit_raw),
        "circuit_check": _artifact(CIRCUIT_CHECK_NAME, check_raw),
        "schematic": _artifact(SCHEMATIC_NAME, schematic_raw),
        "handoff_report": _artifact(HANDOFF_REPORT_NAME, handoff_raw),
    }
    identity = {
        "schema_version": CIRCUIT_HANDOFF_BUNDLE_SCHEMA_VERSION,
        "adapter": CIRCUIT_HANDOFF_BUNDLE_ADAPTER,
        "engine_version": handoff["engine_version"],
        "artifacts": artifacts,
        "circuit_spec_sha256": native_check["circuit_spec_sha256"],
        "electrical_review_sha256": native_check["electrical_review_sha256"],
        "policy_sha256": handoff["policy_sha256"],
        "approved": True,
    }
    manifest = {
        **identity,
        "bundle_sha256": _sha256(
            _BUNDLE_IDENTITY_DOMAIN + _compact_json(identity)
        ),
    }
    manifest_raw = _pretty_json(manifest, "handoff manifest", MAX_NATIVE_CHECK_BYTES)
    entries = [
        (GENERATION_BUNDLE_NAME, generation_bundle_raw),
        (CIRCUIT_SPEC_NAME, circuit_raw),
        (CIRCUIT_CHECK_NAME, check_raw),
        (SCHEMATIC_NAME, schematic_raw),
        (HANDOFF_REPORT_NAME, handoff_raw),
        (MANIFEST_NAME, manifest_raw),
    ]
    return _archive(entries), manifest


def handoff_circuit_generation(
    generation_bundle: Path,
    output: Path,
    pcbex: str | Sequence[str],
    *,
    timeout_seconds: float = 120.0,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Publish one retained generation bundle as an approved handoff ZIP."""

    try:
        try:
            timeout = float(timeout_seconds)
            start = float(_clock())
        except (TypeError, ValueError, OverflowError):
            raise _fail("aggregate timeout is invalid") from None
        if (
            isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout)
            or timeout <= 0
            or timeout > MAXIMUM_TIMEOUT_SECONDS
            or not math.isfinite(start)
        ):
            raise _fail("aggregate timeout is invalid")
        deadline = start + timeout
        validate_no_clobber_path(output)
        _remaining(deadline, _clock)
        generation_raw = read_bytes(
            generation_bundle,
            max_bytes=MAX_GENERATION_BUNDLE_BYTES,
        )
        _remaining(deadline, _clock)
        archive, manifest = build_circuit_handoff_archive(
            generation_raw,
            pcbex,
            timeout_seconds=timeout_seconds,
            _clock=_clock,
            _deadline=deadline,
        )
        _remaining(deadline, _clock)
        atomic_write_no_clobber(
            output,
            archive,
            max_bytes=MAX_HANDOFF_ARCHIVE_BYTES,
        )
    except BoundedIOError:
        raise _fail("circuit handoff input or output path is invalid") from None
    return manifest


__all__ = [
    "CIRCUIT_HANDOFF_BUNDLE_ADAPTER",
    "CIRCUIT_HANDOFF_BUNDLE_NATIVE_ERC_REPLAY_RESULT_SCHEMA_VERSION",
    "CIRCUIT_HANDOFF_BUNDLE_NATIVE_ERC_REPLAY_SCOPE",
    "CIRCUIT_HANDOFF_BUNDLE_REPLAY_RESULT_SCHEMA_VERSION",
    "CIRCUIT_HANDOFF_BUNDLE_REPLAY_SCOPE",
    "CIRCUIT_HANDOFF_BUNDLE_RESULT_SCHEMA_VERSION",
    "CIRCUIT_HANDOFF_BUNDLE_SCHEMA_VERSION",
    "CIRCUIT_HANDOFF_BUNDLE_VERIFICATION_SCOPE",
    "CircuitHandoffBundleError",
    "build_circuit_handoff_archive",
    "circuit_handoff_bundle_json_schema",
    "circuit_handoff_bundle_native_erc_replay_result_json_schema",
    "circuit_handoff_bundle_replay_result_json_schema",
    "circuit_handoff_bundle_result_json_schema",
    "extract_circuit_handoff_bundle",
    "handoff_circuit_generation",
    "replay_circuit_handoff_bundle",
    "validate_circuit_handoff_archive",
    "validate_circuit_generation_bundle",
    "verify_circuit_handoff_bundle",
]
