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
import hashlib
import io
import json
import math
from pathlib import Path
import re
import tempfile
import time
from typing import Any, Callable
import zipfile

from .bounded_io import (
    BoundedIOError,
    atomic_write_no_clobber,
    atomic_write_text_no_clobber,
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
MAX_GENERATION_BUNDLE_BYTES = MAX_NATIVE_CHECK_BYTES
MAX_CIRCUIT_SPEC_BYTES = 16 * 1024 * 1024
MAX_SCHEMATIC_BYTES = 64 * 1024 * 1024
MAX_HANDOFF_REPORT_BYTES = 64 * 1024 * 1024
MAX_HANDOFF_ARCHIVE_BYTES = 224 * 1024 * 1024
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
) -> None:
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
    except CircuitGenerationError:
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

    with tempfile.TemporaryDirectory(prefix="pcbex-handoff-") as directory:
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
    "CIRCUIT_HANDOFF_BUNDLE_SCHEMA_VERSION",
    "CircuitHandoffBundleError",
    "build_circuit_handoff_archive",
    "circuit_handoff_bundle_json_schema",
    "handoff_circuit_generation",
    "validate_circuit_generation_bundle",
]
