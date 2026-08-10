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
from pathlib import Path, PurePosixPath, PureWindowsPath
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
from . import deterministic_pipeline_replay as _deterministic_pipeline_replay
from . import manufacturing_replay as _manufacturing_replay
from .catalog import (
    MAX_CATALOG_RAW_BYTES,
    CatalogError,
    canonical_sha256,
    validate_catalog_receipt_shape,
)
from .catalog_provenance import (
    MAX_PROVENANCE_BYTES,
    PROVENANCE_ADAPTER,
    PROVENANCE_SCHEMA_VERSION,
    CatalogGenerationProvenanceError,
    catalog_generation_provenance_json_schema,
    validate_catalog_generation_provenance,
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
from .supplier_inventory import MAXIMUM_RECEIPT_BYTES


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
CIRCUIT_HANDOFF_BUNDLE_AI_QUORUM_REPLAY_RESULT_SCHEMA_VERSION = 3
CIRCUIT_HANDOFF_BUNDLE_AI_QUORUM_REPLAY_SCOPE = (
    "deterministic-electrical-handoff-chain-ai-schematic-quorum-replay-v3"
)
CIRCUIT_HANDOFF_BUNDLE_CATALOG_PROVENANCE_REPLAY_RESULT_SCHEMA_VERSION = 4
CIRCUIT_HANDOFF_BUNDLE_CATALOG_PROVENANCE_REPLAY_SCOPE = (
    "deterministic-electrical-handoff-chain-catalog-provenance-replay-v4"
)
CIRCUIT_HANDOFF_BUNDLE_BOARD_BINDING_REPLAY_RESULT_SCHEMA_VERSION = 5
CIRCUIT_HANDOFF_BUNDLE_BOARD_BINDING_REPLAY_SCOPE = (
    "deterministic-electrical-handoff-chain-board-binding-replay-v5"
)
CIRCUIT_HANDOFF_BUNDLE_MANUFACTURING_REPLAY_RESULT_SCHEMA_VERSION = 6
CIRCUIT_HANDOFF_BUNDLE_MANUFACTURING_REPLAY_SCOPE = (
    "deterministic-electrical-handoff-chain-manufacturing-package-replay-v6"
)
CIRCUIT_HANDOFF_BUNDLE_PIPELINE_REPLAY_RESULT_SCHEMA_VERSION = 7
CIRCUIT_HANDOFF_BUNDLE_PIPELINE_REPLAY_SCOPE = (
    "deterministic-electrical-handoff-chain-manufacturing-pipeline-replay-v7"
)
MAX_GENERATION_BUNDLE_BYTES = MAX_NATIVE_CHECK_BYTES
MAX_CIRCUIT_SPEC_BYTES = 16 * 1024 * 1024
MAX_SCHEMATIC_BYTES = 64 * 1024 * 1024
MAX_HANDOFF_REPORT_BYTES = 64 * 1024 * 1024
MAX_HANDOFF_ARCHIVE_BYTES = 224 * 1024 * 1024
MAX_NATIVE_KICAD_ERC_REPORT_BYTES = 32 * 1024 * 1024
MAX_NATIVE_KICAD_ERC_WARNING_POLICY_BYTES = 1 * 1024 * 1024
MAX_KICAD_BOARD_BINDING_BYTES = 128 * 1024 * 1024
MAX_KICAD_BOARD_BINDING_POLICY_BYTES = 4 * 1024 * 1024
MAX_KICAD_BOARD_BINDING_REPORT_BYTES = 12 * 1024 * 1024
MAX_KICAD_BOARD_BINDING_RENDERED_REPORT_BYTES = (
    MAX_KICAD_BOARD_BINDING_REPORT_BYTES + 1
)
MAX_KICAD_BOARD_BINDING_TOTAL_INPUT_BYTES = (
    MAX_KICAD_BOARD_BINDING_BYTES
    + MAX_KICAD_BOARD_BINDING_RENDERED_REPORT_BYTES
    + MAX_KICAD_BOARD_BINDING_POLICY_BYTES
)
MAX_AI_QUORUM_INPUT_BYTES = 32 * 1024 * 1024
MAX_AI_QUORUM_TOTAL_INPUT_BYTES = 128 * 1024 * 1024
MAX_AI_QUORUM_REPORT_BYTES = 16 * 1024 * 1024
MAX_AI_QUORUM_MEMBERS = 100
MAX_CATALOG_PROVENANCE_TOTAL_INPUT_BYTES = (
    MAX_PROVENANCE_BYTES + MAXIMUM_RECEIPT_BYTES + MAX_CATALOG_RAW_BYTES
)
MAX_CHILD_STDOUT_BYTES = 1 * 1024 * 1024
MAX_CHILD_STDERR_BYTES = 1 * 1024 * 1024

GENERATION_BUNDLE_NAME = "generation-bundle.json"
CIRCUIT_SPEC_NAME = "circuit-spec-v2.json"
CIRCUIT_CHECK_NAME = "circuit-spec-check.json"
SCHEMATIC_NAME = "circuit-spec.kicad_sch"
HANDOFF_REPORT_NAME = "circuit-kicad-handoff.json"
MANIFEST_NAME = "manifest.json"

_BUNDLE_IDENTITY_DOMAIN = b"pcbex:circuit-generation-kicad-handoff-bundle-v1\0"
_BOARD_BINDING_HANDOFF_DOMAIN = b"pcbex:circuit-kicad-handoff-report-v1\0"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_RESERVED_NUMERIC_SUFFIXES = (
    "123456789\N{SUPERSCRIPT ONE}\N{SUPERSCRIPT TWO}\N{SUPERSCRIPT THREE}"
)
_WINDOWS_RESERVED_LEAF_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{suffix}" for suffix in _WINDOWS_RESERVED_NUMERIC_SUFFIXES}
    | {f"LPT{suffix}" for suffix in _WINDOWS_RESERVED_NUMERIC_SUFFIXES}
)
_MAX_JSON_DEPTH = 128
_MAX_JSON_NODES = 1_000_000
_BOARD_BINDING_REQUIREMENT_UNSET = object()
_MANUFACTURING_KICAD_CLI_UNSET = object()
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
    process_timeout_seconds: float | None = None,
) -> bytes:
    remaining = _remaining(deadline, clock)
    process_timeout = (
        remaining
        if process_timeout_seconds is None
        else min(remaining, process_timeout_seconds)
    )
    if not math.isfinite(process_timeout) or process_timeout <= 0:
        raise _fail(f"native {step} process has no execution budget")
    try:
        result = run_bounded(
            argv,
            timeout_seconds=process_timeout,
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


def _board_binding_count(value: Any, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value.bit_length() > 63
    ):
        raise _fail(f"board binding {label} is invalid")
    return value


def _board_binding_text(value: Any, label: str, *, maximum: int | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise _fail(f"board binding {label} is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise _fail(f"board binding {label} is invalid") from None
    if maximum is not None and len(encoded) > maximum:
        raise _fail(f"board binding {label} exceeds its byte bound")
    return value


def _board_binding_counts(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or list(value) != [
        "errors",
        "warnings",
        "info",
    ]:
        raise _fail("board binding finding counts are invalid")
    return {
        key: _board_binding_count(value[key], f"{key} count")
        for key in ("errors", "warnings", "info")
    }


def _board_binding_replay_evidence(
    summary: Mapping[str, Any],
    *,
    report_raw: bytes,
    board_raw: bytes,
    policy_raw: bytes | None,
    circuit_raw: bytes,
    check: Mapping[str, Any],
    handoff: Mapping[str, Any],
    schematic_raw: bytes,
    approval_required: bool,
) -> dict[str, Any]:
    evidence = _validate_board_binding_summary_opaque(
        summary,
        report_raw=report_raw,
        board_raw=board_raw,
        policy_raw=policy_raw,
        circuit_raw=circuit_raw,
        check=check,
        handoff=handoff,
        schematic_raw=schematic_raw,
    )
    evidence["approval_required"] = approval_required
    return evidence


def _validate_board_binding_summary_opaque(
    summary: Mapping[str, Any],
    *,
    report_raw: bytes,
    board_raw: bytes,
    policy_raw: bytes | None,
    circuit_raw: bytes,
    check: Mapping[str, Any],
    handoff: Mapping[str, Any],
    schematic_raw: bytes,
) -> dict[str, Any]:
    """Validate only bounded board summary metadata; keep the full report opaque."""

    fields = [
        "schema_version",
        "report_schema_version",
        "engine_version",
        "approved",
        "counts",
        "board_source_bytes",
        "board_source_sha256",
        "board_electrical_sha256",
        "circuit_kicad_handoff_sha256",
        "circuit_kicad_handoff",
        "binding_sha256",
        "report_bytes",
        "report_sha256",
    ]
    if list(summary) != fields:
        raise _fail("board binding replay summary has an unexpected shape")
    if (
        isinstance(summary["schema_version"], bool)
        or summary["schema_version"] != 1
        or isinstance(summary["report_schema_version"], bool)
        or summary["report_schema_version"] != 1
        or not isinstance(summary["approved"], bool)
    ):
        raise _fail("board binding replay summary schema is invalid")
    engine = _board_binding_text(
        summary["engine_version"], "summary engine identity", maximum=256
    )
    counts = _board_binding_counts(summary["counts"])
    board_bytes = _board_binding_count(
        summary["board_source_bytes"], "summary board byte count"
    )
    report_bytes = _board_binding_count(
        summary["report_bytes"], "summary report byte count"
    )
    board_sha = _digest(
        summary["board_source_sha256"], "board binding summary board source"
    )
    electrical_sha = _digest(
        summary["board_electrical_sha256"],
        "board binding summary electrical identity",
    )
    handoff_sha = _digest(
        summary["circuit_kicad_handoff_sha256"],
        "board binding summary handoff identity",
    )
    binding_sha = _digest(
        summary["binding_sha256"], "board binding summary binding identity"
    )
    report_sha = _digest(
        summary["report_sha256"], "board binding summary report identity"
    )
    if (
        not report_raw
        or len(report_raw) > MAX_KICAD_BOARD_BINDING_RENDERED_REPORT_BYTES
        or not report_raw.endswith(b"\n")
        or report_raw[:-1].endswith(b"\n")
        or report_bytes != len(report_raw)
        or report_sha != _sha256(report_raw)
    ):
        raise _fail("board binding report identity is invalid")
    if (
        board_bytes == 0
        or board_bytes > MAX_KICAD_BOARD_BINDING_BYTES
        or board_bytes != len(board_raw)
        or board_sha != _sha256(board_raw)
    ):
        raise _fail("board binding board source identity is invalid")

    summary_handoff = summary["circuit_kicad_handoff"]
    handoff_fields = [
        "schema_version",
        "engine_version",
        "circuit_source_bytes",
        "circuit_source_sha256",
        "schematic_source_bytes",
        "schematic_source_sha256",
        "circuit_spec_sha256",
        "circuit_check_sha256",
        "schematic_sha256",
        "policy_sha256",
    ]
    if not isinstance(summary_handoff, Mapping) or list(summary_handoff) != handoff_fields:
        raise _fail("board binding summary nested handoff has an unexpected shape")
    if not isinstance(handoff, Mapping):
        raise _fail("board binding archive handoff is invalid")
    for key in ("schema_version", "circuit_source_bytes", "schematic_source_bytes"):
        if isinstance(summary_handoff[key], bool) or not isinstance(
            summary_handoff[key], int
        ):
            raise _fail("board binding nested handoff byte identity is invalid")
    if (
        summary_handoff["schema_version"] != 1
        or summary_handoff["engine_version"] != engine
        or summary_handoff["circuit_source_bytes"] != len(circuit_raw)
        or summary_handoff["circuit_source_sha256"] != _sha256(circuit_raw)
        or summary_handoff["schematic_source_bytes"] != len(schematic_raw)
        or summary_handoff["schematic_source_sha256"] != _sha256(schematic_raw)
        or summary_handoff["circuit_spec_sha256"] != check["circuit_spec_sha256"]
        or summary_handoff["circuit_check_sha256"] != _sha256(_compact_json(check))
        or summary_handoff["schematic_sha256"] != handoff.get("schematic_sha256")
    ):
        raise _fail("board binding nested handoff source identity is invalid")
    for key in (
        "circuit_source_sha256",
        "schematic_source_sha256",
        "circuit_spec_sha256",
        "circuit_check_sha256",
        "schematic_sha256",
        "policy_sha256",
    ):
        _digest(summary_handoff[key], f"board binding nested handoff {key}")
    if list(handoff) != [
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
    ]:
        raise _fail("board binding nested handoff identity is invalid")
    if any(
        handoff.get(key) != summary_handoff[key]
        for key in handoff_fields
        if key != "policy_sha256"
    ):
        raise _fail("board binding nested handoff identity is invalid")
    if policy_raw is None:
        if handoff.get("policy_sha256") != summary_handoff["policy_sha256"]:
            raise _fail("board binding nested handoff policy identity is invalid")
        expected_handoff_sha = _sha256(
            _BOARD_BINDING_HANDOFF_DOMAIN + _compact_json(dict(handoff))
        )
        if handoff_sha != expected_handoff_sha:
            raise _fail("board binding nested handoff digest is invalid")
    _digest(electrical_sha, "board binding electrical identity")
    _digest(binding_sha, "board binding aggregate identity")
    if policy_raw is not None and (
        not policy_raw
        or len(policy_raw) > MAX_KICAD_BOARD_BINDING_POLICY_BYTES
    ):
        raise _fail("board binding policy identity is invalid")
    return {
        "schema_version": summary["report_schema_version"],
        "engine_version": engine,
        "approved": summary["approved"],
        "approval_required": False,
        "counts": counts,
        "board": {"bytes": board_bytes, "sha256": board_sha},
        "report": {"bytes": report_bytes, "sha256": report_sha},
        "policy": (
            None
            if policy_raw is None
            else {"bytes": len(policy_raw), "sha256": _sha256(policy_raw)}
        ),
        "policy_sha256": summary_handoff["policy_sha256"],
        "board_electrical_sha256": electrical_sha,
        "circuit_kicad_handoff_sha256": handoff_sha,
        "binding_sha256": binding_sha,
    }


def _replay_board_binding(
    circuit_raw: bytes,
    schematic_raw: bytes,
    board_raw: bytes,
    report_raw: bytes,
    policy_raw: bytes | None,
    check: Mapping[str, Any],
    handoff: Mapping[str, Any],
    command: Sequence[str],
    *,
    require_approved: bool,
    deadline: float,
    clock: Callable[[], float],
) -> dict[str, Any]:
    """Replay the standalone board gate in a private fixed-name workspace."""

    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-handoff-board-binding-",
            dir=_trusted_temporary_root(),
        ) as directory:
            root = Path(directory)
            circuit_path = root / CIRCUIT_SPEC_NAME
            schematic_path = root / SCHEMATIC_NAME
            board_path = root / "board.kicad_pcb"
            policy_path = root / "board-binding-policy.json"
            fresh_report_path = root / "board-binding-report.json"
            atomic_write_no_clobber(
                circuit_path,
                circuit_raw,
                max_bytes=MAX_CIRCUIT_SPEC_BYTES,
            )
            _remaining(deadline, clock)
            atomic_write_no_clobber(
                schematic_path,
                schematic_raw,
                max_bytes=MAX_SCHEMATIC_BYTES,
            )
            _remaining(deadline, clock)
            atomic_write_no_clobber(
                board_path,
                board_raw,
                max_bytes=MAX_KICAD_BOARD_BINDING_BYTES,
            )
            _remaining(deadline, clock)
            argv = [
                *command,
                "verify-circuit-kicad-board-binding",
                f"--output={fresh_report_path}",
                "--mcp-echo-report-summary",
            ]
            if policy_raw is not None:
                atomic_write_no_clobber(
                    policy_path,
                    policy_raw,
                    max_bytes=MAX_KICAD_BOARD_BINDING_POLICY_BYTES,
                )
                _remaining(deadline, clock)
                argv.append(f"--policy={policy_path}")
            argv.extend(["--", str(circuit_path), str(schematic_path), str(board_path)])
            outer_remaining = _remaining(deadline, clock)
            cleanup_and_reread_reserve = min(15.0, outer_remaining / 2.0)
            stdout = _run_native(
                argv,
                step="circuit KiCad board binding replay",
                deadline=deadline,
                clock=clock,
                process_timeout_seconds=(
                    outer_remaining - cleanup_and_reread_reserve
                ),
            )
            summary = _strict_object(stdout, "board binding replay summary")
            try:
                fresh_report_raw = read_bytes(
                    fresh_report_path,
                    max_bytes=MAX_KICAD_BOARD_BINDING_RENDERED_REPORT_BYTES,
                )
            except BoundedIOError:
                raise _fail("fresh board binding report is invalid") from None
            if fresh_report_raw != report_raw:
                raise _fail(
                    "fresh board binding replay did not reproduce the retained report"
                )
            evidence = _board_binding_replay_evidence(
                summary,
                report_raw=fresh_report_raw,
                board_raw=board_raw,
                policy_raw=policy_raw,
                circuit_raw=circuit_raw,
                check=check,
                handoff=handoff,
                schematic_raw=schematic_raw,
                approval_required=require_approved,
            )
            for staged_path, expected_raw, maximum in (
                (circuit_path, circuit_raw, MAX_CIRCUIT_SPEC_BYTES),
                (schematic_path, schematic_raw, MAX_SCHEMATIC_BYTES),
                (board_path, board_raw, MAX_KICAD_BOARD_BINDING_BYTES),
                (
                    fresh_report_path,
                    report_raw,
                    MAX_KICAD_BOARD_BINDING_RENDERED_REPORT_BYTES,
                ),
            ):
                if read_bytes(staged_path, max_bytes=maximum) != expected_raw:
                    raise _fail("staged board binding input changed during replay")
                _remaining(deadline, clock)
            if policy_raw is not None:
                if read_bytes(
                    policy_path,
                    max_bytes=MAX_KICAD_BOARD_BINDING_POLICY_BYTES,
                ) != policy_raw:
                    raise _fail("staged board binding policy changed during replay")
                _remaining(deadline, clock)
            return evidence
    except BoundedIOError:
        raise _fail("board binding replay staging failed") from None
    except OSError:
        raise _fail("board binding replay workspace failed") from None


def _ai_quorum_count(value: Any, label: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > MAX_AI_QUORUM_MEMBERS
    ):
        raise _fail(f"AI schematic quorum {label} is invalid")
    return value


def _ai_quorum_thresholds(
    minimum_approvals: Any,
    minimum_distinct_providers: Any,
    minimum_distinct_models: Any,
) -> dict[str, int]:
    policy = {
        "minimum_approvals": _ai_quorum_count(
            minimum_approvals,
            "minimum approval count",
            positive=True,
        ),
        "minimum_distinct_providers": _ai_quorum_count(
            minimum_distinct_providers,
            "minimum distinct provider count",
            positive=True,
        ),
        "minimum_distinct_models": _ai_quorum_count(
            minimum_distinct_models,
            "minimum distinct model count",
            positive=True,
        ),
    }
    if (
        policy["minimum_distinct_providers"] > policy["minimum_approvals"]
        or policy["minimum_distinct_models"] > policy["minimum_approvals"]
    ):
        raise _fail("AI schematic quorum thresholds are inconsistent")
    return policy


def _ai_quorum_path_sequence(value: Any, label: str) -> tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes, bytearray, os.PathLike)) or not isinstance(
        value, Sequence
    ):
        raise _fail(f"AI schematic quorum {label} paths are invalid")
    paths: list[Any] = []
    for path in value:
        if len(paths) == MAX_AI_QUORUM_MEMBERS:
            raise _fail(f"AI schematic quorum {label} count is invalid")
        paths.append(path)
    if not paths:
        raise _fail(f"AI schematic quorum {label} count is invalid")
    return tuple(paths)


def _source_identity(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": _sha256(raw)}


def _is_portable_private_leaf(name: Any) -> bool:
    """Return whether ``name`` is one safe leaf on POSIX and Windows."""

    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or name[-1] in {" ", "."}
        or any(ord(character) < 32 for character in name)
        or any(character in '<>:"/\\|?*' for character in name)
    ):
        return False
    windows_name = PureWindowsPath(name)
    windows_stem = name.partition(".")[0].rstrip(" ").upper()
    return (
        not windows_name.drive
        and not windows_name.root
        and windows_name.parts == (name,)
        and windows_name.name == name
        and windows_stem not in _WINDOWS_RESERVED_LEAF_STEMS
    )


def _catalog_generation_provenance_evidence(
    provenance_raw: bytes,
    fetch_receipt_raw: bytes,
    snapshot_raw: bytes,
    generation_raw: bytes,
    catalog_receipt: Mapping[str, Any],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> dict[str, Any]:
    """Revalidate one captured catalog evidence set without trusting paths."""

    source = catalog_receipt.get("source")
    if not isinstance(source, Mapping) or set(source) != {
        "kind",
        "name",
        "bytes",
        "sha256",
    }:
        raise _fail("catalog generation provenance snapshot source is invalid")
    source_kind = source.get("kind")
    source_name = source.get("name")
    if source_kind == "injected":
        if source_name is not None:
            raise _fail("catalog generation provenance snapshot source is invalid")
        snapshot_source: bytes | Path = snapshot_raw
        temporary_directory = None
    elif source_kind == "file":
        if not _is_portable_private_leaf(source_name):
            raise _fail("catalog generation provenance snapshot source is invalid")
        try:
            temporary_directory = tempfile.TemporaryDirectory(
                prefix="pcbex-handoff-catalog-provenance-",
                dir=_trusted_temporary_root(),
            )
        except OSError:
            raise _fail("catalog generation provenance workspace failed") from None
        workspace = Path(temporary_directory.name)
        snapshot_source = workspace / source_name
        if snapshot_source.parent != workspace or snapshot_source.name != source_name:
            try:
                temporary_directory.cleanup()
            except OSError:
                raise _fail(
                    "catalog generation provenance workspace cleanup failed"
                ) from None
            raise _fail("catalog generation provenance snapshot source is invalid")
    else:
        raise _fail("catalog generation provenance snapshot source is invalid")

    try:
        if temporary_directory is not None:
            atomic_write_no_clobber(
                snapshot_source,
                snapshot_raw,
                max_bytes=MAX_CATALOG_RAW_BYTES,
            )
            _remaining(deadline, clock)
        validated = validate_catalog_generation_provenance(
            provenance_raw,
            fetch_receipt_raw,
            snapshot_source,
            generation_raw,
        )
    except CircuitHandoffBundleError:
        raise
    except (CatalogGenerationProvenanceError, BoundedIOError, OSError, TypeError):
        raise _fail("catalog generation provenance replay failed closed") from None
    finally:
        if temporary_directory is not None:
            try:
                temporary_directory.cleanup()
            except OSError:
                raise _fail(
                    "catalog generation provenance workspace cleanup failed"
                ) from None
    _remaining(deadline, clock)

    if (
        validated.get("schema_version") != PROVENANCE_SCHEMA_VERSION
        or validated.get("adapter") != PROVENANCE_ADAPTER
        or validated.get("fetch_receipt_sha256") != _sha256(fetch_receipt_raw)
        or validated.get("snapshot_sha256") != _sha256(snapshot_raw)
        or validated.get("generation_bundle_sha256") != _sha256(generation_raw)
    ):
        raise _fail("catalog generation provenance replay identity is invalid")
    evidence = copy.deepcopy(dict(validated))
    evidence["sources"] = {
        "provenance": _source_identity(provenance_raw),
        "fetch_receipt": _source_identity(fetch_receipt_raw),
        "snapshot": _source_identity(snapshot_raw),
    }
    return evidence


def _ai_replay_request_sha256(request_raw: bytes) -> str:
    request = _strict_object(request_raw, "AI review request")
    if (
        type(request.get("schema_version")) is not int
        or request.get("schema_version") != 1
        or "artifact_binding" in request
    ):
        raise _fail("AI review request is not replayable schema v1")
    request_sha256 = _digest(
        request.get("request_sha256"),
        "AI review request",
    )
    assert isinstance(request_sha256, str)
    return request_sha256


def _ai_quorum_report_evidence(
    report_raw: bytes,
    request_raw: bytes,
    policy_pack_raw: bytes,
    approvals_raw: Sequence[bytes],
    responses_raw: Sequence[bytes],
    *,
    expected_policy: Mapping[str, int],
    quorum_required: bool,
) -> dict[str, Any]:
    request_sha256 = _ai_replay_request_sha256(request_raw)

    report = _strict_object(report_raw, "AI schematic quorum report")
    expected_report_keys = {
        "schema_version",
        "request_sha256",
        "policy",
        "counts",
        "members",
        "quorum_met",
        "quorum_failures",
    }
    if (
        set(report) != expected_report_keys
        or type(report["schema_version"]) is not int
        or report["schema_version"] != 1
        or report["request_sha256"] != request_sha256
    ):
        raise _fail("AI schematic quorum report schema or request binding is invalid")

    policy = report["policy"]
    if not isinstance(policy, Mapping) or set(policy) != set(expected_policy):
        raise _fail("AI schematic quorum report policy is invalid")
    checked_policy = {
        key: _ai_quorum_count(
            policy[key],
            key.replace("_", " "),
            positive=True,
        )
        for key in expected_policy
    }
    if checked_policy != dict(expected_policy):
        raise _fail("AI schematic quorum report policy is invalid")

    count_keys = (
        "members",
        "approvals",
        "rejections",
        "distinct_providers",
        "distinct_models",
    )
    counts = report["counts"]
    members = report["members"]
    if not isinstance(counts, Mapping) or set(counts) != set(count_keys):
        raise _fail("AI schematic quorum report counts are invalid")
    checked_counts = {
        key: _ai_quorum_count(
            counts[key],
            f"{key.replace('_', ' ')} count",
            positive=key == "members",
        )
        for key in count_keys
    }
    if (
        not isinstance(members, list)
        or not members
        or len(members) > MAX_AI_QUORUM_MEMBERS
        or len(members) != len(approvals_raw)
        or len(members) != len(responses_raw)
    ):
        raise _fail("AI schematic quorum report members are invalid")

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
    signer_ids: set[str] = set()
    public_keys: set[str] = set()
    response_digests: set[str] = set()
    approved_count = 0
    previous_signer_id: str | None = None
    for member in members:
        if not isinstance(member, Mapping) or set(member) != member_keys:
            raise _fail("AI schematic quorum report member is invalid")
        for field in ("signer_id", "provider", "model"):
            value = member[field]
            if not isinstance(value, str) or not value:
                raise _fail("AI schematic quorum report member identity is invalid")
        public_key = _digest(member["public_key"], "AI quorum public key")
        response_sha256 = _digest(
            member["response_sha256"],
            "AI quorum response",
        )
        assert isinstance(public_key, str)
        assert isinstance(response_sha256, str)
        version = member["version"]
        if version is not None and (
            not isinstance(version, str) or not version
        ):
            raise _fail("AI schematic quorum report model version is invalid")
        approved = member["approved"]
        failures = member["gate_failures"]
        if (
            not isinstance(approved, bool)
            or not isinstance(failures, list)
            or any(not isinstance(item, str) or not item for item in failures)
            or approved != (len(failures) == 0)
        ):
            raise _fail("AI schematic quorum report member decision is invalid")

        signer_id = member["signer_id"]
        if previous_signer_id is not None and signer_id <= previous_signer_id:
            raise _fail("AI schematic quorum report member ordering is invalid")
        previous_signer_id = signer_id
        if (
            signer_id in signer_ids
            or public_key in public_keys
            or response_sha256 in response_digests
        ):
            raise _fail("AI schematic quorum report member identity is duplicated")
        signer_ids.add(signer_id)
        public_keys.add(public_key)
        response_digests.add(response_sha256)
        if approved:
            approved_count += 1

    if (
        checked_counts["members"] != len(members)
        or checked_counts["approvals"] != approved_count
        or checked_counts["rejections"] != len(members) - approved_count
        or checked_counts["distinct_providers"] > approved_count
        or checked_counts["distinct_models"] > approved_count
        or checked_counts["distinct_models"]
        < checked_counts["distinct_providers"]
        or (
            approved_count == 0
            and (
                checked_counts["distinct_providers"] != 0
                or checked_counts["distinct_models"] != 0
            )
        )
        or (
            approved_count > 0
            and (
                checked_counts["distinct_providers"] == 0
                or checked_counts["distinct_models"] == 0
            )
        )
    ):
        raise _fail("AI schematic quorum report counts do not match its members")

    quorum_met = report["quorum_met"]
    quorum_failures = report["quorum_failures"]
    if not isinstance(quorum_met, bool) or not isinstance(quorum_failures, list):
        raise _fail("AI schematic quorum report decision is invalid")
    expected_failures: list[str] = []
    for label, required, actual in (
        (
            "insufficient_approvals",
            expected_policy["minimum_approvals"],
            checked_counts["approvals"],
        ),
        (
            "insufficient_distinct_providers",
            expected_policy["minimum_distinct_providers"],
            checked_counts["distinct_providers"],
        ),
        (
            "insufficient_distinct_models",
            expected_policy["minimum_distinct_models"],
            checked_counts["distinct_models"],
        ),
    ):
        if actual < required:
            expected_failures.append(f"{label}:required={required}:actual={actual}")
    if quorum_failures != expected_failures or quorum_met != (not expected_failures):
        raise _fail("AI schematic quorum report decision is inconsistent")

    return {
        "schema_version": 1,
        "quorum_met": quorum_met,
        "quorum_required": quorum_required,
        "request_sha256": request_sha256,
        "policy": copy.deepcopy(dict(expected_policy)),
        "counts": checked_counts,
        "report": _source_identity(report_raw),
        "sources": {
            "request": _source_identity(request_raw),
            "policy_pack": _source_identity(policy_pack_raw),
            "members": [
                {
                    "approval": _source_identity(approval_raw),
                    "response": _source_identity(response_raw),
                }
                for approval_raw, response_raw in zip(
                    approvals_raw,
                    responses_raw,
                    strict=True,
                )
            ],
        },
    }


def _replay_ai_quorum(
    schematic_raw: bytes,
    retained_report_raw: bytes,
    request_raw: bytes,
    policy_pack_raw: bytes,
    approvals_raw: Sequence[bytes],
    responses_raw: Sequence[bytes],
    command: Sequence[str],
    *,
    policy: Mapping[str, int],
    require_quorum: bool,
    deadline: float,
    clock: Callable[[], float],
) -> dict[str, Any]:
    try:
        with tempfile.TemporaryDirectory(
            prefix="pcbex-handoff-ai-quorum-",
            dir=_trusted_temporary_root(),
        ) as directory:
            root = Path(directory)
            schematic_path = root / SCHEMATIC_NAME
            request_path = root / "ai-review-request.json"
            policy_pack_path = root / "ai-policy-pack.json"
            report_path = root / "fresh-ai-quorum.json"
            atomic_write_no_clobber(
                schematic_path,
                schematic_raw,
                max_bytes=MAX_SCHEMATIC_BYTES,
            )
            atomic_write_no_clobber(
                request_path,
                request_raw,
                max_bytes=MAX_AI_QUORUM_INPUT_BYTES,
            )
            atomic_write_no_clobber(
                policy_pack_path,
                policy_pack_raw,
                max_bytes=MAX_AI_QUORUM_INPUT_BYTES,
            )
            staged_inputs: list[tuple[Path, bytes, int]] = [
                (schematic_path, schematic_raw, MAX_SCHEMATIC_BYTES),
                (request_path, request_raw, MAX_AI_QUORUM_INPUT_BYTES),
                (policy_pack_path, policy_pack_raw, MAX_AI_QUORUM_INPUT_BYTES),
            ]
            approval_paths: list[Path] = []
            response_paths: list[Path] = []
            for index, (approval_raw, response_raw) in enumerate(
                zip(approvals_raw, responses_raw, strict=True)
            ):
                approval_path = root / f"approval-{index:03d}.json"
                response_path = root / f"response-{index:03d}.json"
                atomic_write_no_clobber(
                    approval_path,
                    approval_raw,
                    max_bytes=MAX_AI_QUORUM_INPUT_BYTES,
                )
                atomic_write_no_clobber(
                    response_path,
                    response_raw,
                    max_bytes=MAX_AI_QUORUM_INPUT_BYTES,
                )
                approval_paths.append(approval_path)
                response_paths.append(response_path)
                staged_inputs.extend(
                    (
                        (approval_path, approval_raw, MAX_AI_QUORUM_INPUT_BYTES),
                        (response_path, response_raw, MAX_AI_QUORUM_INPUT_BYTES),
                    )
                )
            _remaining(deadline, clock)
            argv = [
                *command,
                "verify-ai-quorum",
                f"--schematic={schematic_path}",
                f"--policy-pack={policy_pack_path}",
                f"--minimum-approvals={policy['minimum_approvals']}",
                "--minimum-distinct-providers="
                f"{policy['minimum_distinct_providers']}",
                f"--minimum-distinct-models={policy['minimum_distinct_models']}",
                f"--output={report_path}",
                *(f"--approval={path}" for path in approval_paths),
                *(f"--response={path}" for path in response_paths),
                "--",
                str(request_path),
            ]
            outer_remaining = _remaining(deadline, clock)
            cleanup_reserve = min(15.0, outer_remaining / 2.0)
            stdout = _run_native(
                argv,
                step="AI schematic quorum replay",
                deadline=deadline,
                clock=clock,
                process_timeout_seconds=outer_remaining - cleanup_reserve,
            )
            if stdout:
                raise _fail("native AI schematic quorum replay stdout is invalid")
            try:
                fresh_report_raw = read_bytes(
                    report_path,
                    max_bytes=MAX_AI_QUORUM_REPORT_BYTES,
                )
            except BoundedIOError:
                raise _fail("fresh AI schematic quorum report is invalid") from None
            if not fresh_report_raw or fresh_report_raw != retained_report_raw:
                raise _fail(
                    "fresh AI schematic quorum replay did not reproduce the retained report"
                )
            for staged_path, expected_raw, maximum in staged_inputs:
                if read_bytes(staged_path, max_bytes=maximum) != expected_raw:
                    raise _fail("staged AI schematic quorum input changed during replay")
            _remaining(deadline, clock)
            return _ai_quorum_report_evidence(
                fresh_report_raw,
                request_raw,
                policy_pack_raw,
                approvals_raw,
                responses_raw,
                expected_policy=policy,
                quorum_required=require_quorum,
            )
    except BoundedIOError:
        raise _fail("AI schematic quorum replay staging failed") from None
    except OSError:
        raise _fail("AI schematic quorum replay workspace failed") from None


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


def circuit_handoff_bundle_ai_quorum_replay_result_json_schema() -> dict[str, Any]:
    """Return the closed exact-chain plus AI schematic quorum replay schema."""

    schema = copy.deepcopy(circuit_handoff_bundle_replay_result_json_schema())
    schema["$id"] = (
        "https://github.com/penguin425/pcbex/schemas/"
        "circuit-generation-kicad-handoff-bundle-ai-quorum-replay-result-v3.json"
    )
    schema["title"] = "pcbex circuit handoff bundle AI quorum replay result"
    schema["required"].append("ai_schematic_quorum")
    properties = schema["properties"]
    properties["schema_version"] = {
        "const": CIRCUIT_HANDOFF_BUNDLE_AI_QUORUM_REPLAY_RESULT_SCHEMA_VERSION
    }
    properties["verification_scope"] = {
        "const": CIRCUIT_HANDOFF_BUNDLE_AI_QUORUM_REPLAY_SCOPE
    }
    validation = properties["validation"]
    validation["required"].append("ai_schematic_quorum_replayed")
    validation["properties"]["ai_schematic_quorum_replayed"] = {"const": True}
    validation["properties"]["native_kicad_erc_replayed"] = {"type": "boolean"}

    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    source = {
        "type": "object",
        "additionalProperties": False,
        "required": ["bytes", "sha256"],
        "properties": {
            "bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_AI_QUORUM_INPUT_BYTES,
            },
            "sha256": digest,
        },
    }
    report_source = copy.deepcopy(source)
    report_source["properties"]["bytes"]["maximum"] = MAX_AI_QUORUM_REPORT_BYTES
    policy = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "minimum_approvals",
            "minimum_distinct_providers",
            "minimum_distinct_models",
        ],
        "properties": {
            "minimum_approvals": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_AI_QUORUM_MEMBERS,
            },
            "minimum_distinct_providers": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_AI_QUORUM_MEMBERS,
            },
            "minimum_distinct_models": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_AI_QUORUM_MEMBERS,
            },
        },
    }
    counts = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "members",
            "approvals",
            "rejections",
            "distinct_providers",
            "distinct_models",
        ],
        "properties": {
            "members": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_AI_QUORUM_MEMBERS,
            },
            "approvals": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_AI_QUORUM_MEMBERS,
            },
            "rejections": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_AI_QUORUM_MEMBERS,
            },
            "distinct_providers": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_AI_QUORUM_MEMBERS,
            },
            "distinct_models": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_AI_QUORUM_MEMBERS,
            },
        },
    }
    pair = {
        "type": "object",
        "additionalProperties": False,
        "required": ["approval", "response"],
        "properties": {
            "approval": copy.deepcopy(source),
            "response": copy.deepcopy(source),
        },
    }
    properties["ai_schematic_quorum"] = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "quorum_met",
            "quorum_required",
            "request_sha256",
            "policy",
            "counts",
            "report",
            "sources",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "quorum_met": {"type": "boolean"},
            "quorum_required": {"type": "boolean"},
            "request_sha256": digest,
            "policy": policy,
            "counts": counts,
            "report": report_source,
            "sources": {
                "type": "object",
                "additionalProperties": False,
                "required": ["request", "policy_pack", "members"],
                "properties": {
                    "request": copy.deepcopy(source),
                    "policy_pack": copy.deepcopy(source),
                    "members": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": MAX_AI_QUORUM_MEMBERS,
                        "items": pair,
                    },
                },
            },
        },
        "oneOf": [
            {"properties": {"quorum_required": {"const": False}}},
            {
                "properties": {
                    "quorum_required": {"const": True},
                    "quorum_met": {"const": True},
                }
            },
        ],
    }
    properties["native_kicad_erc"] = copy.deepcopy(
        circuit_handoff_bundle_native_erc_replay_result_json_schema()["properties"][
            "native_kicad_erc"
        ]
    )
    schema["allOf"] = [
        {
            "oneOf": [
                {
                    "not": {"required": ["native_kicad_erc"]},
                    "properties": {
                        "validation": {
                            "properties": {
                                "native_kicad_erc_replayed": {"const": False}
                            }
                        }
                    },
                },
                {
                    "required": ["native_kicad_erc"],
                    "properties": {
                        "validation": {
                            "properties": {
                                "native_kicad_erc_replayed": {"const": True}
                            }
                        }
                    },
                },
            ]
        }
    ]
    return schema


def circuit_handoff_bundle_catalog_provenance_replay_result_json_schema() -> dict[str, Any]:
    """Return the closed exact-chain plus catalog provenance replay schema."""

    schema = copy.deepcopy(circuit_handoff_bundle_replay_result_json_schema())
    schema["$id"] = (
        "https://github.com/penguin425/pcbex/schemas/"
        "circuit-generation-kicad-handoff-bundle-catalog-provenance-"
        "replay-result-v4.json"
    )
    schema["title"] = (
        "pcbex circuit handoff bundle catalog provenance replay result"
    )
    schema["required"].append("catalog_generation_provenance")
    properties = schema["properties"]
    properties["schema_version"] = {
        "const": CIRCUIT_HANDOFF_BUNDLE_CATALOG_PROVENANCE_REPLAY_RESULT_SCHEMA_VERSION
    }
    properties["verification_scope"] = {
        "const": CIRCUIT_HANDOFF_BUNDLE_CATALOG_PROVENANCE_REPLAY_SCOPE
    }

    validation = properties["validation"]
    validation["required"].extend(
        [
            "ai_schematic_quorum_replayed",
            "catalog_generation_provenance_replayed",
        ]
    )
    validation_properties = validation["properties"]
    validation_properties["catalog_input_erc_required"] = {"const": True}
    validation_properties["catalog_input_erc_replayed"] = {"const": True}
    validation_properties["native_kicad_erc_replayed"] = {"type": "boolean"}
    validation_properties["ai_schematic_quorum_replayed"] = {"type": "boolean"}
    validation_properties["catalog_generation_provenance_replayed"] = {
        "const": True
    }
    schema.pop("oneOf", None)

    native_schema = circuit_handoff_bundle_native_erc_replay_result_json_schema()
    ai_schema = circuit_handoff_bundle_ai_quorum_replay_result_json_schema()
    properties["native_kicad_erc"] = copy.deepcopy(
        native_schema["properties"]["native_kicad_erc"]
    )
    properties["ai_schematic_quorum"] = copy.deepcopy(
        ai_schema["properties"]["ai_schematic_quorum"]
    )

    provenance_schema = catalog_generation_provenance_json_schema()
    provenance_required = list(provenance_schema["required"])
    provenance_properties = copy.deepcopy(provenance_schema["properties"])
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}

    def source(maximum: int) -> dict[str, Any]:
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
                "sha256": copy.deepcopy(digest),
            },
        }

    properties["catalog_generation_provenance"] = {
        "type": "object",
        "additionalProperties": False,
        "required": [*provenance_required, "sources"],
        "properties": {
            **provenance_properties,
            "sources": {
                "type": "object",
                "additionalProperties": False,
                "required": ["provenance", "fetch_receipt", "snapshot"],
                "properties": {
                    "provenance": source(MAX_PROVENANCE_BYTES),
                    "fetch_receipt": source(MAXIMUM_RECEIPT_BYTES),
                    "snapshot": source(MAX_CATALOG_RAW_BYTES),
                },
            },
        },
    }

    def evidence_presence(field: str, replayed: str) -> dict[str, Any]:
        return {
            "oneOf": [
                {
                    "not": {"required": [field]},
                    "properties": {
                        "validation": {
                            "properties": {replayed: {"const": False}}
                        }
                    },
                },
                {
                    "required": [field],
                    "properties": {
                        "validation": {
                            "properties": {replayed: {"const": True}}
                        }
                    },
                },
            ]
        }

    schema["allOf"] = [
        evidence_presence("native_kicad_erc", "native_kicad_erc_replayed"),
        evidence_presence("ai_schematic_quorum", "ai_schematic_quorum_replayed"),
    ]
    return schema


def circuit_handoff_bundle_board_binding_replay_result_json_schema() -> dict[str, Any]:
    """Return the closed exact-chain plus retained board-binding schema."""

    schema = copy.deepcopy(circuit_handoff_bundle_replay_result_json_schema())
    schema["$id"] = (
        "https://github.com/penguin425/pcbex/schemas/"
        "circuit-generation-kicad-handoff-bundle-board-binding-"
        "replay-result-v5.json"
    )
    schema["title"] = "pcbex circuit handoff bundle board binding replay result"
    schema["required"].append("board_binding")
    properties = schema["properties"]
    properties["schema_version"] = {
        "const": CIRCUIT_HANDOFF_BUNDLE_BOARD_BINDING_REPLAY_RESULT_SCHEMA_VERSION
    }
    properties["verification_scope"] = {
        "const": CIRCUIT_HANDOFF_BUNDLE_BOARD_BINDING_REPLAY_SCOPE
    }
    validation = properties["validation"]
    for replay_flag in (
        "native_kicad_erc_replayed",
        "ai_schematic_quorum_replayed",
        "catalog_generation_provenance_replayed",
        "board_binding_replayed",
    ):
        if replay_flag not in validation["required"]:
            validation["required"].append(replay_flag)
    validation["properties"]["board_binding_replayed"] = {"const": True}
    validation["properties"]["native_kicad_erc_replayed"] = {"type": "boolean"}
    validation["properties"]["ai_schematic_quorum_replayed"] = {
        "type": "boolean"
    }
    validation["properties"]["catalog_generation_provenance_replayed"] = {
        "type": "boolean"
    }

    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    count = {"type": "integer", "minimum": 0, "maximum": (1 << 63) - 1}

    def source(maximum: int) -> dict[str, Any]:
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
                "sha256": copy.deepcopy(digest),
            },
        }

    properties["board_binding"] = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "engine_version",
            "approved",
            "approval_required",
            "counts",
            "board",
            "report",
            "policy",
            "policy_sha256",
            "board_electrical_sha256",
            "circuit_kicad_handoff_sha256",
            "binding_sha256",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "engine_version": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
            },
            "approved": {"type": "boolean"},
            "approval_required": {"type": "boolean"},
            "counts": {
                "type": "object",
                "additionalProperties": False,
                "required": ["errors", "warnings", "info"],
                "properties": {
                    "errors": copy.deepcopy(count),
                    "warnings": copy.deepcopy(count),
                    "info": copy.deepcopy(count),
                },
            },
            "board": source(MAX_KICAD_BOARD_BINDING_BYTES),
            "report": source(MAX_KICAD_BOARD_BINDING_RENDERED_REPORT_BYTES),
            "policy": {
                "anyOf": [
                    {"type": "null"},
                    source(MAX_KICAD_BOARD_BINDING_POLICY_BYTES),
                ]
            },
            "policy_sha256": copy.deepcopy(digest),
            "board_electrical_sha256": copy.deepcopy(digest),
            "circuit_kicad_handoff_sha256": copy.deepcopy(digest),
            "binding_sha256": copy.deepcopy(digest),
        },
        "oneOf": [
            {
                "properties": {
                    "approval_required": {"const": False},
                }
            },
            {
                "properties": {
                    "approval_required": {"const": True},
                    "approved": {"const": True},
                }
            },
        ],
    }

    native_schema = circuit_handoff_bundle_native_erc_replay_result_json_schema()
    ai_schema = circuit_handoff_bundle_ai_quorum_replay_result_json_schema()
    catalog_schema = circuit_handoff_bundle_catalog_provenance_replay_result_json_schema()
    properties["native_kicad_erc"] = copy.deepcopy(
        native_schema["properties"]["native_kicad_erc"]
    )
    properties["ai_schematic_quorum"] = copy.deepcopy(
        ai_schema["properties"]["ai_schematic_quorum"]
    )
    properties["catalog_generation_provenance"] = copy.deepcopy(
        catalog_schema["properties"]["catalog_generation_provenance"]
    )

    def evidence_presence(field: str, replayed: str) -> dict[str, Any]:
        return {
            "oneOf": [
                {
                    "not": {"required": [field]},
                    "properties": {
                        "validation": {
                            "properties": {replayed: {"const": False}}
                        }
                    },
                },
                {
                    "required": [field],
                    "properties": {
                        "validation": {
                            "properties": {replayed: {"const": True}}
                        }
                    },
                },
            ]
        }

    schema["allOf"] = [
        evidence_presence("native_kicad_erc", "native_kicad_erc_replayed"),
        evidence_presence("ai_schematic_quorum", "ai_schematic_quorum_replayed"),
        evidence_presence(
            "catalog_generation_provenance",
            "catalog_generation_provenance_replayed",
        ),
    ]
    return schema


def circuit_handoff_bundle_manufacturing_replay_result_json_schema() -> dict[str, Any]:
    """Return the closed v5 board-binding plus manufacturing replay schema."""

    schema = copy.deepcopy(
        circuit_handoff_bundle_board_binding_replay_result_json_schema()
    )
    schema["$id"] = (
        "https://github.com/penguin425/pcbex/schemas/"
        "circuit-generation-kicad-handoff-bundle-manufacturing-package-"
        "replay-result-v6.json"
    )
    schema["title"] = (
        "pcbex circuit handoff bundle manufacturing-package replay result"
    )
    schema["required"].append("manufacturing_package")
    properties = schema["properties"]
    properties["schema_version"] = {
        "const": CIRCUIT_HANDOFF_BUNDLE_MANUFACTURING_REPLAY_RESULT_SCHEMA_VERSION
    }
    properties["verification_scope"] = {
        "const": CIRCUIT_HANDOFF_BUNDLE_MANUFACTURING_REPLAY_SCOPE
    }
    validation = properties["validation"]
    for replay_flag in (
        "manufacturing_package_replayed",
        "manufacturing_board_identity_matched",
    ):
        validation["required"].append(replay_flag)
        validation["properties"][replay_flag] = {"const": True}

    standalone = _manufacturing_replay.manufacturing_package_replay_result_json_schema()
    properties["manufacturing_package"] = {
        key: copy.deepcopy(standalone[key])
        for key in ("type", "additionalProperties", "required", "properties")
    }
    return schema


def circuit_handoff_bundle_pipeline_replay_result_json_schema() -> dict[str, Any]:
    """Return the closed v6 plus deterministic-pipeline replay schema."""

    schema = copy.deepcopy(
        circuit_handoff_bundle_manufacturing_replay_result_json_schema()
    )
    schema["$id"] = (
        "https://github.com/penguin425/pcbex/schemas/"
        "circuit-generation-kicad-handoff-bundle-manufacturing-pipeline-"
        "replay-result-v7.json"
    )
    schema["title"] = (
        "pcbex circuit handoff bundle manufacturing-pipeline replay result"
    )
    schema["required"].append("deterministic_pipeline")
    properties = schema["properties"]
    properties["schema_version"] = {
        "const": CIRCUIT_HANDOFF_BUNDLE_PIPELINE_REPLAY_RESULT_SCHEMA_VERSION
    }
    properties["verification_scope"] = {
        "const": CIRCUIT_HANDOFF_BUNDLE_PIPELINE_REPLAY_SCOPE
    }
    validation = properties["validation"]
    for replay_flag in (
        "deterministic_pipeline_replayed",
        "pipeline_circuit_spec_matched",
        "pipeline_schematic_matched",
        "pipeline_effective_policy_matched",
        "pipeline_board_matched",
        "pipeline_manufacturing_package_matched",
        "pipeline_board_binding_matched",
    ):
        validation["required"].append(replay_flag)
        validation["properties"][replay_flag] = {"const": True}

    standalone = (
        _deterministic_pipeline_replay.deterministic_pipeline_replay_result_json_schema()
    )
    properties["deterministic_pipeline"] = {
        key: copy.deepcopy(standalone[key])
        for key in ("type", "additionalProperties", "required", "properties")
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


def _circuit_handoff_ai_quorum_replay_result(
    verification: Mapping[str, Any],
    *,
    catalog_input_erc_required: bool,
    ai_schematic_quorum: Mapping[str, Any],
    native_kicad_erc: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if native_kicad_erc is None:
        result = _circuit_handoff_replay_result(
            verification,
            catalog_input_erc_required=catalog_input_erc_required,
        )
    else:
        result = _circuit_handoff_native_erc_replay_result(
            verification,
            catalog_input_erc_required=catalog_input_erc_required,
            native_kicad_erc=native_kicad_erc,
        )
    result["schema_version"] = (
        CIRCUIT_HANDOFF_BUNDLE_AI_QUORUM_REPLAY_RESULT_SCHEMA_VERSION
    )
    result["verification_scope"] = CIRCUIT_HANDOFF_BUNDLE_AI_QUORUM_REPLAY_SCOPE
    result["validation"]["ai_schematic_quorum_replayed"] = True
    result["ai_schematic_quorum"] = copy.deepcopy(dict(ai_schematic_quorum))
    return result


def _circuit_handoff_catalog_provenance_replay_result(
    verification: Mapping[str, Any],
    *,
    catalog_input_erc_required: bool,
    catalog_generation_provenance: Mapping[str, Any],
    native_kicad_erc: Mapping[str, Any] | None,
    ai_schematic_quorum: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if ai_schematic_quorum is not None:
        result = _circuit_handoff_ai_quorum_replay_result(
            verification,
            catalog_input_erc_required=catalog_input_erc_required,
            ai_schematic_quorum=ai_schematic_quorum,
            native_kicad_erc=native_kicad_erc,
        )
    elif native_kicad_erc is not None:
        result = _circuit_handoff_native_erc_replay_result(
            verification,
            catalog_input_erc_required=catalog_input_erc_required,
            native_kicad_erc=native_kicad_erc,
        )
    else:
        result = _circuit_handoff_replay_result(
            verification,
            catalog_input_erc_required=catalog_input_erc_required,
        )
    result["schema_version"] = (
        CIRCUIT_HANDOFF_BUNDLE_CATALOG_PROVENANCE_REPLAY_RESULT_SCHEMA_VERSION
    )
    result["verification_scope"] = (
        CIRCUIT_HANDOFF_BUNDLE_CATALOG_PROVENANCE_REPLAY_SCOPE
    )
    result["validation"]["ai_schematic_quorum_replayed"] = (
        ai_schematic_quorum is not None
    )
    result["validation"]["catalog_generation_provenance_replayed"] = True
    result["catalog_generation_provenance"] = copy.deepcopy(
        dict(catalog_generation_provenance)
    )
    return result


def _circuit_handoff_board_binding_replay_result(
    verification: Mapping[str, Any],
    *,
    catalog_input_erc_required: bool,
    board_binding: Mapping[str, Any],
    native_kicad_erc: Mapping[str, Any] | None,
    ai_schematic_quorum: Mapping[str, Any] | None,
    catalog_generation_provenance: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if catalog_generation_provenance is not None:
        result = _circuit_handoff_catalog_provenance_replay_result(
            verification,
            catalog_input_erc_required=catalog_input_erc_required,
            catalog_generation_provenance=catalog_generation_provenance,
            native_kicad_erc=native_kicad_erc,
            ai_schematic_quorum=ai_schematic_quorum,
        )
    elif ai_schematic_quorum is not None:
        result = _circuit_handoff_ai_quorum_replay_result(
            verification,
            catalog_input_erc_required=catalog_input_erc_required,
            ai_schematic_quorum=ai_schematic_quorum,
            native_kicad_erc=native_kicad_erc,
        )
    elif native_kicad_erc is not None:
        result = _circuit_handoff_native_erc_replay_result(
            verification,
            catalog_input_erc_required=catalog_input_erc_required,
            native_kicad_erc=native_kicad_erc,
        )
    else:
        result = _circuit_handoff_replay_result(
            verification,
            catalog_input_erc_required=catalog_input_erc_required,
        )
    result["schema_version"] = (
        CIRCUIT_HANDOFF_BUNDLE_BOARD_BINDING_REPLAY_RESULT_SCHEMA_VERSION
    )
    result["verification_scope"] = CIRCUIT_HANDOFF_BUNDLE_BOARD_BINDING_REPLAY_SCOPE
    result["validation"]["native_kicad_erc_replayed"] = (
        native_kicad_erc is not None
    )
    result["validation"]["ai_schematic_quorum_replayed"] = (
        ai_schematic_quorum is not None
    )
    result["validation"]["catalog_generation_provenance_replayed"] = (
        catalog_generation_provenance is not None
    )
    result["validation"]["board_binding_replayed"] = True
    result["board_binding"] = copy.deepcopy(dict(board_binding))
    return result


def _circuit_handoff_manufacturing_replay_result(
    board_binding_result: Mapping[str, Any],
    *,
    manufacturing_package: Mapping[str, Any],
) -> dict[str, Any]:
    result = copy.deepcopy(dict(board_binding_result))
    result["schema_version"] = (
        CIRCUIT_HANDOFF_BUNDLE_MANUFACTURING_REPLAY_RESULT_SCHEMA_VERSION
    )
    result["verification_scope"] = CIRCUIT_HANDOFF_BUNDLE_MANUFACTURING_REPLAY_SCOPE
    result["validation"]["manufacturing_package_replayed"] = True
    result["validation"]["manufacturing_board_identity_matched"] = True
    result["manufacturing_package"] = copy.deepcopy(dict(manufacturing_package))
    return result


def _circuit_handoff_pipeline_replay_result(
    manufacturing_result: Mapping[str, Any],
    *,
    deterministic_pipeline: Mapping[str, Any],
) -> dict[str, Any]:
    result = copy.deepcopy(dict(manufacturing_result))
    result["schema_version"] = (
        CIRCUIT_HANDOFF_BUNDLE_PIPELINE_REPLAY_RESULT_SCHEMA_VERSION
    )
    result["verification_scope"] = CIRCUIT_HANDOFF_BUNDLE_PIPELINE_REPLAY_SCOPE
    for validation in (
        "deterministic_pipeline_replayed",
        "pipeline_circuit_spec_matched",
        "pipeline_schematic_matched",
        "pipeline_effective_policy_matched",
        "pipeline_board_matched",
        "pipeline_manufacturing_package_matched",
        "pipeline_board_binding_matched",
    ):
        result["validation"][validation] = True
    result["deterministic_pipeline"] = copy.deepcopy(
        dict(deterministic_pipeline)
    )
    return result


def _validate_pipeline_handoff_cross_binding(
    capture: _deterministic_pipeline_replay._DeterministicPipelineReplayCapture,
    report: Mapping[str, Any],
    entries: Mapping[str, bytes],
    board_binding: Mapping[str, Any],
    board_binding_report_raw: bytes,
    manufacturing_package: Mapping[str, Any],
) -> None:
    """Require the fresh pipeline evidence to use the exact v6 artifacts."""

    role_sources = dict(capture.role_sources)
    required_roles = {
        "circuit_spec",
        "schematic",
        "electrical_review",
        "board",
        "manufacturing_package",
    }
    if not required_roles.issubset(role_sources):
        raise _fail("deterministic pipeline capture is missing a shared artifact")
    if role_sources["circuit_spec"] != entries[CIRCUIT_SPEC_NAME]:
        raise _fail("deterministic pipeline circuit specification does not match handoff")
    if role_sources["schematic"] != entries[SCHEMATIC_NAME]:
        raise _fail("deterministic pipeline schematic does not match handoff")

    board_identity = board_binding.get("board")
    if (
        not isinstance(board_identity, Mapping)
        or board_identity.get("bytes") != len(role_sources["board"])
        or board_identity.get("sha256") != _sha256(role_sources["board"])
    ):
        raise _fail("deterministic pipeline board does not match board binding")

    package = manufacturing_package.get("package")
    package_identity = _source_identity(role_sources["manufacturing_package"])
    if (
        not isinstance(package, Mapping)
        or package.get("retained") != package_identity
        or package.get("fresh") != package_identity
        or package.get("identical") is not True
    ):
        raise _fail(
            "deterministic pipeline manufacturing package does not match replay"
        )
    binding = report.get("binding")
    pipeline = report.get("pipeline")
    if not isinstance(binding, Mapping) or not isinstance(pipeline, Mapping):
        raise _fail("deterministic pipeline has no cross-bindable gate evidence")
    handoff = binding.get("circuit_kicad_handoff")
    if not isinstance(handoff, Mapping):
        raise _fail("deterministic pipeline has no cross-bindable handoff evidence")
    try:
        rendered_binding = _compact_json(dict(binding)) + b"\n"
    except CircuitGenerationError:
        raise _fail("deterministic pipeline board binding is not canonical") from None
    if rendered_binding != board_binding_report_raw:
        raise _fail(
            "deterministic pipeline board binding report does not match replay"
        )

    binding_pairs = (
        ("board_source_bytes", board_identity.get("bytes")),
        ("board_source_sha256", board_identity.get("sha256")),
        (
            "board_electrical_sha256",
            board_binding.get("board_electrical_sha256"),
        ),
        (
            "circuit_kicad_handoff_sha256",
            board_binding.get("circuit_kicad_handoff_sha256"),
        ),
        ("binding_sha256", board_binding.get("binding_sha256")),
    )
    if any(binding.get(field) != expected for field, expected in binding_pairs):
        raise _fail("deterministic pipeline board binding does not match replay")
    if handoff.get("policy_sha256") != board_binding.get("policy_sha256"):
        raise _fail("deterministic pipeline electrical policy does not match replay")
    if (
        handoff.get("circuit_source_bytes") != len(entries[CIRCUIT_SPEC_NAME])
        or handoff.get("circuit_source_sha256")
        != _sha256(entries[CIRCUIT_SPEC_NAME])
        or handoff.get("schematic_source_bytes") != len(entries[SCHEMATIC_NAME])
        or handoff.get("schematic_source_sha256")
        != _sha256(entries[SCHEMATIC_NAME])
    ):
        raise _fail("deterministic pipeline handoff source identity is inconsistent")

    identities = pipeline.get("identities")
    if (
        not isinstance(identities, Mapping)
        or identities.get("schematic_sha256")
        != handoff.get("schematic_sha256")
        or identities.get("board_sha256") != _sha256(role_sources["board"])
    ):
        raise _fail("deterministic pipeline gate source identity is inconsistent")

    if report.get("approved") is True:
        review = _strict_object(
            role_sources["electrical_review"],
            "deterministic pipeline electrical review",
        )
        try:
            _deterministic_pipeline_replay._validate_electrical_review(
                review,
                "deterministic pipeline electrical review",
                str(report.get("engine_version", "")),
            )
            _validate_review(review)
        except (
            CircuitGenerationError,
            _deterministic_pipeline_replay.DeterministicPipelineReplayError,
            TypeError,
            ValueError,
        ):
            raise _fail(
                "approved deterministic pipeline electrical review is invalid"
            ) from None
        if handoff.get("schematic_review") != review:
            raise _fail(
                "approved deterministic pipeline electrical review does not match"
            )

        board_descriptor = dict(capture.descriptors).get("board")
        manufacturing_board = manufacturing_package.get("board")
        if (
            not isinstance(board_descriptor, Mapping)
            or not isinstance(manufacturing_board, Mapping)
            or PurePosixPath(str(board_descriptor.get("path", ""))).name
            != manufacturing_board.get("name")
        ):
            raise _fail(
                "approved deterministic pipeline board name does not match"
            )


def replay_circuit_handoff_bundle(
    bundle: str | os.PathLike[str],
    pcbex: str | Sequence[str],
    *,
    catalog_generation_provenance: str | os.PathLike[str] | None = None,
    catalog_fetch_receipt: str | os.PathLike[str] | None = None,
    catalog_snapshot: str | os.PathLike[str] | None = None,
    retained_native_kicad_erc_report: str | os.PathLike[str] | None = None,
    kicad_cli: str | os.PathLike[str] = "kicad-cli",
    native_kicad_erc_warning_policy: str | os.PathLike[str] | None = None,
    require_native_kicad_erc_approved: bool = False,
    kicad_board: str | os.PathLike[str] | None = None,
    retained_board_binding_report: str | os.PathLike[str] | None = None,
    board_binding_policy: str | os.PathLike[str] | None = None,
    require_board_binding_approved: bool | object = _BOARD_BINDING_REQUIREMENT_UNSET,
    retained_manufacturing_package: str | os.PathLike[str] | None = None,
    manufacturing_kicad_cli: str | os.PathLike[str] | object = (
        _MANUFACTURING_KICAD_CLI_UNSET
    ),
    manufacturing_kicad_project: str | os.PathLike[str] | None = None,
    manufacturing_kicad_rules: str | os.PathLike[str] | None = None,
    manufacturing_fab: str | None = None,
    manufacturing_fab_profile: str | os.PathLike[str] | None = None,
    manufacturing_physical_profile: str | os.PathLike[str] | None = None,
    deterministic_pipeline_plan: str | os.PathLike[str] | None = None,
    retained_deterministic_pipeline_report: str | os.PathLike[str] | None = None,
    require_deterministic_pipeline_approved: bool = False,
    retained_ai_quorum_report: str | os.PathLike[str] | None = None,
    ai_review_request: str | os.PathLike[str] | None = None,
    ai_policy_pack: str | os.PathLike[str] | None = None,
    ai_approvals: Sequence[str | os.PathLike[str]] | None = None,
    ai_responses: Sequence[str | os.PathLike[str]] | None = None,
    minimum_ai_approvals: int | None = None,
    minimum_distinct_ai_providers: int | None = None,
    minimum_distinct_ai_models: int | None = None,
    require_ai_quorum: bool = False,
    timeout_seconds: float = 120.0,
    expected_archive_sha256: str | None = None,
    expected_bundle_sha256: str | None = None,
    _clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Reproduce a bundle and any requested retained evidence under one deadline."""

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
    if not isinstance(require_ai_quorum, bool):
        raise _fail("AI schematic quorum requirement is invalid")
    if not isinstance(require_deterministic_pipeline_approved, bool):
        raise _fail("deterministic pipeline approval requirement is invalid")
    if (
        require_board_binding_approved is not _BOARD_BINDING_REQUIREMENT_UNSET
        and not isinstance(require_board_binding_approved, bool)
    ):
        raise _fail("board binding approval requirement is invalid")
    board_binding_requested = any(
        source is not None
        for source in (
            kicad_board,
            retained_board_binding_report,
            board_binding_policy,
        )
    ) or require_board_binding_approved is not _BOARD_BINDING_REQUIREMENT_UNSET
    board_binding_require_approved = (
        False
        if require_board_binding_approved is _BOARD_BINDING_REQUIREMENT_UNSET
        else bool(require_board_binding_approved)
    )
    if board_binding_requested and (
        kicad_board is None or retained_board_binding_report is None
    ):
        raise _fail("board binding replay inputs are incomplete")
    manufacturing_requested = any(
        source is not None
        for source in (
            retained_manufacturing_package,
            manufacturing_kicad_project,
            manufacturing_kicad_rules,
            manufacturing_fab,
            manufacturing_fab_profile,
            manufacturing_physical_profile,
        )
    ) or manufacturing_kicad_cli is not _MANUFACTURING_KICAD_CLI_UNSET
    if manufacturing_requested and (
        retained_manufacturing_package is None or not board_binding_requested
    ):
        raise _fail(
            "manufacturing replay requires a retained package and complete "
            "board binding replay inputs"
        )
    deterministic_pipeline_requested = any(
        source is not None
        for source in (
            deterministic_pipeline_plan,
            retained_deterministic_pipeline_report,
        )
    ) or require_deterministic_pipeline_approved
    if deterministic_pipeline_requested and (
        deterministic_pipeline_plan is None
        or retained_deterministic_pipeline_report is None
        or not manufacturing_requested
    ):
        raise _fail(
            "deterministic pipeline replay requires a complete plan/report pair "
            "and manufacturing replay inputs"
        )
    if (
        sum(
            selection is not None
            for selection in (
                manufacturing_fab,
                manufacturing_fab_profile,
                manufacturing_physical_profile,
            )
        )
        > 1
    ):
        raise _fail("manufacturing profile selections are mutually exclusive")
    manufacturing_kicad_cli_argument: str | None = None
    if manufacturing_requested:
        effective_manufacturing_kicad_cli = (
            "kicad-cli"
            if manufacturing_kicad_cli is _MANUFACTURING_KICAD_CLI_UNSET
            else manufacturing_kicad_cli
        )
        try:
            manufacturing_kicad_cli_argument = _manufacturing_replay._argument(
                effective_manufacturing_kicad_cli,
                "manufacturing kicad-cli argument",
            )
        except _manufacturing_replay.ManufacturingReplayError:
            raise _fail("manufacturing kicad-cli argument is invalid") from None
    catalog_requested = any(
        source is not None
        for source in (
            catalog_generation_provenance,
            catalog_fetch_receipt,
            catalog_snapshot,
        )
    )
    if catalog_requested and any(
        source is None
        for source in (
            catalog_generation_provenance,
            catalog_fetch_receipt,
            catalog_snapshot,
        )
    ):
        raise _fail("catalog generation provenance replay inputs are incomplete")
    kicad_cli_argument = _path_argument(kicad_cli, "kicad-cli argument")
    native_erc_requested = retained_native_kicad_erc_report is not None
    if not native_erc_requested and (
        native_kicad_erc_warning_policy is not None
        or require_native_kicad_erc_approved
        or kicad_cli_argument != "kicad-cli"
    ):
        raise _fail("native KiCad ERC options require a retained report")
    approval_paths = _ai_quorum_path_sequence(ai_approvals, "approval")
    response_paths = _ai_quorum_path_sequence(ai_responses, "response")
    ai_requested = any(
        (
            retained_ai_quorum_report is not None,
            ai_review_request is not None,
            ai_policy_pack is not None,
            ai_approvals is not None,
            ai_responses is not None,
            require_ai_quorum,
            minimum_ai_approvals is not None,
            minimum_distinct_ai_providers is not None,
            minimum_distinct_ai_models is not None,
        )
    )
    ai_policy: dict[str, int] | None = None
    if ai_requested:
        if (
            retained_ai_quorum_report is None
            or ai_review_request is None
            or ai_policy_pack is None
            or not approval_paths
            or not response_paths
            or len(approval_paths) != len(response_paths)
        ):
            raise _fail("AI schematic quorum replay inputs are incomplete")
        ai_policy = _ai_quorum_thresholds(
            2 if minimum_ai_approvals is None else minimum_ai_approvals,
            (
                2
                if minimum_distinct_ai_providers is None
                else minimum_distinct_ai_providers
            ),
            2 if minimum_distinct_ai_models is None else minimum_distinct_ai_models,
        )
    if manufacturing_requested:
        # The composed result promises that every caller source observed before
        # a child runs is unchanged after the final manufacturing child. Freeze
        # each upstream PathLike once so a stateful __fspath__ implementation
        # cannot redirect that final read to a different file.
        try:
            bundle = _manufacturing_replay._freeze_path(
                bundle, "circuit handoff archive source"
            )
            if catalog_generation_provenance is not None:
                catalog_generation_provenance = _manufacturing_replay._freeze_path(
                    catalog_generation_provenance,
                    "catalog generation provenance source",
                )
            if catalog_fetch_receipt is not None:
                catalog_fetch_receipt = _manufacturing_replay._freeze_path(
                    catalog_fetch_receipt, "catalog fetch receipt source"
                )
            if catalog_snapshot is not None:
                catalog_snapshot = _manufacturing_replay._freeze_path(
                    catalog_snapshot, "catalog snapshot source"
                )
            if retained_native_kicad_erc_report is not None:
                retained_native_kicad_erc_report = (
                    _manufacturing_replay._freeze_path(
                        retained_native_kicad_erc_report,
                        "retained native KiCad ERC report source",
                    )
                )
            if native_kicad_erc_warning_policy is not None:
                native_kicad_erc_warning_policy = (
                    _manufacturing_replay._freeze_path(
                        native_kicad_erc_warning_policy,
                        "native KiCad ERC warning policy source",
                    )
                )
            assert kicad_board is not None
            assert retained_board_binding_report is not None
            kicad_board = _manufacturing_replay._freeze_path(
                kicad_board, "manufacturing board source"
            )
            retained_board_binding_report = _manufacturing_replay._freeze_path(
                retained_board_binding_report,
                "retained board binding report source",
            )
            if board_binding_policy is not None:
                board_binding_policy = _manufacturing_replay._freeze_path(
                    board_binding_policy, "board binding policy source"
                )
            if deterministic_pipeline_plan is not None:
                deterministic_pipeline_plan = _manufacturing_replay._freeze_path(
                    deterministic_pipeline_plan,
                    "deterministic pipeline plan source",
                )
            if retained_deterministic_pipeline_report is not None:
                retained_deterministic_pipeline_report = (
                    _manufacturing_replay._freeze_path(
                        retained_deterministic_pipeline_report,
                        "retained deterministic pipeline report source",
                    )
                )
            if retained_ai_quorum_report is not None:
                retained_ai_quorum_report = _manufacturing_replay._freeze_path(
                    retained_ai_quorum_report, "retained AI quorum report source"
                )
            if ai_review_request is not None:
                ai_review_request = _manufacturing_replay._freeze_path(
                    ai_review_request, "AI review request source"
                )
            if ai_policy_pack is not None:
                ai_policy_pack = _manufacturing_replay._freeze_path(
                    ai_policy_pack, "AI policy pack source"
                )
            approval_paths = tuple(
                _manufacturing_replay._freeze_path(path, "AI approval source")
                for path in approval_paths
            )
            response_paths = tuple(
                _manufacturing_replay._freeze_path(path, "AI response source")
                for path in response_paths
            )
        except _manufacturing_replay.ManufacturingReplayError:
            raise _fail("manufacturing replay source path is invalid") from None
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
    if catalog_requested and not catalog_input_erc_required:
        raise _fail("catalog generation provenance requires a catalog-backed archive")
    _remaining(deadline, _clock)

    catalog_provenance_raw: bytes | None = None
    catalog_fetch_receipt_raw: bytes | None = None
    catalog_snapshot_raw: bytes | None = None
    catalog_caller_sources: list[tuple[Any, bytes, int, str]] = []
    if catalog_requested:
        assert catalog_generation_provenance is not None
        assert catalog_fetch_receipt is not None
        assert catalog_snapshot is not None
        catalog_sources = (
            (
                catalog_generation_provenance,
                MAX_PROVENANCE_BYTES,
                "catalog generation provenance",
            ),
            (
                catalog_fetch_receipt,
                MAXIMUM_RECEIPT_BYTES,
                "catalog fetch receipt",
            ),
            (catalog_snapshot, MAX_CATALOG_RAW_BYTES, "catalog snapshot"),
        )
        captured: list[bytes] = []
        aggregate_bytes = 0
        for path, maximum, label in catalog_sources:
            try:
                raw = read_bytes(path, max_bytes=maximum)
            except BoundedIOError:
                raise _fail(f"{label} path is invalid") from None
            if not raw:
                raise _fail(f"{label} is empty")
            aggregate_bytes += len(raw)
            if aggregate_bytes > MAX_CATALOG_PROVENANCE_TOTAL_INPUT_BYTES:
                raise _fail("catalog provenance inputs exceed their aggregate bound")
            captured.append(raw)
            catalog_caller_sources.append((path, raw, maximum, label))
            _remaining(deadline, _clock)
        (
            catalog_provenance_raw,
            catalog_fetch_receipt_raw,
            catalog_snapshot_raw,
        ) = captured

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

    board_raw: bytes | None = None
    board_binding_report_raw: bytes | None = None
    board_binding_policy_raw: bytes | None = None
    board_caller_sources: list[tuple[Any, bytes, int, str]] = []
    if board_binding_requested:
        assert kicad_board is not None
        assert retained_board_binding_report is not None
        board_sources = (
            (kicad_board, MAX_KICAD_BOARD_BINDING_BYTES, "KiCad board"),
            (
                retained_board_binding_report,
                MAX_KICAD_BOARD_BINDING_RENDERED_REPORT_BYTES,
                "retained board binding report",
            ),
        )
        captured_board: list[bytes] = []
        board_aggregate_bytes = 0
        for path, maximum, label in board_sources:
            try:
                raw = read_bytes(path, max_bytes=maximum)
            except BoundedIOError:
                raise _fail(f"{label} path is invalid") from None
            if not raw:
                raise _fail(f"{label} is empty")
            if label == "retained board binding report" and (
                not raw.endswith(b"\n") or raw[:-1].endswith(b"\n")
            ):
                raise _fail("retained board binding report is not canonical rendered JSON")
            board_aggregate_bytes += len(raw)
            if board_aggregate_bytes > MAX_KICAD_BOARD_BINDING_TOTAL_INPUT_BYTES:
                raise _fail("board binding inputs exceed their aggregate bound")
            captured_board.append(raw)
            board_caller_sources.append((path, raw, maximum, label))
            _remaining(deadline, _clock)
        board_raw, board_binding_report_raw = captured_board
        if board_binding_policy is not None:
            try:
                board_binding_policy_raw = read_bytes(
                    board_binding_policy,
                    max_bytes=MAX_KICAD_BOARD_BINDING_POLICY_BYTES,
                )
            except BoundedIOError:
                raise _fail("board binding policy path is invalid") from None
            if not board_binding_policy_raw:
                raise _fail("board binding policy is empty")
            board_aggregate_bytes += len(board_binding_policy_raw)
            if board_aggregate_bytes > MAX_KICAD_BOARD_BINDING_TOTAL_INPUT_BYTES:
                raise _fail("board binding inputs exceed their aggregate bound")
            board_caller_sources.append(
                (
                    board_binding_policy,
                    board_binding_policy_raw,
                    MAX_KICAD_BOARD_BINDING_POLICY_BYTES,
                    "board binding policy",
                )
            )
            _remaining(deadline, _clock)

    manufacturing_capture: (
        _manufacturing_replay._ManufacturingReplayCapture | None
    ) = None
    if manufacturing_requested:
        assert kicad_board is not None
        assert board_raw is not None
        assert retained_manufacturing_package is not None
        try:
            manufacturing_capture = (
                _manufacturing_replay._capture_manufacturing_replay_inputs(
                    kicad_board,
                    retained_manufacturing_package,
                    kicad_project=manufacturing_kicad_project,
                    kicad_rules=manufacturing_kicad_rules,
                    fab=manufacturing_fab,
                    fab_profile=manufacturing_fab_profile,
                    physical_profile=manufacturing_physical_profile,
                    deadline=deadline,
                    clock=_clock,
                    board_raw=board_raw,
                )
            )
        except _manufacturing_replay.ManufacturingReplayError:
            raise _fail("manufacturing replay inputs are invalid") from None
        _remaining(deadline, _clock)

    deterministic_pipeline_capture: (
        _deterministic_pipeline_replay._DeterministicPipelineReplayCapture | None
    ) = None
    if deterministic_pipeline_requested:
        assert deterministic_pipeline_plan is not None
        assert retained_deterministic_pipeline_report is not None
        try:
            deterministic_pipeline_capture = (
                _deterministic_pipeline_replay._capture_deterministic_pipeline_replay_inputs(
                    deterministic_pipeline_plan,
                    retained_deterministic_pipeline_report,
                    deadline=deadline,
                    clock=_clock,
                )
            )
        except _deterministic_pipeline_replay.DeterministicPipelineReplayError:
            raise _fail("deterministic pipeline replay inputs are invalid") from None
        _remaining(deadline, _clock)

    ai_report_raw: bytes | None = None
    ai_request_raw: bytes | None = None
    ai_policy_pack_raw: bytes | None = None
    approval_raws: tuple[bytes, ...] = ()
    response_raws: tuple[bytes, ...] = ()
    ai_caller_sources: list[tuple[Any, bytes, int, str]] = []
    if ai_requested:
        assert retained_ai_quorum_report is not None
        assert ai_review_request is not None
        assert ai_policy_pack is not None
        try:
            ai_report_raw = read_bytes(
                retained_ai_quorum_report,
                max_bytes=MAX_AI_QUORUM_REPORT_BYTES,
            )
        except BoundedIOError:
            raise _fail("retained AI schematic quorum report path is invalid") from None
        if not ai_report_raw:
            raise _fail("retained AI schematic quorum report is empty")
        _remaining(deadline, _clock)

        source_paths: list[tuple[Any, str]] = [
            (ai_review_request, "AI review request"),
            (ai_policy_pack, "AI policy pack"),
            *((path, "AI signed approval") for path in approval_paths),
            *((path, "AI review response") for path in response_paths),
        ]
        source_raws: list[bytes] = []
        aggregate_bytes = 0
        for path, label in source_paths:
            try:
                raw = read_bytes(path, max_bytes=MAX_AI_QUORUM_INPUT_BYTES)
            except BoundedIOError:
                raise _fail(f"{label} path is invalid") from None
            if not raw:
                raise _fail(f"{label} is empty")
            aggregate_bytes += len(raw)
            if aggregate_bytes > MAX_AI_QUORUM_TOTAL_INPUT_BYTES:
                raise _fail("AI schematic quorum inputs exceed their aggregate bound")
            source_raws.append(raw)
            ai_caller_sources.append(
                (path, raw, MAX_AI_QUORUM_INPUT_BYTES, label)
            )
            _remaining(deadline, _clock)
        ai_request_raw = source_raws[0]
        ai_policy_pack_raw = source_raws[1]
        member_count = len(approval_paths)
        approval_raws = tuple(source_raws[2 : 2 + member_count])
        response_raws = tuple(source_raws[2 + member_count :])
        _ai_replay_request_sha256(ai_request_raw)
        ai_caller_sources.insert(
            0,
            (
                retained_ai_quorum_report,
                ai_report_raw,
                MAX_AI_QUORUM_REPORT_BYTES,
                "retained AI schematic quorum report",
            ),
        )
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
    board_check: dict[str, Any] | None = None
    board_handoff: dict[str, Any] | None = None
    if board_binding_requested:
        board_check = _strict_object(entries[CIRCUIT_CHECK_NAME], "native circuit check")
        board_handoff = _strict_object(
            entries[HANDOFF_REPORT_NAME], "native handoff report"
        )
        _remaining(deadline, _clock)
    native_kicad_erc: dict[str, Any] | None = None
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

    def finish_board_binding() -> dict[str, Any] | None:
        if not board_binding_requested:
            return None
        assert board_raw is not None
        assert board_binding_report_raw is not None
        assert board_check is not None
        assert board_handoff is not None
        board_binding = _replay_board_binding(
            entries[CIRCUIT_SPEC_NAME],
            entries[SCHEMATIC_NAME],
            board_raw,
            board_binding_report_raw,
            board_binding_policy_raw,
            board_check,
            board_handoff,
            command,
            require_approved=board_binding_require_approved,
            deadline=deadline,
            clock=_clock,
        )
        _remaining(deadline, _clock)
        # This is the final board-source read before the optional manufacturing
        # stage. It catches mutations by every earlier optional child; the v6
        # composition performs one more complete caller-source read afterward.
        for path, expected_raw, maximum, label in board_caller_sources:
            try:
                observed_raw = read_bytes(path, max_bytes=maximum)
            except BoundedIOError:
                raise _fail(f"{label} changed during replay") from None
            if observed_raw != expected_raw:
                raise _fail(f"{label} changed during replay")
            _remaining(deadline, _clock)
        final_sources: list[tuple[Any, bytes, int, str]] = []
        final_sources.append(
            (bundle, archive_raw, MAX_HANDOFF_ARCHIVE_BYTES, "circuit handoff archive")
        )
        if native_report_raw is not None:
            assert retained_native_kicad_erc_report is not None
            final_sources.append(
                (
                    retained_native_kicad_erc_report,
                    native_report_raw,
                    MAX_NATIVE_KICAD_ERC_REPORT_BYTES,
                    "retained native KiCad ERC report",
                )
            )
            if native_kicad_erc_warning_policy is not None:
                assert warning_policy_raw is not None
                final_sources.append(
                    (
                        native_kicad_erc_warning_policy,
                        warning_policy_raw,
                        MAX_NATIVE_KICAD_ERC_WARNING_POLICY_BYTES,
                        "native KiCad ERC warning policy",
                    )
                )
        final_sources.extend(ai_caller_sources)
        final_sources.extend(catalog_caller_sources)
        for path, expected_raw, maximum, label in final_sources:
            try:
                observed_raw = read_bytes(path, max_bytes=maximum)
            except BoundedIOError:
                raise _fail(f"{label} changed during replay") from None
            if observed_raw != expected_raw:
                raise _fail(f"{label} changed during replay")
            _remaining(deadline, _clock)
        if board_binding_require_approved and not board_binding["approved"]:
            raise _fail("board binding replay approval was not granted")
        return board_binding

    def finish_result(
        result: dict[str, Any],
        board_binding: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        if not manufacturing_requested:
            return result
        assert manufacturing_capture is not None
        assert manufacturing_kicad_cli_argument is not None
        if board_binding is None or "board_binding" not in result:
            raise _fail("manufacturing replay has no reproduced board binding")

        outer_remaining = _remaining(deadline, _clock)
        downstream_reserve = (
            outer_remaining / 2.0
            if deterministic_pipeline_requested
            else min(15.0, outer_remaining / 2.0)
        )
        manufacturing_deadline = deadline - downstream_reserve
        try:
            if manufacturing_deadline <= float(_clock()):
                raise _fail("manufacturing replay has no execution budget")
        except (TypeError, ValueError, OverflowError):
            raise _fail("aggregate deadline clock is invalid") from None
        try:
            manufacturing_package = (
                _manufacturing_replay._replay_captured_manufacturing_package(
                    manufacturing_capture,
                    command,
                    manufacturing_kicad_cli_argument,
                    deadline=manufacturing_deadline,
                    clock=_clock,
                )
            )
        except _manufacturing_replay.ManufacturingReplayError as error:
            raise _fail(f"manufacturing package replay failed: {error}") from None
        _remaining(deadline, _clock)

        captured_board_identity = manufacturing_capture.board_identity
        manufacturing_board = manufacturing_package.get("board")
        board_binding_board = board_binding.get("board")
        if (
            not isinstance(manufacturing_board, Mapping)
            or not isinstance(board_binding_board, Mapping)
            or manufacturing_board.get("bytes") != captured_board_identity["bytes"]
            or manufacturing_board.get("sha256")
            != captured_board_identity["sha256"]
            or board_binding_board.get("bytes") != captured_board_identity["bytes"]
            or board_binding_board.get("sha256")
            != captured_board_identity["sha256"]
        ):
            raise _fail("manufacturing replay board identity is inconsistent")

        final_sources: list[tuple[Any, bytes, int, str]] = [
            (
                bundle,
                archive_raw,
                MAX_HANDOFF_ARCHIVE_BYTES,
                "circuit handoff archive",
            )
        ]
        if native_report_raw is not None:
            assert retained_native_kicad_erc_report is not None
            final_sources.append(
                (
                    retained_native_kicad_erc_report,
                    native_report_raw,
                    MAX_NATIVE_KICAD_ERC_REPORT_BYTES,
                    "retained native KiCad ERC report",
                )
            )
            if native_kicad_erc_warning_policy is not None:
                assert warning_policy_raw is not None
                final_sources.append(
                    (
                        native_kicad_erc_warning_policy,
                        warning_policy_raw,
                        MAX_NATIVE_KICAD_ERC_WARNING_POLICY_BYTES,
                        "native KiCad ERC warning policy",
                    )
                )
        final_sources.extend(ai_caller_sources)
        final_sources.extend(catalog_caller_sources)
        final_sources.extend(board_caller_sources)
        final_sources.extend(
            source
            for source in manufacturing_capture.caller_sources
            if source[3] != "board"
        )
        if deterministic_pipeline_capture is not None:
            final_sources.extend(deterministic_pipeline_capture.caller_sources)
        for path, expected_raw, maximum, label in final_sources:
            try:
                observed_raw = read_bytes(path, max_bytes=maximum)
            except BoundedIOError:
                raise _fail(f"{label} changed during manufacturing replay") from None
            if observed_raw != expected_raw:
                raise _fail(f"{label} changed during manufacturing replay")
            _remaining(deadline, _clock)

        composed = _circuit_handoff_manufacturing_replay_result(
            result,
            manufacturing_package=manufacturing_package,
        )
        _remaining(deadline, _clock)
        if deterministic_pipeline_capture is None:
            return composed

        pipeline_remaining = _remaining(deadline, _clock)
        final_union_reread_reserve = min(30.0, pipeline_remaining / 2.0)
        pipeline_deadline = deadline - final_union_reread_reserve
        try:
            if pipeline_deadline <= float(_clock()):
                raise _fail("deterministic pipeline replay has no execution budget")
        except (TypeError, ValueError, OverflowError):
            raise _fail("aggregate deadline clock is invalid") from None
        try:
            deterministic_pipeline, pipeline_report = (
                _deterministic_pipeline_replay._replay_captured_deterministic_pipeline(
                    deterministic_pipeline_capture,
                    command,
                    deadline=pipeline_deadline,
                    clock=_clock,
                )
            )
        except _deterministic_pipeline_replay.DeterministicPipelineReplayError:
            raise _fail("deterministic pipeline replay failed") from None
        _remaining(deadline, _clock)

        _validate_pipeline_handoff_cross_binding(
            deterministic_pipeline_capture,
            pipeline_report,
            entries,
            board_binding,
            board_binding_report_raw,
            manufacturing_package,
        )
        _remaining(deadline, _clock)

        for path, expected_raw, maximum, label in final_sources:
            try:
                observed_raw = read_bytes(path, max_bytes=maximum)
            except BoundedIOError:
                raise _fail(
                    f"{label} changed during deterministic pipeline replay"
                ) from None
            if observed_raw != expected_raw:
                raise _fail(f"{label} changed during deterministic pipeline replay")
            _remaining(deadline, _clock)
        try:
            _deterministic_pipeline_replay._firmware_entry_names(
                deterministic_pipeline_capture.firmware_source_directory
            )
        except _deterministic_pipeline_replay.DeterministicPipelineReplayError:
            raise _fail(
                "deterministic pipeline firmware bundle changed during replay"
            ) from None
        _remaining(deadline, _clock)

        pipeline_composed = _circuit_handoff_pipeline_replay_result(
            composed,
            deterministic_pipeline=deterministic_pipeline,
        )
        _remaining(deadline, _clock)
        if (
            require_deterministic_pipeline_approved
            and deterministic_pipeline["report"]["approved"] is not True
        ):
            raise _fail("deterministic pipeline replay approval was not granted")
        return pipeline_composed

    if not ai_requested and not catalog_requested:
        board_binding = finish_board_binding()
        if board_binding is not None:
            return finish_result(
                _circuit_handoff_board_binding_replay_result(
                    verification,
                    catalog_input_erc_required=catalog_input_erc_required,
                    board_binding=board_binding,
                    native_kicad_erc=native_kicad_erc,
                    ai_schematic_quorum=None,
                    catalog_generation_provenance=None,
                ),
                board_binding,
            )
        if native_kicad_erc is not None:
            return finish_result(
                _circuit_handoff_native_erc_replay_result(
                    verification,
                    catalog_input_erc_required=catalog_input_erc_required,
                    native_kicad_erc=native_kicad_erc,
                ),
                None,
            )
        return finish_result(
            _circuit_handoff_replay_result(
                verification,
                catalog_input_erc_required=catalog_input_erc_required,
            ),
            None,
        )

    ai_schematic_quorum: dict[str, Any] | None = None
    if ai_requested:
        assert ai_report_raw is not None
        assert ai_request_raw is not None
        assert ai_policy_pack_raw is not None
        assert ai_policy is not None
        ai_schematic_quorum = _replay_ai_quorum(
            entries[SCHEMATIC_NAME],
            ai_report_raw,
            ai_request_raw,
            ai_policy_pack_raw,
            approval_raws,
            response_raws,
            command,
            policy=ai_policy,
            require_quorum=require_ai_quorum,
            deadline=deadline,
            clock=_clock,
        )
        _remaining(deadline, _clock)

        for path, expected_raw, maximum, label in ai_caller_sources:
            try:
                observed_raw = read_bytes(path, max_bytes=maximum)
            except BoundedIOError:
                raise _fail(f"{label} changed during replay") from None
            if observed_raw != expected_raw:
                raise _fail(f"{label} changed during replay")
            _remaining(deadline, _clock)

        # The AI verifier runs after native ERC. Re-read the earlier sidecars so a
        # later child cannot invalidate evidence that the combined result keeps.
        if native_report_raw is not None:
            assert retained_native_kicad_erc_report is not None
            try:
                report_after_ai = read_bytes(
                    retained_native_kicad_erc_report,
                    max_bytes=MAX_NATIVE_KICAD_ERC_REPORT_BYTES,
                )
            except BoundedIOError:
                raise _fail(
                    "retained native KiCad ERC report changed during replay"
                ) from None
            if report_after_ai != native_report_raw:
                raise _fail("retained native KiCad ERC report changed during replay")
            _remaining(deadline, _clock)
            if native_kicad_erc_warning_policy is not None:
                assert warning_policy_raw is not None
                try:
                    warning_policy_after_ai = read_bytes(
                        native_kicad_erc_warning_policy,
                        max_bytes=MAX_NATIVE_KICAD_ERC_WARNING_POLICY_BYTES,
                    )
                except BoundedIOError:
                    raise _fail(
                        "native KiCad ERC warning policy changed during replay"
                    ) from None
                if warning_policy_after_ai != warning_policy_raw:
                    raise _fail(
                        "native KiCad ERC warning policy changed during replay"
                    )
                _remaining(deadline, _clock)

        if require_ai_quorum and not ai_schematic_quorum["quorum_met"]:
            raise _fail("AI schematic quorum replay did not meet every threshold")

    if catalog_requested:
        assert catalog_provenance_raw is not None
        assert catalog_fetch_receipt_raw is not None
        assert catalog_snapshot_raw is not None
        assert isinstance(generation["catalog_receipt"], Mapping)
        for path, expected_raw, maximum, label in catalog_caller_sources:
            try:
                observed_raw = read_bytes(path, max_bytes=maximum)
            except BoundedIOError:
                raise _fail(f"{label} changed during replay") from None
            if observed_raw != expected_raw:
                raise _fail(f"{label} changed during replay")
            _remaining(deadline, _clock)

        catalog_evidence = _catalog_generation_provenance_evidence(
            catalog_provenance_raw,
            catalog_fetch_receipt_raw,
            catalog_snapshot_raw,
            entries[GENERATION_BUNDLE_NAME],
            generation["catalog_receipt"],
            deadline=deadline,
            clock=_clock,
        )
        for path, expected_raw, maximum, label in catalog_caller_sources:
            try:
                observed_raw = read_bytes(path, max_bytes=maximum)
            except BoundedIOError:
                raise _fail(f"{label} changed during replay") from None
            if observed_raw != expected_raw:
                raise _fail(f"{label} changed during replay")
            _remaining(deadline, _clock)
        board_binding = finish_board_binding()
        if board_binding is not None:
            return finish_result(
                _circuit_handoff_board_binding_replay_result(
                    verification,
                    catalog_input_erc_required=catalog_input_erc_required,
                    board_binding=board_binding,
                    native_kicad_erc=native_kicad_erc,
                    ai_schematic_quorum=ai_schematic_quorum,
                    catalog_generation_provenance=catalog_evidence,
                ),
                board_binding,
            )
        return finish_result(
            _circuit_handoff_catalog_provenance_replay_result(
                verification,
                catalog_input_erc_required=catalog_input_erc_required,
                catalog_generation_provenance=catalog_evidence,
                native_kicad_erc=native_kicad_erc,
                ai_schematic_quorum=ai_schematic_quorum,
            ),
            None,
        )

    assert ai_schematic_quorum is not None
    board_binding = finish_board_binding()
    if board_binding is not None:
        return finish_result(
            _circuit_handoff_board_binding_replay_result(
                verification,
                catalog_input_erc_required=catalog_input_erc_required,
                board_binding=board_binding,
                native_kicad_erc=native_kicad_erc,
                ai_schematic_quorum=ai_schematic_quorum,
                catalog_generation_provenance=None,
            ),
            board_binding,
        )
    return finish_result(
        _circuit_handoff_ai_quorum_replay_result(
            verification,
            catalog_input_erc_required=catalog_input_erc_required,
            ai_schematic_quorum=ai_schematic_quorum,
            native_kicad_erc=native_kicad_erc,
        ),
        None,
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
    "CIRCUIT_HANDOFF_BUNDLE_AI_QUORUM_REPLAY_RESULT_SCHEMA_VERSION",
    "CIRCUIT_HANDOFF_BUNDLE_AI_QUORUM_REPLAY_SCOPE",
    "CIRCUIT_HANDOFF_BUNDLE_CATALOG_PROVENANCE_REPLAY_RESULT_SCHEMA_VERSION",
    "CIRCUIT_HANDOFF_BUNDLE_CATALOG_PROVENANCE_REPLAY_SCOPE",
    "CIRCUIT_HANDOFF_BUNDLE_BOARD_BINDING_REPLAY_RESULT_SCHEMA_VERSION",
    "CIRCUIT_HANDOFF_BUNDLE_BOARD_BINDING_REPLAY_SCOPE",
    "CIRCUIT_HANDOFF_BUNDLE_MANUFACTURING_REPLAY_RESULT_SCHEMA_VERSION",
    "CIRCUIT_HANDOFF_BUNDLE_MANUFACTURING_REPLAY_SCOPE",
    "CIRCUIT_HANDOFF_BUNDLE_PIPELINE_REPLAY_RESULT_SCHEMA_VERSION",
    "CIRCUIT_HANDOFF_BUNDLE_PIPELINE_REPLAY_SCOPE",
    "CIRCUIT_HANDOFF_BUNDLE_NATIVE_ERC_REPLAY_RESULT_SCHEMA_VERSION",
    "CIRCUIT_HANDOFF_BUNDLE_NATIVE_ERC_REPLAY_SCOPE",
    "CIRCUIT_HANDOFF_BUNDLE_REPLAY_RESULT_SCHEMA_VERSION",
    "CIRCUIT_HANDOFF_BUNDLE_REPLAY_SCOPE",
    "CIRCUIT_HANDOFF_BUNDLE_RESULT_SCHEMA_VERSION",
    "CIRCUIT_HANDOFF_BUNDLE_SCHEMA_VERSION",
    "CIRCUIT_HANDOFF_BUNDLE_VERIFICATION_SCOPE",
    "CircuitHandoffBundleError",
    "build_circuit_handoff_archive",
    "circuit_handoff_bundle_ai_quorum_replay_result_json_schema",
    "circuit_handoff_bundle_board_binding_replay_result_json_schema",
    "circuit_handoff_bundle_manufacturing_replay_result_json_schema",
    "circuit_handoff_bundle_pipeline_replay_result_json_schema",
    "circuit_handoff_bundle_catalog_provenance_replay_result_json_schema",
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
