"""Closed provenance binding for catalog-backed circuit generation.

The catalog fetch, catalog selection, and circuit-generation contracts already
perform their own validation.  This module adds a small path-free sidecar that
binds those exact artifacts together without changing any existing bundle
schema.  JSON sources are parsed with duplicate-key and non-finite-number
rejection before the authoritative validators are called.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
from pathlib import Path
from typing import Any, Mapping

from .bounded_io import BoundedIOError, read_bytes
from .catalog import (
    MAX_CATALOG_RAW_BYTES,
    MAX_CATALOG_RECEIPT_BYTES,
    MAX_CATALOG_TIMESTAMP,
    CatalogError,
    canonical_sha256,
    load_catalog_snapshot,
    validate_catalog_receipt,
    validate_catalog_receipt_shape,
)
from .circuit_generation import (
    CircuitGenerationError,
    MAX_CORRECTION_BYTES,
    MAX_HISTORY_ITEMS,
    MAX_NATIVE_CHECK_BYTES,
    MAX_REQUIREMENTS_BYTES,
    MAXIMUM_PROVIDER_OUTPUT_BYTES,
    _provider_descriptor,
    _validate_check_envelope,
    _validate_v2_spec,
)
from .supplier_inventory import (
    MAXIMUM_RECEIPT_BYTES,
    SupplierInventoryError,
    validate_catalog_fetch_receipt,
)


PROVENANCE_SCHEMA_VERSION = 1
PROVENANCE_ADAPTER = "catalog-generation-provenance-v1"
MAX_PROVENANCE_BYTES = 1 * 1024 * 1024
MAX_PROVENANCE_BUNDLE_BYTES = MAX_NATIVE_CHECK_BYTES
MAX_PROVENANCE_SKIDL_BYTES = MAXIMUM_PROVIDER_OUTPUT_BYTES
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SUPPLIER_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
_TEXT_CHUNK_CHARACTERS = 64 * 1024

_PROVENANCE_KEYS = frozenset(
    {
        "schema_version",
        "adapter",
        "provider",
        "endpoint_id",
        "evaluated_at_unix",
        "fetch_receipt_sha256",
        "snapshot_sha256",
        "catalog_sha256",
        "selection_receipt_sha256",
        "input_spec_sha256",
        "resolved_spec_sha256",
        "generation_bundle_sha256",
        "generated_skidl_sha256",
    }
)
_BUNDLE_KEYS = frozenset(
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
_HISTORY_DIGEST_KEYS = (
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
_HISTORY_RESOLVED_KEYS = (
    "resolved_spec_sha256",
    "resolved_check_sha256",
    "resolved_circuit_spec_sha256",
    "resolved_electrical_review_sha256",
    "catalog_receipt_sha256",
)


class CatalogGenerationProvenanceError(ValueError):
    """Raised when the closed provenance sidecar cannot be admitted."""


class _DuplicateJSONKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> Any:
    raise ValueError


def _fail(message: str) -> CatalogGenerationProvenanceError:
    # Do not include source paths or untrusted JSON values in diagnostics.
    return CatalogGenerationProvenanceError(message)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json_string_bytes(value: str, *, label: str, maximum: int) -> int:
    if len(value) > maximum:
        raise _fail(f"{label} exceeds its byte bound")
    size = 2
    for character in value:
        codepoint = ord(character)
        if character in {'"', "\\", "\b", "\f", "\n", "\r", "\t"}:
            size += 2
        elif codepoint < 0x20:
            size += 6
        elif codepoint <= 0x7F:
            size += 1
        elif codepoint <= 0x7FF:
            size += 2
        elif 0xD800 <= codepoint <= 0xDFFF:
            raise _fail(f"{label} is not valid UTF-8")
        elif codepoint <= 0xFFFF:
            size += 3
        else:
            size += 4
        if size > maximum:
            raise _fail(f"{label} exceeds its byte bound")
    return size


def _encode_text_bounded(value: str, *, label: str, maximum: int) -> bytes:
    if not value or len(value) > maximum:
        raise _fail(f"{label} exceeds its byte bound")
    output = bytearray()
    for offset in range(0, len(value), _TEXT_CHUNK_CHARACTERS):
        try:
            chunk = value[offset : offset + _TEXT_CHUNK_CHARACTERS].encode(
                "utf-8",
                errors="strict",
            )
        except UnicodeEncodeError:
            raise _fail(f"{label} is not valid UTF-8") from None
        if len(output) + len(chunk) > maximum:
            raise _fail(f"{label} exceeds its byte bound")
        output.extend(chunk)
    return bytes(output)


def _looks_like_json_object_text(value: str) -> bool:
    for character in value:
        if character.isspace():
            continue
        return character == "{"
    return False


def _preflight_injected_json(value: Any, *, label: str, maximum: int) -> None:
    active: set[int] = set()
    used = 0

    def charge(amount: int) -> None:
        nonlocal used
        used += amount
        if used > maximum:
            raise _fail(f"{label} exceeds its byte bound")

    def visit(item: Any, depth: int) -> None:
        if depth > 128:
            raise _fail(f"{label} is nested too deeply")
        if item is None or isinstance(item, bool):
            charge(5)
        elif isinstance(item, int):
            # Estimate decimal digits from the bit length without converting a
            # caller-supplied giant integer to an unbounded temporary string.
            digits = max(1, (abs(item).bit_length() * 30104) // 100000 + 2)
            charge(digits)
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise _fail(f"{label} contains a non-finite number")
            charge(32)
        elif isinstance(item, str):
            charge(_json_string_bytes(item, label=label, maximum=maximum))
        elif isinstance(item, Mapping):
            identity = id(item)
            if identity in active:
                raise _fail(f"{label} contains a recursive object")
            active.add(identity)
            try:
                charge(2)
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise _fail(f"{label} contains a non-string key")
                    charge(
                        _json_string_bytes(key, label=label, maximum=maximum) + 2
                    )
                    visit(child, depth + 1)
            except CatalogGenerationProvenanceError:
                raise
            except (TypeError, ValueError, RuntimeError):
                raise _fail(f"{label} could not be traversed safely") from None
            finally:
                active.remove(identity)
        elif isinstance(item, (list, tuple)):
            if len(item) > maximum:
                raise _fail(f"{label} exceeds its byte bound")
            identity = id(item)
            if identity in active:
                raise _fail(f"{label} contains a recursive array")
            active.add(identity)
            try:
                charge(2)
                for child in item:
                    charge(1)
                    visit(child, depth + 1)
            finally:
                active.remove(identity)
        else:
            raise _fail(f"{label} contains a non-JSON value")

    visit(value, 0)


def _json_bytes(value: Any, *, maximum: int, label: str) -> bytes:
    _preflight_injected_json(value, label=label, maximum=maximum)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        raise _fail(f"{label} is not bounded canonical JSON") from None
    if not encoded or len(encoded) > maximum:
        raise _fail(f"{label} exceeds its byte bound")
    return encoded


def _read_source(
    source: Any,
    *,
    label: str,
    maximum: int,
    string_is_text: bool = False,
) -> bytes:
    if isinstance(source, Mapping):
        return _json_bytes(source, maximum=maximum, label=label)
    if isinstance(source, str) and string_is_text:
        return _encode_text_bounded(source, label=label, maximum=maximum)
    if isinstance(source, str):
        if not source or len(source) > maximum:
            raise _fail(f"{label} exceeds its byte bound")
        # A JSON string is an injected source; every other string is a path.
        if _looks_like_json_object_text(source):
            return _encode_text_bounded(source, label=label, maximum=maximum)
        path_source: str | os.PathLike[str] = source
    elif isinstance(source, bytes):
        raw = source
        if not raw or len(raw) > maximum:
            raise _fail(f"{label} exceeds its byte bound")
        return raw
    elif isinstance(source, bytearray):
        if not source or len(source) > maximum:
            raise _fail(f"{label} exceeds its byte bound")
        try:
            raw = bytes(source)
        except (TypeError, ValueError):
            raise _fail(f"{label} source is invalid") from None
        return raw
    elif isinstance(source, memoryview):
        try:
            size = source.nbytes
        except (TypeError, ValueError):
            raise _fail(f"{label} source is invalid") from None
        if size <= 0 or size > maximum:
            raise _fail(f"{label} exceeds its byte bound")
        try:
            raw = source.tobytes()
        except (TypeError, ValueError):
            raise _fail(f"{label} source is invalid") from None
        return raw
    elif isinstance(source, os.PathLike):
        path_source = source
    else:
        raise _fail(f"{label} source is invalid")
    try:
        raw = read_bytes(path_source, max_bytes=maximum)
    except BoundedIOError:
        raise _fail(f"unable to stably read {label}") from None
    if not raw:
        raise _fail(f"{label} must not be empty")
    return raw


def _parse_object(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, _DuplicateJSONKey, ValueError, RecursionError):
        raise _fail(f"{label} is not strict JSON") from None
    if not isinstance(value, dict):
        raise _fail(f"{label} must be a JSON object")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise _fail(f"{label} digest is invalid")
    return value


def _validate_provenance_shape(provenance: Any) -> dict[str, Any]:
    if not isinstance(provenance, Mapping):
        raise _fail("catalog generation provenance must be an object")
    _preflight_injected_json(
        provenance,
        label="catalog generation provenance",
        maximum=MAX_PROVENANCE_BYTES,
    )
    try:
        value = dict(provenance)
        keys = set(value)
    except (TypeError, ValueError, RuntimeError):
        raise _fail("catalog generation provenance must be an object") from None
    if keys != _PROVENANCE_KEYS:
        raise _fail("catalog generation provenance has invalid fields")
    if (
        isinstance(value["schema_version"], bool)
        or value["schema_version"] != PROVENANCE_SCHEMA_VERSION
        or value["adapter"] != PROVENANCE_ADAPTER
    ):
        raise _fail("catalog generation provenance schema or adapter is invalid")
    provider = value["provider"]
    if not isinstance(provider, str) or _SUPPLIER_RE.fullmatch(provider) is None:
        raise _fail("catalog generation provenance provider is invalid")
    endpoint = value["endpoint_id"]
    if not isinstance(endpoint, str) or not endpoint or len(endpoint) > 4096:
        raise _fail("catalog generation provenance endpoint is invalid")
    timestamp = value["evaluated_at_unix"]
    if (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, int)
        or timestamp < 0
        or timestamp > MAX_CATALOG_TIMESTAMP
    ):
        raise _fail("catalog generation provenance timestamp is invalid")
    for key in _PROVENANCE_KEYS - {
        "schema_version",
        "adapter",
        "provider",
        "endpoint_id",
        "evaluated_at_unix",
    }:
        _digest(value[key], f"provenance {key}")
    try:
        canonical = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        raise _fail("catalog generation provenance is not canonical JSON") from None
    if len(canonical) > MAX_PROVENANCE_BYTES:
        raise _fail("catalog generation provenance exceeds its canonical byte bound")
    return value


def catalog_generation_provenance_json_schema() -> dict[str, Any]:
    """Return the closed schema for a catalog-generation provenance sidecar."""

    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    fields = [
        "schema_version",
        "adapter",
        "provider",
        "endpoint_id",
        "evaluated_at_unix",
        "fetch_receipt_sha256",
        "snapshot_sha256",
        "catalog_sha256",
        "selection_receipt_sha256",
        "input_spec_sha256",
        "resolved_spec_sha256",
        "generation_bundle_sha256",
        "generated_skidl_sha256",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/catalog-generation-provenance-v1.json",
        "$comment": (
            "Runtime validation additionally enforces strict UTF-8 JSON, "
            "bounded stable source reads, fetch/selection/bundle recomputation, "
            "and exact raw artifact digests."
        ),
        "title": "pcbex catalog-generation provenance v1",
        "type": "object",
        "additionalProperties": False,
        "required": fields,
        "properties": {
            "schema_version": {"const": PROVENANCE_SCHEMA_VERSION},
            "adapter": {"const": PROVENANCE_ADAPTER},
            "provider": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$",
            },
            "endpoint_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
                "format": "uri",
            },
            "evaluated_at_unix": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_CATALOG_TIMESTAMP,
            },
            **{
                key: digest
                for key in fields
                if key.endswith("_sha256")
            },
        },
    }


def _validate_descriptor(value: Any, *, label: str, maximum: int) -> None:
    if not isinstance(value, Mapping) or set(value) != {"bytes", "sha256"}:
        raise _fail(f"{label} descriptor is invalid")
    count = value["bytes"]
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= maximum:
        raise _fail(f"{label} byte count is invalid")
    _digest(value["sha256"], f"{label} sha256")


def _compact_artifact(value: Any, *, label: str) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        raise _fail(f"{label} is not canonical JSON") from None


def _validate_history(
    history: Any,
    attempts: Any,
    catalog_receipt_sha: str,
    *,
    resolved_spec: Mapping[str, Any],
    resolved_check: Mapping[str, Any],
    circuit_spec_sha: str,
    electrical_review_sha: str,
) -> None:
    if not isinstance(history, list) or not history or len(history) > MAX_HISTORY_ITEMS:
        raise _fail("generation attempt history is invalid")
    if (
        isinstance(attempts, bool)
        or not isinstance(attempts, int)
        or attempts < 1
        or attempts > MAX_HISTORY_ITEMS
        or attempts != len(history)
    ):
        raise _fail("generation attempt count is invalid")
    approved_count = 0
    for index, record in enumerate(history, 1):
        if not isinstance(record, Mapping):
            raise _fail("generation history record is invalid")
        keys = set(record)
        if keys - (_HISTORY_REQUIRED | {"error"}) or not _HISTORY_REQUIRED <= keys:
            raise _fail("generation history record has invalid fields")
        if (
            isinstance(record["attempt"], bool)
            or not isinstance(record["attempt"], int)
            or record["attempt"] != index
        ):
            raise _fail("generation history attempts are not ordered")
        for key in ("prompt_bytes", "response_bytes"):
            value = record[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise _fail("generation history byte count is invalid")
        _digest(record["prompt_sha256"], "generation history prompt_sha256")
        for key in _HISTORY_DIGEST_KEYS[1:]:
            value = record[key]
            if value is not None:
                _digest(value, f"generation history {key}")
        if (
            not isinstance(record["outcome"], str)
            or not record["outcome"]
            or len(record["outcome"]) > 128
        ):
            raise _fail("generation history outcome is invalid")
        if "error" in record:
            error = record["error"]
            if (
                not isinstance(error, str)
                or not error
                or len(error) > MAX_CORRECTION_BYTES
            ):
                raise _fail("generation history error is invalid")
            try:
                if len(error.encode("utf-8", errors="strict")) > MAX_CORRECTION_BYTES:
                    raise _fail("generation history error is invalid")
            except UnicodeEncodeError:
                raise _fail("generation history error is invalid") from None
        for key in ("errors", "warnings", "error_count"):
            value = record[key]
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise _fail("generation history count is invalid")
        if record["outcome"] == "approved":
            approved_count += 1
            if record["catalog_receipt_sha256"] != catalog_receipt_sha:
                raise _fail("generation history catalog binding is invalid")
        elif any(record[key] is not None for key in _HISTORY_RESOLVED_KEYS):
            raise _fail("non-approved generation history has resolved artifacts")
    if approved_count != 1 or history[-1]["outcome"] != "approved":
        raise _fail("generation history has no unique final approval")
    final = history[-1]
    expected_final = {
        "resolved_spec_sha256": _sha256(
            _compact_artifact(resolved_spec, label="resolved specification")
        ),
        "resolved_check_sha256": _sha256(
            _compact_artifact(resolved_check, label="resolved check")
        ),
        "resolved_circuit_spec_sha256": circuit_spec_sha,
        "resolved_electrical_review_sha256": electrical_review_sha,
        "catalog_receipt_sha256": catalog_receipt_sha,
    }
    for key, expected in expected_final.items():
        if final[key] != expected:
            raise _fail("generation history final artifact digests are invalid")


def _validate_bundle(bundle: Any, bundle_raw: bytes) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    if not isinstance(bundle, Mapping) or set(bundle) != _BUNDLE_KEYS:
        raise _fail("generation bundle does not match its closed shape")
    if bundle["schema_version"] != 2 or isinstance(bundle["schema_version"], bool):
        raise _fail("generation bundle schema version is invalid")
    _validate_descriptor(
        bundle["requirements"],
        label="generation requirements",
        maximum=MAX_REQUIREMENTS_BYTES,
    )
    try:
        _provider_descriptor(bundle["provider"])
        normalized, error_count = _validate_check_envelope(bundle["check"])
        spec = _validate_v2_spec(bundle["spec"])
    except (CircuitGenerationError, TypeError, ValueError):
        raise _fail("generation bundle native artifacts are invalid") from None
    if normalized != spec:
        raise _fail("generation bundle spec/check mismatch")
    check = bundle["check"]
    if (
        bundle["circuit_spec_sha256"] != check["circuit_spec_sha256"]
        or bundle["electrical_review_sha256"] != check["electrical_review_sha256"]
        or error_count != 0
        or not check["electrical_review"]["approved"]
    ):
        raise _fail("generation bundle native digest or approval binding is invalid")
    for key in ("circuit_spec_sha256", "electrical_review_sha256"):
        _digest(bundle[key], f"generation bundle {key}")
    attempts = bundle["attempts"]
    repaired = bundle["repaired"]
    if not isinstance(repaired, bool) or repaired != (attempts > 1):
        raise _fail("generation bundle repaired flag is invalid")
    catalog_receipt = bundle["catalog_receipt"]
    if not isinstance(catalog_receipt, Mapping):
        raise _fail("generation bundle catalog receipt is missing")
    try:
        selection = validate_catalog_receipt_shape(catalog_receipt)
    except (CatalogError, TypeError, ValueError):
        raise _fail("generation bundle catalog receipt is invalid") from None
    receipt_sha = canonical_sha256(selection)
    if bundle["catalog_receipt_sha256"] != receipt_sha:
        raise _fail("generation bundle catalog receipt digest is invalid")
    _digest(bundle["catalog_receipt_sha256"], "generation bundle catalog receipt")
    _validate_history(
        bundle["attempt_history"],
        attempts,
        receipt_sha,
        resolved_spec=spec,
        resolved_check=check,
        circuit_spec_sha=bundle["circuit_spec_sha256"],
        electrical_review_sha=bundle["electrical_review_sha256"],
    )
    skidl = bundle["skidl"]
    if not isinstance(skidl, str) or not skidl:
        raise _fail("generation bundle SKiDL is invalid")
    try:
        skidl_raw = skidl.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise _fail("generation bundle SKiDL is not valid UTF-8") from None
    if len(skidl_raw) > MAX_PROVENANCE_SKIDL_BYTES:
        raise _fail("generation bundle SKiDL exceeds its byte bound")
    if bundle["skidl_sha256"] != _sha256(skidl_raw):
        raise _fail("generation bundle SKiDL digest is invalid")
    _digest(bundle["skidl_sha256"], "generation bundle SKiDL")
    if not bundle_raw:
        raise _fail("generation bundle source is empty")
    return dict(selection), dict(spec), skidl_raw


def _reconstruct_input_spec(
    resolved_spec: Mapping[str, Any],
    selection: Mapping[str, Any],
) -> dict[str, Any]:
    candidate = copy.deepcopy(dict(resolved_spec))
    by_reference = {part["reference"]: part for part in candidate["parts"]}
    for selected in selection["selections"]:
        reference = selected["reference"]
        part = by_reference.get(reference)
        if part is None:
            raise _fail("catalog selection does not cover generation spec")
        if selected["status"] == "assigned":
            part["mpn"] = None
    return candidate


def _validate_linked_sources(
    *,
    fetch_receipt: Mapping[str, Any],
    fetch_receipt_raw: bytes,
    snapshot_raw: bytes,
    snapshot_source: Any,
    bundle_raw: bytes,
    bundle: Mapping[str, Any],
    generated_skidl_raw: bytes,
    evaluated_at_unix: int | None,
    allow_insecure_loopback: bool,
) -> dict[str, Any]:
    try:
        fetch = validate_catalog_fetch_receipt(
            fetch_receipt,
            snapshot_raw,
            evaluated_at_unix=evaluated_at_unix,
            allow_insecure_loopback=allow_insecure_loopback,
        )
    except (SupplierInventoryError, TypeError, ValueError):
        raise _fail("supplier catalog fetch receipt or snapshot is invalid") from None
    fetched_at = fetch["fetched_at_unix"]
    if evaluated_at_unix is not None and evaluated_at_unix != fetched_at:
        raise _fail("provenance evaluation timestamp does not match fetch receipt")
    try:
        # Preserve the source descriptor when a caller supplies a regular
        # snapshot path: catalog selection receipts may bind ``source.kind``
        # and the basename.  The first bounded read above remains authoritative
        # and the loader's second stable read must yield the exact same bytes.
        path_source = None
        if isinstance(snapshot_source, os.PathLike):
            path_source = snapshot_source
        elif isinstance(snapshot_source, str) and not _looks_like_json_object_text(
            snapshot_source
        ):
            path_source = snapshot_source
        snapshot = load_catalog_snapshot(
            path_source if path_source is not None else snapshot_raw,
            evaluated_at_unix=fetched_at,
        )
        if snapshot.raw_bytes != snapshot_raw:
            raise ValueError
    except Exception:
        raise _fail("supplier catalog snapshot cannot be revalidated") from None
    selection, resolved_spec, bundle_skidl_raw = _validate_bundle(bundle, bundle_raw)
    if generated_skidl_raw != bundle_skidl_raw:
        raise _fail("generated SKiDL does not match generation bundle")
    if selection["evaluated_at_unix"] != fetched_at:
        raise _fail("catalog selection evaluation timestamp does not match fetch")
    policy = selection["policy"]
    input_spec = _reconstruct_input_spec(resolved_spec, selection)
    try:
        validate_catalog_receipt(
            selection,
            input_spec,
            resolved_spec,
            snapshot,
            require_available=policy["require_available"],
            require_basic=policy["require_basic"],
            allow_footprint_fallback=policy["allow_footprint_fallback"],
            evaluated_at_unix=fetched_at,
        )
    except (CatalogError, TypeError, ValueError):
        raise _fail("catalog selection receipt does not match generation artifacts") from None
    if fetch["provider"] != selection["supplier"]:
        raise _fail("fetch and selection providers do not match")
    if fetch["catalog_sha256"] != selection["catalog"]["sha256"]:
        raise _fail("fetch and selection catalog digests do not match")
    return {
        "provider": fetch["provider"],
        "endpoint_id": fetch["endpoint_id"],
        "evaluated_at_unix": fetched_at,
        "fetch_receipt_sha256": _sha256(fetch_receipt_raw),
        "snapshot_sha256": _sha256(snapshot_raw),
        "catalog_sha256": fetch["catalog_sha256"],
        "selection_receipt_sha256": canonical_sha256(selection),
        "input_spec_sha256": selection["input_spec_sha256"],
        "resolved_spec_sha256": selection["resolved_spec_sha256"],
        "generation_bundle_sha256": _sha256(bundle_raw),
        "generated_skidl_sha256": _sha256(generated_skidl_raw),
    }


def _prepare_sources(
    fetch_receipt_source: Any,
    snapshot_source: Any,
    generation_bundle_source: Any,
    generated_skidl_source: Any,
) -> tuple[dict[str, Any], bytes, bytes, bytes, bytes, dict[str, Any], dict[str, Any], bytes]:
    fetch_raw = _read_source(
        fetch_receipt_source,
        label="fetch receipt",
        maximum=min(MAXIMUM_RECEIPT_BYTES, MAX_CATALOG_RECEIPT_BYTES),
    )
    fetch = _parse_object(fetch_raw, label="fetch receipt")
    snapshot_raw = _read_source(
        snapshot_source,
        label="normalized snapshot",
        maximum=MAX_CATALOG_RAW_BYTES,
    )
    bundle_raw = _read_source(
        generation_bundle_source,
        label="generation bundle",
        maximum=MAX_PROVENANCE_BUNDLE_BYTES,
    )
    bundle = _parse_object(bundle_raw, label="generation bundle")
    if generated_skidl_source is None:
        generated_raw = None
    else:
        generated_raw = _read_source(
            generated_skidl_source,
            label="generated SKiDL",
            maximum=MAX_PROVENANCE_SKIDL_BYTES,
            string_is_text=True,
        )
    # Validate the bundle once here so a derived SKiDL source can be obtained
    # only from its strict, checked string field.
    try:
        selection, resolved, bundle_skidl = _validate_bundle(bundle, bundle_raw)
    except CatalogGenerationProvenanceError:
        raise
    if generated_raw is None:
        generated_raw = bundle_skidl
    return (
        fetch,
        fetch_raw,
        snapshot_raw,
        bundle_raw,
        generated_raw,
        selection,
        resolved,
        bundle_skidl,
    )


def build_catalog_generation_provenance(
    fetch_receipt_source: Any,
    snapshot_source: Any,
    generation_bundle_source: Any,
    generated_skidl_source: Any = None,
    *,
    evaluated_at_unix: int | None = None,
    allow_insecure_loopback: bool = False,
) -> dict[str, Any]:
    """Build one closed provenance sidecar from exact retained artifacts."""

    if not isinstance(allow_insecure_loopback, bool):
        raise _fail("allow_insecure_loopback must be a boolean")
    try:
        (
            fetch,
            fetch_raw,
            snapshot_raw,
            bundle_raw,
            generated_raw,
            _selection,
            _resolved,
            _bundle_skidl,
        ) = _prepare_sources(
            fetch_receipt_source,
            snapshot_source,
            generation_bundle_source,
            generated_skidl_source,
        )
        values = _validate_linked_sources(
            fetch_receipt=fetch,
            fetch_receipt_raw=fetch_raw,
            snapshot_raw=snapshot_raw,
            snapshot_source=snapshot_source,
            bundle_raw=bundle_raw,
            bundle=_parse_object(bundle_raw, label="generation bundle"),
            generated_skidl_raw=generated_raw,
            evaluated_at_unix=evaluated_at_unix,
            allow_insecure_loopback=allow_insecure_loopback,
        )
    except CatalogGenerationProvenanceError:
        raise
    except Exception:
        raise _fail("catalog generation provenance inputs failed validation") from None
    _validate_provenance_shape(
        {"schema_version": PROVENANCE_SCHEMA_VERSION, "adapter": PROVENANCE_ADAPTER, **values}
    )
    return {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "adapter": PROVENANCE_ADAPTER,
        **values,
    }


def validate_catalog_generation_provenance(
    provenance: Any,
    fetch_receipt_source: Any,
    snapshot_source: Any,
    generation_bundle_source: Any,
    generated_skidl_source: Any = None,
    *,
    evaluated_at_unix: int | None = None,
    allow_insecure_loopback: bool = False,
) -> dict[str, Any]:
    """Re-read and recompute every artifact bound by a provenance sidecar."""

    if not isinstance(allow_insecure_loopback, bool):
        raise _fail("allow_insecure_loopback must be a boolean")
    if isinstance(provenance, Mapping):
        shape = _validate_provenance_shape(provenance)
    elif isinstance(provenance, (bytes, bytearray, memoryview, str, os.PathLike)):
        provenance_raw = _read_source(
            provenance,
            label="catalog generation provenance",
            maximum=MAX_PROVENANCE_BYTES,
        )
        shape = _validate_provenance_shape(
            _parse_object(provenance_raw, label="catalog generation provenance")
        )
    else:
        raise _fail("catalog generation provenance source is invalid")
    try:
        (
            fetch,
            fetch_raw,
            snapshot_raw,
            bundle_raw,
            generated_raw,
            _selection,
            _resolved,
            _bundle_skidl,
        ) = _prepare_sources(
            fetch_receipt_source,
            snapshot_source,
            generation_bundle_source,
            generated_skidl_source,
        )
        values = _validate_linked_sources(
            fetch_receipt=fetch,
            fetch_receipt_raw=fetch_raw,
            snapshot_raw=snapshot_raw,
            snapshot_source=snapshot_source,
            bundle_raw=bundle_raw,
            bundle=_parse_object(bundle_raw, label="generation bundle"),
            generated_skidl_raw=generated_raw,
            evaluated_at_unix=evaluated_at_unix,
            allow_insecure_loopback=allow_insecure_loopback,
        )
    except CatalogGenerationProvenanceError:
        raise
    except Exception:
        raise _fail("catalog generation provenance inputs failed validation") from None
    expected = {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "adapter": PROVENANCE_ADAPTER,
        **values,
    }
    if shape != expected:
        raise _fail("catalog generation provenance does not match retained artifacts")
    return shape


__all__ = [
    "CatalogGenerationProvenanceError",
    "catalog_generation_provenance_json_schema",
    "build_catalog_generation_provenance",
    "validate_catalog_generation_provenance",
]
