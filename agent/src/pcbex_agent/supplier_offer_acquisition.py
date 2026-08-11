"""Bounded HTTPS acquisition of normalized offline supplier offers.

The adapter retains one normalized offer and a correlation receipt.  It does
not retain the raw HTTP response and does not authenticate the supplier,
offer, price, availability, time, inventory, authority, order, or payment.
"""

from __future__ import annotations

from collections.abc import Mapping
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Any
import unicodedata

from .bounded_io import (
    BoundedIOError,
    atomic_write_no_clobber,
    read_bytes,
    validate_no_clobber_path,
)
from . import procurement_intent as _procurement
from . import supplier_offer as _supplier_offer
from . import _supplier_offer_transport as _transport


SUPPLIER_OFFER_FETCH_RECEIPT_SCHEMA_VERSION = 1
SUPPLIER_OFFER_FETCH_RECEIPT_SCOPE = (
    "https-supplier-offer-acquisition-receipt-v1"
)
SUPPLIER_OFFER_FETCH_ADAPTER = "supplier-offer-http-v1"
SUPPLIER_OFFER_REQUEST_BINDING_DOMAIN = (
    b"pcbex:https-supplier-offer-acquisition-request-v1\0"
)

MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES = 1 * 1024 * 1024
_MAXIMUM_VALIDATION_AGGREGATE_BYTES = 5 * 1024 * 1024
_MAXIMUM_PATH_BYTES = 32_768
_MAXIMUM_TIMESTAMP = 9_223_372_036_854_775_807
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SUPPLIER_RE = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?")

_RECEIPT_KEYS = (
    "adapter",
    "adapter_network_performed",
    "current_availability_verified",
    "endpoint_id",
    "fetched_at_unix",
    "inventory_reserved",
    "offer_authenticity_verified",
    "offer_bytes",
    "offer_sha256",
    "order_placed",
    "order_ready",
    "payment_performed",
    "price_authenticity_verified",
    "procurement_authorized",
    "procurement_intent_sha256",
    "request_sha256",
    "response_bytes",
    "response_sha256",
    "schema_version",
    "scope",
    "status",
    "supplier",
    "supplier_authenticity_verified",
    "trusted_time_verified",
)
_FALSE_CLAIM_KEYS = (
    "current_availability_verified",
    "inventory_reserved",
    "offer_authenticity_verified",
    "order_placed",
    "order_ready",
    "payment_performed",
    "price_authenticity_verified",
    "procurement_authorized",
    "supplier_authenticity_verified",
    "trusted_time_verified",
)


class SupplierOfferAcquisitionError(ValueError):
    """Stable, secret/path/body-free offer acquisition failure."""


@dataclass(frozen=True)
class _CapturedFile:
    path: str
    label: str
    maximum: int
    raw: bytes


def _fail(message: str) -> SupplierOfferAcquisitionError:
    return SupplierOfferAcquisitionError(message)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _strict_json_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _strict_json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _strict_json_equal(a, b) for a, b in zip(left, right)
        )
    return left == right


def _compact_json(value: Any, label: str) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        raise _fail(f"{label} cannot be serialized") from None


def _pretty_json(value: Mapping[str, Any], *, maximum: int, label: str) -> bytes:
    try:
        encoder = json.JSONEncoder(
            ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True
        )
        output = bytearray()
        for chunk in encoder.iterencode(dict(value)):
            encoded = str.encode(chunk, "utf-8", "strict")
            if len(output) + len(encoded) + 1 > maximum:
                raise _fail(f"{label} exceeds its byte bound")
            output.extend(encoded)
        output.append(0x0A)
        return bytes(output)
    except SupplierOfferAcquisitionError:
        raise
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        raise _fail(f"{label} cannot be serialized") from None


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise _fail(f"{label} is invalid")
    return value


def _supplier(value: Any, label: str = "supplier") -> str:
    if type(value) is not str or _SUPPLIER_RE.fullmatch(value) is None:
        raise _fail(f"{label} must be lowercase safe ASCII")
    try:
        encoded = str.encode(value, "ascii", "strict")
    except UnicodeEncodeError:
        raise _fail(f"{label} must be lowercase safe ASCII") from None
    if not 1 <= len(encoded) <= 64:
        raise _fail(f"{label} must be lowercase safe ASCII")
    return str.__str__(value)


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _fail(f"{label} is invalid")
    return value


def _timeout(value: Any) -> int:
    return _integer(value, "supplier-offer timeout", minimum=1, maximum=60)


def _response_limit(value: Any) -> int:
    return _integer(
        value,
        "maximum supplier-offer response bytes",
        minimum=1,
        maximum=_supplier_offer.MAXIMUM_SUPPLIER_OFFER_BYTES,
    )


def _timestamp(value: Any, label: str) -> int:
    return _integer(value, label, minimum=0, maximum=_MAXIMUM_TIMESTAMP)


def _loopback_flag(value: Any) -> bool:
    if type(value) is not bool:
        raise _fail("allow_insecure_loopback must be a boolean")
    return value


def _freeze_path(value: Any, label: str, *, absolute: bool) -> str:
    try:
        rendered = os.fspath(value)
    except Exception:
        raise _fail(f"{label} is invalid") from None
    if not isinstance(rendered, str):
        raise _fail(f"{label} is invalid")
    if (
        str.__len__(rendered) == 0
        or str.__len__(rendered) > _MAXIMUM_PATH_BYTES
        or str.__contains__(rendered, "\x00")
    ):
        raise _fail(f"{label} is invalid")
    try:
        encoded = str.encode(rendered, "utf-8", "strict")
    except UnicodeEncodeError:
        raise _fail(f"{label} is invalid") from None
    if len(encoded) > _MAXIMUM_PATH_BYTES:
        raise _fail(f"{label} is invalid")
    frozen = str.__str__(rendered)
    if absolute:
        try:
            frozen = os.path.abspath(frozen)
        except (OSError, TypeError, ValueError):
            raise _fail(f"{label} is invalid") from None
        try:
            frozen_bytes = str.encode(frozen, "utf-8", "strict")
        except UnicodeEncodeError:
            raise _fail(f"{label} is invalid") from None
        if len(frozen_bytes) > _MAXIMUM_PATH_BYTES:
            raise _fail(f"{label} is invalid")
    return frozen


def _comparison_path(path: str, label: str) -> str:
    try:
        resolved = os.path.realpath(path)
        normalized = os.path.normcase(resolved)
        return unicodedata.normalize("NFC", normalized).casefold()
    except Exception:
        raise _fail(f"{label} is invalid") from None


def _outputs_may_alias(output: str, receipt: str) -> bool:
    if _comparison_path(output, "supplier-offer output path") == _comparison_path(
        receipt, "supplier-offer receipt path"
    ):
        return True
    output_parent = os.path.dirname(output)
    receipt_parent = os.path.dirname(receipt)
    try:
        same_parent = os.path.samefile(output_parent, receipt_parent)
    except FileNotFoundError:
        same_parent = False
    except Exception:
        raise _fail("supplier-offer output path identity is invalid") from None
    if not same_parent:
        return False
    output_leaf = unicodedata.normalize("NFC", os.path.basename(output)).casefold()
    receipt_leaf = unicodedata.normalize("NFC", os.path.basename(receipt)).casefold()
    return output_leaf == receipt_leaf


def _preflight_outputs(output_path: Any, receipt_path: Any) -> tuple[Path, Path]:
    output = _freeze_path(output_path, "supplier-offer output path", absolute=True)
    receipt = _freeze_path(receipt_path, "supplier-offer receipt path", absolute=True)
    paths = (Path(output), Path(receipt))
    for path in paths:
        try:
            validate_no_clobber_path(path)
        except (BoundedIOError, OSError, TypeError, ValueError):
            raise _fail(
                "supplier-offer output path is unsafe or already exists"
            ) from None
    if _outputs_may_alias(output, receipt):
        raise _fail("supplier-offer output and receipt paths must differ")
    return paths


def _request_sha256(
    endpoint_id: str, supplier: str, procurement_intent_sha256: str
) -> str:
    material = {
        "adapter": SUPPLIER_OFFER_FETCH_ADAPTER,
        "endpoint_id": endpoint_id,
        "method": "GET",
        "procurement_intent_sha256": procurement_intent_sha256,
        "supplier": supplier,
    }
    return _sha256(
        SUPPLIER_OFFER_REQUEST_BINDING_DOMAIN
        + _compact_json(material, "supplier-offer request material")
    )


def _normalize_offer(raw: bytes) -> tuple[dict[str, Any], bytes]:
    try:
        parsed = _supplier_offer._parse_json_object(raw, "supplier-offer response")
        normalized = _supplier_offer._normalize_offer(parsed)
    except _supplier_offer.SupplierOfferError:
        raise _fail("supplier-offer response failed closed validation") from None
    rendered = _pretty_json(
        normalized,
        maximum=_supplier_offer.MAXIMUM_SUPPLIER_OFFER_BYTES,
        label="normalized supplier offer",
    )
    return normalized, rendered


def _validate_receipt_shape(
    receipt: Any, *, allow_insecure_loopback: bool
) -> dict[str, Any]:
    allow_loopback = _loopback_flag(allow_insecure_loopback)
    if not isinstance(receipt, Mapping) or set(receipt) != set(_RECEIPT_KEYS):
        raise _fail("supplier-offer fetch receipt has invalid fields")
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != SUPPLIER_OFFER_FETCH_RECEIPT_SCHEMA_VERSION
        or receipt["scope"] != SUPPLIER_OFFER_FETCH_RECEIPT_SCOPE
        or receipt["adapter"] != SUPPLIER_OFFER_FETCH_ADAPTER
        or receipt["adapter_network_performed"] is not True
        or any(receipt[key] is not False for key in _FALSE_CLAIM_KEYS)
    ):
        raise _fail("supplier-offer fetch receipt identity or nonclaim state is invalid")
    supplier = _supplier(receipt["supplier"], "receipt supplier")
    try:
        endpoint_id, _parts = _transport._endpoint_parts(
            receipt["endpoint_id"], allow_insecure_loopback=allow_loopback
        )
    except _transport._SupplierOfferTransportError:
        raise _fail("supplier-offer fetch receipt endpoint is invalid") from None
    if endpoint_id != receipt["endpoint_id"]:
        raise _fail("supplier-offer fetch receipt endpoint is not canonical")
    procurement_digest = _digest(
        receipt["procurement_intent_sha256"],
        "receipt procurement-intent digest",
    )
    request_digest = _digest(receipt["request_sha256"], "receipt request digest")
    response_digest = _digest(receipt["response_sha256"], "receipt response digest")
    offer_digest = _digest(receipt["offer_sha256"], "receipt offer digest")
    response_bytes = _integer(
        receipt["response_bytes"],
        "receipt response byte count",
        minimum=1,
        maximum=_supplier_offer.MAXIMUM_SUPPLIER_OFFER_BYTES,
    )
    offer_bytes = _integer(
        receipt["offer_bytes"],
        "receipt offer byte count",
        minimum=1,
        maximum=_supplier_offer.MAXIMUM_SUPPLIER_OFFER_BYTES,
    )
    status = _integer(receipt["status"], "receipt HTTP status", minimum=200, maximum=299)
    if status in {204, 205}:
        raise _fail("supplier-offer fetch receipt has a bodyless HTTP status")
    fetched = _timestamp(receipt["fetched_at_unix"], "receipt fetched timestamp")
    expected_request = _request_sha256(endpoint_id, supplier, procurement_digest)
    if request_digest != expected_request:
        raise _fail("supplier-offer fetch receipt request digest is invalid")
    normalized = {
        "adapter": SUPPLIER_OFFER_FETCH_ADAPTER,
        "adapter_network_performed": True,
        "current_availability_verified": False,
        "endpoint_id": endpoint_id,
        "fetched_at_unix": fetched,
        "inventory_reserved": False,
        "offer_authenticity_verified": False,
        "offer_bytes": offer_bytes,
        "offer_sha256": offer_digest,
        "order_placed": False,
        "order_ready": False,
        "payment_performed": False,
        "price_authenticity_verified": False,
        "procurement_authorized": False,
        "procurement_intent_sha256": procurement_digest,
        "request_sha256": request_digest,
        "response_bytes": response_bytes,
        "response_sha256": response_digest,
        "schema_version": SUPPLIER_OFFER_FETCH_RECEIPT_SCHEMA_VERSION,
        "scope": SUPPLIER_OFFER_FETCH_RECEIPT_SCOPE,
        "status": status,
        "supplier": supplier,
        "supplier_authenticity_verified": False,
        "trusted_time_verified": False,
    }
    if tuple(normalized) != _RECEIPT_KEYS:
        raise AssertionError("receipt key order is not lexicographic")
    if len(_compact_json(normalized, "supplier-offer fetch receipt")) > MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES:
        raise _fail("supplier-offer fetch receipt exceeds its byte bound")
    return normalized


def fetch_supplier_offer(
    endpoint: str,
    supplier: str,
    output_path: Any,
    receipt_path: Any,
    *,
    procurement_intent_sha256: str,
    timeout_seconds: int = 30,
    maximum_response_bytes: int = _supplier_offer.MAXIMUM_SUPPLIER_OFFER_BYTES,
    bearer_token_environment: str | None = None,
    fetched_at_unix: int | None = None,
    allow_insecure_loopback: bool = False,
) -> dict[str, Any]:
    """Fetch, normalize, and no-clobber publish one exact supplier offer."""

    # Both output targets are preflighted before environment access, time
    # observation, DNS, TCP, TLS, or HTTP.
    output, receipt_output = _preflight_outputs(output_path, receipt_path)
    supplier_value = _supplier(supplier)
    procurement_digest = _digest(
        procurement_intent_sha256, "procurement-intent digest"
    )
    timeout = _timeout(timeout_seconds)
    response_limit = _response_limit(maximum_response_bytes)
    allow_loopback = _loopback_flag(allow_insecure_loopback)
    try:
        endpoint_id, _parts = _transport._endpoint_parts(
            endpoint, allow_insecure_loopback=allow_loopback
        )
        token = _transport._load_bearer_token(bearer_token_environment)
    except _transport._SupplierOfferTransportError as error:
        raise _fail(str(error)) from None
    if fetched_at_unix is None:
        try:
            fetched = _timestamp(int(time.time()), "fetched-at timestamp")
        except (TypeError, ValueError, OverflowError):
            raise _fail("fetched-at timestamp is invalid") from None
    else:
        fetched = _timestamp(fetched_at_unix, "fetched-at timestamp")
    try:
        raw_response, status = _transport._http_get(
            endpoint_id,
            timeout_seconds=timeout,
            maximum_response_bytes=response_limit,
            bearer_token=token,
        )
    except _transport._SupplierOfferTransportError as error:
        raise _fail(str(error)) from None
    if (
        type(raw_response) is not bytes
        or not 1 <= len(raw_response) <= response_limit
        or type(status) is not int
        or not 200 <= status <= 299
    ):
        raise _fail("supplier-offer transport returned an invalid response")
    token_bytes = None if token is None else token.encode("ascii", errors="strict")
    if token_bytes and token_bytes in raw_response:
        raise _fail("supplier-offer response reflected the bearer token")
    response_sha = _sha256(raw_response)
    offer, normalized_offer = _normalize_offer(raw_response)
    if offer["supplier"] != supplier_value:
        raise _fail("supplier-offer response supplier does not match request")
    if offer["procurement_intent_sha256"] != procurement_digest:
        raise _fail("supplier-offer response procurement intent does not match request")
    if token_bytes and token_bytes in normalized_offer:
        raise _fail("normalized supplier offer reflected the bearer token")

    receipt: dict[str, Any] = {
        "adapter": SUPPLIER_OFFER_FETCH_ADAPTER,
        "adapter_network_performed": True,
        "current_availability_verified": False,
        "endpoint_id": endpoint_id,
        "fetched_at_unix": fetched,
        "inventory_reserved": False,
        "offer_authenticity_verified": False,
        "offer_bytes": len(normalized_offer),
        "offer_sha256": _sha256(normalized_offer),
        "order_placed": False,
        "order_ready": False,
        "payment_performed": False,
        "price_authenticity_verified": False,
        "procurement_authorized": False,
        "procurement_intent_sha256": procurement_digest,
        "request_sha256": _request_sha256(
            endpoint_id, supplier_value, procurement_digest
        ),
        "response_bytes": len(raw_response),
        "response_sha256": response_sha,
        "schema_version": SUPPLIER_OFFER_FETCH_RECEIPT_SCHEMA_VERSION,
        "scope": SUPPLIER_OFFER_FETCH_RECEIPT_SCOPE,
        "status": status,
        "supplier": supplier_value,
        "supplier_authenticity_verified": False,
        "trusted_time_verified": False,
    }
    receipt = _validate_receipt_shape(
        receipt, allow_insecure_loopback=allow_loopback
    )
    receipt_bytes = _pretty_json(
        receipt,
        maximum=MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
        label="supplier-offer fetch receipt",
    )
    if token_bytes and token_bytes in receipt_bytes:
        raise _fail("supplier-offer fetch receipt reflected the bearer token")
    try:
        atomic_write_no_clobber(
            output,
            normalized_offer,
            max_bytes=_supplier_offer.MAXIMUM_SUPPLIER_OFFER_BYTES,
        )
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail("publishing normalized supplier offer failed") from None
    try:
        atomic_write_no_clobber(
            receipt_output,
            receipt_bytes,
            max_bytes=MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
        )
    except (BoundedIOError, OSError, TypeError, ValueError):
        # The already-published offer remains valid and is never unlinked.
        raise _fail("publishing supplier-offer fetch receipt failed") from None
    return receipt


def _bounded_bytes_like(value: bytes | bytearray | memoryview, label: str, maximum: int) -> bytes:
    try:
        view = memoryview(value)
    except Exception:
        raise _fail(f"{label} is invalid") from None
    try:
        size = view.nbytes
        if not 1 <= size <= maximum:
            raise _fail(f"{label} exceeds its byte bound")
        raw = view.tobytes()
    except SupplierOfferAcquisitionError:
        raise
    except Exception:
        raise _fail(f"{label} is invalid") from None
    finally:
        try:
            view.release()
        except Exception:
            pass
    if len(raw) != size:
        raise _fail(f"{label} is invalid")
    return raw


def _read_file(path: str, label: str, maximum: int) -> bytes:
    try:
        raw = read_bytes(path, max_bytes=maximum)
    except (BoundedIOError, OSError, TypeError, ValueError):
        raise _fail(f"{label} source is invalid") from None
    if not raw:
        raise _fail(f"{label} source is empty")
    return raw


def _parse_receipt_bytes(raw: bytes) -> dict[str, Any]:
    try:
        return _supplier_offer._parse_json_object(raw, "supplier-offer fetch receipt")
    except _supplier_offer.SupplierOfferError:
        raise _fail("supplier-offer fetch receipt is not strict JSON") from None


def _snapshot_receipt_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        raw = _procurement._bounded_injected_json_bytes(
            value,
            maximum=MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
            label="supplier-offer fetch receipt",
        )
    except (
        _procurement.CatalogGenerationProvenanceError,
    ):
        raise _fail("supplier-offer fetch receipt is invalid") from None
    except Exception:
        raise _fail("supplier-offer fetch receipt is invalid") from None
    return _parse_receipt_bytes(raw)


def _ensure_distinct_files(left: str, right: str) -> None:
    if left == right:
        raise _fail("receipt and offer sources must be distinct")
    try:
        if os.path.samefile(left, right):
            raise _fail("receipt and offer sources must be distinct")
    except SupplierOfferAcquisitionError:
        raise
    except (OSError, TypeError, ValueError):
        raise _fail("receipt and offer source identity is invalid") from None


def validate_supplier_offer_fetch_receipt(
    receipt: Mapping[str, Any] | bytes | bytearray | memoryview | str | os.PathLike[str],
    offer_source: bytes | bytearray | memoryview | str | os.PathLike[str],
    *,
    allow_insecure_loopback: bool = False,
) -> dict[str, Any]:
    """Validate one receipt against an exact canonical normalized offer."""

    allow_loopback = _loopback_flag(allow_insecure_loopback)
    offer_file: _CapturedFile | None = None
    if isinstance(offer_source, (bytes, bytearray, memoryview)):
        offer_raw = _bounded_bytes_like(
            offer_source,
            "normalized supplier-offer source",
            _supplier_offer.MAXIMUM_SUPPLIER_OFFER_BYTES,
        )
    elif isinstance(offer_source, (str, os.PathLike)):
        offer_path = _freeze_path(
            offer_source, "normalized supplier-offer source", absolute=True
        )
        offer_raw = _read_file(
            offer_path,
            "normalized supplier offer",
            _supplier_offer.MAXIMUM_SUPPLIER_OFFER_BYTES,
        )
        offer_file = _CapturedFile(
            offer_path,
            "normalized supplier offer",
            _supplier_offer.MAXIMUM_SUPPLIER_OFFER_BYTES,
            offer_raw,
        )
    else:
        raise _fail("normalized supplier-offer source must be a path or bytes")

    receipt_file: _CapturedFile | None = None
    injected_mapping = False
    if isinstance(receipt, Mapping):
        injected_mapping = True
        receipt_value = _snapshot_receipt_mapping(receipt)
        receipt_raw = _pretty_json(
            receipt_value,
            maximum=MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
            label="supplier-offer fetch receipt",
        )
    elif isinstance(receipt, (bytes, bytearray, memoryview)):
        receipt_raw = _bounded_bytes_like(
            receipt,
            "supplier-offer fetch receipt",
            MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
        )
        receipt_value = _parse_receipt_bytes(receipt_raw)
    elif isinstance(receipt, (str, os.PathLike)):
        receipt_path = _freeze_path(
            receipt, "supplier-offer fetch receipt source", absolute=True
        )
        if offer_file is not None:
            _ensure_distinct_files(offer_file.path, receipt_path)
        receipt_raw = _read_file(
            receipt_path,
            "supplier-offer fetch receipt",
            MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
        )
        receipt_value = _parse_receipt_bytes(receipt_raw)
        receipt_file = _CapturedFile(
            receipt_path,
            "supplier-offer fetch receipt",
            MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
            receipt_raw,
        )
    else:
        raise _fail("supplier-offer fetch receipt is invalid")
    if len(offer_raw) + len(receipt_raw) > _MAXIMUM_VALIDATION_AGGREGATE_BYTES:
        raise _fail("supplier-offer receipt inputs exceed their aggregate bound")

    shape = _validate_receipt_shape(
        receipt_value, allow_insecure_loopback=allow_loopback
    )
    canonical_receipt = _pretty_json(
        shape,
        maximum=MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES,
        label="supplier-offer fetch receipt",
    )
    if not injected_mapping and receipt_raw != canonical_receipt:
        raise _fail("supplier-offer fetch receipt is not canonical pretty JSON")
    offer, canonical_offer = _normalize_offer(offer_raw)
    if offer_raw != canonical_offer:
        raise _fail("normalized supplier-offer source is not canonical pretty JSON")
    if (
        len(offer_raw) != shape["offer_bytes"]
        or _sha256(offer_raw) != shape["offer_sha256"]
        or offer["supplier"] != shape["supplier"]
        or offer["procurement_intent_sha256"]
        != shape["procurement_intent_sha256"]
    ):
        raise _fail("supplier-offer fetch receipt does not match the normalized offer")

    for source in (offer_file, receipt_file):
        if source is not None and _read_file(
            source.path, source.label, source.maximum
        ) != source.raw:
            raise _fail(f"{source.label} changed during receipt validation")
    return shape


def supplier_offer_fetch_receipt_json_schema() -> dict[str, Any]:
    """Return the closed Draft 2020-12 acquisition-receipt schema."""

    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    properties: dict[str, Any] = {
        "adapter": {"const": SUPPLIER_OFFER_FETCH_ADAPTER},
        "adapter_network_performed": {"const": True},
        "current_availability_verified": {"const": False},
        "endpoint_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _transport.MAXIMUM_ENDPOINT_BYTES,
            "format": "uri",
        },
        "fetched_at_unix": {
            "type": "integer",
            "minimum": 0,
            "maximum": _MAXIMUM_TIMESTAMP,
        },
        "inventory_reserved": {"const": False},
        "offer_authenticity_verified": {"const": False},
        "offer_bytes": {
            "type": "integer",
            "minimum": 1,
            "maximum": _supplier_offer.MAXIMUM_SUPPLIER_OFFER_BYTES,
        },
        "offer_sha256": copy.deepcopy(digest),
        "order_placed": {"const": False},
        "order_ready": {"const": False},
        "payment_performed": {"const": False},
        "price_authenticity_verified": {"const": False},
        "procurement_authorized": {"const": False},
        "procurement_intent_sha256": copy.deepcopy(digest),
        "request_sha256": copy.deepcopy(digest),
        "response_bytes": {
            "type": "integer",
            "minimum": 1,
            "maximum": _supplier_offer.MAXIMUM_SUPPLIER_OFFER_BYTES,
        },
        "response_sha256": copy.deepcopy(digest),
        "schema_version": {"const": SUPPLIER_OFFER_FETCH_RECEIPT_SCHEMA_VERSION},
        "scope": {"const": SUPPLIER_OFFER_FETCH_RECEIPT_SCOPE},
        "status": {
            "type": "integer",
            "minimum": 200,
            "maximum": 299,
            "not": {"enum": [204, 205]},
        },
        "supplier": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$",
        },
        "supplier_authenticity_verified": {"const": False},
        "trusted_time_verified": {"const": False},
    }
    if tuple(properties) != _RECEIPT_KEYS:
        raise AssertionError("receipt schema keys are not lexicographic")
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/penguin425/pcbex/schemas/"
            "supplier-offer-fetch-receipt-v1.json"
        ),
        "title": "pcbex HTTPS supplier-offer acquisition receipt",
        "type": "object",
        "additionalProperties": False,
        "required": list(_RECEIPT_KEYS),
        "properties": properties,
        "$comment": (
            "Runtime validation additionally enforces exact built-in scalar types, "
            "canonical endpoints and JSON bytes, recomputed request identity, exact "
            "offer byte/digest/supplier/procurement bindings, one-pass Mapping "
            "capture, alias rejection, aggregate bounds, and final source rereads. "
            "No network, trusted-time, or offer-window replay occurs in validation."
        ),
    }


__all__ = [
    "MAXIMUM_SUPPLIER_OFFER_FETCH_RECEIPT_BYTES",
    "SupplierOfferAcquisitionError",
    "fetch_supplier_offer",
    "supplier_offer_fetch_receipt_json_schema",
    "validate_supplier_offer_fetch_receipt",
]
