"""Closed, deterministic supplier catalog snapshots and part selection.

The original catalog helper in this module intentionally accepted a small
array of :class:`CatalogPart` values.  A live supplier response is not a safe
input to a reproducible build, however: it can change while a circuit is being
resolved and it does not provide an auditable binding for the selected MPNs.
The snapshot API below keeps that small legacy helper available while adding a
strict, byte-bound snapshot and a digest-bound selection receipt.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


SNAPSHOT_SCHEMA_VERSION = 1
RECEIPT_SCHEMA_VERSION = 1
RECEIPT_ADAPTER = "catalog-snapshot-v1"
MAX_CATALOG_RAW_BYTES = 4 * 1024 * 1024
MAX_CATALOG_PARTS = 100_000
MAX_CATALOG_SELECTION_WORK = 1_000_000
MAX_CATALOG_QUERY_TOKENS = 128
MAX_CATALOG_QUERY_BYTES = 4 * 1024
MAX_CATALOG_RECEIPT_BYTES = 1 * 1024 * 1024
MAX_CATALOG_TEXT_BYTES = 4 * 1024
MAX_CATALOG_TAGS = 64
MAX_CATALOG_TAG_BYTES = 512
MAX_CATALOG_STOCK = 2_147_483_647
MAX_CATALOG_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_CATALOG_TIMESTAMP = 9_223_372_036_854_775_807
MAX_CATALOG_ID_BYTES = 128
MAX_SPEC_PARTS = 256
MAX_SPEC_BYTES = 16 * 1024 * 1024
MAX_SPEC_NETS = 512
MAX_SPEC_PINS_PER_PART = 256
MAX_SPEC_CONNECTIONS_PER_NET = 4_096
MAX_SPEC_REFERENCE_BYTES = 64
MAX_SPEC_PIN_NUMBER_BYTES = 64
MAX_SPEC_PIN_NAME_BYTES = 256
MAX_SPEC_NET_NAME_BYTES = 128
MAX_SPEC_LIB_ID_BYTES = 256
MAX_SPEC_VALUE_BYTES = 512
MAX_SPEC_FOOTPRINT_BYTES = 512
MAX_SPEC_MPN_BYTES = 256
MAX_SPEC_VOLTAGE = 1_000_000_000

_SUPPLIER_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
_SNAPSHOT_ID_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_JSON_START = re.compile(r"^\s*\{")
_SPEC_REFERENCE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_SPEC_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_+.\/-]+$")
_ELECTRICAL_PIN_TYPES = {
    "input",
    "output",
    "bidirectional",
    "tri_state",
    "passive",
    "free",
    "power_input",
    "power_output",
    "open_collector",
    "open_emitter",
    "no_connect",
}


class CatalogError(ValueError):
    """Raised when a catalog snapshot or selection receipt is unsafe."""


class CatalogSelectionError(CatalogError):
    """Raised when a valid snapshot cannot satisfy a requested part."""


class _DuplicateJSONKey(ValueError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number {value}")


def _preflight_json_value(
    value: Any,
    *,
    label: str,
    max_bytes: int,
    _active: set[int] | None = None,
    _state: list[int] | None = None,
    _depth: int = 0,
) -> None:
    """Bound an injected JSON-like graph before copying or serializing it."""

    active = set() if _active is None else _active
    state = [0] if _state is None else _state
    if _depth > 128:
        raise CatalogError(f"{label} is nested too deeply")
    if value is None or isinstance(value, bool):
        state[0] += 5
    elif isinstance(value, int):
        if isinstance(value, bool):
            raise CatalogError(f"{label} contains a boolean where an integer is required")
        state[0] += 24
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise CatalogError(f"{label} contains a non-finite number")
        state[0] += 32
    elif isinstance(value, str):
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise CatalogError(f"{label} contains invalid UTF-8") from error
        state[0] += (2 * len(encoded)) + 2
    elif isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            raise CatalogError(f"{label} contains a recursive mapping")
        active.add(identity)
        try:
            state[0] += 2
            for key, child in value.items():
                if not isinstance(key, str):
                    raise CatalogError(f"{label} contains a non-string object key")
                try:
                    encoded_key = key.encode("utf-8", errors="strict")
                except UnicodeEncodeError as error:
                    raise CatalogError(f"{label} contains invalid UTF-8 object key") from error
                state[0] += (2 * len(encoded_key)) + 2
                _preflight_json_value(
                    child,
                    label=f"{label}.{key}",
                    max_bytes=max_bytes,
                    _active=active,
                    _state=state,
                    _depth=_depth + 1,
                )
        except (TypeError, ValueError, RuntimeError) as error:
            if isinstance(error, CatalogError):
                raise
            raise CatalogError(f"{label} could not be traversed safely") from error
        finally:
            active.remove(identity)
    elif isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in active:
            raise CatalogError(f"{label} contains a recursive array")
        active.add(identity)
        try:
            state[0] += 2
            for index, child in enumerate(value):
                _preflight_json_value(
                    child,
                    label=f"{label}[{index}]",
                    max_bytes=max_bytes,
                    _active=active,
                    _state=state,
                    _depth=_depth + 1,
                )
        except (TypeError, ValueError, RuntimeError) as error:
            if isinstance(error, CatalogError):
                raise
            raise CatalogError(f"{label} could not be traversed safely") from error
        finally:
            active.remove(identity)
    else:
        raise CatalogError(f"{label} contains a value that is not JSON-compatible")
    if state[0] > max_bytes:
        raise CatalogError(f"{label} exceeds the {max_bytes}-byte bound")


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CatalogError(f"value is not canonical JSON: {error}") from error


def canonical_sha256(value: Any) -> str:
    """Return the lowercase SHA-256 of deterministic compact JSON ``value``."""

    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _text(value: Any, label: str, *, max_bytes: int = MAX_CATALOG_TEXT_BYTES) -> str:
    if not isinstance(value, str):
        raise CatalogError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized:
        raise CatalogError(f"{label} must be a non-empty string")
    try:
        encoded = normalized.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise CatalogError(f"{label} is not valid UTF-8") from error
    if len(encoded) > max_bytes:
        raise CatalogError(f"{label} exceeds {max_bytes} UTF-8 bytes")
    if any(ord(character) < 0x20 for character in normalized):
        raise CatalogError(f"{label} contains a control character")
    return normalized


def _nullable_text(
    value: Any,
    label: str,
    *,
    max_bytes: int = MAX_CATALOG_TEXT_BYTES,
) -> str | None:
    if value is None:
        return None
    return _text(value, label, max_bytes=max_bytes)


def _integer(value: Any, label: str, *, minimum: int = 0, maximum: int = MAX_CATALOG_TIMESTAMP) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CatalogError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise CatalogError(f"{label} must be between {minimum} and {maximum}")
    return value


def _https_url(value: Any, label: str) -> str | None:
    if value is None:
        return None
    result = _text(value, label)
    parsed = urlsplit(result)
    try:
        # Force validation of malformed bracketed hosts/ports that urlsplit
        # defers until the corresponding properties are read.
        hostname = parsed.hostname
        parsed.port
    except ValueError as error:
        raise CatalogError(f"{label} must be null or an HTTPS URL") from error
    if (
        parsed.scheme.lower() != "https"
        or not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise CatalogError(f"{label} must be null or an HTTPS URL without userinfo")
    return result


@dataclass(frozen=True)
class CatalogPart:
    """A normalized vendor-neutral catalog part.

    The first eight fields retain the legacy positional constructor.  The
    supplier part number is appended so existing connectors and tests remain
    source-compatible while strict snapshots can retain that identifier.
    """

    mpn: str
    description: str
    footprint: str
    tags: tuple[str, ...] = ()
    vendor: str = ""
    stock: int = 0
    basic: bool = False
    datasheet_url: str | None = ""
    supplier_part_number: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CatalogPart":
        """Parse the permissive legacy catalog-part shape.

        Strict snapshots use :func:`_snapshot_part`; this method deliberately
        keeps the old defaults (notably missing tags/vendor/stock) for callers
        that still inject a list directly into the SKiDL selector.
        """

        required = {"mpn", "description", "footprint"}
        missing = required - value.keys()
        if missing:
            raise CatalogError(f"catalog part is missing {sorted(missing)}")
        tags = value.get("tags", ())
        if isinstance(tags, str) or not isinstance(tags, (list, tuple)):
            raise CatalogError("catalog part tags must be an array of strings")
        if len(tags) > MAX_CATALOG_TAGS:
            raise CatalogError(
                f"catalog part tags must contain at most {MAX_CATALOG_TAGS} strings"
            )
        if not all(
            _bounded_legacy_catalog_text(
                tag,
                max_bytes=MAX_CATALOG_TAG_BYTES,
                required=True,
            )
            for tag in tags
        ):
            raise CatalogError("catalog part tags must contain bounded non-empty strings")
        stock = value.get("stock", 0)
        if isinstance(stock, bool) or not isinstance(stock, int) or stock < 0:
            raise CatalogError("catalog part stock must be a non-negative integer")
        basic = value.get("basic", False)
        if not isinstance(basic, bool):
            raise CatalogError("catalog part basic must be a boolean")
        fields: dict[str, Any] = {
            "mpn": value["mpn"],
            "description": value["description"],
            "footprint": value["footprint"],
            "tags": tuple(tags),
            "vendor": value.get("vendor", ""),
            "stock": stock,
            "basic": basic,
            "datasheet_url": value.get("datasheet_url", ""),
            "supplier_part_number": value.get("supplier_part_number"),
        }
        if not all(
            isinstance(fields[key], str) and fields[key].strip()
            for key in ("mpn", "description", "footprint")
        ):
            raise CatalogError("catalog part identity fields must be non-empty strings")
        if not isinstance(fields["vendor"], str):
            raise CatalogError("catalog part vendor must be a string")
        if fields["datasheet_url"] is not None and not isinstance(
            fields["datasheet_url"], str
        ):
            raise CatalogError("catalog part datasheet_url must be a string or null")
        if fields["supplier_part_number"] is not None and not isinstance(
            fields["supplier_part_number"], str
        ):
            raise CatalogError("catalog part supplier_part_number must be a string or null")
        candidate = cls(**fields)
        # ``from_mapping`` is public and is also used by legacy callers that
        # bypass the JSON-array adapter.  Apply the same bounded field checks
        # before returning so a direct call cannot smuggle an oversized or
        # unsafe value into ``search_parts``.
        if not _validate_legacy_catalog_part(candidate):
            raise CatalogError("catalog part contains an invalid bounded field")
        return candidate

    def to_mapping(self) -> dict[str, Any]:
        """Return the exact nine-key snapshot representation."""

        return {
            "mpn": self.mpn,
            "supplier_part_number": self.supplier_part_number,
            "description": self.description,
            "footprint": self.footprint,
            "tags": list(self.tags),
            "vendor": self.vendor,
            "stock": self.stock,
            "basic": self.basic,
            "datasheet_url": self.datasheet_url if self.datasheet_url else None,
        }


def _bounded_legacy_catalog_text(
    value: Any,
    *,
    max_bytes: int,
    required: bool,
) -> bool:
    """Check one permissive legacy field without copying unbounded text."""

    if not isinstance(value, str):
        return False
    # Reject an obviously oversized Python string before encoding or placing
    # it in a search haystack.  UTF-8 bytes are checked as the authoritative
    # bound below because non-ASCII code points may occupy multiple bytes.
    if len(value) > max_bytes:
        return False
    normalized = value.strip()
    if required and not normalized:
        return False
    if not required and not normalized and value != "":
        return False
    try:
        if len(normalized.encode("utf-8", errors="strict")) > max_bytes:
            return False
    except UnicodeEncodeError:
        return False
    # Preserve the legacy constructor's acceptance of surrounding whitespace,
    # while rejecting embedded control characters in the normalized value.
    return not any(ord(character) < 0x20 for character in normalized)


def _valid_legacy_datasheet(value: Any) -> bool:
    """Validate optional legacy datasheets while retaining empty defaults."""

    if value is None or value == "":
        return True
    if not _bounded_legacy_catalog_text(
        value,
        max_bytes=MAX_CATALOG_TEXT_BYTES,
        required=True,
    ):
        return False
    normalized = value.strip()
    try:
        parsed = urlsplit(normalized)
        hostname = parsed.hostname
        # Force validation of malformed bracketed hosts and ports.
        parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.casefold() == "https"
        and bool(parsed.netloc)
        and bool(hostname)
        and parsed.username is None
        and parsed.password is None
    )


def _validate_legacy_catalog_part(candidate: Any) -> bool:
    """Apply bounded legacy validation to a directly injected part."""

    if not isinstance(candidate, CatalogPart):
        return False
    if not all(
        _bounded_legacy_catalog_text(
            value,
            max_bytes=MAX_CATALOG_TEXT_BYTES,
            required=True,
        )
        for value in (candidate.mpn, candidate.description, candidate.footprint)
    ):
        return False
    if not isinstance(candidate.tags, tuple) or len(candidate.tags) > MAX_CATALOG_TAGS:
        return False
    if not all(
        _bounded_legacy_catalog_text(
            tag,
            max_bytes=MAX_CATALOG_TAG_BYTES,
            required=True,
        )
        for tag in candidate.tags
    ):
        return False
    if not _bounded_legacy_catalog_text(
        candidate.vendor,
        max_bytes=MAX_CATALOG_TEXT_BYTES,
        required=False,
    ):
        return False
    if not _valid_legacy_datasheet(candidate.datasheet_url):
        return False
    supplier_part_number = getattr(candidate, "supplier_part_number", None)
    if supplier_part_number is not None and not _bounded_legacy_catalog_text(
        supplier_part_number,
        max_bytes=MAX_CATALOG_TEXT_BYTES,
        required=False,
    ):
        return False
    return not (
        isinstance(candidate.stock, bool)
        or not isinstance(candidate.stock, int)
        or candidate.stock < 0
        or candidate.stock > MAX_CATALOG_STOCK
        or not isinstance(candidate.basic, bool)
    )


def _bounded_legacy_mapping_part(value: Mapping[str, Any]) -> CatalogPart:
    """Parse one legacy mapping only after checking collection/field bounds."""

    required = ("mpn", "description", "footprint")
    if not all(
        _bounded_legacy_catalog_text(
            value.get(key),
            max_bytes=MAX_CATALOG_TEXT_BYTES,
            required=True,
        )
        for key in required
    ):
        raise CatalogError("catalog part contains an invalid bounded text field")
    tags = value.get("tags", ())
    if isinstance(tags, str) or not isinstance(tags, (list, tuple)):
        raise CatalogError("catalog part tags must be an array of strings")
    if len(tags) > MAX_CATALOG_TAGS:
        raise CatalogError(
            f"catalog part tags must contain at most {MAX_CATALOG_TAGS} strings"
        )
    if not all(
        _bounded_legacy_catalog_text(
            tag,
            max_bytes=MAX_CATALOG_TAG_BYTES,
            required=True,
        )
        for tag in tags
    ):
        raise CatalogError("catalog part tags contain an invalid bounded text field")
    if not _bounded_legacy_catalog_text(
        value.get("vendor", ""),
        max_bytes=MAX_CATALOG_TEXT_BYTES,
        required=False,
    ):
        raise CatalogError("catalog part vendor is invalid or oversized")
    supplier_part_number = value.get("supplier_part_number")
    if supplier_part_number is not None and not _bounded_legacy_catalog_text(
        supplier_part_number,
        max_bytes=MAX_CATALOG_TEXT_BYTES,
        required=False,
    ):
        raise CatalogError("catalog part supplier_part_number is invalid or oversized")
    if not _valid_legacy_datasheet(value.get("datasheet_url", "")):
        raise CatalogError("catalog part datasheet_url is invalid or unsafe")
    stock = value.get("stock", 0)
    if (
        isinstance(stock, bool)
        or not isinstance(stock, int)
        or stock < 0
        or stock > MAX_CATALOG_STOCK
    ):
        raise CatalogError("catalog part stock is outside its bounded range")
    basic = value.get("basic", False)
    if not isinstance(basic, bool):
        raise CatalogError("catalog part basic must be a boolean")
    try:
        candidate = CatalogPart.from_mapping(value)
    except (CatalogError, TypeError, ValueError) as error:
        if isinstance(error, CatalogError):
            raise
        raise CatalogError(f"catalog part mapping is invalid: {error}") from error
    if not _validate_legacy_catalog_part(candidate):
        raise CatalogError("catalog part contains an invalid bounded field")
    return candidate


def _coerce_legacy_catalog_parts(catalog: Iterable[Any]) -> list[CatalogPart]:
    """Consume a legacy catalog with one-over count protection."""

    try:
        iterator = iter(catalog)
    except TypeError as error:
        raise CatalogError("catalog must be an iterable of CatalogPart values") from error
    parts: list[CatalogPart] = []
    seen_mpns: set[str] = set()
    for index in range(MAX_CATALOG_PARTS + 1):
        try:
            item = next(iterator)
        except StopIteration:
            break
        if index >= MAX_CATALOG_PARTS:
            raise CatalogError(
                f"catalog contains more than {MAX_CATALOG_PARTS} parts"
            )
        if isinstance(item, CatalogPart):
            candidate = item
            if not _validate_legacy_catalog_part(candidate):
                raise CatalogError("catalog contains an invalid CatalogPart value")
        elif isinstance(item, Mapping):
            candidate = _bounded_legacy_mapping_part(item)
        else:
            raise CatalogError("catalog must contain only CatalogPart values")
        folded = candidate.mpn.casefold()
        if folded in seen_mpns:
            raise CatalogError("catalog contains duplicate MPNs (case-insensitive)")
        seen_mpns.add(folded)
        parts.append(candidate)
    return parts


@dataclass(frozen=True)
class CatalogSnapshot:
    """An immutable normalized catalog snapshot and its retained source bytes."""

    supplier: str
    snapshot_id: str
    captured_at_unix: int
    expires_at_unix: int
    evaluated_at_unix: int
    parts: tuple[CatalogPart, ...]
    source_kind: str
    source_name: str | None
    source_bytes: int
    source_sha256: str
    catalog_sha256: str
    normalized: Mapping[str, Any]
    _raw_bytes: bytes = field(repr=False, compare=False)

    @property
    def raw_bytes(self) -> bytes:
        """Return retained source bytes (never included in a receipt)."""

        return self._raw_bytes

    @property
    def raw_sha256(self) -> str:
        return self.source_sha256

    @property
    def normalized_catalog_sha256(self) -> str:
        return self.catalog_sha256

    @property
    def normalized_sha256(self) -> str:
        return self.catalog_sha256

    @property
    def source(self) -> dict[str, Any]:
        return {
            "kind": self.source_kind,
            "name": self.source_name,
            "bytes": self.source_bytes,
            "sha256": self.source_sha256,
        }

    @property
    def catalog(self) -> dict[str, Any]:
        return {"parts": len(self.parts), "sha256": self.catalog_sha256}

    def to_mapping(self) -> dict[str, Any]:
        return copy.deepcopy(dict(self.normalized))

    @property
    def normalized_parts(self) -> tuple[dict[str, Any], ...]:
        return tuple(copy.deepcopy(part) for part in self.normalized["parts"])

    def __len__(self) -> int:
        return len(self.parts)

    def __iter__(self):
        return iter(self.parts)

    def __getitem__(self, index: int | str) -> CatalogPart | Any:
        if isinstance(index, str):
            return self.normalized[index]
        return self.parts[index]


def _snapshot_part(value: Any, index: int) -> tuple[CatalogPart, dict[str, Any]]:
    if not isinstance(value, Mapping):
        raise CatalogError(f"catalog part at index {index} must be an object")
    expected = {
        "mpn",
        "supplier_part_number",
        "description",
        "footprint",
        "tags",
        "vendor",
        "stock",
        "basic",
        "datasheet_url",
    }
    keys = set(value)
    if keys != expected:
        unknown = sorted(keys - expected, key=repr)
        missing = sorted(expected - keys, key=repr)
        detail = []
        if missing:
            detail.append(f"missing {missing}")
        if unknown:
            detail.append(f"unknown {unknown}")
        raise CatalogError(f"catalog part at index {index} has invalid fields ({'; '.join(detail)})")
    mpn = _text(value["mpn"], f"catalog part {index} mpn")
    supplier_part_number = _nullable_text(
        value["supplier_part_number"], f"catalog part {index} supplier_part_number"
    )
    description = _text(value["description"], f"catalog part {index} description")
    footprint = _text(value["footprint"], f"catalog part {index} footprint")
    tags_value = value["tags"]
    if not isinstance(tags_value, list) or len(tags_value) > MAX_CATALOG_TAGS:
        raise CatalogError(
            f"catalog part {index} tags must be an array of at most {MAX_CATALOG_TAGS} strings"
        )
    tags: list[str] = []
    for tag_index, tag in enumerate(tags_value):
        normalized_tag = _text(
            tag,
            f"catalog part {index} tag {tag_index}",
            max_bytes=MAX_CATALOG_TAG_BYTES,
        )
        tags.append(normalized_tag)
    tags.sort(key=lambda item: (item.casefold(), item))
    vendor = _text(value["vendor"], f"catalog part {index} vendor")
    stock = _integer(
        value["stock"],
        f"catalog part {index} stock",
        maximum=MAX_CATALOG_STOCK,
    )
    basic = value["basic"]
    if not isinstance(basic, bool):
        raise CatalogError(f"catalog part {index} basic must be a boolean")
    datasheet_url = _https_url(value["datasheet_url"], f"catalog part {index} datasheet_url")
    part = CatalogPart(
        mpn=mpn,
        description=description,
        footprint=footprint,
        tags=tuple(tags),
        vendor=vendor,
        stock=stock,
        basic=basic,
        datasheet_url=datasheet_url,
        supplier_part_number=supplier_part_number,
    )
    return part, part.to_mapping()


def _coerce_catalog_source(
    source: Any,
) -> tuple[bytes, str, str | None]:
    """Return exact source bytes and a secret/path-free source descriptor."""

    def encode_text(value: str) -> bytes:
        try:
            return value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise CatalogError("catalog snapshot source is not valid UTF-8") from error

    source_kind = "injected"
    source_name: str | None = None
    if isinstance(source, Path):
        source_kind = "file"
        source_name = source.name or None
        try:
            from .bounded_io import read_bytes

            raw = read_bytes(source, max_bytes=MAX_CATALOG_RAW_BYTES)
        except (OSError, ValueError) as error:
            raise CatalogError(f"unable to read catalog snapshot: {error}") from error
    elif isinstance(source, str):
        candidate = source.lstrip()
        if _JSON_START.match(candidate):
            raw = encode_text(source)
        else:
            path = Path(source)
            source_kind = "file"
            source_name = path.name or None
            try:
                from .bounded_io import read_bytes

                raw = read_bytes(path, max_bytes=MAX_CATALOG_RAW_BYTES)
            except (OSError, ValueError) as error:
                raise CatalogError(f"unable to read catalog snapshot: {error}") from error
    elif isinstance(source, (bytes, bytearray, memoryview)):
        raw = bytes(source)
    elif isinstance(source, Mapping):
        _preflight_json_value(
            source,
            label="catalog snapshot mapping",
            max_bytes=MAX_CATALOG_RAW_BYTES,
        )
        raw = _canonical_json(source)
    elif isinstance(source, os.PathLike):
        path = Path(source)
        source_kind = "file"
        source_name = path.name or None
        try:
            from .bounded_io import read_bytes

            raw = read_bytes(path, max_bytes=MAX_CATALOG_RAW_BYTES)
        except (OSError, ValueError) as error:
            raise CatalogError(f"unable to read catalog snapshot: {error}") from error
    else:
        raise CatalogError("catalog snapshot source must be a path, UTF-8 JSON, bytes, or object")
    if not raw:
        raise CatalogError("catalog snapshot source must not be empty")
    if len(raw) > MAX_CATALOG_RAW_BYTES:
        raise CatalogError(f"catalog snapshot exceeds {MAX_CATALOG_RAW_BYTES} bytes")
    return raw, source_kind, source_name


def _decode_snapshot(raw: bytes) -> Mapping[str, Any]:
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJSONKey, ValueError) as error:
        raise CatalogError(f"catalog snapshot is not valid JSON: {error}") from error
    if not isinstance(value, Mapping):
        raise CatalogError("catalog snapshot must be a JSON object")
    return value


def load_catalog(
    source: Any,
    *,
    evaluated_at_unix: int | None = None,
) -> CatalogSnapshot:
    """Load and validate one closed catalog snapshot.

    ``source`` may be a :class:`~pathlib.Path`, UTF-8 JSON text/bytes, or an
    injected mapping.  File names are reduced to basenames before appearing in
    receipts; no path or credential is retained there.
    """

    if isinstance(source, CatalogSnapshot):
        if evaluated_at_unix is None or evaluated_at_unix == source.evaluated_at_unix:
            return source
        evaluated = _integer(evaluated_at_unix, "catalog evaluated_at_unix")
        if not source.captured_at_unix <= evaluated <= source.expires_at_unix:
            raise CatalogError(
                "catalog evaluated_at_unix must lie within capture and expiry"
            )
        return replace(source, evaluated_at_unix=evaluated)
    raw, source_kind, source_name = _coerce_catalog_source(source)
    value = _decode_snapshot(raw)
    expected = {
        "schema_version",
        "supplier",
        "snapshot_id",
        "captured_at_unix",
        "expires_at_unix",
        "parts",
    }
    keys = set(value)
    if keys != expected:
        unknown = sorted(keys - expected, key=repr)
        missing = sorted(expected - keys, key=repr)
        detail = []
        if missing:
            detail.append(f"missing {missing}")
        if unknown:
            detail.append(f"unknown {unknown}")
        raise CatalogError(f"catalog snapshot has invalid fields ({'; '.join(detail)})")
    schema_version = value["schema_version"]
    if isinstance(schema_version, bool) or schema_version != SNAPSHOT_SCHEMA_VERSION:
        raise CatalogError(f"unsupported catalog snapshot schema version {schema_version!r}")
    supplier = _text(value["supplier"], "catalog supplier", max_bytes=64)
    if supplier != supplier.casefold() or _SUPPLIER_RE.fullmatch(supplier) is None:
        raise CatalogError("catalog supplier must be lowercase safe ASCII")
    snapshot_id = _text(value["snapshot_id"], "catalog snapshot_id", max_bytes=MAX_CATALOG_ID_BYTES)
    if _SNAPSHOT_ID_RE.fullmatch(snapshot_id) is None or snapshot_id in {".", ".."}:
        raise CatalogError("catalog snapshot_id contains unsafe characters")
    captured = _integer(value["captured_at_unix"], "catalog captured_at_unix")
    expires = _integer(value["expires_at_unix"], "catalog expires_at_unix")
    if expires < captured:
        raise CatalogError("catalog expires_at_unix must be at or after captured_at_unix")
    if expires - captured > MAX_CATALOG_TTL_SECONDS:
        raise CatalogError("catalog snapshot TTL must be at most seven days")
    evaluated = int(time.time()) if evaluated_at_unix is None else evaluated_at_unix
    evaluated = _integer(evaluated, "catalog evaluated_at_unix")
    if evaluated < captured or evaluated > expires:
        raise CatalogError("catalog evaluated_at_unix must lie within capture and expiry")
    raw_parts = value["parts"]
    if not isinstance(raw_parts, list):
        raise CatalogError("catalog snapshot parts must be an array")
    if len(raw_parts) > MAX_CATALOG_PARTS:
        raise CatalogError(f"catalog snapshot contains more than {MAX_CATALOG_PARTS} parts")
    parsed: list[tuple[CatalogPart, dict[str, Any]]] = []
    seen_mpns: set[str] = set()
    for index, raw_part in enumerate(raw_parts):
        part, normalized_part = _snapshot_part(raw_part, index)
        folded = part.mpn.casefold()
        if folded in seen_mpns:
            raise CatalogError("catalog snapshot contains duplicate MPNs (case-insensitive)")
        seen_mpns.add(folded)
        parsed.append((part, normalized_part))
    parsed.sort(key=lambda item: (item[0].mpn.casefold(), item[0].mpn))
    parts = tuple(part for part, _ in parsed)
    normalized_parts = [normalized for _, normalized in parsed]
    normalized = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "supplier": supplier,
        "snapshot_id": snapshot_id,
        "captured_at_unix": captured,
        "expires_at_unix": expires,
        "parts": normalized_parts,
    }
    return CatalogSnapshot(
        supplier=supplier,
        snapshot_id=snapshot_id,
        captured_at_unix=captured,
        expires_at_unix=expires,
        evaluated_at_unix=evaluated,
        parts=parts,
        source_kind=source_kind,
        source_name=source_name,
        source_bytes=len(raw),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        catalog_sha256=canonical_sha256(normalized_parts),
        normalized=normalized,
        _raw_bytes=raw,
    )


def load_catalog_snapshot(
    source: Any,
    *,
    evaluated_at_unix: int | None = None,
) -> CatalogSnapshot:
    """Explicit v1 name for :func:`load_catalog` used by the secure adapter."""

    return load_catalog(source, evaluated_at_unix=evaluated_at_unix)


def search_parts(
    catalog: Iterable[CatalogPart],
    query: str,
    *,
    footprint: str | None = None,
    limit: int = 10,
    require_available: bool = False,
    require_basic: bool = False,
) -> list[CatalogPart]:
    """Search an injected catalog with deterministic manufacturing filters."""

    for name, value in (
        ("require_available", require_available),
        ("require_basic", require_basic),
    ):
        if not isinstance(value, bool):
            raise CatalogError(f"{name} must be a boolean")
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or limit < 0
        or limit > MAX_CATALOG_PARTS
    ):
        raise CatalogError(
            f"limit must be an integer between 0 and {MAX_CATALOG_PARTS}"
        )
    if not isinstance(query, str):
        raise CatalogError("query must be a string")
    if len(query) > MAX_CATALOG_QUERY_BYTES:
        raise CatalogError(
            f"query exceeds {MAX_CATALOG_QUERY_BYTES} UTF-8 bytes"
        )
    try:
        query_bytes = len(query.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as error:
        raise CatalogError("query is not valid UTF-8") from error
    if query_bytes > MAX_CATALOG_QUERY_BYTES:
        raise CatalogError(
            f"query exceeds {MAX_CATALOG_QUERY_BYTES} UTF-8 bytes"
        )
    if any(ord(character) < 0x20 for character in query):
        raise CatalogError("query contains a control character")
    raw_tokens = [token for token in query.split() if token]
    if len(raw_tokens) > MAX_CATALOG_QUERY_TOKENS:
        raise CatalogError(
            f"query contains more than {MAX_CATALOG_QUERY_TOKENS} tokens"
        )
    words = {word.casefold() for word in raw_tokens}
    if footprint is not None:
        if not isinstance(footprint, str):
            raise CatalogError("footprint must be a string or null")
        if len(footprint) > MAX_CATALOG_TEXT_BYTES:
            raise CatalogError(
                f"footprint exceeds {MAX_CATALOG_TEXT_BYTES} UTF-8 bytes"
            )
        try:
            footprint_bytes = len(footprint.encode("utf-8", errors="strict"))
        except UnicodeEncodeError as error:
            raise CatalogError("footprint is not valid UTF-8") from error
        if footprint_bytes > MAX_CATALOG_TEXT_BYTES:
            raise CatalogError(
                f"footprint exceeds {MAX_CATALOG_TEXT_BYTES} UTF-8 bytes"
            )
        if any(ord(character) < 0x20 for character in footprint):
            raise CatalogError("footprint contains a control character")

    catalog_parts = _coerce_legacy_catalog_parts(catalog)
    selection_work = len(catalog_parts) * (1 + len(words)) + query_bytes
    if selection_work > MAX_CATALOG_SELECTION_WORK:
        raise CatalogError("catalog selection exceeds its deterministic work limit")
    scored: list[tuple[int, int, int, str, CatalogPart]] = []
    for part in catalog_parts:
        if footprint and part.footprint != footprint:
            continue
        if require_available and part.stock <= 0:
            continue
        if require_basic and not part.basic:
            continue
        haystack = " ".join(
            value
            for value in (
                part.mpn,
                part.supplier_part_number or "",
                part.description,
                *part.tags,
            )
            if value
        ).casefold()
        score = sum(word in haystack for word in words)
        if not words or score:
            scored.append((-score, -int(part.stock > 0), -int(part.basic), part.mpn, part))
    scored.sort(key=lambda item: item[:-1])
    return [part for *_, part in scored[:limit]]


def catalog_parts_from_json(value: Any) -> list[CatalogPart]:
    """Validate a legacy vendor-neutral JSON catalog array."""

    if not isinstance(value, list):
        raise CatalogError("catalog JSON must be an array")
    try:
        count = len(value)
    except (TypeError, ValueError, RuntimeError) as error:
        raise CatalogError("catalog JSON array length is not safe") from error
    if count > MAX_CATALOG_PARTS:
        raise CatalogError(
            f"catalog JSON contains more than {MAX_CATALOG_PARTS} parts"
        )
    parts: list[CatalogPart] = []
    seen_mpns: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise CatalogError(f"catalog part at index {index} must be an object")
        part = _bounded_legacy_mapping_part(item)
        folded = part.mpn.casefold()
        if folded in seen_mpns:
            raise CatalogError("catalog JSON contains duplicate MPNs")
        seen_mpns.add(folded)
        parts.append(part)
    return parts


def _spec_digest(value: Mapping[str, Any]) -> str:
    return canonical_sha256(value)


def _part_query(part: Mapping[str, Any]) -> str:
    values: list[str] = []
    for key in ("value", "description", "lib_id", "tags", "keywords"):
        candidate = part.get(key)
        if isinstance(candidate, str):
            values.append(candidate)
        elif isinstance(candidate, (list, tuple)):
            values.extend(item for item in candidate if isinstance(item, str))
    return " ".join(values)


def _query_plan(part: Mapping[str, Any], label: str) -> tuple[tuple[str, ...], int]:
    query = _part_query(part)
    try:
        query_bytes = len(query.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as error:
        raise CatalogError(f"{label} query is not valid UTF-8") from error
    if query_bytes > MAX_CATALOG_QUERY_BYTES:
        raise CatalogError(
            f"{label} query exceeds {MAX_CATALOG_QUERY_BYTES} UTF-8 bytes"
        )
    raw_tokens = [token.casefold() for token in query.split() if token]
    if len(raw_tokens) > MAX_CATALOG_QUERY_TOKENS:
        raise CatalogError(
            f"{label} query contains more than {MAX_CATALOG_QUERY_TOKENS} tokens"
        )
    # Duplicate tokens do not add score, but the raw count above is bounded so
    # adversarial repetition cannot bypass the query-work budget.
    return tuple(sorted(set(raw_tokens))), query_bytes


def _part_footprint(part: Mapping[str, Any], reference: str) -> str:
    value = part.get("footprint")
    if not isinstance(value, str) or not value.strip():
        raise CatalogError(f"{reference} footprint must be a non-empty string")
    return value.strip()


def _spec_text(value: Any, label: str, maximum: int) -> str:
    text = _text(value, label, max_bytes=maximum)
    if text != value:
        raise CatalogError(f"{label} must be normalized")
    if any(0x7F <= ord(character) <= 0x9F for character in text):
        raise CatalogError(f"{label} must not contain control characters")
    return text


def _spec_identifier(value: Any, label: str, maximum: int, pattern: re.Pattern[str]) -> str:
    text = _spec_text(value, label, maximum)
    if pattern.fullmatch(text) is None:
        raise CatalogError(f"{label} contains unsupported identifier characters")
    return text


def _spec_optional_integer(value: Any, label: str) -> None:
    if value is not None:
        _integer(value, label, minimum=0, maximum=MAX_SPEC_VOLTAGE)


def _preflight_spec(value: Mapping[str, Any]) -> None:
    """Validate the closed native v2 shape before copying an injected graph."""

    if not isinstance(value, Mapping):
        raise CatalogError("circuit spec must be an object")
    _preflight_json_value(value, label="circuit spec", max_bytes=MAX_SPEC_BYTES)
    if set(value) != {"schema_version", "parts", "nets"}:
        raise CatalogError(
            "circuit spec must contain exactly schema_version, parts, and nets"
        )
    schema_version = value.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != 2:
        raise CatalogError("circuit spec must use schema_version 2")
    raw_parts = value.get("parts")
    if not isinstance(raw_parts, list) or not raw_parts:
        raise CatalogError("circuit spec parts must be a non-empty array")
    if len(raw_parts) > MAX_SPEC_PARTS:
        raise CatalogError(f"circuit spec contains more than {MAX_SPEC_PARTS} parts")
    raw_nets = value.get("nets")
    if not isinstance(raw_nets, list) or not raw_nets:
        raise CatalogError("circuit spec nets must be a non-empty array")
    if len(raw_nets) > MAX_SPEC_NETS:
        raise CatalogError(f"circuit spec contains more than {MAX_SPEC_NETS} nets")
    seen_refs: set[str] = set()
    for index, part in enumerate(raw_parts):
        if not isinstance(part, Mapping):
            raise CatalogError(f"circuit spec part at index {index} must be an object")
        if set(part) != {"reference", "lib_id", "value", "footprint", "mpn", "power", "pins"}:
            raise CatalogError(f"circuit spec part at index {index} has unknown or missing fields")
        reference = part.get("reference")
        if not isinstance(reference, str) or not reference.strip():
            raise CatalogError(f"circuit spec part at index {index} reference must be non-empty")
        reference = _spec_identifier(
            reference,
            f"part {index} reference",
            MAX_SPEC_REFERENCE_BYTES,
            _SPEC_REFERENCE_RE,
        )
        if reference in seen_refs:
            raise CatalogError("circuit spec part references must be unique")
        seen_refs.add(reference)
        lib_id = _spec_text(part.get("lib_id"), f"{reference} lib_id", MAX_SPEC_LIB_ID_BYTES)
        if (
            lib_id.count(":") != 1
            or any(not piece for piece in lib_id.split(":", 1))
            or any(character.isspace() for character in lib_id)
        ):
            raise CatalogError(f"{reference} lib_id must contain exactly one ':'")
        _spec_text(part.get("value"), f"{reference} value", MAX_SPEC_VALUE_BYTES)
        _spec_text(part.get("footprint"), f"{reference} footprint", MAX_SPEC_FOOTPRINT_BYTES)
        mpn = part.get("mpn")
        if mpn is not None:
            _spec_text(mpn, f"{reference} mpn", MAX_SPEC_MPN_BYTES)
        power = part.get("power")
        if not isinstance(power, Mapping) or set(power) != {
            "rail_voltage_uv", "max_voltage_uv", "requires_decoupling", "decoupling"
        }:
            raise CatalogError(f"{reference} power does not match the native v2 shape")
        _spec_optional_integer(power.get("rail_voltage_uv"), f"{reference} rail_voltage_uv")
        _spec_optional_integer(power.get("max_voltage_uv"), f"{reference} max_voltage_uv")
        if not isinstance(power.get("requires_decoupling"), bool) or not isinstance(
            power.get("decoupling"), bool
        ):
            raise CatalogError(f"{reference} power flags must be booleans")
        pins = part.get("pins")
        if not isinstance(pins, list) or not pins:
            raise CatalogError(f"{reference} pins must be a non-empty array")
        if len(pins) > MAX_SPEC_PINS_PER_PART:
            raise CatalogError(f"{reference} contains too many pins")
        pin_numbers: set[str] = set()
        has_non_no_connect = False
        for pin_index, pin in enumerate(pins):
            if not isinstance(pin, Mapping) or set(pin) != {
                "number", "name", "net", "electrical_type"
            }:
                raise CatalogError(f"{reference} pin {pin_index} has an invalid shape")
            number = _spec_identifier(
                pin.get("number"),
                f"{reference} pin number",
                MAX_SPEC_PIN_NUMBER_BYTES,
                _SPEC_IDENTIFIER_RE,
            )
            if number in pin_numbers:
                raise CatalogError(f"{reference} contains duplicate pin {number}")
            pin_numbers.add(number)
            _spec_text(pin.get("name"), f"{reference} pin {number} name", MAX_SPEC_PIN_NAME_BYTES)
            net = pin.get("net")
            if net is not None:
                _spec_identifier(
                    net,
                    f"{reference}.{number} net",
                    MAX_SPEC_NET_NAME_BYTES,
                    _SPEC_IDENTIFIER_RE,
                )
            electrical_type = pin.get("electrical_type")
            if electrical_type not in _ELECTRICAL_PIN_TYPES:
                raise CatalogError(f"{reference} pin {number} has an invalid electrical_type")
            if net is None and electrical_type != "no_connect":
                raise CatalogError(f"{reference} pin {number} must declare a net")
            if net is not None and electrical_type == "no_connect":
                raise CatalogError(f"{reference} pin {number} no_connect must not declare a net")
            if electrical_type != "no_connect":
                has_non_no_connect = True
        if not has_non_no_connect:
            raise CatalogError(f"{reference} must contain a non-no-connect pin")
    seen_nets: set[str] = set()
    for index, net in enumerate(raw_nets):
        if not isinstance(net, Mapping) or set(net) != {"name", "voltage_uv", "connections"}:
            raise CatalogError(f"circuit net at index {index} has an invalid shape")
        name = _spec_identifier(
            net.get("name"), f"net {index} name", MAX_SPEC_NET_NAME_BYTES, _SPEC_IDENTIFIER_RE
        )
        if name in seen_nets:
            raise CatalogError(f"duplicate net name {name}")
        seen_nets.add(name)
        _spec_optional_integer(net.get("voltage_uv"), f"net {name} voltage_uv")
        connections = net.get("connections")
        if not isinstance(connections, list) or len(connections) < 2:
            raise CatalogError(f"net {name} must have at least two connections")
        if len(connections) > MAX_SPEC_CONNECTIONS_PER_NET:
            raise CatalogError(f"net {name} contains too many connections")
        for connection in connections:
            if not isinstance(connection, Mapping) or set(connection) != {"reference", "pin"}:
                raise CatalogError(f"net {name} has an invalid connection")
            _spec_identifier(
                connection.get("reference"),
                f"net {name} connection reference",
                MAX_SPEC_REFERENCE_BYTES,
                _SPEC_REFERENCE_RE,
            )
            _spec_identifier(
                connection.get("pin"),
                f"net {name} connection pin",
                MAX_SPEC_PIN_NUMBER_BYTES,
                _SPEC_IDENTIFIER_RE,
            )


def _generic_spec(value: Mapping[str, Any]) -> dict[str, Any]:
    _preflight_spec(value)
    result = copy.deepcopy(dict(value))
    return result


def _legacy_spec(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CatalogError("circuit spec must be an object")
    _preflight_json_value(value, label="legacy circuit spec", max_bytes=MAX_SPEC_BYTES)
    result = copy.deepcopy(dict(value))
    raw_parts = result.get("parts")
    if not isinstance(raw_parts, list) or not raw_parts:
        raise CatalogError("circuit spec parts must be a non-empty array")
    if len(raw_parts) > MAX_SPEC_PARTS:
        raise CatalogError(f"circuit spec contains more than {MAX_SPEC_PARTS} parts")
    seen_refs: set[str] = set()
    for index, part in enumerate(raw_parts):
        if not isinstance(part, Mapping):
            raise CatalogError(f"circuit spec part at index {index} must be an object")
        reference = _text(part.get("reference"), f"part {index} reference", max_bytes=MAX_SPEC_REFERENCE_BYTES)
        if reference in seen_refs:
            raise CatalogError("circuit spec part references must be unique")
        seen_refs.add(reference)
        _part_footprint(part, reference)
    return result


def _part_mapping_digest(part: CatalogPart) -> str:
    return canonical_sha256(part.to_mapping())


def _candidate_sort_key(part: CatalogPart, score: int) -> tuple[int, int, int, str, str]:
    return (
        -score,
        -int(part.stock > 0),
        -int(part.basic),
        part.mpn.casefold(),
        part.mpn,
    )


def _select_from_snapshot(
    spec: Mapping[str, Any],
    snapshot: CatalogSnapshot,
    *,
    require_available: bool,
    require_basic: bool,
    allow_footprint_fallback: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized = _generic_spec(spec)
    for flag, label in (
        (require_available, "require_available"),
        (require_basic, "require_basic"),
        (allow_footprint_fallback, "allow_footprint_fallback"),
    ):
        if not isinstance(flag, bool):
            raise CatalogError(f"{label} must be a boolean")
    if snapshot.evaluated_at_unix < snapshot.captured_at_unix or snapshot.evaluated_at_unix > snapshot.expires_at_unix:
        raise CatalogError("catalog snapshot is outside its validity window")
    by_mpn = {part.mpn.casefold(): part for part in snapshot.parts}
    parts = normalized["parts"]
    candidate_count = max(1, len(snapshot.parts))
    query_plans: dict[str, tuple[tuple[str, ...], int]] = {}
    selection_work = 0
    for part in parts:
        reference = part["reference"].strip()
        words, query_bytes = _query_plan(part, reference)
        query_plans[reference] = (words, query_bytes)
        # One deterministic charge covers the candidate comparison itself,
        # every token containment comparison, and the query bytes inspected.
        selection_work += candidate_count * (1 + len(words)) + query_bytes
    if selection_work > MAX_CATALOG_SELECTION_WORK:
        raise CatalogError(
            "catalog selection exceeds its deterministic work limit"
        )
    references = sorted((part["reference"].strip() for part in parts), key=lambda ref: (ref.casefold(), ref))
    by_ref = {part["reference"].strip(): part for part in parts}
    demand: dict[str, int] = {}
    chosen: dict[str, tuple[CatalogPart, str]] = {}

    def permitted(part: CatalogPart, footprint: str) -> bool:
        if part.footprint != footprint:
            return False
        if require_available and part.stock <= 0:
            return False
        if require_basic and not part.basic:
            return False
        return True

    # Verify explicitly requested MPNs first so implicit choices cannot consume
    # inventory reserved by a prefilled part.
    prefilled = [ref for ref in references if by_ref[ref].get("mpn") is not None]
    for reference in prefilled:
        raw_part = by_ref[reference]
        requested = raw_part["mpn"].strip()
        catalog_part = by_mpn.get(requested.casefold())
        if catalog_part is None:
            raise CatalogSelectionError(
                f"{reference} prefilled MPN {requested!r} is not in the catalog"
            )
        footprint = _part_footprint(raw_part, reference)
        if not permitted(catalog_part, footprint):
            raise CatalogSelectionError(
                f"{reference} prefilled MPN {requested!r} violates footprint or policy"
            )
        folded = catalog_part.mpn.casefold()
        demand[folded] = demand.get(folded, 0) + 1
        if require_available and demand[folded] > catalog_part.stock:
            raise CatalogSelectionError(
                f"catalog stock for MPN {catalog_part.mpn!r} is insufficient"
            )
        chosen[reference] = (catalog_part, "verified")

    for reference in references:
        if reference in chosen:
            continue
        raw_part = by_ref[reference]
        footprint = _part_footprint(raw_part, reference)
        words, _query_bytes = query_plans[reference]
        best_any: tuple[tuple[int, int, int, str, str], CatalogPart] | None = None
        best_positive: tuple[tuple[int, int, int, str, str], CatalogPart] | None = None
        exhausted: list[CatalogPart] = []
        for catalog_part in snapshot.parts:
            if not permitted(catalog_part, footprint):
                continue
            folded = catalog_part.mpn.casefold()
            if (
                require_available
                and demand.get(folded, 0) >= catalog_part.stock
            ):
                exhausted.append(catalog_part)
                continue
            haystack = " ".join(
                value
                for value in (
                    catalog_part.mpn,
                    catalog_part.supplier_part_number or "",
                    catalog_part.description,
                    *catalog_part.tags,
                )
                if value
            ).casefold()
            score = sum(word in haystack for word in words)
            candidate_key = _candidate_sort_key(catalog_part, score)
            candidate_value = (candidate_key, catalog_part)
            if best_any is None or candidate_key < best_any[0]:
                best_any = candidate_value
            if score > 0 and (best_positive is None or candidate_key < best_positive[0]):
                best_positive = candidate_value
        if best_positive is not None:
            _score_key, catalog_part = best_positive
        elif allow_footprint_fallback and best_any is not None:
            # Streaming tie-break selection avoids an O(S log S) sort; only
            # the score is zero in this branch.
            _score_key, catalog_part = best_any
        else:
            if exhausted and best_any is None:
                raise CatalogSelectionError(
                    f"catalog stock for MPN {exhausted[0].mpn!r} is insufficient"
                )
            raise CatalogSelectionError(
                f"no catalog part satisfies {reference} footprint={footprint!r}"
            )
        folded = catalog_part.mpn.casefold()
        demand[folded] = demand.get(folded, 0) + 1
        if require_available and demand[folded] > catalog_part.stock:
            raise CatalogSelectionError(
                f"catalog stock for MPN {catalog_part.mpn!r} is insufficient"
            )
        chosen[reference] = (catalog_part, "assigned")

    normalized["parts"] = [
        dict(part, mpn=chosen[part["reference"].strip()][0].mpn)
        for part in parts
    ]
    selections = [
        {
            "reference": reference,
            "status": chosen[reference][1],
            "mpn": chosen[reference][0].mpn,
            "supplier_part_number": chosen[reference][0].supplier_part_number,
            "footprint": chosen[reference][0].footprint,
            "catalog_part_sha256": _part_mapping_digest(chosen[reference][0]),
        }
        for reference in references
    ]
    policy = {
        "require_available": require_available,
        "require_basic": require_basic,
        "allow_footprint_fallback": allow_footprint_fallback,
    }
    receipt = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "adapter": RECEIPT_ADAPTER,
        "supplier": snapshot.supplier,
        "snapshot_id": snapshot.snapshot_id,
        "captured_at_unix": snapshot.captured_at_unix,
        "expires_at_unix": snapshot.expires_at_unix,
        "evaluated_at_unix": snapshot.evaluated_at_unix,
        "source": {
            "kind": snapshot.source_kind,
            "name": snapshot.source_name,
            "bytes": snapshot.source_bytes,
            "sha256": snapshot.source_sha256,
        },
        "catalog": {
            "parts": len(snapshot.parts),
            "sha256": snapshot.catalog_sha256,
        },
        "input_spec_sha256": _spec_digest(spec),
        "resolved_spec_sha256": _spec_digest(normalized),
        "policy": policy,
        "selections": selections,
        # Keep the digest field at its fixed 64-byte shape while checking the
        # aggregate receipt bound before doing the selection hash work.
        "selections_sha256": "0" * 64,
    }
    _check_receipt_canonical_size(receipt)
    receipt["selections_sha256"] = canonical_sha256(selections)
    validate_catalog_receipt_shape(receipt)
    return normalized, receipt


def select_catalog_parts(
    spec: Mapping[str, Any],
    catalog: CatalogSnapshot | Mapping[str, Any] | bytes | str | Path,
    *,
    require_available: bool = True,
    require_basic: bool = False,
    allow_footprint_fallback: bool = False,
    evaluated_at_unix: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify/assign every circuit part and return ``(resolved_spec, receipt)``."""

    _preflight_spec(spec)
    snapshot = catalog if isinstance(catalog, CatalogSnapshot) else load_catalog(
        catalog, evaluated_at_unix=evaluated_at_unix
    )
    if evaluated_at_unix is not None and snapshot.evaluated_at_unix != evaluated_at_unix:
        if not snapshot.captured_at_unix <= evaluated_at_unix <= snapshot.expires_at_unix:
            raise CatalogError("catalog evaluated_at_unix must lie within capture and expiry")
        # Keep the original source descriptor (especially a file basename)
        # when changing the evaluation instant of an already loaded snapshot.
        snapshot = replace(snapshot, evaluated_at_unix=evaluated_at_unix)
    return _select_from_snapshot(
        spec,
        snapshot,
        require_available=require_available,
        require_basic=require_basic,
        allow_footprint_fallback=allow_footprint_fallback,
    )


def assign_catalog_parts(
    spec: Mapping[str, Any],
    catalog: Any,
    *,
    require_available: bool = True,
    require_basic: bool = False,
    allow_footprint_fallback: bool = False,
    evaluated_at_unix: int | None = None,
) -> Any:
    """Compatibility wrapper for secure selection and the legacy list API.

    A strict snapshot/source returns ``(resolved_spec, receipt)``.  A legacy
    list of :class:`CatalogPart` values keeps the historical spec-only return
    and footprint fallback behavior; callers should migrate to
    :func:`select_catalog_parts` for receipt-bound selection.
    """

    for name, value in (
        ("require_available", require_available),
        ("require_basic", require_basic),
        ("allow_footprint_fallback", allow_footprint_fallback),
    ):
        if not isinstance(value, bool):
            raise CatalogError(f"{name} must be a boolean")
    if isinstance(catalog, (list, tuple)):
        # The legacy list remains receipt-free, but it must use exactly the
        # same v1 validation, prefilled checks, and inventory reservation as
        # the public SKiDL adapter.  Import locally to avoid catalog/skidl's
        # module-level cycle.
        available = _coerce_legacy_catalog_parts(catalog)
        from .skidl import CircuitSpecError, assign_catalog_parts as _assign_skidl

        try:
            return _assign_skidl(
                spec,
                available,
                require_available=require_available,
                require_basic=require_basic,
                allow_footprint_fallback=allow_footprint_fallback,
            )
        except CircuitSpecError as error:
            # Preserve catalog.py's established exception family while
            # retaining the hardened adapter's exact validation semantics.
            raise CatalogError(str(error)) from error
    return select_catalog_parts(
        spec,
        catalog,
        require_available=require_available,
        require_basic=require_basic,
        allow_footprint_fallback=allow_footprint_fallback,
        evaluated_at_unix=evaluated_at_unix,
    )


def _valid_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise CatalogError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _check_receipt_canonical_size(receipt: Mapping[str, Any]) -> int:
    encoded = _canonical_json(receipt)
    if len(encoded) > MAX_CATALOG_RECEIPT_BYTES:
        raise CatalogError(
            f"catalog receipt exceeds {MAX_CATALOG_RECEIPT_BYTES} canonical bytes"
        )
    return len(encoded)


def validate_catalog_receipt_shape(receipt: Any) -> dict[str, Any]:
    """Validate the closed receipt shape and recompute its selection digest."""

    expected = {
        "schema_version",
        "adapter",
        "supplier",
        "snapshot_id",
        "captured_at_unix",
        "expires_at_unix",
        "evaluated_at_unix",
        "source",
        "catalog",
        "input_spec_sha256",
        "resolved_spec_sha256",
        "policy",
        "selections",
        "selections_sha256",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != expected:
        raise CatalogError("catalog receipt does not match the closed shape")
    if (
        isinstance(receipt["schema_version"], bool)
        or receipt["schema_version"] != RECEIPT_SCHEMA_VERSION
        or receipt["adapter"] != RECEIPT_ADAPTER
    ):
        raise CatalogError("catalog receipt has an unsupported adapter or schema version")
    def canonical_text(value: Any, label: str, *, max_bytes: int = MAX_CATALOG_TEXT_BYTES) -> str:
        normalized = _text(value, label, max_bytes=max_bytes)
        if normalized != value:
            raise CatalogError(f"{label} must be normalized")
        return normalized

    supplier = canonical_text(receipt["supplier"], "receipt supplier", max_bytes=64)
    if supplier != supplier.casefold() or _SUPPLIER_RE.fullmatch(supplier) is None:
        raise CatalogError("receipt supplier must be lowercase safe ASCII")
    snapshot_id = canonical_text(
        receipt["snapshot_id"], "receipt snapshot_id", max_bytes=MAX_CATALOG_ID_BYTES
    )
    if _SNAPSHOT_ID_RE.fullmatch(snapshot_id) is None:
        raise CatalogError("receipt snapshot_id contains unsafe characters")
    captured = _integer(receipt["captured_at_unix"], "receipt captured_at_unix")
    expires = _integer(receipt["expires_at_unix"], "receipt expires_at_unix")
    evaluated = _integer(receipt["evaluated_at_unix"], "receipt evaluated_at_unix")
    if expires < captured or expires - captured > MAX_CATALOG_TTL_SECONDS or not captured <= evaluated <= expires:
        raise CatalogError("receipt timestamps are outside the snapshot validity window")
    source = receipt["source"]
    if not isinstance(source, Mapping) or set(source) != {"kind", "name", "bytes", "sha256"}:
        raise CatalogError("receipt source does not match the closed shape")
    if source["kind"] not in {"file", "injected"}:
        raise CatalogError("receipt source kind is invalid")
    if source["name"] is not None:
        name = canonical_text(
            source["name"], "receipt source name", max_bytes=MAX_CATALOG_ID_BYTES
        )
        if "/" in name or "\\" in name or name in {".", ".."}:
            raise CatalogError("receipt source name must be a basename")
    elif source["kind"] == "file":
        raise CatalogError("file receipt sources must retain a basename")
    if source["kind"] == "injected" and source["name"] is not None:
        raise CatalogError("injected receipt sources must not retain a path or name")
    _integer(source["bytes"], "receipt source bytes", minimum=1, maximum=MAX_CATALOG_RAW_BYTES)
    _valid_sha(source["sha256"], "receipt source sha256")
    catalog = receipt["catalog"]
    if not isinstance(catalog, Mapping) or set(catalog) != {"parts", "sha256"}:
        raise CatalogError("receipt catalog does not match the closed shape")
    _integer(catalog["parts"], "receipt catalog parts", minimum=1, maximum=MAX_CATALOG_PARTS)
    _valid_sha(catalog["sha256"], "receipt catalog sha256")
    _valid_sha(receipt["input_spec_sha256"], "receipt input_spec_sha256")
    _valid_sha(receipt["resolved_spec_sha256"], "receipt resolved_spec_sha256")
    policy = receipt["policy"]
    policy_keys = {"require_available", "require_basic", "allow_footprint_fallback"}
    if not isinstance(policy, Mapping) or set(policy) != policy_keys or not all(
        isinstance(policy[key], bool) for key in policy_keys
    ):
        raise CatalogError("receipt policy does not match the closed shape")
    selections = receipt["selections"]
    if (
        not isinstance(selections, list)
        or not selections
        or len(selections) > MAX_SPEC_PARTS
    ):
        raise CatalogError(
            f"receipt selections must contain between 1 and {MAX_SPEC_PARTS} items"
        )
    seen_references: set[str] = set()
    previous_reference: tuple[str, str] | None = None
    for selection in selections:
        selection_keys = {
            "reference",
            "status",
            "mpn",
            "supplier_part_number",
            "footprint",
            "catalog_part_sha256",
        }
        if not isinstance(selection, Mapping) or set(selection) != selection_keys:
            raise CatalogError("receipt selection does not match the closed shape")
        reference = _text(
            selection["reference"],
            "receipt selection reference",
            max_bytes=MAX_SPEC_REFERENCE_BYTES,
        )
        folded_ref = (reference.casefold(), reference)
        if reference in seen_references or (previous_reference is not None and folded_ref < previous_reference):
            raise CatalogError("receipt selections must be unique and reference-sorted")
        seen_references.add(reference)
        previous_reference = folded_ref
        if selection["status"] not in {"assigned", "verified"}:
            raise CatalogError("receipt selection status is invalid")
        canonical_text(
            selection["reference"],
            "receipt selection reference",
            max_bytes=MAX_SPEC_REFERENCE_BYTES,
        )
        canonical_text(
            selection["mpn"],
            "receipt selection mpn",
            max_bytes=MAX_SPEC_MPN_BYTES,
        )
        supplier_part_number = selection["supplier_part_number"]
        if supplier_part_number is not None:
            canonical_text(supplier_part_number, "receipt selection supplier_part_number")
        canonical_text(
            selection["footprint"],
            "receipt selection footprint",
            max_bytes=MAX_SPEC_FOOTPRINT_BYTES,
        )
        _valid_sha(selection["catalog_part_sha256"], "receipt selection catalog_part_sha256")
    _valid_sha(receipt["selections_sha256"], "receipt selections_sha256")
    _check_receipt_canonical_size(receipt)
    expected_selections_sha = canonical_sha256(selections)
    if receipt["selections_sha256"] != expected_selections_sha:
        raise CatalogError("receipt selections_sha256 does not match selections")
    return dict(receipt)


def validate_catalog_receipt(
    receipt: Any,
    input_spec: Mapping[str, Any],
    resolved_spec: Mapping[str, Any],
    catalog: CatalogSnapshot | Mapping[str, Any] | bytes | str | Path,
    *,
    require_available: bool = True,
    require_basic: bool = False,
    allow_footprint_fallback: bool = False,
    evaluated_at_unix: int | None = None,
) -> dict[str, Any]:
    """Recompute and verify a receipt against input/resolved specs and snapshot.

    ``resolved_spec`` is intentionally required even though it can be derived
    from ``input_spec``.  Requiring the caller to provide the exact artifact it
    intends to generate lets this gate catch an output substitution before any
    source is emitted.
    """

    _preflight_spec(input_spec)
    _preflight_spec(resolved_spec)
    shape = validate_catalog_receipt_shape(receipt)
    if evaluated_at_unix is not None and evaluated_at_unix != shape["evaluated_at_unix"]:
        raise CatalogError("validator evaluated_at_unix does not match receipt")
    if not isinstance(require_available, bool) or not isinstance(require_basic, bool) or not isinstance(allow_footprint_fallback, bool):
        raise CatalogError("receipt policy arguments must be booleans")
    expected_policy = {
        "require_available": require_available,
        "require_basic": require_basic,
        "allow_footprint_fallback": allow_footprint_fallback,
    }
    if shape["policy"] != expected_policy:
        raise CatalogError("receipt policy does not match validator policy")
    snapshot = catalog if isinstance(catalog, CatalogSnapshot) else load_catalog(
        catalog, evaluated_at_unix=shape["evaluated_at_unix"] if evaluated_at_unix is None else evaluated_at_unix
    )
    if snapshot.evaluated_at_unix != shape["evaluated_at_unix"]:
        if not snapshot.captured_at_unix <= shape["evaluated_at_unix"] <= snapshot.expires_at_unix:
            raise CatalogError("receipt evaluated_at_unix is outside snapshot validity")
        snapshot = replace(snapshot, evaluated_at_unix=shape["evaluated_at_unix"])
    expected_spec, expected_receipt = _select_from_snapshot(
        input_spec,
        snapshot,
        require_available=require_available,
        require_basic=require_basic,
        allow_footprint_fallback=allow_footprint_fallback,
    )
    if not isinstance(resolved_spec, Mapping):
        raise CatalogError("resolved_spec must be an object")
    if dict(resolved_spec) != expected_spec:
        raise CatalogError("resolved_spec does not match recomputed selection")
    if shape != expected_receipt:
        raise CatalogError("catalog receipt does not match recomputed selection")
    return shape


def catalog_snapshot_json_schema() -> dict[str, Any]:
    """Return the closed JSON Schema for catalog snapshots."""

    nullable_catalog_text = {
        "anyOf": [
            {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_CATALOG_TEXT_BYTES,
            },
            {"type": "null"},
        ]
    }
    part_properties = {
        "mpn": {"type": "string", "minLength": 1, "maxLength": MAX_CATALOG_TEXT_BYTES},
        "supplier_part_number": nullable_catalog_text,
        "description": {"type": "string", "minLength": 1, "maxLength": MAX_CATALOG_TEXT_BYTES},
        "footprint": {"type": "string", "minLength": 1, "maxLength": MAX_CATALOG_TEXT_BYTES},
        "tags": {"type": "array", "maxItems": MAX_CATALOG_TAGS, "items": {"type": "string", "minLength": 1, "maxLength": MAX_CATALOG_TAG_BYTES}},
        "vendor": {"type": "string", "minLength": 1, "maxLength": MAX_CATALOG_TEXT_BYTES},
        "stock": {"type": "integer", "minimum": 0, "maximum": MAX_CATALOG_STOCK},
        "basic": {"type": "boolean"},
        "datasheet_url": {
            "anyOf": [
                {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_CATALOG_TEXT_BYTES,
                    "format": "uri",
                    "pattern": "^https://",
                },
                {"type": "null"},
            ]
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/catalog-snapshot-v1.json",
        "$comment": (
            "The loader additionally enforces UTF-8 byte limits, normalized "
            "text, duplicate-key rejection, HTTPS host/userinfo rules, and the "
            "capture/evaluation/expiry ordering and seven-day TTL."
        ),
        "title": "pcbex catalog snapshot v1",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "supplier", "snapshot_id", "captured_at_unix", "expires_at_unix", "parts"],
        "properties": {
            "schema_version": {"const": SNAPSHOT_SCHEMA_VERSION},
            "supplier": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$",
            },
            "snapshot_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_CATALOG_ID_BYTES,
                "pattern": "^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$",
            },
            "captured_at_unix": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_CATALOG_TIMESTAMP,
            },
            "expires_at_unix": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_CATALOG_TIMESTAMP,
            },
            "parts": {"type": "array", "maxItems": MAX_CATALOG_PARTS, "items": {"type": "object", "additionalProperties": False, "required": list(part_properties), "properties": part_properties}},
        },
    }


def catalog_receipt_json_schema() -> dict[str, Any]:
    """Return the closed JSON Schema for selection receipts."""

    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    selection = {
        "type": "object",
        "additionalProperties": False,
        "required": ["reference", "status", "mpn", "supplier_part_number", "footprint", "catalog_part_sha256"],
        "properties": {
            "reference": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_SPEC_REFERENCE_BYTES,
            },
            "status": {"enum": ["assigned", "verified"]},
            "mpn": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_SPEC_MPN_BYTES,
            },
            "supplier_part_number": {
                "anyOf": [
                    {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_CATALOG_TEXT_BYTES,
                    },
                    {"type": "null"},
                ]
            },
            "footprint": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_SPEC_FOOTPRINT_BYTES,
            },
            "catalog_part_sha256": digest,
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/catalog-selection-receipt-v1.json",
        "$comment": (
            "The receipt validator additionally enforces a 1 MiB canonical "
            "encoding, UTF-8 byte limits, normalized text, basename/source-kind "
            "correlation, timestamp/TTL semantics, reference ordering, uniqueness, "
            "and every recomputed digest binding."
        ),
        "title": "pcbex catalog selection receipt v1",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version", "adapter", "supplier", "snapshot_id",
            "captured_at_unix", "expires_at_unix", "evaluated_at_unix",
            "source", "catalog", "input_spec_sha256", "resolved_spec_sha256",
            "policy", "selections", "selections_sha256",
        ],
        "properties": {
            "schema_version": {"const": RECEIPT_SCHEMA_VERSION},
            "adapter": {"const": RECEIPT_ADAPTER},
            "supplier": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$",
            },
            "snapshot_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_CATALOG_ID_BYTES,
                "pattern": "^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$",
            },
            "captured_at_unix": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_CATALOG_TIMESTAMP,
            },
            "expires_at_unix": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_CATALOG_TIMESTAMP,
            },
            "evaluated_at_unix": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_CATALOG_TIMESTAMP,
            },
            "source": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "name", "bytes", "sha256"],
                "properties": {
                    "kind": {"enum": ["file", "injected"]},
                    "name": {
                        "anyOf": [
                            {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": MAX_CATALOG_ID_BYTES,
                                "pattern": "^[^/\\\\]+$",
                            },
                            {"type": "null"},
                        ]
                    },
                    "bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_CATALOG_RAW_BYTES,
                    },
                    "sha256": digest,
                },
                "oneOf": [
                    {
                        "properties": {
                            "kind": {"const": "file"},
                            "name": {"type": "string"},
                        }
                    },
                    {
                        "properties": {
                            "kind": {"const": "injected"},
                            "name": {"type": "null"},
                        }
                    },
                ],
            },
            "catalog": {
                "type": "object",
                "additionalProperties": False,
                "required": ["parts", "sha256"],
                "properties": {
                    "parts": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_CATALOG_PARTS,
                    },
                    "sha256": digest,
                },
            },
            "input_spec_sha256": digest,
            "resolved_spec_sha256": digest,
            "policy": {"type": "object", "additionalProperties": False, "required": ["require_available", "require_basic", "allow_footprint_fallback"], "properties": {"require_available": {"type": "boolean"}, "require_basic": {"type": "boolean"}, "allow_footprint_fallback": {"type": "boolean"}}},
            "selections": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_SPEC_PARTS,
                "uniqueItems": True,
                "items": selection,
            },
            "selections_sha256": digest,
        },
    }


# A descriptive alias used by callers that refer to the normalized catalog
# itself rather than the JSON-schema function name.
catalog_json_schema = catalog_snapshot_json_schema
catalog_selection_receipt_json_schema = catalog_receipt_json_schema
validate_catalog_selection_receipt = validate_catalog_receipt
