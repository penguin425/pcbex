from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

from .catalog import (
    MAX_CATALOG_PARTS,
    MAX_CATALOG_QUERY_BYTES,
    MAX_CATALOG_QUERY_TOKENS,
    MAX_CATALOG_SELECTION_WORK,
    MAX_CATALOG_STOCK,
    MAX_CATALOG_TAG_BYTES,
    MAX_CATALOG_TAGS,
    MAX_CATALOG_TEXT_BYTES,
    MAX_SPEC_PARTS,
    CatalogPart,
    search_parts,
)

SCHEMA_VERSION = 1
_REFERENCE = re.compile(r"^[A-Z][A-Z0-9_]*$", re.IGNORECASE)
_PIN = re.compile(r"^[A-Za-z0-9_+./-]+$")


class CircuitSpecError(ValueError):
    """Raised when an LLM-produced circuit spec is not safe to generate."""


@dataclass(frozen=True)
class CircuitPart:
    reference: str
    lib_id: str
    value: str
    footprint: str
    pins: tuple[tuple[str, str], ...]
    mpn: str | None = None


def circuit_spec_json_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/circuit-spec-v1.json",
        "title": "pcbex Text-to-Circuit specification",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "parts", "nets"],
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "parts": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_SPEC_PARTS,
                "items": {"$ref": "#/$defs/part"},
            },
            "nets": {"type": "array", "items": {"$ref": "#/$defs/net"}},
        },
        "$defs": {
            "part": {
                "type": "object",
                "additionalProperties": False,
                "required": ["reference", "lib_id", "value", "footprint", "pins"],
                "properties": {
                    "reference": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_]*$"},
                    "lib_id": {"type": "string", "pattern": "^[^:]+:[^:]+$"},
                    "value": {"type": "string", "minLength": 1, "maxLength": 512},
                    "footprint": {"type": "string", "minLength": 1, "maxLength": 512},
                    "mpn": {"type": ["string", "null"]},
                    "pins": {
                        "type": "object",
                        "minProperties": 1,
                        "additionalProperties": {"type": "string", "minLength": 1},
                    },
                },
            },
            "net": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "connections"],
                "properties": {
                    "name": {"type": "string", "pattern": "^[A-Za-z0-9_+./-]+$"},
                    "connections": {
                        "type": "array",
                        "minItems": 2,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["reference", "pin"],
                            "properties": {
                                "reference": {"type": "string"},
                                "pin": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
    }


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CircuitSpecError(f"{label} must be a non-empty string")
    return value.strip()


def _part(value: Mapping[str, Any]) -> CircuitPart:
    expected = {"reference", "lib_id", "value", "footprint", "pins", "mpn"}
    unknown = set(value) - expected
    if unknown:
        raise CircuitSpecError(f"part contains unknown fields: {sorted(unknown)}")
    reference = _text(value.get("reference"), "part reference")
    if not _REFERENCE.fullmatch(reference):
        raise CircuitSpecError(f"invalid part reference {reference!r}")
    lib_id = _text(value.get("lib_id"), f"{reference} lib_id")
    if lib_id.count(":") != 1:
        raise CircuitSpecError(f"{reference} lib_id must have Lib:Symbol form")
    footprint = _text(value.get("footprint"), f"{reference} footprint")
    raw_pins = value.get("pins")
    if not isinstance(raw_pins, dict) or not raw_pins:
        raise CircuitSpecError(f"{reference} pins must be a non-empty object")
    pins: list[tuple[str, str]] = []
    for pin, net in raw_pins.items():
        pin = _text(pin, f"{reference} pin")
        net = _text(net, f"{reference}.{pin} net")
        if not _PIN.fullmatch(pin) or not _PIN.fullmatch(net):
            raise CircuitSpecError(f"invalid pin or net identifier {pin!r}/{net!r}")
        pins.append((pin, net))
    return CircuitPart(
        reference, lib_id, _text(value.get("value"), f"{reference} value"),
        footprint, tuple(sorted(pins)),
        None if value.get("mpn") is None else _text(value["mpn"], f"{reference} mpn"),
    )


def validate_circuit_spec(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema_version", "parts", "nets"}:
        raise CircuitSpecError("circuit spec must contain exactly schema_version, parts, and nets")
    if value["schema_version"] != SCHEMA_VERSION:
        raise CircuitSpecError(f"unsupported circuit spec schema version {value['schema_version']!r}")
    raw_parts = value["parts"]
    raw_nets = value["nets"]
    if not isinstance(raw_parts, list) or not raw_parts:
        raise CircuitSpecError("parts must be a non-empty array")
    if len(raw_parts) > MAX_SPEC_PARTS:
        raise CircuitSpecError(
            f"circuit spec contains more than {MAX_SPEC_PARTS} parts"
        )
    if not isinstance(raw_nets, list):
        raise CircuitSpecError("nets must be an array")
    parts: list[CircuitPart] = []
    for raw_part in raw_parts:
        if not isinstance(raw_part, dict):
            raise CircuitSpecError("each part must be an object")
        parts.append(_part(raw_part))
    references = [part.reference for part in parts]
    if len(references) != len(set(references)):
        raise CircuitSpecError("part references must be unique")
    pin_map = {part.reference: dict(part.pins) for part in parts}
    nets: list[dict[str, Any]] = []
    net_names: set[str] = set()
    connected: set[tuple[str, str]] = set()
    for raw_net in raw_nets:
        if not isinstance(raw_net, dict) or set(raw_net) != {"name", "connections"}:
            raise CircuitSpecError("each net must contain exactly name and connections")
        name = _text(raw_net.get("name"), "net name")
        if not _PIN.fullmatch(name) or name in net_names:
            raise CircuitSpecError(f"invalid or duplicate net name {name!r}")
        net_names.add(name)
        connections = raw_net["connections"]
        if not isinstance(connections, list) or len(connections) < 2:
            raise CircuitSpecError(f"net {name} must have at least two connections")
        seen_connections: set[tuple[str, str]] = set()
        normalized: list[dict[str, str]] = []
        for connection in connections:
            if not isinstance(connection, dict) or set(connection) != {"reference", "pin"}:
                raise CircuitSpecError(f"net {name} has an invalid connection")
            reference = _text(connection.get("reference"), "connection reference")
            pin = _text(connection.get("pin"), "connection pin")
            if reference not in pin_map or pin not in pin_map[reference]:
                raise CircuitSpecError(f"net {name} references unknown {reference}.{pin}")
            declared_net = pin_map[reference][pin]
            if declared_net != name:
                raise CircuitSpecError(
                    f"{reference}.{pin} declares net {declared_net!r} "
                    f"but is connected to {name!r}"
                )
            if (reference, pin) in seen_connections:
                raise CircuitSpecError(f"net {name} contains duplicate connection {reference}.{pin}")
            if (reference, pin) in connected:
                raise CircuitSpecError(f"{reference}.{pin} is connected to multiple nets")
            seen_connections.add((reference, pin))
            connected.add((reference, pin))
            normalized.append({"reference": reference, "pin": pin})
        nets.append({"name": name, "connections": normalized})
    declared = {(part.reference, pin) for part in parts for pin, _ in part.pins}
    if connected != declared:
        missing = sorted(declared - connected)
        extra = sorted(connected - declared)
        raise CircuitSpecError(f"pin/net coverage mismatch; missing={missing}, extra={extra}")
    return {
        "schema_version": SCHEMA_VERSION,
        "parts": [{"reference": p.reference, "lib_id": p.lib_id, "value": p.value,
                   "footprint": p.footprint, "mpn": p.mpn,
                   "pins": dict(p.pins)} for p in parts],
        "nets": nets,
    }


def _bounded_catalog_text(value: Any, *, max_bytes: int, required: bool) -> bool:
    """Return whether one directly injected catalog text field is safe.

    ``CatalogPart`` is intentionally a small frozen dataclass and can be
    instantiated directly, bypassing ``CatalogPart.from_mapping`` and the
    strict snapshot loader.  Keep this check local to the legacy adapter so
    those values receive the same byte/control-character guardrails without
    changing the permissive constructor's compatibility defaults.
    """

    if not isinstance(value, str):
        return False
    # Every UTF-8 code point consumes at least one byte.  Reject an obviously
    # oversized Python string before copying/encoding it, keeping validation
    # itself bounded even when a caller injected a very large value.
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
    return not any(ord(character) < 0x20 for character in normalized)


def _valid_catalog_datasheet(value: Any) -> bool:
    """Validate optional direct ``CatalogPart.datasheet_url`` values."""

    # Empty-string is the legacy constructor default; strict snapshots use
    # null.  Preserve both representations while validating non-empty URLs.
    if value is None or value == "":
        return True
    if not _bounded_catalog_text(
        value, max_bytes=MAX_CATALOG_TEXT_BYTES, required=True
    ):
        return False
    normalized = value.strip()
    try:
        parsed = urlsplit(normalized)
        hostname = parsed.hostname
        # Accessing ``port`` forces urlsplit to validate malformed bracketed
        # hosts and ports that it otherwise defers.
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


def _validate_direct_catalog_part(candidate: CatalogPart) -> bool:
    """Apply snapshot-equivalent bounds to a directly supplied CatalogPart."""

    if not all(
        _bounded_catalog_text(value, max_bytes=MAX_CATALOG_TEXT_BYTES, required=True)
        for value in (candidate.mpn, candidate.description, candidate.footprint)
    ):
        return False
    if not isinstance(candidate.tags, tuple) or len(candidate.tags) > MAX_CATALOG_TAGS:
        return False
    if not all(
        _bounded_catalog_text(tag, max_bytes=MAX_CATALOG_TAG_BYTES, required=True)
        for tag in candidate.tags
    ):
        return False
    # ``vendor`` and ``datasheet_url`` historically default to an empty string
    # in the legacy constructor.  Empty values remain accepted, but non-empty
    # values are bounded and datasheets must use HTTPS like snapshots.
    if not _bounded_catalog_text(
        candidate.vendor, max_bytes=MAX_CATALOG_TEXT_BYTES, required=False
    ):
        return False
    if not _valid_catalog_datasheet(candidate.datasheet_url):
        return False
    supplier_part_number = getattr(candidate, "supplier_part_number", None)
    if supplier_part_number is not None and not _bounded_catalog_text(
        supplier_part_number, max_bytes=MAX_CATALOG_TEXT_BYTES, required=False
    ):
        return False
    if (
        isinstance(candidate.stock, bool)
        or not isinstance(candidate.stock, int)
        or candidate.stock < 0
        or candidate.stock > MAX_CATALOG_STOCK
        or not isinstance(candidate.basic, bool)
    ):
        return False
    return True


def _catalog_query(part: Mapping[str, Any]) -> tuple[str, int, int]:
    """Build and bound the legacy value/library search query."""

    value = part["value"]
    lib_id = part["lib_id"]
    # Avoid constructing a potentially enormous f-string just to reject it
    # against the byte ceiling below.  Both fields are validated strings.
    if len(value) > MAX_CATALOG_QUERY_BYTES or len(lib_id) > MAX_CATALOG_QUERY_BYTES:
        raise CircuitSpecError(
            f"catalog query exceeds {MAX_CATALOG_QUERY_BYTES} UTF-8 bytes"
        )
    query = f"{value} {lib_id}"
    try:
        query_bytes = len(query.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as error:
        raise CircuitSpecError("catalog query is not valid UTF-8") from error
    if query_bytes > MAX_CATALOG_QUERY_BYTES:
        raise CircuitSpecError(
            f"catalog query exceeds {MAX_CATALOG_QUERY_BYTES} UTF-8 bytes"
        )
    tokens = query.split()
    if len(tokens) > MAX_CATALOG_QUERY_TOKENS:
        raise CircuitSpecError(
            f"catalog query contains more than {MAX_CATALOG_QUERY_TOKENS} tokens"
        )
    return query, len(tokens), query_bytes


def assign_catalog_parts(
    spec: Mapping[str, Any],
    catalog: list[CatalogPart],
    *,
    require_available: bool = True,
    require_basic: bool = False,
    allow_footprint_fallback: bool = False,
) -> dict[str, Any]:
    """Fill missing MPNs using deterministic, availability-aware selection."""
    for name, value in (
        ("require_available", require_available),
        ("require_basic", require_basic),
        ("allow_footprint_fallback", allow_footprint_fallback),
    ):
        if not isinstance(value, bool):
            raise CircuitSpecError(f"{name} must be a boolean")

    try:
        catalog_iterator = iter(catalog)
    except TypeError as error:
        raise CircuitSpecError("catalog must be an iterable of CatalogPart values") from error
    catalog_parts: list[CatalogPart] = []
    # Consume at most one item beyond the published bound.  A malicious
    # generator must not be allowed to run forever while ``list(catalog)``
    # attempts to materialize it before the size check.
    for index in range(MAX_CATALOG_PARTS + 1):
        try:
            candidate = next(catalog_iterator)
        except StopIteration:
            break
        if index >= MAX_CATALOG_PARTS:
            raise CircuitSpecError(
                f"catalog contains more than {MAX_CATALOG_PARTS} parts"
            )
        catalog_parts.append(candidate)
    catalog_by_mpn: dict[str, CatalogPart] = {}
    for candidate in catalog_parts:
        if not isinstance(candidate, CatalogPart):
            raise CircuitSpecError("catalog must contain only CatalogPart values")
        if not _validate_direct_catalog_part(candidate):
            raise CircuitSpecError("catalog contains an invalid CatalogPart value")
        key = candidate.mpn.casefold()
        if key in catalog_by_mpn:
            raise CircuitSpecError("catalog contains duplicate MPNs (case-insensitive)")
        catalog_by_mpn[key] = candidate

    normalized = validate_circuit_spec(dict(spec))
    ordered_parts = sorted(
        normalized["parts"],
        key=lambda part: (part["reference"].casefold(), part["reference"]),
    )
    queries: dict[str, tuple[str, int, int]] = {}
    selection_work = 0
    for part in ordered_parts:
        if part["mpn"] is not None:
            continue
        query, token_count, query_bytes = _catalog_query(part)
        queries[part["reference"]] = (query, token_count, query_bytes)
        # Mirror search_parts exactly: each candidate incurs one traversal
        # charge plus every token comparison, and the query bytes themselves
        # are charged once.  A possible footprint-only fallback is a second
        # candidate traversal with an empty query.
        selection_work += (
            len(catalog_parts) * (1 + token_count)
            + query_bytes
            + len(catalog_parts) * int(allow_footprint_fallback)
        )
    if selection_work > MAX_CATALOG_SELECTION_WORK:
        raise CircuitSpecError("catalog selection exceeds its deterministic work limit")
    selected: dict[str, CatalogPart] = {}
    demand: dict[str, int] = {}

    def reserve(candidate: CatalogPart) -> bool:
        key = candidate.mpn.casefold()
        next_demand = demand.get(key, 0) + 1
        if require_available and next_demand > candidate.stock:
            return False
        demand[key] = next_demand
        return True

    # Explicit MPNs reserve their inventory before automatic choices.
    for part in ordered_parts:
        reference = part["reference"]
        if part["mpn"] is None:
            continue
        candidate = catalog_by_mpn.get(part["mpn"].casefold())
        if candidate is None:
            raise CircuitSpecError(f"prefilled MPN for {reference} is not in catalog")
        if candidate.footprint != part["footprint"]:
            raise CircuitSpecError(
                f"prefilled MPN for {reference} has mismatched footprint"
            )
        if require_basic and not candidate.basic:
            raise CircuitSpecError(f"prefilled MPN for {reference} is not basic")
        if require_available and not reserve(candidate):
            raise CircuitSpecError(f"prefilled MPN for {reference} is unavailable")
        if not require_available:
            reserve(candidate)
        selected[reference] = candidate

    for part in ordered_parts:
        reference = part["reference"]
        if part["mpn"] is not None:
            continue
        query, _, _ = queries[reference]
        ranked_candidates = search_parts(
            catalog_parts,
            query,
            footprint=part["footprint"],
            limit=len(catalog_parts),
            require_available=require_available,
            require_basic=require_basic,
        )
        candidates = [
            candidate
            for candidate in ranked_candidates
            if not require_available
            or demand.get(candidate.mpn.casefold(), 0) < candidate.stock
        ]
        depleted_match = bool(ranked_candidates) and not candidates
        if not candidates and not depleted_match and allow_footprint_fallback:
            # Catalogs frequently omit value/lib-id aliases.  Once the
            # manufacturing filters are satisfied, footprint is the safe
            # deterministic fallback instead of guessing a different package.
            candidates = search_parts(
                catalog_parts,
                "",
                footprint=part["footprint"],
                limit=len(catalog_parts),
                require_available=require_available,
                require_basic=require_basic,
            )
            candidates = [
                candidate
                for candidate in candidates
                if not require_available
                or demand.get(candidate.mpn.casefold(), 0) < candidate.stock
            ]
        if not candidates:
            if depleted_match:
                raise CircuitSpecError(
                    "catalog stock is insufficient for requested references"
                )
            raise CircuitSpecError(
                f"no catalog part satisfies {reference} footprint={part['footprint']!r}"
            )
        candidate = candidates[0]
        if not reserve(candidate):
            raise CircuitSpecError("catalog stock is insufficient for requested references")
        selected[reference] = candidate
        part["mpn"] = candidate.mpn
    return normalized


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _normalize_no_connects(
    value: Sequence[tuple[str, str]] | None,
) -> tuple[tuple[str, str], ...]:
    """Validate the private v2-to-v1 no-connect side channel.

    The public schema-v1 contract has no representation for an explicitly
    unconnected pin.  The v2 adapter therefore passes those pins separately to
    the renderer.  Keep this argument private and closed: malformed values
    must not become Python source, even when an internal caller is replaced by
    an injected test callback.
    """

    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise CircuitSpecError("private no-connect side channel must be a sequence")
    normalized: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for marker in value:
        if (
            isinstance(marker, (str, bytes))
            or not isinstance(marker, Sequence)
            or len(marker) != 2
        ):
            raise CircuitSpecError("private no-connect marker must contain reference and pin")
        reference, pin = marker
        if (
            not isinstance(reference, str)
            or not isinstance(pin, str)
            or _REFERENCE.fullmatch(reference) is None
            or _PIN.fullmatch(pin) is None
        ):
            raise CircuitSpecError("private no-connect marker has invalid reference or pin")
        key = (reference, pin)
        if key in seen:
            raise CircuitSpecError(
                f"private no-connect markers contain duplicate {reference}.{pin}"
            )
        seen.add(key)
        normalized.append(key)
    normalized.sort(key=lambda marker: (marker[0], marker[1]))
    return tuple(normalized)


def _generate_skidl_with_no_connects(
    spec: Mapping[str, Any],
    *,
    include_netlist: bool = True,
    catalog_receipt_sha256: str | None = None,
    no_connects: Sequence[tuple[str, str]] | None = None,
) -> str:
    """Render schema-v1 plus trusted no-connects from the native-v2 adapter."""
    if catalog_receipt_sha256 is not None and (
        not isinstance(catalog_receipt_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", catalog_receipt_sha256) is None
    ):
        raise CircuitSpecError("catalog_receipt_sha256 must be lowercase 64-hex")
    normalized = validate_circuit_spec(dict(spec))
    normalized_no_connects = _normalize_no_connects(no_connects)
    parts = sorted(normalized["parts"], key=lambda part: part["reference"])
    nets = sorted(normalized["nets"], key=lambda net: net["name"])
    parts_by_reference = {part["reference"]: part for part in parts}
    for reference, pin in normalized_no_connects:
        part = parts_by_reference.get(reference)
        if part is None:
            raise CircuitSpecError(
                f"private no-connect marker references unknown part {reference}"
            )
        if pin in part["pins"]:
            raise CircuitSpecError(
                f"private no-connect marker overlaps declared pin {reference}.{pin}"
            )
    mpn_by_reference = {
        part["reference"]: part["mpn"]
        for part in parts
        if part["mpn"] is not None
    }
    if catalog_receipt_sha256 is not None and len(mpn_by_reference) != len(parts):
        raise CircuitSpecError(
            "catalog receipt evidence requires an MPN for every circuit part"
        )
    import_line = (
        "from skidl import NC, Net, Part, generate_netlist"
        if normalized_no_connects
        else "from skidl import Net, Part, generate_netlist"
    )
    lines = ["# Generated by pcbex Text-to-Circuit; do not edit by hand.",
             import_line, "",
             "_PCBEX_MPN_BY_REFERENCE = " + json.dumps(
                 mpn_by_reference, ensure_ascii=False, sort_keys=True
             )]
    if catalog_receipt_sha256 is not None:
        lines.append(f"_PCBEX_CATALOG_RECEIPT_SHA256 = {_quote(catalog_receipt_sha256)}")
    lines.extend(["", "_pcbex_nets = {}", "_pcbex_parts = {}", ""])
    for net in nets:
        name = _quote(net["name"])
        lines.append(f"_pcbex_nets[{name}] = Net({name})")
    lines.append("")
    for part in parts:
        library, symbol = part["lib_id"].split(":", 1)
        lines.append(
            f"_pcbex_parts[{_quote(part['reference'])}] = "
            f"Part({_quote(library)}, {_quote(symbol)}, "
            f"value={_quote(part['value'])}, footprint={_quote(part['footprint'])})"
        )
    lines.append("")
    for reference, pin in normalized_no_connects:
        lines.append(
            f"_pcbex_parts[{_quote(reference)}][{_quote(pin)}] += NC"
        )
    if normalized_no_connects:
        lines.append("")
    for net in nets:
        for connection in net["connections"]:
            lines.append(
                f"_pcbex_parts[{_quote(connection['reference'])}]"
                f"[{_quote(connection['pin'])}] += _pcbex_nets[{_quote(net['name'])}]"
            )
    if include_netlist:
        lines.extend(["", "generate_netlist()"])
    return "\n".join(lines) + "\n"


def generate_skidl(
    spec: Mapping[str, Any],
    *,
    include_netlist: bool = True,
    catalog_receipt_sha256: str | None = None,
) -> str:
    """Generate deterministic, executable SKiDL source from a closed spec."""
    return _generate_skidl_with_no_connects(
        spec,
        include_netlist=include_netlist,
        catalog_receipt_sha256=catalog_receipt_sha256,
    )


def generate_skidl_from_json(source: str, *, include_netlist: bool = True) -> str:
    try:
        value = json.loads(source)
    except json.JSONDecodeError as error:
        raise CircuitSpecError(f"invalid circuit spec JSON: {error}") from error
    return generate_skidl(value, include_netlist=include_netlist)
