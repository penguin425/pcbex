from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .catalog import CatalogPart, search_parts

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
            "parts": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/part"}},
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
    pin_map = {part.reference: {pin for pin, _ in part.pins} for part in parts}
    nets: list[dict[str, Any]] = []
    net_names: set[str] = set()
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
            if (reference, pin) in seen_connections:
                raise CircuitSpecError(f"net {name} contains duplicate connection {reference}.{pin}")
            seen_connections.add((reference, pin))
            normalized.append({"reference": reference, "pin": pin})
        nets.append({"name": name, "connections": normalized})
    connected = {(connection["reference"], connection["pin"])
                 for net in nets for connection in net["connections"]}
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


def assign_catalog_parts(
    spec: Mapping[str, Any],
    catalog: list[CatalogPart],
    *,
    require_available: bool = True,
    require_basic: bool = False,
) -> dict[str, Any]:
    """Fill missing MPNs using deterministic, availability-aware selection."""
    normalized = validate_circuit_spec(dict(spec))
    for part in normalized["parts"]:
        if part["mpn"] is not None:
            continue
        candidates = search_parts(
            catalog,
            f"{part['value']} {part['lib_id']}",
            footprint=part["footprint"],
            limit=1,
            require_available=require_available,
            require_basic=require_basic,
        )
        if not candidates:
            # Catalogs frequently omit value/lib-id aliases.  Once the
            # manufacturing filters are satisfied, footprint is the safe
            # deterministic fallback instead of guessing a different package.
            candidates = search_parts(
                catalog,
                "",
                footprint=part["footprint"],
                limit=1,
                require_available=require_available,
                require_basic=require_basic,
            )
        if not candidates:
            raise CircuitSpecError(
                f"no catalog part satisfies {part['reference']} footprint={part['footprint']!r}"
            )
        part["mpn"] = candidates[0].mpn
    return normalized


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def generate_skidl(spec: Mapping[str, Any], *, include_netlist: bool = True) -> str:
    """Generate deterministic, executable SKiDL source from a closed spec."""
    normalized = validate_circuit_spec(dict(spec))
    parts = sorted(normalized["parts"], key=lambda part: part["reference"])
    nets = sorted(normalized["nets"], key=lambda net: net["name"])
    lines = ["# Generated by pcbex Text-to-Circuit; do not edit by hand.",
             "from skidl import Net, Part, generate_netlist", ""]
    for net in nets:
        lines.append(f"{net['name']} = Net({_quote(net['name'])})")
    lines.append("")
    for part in parts:
        library, symbol = part["lib_id"].split(":", 1)
        lines.append(
            f"{part['reference']} = Part({_quote(library)}, {_quote(symbol)}, "
            f"value={_quote(part['value'])}, footprint={_quote(part['footprint'])})"
        )
    lines.append("")
    for net in nets:
        for connection in net["connections"]:
            lines.append(f"{connection['reference']}[{_quote(connection['pin'])}] += {net['name']}")
    if include_netlist:
        lines.extend(["", "generate_netlist()"])
    return "\n".join(lines) + "\n"


def generate_skidl_from_json(source: str, *, include_netlist: bool = True) -> str:
    try:
        value = json.loads(source)
    except json.JSONDecodeError as error:
        raise CircuitSpecError(f"invalid circuit spec JSON: {error}") from error
    return generate_skidl(value, include_netlist=include_netlist)
