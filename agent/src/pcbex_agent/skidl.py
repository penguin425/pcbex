from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .catalog import CatalogPart, search_parts

SCHEMA_VERSION = 1
_REFERENCE = re.compile(r"^[A-Z][A-Z0-9_]*$", re.IGNORECASE)
_PIN = re.compile(r"^[A-Za-z0-9_+./-]+$")


class CircuitSpecError(ValueError):
    """Raised when an LLM-produced circuit spec is not safe to generate."""


class CircuitErcError(CircuitSpecError):
    """Raised when deterministic circuit-level electrical checks fail."""


@dataclass(frozen=True)
class CircuitPart:
    reference: str
    lib_id: str
    value: str
    footprint: str
    pins: tuple[tuple[str, str], ...]
    mpn: str | None = None
    electrical: dict[str, Any] | None = None


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
                    "electrical": {"$ref": "#/$defs/electrical"},
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
                    "voltage_v": {"type": ["number", "null"], "exclusiveMinimum": 0},
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
            "electrical": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "max_voltage_v": {"type": ["number", "null"], "exclusiveMinimum": 0},
                    "pin_max_voltage_v": {
                        "type": "object",
                        "additionalProperties": {"type": "number", "exclusiveMinimum": 0},
                    },
                    "power_output_v": {"type": ["number", "null"], "exclusiveMinimum": 0},
                    "requires_decoupling": {"type": "boolean"},
                    "decoupling": {"type": "boolean"},
                },
            },
        },
    }


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CircuitSpecError(f"{label} must be a non-empty string")
    return value.strip()


def _optional_voltage(value: Any, label: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CircuitSpecError(f"{label} must be a positive finite number or null")
    number = float(value)
    if not math.isfinite(number) or number <= 0 or number > 1000:
        raise CircuitSpecError(f"{label} must be between 0 and 1000 volts")
    return number


def _electrical(value: Any, reference: str, pins: set[str]) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise CircuitSpecError(f"{reference} electrical metadata must be an object")
    expected = {
        "max_voltage_v",
        "pin_max_voltage_v",
        "power_output_v",
        "requires_decoupling",
        "decoupling",
    }
    unknown = set(value) - expected
    if unknown:
        raise CircuitSpecError(
            f"{reference} electrical metadata contains unknown fields: {sorted(unknown)}"
        )
    pin_limits = value.get("pin_max_voltage_v", {})
    if not isinstance(pin_limits, dict):
        raise CircuitSpecError(f"{reference} pin_max_voltage_v must be an object")
    normalized_limits: dict[str, float] = {}
    for pin, limit in pin_limits.items():
        pin = _text(pin, f"{reference} electrical pin")
        if pin not in pins:
            raise CircuitSpecError(f"{reference} pin_max_voltage_v references unknown pin {pin}")
        voltage = _optional_voltage(limit, f"{reference}.{pin} max voltage")
        assert voltage is not None
        normalized_limits[pin] = voltage
    requires_decoupling = value.get("requires_decoupling", False)
    decoupling = value.get("decoupling", False)
    if not isinstance(requires_decoupling, bool) or not isinstance(decoupling, bool):
        raise CircuitSpecError(f"{reference} electrical decoupling flags must be booleans")
    return {
        "max_voltage_v": _optional_voltage(value.get("max_voltage_v"), f"{reference}.max_voltage_v"),
        "pin_max_voltage_v": dict(sorted(normalized_limits.items())),
        "power_output_v": _optional_voltage(value.get("power_output_v"), f"{reference}.power_output_v"),
        "requires_decoupling": requires_decoupling,
        "decoupling": decoupling,
    }


def _part(value: Mapping[str, Any]) -> CircuitPart:
    expected = {"reference", "lib_id", "value", "footprint", "pins", "mpn", "electrical"}
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
        _electrical(value.get("electrical"), reference, {pin for pin, _ in pins}),
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
        if not isinstance(raw_net, dict) or not set(raw_net).issubset({"name", "connections", "voltage_v"}):
            raise CircuitSpecError("each net contains an unknown field")
        if not {"name", "connections"}.issubset(raw_net):
            raise CircuitSpecError("each net must contain name and connections")
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
        nets.append({
            "name": name,
            "connections": normalized,
            "voltage_v": _optional_voltage(raw_net.get("voltage_v"), f"net {name}.voltage_v"),
        })
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
                   "pins": dict(p.pins),
                   "electrical": p.electrical or {}}
                  for p in parts],
        "nets": nets,
    }


def circuit_erc_json_schema() -> dict[str, Any]:
    """Return the closed deterministic circuit-level ERC report schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/circuit-erc-v1.json",
        "title": "pcbex deterministic circuit electrical rules report",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "passed", "errors", "findings"],
        "properties": {
            "schema_version": {"const": 1},
            "passed": {"type": "boolean"},
            "errors": {"type": "integer", "minimum": 0},
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["code", "severity", "message", "net", "references"],
                    "properties": {
                        "code": {"type": "string", "pattern": "^[a-z0-9_]+$"},
                        "severity": {"const": "error"},
                        "message": {"type": "string", "minLength": 1},
                        "net": {"type": ["string", "null"]},
                        "references": {
                            "type": "array",
                            "items": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_]*$"},
                        },
                    },
                },
            },
        },
    }


def check_circuit_electrical(spec: Mapping[str, Any]) -> dict[str, Any]:
    """Run deterministic power-tree, rating, and decoupling checks.

    The check intentionally accepts the normalized closed circuit spec rather
    than arbitrary model output.  A missing voltage annotation is not guessed;
    only explicit metadata and conservative rail-name aliases are evaluated.
    """

    normalized = validate_circuit_spec(dict(spec))
    parts = {part["reference"]: part for part in normalized["parts"]}
    findings: list[dict[str, Any]] = []

    def add(code: str, message: str, net: str | None, references: set[str]) -> None:
        findings.append(
            {
                "code": code,
                "severity": "error",
                "message": message,
                "net": net,
                "references": sorted(references),
            }
        )

    for net in normalized["nets"]:
        net_name = net["name"]
        declared_voltage = net["voltage_v"]
        inferred_voltage = _infer_rail_voltage(net_name)
        net_voltage = declared_voltage if declared_voltage is not None else inferred_voltage
        connections = net["connections"]
        references = {connection["reference"] for connection in connections}
        outputs = []
        decoupling_references: set[str] = set()
        required_decoupling: set[str] = set()
        for connection in connections:
            part = parts[connection["reference"]]
            electrical = part["electrical"]
            output_voltage = electrical["power_output_v"]
            if output_voltage is not None:
                outputs.append((connection["reference"], output_voltage))
            if electrical["decoupling"]:
                decoupling_references.add(connection["reference"])
            if electrical["requires_decoupling"]:
                required_decoupling.add(connection["reference"])
            if net_voltage is not None:
                pin_limit = electrical["pin_max_voltage_v"].get(connection["pin"])
                limit = pin_limit if pin_limit is not None else electrical["max_voltage_v"]
                if limit is not None and net_voltage > limit + 1e-9:
                    add(
                        "power_input_voltage_exceeded",
                        f"net {net_name} is {net_voltage:g} V but {connection['reference']}.{connection['pin']} tolerates at most {limit:g} V",
                        net_name,
                        {connection["reference"]},
                    )

        output_voltages = {voltage for _, voltage in outputs}
        all_voltages = set(output_voltages)
        if net_voltage is not None:
            all_voltages.add(net_voltage)
        if len(output_voltages) > 1:
            add(
                "multiple_power_outputs",
                f"net {net_name} has incompatible power outputs: {', '.join(f'{v:g} V' for v in sorted(output_voltages))}",
                net_name,
                {reference for reference, _ in outputs},
            )
        if len(all_voltages) > 1:
            add(
                "power_rail_voltage_conflict",
                f"net {net_name} combines incompatible rail voltages: {', '.join(f'{v:g} V' for v in sorted(all_voltages))}",
                net_name,
                references,
            )
        if required_decoupling and not decoupling_references and net_voltage is not None:
            add(
                "missing_decoupling_capacitor",
                f"net {net_name} requires a decoupling capacitor for {', '.join(sorted(required_decoupling))}",
                net_name,
                required_decoupling,
            )

    findings.sort(key=lambda finding: (finding["code"], finding["net"] or "", finding["references"]))
    return {
        "schema_version": 1,
        "passed": not findings,
        "errors": len(findings),
        "findings": findings,
    }


def _infer_rail_voltage(name: str) -> float | None:
    normalized = name.upper().replace("_", "").replace("-", "")
    aliases = {
        "5V": 5.0,
        "VCC5": 5.0,
        "VDD5": 5.0,
        "3V3": 3.3,
        "VCC3V3": 3.3,
        "VDD3V3": 3.3,
        "1V8": 1.8,
        "VCC1V8": 1.8,
        "VDD1V8": 1.8,
    }
    return aliases.get(normalized)


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
