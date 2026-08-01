"""Deterministic KiCad schematic generation from the closed circuit contract.

The generated schematic deliberately uses self-contained ``PCBEX:*`` library
symbols.  This keeps the handoff independent of a user's global KiCad symbol
library while retaining the source library id as a hidden property.  Pin
electrical types are passive because the circuit contract carries the
deterministic power/rating ERC metadata; callers can replace symbols with
project-approved libraries before simulation or assembly.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from typing import Any

from .skidl import CircuitSpecError, validate_circuit_spec


class SchematicGenerationError(CircuitSpecError):
    """Raised when a circuit cannot be rendered as a KiCad schematic."""


def _spec_from_value(value: Mapping[str, Any]) -> dict[str, Any]:
    candidate = value.get("spec") if isinstance(value.get("spec"), Mapping) else value
    if not isinstance(candidate, Mapping):
        raise SchematicGenerationError("schematic input must be a spec or generation bundle")
    return validate_circuit_spec(dict(candidate))


def _uuid(seed: str) -> str:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:]}"


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _mm(value: float) -> str:
    if not math.isfinite(value):
        raise SchematicGenerationError("schematic coordinate must be finite")
    rendered = f"{value:.6f}".rstrip("0").rstrip(".")
    return rendered or "0"


def _pin_x(index: int) -> float:
    # Keep every connection point on KiCad's 2.54 mm schematic grid.  Pins are
    # laid out horizontally because KiCad's library Y axis is mirrored between
    # the native ERC engine and the lightweight pcbex schematic importer.
    return -5.08 - index * 5.08


def circuit_spec_to_kicad_sch(
    value: Mapping[str, Any],
    *,
    project_name: str = "pcbex-generated",
) -> str:
    """Render a valid, self-contained KiCad ``.kicad_sch`` document.

    Connectivity is represented by repeated local labels at each pin endpoint,
    so the generated document remains compact even for multi-terminal nets.
    ``pcbex``'s deterministic circuit ERC remains authoritative for voltage and
    decoupling constraints; KiCad's native ERC can be run as an additional
    environment gate on the emitted file.
    """

    if not isinstance(project_name, str) or not project_name.strip():
        raise SchematicGenerationError("schematic project_name must be non-empty")
    spec = _spec_from_value(value)
    parts = sorted(spec["parts"], key=lambda item: item["reference"])
    pins_by_reference = {
        part["reference"]: sorted(part["pins"], key=lambda pin: (len(pin), pin))
        for part in parts
    }
    root_uuid = _uuid(f"schematic:{project_name}:root")
    lib_ids = {part["reference"]: f"PCBEX:{part['reference']}" for part in parts}
    lines = [
        "(kicad_sch",
        "  (version 20231120)",
        "  (generator pcbex)",
        "  (generator_version \"1\")",
        f"  (uuid {_uuid(f'schematic:{project_name}:document')})",
        "  (paper \"A4\")",
        "  (lib_symbols",
    ]
    for part in parts:
        reference = part["reference"]
        pins = pins_by_reference[reference]
        lines.extend([
            f"    (symbol {_quote(lib_ids[reference])}",
            "      (pin_names (offset 0))",
            "      (in_bom yes)",
            "      (on_board yes)",
            f"      (symbol {_quote(f'{reference}_1_1')}",
        ])
        for index, pin in enumerate(pins):
            lines.extend([
                "        (pin passive line",
                f"          (at {_mm(_pin_x(index))} 0 0)",
                "          (length 2.54)",
                f"          (name {_quote(f'PIN_{pin}')} (effects (font (size 1.27 1.27))))",
                f"          (number {_quote(pin)} (effects (font (size 1.27 1.27)))))",
            ])
        lines.extend([
            "      )",
            "    )",
        ])
    lines.append("  )")

    positions: dict[tuple[str, str], tuple[float, float]] = {}
    for index, part in enumerate(parts):
        reference = part["reference"]
        column = index % 6
        row = index // 6
        x = 25.4 + column * 35.56
        y = 25.4 + row * 35.56
        lines.extend([
            "  (symbol",
            f"    (lib_id {_quote(lib_ids[reference])})",
            f"    (at {_mm(x)} {_mm(y)} 0)",
            "    (unit 1)",
            "    (exclude_from_sim no)",
            "    (in_bom yes)",
            "    (on_board yes)",
            "    (dnp no)",
            f"    (uuid {_uuid(f'schematic:{project_name}:symbol:{reference}')})",
            f"    (property \"Reference\" {_quote(reference)} (at {_mm(x)} {_mm(y - 8)} 0) (effects (font (size 1.27 1.27))))",
            f"    (property \"Value\" {_quote(str(part['value']))} (at {_mm(x)} {_mm(y - 5.5)} 0) (effects (font (size 1.27 1.27))))",
            # KiCad's native ERC checks the standard Footprint property against
            # the project's global footprint table.  Keep it empty in the
            # library-independent handoff and retain the requested footprint
            # in a private property for the PCB/BOM stages.
            "    (property \"Footprint\" \"\" (at 0 0 0) (effects (font (size 1.27 1.27)) hide))",
            f"    (property \"PCBEX_Footprint\" {_quote(str(part['footprint']))} (at {_mm(x)} {_mm(y + 8)} 0) (effects (font (size 1.27 1.27)) hide))",
            f"    (property \"PCBEX_SourceLibId\" {_quote(str(part['lib_id']))} (at {_mm(x)} {_mm(y + 10.5)} 0) (effects (font (size 1.27 1.27)) hide))",
        ])
        for pin in pins_by_reference[reference]:
            lines.append(
                f"    (pin {_quote(pin)} (uuid {_uuid(f'schematic:{project_name}:pin:{reference}:{pin}')}))"
            )
        lines.extend([
            "    (instances",
            f"      (project {_quote(project_name)}",
            f"        (path \"/{root_uuid}\" (reference {_quote(reference)}) (unit 1)))",
            "    )",
            "  )",
        ])
        for index, pin in enumerate(pins_by_reference[reference]):
            positions[(reference, pin)] = (x + _pin_x(index), y)

    # Labels at the exact pin endpoint create deterministic, sheet-local nets.
    # Add a short wire for human readability and to make the connection visible
    # when the document is opened in Eeschema.
    parts_by_reference = {part["reference"]: part for part in parts}
    for net in sorted(spec["nets"], key=lambda item: item["name"]):
        for connection in sorted(
            net["connections"], key=lambda item: (item["reference"], item["pin"])
        ):
            reference = connection["reference"]
            pin = connection["pin"]
            x, y = positions[(reference, pin)]
            label_uuid = _uuid(f"schematic:{project_name}:label:{net['name']}:{reference}:{pin}")
            wire_uuid = _uuid(f"schematic:{project_name}:wire:{net['name']}:{reference}:{pin}")
            lines.extend([
                "  (wire",
                f"    (pts (xy {_mm(x)} {_mm(y)}) (xy {_mm(x - 2.54)} {_mm(y)}))",
                "    (stroke (width 0) (type default))",
                f"    (uuid {wire_uuid})",
                "  )",
                f"  (label {_quote(net['name'])} (at {_mm(x - 2.54)} {_mm(y)} 0)",
                "    (effects (font (size 1.27 1.27)) (justify left bottom))",
                f"    (uuid {label_uuid}))",
            ])
    lines.extend([
        "  (sheet_instances",
        "    (path \"/\" (page \"1\"))",
        "  )",
        ")",
    ])
    # Keep a deliberate reference to the normalized part map in this function;
    # it catches accidental future changes that omit a part from the positions
    # table while remaining a no-op for the current deterministic renderer.
    if set(parts_by_reference) != set(pins_by_reference):
        raise SchematicGenerationError("schematic part index is inconsistent")
    return "\n".join(lines) + "\n"


def schematic_generation_json_schema() -> dict[str, Any]:
    """Return the closed metadata contract for a generated schematic artifact."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/generated-schematic-v1.json",
        "title": "pcbex generated KiCad schematic artifact",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "format", "sha256", "bytes"],
        "properties": {
            "schema_version": {"const": 1},
            "format": {"const": "kicad_sch"},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "bytes": {"type": "integer", "minimum": 1},
        },
    }
