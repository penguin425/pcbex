from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from typing import Any

from .skidl import CircuitSpecError, validate_circuit_spec


def _spec_from_value(value: Mapping[str, Any]) -> dict[str, Any]:
    """Extract and validate a circuit spec from a spec or generation bundle."""

    candidate = value.get("spec") if isinstance(value.get("spec"), Mapping) else value
    if not isinstance(candidate, Mapping):
        raise CircuitSpecError("circuit input must be a spec or generation bundle")
    return validate_circuit_spec(candidate)


def _dimension(value: Any, *, key: str) -> tuple[int, int, dict[str, Any]]:
    """Normalize one footprint-size entry and retain optional placement metadata."""

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        if len(value) != 2:
            raise CircuitSpecError(f"footprint size {key!r} must contain width and height")
        width, height = value
        metadata: dict[str, Any] = {}
    elif isinstance(value, Mapping):
        width = value.get("width_nm")
        height = value.get("height_nm")
        metadata = dict(value)
    else:
        raise CircuitSpecError(f"footprint size {key!r} must be an array or object")
    if (
        isinstance(width, bool)
        or isinstance(height, bool)
        or not isinstance(width, int)
        or not isinstance(height, int)
        or width <= 0
        or height <= 0
    ):
        raise CircuitSpecError(f"footprint size {key!r} must use positive integer nanometres")
    return width, height, metadata


def _sizes_by_key(footprint_sizes: Mapping[str, Any]) -> dict[str, tuple[int, int, dict[str, Any]]]:
    if not isinstance(footprint_sizes, Mapping) or not footprint_sizes:
        raise CircuitSpecError("footprint_sizes must be a non-empty object")
    return {
        str(key): _dimension(value, key=str(key))
        for key, value in footprint_sizes.items()
    }


def _part_size(
    part: Mapping[str, Any], sizes: Mapping[str, tuple[int, int, dict[str, Any]]]
) -> tuple[int, int, dict[str, Any]]:
    reference = str(part["reference"])
    footprint = str(part["footprint"])
    value = sizes.get(reference) or sizes.get(footprint)
    if value is None:
        raise CircuitSpecError(
            f"missing footprint dimensions for {reference} ({footprint})"
        )
    return value


def circuit_spec_to_placement_problem(
    value: Mapping[str, Any],
    footprint_sizes: Mapping[str, Any],
    *,
    width_nm: int,
    height_nm: int,
    grid_nm: int,
    constraints: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Convert a validated circuit spec into pcbex's placement JSON contract.

    A net with more than two pins is represented as a deterministic star of
    weighted component connections. Pin offsets are intentionally omitted until
    a real footprint library is selected; the generated KiCad handoff below
    creates stable placeholder pad locations for the same net graph.
    """

    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in (width_nm, height_nm, grid_nm)
    ):
        raise CircuitSpecError("board dimensions and grid must be positive integers")
    spec = _spec_from_value(value)
    sizes = _sizes_by_key(footprint_sizes)
    components: list[dict[str, Any]] = []
    metadata_by_reference: dict[str, dict[str, Any]] = {}
    for part in sorted(spec["parts"], key=lambda item: item["reference"]):
        width, height, metadata = _part_size(part, sizes)
        component: dict[str, Any] = {
            "reference": part["reference"],
            "width_nm": width,
            "height_nm": height,
        }
        for field in ("position", "rotation_deg", "fixed", "side", "allowed_rotations", "allow_side_flip"):
            if field in metadata:
                component[field] = metadata[field]
        components.append(component)
        metadata_by_reference[part["reference"]] = metadata

    connections: list[dict[str, Any]] = []
    for net in sorted(spec["nets"], key=lambda item: item["name"]):
        references = sorted({item["reference"] for item in net["connections"]})
        if len(references) < 2:
            continue
        anchor = references[0]
        for reference in references[1:]:
            connections.append(
                {
                    "from": {"component": anchor},
                    "to": {"component": reference},
                    "weight": 1.0,
                    "net": net["name"],
                }
            )
    connection_keys = ("from", "to", "weight", "net")
    connections = [
        {key: connection[key] for key in connection_keys}
        for connection in sorted(
            connections,
            key=lambda item: (
                item["net"],
                item["from"]["component"],
                item["to"]["component"],
            ),
        )
    ]
    result: dict[str, Any] = {
        "schema_version": 1,
        "width_nm": width_nm,
        "height_nm": height_nm,
        "grid_nm": grid_nm,
        "components": components,
        "connections": connections,
        "constraints": list(constraints or []),
    }
    # Keep the normalized mapping available to downstream consumers without
    # putting arbitrary catalog metadata into the Rust placement contract.
    if metadata_by_reference:
        result["metadata"] = {
            "footprints": {
                reference: {
                    key: value
                    for key, value in metadata.items()
                    if key not in {"width_nm", "height_nm"}
                }
                for reference, metadata in sorted(metadata_by_reference.items())
            }
        }
    return result


def circuit_spec_to_netlist(value: Mapping[str, Any]) -> dict[str, Any]:
    """Emit a canonical, digest-bound connectivity artifact for downstream gates."""

    spec = _spec_from_value(value)
    normalized = {
        "schema_version": 1,
        "parts": [
            {
                key: part[key]
                for key in ("reference", "lib_id", "value", "footprint", "mpn", "pins", "electrical")
                if key in part
            }
            for part in sorted(spec["parts"], key=lambda item: item["reference"])
        ],
        "nets": [
            {
                "name": net["name"],
                "voltage_v": net.get("voltage_v"),
                "connections": sorted(
                    net["connections"],
                    key=lambda item: (item["reference"], item["pin"]),
                ),
            }
            for net in sorted(spec["nets"], key=lambda item: item["name"])
        ],
    }
    canonical = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    normalized["sha256"] = hashlib.sha256(canonical).hexdigest()
    return normalized


def _mm(value_nm: int) -> str:
    """Render nanometres as a stable KiCad decimal in millimetres."""

    return f"{value_nm / 1_000_000:.6f}".rstrip("0").rstrip(".") or "0"


def circuit_spec_to_kicad_pcb(
    value: Mapping[str, Any],
    footprint_sizes: Mapping[str, Any],
    *,
    width_nm: int,
    height_nm: int,
    grid_nm: int = 250_000,
) -> str:
    """Render a minimal, deterministic KiCad PCB handoff for pcbex routing.

    The generated footprints are intentionally library-independent placeholders:
    their references, pad numbers, and net assignments are exact, while a real
    footprint library can replace their geometry later. This makes the circuit
    graph executable by headless placement/routing without executing untrusted
    model-produced Python.
    """

    spec = _spec_from_value(value)
    problem = circuit_spec_to_placement_problem(
        spec,
        footprint_sizes,
        width_nm=width_nm,
        height_nm=height_nm,
        grid_nm=grid_nm,
    )
    sizes = _sizes_by_key(footprint_sizes)
    net_ids = {net["name"]: index for index, net in enumerate(sorted(spec["nets"], key=lambda item: item["name"]), 1)}
    pin_nets = {
        (connection["reference"], connection["pin"]): net_ids[net["name"]]
        for net in spec["nets"]
        for connection in net["connections"]
    }
    pin_names = {
        part["reference"]: sorted(part["pins"], key=lambda pin: (len(pin), pin))
        for part in spec["parts"]
    }
    components = {component["reference"]: component for component in problem["components"]}
    lines = [
        "(kicad_pcb (version 20250114) (generator pcbex-text-to-circuit)",
        "  (general (thickness 1.6))",
        "  (paper \"A4\")",
        "  (layers (0 \"F.Cu\" signal) (31 \"B.Cu\" signal) (34 \"B.Mask\" user \"b.mask\") (35 \"F.Mask\" user \"f.mask\") (36 \"B.SilkS\" user \"b.silkscreen\") (37 \"F.SilkS\" user \"f.silkscreen\") (44 \"Edge.Cuts\" user))",
        "  (setup (pad_to_mask_clearance 0))",
        "  (net 0 \"\")",
    ]
    for name, net_id in sorted(net_ids.items(), key=lambda item: item[1]):
        lines.append(f"  (net {net_id} {_quote_kicad(name)})")

    margin_nm = max(grid_nm, 1_000_000)
    for index, part in enumerate(sorted(spec["parts"], key=lambda item: item["reference"])):
        reference = part["reference"]
        component = components[reference]
        width, height, metadata = _part_size(part, sizes)
        position = metadata.get("position")
        if not isinstance(position, Mapping):
            columns = max(1, (width_nm - margin_nm) // max(grid_nm, 1))
            x_nm = margin_nm + (index % columns) * max(grid_nm, 1)
            y_nm = margin_nm + (index // columns) * max(grid_nm, 1)
        else:
            x_nm = position.get("x_nm")
            y_nm = position.get("y_nm")
            if not isinstance(x_nm, int) or not isinstance(y_nm, int):
                raise CircuitSpecError(f"position for {reference} must use x_nm/y_nm integers")
        rotation = metadata.get("rotation_deg", 0)
        if isinstance(rotation, bool) or not isinstance(rotation, (int, float)):
            raise CircuitSpecError(f"rotation for {reference} must be numeric")
        locked = metadata.get("fixed", False)
        if not isinstance(locked, bool):
            raise CircuitSpecError(f"fixed flag for {reference} must be boolean")
        lock_clause = " (locked yes)" if locked else ""
        lines.extend([
            f"  (footprint {_quote_kicad(str(part['footprint']))} (layer \"F.Cu\") (at {_mm(x_nm)} {_mm(y_nm)} {rotation}){lock_clause}",
            f"    (fp_text reference {_quote_kicad(reference)} (at 0 0) (layer \"F.Fab\") hide)",
            f"    (fp_text value {_quote_kicad(str(part['value']))} (at 0 0) (layer \"F.Fab\") hide)",
        ])
        pins = pin_names[reference]
        for pin_index, pin in enumerate(pins):
            # Arrange placeholder pads on a deterministic horizontal grid. The
            # selected footprint library may later replace these geometries.
            pad_x = (pin_index - (len(pins) - 1) / 2) * min(1.0, max(width / 1_000_000 / max(len(pins), 1), 0.5))
            net_id = pin_nets[(reference, pin)]
            net_name = next(name for name, value in net_ids.items() if value == net_id)
            lines.append(
                f"    (pad {_quote_kicad(pin)} smd rect (at {pad_x:.6f} 0) (size 0.8 0.8) (layers \"F.Cu\" \"F.Paste\" \"F.Mask\") (net {net_id} {_quote_kicad(net_name)}))"
            )
        lines.append("  )")
    lines.append(
        f"  (gr_rect (start 0 0) (end {_mm(width_nm)} {_mm(height_nm)}) (stroke (width 0.05) (type default)) (fill none) (layer \"Edge.Cuts\"))"
    )
    lines.append(")")
    return "\n".join(lines) + "\n"


def _quote_kicad(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def skidl_to_placement_problem(
    circuit: Any,
    footprint_sizes: dict[str, tuple[int, int]],
    *,
    width_nm: int,
    height_nm: int,
    grid_nm: int,
) -> dict:
    """Convert SKiDL's public part/pin/net shape to the placement JSON model.

    SKiDL remains optional: callers pass a built circuit object, which keeps the
    core agent importable in environments that do not install EDA libraries.
    """
    components = []
    part_index: dict[int, str] = {}
    for part in circuit.parts:
        reference = str(part.ref)
        footprint = str(getattr(part, "footprint", ""))
        if footprint not in footprint_sizes:
            raise ValueError(f"missing dimensions for footprint {footprint!r}")
        width, height = footprint_sizes[footprint]
        components.append(
            {
                "reference": reference,
                "width_nm": width,
                "height_nm": height,
            }
        )
        part_index[id(part)] = reference

    connections = []
    for net in circuit.nets:
        pins = list(net.pins)
        if len(pins) < 2:
            continue
        anchor = pins[0]
        for pin in pins[1:]:
            connections.append(
                {
                    "from": {"component": part_index[id(anchor.part)]},
                    "to": {"component": part_index[id(pin.part)]},
                    "weight": 1.0,
                }
            )
    return {
        "width_nm": width_nm,
        "height_nm": height_nm,
        "grid_nm": grid_nm,
        "components": components,
        "connections": connections,
        "constraints": [],
    }
