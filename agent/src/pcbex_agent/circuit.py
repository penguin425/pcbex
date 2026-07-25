from __future__ import annotations

from typing import Any


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
