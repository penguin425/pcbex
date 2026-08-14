# Multi-unit circuit-spec v3

Model multiple KiCad symbol units without duplicating the physical part.

Circuit-spec v3 is an opt-in extension to the closed v2 circuit boundary. It
keeps one part per reference, nests explicit units beneath that part, and binds
every net connection to `(reference, unit, pin)`.

> [!NOTE]
> Circuit-spec v2 remains wire-compatible and existing v2 documents need no
> migration. Provider-driven natural-language generation and the compatibility
> SKiDL adapter still emit v2; choose v3 only when the source design needs
> explicit KiCad units. Version-stamped generated evidence naturally records
> the installed pcbex release.

## Quick start

Validate the example, write a schematic, then verify the exact handoff:

```sh
pcbex check-circuit-spec examples/circuit-board-spec-v3.json \
  --output build/circuit-v3.check.json \
  --require-approved

pcbex write-circuit-spec-kicad-schematic \
  examples/circuit-board-spec-v3.json \
  --output build/circuit-v3.kicad_sch

pcbex verify-circuit-kicad-handoff \
  examples/circuit-board-spec-v3.json \
  build/circuit-v3.kicad_sch \
  --output build/circuit-v3.handoff.json \
  --require-approved
```

Need machine-readable contracts? Emit them directly:

```sh
pcbex circuit-spec-v3-schema --output build/circuit-spec-v3.schema.json
pcbex circuit-spec-v3-check-schema --output build/circuit-spec-v3-check.schema.json
```

Schema files use atomic no-clobber publication. Choose a new output path for
each write.

## Wire model

The outer shape stays familiar. Only parts and connections become unit-aware.

| Field | Meaning |
| --- | --- |
| `parts[].reference` | One physical component identity, such as `U1` |
| `parts[].units[].unit` | KiCad unit number from 1 through 255 |
| `parts[].units[].pins[]` | Pins visible on that symbol unit |
| `nets[].connections[]` | Exact `reference`, `unit`, and physical `pin` tuple |

```json
{
  "schema_version": 3,
  "parts": [
    {
      "reference": "U1",
      "lib_id": "Amplifier_Operational:DUAL",
      "value": "DUAL",
      "footprint": "Package_SO:SOIC-8",
      "mpn": null,
      "power": {
        "rail_voltage_uv": null,
        "max_voltage_uv": null,
        "requires_decoupling": false,
        "decoupling": false
      },
      "units": [
        {"unit": 1, "pins": [{"number": "1", "name": "OUTA", "net": "A", "electrical_type": "passive"}]},
        {"unit": 2, "pins": [{"number": "7", "name": "OUTB", "net": "B", "electrical_type": "passive"}]}
      ]
    }
  ],
  "nets": []
}
```

The fragment illustrates the unit shape only. A valid document must contain at
least one net, and every net must have at least two exact connections; use the
checked-in [complete example](../examples/circuit-board-spec-v3.json) as a
copyable starting point.

## Safety invariants

- **Bind every unit:** Unit numbers are unique per physical reference and stay
  attached to every schematic symbol and net terminal.

- **Keep package pins unique:** A physical pin number may appear in only one
  unit of a part. This makes the later board projection lossless.

- **Close every connection:** A pin's declared `net` must match exactly one
  net connection. No-connect pins must use `net: null` and cannot appear in a
  net.

- **Bound the graph:** A part has at most 32 units, a document has at most
  4,096 units, and one physical part still has at most 256 package pins. The
  existing document-wide pin, net, connection, text, and byte ceilings also
  apply.

- **Run the same electrical floor:** v3 converts to the same electrical IR and
  cannot weaken immutable ERC errors.

## KiCad mapping

The writer embeds one library container for each `lib_id`, then adds one
unit-specific definition per declared unit. Each `(reference, unit)` becomes a
separate KiCad symbol instance with a stable domain-separated UUID.

KiCad still treats those instances as one physical component. The release E2E
opens the generated document with KiCad 10, exports its native netlist, and
requires one component record plus the complete cross-unit pin membership.

The handoff verifier performs the inverse check. It compares exact unit number,
convert, pin definition, component metadata, net labels, voltage labels, and
terminal membership while continuing to ignore drawing geometry and random
KiCad UUID choices.

## Board and manufacturing projection

Board-facing formats need one footprint, not one footprint per symbol unit.
After v3 validation proves global package-pin uniqueness, pcbex flattens the
unit pins into the unchanged physical v2-shaped part inventory.

That projection feeds board binding, deterministic board generation, BOM, CPL,
and manufacturing consumers. The original v3 canonical digest remains in the
handoff and board manifest, so the physical projection does not erase source
identity.

> [!IMPORTANT]
> Unit-aware verification does not prove that a caller-selected `lib_id`,
> footprint, symbol drawing, pin assignment, datasheet, or supplier record is
> authentic. Use reviewed local sources and retain the normal board,
> manufacturing, and authorization evidence.

## Deliberate limits

v3 does not add hierarchical sheets, buses, automatic library discovery,
interchangeable-unit reassignment, hidden shared pins, alternate De Morgan
conversions, graphical symbol fidelity, or live schematic editing. It writes a
new deterministic logical handoff artifact.

It also does not change the natural-language generation contract. A future
provider boundary can emit v3 only after it gains equivalent bounded correction,
schema, and regression coverage; v1.473 keeps that expansion separate.
