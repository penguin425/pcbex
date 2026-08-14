# Circuit-spec to KiCad schematic handoff verification

The handoff gate verifies an already-authored KiCad schematic against a
closed circuit-spec v2 or v3 contract. It is a semantic verification boundary,
not a circuit or schematic generator: neither input is rewritten and no
library, supplier, or placement decision is made by this command.

This remains the v1.415 schematic-only contract.  v1.416 adds the separate
`verify-circuit-kicad-board-binding` gate, which recalculates this handoff from
the raw circuit and schematic before binding the result to the actual
`.kicad_pcb`; a previously retained handoff report is never accepted as a
substitute.  See [Circuit-spec v2 to KiCad schematic and board
binding](CIRCUIT_KICAD_BOARD_BINDING.md) for that three-way boundary.

## Contracts and commands

Discover the exact native JSON Schema before producing a handoff artifact:

```sh
pcbex circuit-kicad-handoff-schema --output circuit-kicad-handoff.schema.json
```

Verify a circuit specification and its KiCad schematic together:

```sh
pcbex verify-circuit-kicad-handoff \
  circuit-spec.json \
  hardware/controller.kicad_sch \
  --policy electrical-policy.json \
  --output build/circuit-kicad-handoff.json \
  --require-approved
```

`--policy` is optional and applies to the KiCad schematic review. The supplied
circuit specification always passes the immutable native ERC floor; a policy
cannot weaken that floor. `--output` is a report destination. The report is
retained before the command returns a rejection for `--require-approved`, so
CI can publish the reason for a failed gate. A caller that does not request
`--require-approved` can inspect the report and apply its own review policy.

The MCP server exposes the same boundary as
`verify_circuit_kicad_handoff`. Its arguments name the circuit specification,
schematic, optional policy, output report, and approval requirement. The tool
returns the retained report and its structured evidence when the gate rejects;
it does not silently discard a failed comparison.

## What is compared

The verifier normalizes both files and binds the result to source and
canonical identities. The report records the engine/schema identity, raw
source identities, canonical circuit-spec and schematic identities, the
effective policy identity, and the native ERC/check outcomes. The
stable report envelope exposes `schema_version`, `engine_version`,
`circuit_source_bytes`, `circuit_source_sha256`, `schematic_source_bytes`,
`schematic_source_sha256`, `circuit_spec_sha256`, `circuit_check_sha256`,
`circuit_review`, `schematic_sha256`, `schematic_review`, `policy_sha256`,
`findings`, `counts`, and `approved`. The exact native schema remains the
authority for nullable fields and finding details. `counts` aggregates the
handoff mismatches and both embedded ERC reviews; `findings` contains the
handoff-specific mismatch details, while the two review objects contain their
own electrical findings. The
normalized comparison is closed and intentionally small:

- exact `(reference, unit)` symbol membership (v2 fixes every unit to 1);
- exact symbol identity and reference/value metadata;
- exact pin identities, pin numbers, electrical types, and net membership;
- exact explicit net-label sets, canonical voltage labels, and complete pin
  membership;
- exact footprint metadata where it is present in the circuit contract; and
- the declared `pcbex` circuit metadata needed to bind the two representations.

The circuit check and imported schematic identities are calculated from their
canonical representations. Drawing geometry, positions, orientations,
graphical styling, and KiCad UUIDs are ignored by the semantic comparison, so
a harmless redraw does not create a logical mismatch. The actual source bytes
and their SHA-256 identities remain in the report to make the exact verified
inputs auditable.

When a circuit net name differs from its canonical voltage label, both labels
must be present on the same KiCad net. The default policy treats that pair as
an advisory multiple-name finding, so it can still be approved. A custom
policy that elevates `multiple_net_names` to an error deliberately rejects the
pair; use the canonical voltage label as the circuit net name when that strict
policy is required.

Both sides still pass the native electrical checks. A semantic match is not
an approval by itself: an ERC finding, a missing/extra symbol,
pin, net, footprint, or metadata value keeps the report rejected. The
immutable native ERC safety floor cannot be disabled by a policy or by an
AI-generated candidate.

Malformed, non-UTF-8, oversized, or unsupported inputs fail before a handoff
report exists. Once both contracts have been imported, semantic or ERC
rejection retains the report before `--require-approved` returns failure.

## Deliberate boundary

The handoff contract rejects or leaves unresolved anything outside the
closed subset. It does not currently support:

- hierarchical sheets, buses, power-symbol extras, interchangeable unit
  reassignment, hidden shared pins, or alternate symbol conversions;
- unresolved library links or live supplier/datasheet lookup;
- automatic symbol/footprint generation or circuit-to-KiCad conversion;
- component placement, board geometry, routing, DRC, fabrication, Gerber,
  BOM/CPL, or factory submission.

Those are separate gates. For v3, a passing handoff proves the exact declared
unit and package-pin membership in addition to the existing circuit intent; it
does not authenticate a library or datasheet. The schematic must still pass
the complete PCB, manufacturing, and approval pipeline before production.

The v1.416 board-binding gate is intentionally not folded into this command,
the v1/v2 `pipeline-verify` reports, or the existing pipeline phases. Invoke it
explicitly when the board must be bound to the already-verified schematic, or
use the v1.417
[bounded-input deterministic runner](DETERMINISTIC_PIPELINE_RUNNER.md) to
recompute it beside the unchanged pipeline gate from one authorized snapshot.
