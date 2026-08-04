# Circuit-spec v2 to KiCad schematic and board binding

The v1.416 gate verifies one closed `circuit-spec-v2` document against the
actual KiCad schematic and the actual `.kicad_pcb` board that are intended to
implement it.  It is a standalone Rust API/CLI/MCP boundary.  It recalculates
the v1.415 schematic handoff from the raw circuit and schematic inputs, then
binds that result to the raw board; a copied handoff report is never treated as
evidence.  The gate does not rewrite either input and does not invoke the
pipeline runner.

## Contracts and commands

Emit the exact closed native report schema before producing an artifact:

```sh
pcbex circuit-kicad-board-binding-schema \
  --output circuit-kicad-board-binding.schema.json
```

Verify a circuit specification, schematic, and board together:

```sh
pcbex verify-circuit-kicad-board-binding \
  circuit-spec-v2.json \
  hardware/controller.kicad_sch \
  hardware/controller.kicad_pcb \
  --policy electrical-policy.json \
  --output build/circuit-kicad-board-binding.json \
  --require-approved
```

`--policy` is optional and applies to the recalculated schematic review.  The
circuit specification still passes the immutable native circuit/ERC floor; a
policy cannot weaken that floor.  `--output` is a no-clobber report destination.
With `--require-approved`, a semantic or review rejection is reported only
after the retained report has been written, so CI can publish the evidence.

The MCP server exposes the same operation as
`verify_circuit_kicad_board_binding`.  Its closed arguments require the raw
`circuit_spec`, `schematic`, `board`, and `output`; `policy` and
`require_approved` are optional.  The tool returns the complete report and
structured findings on rejection instead of discarding a failed comparison;
its text content is a bounded summary so the report is not duplicated inside
the 16 MiB MCP frame.  API consumers should use the native schema emitted by
`circuit-kicad-board-binding-schema`; field nullability and finding details are
not inferred from this document.

## Three-way identity and comparison

The gate records three identity layers for every accepted input:

1. exact source byte counts and SHA-256 digests for the circuit JSON, KiCad
   schematic, and `.kicad_pcb`;
2. canonical digests for the normalized circuit/check and imported schematic
   inside `circuit_kicad_handoff`, plus the geometry-free
   `board_electrical_sha256`; and
3. `binding_sha256`, which domain-separates the recomputed handoff identity,
   exact board-source identity, board-electrical identity, and closed findings.

The report also retains the recalculated circuit and schematic reviews.  Its
findings are deterministic: the same bytes, policy, and engine produce the
same closed finding objects in stable order, independent of parser traversal
order.  These digests establish identity and integrity, not producer
signatures or fabrication authorization.

The strict comparison binds the following semantic data:

- each circuit reference to exactly one schematic symbol and board footprint;
- exact reference, schematic-declared footprint identifier, value, MPN,
  BOM/DNP state, and board presence, with missing, extra, or duplicate records
  rejected;
- every declared pin to the board pad with the exact pad number, net, and
  explicit no-connect state;
- every net's canonical name and complete terminal membership, including
  missing, extra, duplicate, and merged nets; numeric KiCad net IDs are only
  local lookup keys and may be renumbered without changing electrical identity;
  and
- every footprint and pad's declared ownership, including missing, extra, or
  duplicate footprints/pads.

Raw terminal-less nets are not silently dropped.  Duplicate net IDs/names are
malformed board input because they make pad resolution ambiguous; they fail
before a semantic report is possible.  Net `0` (KiCad's no-net
identity) is a reserved board identifier, not a circuit net terminal; it is
still validated and retained as part of the closed board import.  Board-net
matching uses the canonical net names obtained from the imported schematic,
not labels invented from the circuit JSON.  A schematic no-connect pin must
map to its same-numbered unconnected board pad; an absent net field and an
explicit `(net 0 "")` both mean unconnected.  Beyond those declared pins, the
only permitted extra unnumbered pad is an empty, unconnected NPTH mechanical
pad.  A numbered NPTH pad cannot implement a circuit pin.  Mapping a connected
circuit terminal to no net, or retaining any other unbound pad, is a
deterministic rejection.

The binding recalculates the v1.415 handoff from the source files before board
comparison.  A valid schematic-only handoff therefore does not imply a valid
board binding; all three raw inputs and their canonical identities must agree.

## Closed subset and rejection behavior

Only the strict flat/single-unit subset is accepted.  Hierarchical or nested
schematics, buses, multi-unit symbols, unsupported library constructs, and
other incomplete handoff coverage are rejected rather than flattened or
silently ignored.  Extra or missing symbols, footprints, pads, nets, pin/pad
connections, no-connect states, or metadata fail closed.  Geometry-only
differences do not establish a board binding, but this gate intentionally does
not evaluate geometry.

Malformed, non-UTF-8, oversized, or symlinked inputs fail within the bounded
input policy. Unsupported circuit/schematic handoff coverage and malformed
binding-relevant board fields also fail closed.  Every pad must have a supported
KiCad type and shape, positive bounded size, one canonical layer set containing
declared copper, and a valid type-appropriate drill; supported custom pads must
contain the same bounded polygon primitive accepted by the native importer.
Unknown top-level placement/routing/graphics constructs remain ignored because
their geometry is outside this gate.  The output path is checked for aliases,
symlinks, and existing entries before work starts; no existing report is
overwritten.  Once all three raw contracts have been imported, a rejected
comparison is published atomically and retained before `--require-approved`
returns failure.

The board input is capped at 128 MiB and the compact report at 12 MiB.  Exceeding
the report cap is a resource-contract error rather than a semantic rejection,
so no partial or truncated report is published.  The CLI stores board-binding
reports as compact JSON to keep the retained file, MCP child output, and parsed
structured result under their aligned limits.

## Deliberate boundary

This is an electrical/identity binding gate, not a board-quality or production
gate.  It does not perform placement or footprint geometry checks, routing
verification, DRC, DFM, Gerber/BOM/CPL generation, supplier lookup, hierarchy
flattening, bus analysis, or multi-unit expansion. Existing `pipeline-verify`
v1 and v2 reports and phases are unchanged and do not consume this report.
Version 1.417's bounded-input deterministic runner recomputes this gate from
the same privately staged raw files and nests the resulting report beside the
unchanged pipeline report; it never treats a copied board-binding report as an
input. See [Bounded-input deterministic pipeline runner](DETERMINISTIC_PIPELINE_RUNNER.md).
