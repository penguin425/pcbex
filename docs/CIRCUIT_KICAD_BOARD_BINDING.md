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

For bounded subprocess bridges, the hidden `--mcp-echo-report-summary` option
requires `--output` and emits only a closed numeric/digest summary after the
full report has been atomically retained. It is mutually exclusive with the
hidden full `--mcp-echo-report` option. The summary authenticates the retained
report bytes and source/electrical/binding identities without copying the
12 MiB report through a 1 MiB child-stdout channel; it does not replace the
full report as the retained evidence.

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

Raw terminal-less nets are not silently dropped. The board date-code selects
the native net dialect: versions before `20251028` retain the legacy top-level
numeric table and exact ID/name cross-checks, while versions at or after that
cutoff use KiCad 10's quoted name-only fields and must not contain a legacy
table. The modern net inventory includes pads, segments, arcs, vias, zones,
and connected board/footprint graphics; this preserves `extra_net` detection
even when a net exists only on routed copper. Connected fields are valid only
at their native board/footprint ancestry, so wrapping a supported object in an
unknown container cannot contribute a net. Quoted and unquoted atoms remain
distinct where the dialect needs that distinction: numeric IDs are always
unquoted, modern names are quoted, and legacy names retain their native scalar
compatibility while being cross-checked exactly against the table. The two
dialects cannot be mixed. Duplicate IDs or names in the legacy top-level net
table are malformed because they make pad resolution ambiguous; they fail
before a semantic report is possible. A legacy zone's optional `net_name` must
match its numeric ID exactly; modern or out-of-context `net_name` fields are
rejected. Repeated references to one quoted name across modern connected
objects are expected and collapse to one semantic net. Net `0` (KiCad's no-net
identity) is explicit and checked in the legacy dialect; the modern dialect
makes that unconnected state implicit through an absent net field or KiCad's
quoted empty net on a free segment, arc, or via. Board-net
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
Unknown placement/routing/graphics geometry remains ignored because its shape
is outside this gate, but a net field in an unsupported context fails closed
instead of being used to complete the electrical inventory. The output path is
checked for aliases, symlinks, and existing entries before work starts; no
existing report is overwritten. Once all three raw contracts have been
imported, a rejected comparison is published atomically and retained before
`--require-approved` returns failure.

The board input is capped at 128 MiB and the compact canonical report at
12 MiB (12 MiB plus one byte when rendered with its required newline).
Exceeding the report cap is a resource-contract error rather than a semantic
rejection, so no partial or truncated report is published. The CLI stores
board-binding reports as compact JSON to keep the retained file, MCP child
output, and parsed structured result under their aligned limits.

## Retained-board replay in a circuit handoff (v1.454)

The standalone gate remains the authority for the board's geometry-free
electrical binding.  `replay-circuit-handoff-bundle` can optionally invoke that
gate against the exact reproduced `circuit-spec-v2.json` and
`circuit-spec.kicad_sch`, a retained `--kicad-board`, and a retained
`--board-binding-report`.  Those two retained sources are required together;
an optional `--board-binding-policy` is the exact custom policy source for the fresh replay, while
omission uses the standalone gate's built-in policy.  The optional
`--require-board-binding-approved` failure is deferred until fresh report
bytes, closed report shape, source identities, and all final rereads pass.

The handoff replay stable-reads the board (128 MiB), compact report (12 MiB
canonical JSON plus its one trailing newline), and optional policy (4 MiB;
all three sources 144 MiB plus one byte aggregate) before any producer child.
After the unchanged
six-entry archive and any independently requested native-ERC, AI, and catalog
assertions finish, it invokes the existing CLI verifier with a private output
destination.  The fresh compact report must equal the retained report bytes
exactly, including its trailing newline; the full report is not transported in
Python child stdout.  Board, report, and policy are reread after the child and
must remain byte-identical.  The existing one monotonic 1–600 second replay
deadline (default 120 seconds) supplies the remaining time to this child; the
standalone board command itself has no timeout option.

The retained report binds the normalized effective policy rather than the
historical policy file's raw JSON serialization. The v5 evidence exposes that
effective `policy_sha256` and separately records the exact raw custom-policy
source used for this fresh replay when one is supplied. Semantically equivalent
policy JSON can therefore reproduce the same retained report; this replay does
not claim byte identity with the original historical policy source.

The v5 path-free replay result has scope
`deterministic-electrical-handoff-chain-board-binding-replay-v5`; its
`board_binding` object carries only the bounded retained-report schema and
engine metadata, decision/approval metadata,
compact finding counts, and byte/SHA-256 identities for the board and report,
plus board-electrical, circuit-handoff, binding, and effective-policy
identities. The object is closed schema-v1 with `counts`, `board`, `report`,
optional raw replay-source `policy` (`null` for the built-in policy),
`policy_sha256`, and the three electrical/handoff/binding SHA-256 identities.
`validation.board_binding_replayed` is true.
It contains no host
paths or raw sidecar bodies. This result proves exact
electrical binding to the retained board artifact, not layout approval:
placement and footprint geometry, copper/routing/zones, PCB DRC/DFM,
Gerber/BOM/CPL, manufacturing/fabrication, procurement, supplier state, and
KiCad/pcbex/tool provenance remain outside the claim.  Geometry-only board
changes may leave `board_electrical_sha256` unchanged while changing raw and
binding identities, so they are not accepted as an equivalent retained replay.

With no v1.454 board options, the prior v1–v4 replay result bytes, schemas,
archive bytes, and canonical six-entry ZIP remain unchanged.  Board evidence
is a sidecar and never becomes a seventh archive entry or a new pipeline phase.

## Deliberate boundary

This is an electrical/identity binding gate, not a board-quality or production
gate.  It does not perform placement or footprint geometry checks, routing
verification, DRC, DFM, Gerber/BOM/CPL generation, supplier lookup, hierarchy
flattening, bus analysis, or multi-unit expansion. It does not establish
manufacturing or fabrication approval, procurement authority, or toolchain
provenance. Existing `pipeline-verify`
v1 and v2 reports and phases are unchanged and do not consume this report.
Version 1.417's bounded-input deterministic runner recomputes this gate from
the same privately staged raw files and nests the resulting report beside the
unchanged pipeline report; it never treats a copied board-binding report as an
input. See [Bounded-input deterministic pipeline runner](DETERMINISTIC_PIPELINE_RUNNER.md).
Version 1.463's explicit [KiCad board writer](CIRCUIT_KICAD_BOARD_WRITER.md)
also invokes this unchanged gate against its exact generated board and refuses
publication unless it is approved. The writer's separate footprint,
construction, placement, and raw-byte evidence does not broaden this report's
geometry-free approval meaning.
