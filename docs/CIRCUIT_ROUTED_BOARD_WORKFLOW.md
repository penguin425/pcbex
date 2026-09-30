# Circuit to routed KiCad board workflow

`pcbex generate-circuit-kicad-routed-board` generates a schematic, places a new
board, performs bounded convergence routing, and independently replays the
electrical binding and routing evidence. It publishes one new bundle only when
routing is complete and the internal checks pass. This CLI-only workflow uses
local, explicit inputs and does not invoke an AI provider or KiCad itself.

## Generate a verified routing bundle

Create a trusted output parent first. On Unix it must be owned by the effective
user and must not be writable by group or other users.

```sh
mkdir -p build
pcbex generate-circuit-kicad-routed-board \
  examples/circuit-board-spec-v2.json \
  --footprint-closure examples/circuit-board-footprint-closure-v1.json \
  --construction-profile examples/circuit-board-construction-profile-v1.json \
  --physical-profile examples/circuit-board-physical-profile-v1.json \
  --output-dir build/routed-circuit
```

Circuit-spec v2 and explicit multi-unit v3 use the same command. The immutable
ERC floor must accept the specification; this electrical decision does not
constitute human or AI approval. The default electrical policy is fixed for
this initial workflow.

The footprint closure, construction profile, and physical profile follow the
same closed contracts and geometric limits as the
[KiCad Board Writer](CIRCUIT_KICAD_BOARD_WRITER.md). All four input files are
captured before generation and re-read by identity and exact bytes before
publication. Aliases and symbolic-link path components are refused.

## Routing conditions and budgets

All seven `routing_defaults` from the construction profile become the effective
`Rules`: grid, track width, clearance, via diameter, via drill, bend cost, and
via cost. They stay as integer nanometres and costs; there is no nm to mm
round trip and no individual routing override. The physical profile is also
applied to the effective routing board, including constraints not represented
in KiCad text. The workflow does not discover sibling `.kicad_pro` or
`.kicad_dru` files or load installed footprint libraries.

The five optional convergence controls have the existing bounds:

| Option | Default | Accepted range |
| --- | ---: | ---: |
| `--convergence-rounds` | 3 | 1 to 8 |
| `--convergence-candidates` | 5 | 1 to 32 |
| `--convergence-workers` | 4 | 1 to 8 |
| `--convergence-router-workers` | 2 | 1 to 8 |
| `--convergence-work-budget` | 2,000,000 | Number of declared candidate slots to 2,000,000 |

Candidate workers times router workers may not exceed 16. The work budget is
a deterministic A* allocation, not a wall-clock deadline. A fresh replay runs
the same bounded allocation again; the limit does not cover both passes as one
combined budget. See [Routing Convergence](ROUTING_CONVERGENCE.md) for selection
rules and work accounting.

Partial routing or no admissible candidate causes a nonzero exit without
publishing the output directory. There is no `--allow-unrouted` option. The
workflow never relaxes clearance, construction rules, or manufacturing minima
to obtain a complete result.

## Retained files and manifest

A successful output directory contains exactly fourteen regular files:

| Files | Purpose |
| --- | --- |
| `circuit-spec.json`, `footprint-closure.json`, `construction-profile.json`, `physical-profile.json` | Exact caller input bytes, including original whitespace |
| `circuit.kicad_sch` | Generated schematic |
| `board.placed.kicad_pcb`, `board.placed-binding.json`, `board.placed-manifest.json` | Original placed board and unchanged board producer evidence |
| `board.kicad_pcb` | Completely routed final board |
| `circuit-handoff.json`, `board-binding.json` | Fresh schematic handoff and final routed board binding |
| `routing-convergence.json`, `routing-verification.json` | Canonical convergence decisions and independent exact replay |
| `manifest.json` | Closed workflow manifest |

The workflow manifest binds all four raw snapshots and nine generated outputs
by byte count and SHA-256, preserves normalized input identities, and records
the effective rules, convergence options, and final verification binding
digests. Its `status` is `verified_complete`. The placed producer manifest
still describes the placed, unrouted input; it is not a manifest for the final
routed board.

Inspect the public schema without running generation:

```sh
pcbex circuit-kicad-routed-board-manifest-schema \
  --output circuit-kicad-routed-board-manifest-v1.schema.json
```

The manifest is path-free and contains no timestamps or randomness. The same
four exact inputs and convergence options reproduce the same fourteen byte
streams with the same compiled executable on the same supported target.
Cross-target floating-point identity and executable provenance are not claimed.

## Independently replay the evidence

The retained snapshots are sufficient for the existing fresh verifiers. For
the example profile above:

```sh
pcbex verify-circuit-kicad-board-binding \
  build/routed-circuit/circuit-spec.json \
  build/routed-circuit/circuit.kicad_sch \
  build/routed-circuit/board.kicad_pcb \
  --output build/fresh-board-binding.json --require-approved

pcbex verify-kicad-routing-convergence \
  build/routed-circuit/board.placed.kicad_pcb \
  --routed build/routed-circuit/board.kicad_pcb \
  --report build/routed-circuit/routing-convergence.json \
  --physical-profile build/routed-circuit/physical-profile.json \
  --grid-mm 0.1 --width-mm 0.25 --clearance-mm 0.2 \
  --via-diameter-mm 0.66 --via-drill-mm 0.3 --bend-cost 5 --via-cost 50 \
  --output build/fresh-routing-verification.json --require-complete
```

Use the actual retained construction defaults for other profiles. These
commands replay their individual reports, not a whole-bundle authenticity
check. A manifest digest identifies content; it does not establish its source.

## Publication and downstream gates

The workflow builds the complete bundle in private staging, validates its
exact inventory and bytes, rechecks every caller input, and publishes with the
existing no-replace directory boundary. An occupied destination is preserved.
A failure before rename leaves no output directory. A failure during checks or
synchronization after rename may leave the directory present; the diagnostic
explicitly prohibits consuming it. A concurrent process with the same OS
identity and access to the trusted parent remains outside this guarantee.

`internal_rule_check_verified` is true. `native_kicad_drc_verified`,
`manufacturability_verified`, `human_approval_verified`,
`source_authenticity_verified`, and `release_authorized` are false. Run native
KiCad DRC and the applicable DFM, deterministic pipeline, manufacturing, and
authorization gates separately before fabrication. This command does not
create Gerbers, prove signal integrity, authorize procurement, or place orders.
Existing single-step commands and their partial-result semantics are unchanged.
MCP and Composite Action parity for this producer are not included.
