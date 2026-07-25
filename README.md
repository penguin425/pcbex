# pcbex

[![CI](https://github.com/penguin425/pcbex/actions/workflows/ci.yml/badge.svg)](https://github.com/penguin425/pcbex/actions/workflows/ci.yml)

`pcbex` is a deterministic PCB physical-design engine written in Rust. The
current implementation routes placed two-layer boards from a small, stable JSON
model. It uses integer nanometre coordinates and multi-layer A* with eight-way
movement, bend/via/congestion/proximity costs, clearance-inflated obstacles,
route simplification, Steiner-style multi-terminal branching, and SVG
inspection output.

The requirement-by-requirement evidence is recorded in
[`docs/COMPLETION_AUDIT.md`](docs/COMPLETION_AUDIT.md).

## Run

```sh
cargo run -p pcbex -- route examples/simple.json \
  --output simple.routed.json --svg simple.svg
cargo run -p pcbex -- check simple.routed.json
```

Generate completion definitions for Bash, Zsh, Fish, Elvish, or PowerShell:

```sh
pcbex completion bash > ~/.local/share/bash-completion/completions/pcbex
pcbex completion zsh > "${fpath[1]}/_pcbex"
pcbex completion fish > ~/.config/fish/completions/pcbex.fish
```

By default `route` fails when any net cannot be routed, making it suitable for
CI. Pass `--allow-unrouted` to retain a partial result. Every completed route is
checked internally for full copper-graph connectivity, orphan copper, supported
angles, track/via dimensions, board boundaries, obstacle clearance, and
cross-net copper clearance. These checks use integer geometry predicates,
including exact collinear overlap, endpoint contact, and clearance-boundary
comparisons without floating-point rounding.

Routes already present in the JSON input are preserved and reserved while only
missing nets are routed. Running the router again on its output is therefore
idempotent.

For nets with three or more terminals, the router chooses a central root and
repeatedly connects the cheapest remaining terminal to any point in the routed
tree. This avoids the input-order-dependent detours of terminal-to-terminal
chain routing.

When a net cannot be routed, the failed A* search records which committed nets
blocked its frontier. Only those conflicting routes are ripped up and retried,
with the failed net ordered first; unrelated and imported locked routes remain
in place. The route report separates preserved, newly routed, rerouted, and
unrouted nets and includes the number of rip-up events.

## JSON model

All coordinates and dimensions use integer nanometres. Layers are `F.Cu` and
`B.Cu`. An optional ordered `outline` defines a simple, concave or convex board
polygon; an empty outline uses the width/height rectangle. `keepouts` use exact
polygons and layer sets, while legacy `obstacles` remain axis-aligned
rectangles. Copper envelopes are expanded by width/via radius plus clearance.
Terminals declare the layers on which they may be reached. See
[`examples/simple.json`](examples/simple.json).

Optional `net_classes` define per-class track width, clearance, via dimensions,
and allowed layers. Assign a class by setting a net's `class` field. Routing and
internal rule checking both apply the class; unspecified nets use board defaults.

## KiCad boards

Route a placed KiCad board with a closed, straight-segment `Edge.Cuts` outline:

```sh
cargo run -p pcbex -- route-kicad examples/simple.kicad_pcb \
  --output simple.routed.kicad_pcb --svg simple.kicad.svg \
  --json-output simple.ipc-routes.json
```

[`examples/nonrect.kicad_pcb`](examples/nonrect.kicad_pcb) demonstrates a
five-sided outline that routes and passes KiCad DRC.
[`examples/keepout.kicad_pcb`](examples/keepout.kicad_pcb) exercises a
polygonal copper keepout and an embedded net class. CI routes all three example
boards twice with KiCad 10, requires zero DRC violations, checks that the second
pass is byte-for-byte idempotent, and retains routed boards and DRC reports as
workflow artifacts.

The importer reads polygonal board outlines and copper keepouts without reducing
them to bounding boxes, plus pad positions (including footprint rotation).
Circular pads retain their exact copper envelope instead of being expanded to
their bounding rectangles. Oval pads are represented as rotated capsule shapes
and use exact segment-to-capsule clearance. The importer also reads
copper layers, net assignments, legacy board-embedded net classes, existing
segments and vias.
Fully connected existing nets are preserved as locked routes; incomplete copper
remains an obstacle and is not mistaken for a completed route. Generated tracks
and through vias are appended at board level without duplicating locked routes,
while preserving the source document.
Use `--drc` to run `kicad-cli pcb drc` on the result when KiCad is installed.
After DRC passes, generate Gerber and Excellon drill files with:

```sh
cargo run -p pcbex -- fabricate simple.routed.kicad_pcb \
  --output-dir manufacturing
```

## Component placement

The placement engine combines graph-clustered initialization with deterministic
simulated annealing. Its score covers weighted HPWL, overlap area, board
boundary overflow, coarse routing congestion, and declarative constraints.

```sh
cargo run -p pcbex -- place examples/placement.json \
  --output placement.result.json --iterations 20000
```

Components may be fixed, moved on the placement grid, swapped, or rotated by 90
degrees. Supported constraints are `near`, `board_edge`, and `keep_together`.

## Planning and repair agent

The dependency-free Python agent converts bounded natural-language requirements
to an auditable JSON plan. It does not choose coordinates: only the
deterministic Rust engines may change physical design state.

```sh
PYTHONPATH=agent/src python -m pcbex_agent plan examples/requirements.txt \
  --output plan.json
PYTHONPATH=agent/src python -m pcbex_agent apply-constraints \
  examples/placement.json plan.json --output planned-placement.json
```

The agent also normalizes KiCad DRC reports, maps violations to repair actions,
limits repair iterations and changed components, and accepts a candidate only
when its score does not regress. Unrecognized prose is surfaced explicitly
instead of being guessed. Optional adapters accept an injected LLM transport,
convert a built SKiDL circuit into the placement graph, and search an injected
component catalog. None of these adapters can write coordinates directly.
With `pcbex-agent[kicad]` installed and KiCad's IPC API enabled, routed JSON can
also be applied to the open editor as one undoable transaction:

```sh
pcbex-agent apply-ipc simple.ipc-routes.json
```

For a headless repair run, the agent generates bounded routing candidates,
executes KiCad DRC after each one, rejects repeated or unsupported repairs, and
atomically publishes only a DRC-clean board:

```sh
pcbex-agent repair-kicad input.kicad_pcb \
  --output repaired.kicad_pcb --report repair.json \
  --pcbex target/release/pcbex --max-iterations 4
```

The JSON report records every iteration, remaining errors and warnings, repair
actions, the stop reason, and the best observed error count.

## Releases

Pushing a semantic-version tag from `main` creates a GitHub Release:

```sh
git switch main
git pull --ff-only
git tag -a v0.1.0 -m "pcbex v0.1.0"
git push origin v0.1.0
```

The tag must match both the workspace version in `Cargo.toml` and the agent
version in `agent/pyproject.toml`. The release workflow runs all Rust and Python
checks, then publishes CLI archives for Linux x64, macOS Intel and Apple
Silicon, and Windows x64. Each archive includes a SHA-256 checksum and an SPDX
SBOM, and has signed GitHub build-provenance and SBOM attestations. Verify a
downloaded archive with:

```sh
gh attestation verify pcbex-v0.1.2-x86_64-unknown-linux-gnu.tar.gz \
  --repo penguin425/pcbex
```

If a build fails, the release remains a draft and the workflow can be rerun
safely.

## Scope

This foundation covers the routing core and headless KiCad exchange planned for
the first four sprints:
two copper layers, signal nets, polygonal straight-edge outlines and keepouts,
rectangular component obstacles, circular
through vias, horizontal/vertical/45-degree tracks, deterministic net ordering,
an unrouted-net report, `.kicad_pcb` I/O, optional KiCad DRC, HPWL placement,
overlap/boundary/congestion scoring, simulated annealing, and placement
constraints. Differential pairs, length matching, copper zones, and the AI
planner's external services remain outside the deterministic engine by design.
