# pcbex

`pcbex` is a deterministic PCB physical-design engine written in Rust. The
current implementation routes placed two-layer boards from a small, stable JSON
model. It uses integer nanometre coordinates and multi-layer A* with eight-way
movement, bend/via/congestion/proximity costs, clearance-inflated obstacles,
route simplification, and SVG inspection output.

The requirement-by-requirement evidence is recorded in
[`docs/COMPLETION_AUDIT.md`](docs/COMPLETION_AUDIT.md).

## Run

```sh
cargo run -p pcbex -- route examples/simple.json \
  --output simple.routed.json --svg simple.svg
cargo run -p pcbex -- check simple.routed.json
```

By default `route` fails when any net cannot be routed, making it suitable for
CI. Pass `--allow-unrouted` to retain a partial result. Every completed route is
checked internally for full copper-graph connectivity, orphan copper, supported
angles, track/via dimensions, board boundaries, obstacle clearance, and
cross-net copper clearance.

Routes already present in the JSON input are preserved and reserved while only
missing nets are routed. Running the router again on its output is therefore
idempotent.

## JSON model

All coordinates and dimensions use integer nanometres. Layers are `F.Cu` and
`B.Cu`. Obstacles are axis-aligned rectangles and are expanded internally by
half the track width plus clearance. Terminals declare the layers on which they
may be reached. See [`examples/simple.json`](examples/simple.json).

Optional `net_classes` define per-class track width, clearance, via dimensions,
and allowed layers. Assign a class by setting a net's `class` field. Routing and
internal rule checking both apply the class; unspecified nets use board defaults.

## KiCad boards

Route a placed KiCad board with a rectangular `Edge.Cuts` outline:

```sh
cargo run -p pcbex -- route-kicad examples/simple.kicad_pcb \
  --output simple.routed.kicad_pcb --svg simple.kicad.svg \
  --json-output simple.ipc-routes.json
```

The importer reads pad positions (including footprint rotation), copper layers,
net assignments, legacy board-embedded net classes, existing segments and vias.
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

## Scope

This foundation covers the routing core and headless KiCad exchange planned for
the first four sprints:
two copper layers, signal nets, rectangular outlines and obstacles, circular
through vias, horizontal/vertical/45-degree tracks, deterministic net ordering,
an unrouted-net report, `.kicad_pcb` I/O, optional KiCad DRC, HPWL placement,
overlap/boundary/congestion scoring, simulated annealing, and placement
constraints. Differential pairs, length matching, copper zones, and the AI
planner's external services remain outside the deterministic engine by design.
