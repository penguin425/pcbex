# Design completion audit

This audit maps the supplied `pcbex` design to executable evidence. The target
is the deliberately bounded MVP in that design: rectangular, placed, two-layer
signal boards with no differential-pair routing, length matching, or copper
zones.

| Requirement | Implementation | Evidence |
| --- | --- | --- |
| Rust core/CLI and Python agent separation | `pcbex-core`, `pcbex-kicad`, `pcbex-cli`, `pcbex_agent` | Workspace release build |
| Integer-nanometre model | `Point`, `Board`, `Footprint`, `Pad`, `Obstacle`, `Rules`, `Route`, `Via` | Serde models and round-trip tests |
| JSON single-net routing and SVG | Multi-layer A* and `render_svg` | `routes_around_obstacle`, `svg_is_produced` |
| 8-way tracks and path simplification | Directional A* state and segment coalescing | Internal checker enforces H/V/45-degree tracks |
| Width and clearance | Inflated fixed obstacles and expanded committed routes | `separate_nets_keep_clearance` |
| Multiple nets and ordering | Priority, terminal count, and span ordering | `routes_ten_signal_nets` |
| Two layers and through vias | Layer state, via transition cost, circular via output | `changes_layers_with_through_vias_when_front_is_blocked` |
| Layer-specific obstacles and keepouts | Layer-owned raster cells; KiCad keepout import | `imports_copper_keepout` |
| Rip-up/reroute and failure report | Four bounded full rip-up passes with history cost | `reports_unrouted_after_bounded_reroute_passes` |
| Pad ownership and off-grid access | Net-owned obstacles and exact orthogonal access tracks | `foreign_net_pad_blocks_but_own_pad_is_enterable`, `connects_off_grid_terminals_exactly` |
| Internal rule checking | Connectivity, angle, dimensions, boundaries, obstacles, copper clearance | `detects_cross_net_short`; every CLI route invokes it |
| KiCad input/output | Rectangular outline, rotated pads, footprints, tracks, vias, keepouts; board-level track/via output | Four `pcbex-kicad` tests |
| Headless KiCad validation | `route-kicad --drc` | KiCad 10.0.5: 0 violations, 0 unconnected pads |
| Manufacturing output | `fabricate` DRC gate plus Gerber/Excellon export | F/B copper, mask, silkscreen, Edge.Cuts, drill, job file generated |
| Interactive KiCad integration | Official `kicad-python` IPC adapter and one undoable commit | Mock transaction test and real wrapper-object serialization check |
| Placement scoring | HPWL, overlap, boundary, congestion, constraint penalties | Placement score improved from 560624 to 642 in the example |
| Placement search | Graph-clustered initial state, deterministic simulated annealing, move/rotate/swap, final snap | Placement unit tests |
| Placement constraints | `near` (including rotated named pins), `board_edge`, `keep_together` | Placement and agent tests |
| Natural-language planning | Deterministic English/Japanese parser plus schema-validated injected LLM adapter | Planner and LLM safety tests |
| SKiDL and part search boundaries | Optional SKiDL graph converter and injected catalog search | Adapter tests |
| DRC repair planning | KiCad 10 report normalization and rule-to-repair mapping | DRC normalization tests |
| Bounded repair and score comparison | Iteration/item limits and non-regression acceptance | Bounded executor test |

## Final verification commands

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --release
PYTHONPATH=agent/src python3 -m unittest discover -s agent/tests -v
cargo run -p pcbex -- route-kicad examples/simple.kicad_pcb \
  --output /tmp/pcbex-complete.kicad_pcb \
  --json-output /tmp/pcbex-complete-ipc.json --drc
cargo run -p pcbex -- fabricate /tmp/pcbex-complete.kicad_pcb \
  --output-dir /tmp/pcbex-complete-mfg
```

At audit time all 16 Rust tests and all 9 Python tests passed, the release build
completed, KiCad DRC reported zero violations and zero unconnected pads, and
all expected manufacturing layers plus the drill file were generated.
