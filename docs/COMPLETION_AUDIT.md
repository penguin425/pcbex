# Design completion audit

This audit maps the supplied `pcbex` design and subsequent extensions to
executable evidence. The project began with the deliberately bounded,
rectangular two-layer MVP and now supports polygonal multilayer signal boards,
coupled differential-pair routing, and native KiCad copper-zone generation.

| Requirement | Implementation | Evidence |
| --- | --- | --- |
| Rust core/CLI and Python agent separation | `pcbex-core`, `pcbex-kicad`, `pcbex-cli`, `pcbex_agent` | Workspace release build |
| Integer-nanometre model | `Point`, `Board`, `Footprint`, `Pad`, `Obstacle`, `Rules`, `Route`, `Via` | Serde models and round-trip tests |
| Versioned JSON contract | Draft 2020-12 schema, `schema_version`, v1 aliases, strict unknown-field/future-version diagnostics, and migrate CLI | Legacy width/height/signals migration and rejection regressions |
| JSON single-net routing and SVG | Multi-layer A* and `render_svg` | `routes_around_obstacle`, `svg_is_produced` |
| 8-way tracks and path simplification | Directional A* state and segment coalescing | Internal checker enforces H/V/45-degree tracks |
| Width and clearance | Inflated fixed obstacles and expanded committed routes | `separate_nets_keep_clearance` |
| Multiple nets and ordering | Priority, terminal count, and span ordering | `routes_ten_signal_nets` |
| Two layers and through vias | Layer state, via transition cost, circular via output | `changes_layers_with_through_vias_when_front_is_blocked` |
| Layer-specific obstacles and keepouts | Layer-owned raster cells; KiCad keepout import | `imports_copper_keepout` |
| Rip-up/reroute and failure report | Four bounded full rip-up passes with history cost | `reports_unrouted_after_bounded_reroute_passes` |
| Pad ownership and off-grid access | Net-owned obstacles and exact orthogonal access tracks | `foreign_net_pad_blocks_but_own_pad_is_enterable`, `connects_off_grid_terminals_exactly` |
| Internal rule checking | Copper-graph connectivity, orphan copper, angle, dimensions, boundaries, obstacles, copper clearance | Connectivity regression tests and `detects_cross_net_short`; every CLI route invokes it |
| Incremental routing | Preserve and reserve complete existing routes; route only missing nets | Idempotence, preservation, duplicate-route, and KiCad import regression tests |
| Exact geometry predicates | Integer point/segment/rectangle distance comparisons and inclusive segment intersection | Collinear overlap, endpoint contact, half-unit, and exact-clearance tests |
| Multi-terminal routing | Central-root selection and cheapest terminal-to-tree A* branching | Five-terminal cross costs 320 versus 512 for input-order chaining |
| Selective rip-up/reroute | Failed-search blocker attribution, conflict-only rip-up, failed-net-first retry, via reservation | Crossing regression reroutes only the flexible blocker; static blockage stops after one pass |
| Explicit local route repair | Checker-derived or user-selected net rip-up with byte-locked unrelated routes and owned-zone preservation | Obstacle violation regression reroutes one net while proving the other route is unchanged |
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
| Automatic DRC repair loop | Bounded candidate generation, KiCad revalidation, convergence guard, atomic clean-output promotion | Injected three-iteration repair and repeated-candidate tests; real KiCad clean-board run |
| Polygon board geometry | Concave/convex outlines, exact polygon keepouts, edge-aware routing/checking/SVG, KiCad line-outline import | L-board routing, triangular keepout bounding-box escape, concavity tests; five-sided example passes real KiCad DRC |
| Exact circular pad geometry | Circle-aware rasterization, checking, SVG, and KiCad import without bounding-box blockage | Circle-corner routing and clearance regressions; KiCad circle-pad import test |
| Exact oval pad geometry | Rotation-aware capsule rasterization, checking, SVG, and KiCad import | Capsule bounding-box escape and collision regressions; rotated KiCad oval test |
| Exact rotated rectangular pads | Four-corner polygon rasterization, checking, SVG, and KiCad import | 30-degree coordinate regression and 35-degree real-KiCad E2E fixture |
| Curved board outlines | Three-point `gr_arc` sampling with a 0.01 mm maximum chord deviation | Semicircle import regression and curved-board real-KiCad E2E fixture |
| Board cutouts and multiple contours | Largest Edge.Cuts contour is the outer outline; enclosed contours are clearance-aware holes | Core routing/checking regression, importer classification test, and holed curved-board E2E fixture |
| Property and fuzz testing | Geometry symmetry/translation properties plus KiCad parser and board-model libFuzzer targets | Property tests run on every PR; scheduled/manual fuzz workflow runs both targets |
| Routing performance suite | Criterion scenarios for obstacle, 5/10-net, and board-cutout routing | Benchmark targets compile on every PR and retain local Criterion baselines |
| Routing quality gates | Stable per-net, board-total, and differential-pair metrics with JSON/SARIF output, thresholds, and baseline regression comparison | Geometry-count regression plus CLI JSON/baseline smoke test |
| Performance regression gate | Deterministic search-state budgets for 10 parallel nets and a 100 mm board with 200 obstacles | Dedicated `performance_budget` target runs on every PR |
| Practical board regression corpus | Anonymized USB differential, four-layer power/inner-signal, and eight-net BGA fanout topologies | Clean, byte-idempotent routing with per-fixture search budgets on every PR |
| BGA escape routing | Deterministic radial dog-bone stubs, stackup-aware fanout vias, and inner-layer continuation before global routing | Two-net BGA regression checks microvias, front stubs, inner tracks, and full-board cleanliness |
| KiCad placement I/O | Footprints, pad-net connections, locked state, origin-aware position/rotation write-back, and `place-kicad` CLI | Locked/rotated/non-zero-origin round-trip regression and CLI integration test |
| Multilayer routing | `In1.Cu`–`In30.Cu` model/serde, KiCad layer-table and item I/O, all-layer through vias, and per-net layer constraints | Forced inner-layer core regression, four-layer importer test, and real-KiCad four-layer DRC/idempotence fixture |
| Differential-pair rules and checking | Explicit pair model, KiCad net-class inference, differential width, skew/coupling/layer-via symmetry checks | Coupled/skew core regression and KiCad `_P`/`_N` inference test |
| Coupled differential-pair autorouting | Pair-terminal correspondence, full-route translation, and accept-only-on-clean fallback | 100%-coupled, zero-skew autorouting regression |
| Simultaneous differential-pair search | Pair-state A* validates both offset tracks at every step before committing either route | One-sided obstacle regression requires a joint detour while retaining 100% coupling |
| Length constraints and meander tuning | Net-class minimum/maximum length checks and deterministic legal orthogonal detours | Meander regression verifies the interval and a clean full-board check |
| Parallel-bus length matching | Named net-ID groups with maximum skew, group checking, and automatic tuning toward the longest member | Two-member bus regression ends within its declared skew and remains clean |
| Filled copper-zone interoperability | KiCad filled polygons become exact layer/net-owned copper and are preserved during route write-back | Filled GND-zone import regression |
| Native copper-zone generation | Net-owned polygon model with layer, clearance, and minimum thickness; native KiCad zone output and outline/fill import | Zone syntax, parameter, polygon, and owned-obstacle round-trip regression |
| Internal copper-zone fill | Conservative cell fill, foreign-copper/keepout clearance, pad thermal spokes, connected-component island removal, and filled-polygon export | Split-zone and thermal regression plus KiCad filled-polygon round trip |
| Via types and layer ranges | Through, blind/buried, and microvia model; KiCad round-trip; range-aware connectivity/clearance | Blind and adjacent-layer microvia regression |
| Automatic Via strategy | Stackup-aware micro, blind/buried, and through selection with span-aware collision reservation and cost | Transition classification and forced inner-layer autorouting regressions |
| Extended pad shapes | Roundrect, trapezoid, and custom polygon model/import with rotated exact polygon obstacles | Three-shape KiCad geometry regression |
| Practical placement constraints | Front/back side, allowed rotations, rectangular regions, and KiCad courtyard dimensions | Region optimization and back-side courtyard regressions |
| Placement flips and exact courtyards | Side-aware pin mirroring, polygon collision/boundary scoring, and atomic KiCad footprint layer swap | Bounding-box false-positive, opposite-side, and front/back round-trip regressions |
| Spatially bounded rasterization | Conservative per-shape cell windows followed by exact predicates | Window regression and 100 mm/200-obstacle Criterion scenario |
| Configurable DFM checks | Width, actual copper clearance, drill, annular ring, aspect ratio, and copper-to-edge checks with JSON CLI report | Multi-rule manufacturing regression and `dfm` command |
| Extended DFM and SARIF | Exact circle/oval/custom Via-in-pad, drill spacing, acute junctions, and SARIF 2.1.0 output | Multi-violation geometry and SARIF result-count regression |
| KiCad route arcs and teardrops | Three-point copper-arc import/export with checker linearization and native pad/via teardrop zones | Arc coordinate round-trip and teardrop syntax regression |
| Automatic teardrop generation | Via/track junction taper geometry with boundary, foreign-copper, and duplicate rejection | Clean four-point taper and second-pass idempotence regression |
| Precise route-arc geometry | Analytical circumcircle/sweep length plus conservative 1 µm adaptive DRC envelope and curved SVG output | Semicircle length and midpoint-only collision regression |
| Self-updating completion audit | Version and discovered Rust/Python test totals generated between protected markers | `update-completion-audit.py --check` runs on every PR |
| KiCad end-to-end CI | KiCad 10 routing, DRC, second-pass idempotence, and retained diagnostics for three fixtures | Rectangular, non-rectangular, and polygon-keepout boards run on every PR |
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

<!-- completion-audit:start -->
Version 1.28.0 exposes 77 Rust tests and 11 Python tests. The release workflow
also verifies formatting, Clippy, release builds, KiCad DRC fixtures, SBOMs,
and build-provenance attestations.
<!-- completion-audit:end -->
