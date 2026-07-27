# Design completion audit

This audit maps the supplied `pcbex` design and subsequent extensions to
executable evidence. The project began with the deliberately bounded,
rectangular two-layer MVP and now supports polygonal multilayer signal boards,
coupled differential-pair routing, and native KiCad copper-zone generation.

| Requirement | Implementation | Evidence |
| --- | --- | --- |
| Rust core/CLI and Python agent separation | `pcbex-core`, `pcbex-kicad`, `pcbex-cli`, `pcbex_agent` | Workspace release build |
| Core module boundaries | Dedicated geometry, checking, placement, schema/migration, and quality-analysis modules with stable root re-exports | Workspace tests exercise schema and quality APIs through their unchanged public paths |
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
| Modern KiCad project/custom rules | Ordered wildcard/regex `netclass_patterns`, exact-assignment precedence, and NetClass-conditioned `.kicad_dru` routing dimensions | KiCad 9-style project fixture plus mm/mil custom-rule regression |
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
| Property and fuzz testing | Geometry symmetry/translation properties plus KiCad parser, migrated board-model, length-tuning, and BGA-escape libFuzzer targets | Property tests run on every PR; scheduled/manual fuzz workflow runs all four targets |
| Schema compatibility gate | Draft 2020-12 schema has closed definitions for routing rules, net classes, length/escape/return-path constraints, and stackup; v1 migration is compared semantically with native v2 parsing | Migration regression rejects future versions/unknown fields and verifies every advanced constraint definition is closed |
| Routing performance suite | Criterion scenarios for obstacle, 5/10-net, and board-cutout routing | Benchmark targets compile on every PR and retain local Criterion baselines |
| Routing quality gates | Stable per-net, board-total, and differential-pair metrics with JSON/SARIF output, thresholds, and baseline regression comparison | Geometry-count regression plus CLI JSON/baseline smoke test |
| Performance regression gate | Deterministic search-state budgets for 10 parallel nets and a 100 mm board with 200 obstacles | Dedicated `performance_budget` target runs on every PR |
| Deterministic parallel candidate search | Configurable 1–8 bounded workers explore first-pass A* candidates; ordered validation reuses one board snapshot per pass and sequential conflict fallback controls commits | Ten-net 1-vs-8-worker regression is byte-identical; Criterion measures actual 1/2/4/8-worker wall time |
| Automatic local push-and-shove | Grid-aligned route-interior translation keeps terminal anchors fixed; failed nets try bounded blocker shoves before selective rip-up and atomically accept only checked combined routes | Successful manual shove preserves terminals, invalid edits roll back, and automatic blocker recovery produces a clean two-route board |
| Complete Rule Area constraints | Track, via, copper-pour, and footprint prohibitions are independent; local minimum width/clearance profiles participate in routing and DRC | KiCad selective Rule Area retains footprint/via-only flags; undersized nets route around a local profile and existing footprint/track violations are reported |
| PDN design checks | Per-power-net current, voltage-drop budget, and parallel-via minimum use routed geometry and stackup copper thickness for DC resistance estimation | 1 A narrow-trace regression reports both excessive voltage drop and insufficient vias |
| Decoupling placement quality | Dedicated capacitor-anchor to IC-power-pin distance and same-side constraint uses transformed named anchors | Colocated anchors score clean on one side and receive a deterministic penalty across board sides |
| Practical board regression corpus | Anonymized USB differential, four-layer power/inner-signal, eight-net BGA fanout, and reproducibly generated 100-net six-layer backplane topologies | Clean, byte-idempotent routing with per-fixture search budgets on every PR; large fixture completes in 46,500 states under a 100,000-state ceiling |
| BGA escape routing | Deterministic radial/row/column/four-way dog-bone stubs, optional via-grid snapping, multi-ring collision fallback, stackup-aware fanout vias, and inner-layer continuation before global routing | Two-net BGA regression blocks every first-ring site, checks grid-aligned second-ring microvias, front stubs, inner tracks, and full-board cleanliness |
| Return-path control | Per-signal/reference-net transition rules check maximum stitching-via distance, sample stackup-selected reference fills for split-plane/slot crossings, and add fully checked Zone-connected or track-connected reference vias | Filled-plane gap regression detects a slot; two-layer transitions insert legal direct-to-Zone and track-connected GND stitches and finish DRC-clean |
| Automatic rounded routing | Orthogonal corners are trimmed into tangent quarter-circle native arcs at the routing-grid radius, with whole-board acceptance checks and reporting | Right-angle regression verifies valid arc geometry, preserved connectivity, and a clean full-board check |
| Stackup impedance constraints | KiCad stackup import captures copper thickness plus dielectric height/permittivity and reference planes on both sides; DRC selects microstrip or symmetric/asymmetric embedded geometry | Four-layer import verifies both references and physical dimensions; controlled-impedance regression checks shifted targets; embedded estimators cover symmetric and asymmetric geometry |
| Advanced length tuning | Length groups constrain meander amplitude, pitch, and up to 16 distributed tuning sections; each incremental section is whole-board checked | Three-section regression adds exactly 3 mm across separate legal spans and bus-skew regression remains clean |
| KiCad placement I/O | Footprints, pad-net connections, locked state, origin-aware position/rotation write-back, and `place-kicad` CLI | Locked/rotated/non-zero-origin round-trip regression and CLI integration test |
| Multilayer routing | `In1.Cu`–`In30.Cu` model/serde, KiCad layer-table and item I/O, all-layer through vias, and per-net layer constraints | Forced inner-layer core regression, four-layer importer test, and real-KiCad four-layer DRC/idempotence fixture |
| Differential-pair rules and checking | Explicit pair model, KiCad net-class inference, differential width, skew/coupling/layer-via symmetry checks | Coupled/skew core regression and KiCad `_P`/`_N` inference test |
| Differential impedance DRC | Pair-level target/tolerance applies an edge-coupled microstrip odd-mode correction to copper-aware single-ended impedance | Calculated target passes; a 20 Ω target shift produces a dedicated differential-impedance violation |
| Impedance width solver | `impedance-width` reverse-solves single-ended or differential trace width from a board stackup, layer, target, optional pair gap, and bounded manufacturing range | Core regressions round-trip solved widths through both estimators; CLI parsing covers inner-layer differential arguments |
| Impedance transition DRC | Per-net-class maximum step compares stackup-derived impedances of segments connected through each via, independently of absolute target tolerance | Two-layer regression uses different widths around a through-via and reports the dedicated `impedance_transition` rule |
| Differential impedance transition DRC | Pair-level maximum step evaluates every via on both members with the differential stackup model, independently of an absolute target | Symmetric two-member layer transition with different pre/post-via widths reports `differential_impedance_transition` |
| Board-wide impedance report | `impedance-report` emits JSON for every routed single-ended segment and differential member, with estimates, target deviations/pass state, via steps, and invalid-geometry count | Core report regression verifies evaluated geometry; CLI regression covers explicit report output |
| Impedance CI quality gate | Report-level counters aggregate invalid geometry, out-of-tolerance segments, and excessive single-ended/differential transitions; `--fail-on-violations` writes JSON before returning nonzero | Missing-stackup regression fails the clean-state predicate; counter-state and CLI flag regressions cover all gate plumbing |
| Impedance baseline regression gate | Deserializable reports compare summary counts, stable net/segment target deviation, and single-ended/differential member transition steps; `--baseline` fails CI after writing the current report | Baseline regression proves count, segment-deviation, and transition-step worsening are detected while improvements are accepted |
| Coupled differential-pair autorouting | Pair-terminal correspondence, full-route translation, and accept-only-on-clean fallback | 100%-coupled, zero-skew autorouting regression |
| Simultaneous differential-pair search | Pair-state A* validates both offset tracks at every step before committing either route | One-sided obstacle regression requires a joint detour while retaining 100% coupling |
| Synchronous differential-pair tuning | Pair-level minimum length, amplitude, pitch, and distributed-section controls transform both members atomically with whole-board acceptance | Equal-length translated pair gains a legal synchronized meander and remains DRC-clean |
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
| Component and mounting-hole DFM | KiCad PTH/NPTH drill dimensions and plating are preserved; minimum drill, plated annular ring, aspect ratio, board-edge, and capsule-exact spacing checks include component holes and vias | Circular PTH and rotated oval NPTH import plus combined component-hole DFM regression |
| Component-hole model validation | Normal DRC rejects incomplete/non-positive drill dimensions and plated drills that do not fit inside their pads, independently of optional manufacturing rules | Invalid PTH and incomplete NPTH regression without manufacturing rules |
| Offset component drills | KiCad pad-local drill offsets are preserved and rotated into exact circular/oval hole geometry for DRC and DFM | Rotated offset capsule coordinates plus offset oval NPTH import regression |
| Exact plated-hole containment | Circular and oval pads validate the complete offset hole capsule against their curved boundary; rectangular pads validate capsule extents | Diagonal-offset circle rejection and valid rotated oval-slot containment regressions |
| Roundrect plated-hole containment | KiCad roundrect ratios are retained as corner radii and the complete hole capsule is tested against the radius-eroded curved boundary | 0.25-ratio import assertion and corner-offset hole rejection regression |
| Trapezoid plated-hole containment | KiCad `rect_delta` geometry is retained and each hole-capsule endpoint must clear every convex sloped edge by the drill radius | Delta import assertions and bounding-box false-negative rejection regression |
| Custom-polygon plated-hole containment | Complete circular/oval hole capsules require endpoint membership and exact radius clearance from every imported custom-pad polygon edge | Triangular custom-pad bounding-box false-negative regression |
| Custom-pad topology validation | Normal DRC rejects insufficient vertices, degenerate edges or area, and non-adjacent self-intersections before routing or hole geometry consumes custom polygons | Three malformed polygon regressions without manufacturing rules |
| Base pad geometry validation | Normal DRC rejects non-positive dimensions, non-finite rotations, out-of-range roundrect radii, and degenerate trapezoid deltas | Four malformed shape regressions without manufacturing rules |
| Pad layer membership validation | Normal DRC requires a non-empty, duplicate-free pad layer set drawn entirely from the board copper stackup | Empty, duplicate, unknown-inner-layer, and valid multilayer regressions |
| Pad net-reference validation | Normal DRC rejects pad net identifiers absent from the board net table while accepting mechanical and declared-net pads | Mechanical, declared-net, and undeclared-net regression |
| Net table identity validation | Normal DRC requires unique non-zero net IDs and unique non-empty names before routing, rule lookup, or pad ownership consumes the table | Zero ID, blank name, duplicate ID, and duplicate name regressions |
| Terminal layer membership validation | Normal DRC and Router require every net terminal to use a non-empty unique subset of the declared copper stackup | Empty, duplicate, undeclared, valid multilayer, and Router-construction regressions |
| Net-class reference validation | Normal DRC and Router require every optional net-class assignment to resolve against the board net-class table instead of silently applying base rules | Unassigned, declared, undeclared, and Router-construction regressions |
| Net-class dimension validation | Normal DRC independently requires positive track width/drill, non-negative clearance, and via diameter greater than drill for every declared class | Invalid width, clearance, drill, annulus, and valid unused-class regressions |
| Net-class layer membership validation | Normal DRC requires every optional class layer restriction to be a non-empty unique subset of the declared copper stackup while preserving omitted restrictions | Empty, duplicate, undeclared, unrestricted, and valid multilayer regressions |
| Net-class length-limit validation | Normal DRC requires optional minimum/maximum route lengths to be positive and ordered while preserving one-sided and unbounded limits | Zero minimum, negative maximum, reversed range, one-sided, bounded, and unbounded regressions |
| Net-class impedance-limit validation | Normal DRC requires target/tolerance pairing, finite values, positive targets, and non-negative tolerances/transition limits for every class | Missing pair member, zero/NaN target, negative/infinite tolerance, negative/NaN step, and valid optional combinations |
| Net-class differential-dimension validation | Normal DRC and Router require optional differential widths to be positive and differential gaps to be non-negative | Zero/negative width, negative/zero gap, valid pair, omitted values, and Router-construction regressions |
| Net-class name validation | Normal DRC and Router require every net-class table key to contain at least one non-whitespace character | Empty, whitespace-only, valid-name, and Router-construction regressions |
| Differential-pair identity validation | Normal DRC and Router require unique non-empty pair names, distinct declared member nets, and exclusive pair membership | Blank/duplicate names, self-pairing, unknown/reused members, valid pair, and Router-construction regressions |
| Route net-reference validation | Normal DRC rejects route net identifiers absent from the board net table before connectivity, width, or clearance checks consume the route | Declared and undeclared empty-route regression |
| Duplicate route validation | Normal DRC permits at most one route record per net so route indexing cannot silently hide additional copper | Two-route single-net regression with one explicit duplicate violation |
| Track segment geometry validation | Normal DRC requires distinct endpoints, positive width, and a declared copper layer before angle, boundary, or clearance evaluation | Zero-length, zero-width, unknown-layer, and valid segment regressions |
| Route arc geometry validation | Normal DRC requires positive width, a declared copper layer, and three points defining a curve; invalid arcs are excluded from DRC linearization | Zero-width, unknown-layer, repeated-point, collinear, and valid arc regressions |
| Via geometry validation | Normal DRC requires a positive drill diameter and a strictly larger outer diameter before layer, edge, minimum-size, or clearance checks consume the via | Zero-diameter, zero-drill, equal-diameter, oversized-drill, and valid-via regressions |
| Via layer-range validation | Normal DRC requires distinct declared endpoint layers and restricts microvias to adjacent copper layers before edge, size, or clearance checks consume the via | Unknown-layer, same-layer, non-adjacent microvia, adjacent microvia, and through-via regressions |
| Teardrop geometry validation | Normal DRC requires simple non-degenerate polygons on declared copper layers before converting teardrops into net-owned obstacles | Insufficient-point, repeated-edge, zero-area, unknown-layer, and valid-triangle regressions |
| Filled-zone geometry validation | Normal DRC requires every filled contour to be a simple non-degenerate polygon on a declared copper layer before conversion into a net-owned obstacle | Insufficient-point, repeated-edge, zero-area, unknown-layer, and valid-fill regressions |
| Zone outline validation | Normal DRC requires every source zone outline to be a simple non-degenerate polygon on a declared copper layer before refilling or plane analysis consumes it | Insufficient-point, repeated-edge, zero-area, unknown-layer, and valid-outline regressions |
| Zone rule-dimension validation | Normal DRC requires non-negative clearance/thermal gaps, positive minimum copper thickness, and positive spoke width when thermal relief is enabled | Negative-clearance/gap, zero-thickness/spoke, solid-fill, and valid-thermal regressions |
| Board dimension validation | Normal DRC independently requires positive board width and height, matching the routing precondition | Zero-width, negative-height, and valid-board regressions |
| Copper-layer table validation | Normal DRC independently requires a non-empty, duplicate-free table containing only supported front/back/internal copper layers | Empty, duplicate, unsupported `Inner(31)`, and valid-stackup regressions |
| Board outline validation | Normal DRC requires an explicit outline to be a simple non-degenerate polygon while preserving the empty-outline rectangular fallback | Insufficient-point, repeated-edge, zero-area, self-crossing, fallback, and valid-outline regressions |
| Board cutout topology validation | Normal DRC requires every cutout to be a simple non-degenerate polygon before board-boundary and copper-edge checks consume it | Insufficient-point, repeated-edge, zero-area, self-crossing, and valid-cutout regressions |
| Board cutout containment validation | Normal DRC requires every topologically valid cutout vertex to remain inside the effective explicit or rectangular board outline | Inside and partially outside cutout regressions |
| Board outline bounds validation | Normal DRC requires every topologically valid explicit-outline vertex to remain within the declared board width and height | Negative-coordinate, oversized-coordinate, and boundary-inclusive valid regressions |
| Routing-grid validation | Normal DRC independently requires a positive global routing grid, matching the routing precondition | Zero-grid, negative-grid, and valid-grid regressions |
| Base routing-rule validation | Normal DRC and Router require positive track width/drill, non-negative clearance, and via diameter greater than drill | Invalid width, clearance, drill, annulus, valid-rule, and Router regressions |
| Obstacle-layer validation | Normal DRC requires rectangular, round, capsule, polygon, and keepout obstacles to use a non-empty unique subset of the declared copper stackup | Empty, duplicate, undeclared, and valid layer-list regressions across all obstacle families |
| Obstacle net-reference validation | Normal DRC requires optional net ownership on rectangular, round, capsule, polygon, and keepout obstacles to resolve against the board net table | Unknown ownership across all five obstacle families plus declared ownership regression |
| Rectangular-obstacle geometry validation | Normal DRC and Router require strictly ordered minimum/maximum coordinates on both axes | Reversed-X, zero-height, valid rectangle, and Router-construction regressions |
| Curved-obstacle diameter validation | Normal DRC and Router require strictly positive diameters for round and capsule obstacles | Zero/negative and valid diameter regressions for both shapes plus Router-construction coverage |
| Polygon-obstacle topology validation | Normal DRC and Router require polygon obstacles to be simple and non-degenerate before rasterization or clearance checks consume them | Insufficient-point, repeated-edge, zero-area, self-crossing, valid-triangle, and Router regressions |
| Keepout-definition validation | Normal DRC and Router require simple non-degenerate keepout polygons with at least one prohibition/local rule and physically valid local dimensions | Malformed, inert, zero-width, negative-clearance, valid-local-rule, and Router regressions |
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
Version 1.171.0 exposes 237 Rust tests and 11 Python tests. The release workflow
also verifies formatting, Clippy, release builds, KiCad DRC fixtures, SBOMs,
and build-provenance attestations.
<!-- completion-audit:end -->
