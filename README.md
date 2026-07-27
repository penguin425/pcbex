# pcbex

[![CI](https://github.com/penguin425/pcbex/actions/workflows/ci.yml/badge.svg)](https://github.com/penguin425/pcbex/actions/workflows/ci.yml)

`pcbex` is a deterministic PCB physical-design engine written in Rust. The
current implementation routes placed multilayer boards from a small, stable JSON
model. It uses integer nanometre coordinates and multi-layer A* with eight-way
movement, bend/via/congestion/proximity costs, clearance-inflated obstacles,
route simplification, Steiner-style multi-terminal branching, and SVG
inspection output.

The core crate keeps geometry, checking, placement, schema/migration, and
routing-quality analysis in separate modules. Stable root-level re-exports
preserve the public API while keeping format contracts and reporting logic out
of the routing engine.
Normal DRC requires positive board width and height even when invoked directly,
matching the router's geometry precondition.
The configured routing grid must also be positive so direct DRC callers receive
the same early diagnostic as the router.
Base routing rules require a positive track width and via drill, non-negative
clearance, and a via diameter larger than the drill in both DRC and routing.
The copper-layer table must also be non-empty, duplicate-free, and limited to
the supported front, back, and first 30 internal copper layers.
Every net terminal must reference a non-empty, duplicate-free subset of that
declared copper stackup before connectivity checks or routing consume it.
Rectangular, round, capsule, polygon, and keepout obstacles must each reference
a non-empty, duplicate-free subset of that declared copper stackup.
When those objects carry optional net ownership, the identifier must resolve to
the board net table.
Rectangular obstacles must use strictly ordered minimum and maximum coordinates
on both axes so they always describe positive-area geometry.
Round and capsule obstacles must likewise have strictly positive diameters in
both direct DRC and Router construction.
Polygon obstacles must be simple, non-degenerate polygons before routing or
clearance checks consume their edges.
Keepouts additionally require at least one prohibition or local rule, positive
minimum track widths, and non-negative minimum clearances.
When an explicit board outline is supplied, it must be a simple,
non-degenerate polygon; an empty outline retains the rectangular fallback.
Every board cutout must likewise be a simple, non-degenerate polygon before
boundary and copper-edge checks consume it.
Valid cutouts must additionally keep every vertex inside the effective board
outline, including the rectangular fallback.
Explicit board-outline vertices must remain within the declared board width
and height, matching the router's coordinate-domain precondition.

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

New and selectively rerouted tracks pass through a deterministic post-router
optimizer. It replaces contiguous detours with direct horizontal, vertical, or
45-degree segments only when the complete board remains clean; imported locked
routes are never rewritten.

Repair checker violations without disturbing clean routes:

```sh
pcbex repair board.json --output repaired.json
pcbex repair board.json --output repaired.json --net-id 12 --net-id 15
```

With no explicit IDs, `repair` selects the nets named by the internal checker.
Selected tracks are ripped up and rerouted; every other route is locked and
verified byte-for-byte, and owned zones survive the replacement.

For nets with three or more terminals, the router chooses a central root and
repeatedly connects the cheapest remaining terminal to any point in the routed
tree. This avoids the input-order-dependent detours of terminal-to-terminal
chain routing.

When a net cannot be routed, the failed A* search records which committed nets
blocked its frontier. Only those conflicting routes are ripped up and retried,
with the failed net ordered first; unrelated and imported locked routes remain
in place. The route report separates preserved, newly routed, rerouted, and
unrouted nets and includes the number of rip-up events.

For interactive repair, `shove_route` applies a grid-aligned offset only to a
route's interior vertices, vias, teardrops, and zones while keeping terminal
anchors fixed. The edit is atomic: boundary, angle, clearance, connectivity,
and every other board check must pass or the original route is restored.
During autorouting, a failed net now tries one- and two-grid local shoves of
only the generated routes identified as blockers before escalating to rip-up.
Each combined shove-and-route candidate is accepted only after full-board
checking, and `RouteReport.shove_events` records successful recoveries.

## JSON model

All coordinates and dimensions use integer nanometres. Layers are `F.Cu` and
`B.Cu`. An optional ordered `outline` defines a simple, concave or convex board
polygon; an empty outline uses the width/height rectangle. `keepouts` use exact
polygons and layer sets, with independent `tracks_not_allowed`,
`vias_not_allowed`, and `zones_not_allowed` flags. KiCad Rule Area
`tracks`/`vias`/`copperpour` restrictions map to those flags without collapsing
selective areas into a blanket prohibition. `footprints_not_allowed` is also
imported, while JSON Rule Areas may set local `minimum_track_width_nm` and
`minimum_clearance_nm`; nets whose class cannot satisfy those local dimensions
route around the area and existing copper/footprints receive dedicated DRC
violations. Legacy `obstacles` remain
axis-aligned rectangles. Copper envelopes are expanded by width/via radius plus clearance.
Terminals declare the layers on which they may be reached. See
[`examples/simple.json`](examples/simple.json).

Board documents use `schema_version: 2`. Inputs without a version are migrated
from the legacy shape before strict deserialization; unsupported versions and
unknown top-level fields are rejected. Inspect the current JSON Schema or
upgrade a file with:

```sh
pcbex schema --output board-v2.schema.json
pcbex migrate old-board.json --output board-v2.json
```

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

When a sibling `.kicad_pro` file exists, `route-kicad` imports its modern
net-class dimensions and exact net assignments automatically. Use
`--project path/to/board.kicad_pro` when the project has a different basename.
Ordered `netclass_patterns` support hierarchical names, `*`/`?` wildcards, and
regular expressions; exact assignments retain precedence. A sibling
`.kicad_dru` is also discovered automatically. NetClass-conditioned clearance,
track/via/hole dimensions, differential gap, and length constraints are applied
to routing; use `--rules-file` to select another rules file.

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
and use exact segment-to-capsule clearance. Rotated rectangular pads retain
their four copper corners as polygons. The importer also reads
copper layers, net assignments, legacy board-embedded net classes, existing
segments and vias.
Line and three-point arc primitives on `Edge.Cuts` are joined into a polygonal
outline; arcs use a maximum chord deviation of 0.01 mm.
Additional closed contours inside the largest outline are imported as board
cutouts and excluded from routing with the same copper-to-edge clearance.
Geometry invariants run as property tests in the normal Rust suite. Dedicated
libFuzzer targets exercise arbitrary KiCad input, migrated/serialized board
models, constrained multi-section length tuning, and grid/ring BGA escape.
Criterion benchmarks cover obstacle, multi-net, and board-cutout routing
scenarios. Every pull request also enforces deterministic search and
rasterization operation budgets; see `docs/BENCHMARKS.md`.
The generated summary in `docs/COMPLETION_AUDIT.md` is kept current with
`python3 scripts/update-completion-audit.py`; CI rejects stale versions or test
totals.
Fully connected existing nets are preserved as locked routes; incomplete copper
remains an obstacle and is not mistaken for a completed route. Generated tracks
and through vias are appended at board level without duplicating locked routes,
while preserving the source document.
The route model also preserves KiCad three-point copper arcs and can emit
native pad/via teardrop zones from explicit polygon geometry.
New via-to-track junctions automatically receive tapered teardrop polygons
when sufficient straight length is available. Each candidate is accepted only
after complete-board clearance checking and generation is idempotent.
Arc length is calculated from the circumcircle and sweep angle. Connectivity,
clearance, and boundary checks use a conservative adaptive curve envelope with
1 µm maximum chord deviation, and SVG output renders the complete curve.
Matched two-terminal differential pairs use a simultaneous A* search that
evaluates both track positions for every move. The resulting pair is accepted
only when connectivity, clearance, skew, and coupling checks pass; more general
terminal arrangements retain the independently routed fallback.
Net-owned polygonal copper zones can be supplied in route JSON and are emitted
as native KiCad zones with clearance and minimum-thickness settings. Both
unfilled outlines and filled zone polygons are imported as owned copper.
The internal zone filler rasterizes conservative grid cells, removes clearance
conflicts, creates cross-shaped pad thermal reliefs, and discards islands not
connected to the owning net before exporting explicit filled polygons.
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
KiCad footprints can be optimized and written back without reformatting the
rest of the board:

```sh
cargo run -p pcbex -- place-kicad input.kicad_pcb \
  --output placed.kicad_pcb --json-output placement.result.json
```

Footprints marked `locked` remain fixed. Pad nets become weighted placement
connections, and `Reference`, position, rotation, and the board origin survive
the KiCad round trip.

## Multilayer routing

Boards may declare `F.Cu`, `In1.Cu` through `In30.Cu`, and `B.Cu` in
`copper_layers`. The KiCad importer reads the board layer table, wildcard
through-hole pads span every copper layer, and generated through vias connect
the full stack. Net-class layer restrictions continue to constrain which
layers the router may use.

## Differential-pair rules

JSON boards may declare `differential_pairs` with positive/negative net IDs,
nominal gap, gap tolerance, maximum skew, and minimum coupled percentage.
Normal DRC rejects negative geometry constraints and coupled percentages above
100 before evaluating routed pair geometry.
The checker reports skew, layer/via asymmetry, and insufficient coupling.
KiCad net classes containing `diff_pair_width` and `diff_pair_gap` automatically
pair `_P`/`_N` or `+`/`-` nets and apply the differential trace width.
Pairs may additionally set `minimum_length_nm`, `tuning_amplitude_nm`,
`tuning_pitch_nm`, and `max_tuning_sections`. The router adds each meander to
both members in one transaction, retaining equal length and accepting only
whole-board DRC-clean geometry. Tuning dimensions must be positive and the
section count must be between 1 and 16.
Set `target_differential_impedance_ohms` together with
`differential_impedance_tolerance_ohms` to check edge-coupled microstrip
impedance. The estimate combines routed width, pair gap, copper thickness,
dielectric height, and permittivity and reports missing/invalid stackup data
separately.
Normal DRC also reports incomplete, non-finite, or negative impedance
constraints before evaluating routed geometry.
`maximum_differential_impedance_step_ohms` additionally limits the largest
stackup-derived impedance change around any via on either member, even when no
absolute differential target is configured.

## Length constraints and tuning

Length groups require unique non-empty names and at least two unique declared
net IDs; normal DRC reports malformed groups before evaluating routed skew.
Maximum skew must be non-negative, optional tuning dimensions must be positive,
and the supported tuning-section range is 1 through 16.
Net classes may set `minimum_length_nm` and `maximum_length_nm`. The checker
reports routes outside that interval. After routing, pcbex deterministically
adds an orthogonal meander to short routes and accepts it only when the complete
board remains free of boundary, obstacle, connectivity, and clearance errors.
For parallel buses, `length_groups` declares a name, member net IDs, and maximum
skew. The checker reports group skew and the router tunes shorter members toward
the longest route while retaining every normal board constraint.

## Copper zones

Filled KiCad copper-zone polygons are imported as exact, layer-specific,
net-owned copper geometry. They block foreign nets with the normal clearance
while remaining enterable by their owning net. Existing zone definitions and
fills are preserved when routed tracks are written back to the board.

## PDN checks

Each declared power-net rule must reference a distinct net present in the board
net table. Expected current and maximum permitted voltage drop must both be
positive, finite values.

`power_net_rules` declares a power net's expected current in mA, maximum
permitted DC drop in mV, and optional minimum parallel-via count. The checker
uses each routed segment's real length and width plus per-layer stackup copper
thickness (35 µm fallback) to estimate copper resistance and reports
`pdn_voltage_drop` or `pdn_via_count` violations.

## Via types and layer ranges

Vias carry an explicit `through`, `blind_buried`, or `micro` kind plus start and
end copper layers. KiCad blind/buried and microvias retain their ranges during
import and write-back. Connectivity and clearance checks only consider layers
actually spanned by the via, and microvias are restricted to adjacent layers.
Set `via_strategy` to `auto` to let the router choose microvias for adjacent
layers, blind/buried vias for partial non-adjacent spans, and through vias for
the complete stack. Partial-span Via costs discourage unnecessary deep drills.

## Extended pad geometry

KiCad round-rectangle, trapezoid, and custom polygon pads retain their shape in
the board model. Rounded corners, trapezoid deltas, rotation, and custom
`gr_poly` primitives are converted to polygon obstacles instead of rectangular
bounding-box approximations.

## Practical placement constraints

Placement components carry front/back side and optional allowed 90-degree
rotations. `region` constraints keep a complete component body inside a
specified rectangle. KiCad placement derives component dimensions from
`F.CrtYd`/`B.CrtYd` geometry when available instead of pad extents alone.
Polygon courtyards are transformed with component rotation and side mirroring,
so non-overlapping concave space is not rejected by bounding boxes. Side flips
swap all footprint front/back layers atomically during KiCad write-back.
The `decoupling` constraint measures transformed capacitor and IC-pin anchors,
enforces a maximum connection distance, and can require both parts on the same
board side.

## Routing scalability

Obstacle rasterization uses conservative grid-cell windows derived from each
circle, capsule, polygon, and keepout bounding envelope. Exact geometry remains
the final predicate, while distant board cells are no longer scanned once per
obstacle. The Criterion suite includes a 100 mm board with 200 round obstacles.
CI also routes an anonymized practical corpus covering a USB differential pair,
a four-layer power/inner-signal board, and an eight-net BGA fanout. Each fixture
has a deterministic search budget and must remain clean and byte-idempotent;
see `docs/REGRESSION_CORPUS.md`. A reproducible generator also creates a
100-net, six-layer backplane; CI checks full routing, DRC, byte-idempotence, and
a 100,000-state ceiling.

Independent first-pass A* candidates are explored concurrently by up to eight
workers. Results are validated and committed in the original deterministic net
order. A candidate that conflicts with an earlier commit is discarded and
searched again against the updated board, retaining byte-identical output.

Generate a stable quality report for review or CI:

```sh
pcbex quality routed.json --output quality.json --max-unrouted 0
pcbex quality candidate.json --baseline quality.json
pcbex quality candidate.json --baseline quality.json --format sarif \
  --output quality.sarif
```

Reports include per-net length, segments, arcs, vias, bends, used layers, board
totals, unrouted count, and differential-pair skew/coupling. Baseline gates
reject increases in total length, vias, bends, or unrouted nets.

Length groups may also set `tuning_amplitude_nm`, `tuning_pitch_nm`, and
`max_tuning_sections`. The tuner distributes the required delay across multiple
legal straight sections, checking the whole board after every section, while
the existing defaults retain single-section behavior.

## BGA escape routing

Escape groups require unique non-empty names, declared unique net IDs, and
exclusive membership so a net cannot be assigned to multiple escape groups.
Fanout distance and optional via grid must be positive, ring count must be
between 1 and 8, and the target must be a declared non-front copper layer.
Each unrouted group is preflighted to ensure its nets begin at front-layer
terminals. Router construction also rejects assigned nets that already have
routes.
`escape_groups` assigns dense package nets a fanout distance and target copper
layer. Four-way, radial, row, and column strategies classify package pads from
their group centroid. Via locations may snap to an absolute grid and search up
to eight outward rings; blocked candidates rotate through the remaining
directions. Before global routing, pcbex creates checked dog-bone tracks and
stackup-aware vias from each first terminal, routes from the escaped inner-layer
locations, then restores the original pad terminals. The completed board,
including every fanout stub, must pass the normal full-board checker.

## Return-path stitching

Return-path rules require unique non-empty names, one declared reference net,
and a non-empty set of unique declared signal nets distinct from the reference.
Maximum stitching-via distance and optional plane-sampling interval must both
be positive.

`return_path_rules` associates high-speed signal nets with a reference net and
a maximum signal-to-reference via distance. The board checker reports every
layer transition without a nearby reference via that spans the same layers.
With `auto_stitch: true`, routing adds a checked reference via and short
connection to existing reference copper when a legal site is available. A via
inside an owned reference Zone connects directly to that plane without an
artificial track.

With `require_continuous_plane: true`, each signal segment is sampled against
the stackup-selected reference layer. Missing fills and split-plane/slot
crossings produce `return_path_plane` violations; the optional
`plane_sample_spacing_nm` controls resolution.

## Rounded routing

New routes automatically replace legal orthogonal corners with tangent
quarter-circle arcs using the routing grid as the preferred radius. Each
replacement is kept only when the complete board passes connectivity,
clearance, edge, length, and manufacturing checks.

## Stackup impedance checks

KiCad `(setup (stackup ...))` data is imported automatically, including copper
thickness, adjacent dielectric height/permittivity, and reference planes on
both sides. Inner layers therefore retain symmetric stripline or asymmetric
embedded-microstrip geometry. JSON entries can define the second side with
`secondary_reference_layer`, `secondary_dielectric_height_nm`, and
`secondary_dielectric_constant`.
Net classes may set
`target_impedance_ohms` and `impedance_tolerance_ohms`; the normal checker uses
the copper-thickness-aware microstrip or embedded estimate for every routed
segment and reports missing stackup data or out-of-range geometry. Differential
pairs use the same stackup geometry. This is an early
layout constraint, not a replacement for a field solver or fabrication-house
stackup validation.
Every net-class name assigned to a net must exist in `net_classes`; both the
normal checker and Router reject unresolved names instead of silently applying
the base routing rules.
Net-class track widths and via drills must be positive, clearances must be
non-negative, and via diameters must be larger than their drills. These
dimensions are validated even when no net currently uses the class.
When a net class restricts routing layers, its `layers` value must be a
non-empty, duplicate-free subset of the board copper stackup. Omitting
`layers` keeps the class unrestricted.
Optional `minimum_length_nm` and `maximum_length_nm` values must be positive,
and a bounded range must place the minimum at or below the maximum.
Impedance targets and tolerances must be provided together as finite values;
targets must be positive, while tolerances and maximum impedance steps must be
non-negative.
Optional differential widths must be positive and differential gaps must be
non-negative; both normal DRC and Router construction enforce these dimensions.
Net-class table keys must contain at least one non-whitespace character.
Differential-pair definitions require unique non-empty names and two distinct,
declared member nets; a net may belong to at most one pair.

Set `maximum_impedance_step_ohms` on a net class to limit discontinuity where
connected segments change layers through a via. This check is independent of
the absolute target, so it also catches large layer-to-layer steps when both
segments would individually fit a broad target tolerance.

Use `pcbex impedance-width board.json --layer F.Cu --target-ohms 50` to
reverse-solve a trace width from the imported stackup. Add
`--differential-gap-mm 0.15` for a differential target. The command searches
the configured width range and emits the selected width and estimated impedance
as JSON, using the same microstrip or embedded model as DRC.

`pcbex impedance-report board.json [--output impedance.json]` audits every
routed segment and differential-pair member. Its JSON includes layer, width,
estimate, target deviation/pass state, allowed and observed via-transition
steps, and a total count of segments whose stackup geometry could not be
evaluated. Add `--fail-on-violations` for CI: the report is still written, then
the command exits unsuccessfully if geometry is missing, a segment misses its
target, or a via step exceeds its configured limit.
Use `--baseline previous-impedance.json` to reject regressions against an
earlier report. Besides increases in the three summary counters, this compares
the absolute target deviation of stable net/segment indexes and observed
transition steps for single-ended nets and both differential members.

## Manufacturing checks

Boards may define `manufacturing_rules` for minimum track width, copper
clearance, drill, annular ring, copper-to-edge distance, board thickness, and
maximum via aspect ratio. These checks are included in the normal board checker.
Invalid physical limits are reported individually as `dfm_rule_dimensions`;
track width, drill size, and board thickness must be positive, while clearance
and spacing limits may be zero but not negative.
The maximum via aspect ratio must be positive, and the minimum trace angle must
be at most 180 degrees; invalid values use `dfm_rule_aspect_ratio` and
`dfm_rule_trace_angle`, respectively.
Aspect-ratio comparisons use overflow-safe widened arithmetic for both routed
vias and plated component holes.
Annular-ring comparisons likewise use widened arithmetic, including exact
boundary handling for routed vias and circular or slotted plated holes.
Drill-to-drill spacing thresholds use widened, saturating arithmetic so extreme
input dimensions cannot wrap before geometric comparison.
Copper-to-edge envelopes use the same overflow-safe approach for tracks, vias,
and component holes.
PDN resistance estimation widens endpoint coordinate differences before
computing segment lengths, preventing wraparound on extreme board coordinates.
Acute trace-angle analysis reuses the widened coordinate-difference path for
both vectors at each junction.
Rotated component-hole offsets and slot endpoints use saturating coordinate
arithmetic at the signed board-coordinate boundaries.
PDN resistance estimation skips invalid or non-finite conductor cross sections
instead of propagating infinite or NaN voltage-drop results.
Track-angle classification widens and safely takes the absolute value of
endpoint coordinate differences before checking horizontal, vertical, or
45-degree geometry.
The normal DRC track-angle check shares that full-range-safe classification,
so extreme signed coordinates cannot panic or be misclassified.
Route-length measurement widens endpoint differences and saturates accumulated
segment and arc lengths, preserving deterministic results for extreme routes.
Differential-pair coupled-length measurement uses the same widened geometry and
saturating accumulation for full-range and multi-segment routes.
Differential coupling-distance thresholds combine both widths, gap, and
tolerance with widened saturating arithmetic.
Rule-area segment midpoints use widened interpolation, including segments that
span the complete signed coordinate range.
Track-to-edge, rectangular, polygon, and keepout clearance envelopes combine
track width and both clearance sides with widened saturating arithmetic.
Round and capsule obstacle clearance envelopes additionally combine obstacle
diameters without overflowing extreme manufacturing dimensions.
Cross-net track-to-track clearance thresholds combine both widths and bilateral
clearance with widened saturating arithmetic.
Cross-net track-to-via checks use the same overflow-safe envelope in both route
directions, combining track width, via diameter, and bilateral clearance.
Cross-net via-to-via checks likewise combine both diameters and bilateral
clearance with widened saturating arithmetic.
Manufacturing track-to-track clearance uses the same overflow-safe envelope,
including extreme imported widths and clearance limits.
Manufacturing track-to-via clearance applies widened saturating arithmetic in
both route-order directions.
Within-route via connectivity combines both via diameters with widened
saturating arithmetic before evaluating the connectivity graph.
Within-route track connectivity combines both track widths with widened
saturating arithmetic before testing segment contact.
Within-route track-to-via connectivity safely combines track width and via
diameter before testing layer-spanning contact.
Via-to-edge, rectangular, polygon, and keepout clearance checks reuse a widened
saturating diameter-plus-bilateral-clearance envelope.
Via-to-round and via-to-capsule obstacle checks additionally combine obstacle
diameters through a widened saturating envelope.
Return-path plane sampling uses overflow-safe ceiling division and widened
endpoint interpolation, including segments spanning the full coordinate range.
Return-path via proximity checks widen coordinate differences before subtraction
and bound each axis before squaring, including full-range coordinates.
Pad containment widens point-to-pad coordinate differences before rotation so
full-range board coordinates cannot wrap into a false electrical connection.
`pcbex dfm board.json [--output report.json]` emits a machine-readable report
and exits unsuccessfully when manufacturing violations are present.
Optional rules also detect drill-to-drill spacing, prohibited Via-in-pad, and
acute trace junctions. Use `--format sarif` to emit SARIF 2.1.0 suitable for
GitHub Code Scanning; JSON remains the default.
KiCad PTH and NPTH pad drill dimensions are retained, including rotated oval
holes. Component and mounting holes participate in minimum-drill, aspect-ratio,
board-edge, and exact hole-to-hole spacing checks alongside vias. Plated holes
also enforce the minimum annular ring, while NPTH mounting holes do not.
The normal board checker rejects incomplete or non-positive component drills
even without manufacturing rules, and requires every plated drill to fit
strictly inside its pad.
KiCad `(drill ... (offset x y))` values are retained in pad-local coordinates.
The rotated offset is applied to exact hole capsules for board-edge and
hole-spacing DFM, and plated-hole validation includes the offset displacement.
For circular and oval pads, plated-hole containment follows the actual curved
boundary rather than its bounding box, catching diagonal offset holes that
leave insufficient copper while retaining valid offset slots.
KiCad roundrect corner ratios are retained as physical radii. Plated-hole
containment erodes the rounded rectangle by the drill radius, so holes entering
a curved corner are rejected even when their bounding boxes still fit.
KiCad trapezoid `rect_delta` values are also retained. Plated-hole containment
requires the complete hole capsule to remain at least its radius inside every
sloped edge of the resulting convex pad polygon.
Custom plated pads use their imported polygon directly: both hole-capsule
endpoints must be inside, and the centerline must remain more than the drill
radius from every boundary edge, including concave boundaries.
The normal board checker also rejects custom pad polygons with fewer than three
vertices, degenerate edges or area, or non-adjacent self-intersections before
routing and hole checks consume their geometry.
All pad shapes require positive dimensions and a finite rotation. Roundrect
radii must fit the source pad, and trapezoid deltas must leave a non-degenerate
shape.
Pads must also name at least one unique layer present in the board copper
stackup; invalid or duplicate layer memberships are rejected by normal DRC.
When a pad carries a net identifier, that identifier must exist in the board
net table; normal DRC reports undeclared pad-net references explicitly.
The net table itself requires unique non-zero identifiers and unique non-empty
names, preventing ambiguous routing, rule lookup, and pad ownership.
Every route must likewise reference a declared net; normal DRC reports unknown
route ownership before applying connectivity, width, or clearance rules.
Normal DRC also permits at most one route record per net, preventing map
construction from silently hiding copper in duplicate records.
Track segments require distinct endpoints, a positive width, and a layer from
the declared copper stackup before angle, boundary, or clearance evaluation.
Route arcs similarly require positive width, a declared copper layer, and three
points defining a curve; malformed arcs are rejected before DRC linearization.
Vias require a positive drill diameter and a larger outer diameter before
layer-range, board-edge, minimum-size, or copper-clearance evaluation.
Via endpoints must also belong to distinct declared copper layers, and
microvias may span only adjacent layers, before further physical checks.
Teardrops must form simple, non-degenerate polygons on declared copper layers
before normal DRC converts them into net-owned copper obstacles.
Filled zone contours have the same topology and layer requirements before
their copper participates in clearance and return-plane calculations.
Zone source outlines must also be simple, non-degenerate polygons on declared
copper layers so refilling and plane checks never consume malformed inputs.
Zone clearance and thermal gaps must be non-negative, minimum copper thickness
must be positive, and enabled thermal relief requires a positive spoke width.

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

pcbex is a deterministic physical-design engine for placed signal boards. It
supports polygonal multilayer boards, differential pairs, length tuning, copper
zones, partial-span vias, exact KiCad pad geometry, placement optimization, DFM
reporting, and headless or IPC-assisted KiCad workflows. It does not synthesize
schematics, select electrical components, perform analog or signal-integrity
simulation, or replace final KiCad DRC and fabrication review.
