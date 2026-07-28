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
Numeric net IDs and scalar net names in a `.kicad_pcb` must be present and
valid; malformed declarations, duplicate IDs, and duplicate names are rejected
instead of silently dropping or overwriting a declaration or retaining
ambiguous nets. Except for KiCad's reserved `net 0 ""` entry, net names must
also be non-blank; reserved net 0 must retain its exact empty name.
Connected pads must reference a declared nonzero net ID; stale references are
rejected instead of silently discarding the terminal and connection request.
When a pad contains a net record, its ID must also be a valid non-negative
integer, its name must be scalar, and the ID/name pair must match the board
declaration. The record must not be repeated; malformed, duplicate, or
contradictory records are rejected instead of treating the pad as unconnected or
attaching it to a differently named net.
Board segments, routed arcs, and vias with a nonzero net ID must likewise
reference a declared net; stale routed copper is rejected instead of creating
an ownerless route candidate.
Project net-class dimensions must be non-negative and fit the signed nanometer
range; oversized values are rejected instead of saturating at the integer limit.
Legacy net classes embedded in `.kicad_pcb` files follow the same finite,
non-negative, signed-nanometer range contract; `trace_width` and `via_drill`
must be positive, `via_dia` must be greater than `via_drill`, and an optional
`diff_pair_width` must be positive while a zero `diff_pair_gap` remains valid.
Their names must be present as scalar values, non-blank, and unique, and their
descriptions must be scalar values (an empty description remains valid). All
following values must be setting lists, and each supported dimension setting
must contain exactly one finite scalar value and appear at most once. Missing,
malformed, blank, duplicate, trailing, or stray scalar values are rejected
instead of being ignored, retaining an unusable class, or silently selecting
the first or last value.
Legacy `add_net` assignments must contain exactly one non-blank scalar name for
a nonzero net present in the board; malformed, trailing, stale, blank, reserved,
or misspelled references are rejected instead of being silently ignored. Each
net may appear only once and belong to only one embedded class; duplicate or
conflicting assignments are rejected instead of silently overwriting or
repeating the assignment.
Project settings are applied atomically, so an invalid class, pattern, or exact
assignment cannot leave new classes or partial net assignments behind.
Exact project assignments must use a non-blank name for a net present in the
board and reference a non-blank class; blank, stale, or misspelled targets and
blank class references are rejected instead of being silently ignored.
Each project `classes` entry must have a non-blank, unique name; blank or
duplicate definitions are rejected instead of retaining an unusable class or
silently selecting the last one. Project track widths and via drills must be
positive, and each via diameter must be greater than its drill; zero or
physically inconsistent dimensions are rejected before any project settings
are applied. Differential-pair widths must likewise be positive, while a zero
gap remains valid. Optional project minimum and maximum track lengths must also
be positive when present, and the minimum must not exceed the maximum.
Ordered `netclass_patterns` support hierarchical names, `*`/`?` wildcards, and
regular expressions; patterns and their class references must be non-blank,
exactly repeated patterns are rejected, and exact assignments retain
precedence. A sibling
`.kicad_dru` is also discovered automatically. NetClass-conditioned clearance,
track/via/hole dimensions, differential gap, and length constraints are applied
to routing; use `--rules-file` to select another rules file. Custom-rule
dimensions in either mm or mil must also fit the signed nanometer range.
Effective custom-rule track widths and hole sizes must be positive, while zero
clearance and differential gap remain valid. After all applicable rules are
combined, each modified via diameter must be greater than its hole size.
Custom-rule minimum and maximum length bounds must be positive when present,
at least one supported bound is required, and the minimum must not exceed the
maximum. A custom constraint may specify each supported `min`, `max`, or `opt`
value at most once; repeated values are rejected instead of silently selecting
the first, and each value must contain exactly one dimension. Custom-rule
types supported by pcbex may each appear only once within a rule, while later
rules may deliberately override earlier rules. Every custom constraint must
name one non-blank scalar type; missing, blank, or structured type fields and
extra scalar values are rejected. Each rule may contain at most one `condition`;
repeated conditions are rejected instead of silently selecting the first. A
custom rule must contain one scalar name; missing or structured names are
rejected, blank names are invalid, and extra scalar values are not permitted. A
condition field must contain one scalar expression and no extra expressions. A
blank condition is rejected. A recognized NetClass condition must close its
quoted class name and end immediately afterward; the class name must be
present, quoted, and non-blank,
and trailing condition fragments are rejected rather than partially applied.
Only direct `A.NetClass` or `B.NetClass` selectors using the `==` operator are
interpreted; malformed direct operators are rejected, while compound conditions
remain KiCad's authority. Custom-rule application is atomic, so an invalid later
constraint or unknown net class cannot leave earlier rule updates partially
applied.

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
Line, rectangle, and three-point arc primitives on `Edge.Cuts` are joined into a
polygonal outline; arcs use a maximum chord deviation of 0.01 mm.
All three arc points must be distinct before circle fitting, so repeated
endpoints or midpoints are rejected as malformed rather than merely collinear.
Arc sampling is capped at 16,384 segments per primitive before allocation,
matching the resource bounds applied to circles and cubic curves.
Arc collinearity is classified with exact integer geometry; extreme noncollinear
inputs that lose precision during circle fitting report a separate error.
Intermediate arc samples must remain within the signed nanometer coordinate
range, preventing saturated points from distorting a bulging arc.
Circle primitives use the same chord-deviation bound and can define either the
outer board outline or an inner cutout. Their complete radius must fit within
the signed nanometer coordinate range, preventing saturated samples from
distorting circles near a coordinate limit.
Cubic curve primitives are adaptively subdivided to the same deviation bound.
They must contain exactly four finite `xy` points before subdivision.
Polygon primitives preserve their exact vertices and can likewise define an
outer outline or cutout, with at most 16,384 input points per primitive.
Apart from an optional closing point equal to the first, every polygon vertex
must be distinct so a single primitive cannot create a branched contour.
An imported board may contain at most 65,536 generated `Edge.Cuts` segments in
total across all supported primitives.
Every generated edge passes a shared zero-length check before insertion, so new
or adaptively sampled primitives cannot introduce collapsed contour segments.
Line, rectangle, circle, and arc coordinates must be finite before conversion
to nanometers, matching the validation applied to polygons and cubic curves.
All supported Edge.Cuts coordinates must also fit the signed nanometer range;
oversized finite values are rejected instead of saturating at integer limits.
Board-level line, rectangle, circle, and arc points reject trailing values
instead of silently ignoring malformed coordinate-list elements.
Polygon and cubic-curve `xy` entries likewise contain exactly two coordinates,
so every supported outline point has strict arity.
Board-level Edge.Cuts primitives reject repeated `start`, `mid`, `end`, or
`center` fields instead of selecting the first ambiguous value.
Polygon and cubic-curve primitives also require a single `pts` list, rejecting
ambiguous duplicate point collections.
Each Edge.Cuts primitive must declare exactly one `layer` field, preventing
ambiguous mixed-layer graphics from being treated as board outlines.
That field must contain only the `Edge.Cuts` layer value; trailing values are
rejected rather than ignored.
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
Graph-clustered initialization uses saturating spacing and cursor arithmetic
for extreme board grids and component dimensions.
Annealing moves also multiply grid steps and update coordinates with saturating
arithmetic before clamping each component to the board.
Placement HPWL scoring widens both coordinate differences and their Manhattan
sum, including connections spanning the full signed coordinate range.
Board-boundary scoring likewise widens negative and positive overflow distances
before aggregating courtyard penalties.
`near` placement constraints widen Manhattan distance and allowed-distance
subtraction before calculating their excess penalty.
Decoupling anchor-to-power-pin distance uses the same full-range-safe excess
calculation before applying its board-side penalty.
Board-edge constraints widen left, right, top, and bottom distances before
subtracting the permitted edge offset.
`keep_together` constraints widen both point-cloud spans and their sum before
subtracting the permitted group span.
Axis-aligned component bounds use saturating half-dimension offsets at the
signed board-coordinate limits.
Custom courtyard transforms saturate back-side mirroring and rotated center
offsets at the same coordinate limits.
Placement pin coordinates also saturate board-side mirroring, right-angle
rotation negation, and center-offset addition.
Region constraints widen all four component-to-region overflow distances before
aggregating their placement penalty.
Placement overlap scoring widens rectangle intersection widths and heights
before calculating their area.
Final placement grid snapping widens rounding arithmetic and stays on a
representable grid multiple at coordinate limits.
BGA escape-via grid snapping uses exact integer rounding beyond floating-point
precision and at signed coordinate limits.
BGA escape-group centroids widen terminal-coordinate sums before averaging.
BGA escape direction selection widens centroid differences before comparing
axis distances.
BGA escape candidate coordinates widen ring-distance products and saturate
directional offsets at signed coordinate limits.
BGA escape stub shape detection widens endpoint differences before comparing
axis distances.
KiCad board extents and origin-relative coordinates widen endpoint differences
and saturate them at signed coordinate limits.
KiCad courtyard width and height derivation also saturates full-range coordinate
spans before creating placement components.
KiCad placement fallback bounds saturate pad-relative differences, half-size
offsets, and final component spans.
KiCad placement and copper writers saturate board-origin translation at signed
coordinate limits.
KiCad track-segment obstacle envelopes saturate half-width expansion at signed
coordinate limits.
KiCad route-arc obstacle envelopes saturate half-width expansion at signed
coordinate limits.
KiCad via obstacle envelopes saturate half-diameter expansion at signed
coordinate limits.
KiCad oval-pad capsule endpoints saturate rotated center offsets at signed
coordinate limits.
KiCad generated pad-polygon vertices saturate rotated center offsets at signed
coordinate limits.
KiCad custom-pad primitive vertices saturate rotated center offsets at signed
coordinate limits.
KiCad board-cutout containment checks handle polygons spanning signed coordinate
limits without overflowing intermediate edge differences.
KiCad Edge.Cuts contour ordering and zero-area validation use wide signed area
accumulation across the full coordinate range.
KiCad Edge.Cuts arc fitting uses start-relative coordinates so small arcs remain
stable near signed coordinate limits.
KiCad Edge.Cuts arcs retain an intermediate sample even when their radius is
smaller than the chord tolerance.
KiCad three-point Edge.Cuts arc sampling preserves the declared midpoint for
asymmetric sweeps.
KiCad board-cutout containment uses exact wide-integer ray crossings, including
points one nanometer from signed coordinate limits.
KiCad Edge.Cuts primitives are assembled through an endpoint index, keeping
large unordered and mixed-direction outlines linear in the number of segments.
Every Edge.Cuts contour vertex must join exactly two primitives, so branched or
touching contours are rejected instead of being folded into ambiguous outlines.
Cutout edges are checked exactly against the outer contour, preventing an
all-vertices-inside cutout from crossing outside a concave board outline.
Non-adjacent edges within every Edge.Cuts contour are also checked exactly, so
asymmetric self-intersections cannot pass merely because their area is nonzero.
Edge.Cuts polygon primitives reject self-intersections during parsing, before
their invalid edges enter contour assembly. They also require nonzero exact
wide-integer area, so collinear polygons cannot enter contour assembly.
Multiple Edge.Cuts cutouts must be disjoint and unnested because the board model
represents a flat set of holes rather than alternating material islands.
Edge.Cuts line primitives must declare both endpoints; malformed lines are
rejected instead of being silently omitted from the imported board outline.
Their endpoints must also be distinct, preventing zero-length primitives from
entering contour assembly.
Edge.Cuts rectangle primitives likewise require both opposite corners, so an
incomplete rectangle cannot disappear from the imported board geometry.
Those corners must span nonzero width and height, rejecting collapsed
rectangles before contour assembly.
Duplicate Edge.Cuts edges are detected independent of direction across line,
arc, and rectangle primitives without changing linear contour-import scaling.

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

Generate several deterministic trade-off candidates in parallel:

```sh
pcbex place-candidates examples/placement.json \
  --output-dir placement-candidates --candidates 10 --workers 4

pcbex place-kicad-candidates input.kicad_pcb \
  --output-dir kicad-candidates --candidates 10 --workers 4
```

Candidates cycle through balanced, wirelength, routability, constraint, and
legalization objectives with distinct reproducible seeds. `candidates.json`
records every objective, seed, weight set, raw score, base-weight comparison
score, Pareto membership, and the deterministically selected candidate.
Per-candidate JSON files and `selected.json` are emitted alongside the manifest;
KiCad mode also writes each candidate board and `selected.kicad_pcb`. Candidate
generation accepts 1–32 candidates and 1–8 workers. Worker count does not change
candidate geometry, scores, Pareto membership, or selection.

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

Generate an N-best routing portfolio for board JSON or a placed KiCad board:

```sh
pcbex route-candidates placed.json \
  --output-dir routing-candidates --candidates 10 \
  --workers 4 --router-workers 2

pcbex route-kicad-candidates placed.kicad_pcb \
  --output-dir kicad-routing-candidates --candidates 10 \
  --workers 4 --router-workers 2
```

Candidates cycle through balanced, shortest-route, via-minimized,
bend-minimized, and alternate-net-order searches. The versioned
`candidates.json` manifest records the effective search costs, route report,
quality metrics, duplicate identity, Pareto membership, and deterministic
selection. The Pareto front minimizes unrouted nets, total length, vias, and
bends; selection then applies the caller's original routing costs. Every board
and report is retained, together with `selected.board.json` and
`selected.report.json`; KiCad mode also writes each candidate board and
`selected.kicad_pcb`.

Generation accepts 1–32 candidates, 1–8 portfolio workers, and 1–8 router
workers per candidate, with a combined ceiling of 16 threads. Parallel worker
counts do not change candidate geometry, metrics, duplicate detection, Pareto
membership, or selection. Unless `--allow-unrouted` is given, artifacts are
written first and the command then fails if the selected candidate is not
fully routed.

Generate a stable quality report for review or CI:

```sh
pcbex quality routed.json --output quality.json --max-unrouted 0
pcbex quality candidate.json --baseline quality.json
pcbex quality candidate.json --baseline quality.json --format sarif \
  --output quality.sarif
```

Quality-report total route length uses saturating accumulation, so large
multi-net designs cannot wrap the reported aggregate.

Reports include per-net length, segments, arcs, vias, bends, used layers, board
totals, unrouted count, and differential-pair skew/coupling. Baseline gates
reject increases in total length, vias, bends, or unrouted nets.

Analyze a KiCad board directly and produce one self-contained artifact bundle
for CI, MCP, or later candidate comparison:

```sh
pcbex analyze-kicad board.kicad_pcb --output-dir build/pcbex-analysis
```

The bundle contains the normalized board JSON, SVG, quality and internal
DRC/DFM JSON, SARIF, a Markdown summary, and `run.json`. The run manifest records
the engine version, SHA-256 and byte length of every applied input, effective
routing defaults, applied custom-rule count, result totals, and artifact names.
Sibling `.kicad_pro` and `.kicad_dru` files are discovered automatically or may
be selected with `--project` and `--rules-file`. Add `--fail-on-violations` to
write the complete bundle and then fail a CI job when internal checks are not
clean.

Compare a baseline bundle with the current bundle:

```sh
pcbex compare-analysis build/baseline build/current \
  --output-dir build/comparison --fail-on-regressions
```

The comparison writes `delta.json`, `summary.md`, `report.sarif`, and a
SHA-256-addressed `run.json` before applying the optional failure gate. Signed
changes cover total length, vias, bends, routed and unrouted nets, and violation
count. Violations are compared by rule, message, and normalized net IDs so a
new finding cannot be hidden by resolving an unrelated finding. Resolved
violations are retained separately for review.

### GitHub Actions hardware CI

The repository is also a composite GitHub Action. It builds the engine from the
selected pcbex tag, analyzes the current board, adds Markdown to the Job
Summary, and uploads the complete bundle. An optional baseline board enables
the structured regression comparison:

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write

steps:
  - uses: actions/checkout@v7
  - uses: actions/checkout@v7
    with:
      ref: ${{ github.event.pull_request.base.sha }}
      path: .pcbex-baseline
  - name: Install trusted pcbex policy root
    env:
      PCBEX_POLICY_PUBLIC_KEY: ${{ vars.PCBEX_POLICY_PUBLIC_KEY }}
    run: |
      umask 077
      printf '%s\n' "$PCBEX_POLICY_PUBLIC_KEY" \
        > "$RUNNER_TEMP/pcbex-policy-root.pub"
  - id: hardware
    uses: penguin425/pcbex@v1.321.0
    with:
      board: hardware/controller.kicad_pcb
      baseline-board: .pcbex-baseline/hardware/controller.kicad_pcb
      signed-policy-pack: hardware/organization-policy-pack.signed.json
      policy-public-key: ${{ runner.temp }}/pcbex-policy-root.pub
      fail-on-regressions: "true"
      upload-sarif: "true"
      pr-comment: ${{ github.event.pull_request.head.repo.full_name == github.repository }}
      github-token: ${{ github.token }}
      comment-id: controller-layout
```

The action outputs the artifact directory, current and comparison SARIF paths,
violation count, regression result, and optional PR comment URL.
`upload-sarif` is opt-in because the calling job must grant
`security-events: write`; artifact upload defaults to on.

`pr-comment` is also opt-in and requires both `pull-requests: write` and an
explicit `github-token`. A stable `comment-id` creates a hidden marker; later
runs update the newest editable matching comment instead of appending another.
The comment body is read from the generated `pr-comment.md` artifact and is
never expanded as shell source. Invalid identities, blank or oversized bodies,
unexpected API shapes, and missing event context fail closed. The example
disables comments for fork PRs, whose default `GITHUB_TOKEN` is read-only,
while still producing their Job Summary and evidence artifact.

Callers select exactly one of `fab`, `fab-profile`, `policy-pack`, or
`signed-policy-pack`. A signed pack additionally requires
`policy-public-key`. The same authenticated physical policy is applied to
current and baseline analysis, and the exact verified source digest is
retained in each run manifest.

Violation and regression gates run only after uploads and comment updates, so
a failed PR check still retains the JSON, SVG, SARIF, summaries, and provenance
manifests. Baseline checkout is intentionally caller-controlled, allowing a PR
workflow to compare against its exact base SHA without using
`pull_request_target`.

### MCP server

Start the built-in Model Context Protocol server over stdio:

```sh
pcbex mcp-server
```

Configure an MCP host to launch the binary directly:

```json
{
  "mcpServers": {
    "pcbex": {
      "command": "/absolute/path/to/pcbex",
      "args": ["mcp-server"]
    }
  }
}
```

The server implements the 2025-11-25 MCP lifecycle and negotiates compatible
2025-06-18, 2025-03-26, and 2024-11-05 clients. It exposes
`list_dfm_profiles`, `analyze_kicad`, `compare_analysis`, and `route_kicad`.
Every tool has a closed input schema, an output schema, safety annotations, a
human-readable text result, and matching `structuredContent`. Tool processes
capture stdout and stderr so the stdio transport emits only newline-delimited
JSON-RPC messages. Expected analysis or regression gate failures use
`isError: true` while retaining structured manifests and artifact paths;
malformed requests remain JSON-RPC errors so an agent can correct its call.

For 2025-11-25 clients, the server also implements the experimental MCP Tasks
API. `analyze_kicad`, `compare_analysis`, and `route_kicad` declare
`execution.taskSupport: "optional"` and accept task-augmented calls:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "analyze_kicad",
    "arguments": {
      "input": "board.kicad_pcb",
      "output_dir": "pcbex-analysis"
    },
    "task": {"ttl": 600000}
  }
}
```

Use `tasks/get` to poll, `tasks/result` to retrieve the original tool result,
`tasks/list` to inspect retained jobs, and `tasks/cancel` to terminate work.
Tasks are process-local, default to a 10-minute lifetime, and permit a requested
TTL up to 24 hours. The server retains at most 32 tasks and executes at most
four concurrently. Older negotiated protocol versions continue to execute
calls synchronously and ignore task augmentation as required by their
capability model.

Analysis and routing tools require explicit output paths and may overwrite
files there. MCP hosts should retain their normal user-approval prompt for
these non-read-only tools.

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

Built-in fabrication profiles make those rules explicit, revisioned, and
reproducible:

```sh
pcbex dfm-profiles
pcbex analyze-kicad board.kicad_pcb --output-dir build/analysis \
  --fab jlcpcb-2layer
pcbex route-kicad board.kicad_pcb --output routed.kicad_pcb \
  --fab pcbway-2layer
pcbex dfm board.json --fab jlcpcb-standard-2layer-1oz-v1
```

The stable aliases `jlcpcb-2layer` and `pcbway-2layer` currently resolve to the
immutable `jlcpcb-standard-2layer-1oz-v1` and
`pcbway-standard-2layer-1oz-v1` profiles. Each listing includes its revision,
verification date, official capability URLs, and exact nanometre rules.
`analyze-kicad` records the resolved profile and effective routing rules in
`run.json`. Profile application raises base and net-class track width,
clearance, drill, and annular-ring-derived via diameter where required; it
never lowers a stricter project rule. Both initial profiles model routed-edge
clearance and a 1.6 mm board. They use a conservative 10:1 via aspect-ratio
limit where the standard capability pages do not publish a tighter limit.

Organizations can distribute the same contract as a strict external JSON file:

```sh
pcbex dfm-profile-schema --output dfm-profile.schema.json
pcbex validate-dfm-profile hardware/acme-dfm.json \
  --output build/acme-dfm.normalized.json
pcbex analyze-kicad board.kicad_pcb --output-dir build/analysis \
  --fab-profile hardware/acme-dfm.json
```

External profiles use `schema_version: 1`, a stable lowercase ID, optional
aliases, a positive revision, a real `YYYY-MM-DD` verification date, at least
one HTTPS source, and a complete manufacturing-rules object. Unknown fields,
invalid dimensions, duplicate names or sources, and collisions with built-in
IDs or aliases fail closed. `--fab-profile` is supported by KiCad analysis,
routing, route-candidate generation, board DFM checks, the composite Action,
and the corresponding MCP analysis and routing tools. Analysis manifests bind
both the normalized resolved profile and the source file's path, byte length,
and SHA-256 digest.

### Organization policy packs

An organization can bind its complete approval contract in one distributable
JSON file:

```sh
pcbex policy-pack-schema --output organization-policy-pack.schema.json
pcbex validate-policy-pack examples/acme-policy-pack.json \
  --output build/acme-policy-pack.normalized.json

pcbex analyze-kicad board.kicad_pcb --output-dir build/analysis \
  --policy-pack examples/acme-policy-pack.json
pcbex check-schematic design.kicad_sch \
  --policy-pack examples/acme-policy-pack.json \
  --output electrical-review.json --require-approved
```

The closed `schema_version: 1` contract combines one DFM profile, one
electrical policy, explicit AI-review requirements, whether simulation
evidence is mandatory, and an allowlist of signer IDs with Ed25519 public
keys. IDs, dates, dimensions, rule settings, requirements, and keys are
strictly validated; unknown fields, duplicates, and altered profiles that
impersonate built-in DFM identities fail closed. Private keys are never part
of a policy pack.

`--policy-pack` applies to KiCad analysis, routing, route-candidate generation,
board DFM checking, schematic checking, AI-review preparation, approval
verification, the composite Action, and the corresponding MCP analysis,
routing, preparation, and verification tools. It is mutually exclusive with
ad-hoc policy/profile overrides. Analysis manifests bind the pack ID, resolved
DFM rules, source path, byte length, and SHA-256 digest.

Authenticate packs before distributing them to CI:

```sh
# Run once and keep the private key outside the repository.
pcbex policy-keygen \
  --private-key .secrets/policy-signing.key \
  --public-key policy-root.pub

pcbex sign-policy-pack organization-policy-pack.json \
  --private-key .secrets/policy-signing.key \
  --signer-id hardware-security \
  --output organization-policy-pack.signed.json

pcbex signed-policy-pack-schema \
  --output signed-policy-pack.schema.json
pcbex verify-policy-pack organization-policy-pack.signed.json \
  --public-key policy-root.pub \
  --output build/verified-policy-pack.json
```

The signed envelope embeds the normalized pack and authenticates its SHA-256,
ID, revision, and signer under a domain-separated Ed25519 signature. Unknown
fields, digest mismatch, altered content, unsupported algorithms, invalid
signatures, and a key other than the separately trusted public key fail
closed. Key generation, signing, and verified extraction refuse to overwrite
existing files.
The MCP server exposes the same authenticated extraction boundary as
`verify_policy_pack`; it never receives or exposes the signing private key.

For the composite Action, write the trusted public key from a protected
repository variable or secret into a runner-temporary file before invoking
the Action; do not derive trust from the public key embedded in the signed
envelope. The Action verifies and retains the extracted pack before current
or baseline analysis starts.

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
Routing-quality bend classification also widens endpoint differences before
deriving segment direction at the signed coordinate limits.
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
Manufacturing via-to-via clearance also combines both diameters and bilateral
clearance without signed overflow.
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
When a pad carries a net identifier, its `net` field must contain exactly one
identifier and name, and that identifier must exist in the board net table;
normal DRC reports malformed or undeclared pad-net references explicitly.
Imported KiCad track segments, route arcs, vias, and copper zones with non-zero
net identifiers must likewise reference entries declared in that table.
When any of those copper primitives supplies a `net` field, its identifier must
be a non-negative integer rather than malformed data that loses net ownership.
Each primitive may supply at most one such field, preventing duplicate or
conflicting declarations from being silently resolved by source order. The
field must contain exactly one identifier, so trailing values cannot be
silently ignored.
Copper zones with a net field must also provide a scalar `net_name`; the empty
name remains valid for unconnected net 0 zones, while every other name must
match the net table declaration for its identifier. At most one `net_name`
field is permitted, and that field must contain exactly one name, so duplicate,
conflicting, or trailing values cannot be hidden.
Each net-table declaration must contain exactly one identifier and one name.
The table requires unique non-zero identifiers and unique non-empty names,
preventing trailing metadata, ambiguous routing, rule lookup, and pad ownership.
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

## Schematic electrical IR

Normalize a KiCad 6–10 `.kicad_sch` file before deterministic electrical
checking or AI review:

```sh
pcbex import-schematic design.kicad_sch \
  --output design.schematic.json --require-complete
pcbex schematic-schema --output schematic-ir-v1.schema.json
```

The schema-versioned IR retains source-format identity, symbols, all
properties, unit/convert selection, pin UUIDs and electrical types, transformed
pin coordinates, wires, junctions, local/global/power labels, explicit
no-connect markers, KiCad 10 local/global power scope, and deterministic
electrical nets. Connectivity joins wire endpoints and T-junctions, splits
unmarked crossings, and unifies repeated labels. Net members retain both
reference designators and symbol UUIDs so unannotated or multi-unit parts
remain unambiguous.

The importer rejects unknown future formats, malformed coordinates, duplicate
UUIDs/properties/pins, missing embedded symbols, unsupported pin types, and
bounded-resource overflows. Buses, bus entries, net-class directives, extended
library symbols, and hierarchical sheets/labels are retained as explicit
coverage gaps rather than silently approved. `--require-complete` writes the
inspectable IR first and then fails if any such gap exists. The included
example is also parsed by KiCad 10 in CI-facing verification.

## Deterministic schematic approval gate

Run policy-controlled electrical checks before asking an AI reviewer to assess
intent:

```sh
pcbex check-schematic design.kicad_sch \
  --output electrical-review.json \
  --explain electrical-explanations.json \
  --junit-output electrical-review.xml \
  --sarif-output electrical-review.sarif \
  --require-approved
pcbex electrical-policy --output electrical-policy.json
pcbex check-schematic design.kicad_sch \
  --policy electrical-policy.json \
  --output electrical-review.json --require-approved
```

The default policy checks importer coverage, annotation and footprint
completeness, duplicate reference units, connected no-connect pins, unmarked
unconnected pins, conflicting signal and power drivers, undriven signal and
power inputs, and nets with multiple names. DNP symbols are excluded. Every
finding has a stable identity and structured symbol/pin references.

`--explain` writes a separate policy-bound report covering all 12 rules,
including each rule's purpose, exact trigger, remediation guidance, effective
severity and enablement, and the stable IDs of findings it produced. This keeps
the signed electrical-review contract unchanged while making CI failures and
AI hand-offs directly explainable.

`--junit-output` emits one testcase for each built-in electrical rule. Enabled
rules with error findings produce failures, warning and informational findings
remain visible in `system-out`, and policy-disabled rules are explicitly
skipped. Suite properties retain the schematic and policy SHA-256 identities,
so Jenkins, GitLab, Buildkite, and other JUnit-aware CI systems can display the
same approval evidence without changing the canonical JSON review.

`--sarif-output` emits SARIF 2.1.0 for GitHub Code Scanning and other
SARIF-aware review tools. Every finding carries its severity, source schematic,
stable partial fingerprint, net/symbol/pin context, and the canonical
schematic/policy identities. The SARIF driver also embeds the title, purpose,
trigger, remediation, default level, and enablement of all 12 rules.

Adopt an existing review as a CI baseline without allowing new electrical
errors:

```sh
pcbex compare-electrical-reviews accepted-review.json electrical-review.json \
  --output electrical-comparison.json \
  --require-no-new-errors
pcbex electrical-review-comparison-schema \
  --output electrical-review-comparison-v1.schema.json
```

The comparison uses stable finding IDs instead of aggregate counts. Existing
baseline errors do not fail the gate, while a new error or a warning/info
finding escalated to error returns nonzero after writing the report. New,
resolved, unchanged, and severity-changed findings are counted separately;
actionable summaries and canonical SHA-256 identities for both reviews are
retained. Duplicate or malformed finding IDs, inconsistent counts or approval
flags, blank policy identities, and future schema versions fail closed.

Temporary exceptions are represented separately from the immutable electrical
review. Every waiver targets one stable finding ID and requires a non-empty
reason, approver identity, and expiration date:

```json
{
  "schema_version": 1,
  "id": "prototype-v1",
  "waivers": [{
    "id": "temporary-power-source",
    "finding_id": "pcbex-er-0123456789abcdef",
    "reason": "External bench supply is used for prototype validation",
    "approved_by": "hardware-lead",
    "expires_on": "2026-08-31"
  }]
}
```

Apply waivers with an explicit date so the same invocation remains
reproducible:

```sh
pcbex apply-electrical-waivers \
  electrical-review.json electrical-waivers.json \
  --as-of 2026-08-01 \
  --output electrical-waiver-report.json \
  --require-approved
```

Unknown findings, duplicate waiver IDs or targets, invalid dates, blank audit
fields, and expired waivers fail closed. The result binds canonical SHA-256
identities for the source review and waiver set. Closed contracts are emitted
by `electrical-waiver-set-schema` and `electrical-waiver-report-schema`.

Reports are deterministic and contain canonical SHA-256 identities for both
the normalized schematic and effective policy. An approval is granted only
when no enabled error-severity finding remains. A policy may explicitly
disable or change the severity of known rules; unknown rules, fields, and
schema versions fail closed. `--require-approved` writes the report before
returning nonzero so CI and later AI-review stages retain evidence.

Closed Draft 2020-12 contracts are available through
`electrical-policy-schema`, `electrical-review-schema`, and
`electrical-explanation-schema`.

## Bound simulation evidence

Simulator-independent declarations turn measured results into an auditable
approval gate. Each assertion declares a measurement, unit, and inclusive
minimum and/or maximum:

```json
{
  "schema_version": 1,
  "id": "power-rail-dc",
  "analysis": "dc_operating_point",
  "simulator": {"name": "ngspice", "version": "42"},
  "schematic_sha256": "<electrical-review schematic_sha256>",
  "assertions": [{
    "id": "vout",
    "description": "regulated output",
    "measured": 3.3,
    "unit": "V",
    "minimum": 3.2,
    "maximum": 3.4
  }]
}
```

Bind that declaration and the raw simulator output to an approved electrical
review:

```sh
pcbex record-simulation-evidence simulation.json \
  --electrical-review electrical-review.json \
  --artifact ngspice.raw --artifact measurements.csv \
  --output simulation-evidence.json --require-passed
```

Artifacts are streamed through SHA-256 rather than loaded into memory. The
deterministic evidence report records their basename, media type, byte count,
and digest together with the exact electrical-review and normalized schematic
identities. It passes only when the electrical review is approved and every
bounded assertion passes. Empty artifacts, duplicate basenames/assertions,
non-finite values, reversed bounds, mismatched schematics, unknown fields, and
future schema versions fail closed. The report is still written before a
failed assertion gate.

Supported analysis categories are DC operating point, AC sweep, transient,
signal integrity, power integrity, thermal, and custom. The engine does not
trust a specific simulator; CI supplies raw results from ngspice, SPICE,
IBIS/SI, PDN, or thermal tooling. Closed contracts are emitted by
`simulation-declaration-schema` and `simulation-evidence-schema`.

## AI schematic review and signed approval

The AI reviews intent, while pcbex retains authority over deterministic gates
and the cryptographic approval:

```sh
# Run once; existing key files are never overwritten.
pcbex approval-keygen \
  --private-key .secrets/schematic-approval.key \
  --public-key schematic-approval.pub

# Recomputes the embedded electrical review and validates every simulation
# binding. Simulation evidence is required unless explicitly waived.
pcbex prepare-ai-review design.kicad_sch \
  --electrical-review electrical-review.json \
  --policy electrical-policy.json \
  --simulation-evidence power-rail.evidence.json \
  --requirement 'power=All IC supply pins have a valid source and decoupling' \
  --requirement 'reset=Reset defaults to a defined safe state' \
  --output ai-review-request.json

# Give ai-review-request.json to the model and require the closed response
# contract emitted by `ai-review-response-schema`.

pcbex sign-ai-review ai-review-request.json ai-review-response.json \
  --private-key .secrets/schematic-approval.key \
  --signer-id production-ci \
  --output signed-approval.json --require-approved

pcbex verify-ai-approval \
  signed-approval.json ai-review-request.json ai-review-response.json \
  --public-key schematic-approval.pub --require-approved
```

With an organization policy pack, review requirements and the simulation gate
are supplied by policy, and approval verification selects the trusted key by
the signed envelope's `signer_id`. Verification also requires the request's
electrical policy, complete requirement set, and simulation gate to match the
pack exactly:

```sh
pcbex prepare-ai-review design.kicad_sch \
  --electrical-review electrical-review.json \
  --policy-pack examples/acme-policy-pack.json \
  --simulation-evidence power-rail.evidence.json \
  --output ai-review-request.json

pcbex verify-ai-approval \
  signed-approval.json ai-review-request.json ai-review-response.json \
  --policy-pack examples/acme-policy-pack.json --require-approved
```

The request embeds the normalized schematic, effective electrical policy,
freshly recomputed electrical review, bound simulation evidence, explicit
requirements, and the complete set of evidence IDs the model may cite. Its
self-identity excludes only the identity field itself, so any mutation is
detected. Every requirement must be assessed exactly once and cite at least
one known evidence ID. Unknown requirements, missing evidence, failed
simulations, ERC rejection, an AI reject/needs-human decision, or error/critical
AI risks prevent approval.

The model response is never allowed to change those gates. pcbex reevaluates
the full request immediately before signing and produces a deterministic
Ed25519 approval or rejection envelope. Verification requires the separately
trusted public-key file; trusting only the public key embedded in the envelope
would not establish signer identity. The private key is created with mode
`0600` on Unix and must never be supplied to the model.

AI integration is provider-neutral. `pcbex_agent.review_schematic_with_llm`
accepts an injected transport, rejects non-JSON or invented evidence before
Rust validation, and tells the model to use `unknown`/`needs_human` instead of
guessing. The MCP server exposes `prepare_schematic_review`,
`sign_schematic_approval`, and `verify_schematic_approval`; signing is marked
as a destructive action so MCP hosts can retain their user-approval boundary.
Closed request, response, and signature contracts are emitted by
`ai-review-request-schema`, `ai-review-response-schema`, and
`signed-ai-approval-schema`.

For a real provider, wrap its SDK or HTTP API in an executable that reads the
review prompt from stdin and writes only the response JSON to stdout. The agent
runs that adapter without a shell:

```sh
pcbex-agent review-schematic ai-review-request.json \
  --output ai-review-response.json \
  --receipt ai-provider-receipt.json \
  --timeout-seconds 120 \
  --maximum-output-bytes 1048576 \
  --provider-command ./review-adapter --model production-reviewer

pcbex-agent provider-receipt-schema \
  --output provider-receipt.schema.json
```

`--provider-command` must be last so every following token is passed as one
exact argument. pcbex-agent does not interpret a command string, expand shell
syntax, or accept or persist a provider credential. Credentials remain an
adapter concern, typically supplied through its environment. pcbex-agent
bounds stdout and stderr while the process runs, kills timed-out or oversized
providers, validates the closed response before writing anything, and refuses
to overwrite an existing response or receipt. The generated prompt labels
every schematic and requirement field as untrusted evidence rather than model
instructions, reducing prompt-injection authority at the review boundary.

The versioned receipt records SHA-256 and byte length for the request and
normalized response, the provider executable basename, a SHA-256 commitment to
the exact argument vector, and the applied runtime limits. The receipt does not
contain the prompt, command arguments, environment, or credentials. A valid
provider response still has no approval authority until `sign-ai-review`
recomputes every deterministic gate and signs it with the separately held
Ed25519 key.

## Releases

Diagnose the local CLI and its optional KiCad, Git, and Python integrations
before adding it to CI:

```sh
pcbex capabilities
pcbex doctor
pcbex doctor --require-kicad --output doctor.json
```

`capabilities` emits a versioned JSON inventory of every CLI command, supported
board schema, fabrication profile, external integration, and output contract.
Agents and CI wrappers can use it for feature discovery without parsing help
text or assuming compatibility from the executable version alone.

The command always emits a versioned JSON report. Optional integrations are
reported without failing the command; `--require-kicad` promotes KiCad CLI
availability to a required readiness check.

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

Before publication, the workflow runs `scripts/release-audit.py` against the
machine-readable [product roadmap](docs/ROADMAP.md). It requires the exact 12
release assets, downloads them, verifies every archive checksum and SPDX
document, and confirms the tag commit. Repository administrators can also
audit the live `main` protection:

```sh
python3 scripts/release-audit.py \
  --repository penguin425/pcbex \
  --check-protection
```

The protection audit requires pull-request flow, strict Rust/Python/KiCad
checks, administrator enforcement, linear history, conversation resolution,
and disabled force-pushes and deletions.

## Scope

pcbex is a deterministic physical-design engine for placed signal boards with
a versioned KiCad schematic electrical IR. It supports polygonal multilayer
boards, differential pairs, length tuning, copper zones, partial-span vias,
exact KiCad pad geometry, placement optimization, DFM reporting, and headless
or IPC-assisted KiCad workflows. It does not yet synthesize schematics, select
electrical components, perform analog or signal-integrity simulation, or
replace final KiCad ERC/DRC and fabrication review.
