# Numeric and raster resource limits

pcbex treats KiCad and board-model dimensions as untrusted input. Syntax
limits are documented separately in
[`KICAD_SEXP_LIMITS.md`](KICAD_SEXP_LIMITS.md); this boundary starts after
syntax parsing and rejects unsafe numeric values or statically excessive
physical work before routing, checking, raster allocation, or zone mutation.

## Numeric conversion

Every imported physical millimetre value must be finite and must round into the
mathematical nanometre interval `[i64::MIN, 2^63)`. Dimensions additionally
enforce their nonnegative or positive contract. A physical field that is
present but malformed, repeated, structurally invalid, or out of range is an
error; only a genuinely absent optional field may use its documented default.

The checked path covers board outlines, footprint and pad positions, pad size,
shape, drill and custom geometry, track segments and arcs, vias, keepouts,
copper-zone outlines and fills, courtyards, stackup dimensions, and schematic
coordinates. Explicit invalid routing-relevant copper layer sets and
unsupported pad geometry are also rejected instead of being normalized to a
default physical interpretation.

Some derived internal geometry still uses saturating translation to preserve a
representable intermediate value. It runs only after checked import, and the
core preflight below rejects coordinates and dimensions outside the supported
board domain before high-cost work.

## Production ceilings

`pcbex-core::validate_routing_resource_bounds` enforces these fixed ceilings.
`RoutingResourceLimits` exists for exact-boundary tests and embedded callers;
custom ceilings may only tighten the production values.

| Resource | Production ceiling |
| --- | ---: |
| Board dimension | 1,000,000,000 nm (1,000 mm) |
| Absolute board-space coordinate | 1,000,000,000 nm |
| Cells in one raster plane | 1,000,000 |
| Plane-cell/layer slots | 2,000,000 |
| Cumulative raster candidate visits | 10,000,000 |
| Clearance/inflation radius | 128 cells |
| Vertices in one polygon | 4,096 |
| Vertices across all polygons | 65,536 |
| Pairwise topology/checker work | 8,500,000 pairs |
| Raster polygon-edge evaluations | 50,000,000 edge visits |
| Copper-zone candidate cells | 524,288 |
| Copper-zone blocker evaluations | 50,000,000 operations |
| Cells in one rasterized line | 1,000,000 |

All products and sums are computed with checked `u128` or `i128` arithmetic
before narrowing. Accounting includes the effective rectangular outline when a
board has no explicit outline; board/cutout edge tests; polygon obstacle and
track-keepout windows; static accounting of existing segment/via clearance
scans and runtime counting of generated scans; route cross-products and
self-pairs used by the checker; drilled-hole pairs;
and modeled per-cell zone outline, boundary, blocker, route, and thermal-pad
predicate work. Layer-vector membership scans and the cardinality of outer
blocker collection remain separate follow-up accounting; this preflight does
not claim to bound every container traversal.

## Enforcement points and failure behavior

The production preflight runs at the start of `Router` construction,
`route_board` before escape preparation, and `check_board` before geometry
linearization or pairwise checks. `try_fill_copper_zones` repeats the preflight,
requires positive board and grid dimensions, prepares every fill separately,
and commits only after all zones succeed. Therefore a resource or arithmetic
failure leaves the caller's zone fills unchanged.

The historical `fill_copper_zones(&mut Board) -> usize` API remains available
for source compatibility and performs an atomic no-op returning zero on error.
New integrations should call `try_fill_copper_zones` so they can distinguish an
empty valid fill from a rejected input.

Errors are stable, fail-closed strings beginning with `resource limit exceeded:`
or `resource limit configuration:` and name the rejected resource. A caller
must not retry the same model by silently relaxing these ceilings.

## Separate runtime budgets

These limits bound work that can be derived from one immutable board before the
operation begins. A* routing now has an additional aggregate runtime ceiling,
documented in [`ASTAR_WORK_BUDGET.md`](ASTAR_WORK_BUDGET.md), and zone-fill
connectivity has a separate queue-work ceiling documented in
[`ZONE_FILL_WORK_BUDGET.md`](ZONE_FILL_WORK_BUDGET.md). None of these boundaries
is a whole-command deadline or a shared budget across a multi-candidate
portfolio.

Generic Rust CLI files and the doctor, KiCad, and MCP subprocess paths now have
separate dynamic controls documented in
[`CLI_IO_LIMITS.md`](CLI_IO_LIMITS.md). Repeated routing-candidate portfolios,
aggregate arc linearization, placement/optimization passes, specialized
manufacturing artifact walkers, and Python or CI subprocesses still require
their own aggregate controls. Keeping those boundaries explicit prevents this
static preflight from claiming a whole-command wall-clock guarantee it does not
provide.
