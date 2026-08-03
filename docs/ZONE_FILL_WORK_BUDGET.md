# Deterministic zone-fill work budget

pcbex applies a fixed aggregate queue-work ceiling while retaining the connected
copper component for every zone. The production limit is 1,048,576 units for
one top-level fill operation.

## Accounting and ceiling

One work unit is charged before either of these operations:

- removing one cell from the zone-connectivity queue;
- inserting one previously undiscovered candidate neighbor into that queue.

The initial seed insertion for each nonempty zone is not charged. Seeds use the
owning net's terminal order, with a lexicographically smallest-cell fallback,
and neighbors are considered in a fixed order. Only candidate cells that have
not already been discovered are enqueued, so duplicate and out-of-zone queue
entries cannot amplify work or memory.

For a zone whose retained connected component contains `C` cells, the exact
charge is `2C - 1`: every cell is removed once and every cell except the seed is
inserted once. The static preflight limits the aggregate candidate windows for
all zones to 524,288 cells. Consequently twice that existing ceiling,
1,048,576 units, safely bounds all connectivity queues without weakening the
static candidate-cell or blocker-evaluation limits.

## Sharing, determinism, and failure

One budget is shared in stable route and zone order across all zones processed
by a call. Filled cell polygons are sorted before publication. Exhaustion
returns a stable error beginning with `resource limit exceeded:` and publishes
no partial result: every `filled_polygons` value remains exactly as it was on
entry. Using the final unit is valid when no further charged operation is
needed.

The historical `fill_copper_zones(&mut Board) -> usize` API retains its
count-only behavior. Any checked failure becomes an atomic no-op returning zero.
`try_fill_copper_zones` keeps its existing checked signature and uses the
production budget.

## API and scope

`try_fill_copper_zones_with_work_budget` lets integrations and tests select a
smaller limit. A value above the production ceiling is rejected as a resource
limit configuration error rather than silently relaxing the boundary.

Each top-level fill call, including a fill performed by a routing candidate or
repair stage, receives its own budget. This budget is not a wall-clock deadline
and does not replace the static bounds on raster candidate scans, polygon-edge
predicates, or blocker checks.
