# Deterministic A* work budget

pcbex applies a fixed aggregate work ceiling after the static numeric and
raster preflight. The production limit is 2,000,000 A* work units for one
top-level `route_board` operation.

## Accounting

One work unit is charged for either of these operations:

- removing an entry from an A* heap, including a stale entry that is discarded;
- inserting an improved node through a successful relaxation.

Initial frontier insertion is not a relaxation and is not charged. The same
budget spans coupled differential-pair searches, ordinary multi-terminal nets,
rip-up/retry passes, validation reroutes, and routes attempted by automatic
shove. Constructing a temporary `Router`, starting another net, or beginning a
new pass does not reset it.

## Determinism and failure behavior

First-pass parallel nets receive work leases in stable routing order. Workers
never race for the last shared unit, and their results are accounted and
committed in the same order regardless of scheduling. Any deterministic
sequential fallback consumes only the remaining aggregate allowance. Automatic
shove also examines blocking net IDs in sorted order.

If routing requires another charged operation after the allowance is spent,
that interruption is distinct from an ordinary unroutable net. Using the final
unit and then naturally completing or exhausting the search is valid. Checked
board-routing APIs return a stable error beginning with
`resource limit exceeded:` and do not publish a partially routed board. The
historical report-only `Router::route_all*` APIs retain source and behavior
compatibility: a resource failure returns the input board's existing routes,
marks the other nets unrouted, and exposes no partial candidates.

## API

`route_board` and `route_board_with_workers` enforce the production ceiling.
`route_board_with_work_budget` is the checked integration/test entry point for
a smaller explicit limit while retaining a deterministic worker bound. Limits
larger than the production ceiling are rejected as configuration errors rather
than silently weakening the boundary.

The limit is aggregate only within one board-routing call. A historical
`route_candidates` portfolio gives each candidate its own top-level budget.
The opt-in `route_board_with_convergence` boundary instead divides one declared
ceiling deterministically across every round/candidate slot, so the complete
portfolio cannot exceed it. Unused slot allocations are not reassigned. See
[`ROUTING_CONVERGENCE.md`](ROUTING_CONVERGENCE.md) for the exact allocation and
selection contract. This budget is not a wall-clock deadline and does not cover zone BFS,
arc linearization, placement, post-route optimization, file I/O, or child
process execution. Zone BFS has its own independent ceiling documented in
[`ZONE_FILL_WORK_BUDGET.md`](ZONE_FILL_WORK_BUDGET.md); the other boundaries
remain separately tracked.
