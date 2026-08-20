# Bounded deterministic routing convergence

`pcbex` can run a bounded portfolio of deterministic routing strategies and
feed only an improved, rule-clean result into the next round. The feature is
opt-in. Existing single-pass `route` and `route-kicad` behavior stays unchanged
unless `--convergence-report` is present.

## Quick start

Route board JSON and retain the exact convergence decision:

```sh
pcbex route board.json \
  --output board.routed.json \
  --convergence-report board.routing-convergence.json
```

Use the same boundary with a placed KiCad board:

```sh
pcbex route-kicad board.kicad_pcb \
  --output board.routed.kicad_pcb \
  --convergence-report board.routing-convergence.json
```

Discover the closed report contract without parsing help text:

```sh
pcbex routing-convergence-report-schema \
  --output routing-convergence-report-v1.schema.json
```

> [!NOTE]
> The report path is explicit. pcbex never creates an implicit file beside the
> routed board.

## Options and bounds

| CLI option | Default | Accepted range | Meaning |
| --- | ---: | ---: | --- |
| `--convergence-rounds` | 3 | 1–8 | Maximum accepted-input rounds |
| `--convergence-candidates` | 5 | 1–32 | Candidate slots in each round |
| `--convergence-workers` | 4 | 1–8 | Parallel candidate workers |
| `--convergence-router-workers` | 2 | 1–8 | First-pass router workers per candidate |
| `--convergence-work-budget` | 2,000,000 | candidate slots–2,000,000 | Aggregate A* work allocation |

Candidate workers multiplied by router workers may not exceed 16. Every tuning
option requires `--convergence-report`, so an accidental flag cannot change the
historical single-pass path.

The Rust API exposes the same contract through `RoutingConvergenceOptions` and
`route_board_with_convergence`.

## Strategy schedule

Candidate IDs follow `round-NNN-candidate-NNN`. The global candidate index
selects a stable objective and search variant:

- **Balanced:** Keep the input bend and via costs.
- **Shortest:** Remove bend cost and reduce via cost.
- **Via minimized:** Increase only the route-search via cost.
- **Bend minimized:** Increase only the route-search bend cost.
- **Alternate order:** Keep both costs and use the next deterministic search
  ordering.

Every candidate starts from the same immutable round input. Temporary objective
costs guide search only; pcbex restores the complete original `Rules` value on
every candidate before checking or selection.

pcbex does not lower clearance, track width, via diameter, drill, DFM minima,
net-class limits, layer constraints, keepouts, or electrical policy. It also
does not switch to a more permissive via strategy.

## Aggregate A* budget

One declared budget covers every candidate slot across every declared round.
For `S = rounds × candidates`, each slot receives `budget / S` units and the
first `budget % S` slots receive one additional unit. Unused units are not
reassigned, which keeps allocation independent of thread scheduling.

The sum of attempted slot allocations never exceeds the declared maximum.
Early convergence leaves later allocations unused. `allocated_work_units` in
the report records reserved candidate allocations, while `expanded_states`
records the router's successful report metric; they are deliberately different
quantities.

The unit definition and checked A* failure behavior remain those in
[Deterministic A* work budget](ASTAR_WORK_BUDGET.md). This is not a wall-clock
deadline and does not cover checking, serialization, file I/O, KiCad, or zone
fill.

## Admission and selection

An input board may be incomplete only through checker findings whose rule is
`unrouted`. Any other initial violation is a hard error before candidate work.

Each completed candidate runs through the full internal board checker:

- **Admissible:** No checker finding except `unrouted`.
- **Rejected DRC violations:** One or more other checker findings. The candidate
  is retained in the report but cannot win.
- **Routing failed:** The bounded routing call failed. Metrics and DRC count are
  `null`, and the candidate cannot win.

pcbex ranks admissible candidates by this exact tuple:

1. fewer unrouted nets;
2. lower selection cost under the original input costs;
3. shorter total route length;
4. fewer vias;
5. fewer bends; and
6. lexicographically smaller stable candidate ID.

A DRC-invalid result therefore cannot outrank a valid partial route. Candidate
duplicates remain visible, but the earliest identical candidate wins every
tie.

The round winner becomes the next round input only when its tuple strictly
improves on the current input. pcbex stops on complete routing, no admissible
candidate, no strict improvement, or the configured round ceiling. Existing
routed copper stays reserved under the normal router contract.

## Report contract

The schema-v1 report is path-free and closes every object and array. It retains:

- engine version, options, terminal status, and stop reason;
- canonical compact-JSON byte count and SHA-256 for the effective input Board
  and selected final Board;
- input and final routed/unrouted, length, via, and bend metrics;
- aggregate candidate count and allocated work;
- every round input, strategy, budget allocation, status, checker violation
  count, metrics, duplicate identity, and selection reason; and
- the exact round/candidate accepted as the next input.

The canonical Board identities bind the internal model after profile, KiCad
project, custom-rule, and DFM application. They do not authenticate raw JSON,
raw KiCad text, companion files, or the origin of those policies.

Use [Fresh Routing Convergence Verification](ROUTING_CONVERGENCE_VERIFICATION.md)
when a later consumer must capture those raw sources, reproduce this complete
report, and require the routed JSON or KiCad artifact byte for byte. The Rust
API exposes the inner replay as `verify_routing_convergence_report`.

`design_rules_unchanged: true` means the selected Board retains the exact input
`Rules` value. `final_drc_violation_count` excludes only the explicit
`unrouted` finding and must be zero for every returned result.

## Publication and failure

The report destination must be new and must not alias the board input, board
output, profile/rule inputs, SVG output, or JSON adapter output. pcbex rejects
symbolic-link path components, stages the complete report beside the
destination, flushes and synchronizes it, then publishes without replacement.

A valid partial or no-candidate report and its unchanged/partially routed Board
are retained before the normal unrouted gate returns nonzero. Add
`--allow-unrouted` only when a downstream process intentionally consumes that
partial result.

Malformed options, non-`unrouted` input violations, resource-bound rejection,
serialization failure, unsafe aliases, occupied report paths, and output
publication failures are hard errors. The board and report are separate file
publications, not one transaction.

## Nonclaims

Routing convergence proves a deterministic bounded local selection under the
embedded rules. It does not prove global optimality, routing completeness,
native KiCad DRC, DFM suitability for a fabricator, signal integrity,
manufacturability, external-tool authenticity, source-file authenticity, or
release authorization.

Run native DRC and the relevant manufacturing/evidence gates after routing.
Treat retained partial reports as diagnostics, not approval artifacts.
