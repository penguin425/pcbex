# Routing performance

The Criterion suite measures complete deterministic routing for these scenarios:

- one net around a tall rectangular obstacle;
- five and ten parallel nets;
- ten parallel nets with explicit 1, 2, 4, and 8 worker limits;
- one net around an internal board cutout;
- one net on a 100 mm board with 200 circular obstacles.

Run it with:

```console
cargo bench -p pcbex-core --bench routing --locked
```

Criterion stores local baselines under `target/criterion`.

The `parallel_workers/*` cases are wall-clock measurements of the same board and
therefore show the scaling and thread overhead on the machine running the
benchmark. `route_board_with_workers` makes these comparisons repeatable while
the normal `route_board` entry point continues to select the available CPU
parallelism automatically (up to eight workers).

GitHub Actions also runs `performance_budget`, which checks deterministic
algorithmic work instead of wall-clock time. It limits A* expanded states and
rasterized candidate cells for ten parallel nets and the 200-obstacle board.
This catches search or geometry regressions without depending on shared-runner
timing:

```console
cargo test -p pcbex-core --test performance_budget --locked -- --nocapture
```
