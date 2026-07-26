# Routing performance

The Criterion suite measures complete deterministic routing for five scenarios:

- one net around a tall rectangular obstacle;
- five and ten parallel nets;
- one net around an internal board cutout;
- one net on a 100 mm board with 200 circular obstacles.

Run it with:

```console
cargo bench -p pcbex-core --bench routing --locked
```

Criterion stores local baselines under `target/criterion`.

GitHub Actions also runs `performance_budget`, which checks deterministic
algorithmic work instead of wall-clock time. It limits A* expanded states and
rasterized candidate cells for ten parallel nets and the 200-obstacle board.
This catches search or geometry regressions without depending on shared-runner
timing:

```console
cargo test -p pcbex-core --test performance_budget --locked -- --nocapture
```
