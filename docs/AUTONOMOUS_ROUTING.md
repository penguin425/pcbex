# Autonomous routing convergence

`route-kicad` accepts `--convergence-rounds N` (1–8). The default value `1`
preserves the single-pass router. Values greater than one run a bounded,
deterministic convergence loop:

1. inject the selected built-in, external, or policy-pack DFM profile;
2. generate Pareto candidates with the existing router;
3. score every candidate with unrouted-net count, internal DRC violations,
   length, vias, and bends; and
4. keep the best checked board, changing strategy when progress stalls.

The strategy schedule alternates the physical layer-transition policy
(`ThroughOnly` and `Auto`) and then tightens clearance in fixed 50 µm steps.
No candidate is accepted without the internal checker. A successful run writes
`<output>.convergence.json` with every round, strategy, score, selected round,
and convergence/stall status. The normal `--allow-unrouted`, internal checker,
and optional KiCad `--drc` gates still apply to the selected board.

The loop is intentionally bounded and deterministic so it can run in CI without
an unbounded autonomous process or hidden relaxation of manufacturing rules.
