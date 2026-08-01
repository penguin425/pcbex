# Physical orchestration profile

The `physical-profile` contract binds the physical inputs that an autonomous
layout run must not guess: board dimensions, fixed connector coordinates,
routing keepouts, and manufacturing minimums.

Inspect the schema with:

```sh
cargo run -p pcbex -- physical-profile-schema
```

Validate or apply a profile to a board JSON document:

```sh
cargo run -p pcbex -- validate-physical-profile \
  examples/nes-60pin-physical-profile.json
cargo run -p pcbex -- apply-physical-profile board.json \
  examples/nes-60pin-physical-profile.json -o build/profiled-board.json
```

For a KiCad route, pass the same profile directly:

```sh
cargo run -p pcbex -- route-kicad input.kicad_pcb \
  --physical-profile examples/nes-60pin-physical-profile.json \
  --convergence-rounds 4 -o build/routed.kicad_pcb
```

The profile is applied before routing. Existing fixed footprints must match the
declared reference, position, and rotation within the explicit tolerance;
missing or drifting connectors fail closed. Fixed-component body keepouts and
profile keepouts are added to every declared copper layer, and the embedded
manufacturing rules raise (never relax) the router minimums. A profile cannot
silently override a separately selected `--fab`, external DFM profile, or
organization policy pack.
