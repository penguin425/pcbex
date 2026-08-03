# Physical constraint profiles

A physical constraint profile is the versioned input for geometry an
autonomous layout must not guess: exact board dimensions and outline, fixed
component coordinates, routing keepouts, and manufacturing minima. The v1
document is closed and bounded. Unknown or duplicate JSON fields, unsafe
identifiers, excessive collections, invalid/self-intersecting polygons,
out-of-board geometry, duplicate references/layers, and relaxed existing
manufacturing rules are rejected.

## Inspect, validate, and apply

```sh
pcbex physical-profile-schema --output physical-profile.schema.json

pcbex validate-physical-profile \
  examples/nes-60pin-physical-profile.json \
  --output build/physical-profile.normalized.json

pcbex apply-physical-profile board.json \
  examples/nes-60pin-physical-profile.json \
  --output build/profiled-board.json
```

The validation result contains the normalized `profile` and a `binding`.
`binding.source.sha256` identifies the exact source bytes, while
`binding.canonical_sha256` is domain-separated and identifies the normalized
meaning. Whitespace-only rewrites keep the canonical digest but change the
source digest. A source path is reduced to one portable basename; host paths
never enter the portable binding.

Profile files are read as stable, non-symlink regular files with a 4 MiB
ceiling and an unchanged second pass. The profile itself is bounded to 4,096
fixed components, 4,096 keepouts, 4,096 points per polygon, and 65,536 points
in aggregate. Polygon intersection work is also finite.

## Placement, routing, and analysis

Pass the same profile to JSON or KiCad commands:

```sh
pcbex place-kicad input.kicad_pcb \
  --physical-profile profile.json --output placed.kicad_pcb

pcbex route-kicad placed.kicad_pcb \
  --physical-profile profile.json --output routed.kicad_pcb

pcbex analyze-kicad routed.kicad_pcb \
  --physical-profile profile.json --output-dir build/analysis
```

Placement sets the declared coordinate and whole-degree rotation and locks the
component before optimization. Routing and analysis require existing fixed
footprints to match the coordinate within `tolerance_nm` and the declared
rotation. Missing references, board-dimension/outline drift, or keepouts on an
undeclared copper layer fail before the caller's board is mutated. Profile
manufacturing rules can only tighten rules already embedded in a board.

KiCad placement reimports every written candidate and revalidates its fixed
footprints, effective outline, and cutouts against the profile before publishing
it. The placement optimizer itself currently has a rectangular envelope and
consumes the profile's dimensions and fixed components; routing keepouts are
enforced by the subsequent routing, analysis, and fabrication gates.

`--physical-profile` is mutually exclusive with `--fab`, `--fab-profile`, and
`--policy-pack` for KiCad analysis and routing. One profile is therefore the
sole physical/DFM authority for that run. The GitHub Action and MCP analysis
and routing tools forward the same option and retain the CLI's conflict gate.

## Manufacturing and pipeline binding

```sh
pcbex fabricate routed.kicad_pcb \
  --physical-profile profile.json --output-dir build/manufacturing

pcbex pipeline-verify \
  --schematic design.kicad_sch \
  --electrical-review build/electrical-review.json \
  --board routed.kicad_pcb \
  --analysis-manifest build/analysis/run.json \
  --analysis-checks build/analysis/checks.json \
  --quality build/analysis/quality.json \
  --analysis-physical-profile profile.json \
  --manufacturing-package build/manufacturing/manufacturing.zip \
  --firmware-manifest build/firmware/manifest.json \
  --output build/pipeline-gate.json
```

Without a profile, analysis and manufacturing continue to emit schema-v1
manifests. With a profile they emit schema v2 and require its exact binding.
The pipeline re-reads the supplied profile, checks raw and canonical digests,
recomputes analysis after applying it, and requires the manufacturing ZIP to
carry the identical binding. Factory submission already binds the complete
ZIP digest, so the profile is transitively fixed for that submission. A
factory feedback repair may change board/manufacturing artifacts but may not
add, remove, or substitute the profile binding.

The v1 profile does not perform vendor-specific CPL coordinate transforms and
does not authorize a circuit-generation provider. Those boundaries remain
vendor-neutral and are handled by the subsequent circuit-to-KiCad handoff and
factory-profile milestones.
