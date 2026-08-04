# Deterministic circuit-spec v2 to KiCad schematic writer

`pcbex write-circuit-spec-kicad-schematic` turns the closed circuit-spec v2
contract into a self-contained KiCad `.kicad_sch` file without a GUI, network
request, supplier lookup, or external symbol-library lookup.

```sh
pcbex write-circuit-spec-kicad-schematic circuit-spec-v2.json \
  --output hardware/generated.kicad_sch

pcbex verify-circuit-kicad-handoff \
  circuit-spec-v2.json hardware/generated.kicad_sch \
  --output build/circuit-kicad-handoff.json \
  --require-approved
```

The command always normalizes the input and runs the immutable ERC safety
floor. A rejected design produces no schematic. Before returning generated
bytes, the writer re-imports them with pcbex's bounded KiCad parser and runs
the existing semantic handoff verifier against the normalized input. A parser,
coverage, ERC, or semantic mismatch therefore fails before publication.
The KiCad end-to-end job also opens the emitted file with KiCad 10, exports its
native XML netlist, and compares the complete pin sets (including the explicit
no-connect) with the source fixture. This independently checks KiCad's own
coordinate and connectivity semantics rather than relying only on pcbex's
importer.

## Deterministic mapping

The v1 writer supports the same deliberately small boundary as the handoff
verifier: a flat schematic with one unit per symbol. It emits synthetic
embedded symbol definitions, fixed-grid symbol and pin positions,
domain-separated stable UUIDs, explicit net labels, voltage labels, and
no-connect markers. Reference, value, footprint, MPN, and `pcbex:*` power
metadata survive the write/import round trip.

When a circuit net has `voltage_uv`, the writer intentionally emits both the
declared net name and its canonical voltage label. That is how the existing
handoff gate proves the voltage annotation survived, but KiCad may report its
advisory `multiple_net_names` warning when those two names differ. The pcbex
immutable ERC result remains the publication gate; this v1 boundary does not
claim a warning-free native KiCad ERC report.

Normalization makes part, pin, net, and connection ordering independent of the
source JSON order. Output contains no timestamp, source path, random value, or
host-specific library result, so the same normalized circuit and pcbex version
produce the same UTF-8 bytes. Symbol-library identifiers are retained as
metadata; the embedded drawings are intentionally synthetic and are not a
claim that a system KiCad library was consulted.

## Publication and safety boundary

Input uses the circuit-spec byte and topology limits. Generated text has a
fixed byte ceiling and uses checked coordinates and escaping. Ambiguous label
collisions and incompatible pin signatures for a reused library identifier are
rejected. Library identifiers containing a quote or backslash are also
rejected because KiCad 10 cannot load those identifiers even when their
S-expression text is escaped; those characters remain supported in ordinary
component metadata. The CLI refuses input/output aliases, existing destinations,
symlinks, and symlinked parents, then publishes the one file atomically.
As with pcbex's existing generic single-file no-clobber publisher, the output
directory is a trusted local boundary: it must not be concurrently renamed or
replaced by an attacker between preflight and commit. Directory-descriptor-
anchored publication is already used by manufacturing workspaces, but is not
yet the cross-platform contract of this command.

This writer creates a logical handoff artifact, not a production layout. It
does not support hierarchy, buses, multi-unit symbols, external library
resolution, graphical symbol fidelity, editing or merging an existing
schematic, PCB placement/routing, DRC/DFM, manufacturing export, MCP/Action
orchestration, or pipeline approval. Downstream designs must still pass the
normal schematic, board-binding, pipeline, manufacturing, and approval gates.
