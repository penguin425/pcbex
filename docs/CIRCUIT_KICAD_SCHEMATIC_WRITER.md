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

Version 1.423 exposes the same writer through MCP and the root composite
Action. An MCP call is synchronous by default and supports optional Tasks:

```json
{
  "name": "write_circuit_spec_kicad_schematic",
  "arguments": {
    "input": "circuit-spec-v2.json",
    "output": "build/generated.kicad_sch"
  }
}
```

The tool response does not embed the generated document. Its `schematic`
summary contains only the retained path, byte count, and SHA-256; the exact
file remains at `output`. This preserves the 16 MiB MCP frame even though the
writer permits a bounded document of up to 64 MiB.

The Action keeps `board` required for backward-compatible hardware analysis
and adds one opt-in input:

```yaml
- id: pcbex
  uses: penguin425/pcbex@v1.428.0
  with:
    board: hardware/controller.kicad_pcb
    circuit-spec: build/circuit-spec-v2.json
```

It first retains `output-dir/circuit-spec-check.json`. An ERC rejection
publishes that report and `circuit-spec-approved: "false"` but never invokes
the writer. Approval produces the fixed
`output-dir/circuit-spec.kicad_sch` artifact and exposes
`circuit-spec-schematic`, `circuit-spec-schematic-bytes`, and
`circuit-spec-schematic-sha256`. The generated path is not substituted for
the Action's `schematic` input and is not injected into either pipeline; a
later trusted step must opt in to those operations explicitly.

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
immutable ERC result remains the publication gate. Native ERC report v1 does
not claim a warning-free result; report v2 can apply an explicit warning
budget without weakening the error gate.

## Native KiCad ERC handoff

Writer publication and pcbex's immutable circuit-spec ERC remain the first
gates. To add KiCad's independent electrical checker, run the retained
schematic through the bounded native runner:

```sh
pcbex run-native-kicad-erc build/circuit-spec.kicad_sch \
  --output build/native-kicad-erc.json --require-approved

pcbex run-native-kicad-erc build/circuit-spec.kicad_sch \
  --warning-policy examples/native-kicad-warning-policy.json \
  --output build/native-kicad-erc-warning.json --require-approved
```

The runner stages only the schematic bytes in a private directory and invokes
KiCad with `--severity-error`; it does not load a sibling `.kicad_pro` or
other sidecar. KiCad warnings are outside the v1 native approval/report
contract. The opt-in v2 contract invokes explicit error and warning severities
and accepts the current writer fixture's 11 known warnings only under the
closed sample policy; unlisted warnings, excessive counts, unapproved ignored
checks, and every electrical error reject. A rejected report is retained
before `--require-approved` returns a
failure, so CI can inspect the exact evidence. The normalized report binds the
writer output's source byte count/SHA-256 and a deterministic native run
digest. See [`NATIVE_KICAD_ERC.md`](NATIVE_KICAD_ERC.md).

When a v1 report is supplied to `prepare-ai-review` together with the
deterministic plan and retained report, the request becomes schema v3 with an
artifact binding schema v2. Signing, verification, quorum, MCP, the Python
adapter, and the composite Action accept the same opt-in native evidence; the
legacy v1 unbound and v2 deterministic-only flows remain unchanged.

Supplying a v2 report plus
`--native-kicad-erc-warning-policy examples/native-kicad-warning-policy.json`
produces request schema v4/artifact binding v3/native identity v2. The same
trusted policy path is mandatory during signing and both verification modes.

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
implicit pipeline orchestration, or pipeline approval. Downstream designs must
still pass the normal schematic, board-binding, pipeline, manufacturing, and
approval gates.
