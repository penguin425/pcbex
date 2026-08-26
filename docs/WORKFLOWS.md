# Workflow guide

`pcbex` supports several hardware paths, but no single command owns the full
design-to-order lifecycle. Choose the narrowest workflow that produces the
evidence your next consumer actually needs.

## Choose a path

| Starting point | Desired result | Path |
| --- | --- | --- |
| Board JSON | Routed and internally checked board | `route` → `check` |
| Placed KiCad PCB | Routed board and optional native DRC | `route-kicad` → native DRC |
| Clean KiCad PCB | Reproducible manufacturing archive | `fabricate` |
| Converged KiCad PCB plus retained ZIP | Fresh board-to-package evidence | routing verification → routing/manufacturing handoff |
| Converged KiCad PCB plus retained ZIP and native DRC | Fresh clean release evidence | routing/manufacturing handoff → routing/native-DRC/manufacturing handoff |
| Fresh clean package plus factory pipeline and approvals | Policy-pinned offline fabrication release | routing/DRC handoff → fabrication authorization → release composition |
| Retained fabrication release plus protected binary pins | Digest-pinned point-in-time release | stable v1.478 subject → three native entrypoint pin checks → fresh assessment and outer binding |
| Digest-pinned release plus signed factory receipt | Authenticated receipt release | stable v1.479 subject → policy-pinned receipt signature → fresh outer authentication |
| Durable signed factory release | Idempotency-keyed adapter handoff | authenticated v1.480 release → local v1.481 reservation → durable intent → one POST or GET reconciliation |
| Durable release with authenticated adapter evidence | Policy-pinned signed response handoff | v1.481 reservation → unchanged v1.482 intent → one signed POST or GET → durable v1.483 authentication report |
| Durable release with authenticated state history | Rollback-resistant adapter handoff | v1.481 reservation → unchanged intent/receipt → signed genesis → head-bound one-step reconciliation → durable v1.484 state chain |
| Current factory state plus external transparency receipt | Policy-pinned inclusion evidence | complete v1.484 chain replay → exact current head → supplied signed Merkle receipt → durable v1.485 report |
| Retained and newer transparency checkpoints | Selected-log append-only evidence | retained v1.485 anchor → supplied newer receipt and RFC 6962-shaped consistency path → durable v1.486 chain |
| Latest consistent checkpoint plus witness receipts | Selected-witness checkpoint agreement | complete v1.486 chain replay → externally pinned witness policy → distinct-organization Ed25519 quorum → durable v1.487 report |
| Latest witness-backed checkpoint plus external inclusion proof | Separately anchored checkpoint evidence | complete v1.487 replay → independently pinned external log → signed tree head and bounded Merkle path → durable v1.488 report |
| Retained external anchor plus newer signed views | Selected external-log append-only evidence | complete v1.488 replay → authenticated old/new heads → bounded consistency proof → durable v1.489 chain |
| Latest external-log consistency head plus an observer receipt | Selected external-log gossip evidence | complete v1.489 replay → log and observer signature checks → exact-head comparison → optional consistency proof → durable v1.490 report |
| Latest external-log consistency head plus remote observer endpoints | Selected external-log quorum evidence | bounded observation acquisition → hash-bound transport receipts → full v1.490 replay per observer → exact-head organization quorum → durable v1.491 report |
| Base observer policy plus successor keys | Rotated external-log quorum trust | export latest trust → old/new dual-sign → no-replace apply → derive effective v1.491 policy → acquire and verify → bind durable quorum to complete histories |
| Durable observer-trust quorum plus organization authority | Governed external-log quorum eligibility | pin empty registry genesis → admit exact current trust states → retain signed transitions → bind durable v1.492 quorum to latest active organizations |
| Governed observer registry plus successor authority key | Rotated registry authority trust | export latest registry → old/new dual-sign → serialized no-replace apply → replay mixed transition/rotation history → bind the durable observer quorum |
| Rotated observer registry plus multiple administrators | Threshold-governed registry decisions | export latest registry → root-sign fixed governance → collect distinct administrator approvals → serialized no-replace apply → replay mixed history with root-only mutation locked out |
| Threshold-governed observer registry plus successor policy | Rotated registry governance | export latest registry → root-sign state-bound successor governance → satisfy retained and successor quorums → serialized no-replace apply → replay four event types |
| Rotatable governance plus a prospective registry root | Governed root handoff | export exact active state → prospective-root-sign successor governance → satisfy both governance quorums → atomically rotate root and governance → replay five event types |
| Retained authenticated receipt release | Local at-most-once admission | fresh v1.480 replay → active-window checks → pinned-ledger no-replace marker |
| Circuit specification | Checked schematic and board handoff | circuit check → KiCad writers → binding |
| Natural-language requirements | Provider proposal accepted by deterministic ERC | `pcbex-agent generate-circuit` |
| Manufacturing package | Exact BOM/CPL and procurement intent | final verifiers → procurement intent |
| Complete assembly and offer evidence | Point-in-time dual-control release decision | evidence replay → signed approvals → authorization |

> [!TIP]
> Stop at the first artifact that satisfies the downstream contract. Additional
> composition creates stronger identity binding, but it also adds more inputs,
> replay work, and trust roots.

## Board routing

### JSON board flow

Use board JSON when you control the geometric input and want the smallest
deterministic routing surface:

```sh
pcbex route board.json --output board.routed.json --svg board.svg
pcbex check board.routed.json
```

Existing routes remain reserved. Missing nets are routed, then the complete
board passes through the checker before the output is accepted.

For difficult boards, opt into bounded convergence and retain every strategy
decision:

```sh
pcbex route board.json \
  --output board.routed.json \
  --convergence-report board.routing-convergence.json

pcbex verify-routing-convergence board.json \
  --routed board.routed.json \
  --report board.routing-convergence.json \
  --output board.routing-verification.json \
  --require-complete
```

The single-pass route remains the default. The convergence boundary shares one
A* allocation across all rounds, excludes non-`unrouted` checker violations
from selection, and retains a valid partial report before the unrouted gate.
Read [Routing Convergence](ROUTING_CONVERGENCE.md) before consuming partial
results. Use [Fresh Routing Convergence Verification](ROUTING_CONVERGENCE_VERIFICATION.md)
when a later handoff must reproduce the decision from raw sources and match the
routed artifact exactly.

Use `repair` to reroute only checker-selected or explicitly named nets:

```sh
pcbex repair board.routed.json --output board.repaired.json
pcbex repair board.routed.json --output board.repaired.json \
  --net-id 12 --net-id 15
```

Inspect the current input contract with `pcbex schema`. Apply a strict
[physical profile](PHYSICAL_CONSTRAINT_PROFILE.md) when board construction,
placement, or edge constraints must travel with the result.

### KiCad board flow

Use `route-kicad` when the source of truth is a placed KiCad board:

```sh
pcbex route-kicad hardware/controller.kicad_pcb \
  --output build/controller.routed.kicad_pcb \
  --physical-profile config/controller-physical.json \
  --svg build/controller.svg
```

Run native DRC as a separate evidence boundary when you need a retained,
freshly replayable report:

```sh
pcbex run-native-kicad-drc build/controller.routed.kicad_pcb \
  --output build/native-kicad-drc.json \
  --require-approved
```

Read [Native KiCad PCB DRC](NATIVE_KICAD_DRC.md) for companion-file discovery,
normalization, replay, and rejection semantics.

## Circuit-to-KiCad handoff

The deterministic circuit path keeps model output away from executable source
and KiCad files. Rust validates the closed specification before either writer
publishes an artifact.

1. **Check the specification.** Run `pcbex check-circuit-spec` against
   circuit-spec v2, or opt into v3 for explicit multi-unit parts.
2. **Write the schematic.** Use `write-circuit-spec-kicad-schematic` only after
   the immutable ERC floor approves the input.
3. **Verify the handoff.** Bind the specification and schematic with
   `verify-circuit-kicad-handoff`.
4. **Generate the board.** Apply a footprint closure, construction profile, and
   physical profile with `generate-circuit-kicad-board`.
5. **Verify board binding.** Recheck the exact specification, schematic, and
   generated board with `verify-circuit-kicad-board-binding`.

The focused contracts document each boundary:

- [KiCad Schematic Writer](CIRCUIT_KICAD_SCHEMATIC_WRITER.md)
- [Multi-unit Circuit Spec](MULTI_UNIT_CIRCUIT_SPEC.md)
- [Circuit-to-KiCad Handoff](CIRCUIT_KICAD_HANDOFF.md)
- [KiCad Board Writer](CIRCUIT_KICAD_BOARD_WRITER.md)
- [Circuit-to-Board Binding](CIRCUIT_KICAD_BOARD_BINDING.md)

Use the [Circuit Handoff Bundle](CIRCUIT_HANDOFF_BUNDLE.md) when one portable ZIP
must retain and replay the complete producer chain.

## Provider-driven circuit generation

`pcbex-agent generate-circuit` lets a caller-selected provider propose circuit
specifications. The provider never writes arbitrary Python or KiCad source;
every candidate must pass the Rust schema and electrical checks.

```sh
pcbex-agent generate-circuit requirements.txt \
  --output build/circuit-generation.json \
  --skidl-output build/circuit.py \
  --pcbex target/release/pcbex \
  --catalog-snapshot examples/catalog-snapshot-v1.json \
  --require-basic \
  --provider-command ./structured-circuit-provider --model circuit-model
```

`--provider-command` must be the final option because it consumes the remaining
arguments. Treat that executable as unsandboxed caller-selected code, then read
[Bounded Circuit Generation](CIRCUIT_GENERATION.md) and
[Python Agent Limits](PYTHON_AGENT_LIMITS.md).

## Manufacturing and firmware

### Manufacturing package

`fabricate` runs native KiCad DRC before publishing a normalized manufacturing
tree and canonical ZIP:

```sh
pcbex fabricate build/controller.routed.kicad_pcb \
  --physical-profile config/controller-physical.json \
  --output-dir build/manufacturing
```

The ZIP becomes meaningful only with its manifest and exact source identity.
Review [Manufacturing Package](MANUFACTURING_PACKAGE.md), then use
[Final CPL Verification](FINAL_CPL.md) when board placement must match the
package exactly.

When a downstream consumer must prove that the converged routed board is also
the board that reproduces the retained ZIP, compose both fresh checks:

```sh
pcbex-agent replay-routing-manufacturing-handoff \
  hardware/controller.kicad_pcb build/controller.routed.kicad_pcb \
  --convergence-report build/controller.convergence.json \
  --routing-verification-report build/controller.routing-verification.json \
  --manufacturing-package build/manufacturing/manufacturing.zip \
  --output build/controller.routing-manufacturing.json \
  --require-ready
```

This is artifact-consistency evidence, not fabrication approval. Read
[Fresh Routing-to-Manufacturing Handoff](ROUTING_MANUFACTURING_HANDOFF.md) for
the exact closure and nonclaims.

When the same handoff must also carry independently replayable normalized
native DRC evidence, retain the DRC report and compose one more boundary:

```sh
pcbex run-native-kicad-drc build/controller.routed.kicad_pcb \
  --output build/controller.native-drc.json --require-approved

pcbex-agent replay-routing-drc-manufacturing-handoff \
  hardware/controller.kicad_pcb build/controller.routed.kicad_pcb \
  --convergence-report build/controller.convergence.json \
  --routing-verification-report build/controller.routing-verification.json \
  --manufacturing-package build/manufacturing/manufacturing.zip \
  --routing-manufacturing-handoff-report build/controller.routing-manufacturing.json \
  --native-drc-report build/controller.native-drc.json \
  --output build/controller.routing-drc-manufacturing.json \
  --require-ready
```

This promotes only the native-DRC evidence claim. Manufacturability,
fabrication authorization, and release authority remain separate; see
[Fresh Routing, Native DRC, and Manufacturing Handoff](ROUTING_DRC_MANUFACTURING_HANDOFF.md).

When a deployment also has a factory-required pipeline, an externally expected
canonical policy digest, and dedicated fabrication approvals, compose the
point-in-time decision with
[Policy-pinned Routing, DRC, and Fabrication Release](ROUTING_DRC_FABRICATION_RELEASE.md).

When deployment policy also owns expected hashes for the routing pcbex,
authorization pcbex, and KiCad CLI files, add the strict
[Executable-pinned Fabrication Release](EXECUTABLE_PINNED_FABRICATION_RELEASE.md)
consumer. It binds those entrypoint observations without promoting them to
binary-origin, dynamic-library, plugin, loader, sandbox, or OS provenance.

### Firmware evidence

`generate-firmware` derives sources from the canonical schematic IR.
`verify-firmware-build` freshly compiles and smoke-tests the exact retained
bundle.

These commands prove a bounded build relationship, not firmware correctness on
real hardware. See [Firmware Generator](FIRMWARE_GENERATOR.md) and
[Firmware Build Verification](FIRMWARE_BUILD_VERIFICATION.md).

### Complete pipeline

Use [Hardware Pipeline Gate](PIPELINE_GATE.md) to bind electrical review, board
analysis, routing quality, manufacturing, firmware, and optional factory
evidence. Use [Deterministic Pipeline Runner](DETERMINISTIC_PIPELINE_RUNNER.md)
when the plan and its selected inputs must be snapshotted and replayed under one
outer boundary.

## Procurement release

The procurement chain advances through deliberately separate artifacts:

1. **Final BOM:** Verify that one manufacturing ZIP contains the canonical BOM
   for the exact board.
2. **Procurement intent:** Replay catalog-backed selections and bind them to the
   exact per-board BOM.
3. **Supplier acquisition:** Retain one bounded response and transport receipt.
4. **Coverage:** Correlate offer lines, requested board count, currency, and
   component-line subtotal.
5. **Assembly composition:** Bind manufacturing, placement, procurement, and
   offer evidence into one exact closure.
6. **Authorization:** Require policy-pinned Ed25519 approvals over the same
   bounded commercial scope.
7. **Local admission:** Freshly replay the retained authorization and reserve
   its challenge in one pinned local ledger before an external handoff.

Read these contracts in order:

- [Procurement Intent](PROCUREMENT_INTENT.md)
- [Supplier Offer Acquisition](SUPPLIER_OFFER_ACQUISITION.md)
- [Supplier Offer Coverage](SUPPLIER_OFFER_COVERAGE.md)
- [Assembly Evidence](ASSEMBLY_EVIDENCE.md)
- [Assembly and Supplier Offer Evidence](ASSEMBLY_SUPPLIER_OFFER_EVIDENCE.md)
- [Procurement Authorization](PROCUREMENT_AUTHORIZATION.md)
- [Procurement Authorization Reservation](PROCUREMENT_AUTHORIZATION_RESERVATION.md)

> [!WARNING]
> Authorization is a point-in-time signed handoff decision. Local reservation
> prevents reuse only inside one selected ledger; neither artifact authenticates
> supplier facts, reserves stock, places an order, approves payment, or proves
> global one-time execution.

## CI and agent integration

Use the root composite Action for board-centric CI, focused Actions for narrow
ERC/DRC or authorization jobs, and MCP for stdio-based agent discovery. The
[Integrations](INTEGRATIONS.md) guide includes minimal configurations.

Before adding a gate, decide which failures should retain a negative report and
which malformed inputs must produce no artifact. The focused contract for that
gate defines the distinction.
