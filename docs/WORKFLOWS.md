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
