# pcbex

[![CI](https://github.com/penguin425/pcbex/actions/workflows/ci.yml/badge.svg)](https://github.com/penguin425/pcbex/actions/workflows/ci.yml)
[![KiCad E2E](https://github.com/penguin425/pcbex/actions/workflows/kicad-e2e.yml/badge.svg)](https://github.com/penguin425/pcbex/actions/workflows/kicad-e2e.yml)
[![Latest release](https://img.shields.io/github/v/release/penguin425/pcbex)](https://github.com/penguin425/pcbex/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Route boards, verify hardware, and ship reproducible evidence.**

`pcbex` is a deterministic PCB physical-design engine and hardware automation
toolkit. It routes board JSON and KiCad PCBs, runs layered design checks, and
builds replayable evidence for CI, manufacturing, and controlled release
workflows.

[Get started](docs/GETTING_STARTED.md) ·
[Explore the docs](docs/README.md) ·
[Understand the architecture](docs/ARCHITECTURE.md) ·
[Review the roadmap](docs/ROADMAP.md)

## Why pcbex

Hardware automation breaks down when geometry, external tools, and approval
decisions blur into one opaque pipeline. `pcbex` keeps those boundaries explicit.

- **Route deterministically:** Use integer-nanometre geometry and bounded
  multilayer A* search for reproducible results.

- **Converge safely:** Explore bounded deterministic routing portfolios while
  excluding every DRC-invalid candidate from final selection.

- **Validate continuously:** Check connectivity, copper clearance, board
  boundaries, keepouts, dimensions, zones, and fabrication constraints.

- **Work with KiCad:** Read and write KiCad boards, normalize native ERC/DRC
  evidence, and preserve project rule context.

- **Package manufacturing output:** Gate Gerber, drill, BOM, and CPL publication
  behind exact validation and hash-bound manifests.

- **Automate circuit handoff:** Convert constrained circuit specifications into
  deterministic schematic, board-binding, firmware, and pipeline evidence.

- **Model multi-unit parts:** Keep one physical component identity while
  binding every KiCad symbol unit and package pin explicitly.

- **Govern release decisions:** Bind AI review, fabrication, and procurement
  approvals to exact evidence, then reserve approved challenges in pinned local
  ledgers without claiming an order or payment.

- **Authenticate factory receipts:** Bind the exact normalized receipt and
  manufacturing package to a dedicated policy-pinned Ed25519 key.

- **Reserve signed releases:** Admit an authenticated receipt challenge once
  into a pinned local Unix ledger before any external executor runs.

- **Submit without blind retries:** Commit one signed-release intent before a
  single adapter POST, then reconcile uncertain outcomes without resending the ZIP.

- **Authenticate adapter responses:** Verify RFC 9421 Ed25519 signatures and
  RFC 9530 content digests against exact policy-pinned factory keys.

- **Verify factory-state history:** Chain authenticated adapter states to one
  retained ledger, reject rollback and forks, then verify the current head in a
  separately pinned signed Merkle view and prove strict append-only extension
  between retained checkpoints. Require distinct policy-pinned witness
  organizations to endorse the exact latest checkpoint, then anchor that exact
  quorum report in a separately trusted external signed Merkle view and prove
  later external views strictly extend the retained anchor.

- **Integrate everywhere:** Run from the CLI, Python agent, GitHub Actions, or a
  newline-delimited MCP server.

> [!IMPORTANT]
> `pcbex` separates evidence from authority. A clean report does not, by itself,
> authenticate a supplier, reserve stock, place an order, approve payment, or
> prove that an external tool is trustworthy. See the
> [trust model](docs/TRUST_MODEL.md) before using evidence at a release boundary.

## Quick start

Build from source with a current stable Rust toolchain:

```sh
git clone https://github.com/penguin425/pcbex.git
cd pcbex
cargo build --release --locked
./target/release/pcbex doctor
```

Route the included board and verify the result:

```sh
mkdir -p target/pcbex-demo

./target/release/pcbex route examples/simple.json \
  --output target/pcbex-demo/simple.routed.json \
  --svg target/pcbex-demo/simple.svg

./target/release/pcbex check target/pcbex-demo/simple.routed.json
```

The route command fails on unrouted nets by default, which makes it suitable
for CI. A successful check prints a compact board summary.

> [!TIP]
> Prebuilt archives, SHA-256 checksum files, and SPDX SBOMs are available on the
> [releases page](https://github.com/penguin425/pcbex/releases/latest). On
> Windows, use `target\release\pcbex.exe` for a local source build. If
> `CARGO_TARGET_DIR` is set, use its `release` directory instead.

## Usage

### Route a KiCad board

Route a placed board, write an SVG preview, then ask KiCad to run native DRC:

```sh
./target/release/pcbex route-kicad examples/simple.kicad_pcb \
  --output target/pcbex-demo/simple.routed.kicad_pcb \
  --svg target/pcbex-demo/simple.kicad.svg \
  --drc
```

`--drc` requires `kicad-cli`. Omit it when you only need pcbex routing and
internal checks.

### Converge difficult routes

Opt into a bounded strategy portfolio and retain the complete selection record:

```sh
./target/release/pcbex route-kicad examples/simple.kicad_pcb \
  --output target/pcbex-demo/simple.converged.kicad_pcb \
  --convergence-report target/pcbex-demo/simple.convergence.json

./target/release/pcbex verify-kicad-routing-convergence \
  examples/simple.kicad_pcb \
  --routed target/pcbex-demo/simple.converged.kicad_pcb \
  --report target/pcbex-demo/simple.convergence.json \
  --output target/pcbex-demo/simple.convergence.verification.json \
  --require-complete
```

The normal single-pass route stays the default. Convergence shares one A* work
ceiling across all declared rounds and candidates, rejects DRC-invalid winners,
and publishes a closed no-clobber report. The verifier reruns that exact
decision and regenerates the routed bytes. See [Routing Convergence](docs/ROUTING_CONVERGENCE.md)
and [Fresh Verification](docs/ROUTING_CONVERGENCE_VERIFICATION.md).

### Build a manufacturing package

For a DRC-clean production board with complete BOM/CPL metadata, run KiCad DRC
and publish normalized manufacturing artifacts plus a canonical ZIP:

```sh
./target/release/pcbex fabricate \
  hardware/controller.routed.kicad_pcb \
  --output-dir build/manufacturing
```

Add `--physical-profile`, `--fab`, or `--fab-profile` when the package must bind
organization or fabricator constraints. Read the
[manufacturing package contract](docs/MANUFACTURING_PACKAGE.md) before treating
the archive as release evidence.

When release also requires fresh native DRC and a policy-pinned human quorum,
use the [routing/DRC fabrication-release boundary](docs/ROUTING_DRC_FABRICATION_RELEASE.md).

### Generate a multi-unit KiCad handoff

Use circuit-spec v3 when one physical package appears as multiple schematic
units. Existing v2 documents continue to work without migration.

```sh
./target/release/pcbex check-circuit-spec \
  examples/circuit-board-spec-v3.json --require-approved

./target/release/pcbex write-circuit-spec-kicad-schematic \
  examples/circuit-board-spec-v3.json \
  --output target/pcbex-demo/multi-unit.kicad_sch

./target/release/pcbex verify-circuit-kicad-handoff \
  examples/circuit-board-spec-v3.json \
  target/pcbex-demo/multi-unit.kicad_sch \
  --require-approved
```

Discover the closed wire contracts with `circuit-spec-v3-schema` and
`circuit-spec-v3-check-schema`. See the
[multi-unit circuit guide](docs/MULTI_UNIT_CIRCUIT_SPEC.md) for invariants and
physical-board collapse rules.

### Inspect machine-readable contracts

Discover the installed feature surface instead of parsing help text:

```sh
./target/release/pcbex capabilities \
  --output target/pcbex-demo/capabilities.json

./target/release/pcbex schema \
  --output target/pcbex-demo/board-v2.schema.json
```

Schema commands publish closed JSON Schemas for boards, policies, reports, and
approval artifacts. Run `pcbex --help` or `pcbex <command> --help` for the live
CLI contract.

### Use the Python agent

The optional agent adds bounded orchestration for circuit generation, KiCad
repair, evidence replay, supplier-offer correlation, and procurement approval:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ./agent

pcbex-agent generate-skidl examples/circuit-spec.json \
  --output target/pcbex-demo/circuit.py
```

Full natural-language generation requires an explicit provider command. Start
with the [Text-to-Circuit contract](docs/TEXT_TO_CIRCUIT.md) and the
[workflow guide](docs/WORKFLOWS.md).

## Configuration

`pcbex` favors versioned files over hidden state. Validate each contract before
it enters a routing, manufacturing, or authorization flow.

| Contract | Purpose | Discovery command |
| --- | --- | --- |
| Board JSON v2 | Geometry, nets, layers, rules, and routed copper | `pcbex schema` |
| Routing convergence report v1 | Bounded candidate rounds and validity-first selection | `pcbex routing-convergence-report-schema` |
| Routing convergence verification v1 | Fresh replay plus exact routed-artifact binding | `pcbex routing-convergence-verification-report-schema` |
| Routing/manufacturing handoff v1 | Bind one freshly verified routed KiCad board to one exact manufacturing ZIP | `pcbex-agent routing-manufacturing-handoff-report-schema` |
| Routing/native-DRC/manufacturing handoff v1 | Add fresh normalized KiCad DRC evidence to the exact routed package | `pcbex-agent routing-drc-manufacturing-handoff-report-schema` |
| Routing/DRC fabrication release v1 | Bind that package to a factory-required pipeline and policy-pinned fabrication quorum | `pcbex-agent routing-drc-fabrication-release-report-schema` |
| Executable-pinned fabrication release v1 | Freshly reassess one retained release subject while matching routing, authorization, and KiCad native entrypoints to deployment-owned SHA-256 pins | `pcbex-agent executable-pinned-fabrication-release-report-schema` |
| Signed factory-receipt release v1 | Freshly replay the executable-pinned release and authenticate its exact normalized receipt with a dedicated policy-pinned Ed25519 key | `pcbex-agent signed-factory-receipt-release-report-schema` |
| Signed release reservation v1 | Durably admit one freshly authenticated receipt challenge to a pinned local ledger | `pcbex signed-factory-receipt-release-reservation-schema` |
| Durable signed-release submission v1 | Commit one idempotency-keyed adapter intent, retain its result, and reconcile by GET without retransmitting the ZIP | `pcbex signed-factory-release-adapter-receipt-schema` |
| Authenticated factory response v1 | Verify the exact adapter acknowledgement, status, request binding, and body digest under a policy-pinned Ed25519 key | `pcbex factory-release-adapter-response-authentication-report-schema` |
| Monotonic factory state v1 | Bind signed adapter states to the accepted local head and reject rollback, equivocation, gaps, forks, or terminal mutation | `pcbex factory-release-adapter-monotonic-observation-report-schema` |
| Factory-state transparency v1 | Verify the exact current monotonic head in one separately policy-pinned signed Merkle view | `pcbex factory-release-state-transparency-verification-report-schema` |
| Factory-state transparency consistency v1 | Prove one retained signed view strictly extends another and retain the transition in a no-replace chain | `pcbex factory-release-state-transparency-consistency-verification-report-schema` |
| Factory-state transparency witness quorum v1 | Require distinct policy-pinned organizations to sign the exact latest v1.486 report and tree head | `pcbex factory-release-state-transparency-witness-quorum-verification-report-schema` |
| Factory-state transparency external anchor v1 | Prove the exact latest v1.487 quorum report appears in one separately policy-pinned external signed Merkle view | `pcbex factory-release-state-transparency-external-anchor-verification-report-schema` |
| Factory-state transparency external consistency v1 | Prove later signed views strictly extend the retained external anchor and keep a bounded no-replace chain | `pcbex factory-release-state-transparency-external-consistency-verification-report-schema` |
| Circuit spec v2/v3 | Flat or explicit multi-unit circuit intent | `pcbex circuit-spec-v2-schema` / `pcbex circuit-spec-v3-schema` |
| Physical profile | Board construction and placement constraints | `pcbex physical-profile-schema` |
| DFM profile | Fabricator-specific manufacturing limits | `pcbex dfm-profile-schema` |
| Organization policy pack | Electrical, physical, review, and signer policy | `pcbex policy-pack-schema` |
| Capability inventory | Versioned commands and integration contracts | `pcbex capabilities` |

Examples live in [`examples/`](examples/). Detailed format ownership and data
flow are documented in [Architecture](docs/ARCHITECTURE.md).

## Architecture

| Layer | Responsibility |
| --- | --- |
| `pcbex-core` | Integer geometry, checking, placement, routing, migration, and quality analysis |
| `pcbex-kicad` | KiCad parsing/writing, electrical models, native evidence, and board binding |
| `pcbex` CLI | Policy, bounded I/O, manufacturing, signatures, replay, and integrations |
| `pcbex-agent` | Bounded Python orchestration around providers, pcbex, KiCad, and retained evidence |
| GitHub Actions / MCP | CI reporting and agent-facing command discovery without changing core authority |

The core remains deterministic. Network calls, external executables, retained
evidence, and human signatures cross explicit adapters with their own limits
and nonclaims.

## Integrations

- **GitHub Actions:** Analyze boards, compare baselines, publish SARIF and
  artifacts, and gate regressions with a composite Action.

- **MCP:** Expose bounded analysis tools over stdio with `pcbex mcp-server`.

- **KiCad:** Run routing, native ERC/DRC, board generation, and manufacturing
  export through directly invoked `kicad-cli` processes.

- **Python:** Compose provider-driven and evidence-replay workflows without
  moving Rust-owned verification rules into the agent.

See [Integrations](docs/INTEGRATIONS.md) for copy-pasteable configuration and
the security model for each adapter.

## Documentation

| Read this | When you need to |
| --- | --- |
| [Getting Started](docs/GETTING_STARTED.md) | Install pcbex and complete the first JSON or KiCad workflow |
| [Workflow Guide](docs/WORKFLOWS.md) | Choose the shortest path from input artifact to verified output |
| [Architecture](docs/ARCHITECTURE.md) | Understand crates, data flow, and boundary ownership |
| [Integrations](docs/INTEGRATIONS.md) | Configure GitHub Actions, MCP, KiCad, or the Python agent |
| [Trust Model](docs/TRUST_MODEL.md) | Distinguish deterministic evidence from external authority |
| [Monotonic Factory State](docs/MONOTONIC_FACTORY_RELEASE_ADAPTER_STATE.md) | Integrate the signed state-chain profile and its durable retry rules |
| [Transparency Consistency](docs/FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY.md) | Verify append-only extension between retained factory-state log views |
| [Transparency Witness Quorum](docs/FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_QUORUM.md) | Require independent configured organizations to endorse one exact latest checkpoint |
| [Transparency External Anchor](docs/FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR.md) | Anchor the exact witness-quorum report in a separately trusted signed Merkle view |
| [Documentation Index](docs/README.md) | Find every detailed contract and operational limit |

For release-by-release capability history, use the
[roadmap](docs/ROADMAP.md). For requirement-level verification and exact test
counts, use the [completion audit](docs/COMPLETION_AUDIT.md).

## Development

Run the focused project checks before opening a change:

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
PYTHONPATH=agent/src python3 -m unittest discover -s agent/tests -v
python3 -m unittest discover -s scripts/tests -v
```

KiCad-dependent end-to-end coverage lives in
[`scripts/kicad-e2e.sh`](scripts/kicad-e2e.sh). Benchmark and regression-corpus
instructions live in [Benchmarks](docs/BENCHMARKS.md) and
[Regression Corpus](docs/REGRESSION_CORPUS.md).

## Security

Report vulnerabilities through GitHub private vulnerability reporting. The
[security policy](SECURITY.md) defines supported versions and reporting
expectations; [CLI limits](docs/CLI_IO_LIMITS.md) and
[Python agent limits](docs/PYTHON_AGENT_LIMITS.md) define the local execution
boundaries.

## License

`pcbex` is available under the [MIT License](LICENSE).
