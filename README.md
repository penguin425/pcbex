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

- **Validate continuously:** Check connectivity, copper clearance, board
  boundaries, keepouts, dimensions, zones, and fabrication constraints.

- **Work with KiCad:** Read and write KiCad boards, normalize native ERC/DRC
  evidence, and preserve project rule context.

- **Package manufacturing output:** Gate Gerber, drill, BOM, and CPL publication
  behind exact validation and hash-bound manifests.

- **Automate circuit handoff:** Convert constrained circuit specifications into
  deterministic schematic, board-binding, firmware, and pipeline evidence.

- **Govern release decisions:** Bind AI review, fabrication, and procurement
  approvals to exact evidence with explicit policy and signature boundaries.

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
