# Getting started

This guide takes `pcbex` from a fresh checkout to a verified routed board. It
also shows where KiCad and the Python agent enter the toolchain.

## Choose an installation path

| Path | Best for | Requirements |
| --- | --- | --- |
| Release archive | CI and pinned local tooling | Download, checksum verification, and archive extraction |
| Source build | Development and source review | Stable Rust with Edition 2024 support |
| Python agent | Provider orchestration and evidence composition | Python 3.11+ and a working `pcbex` binary |

Published archives include a `.sha256` file and SPDX SBOM for each supported
target. Download them from the
[latest release](https://github.com/penguin425/pcbex/releases/latest) and verify
the checksum before placing the binary on `PATH`.

## Build from source

Clone the repository and build the locked dependency graph:

```sh
git clone https://github.com/penguin425/pcbex.git
cd pcbex
cargo build --release --locked
```

The examples below use Cargo's default `target` directory. If
`CARGO_TARGET_DIR` is configured, use that directory's release binary instead;
on Windows the binary name is `pcbex.exe`.

Confirm the binary and inspect optional integrations:

```sh
./target/release/pcbex --version
./target/release/pcbex doctor
```

Use `doctor --require-kicad` when native KiCad checks or manufacturing export
must be available:

```sh
./target/release/pcbex doctor --require-kicad
```

> [!NOTE]
> KiCad is optional for board JSON routing. Commands that run native ERC, native
> DRC, board export, or manufacturing packaging require a compatible
> `kicad-cli` executable.

## Route the first board

The checked-in example uses board schema v2 and integer nanometre coordinates.
Route it into the ignored Cargo target tree:

```sh
mkdir -p target/pcbex-demo

./target/release/pcbex route examples/simple.json \
  --output target/pcbex-demo/simple.routed.json \
  --svg target/pcbex-demo/simple.svg
```

Verify the routed result independently:

```sh
./target/release/pcbex check target/pcbex-demo/simple.routed.json
```

A successful run reports routed and unrouted net counts. The checker then
confirms connectivity, dimensions, boundaries, supported angles, obstacle
clearance, and cross-net copper clearance.

By default, `route` fails if any net remains unrouted. Use `--allow-unrouted`
only when a partial artifact is an intentional intermediate result.

## Route a KiCad PCB

Start from a placed `.kicad_pcb` file:

```sh
./target/release/pcbex route-kicad examples/simple.kicad_pcb \
  --output target/pcbex-demo/simple.routed.kicad_pcb \
  --svg target/pcbex-demo/simple.kicad.svg
```

Add `--drc` to invoke native KiCad DRC after pcbex writes the board:

```sh
./target/release/pcbex route-kicad examples/simple.kicad_pcb \
  --output target/pcbex-demo/simple.checked.kicad_pcb \
  --drc
```

The command discovers same-stem `.kicad_pro` and `.kicad_dru` companions when
present. Use `--project` and `--rules-file` to select them explicitly.

## Inspect schemas and capabilities

Write the current board schema and versioned feature inventory:

```sh
./target/release/pcbex schema \
  --output target/pcbex-demo/board-v2.schema.json

./target/release/pcbex capabilities \
  --output target/pcbex-demo/capabilities.json
```

Use command-specific help for the exact installed options:

```sh
./target/release/pcbex route-kicad --help
./target/release/pcbex fabricate --help
```

Shell completions are available for Bash, Zsh, Fish, Elvish, and PowerShell:

```sh
./target/release/pcbex completion bash > pcbex.bash
```

## Install the optional Python agent

Create an isolated environment and install the local package:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ./agent
pcbex-agent --help
```

Generate deterministic SKiDL from a closed circuit specification without an
external model provider:

```sh
pcbex-agent generate-skidl examples/circuit-spec.json \
  --output target/pcbex-demo/circuit.py
```

Provider-driven natural-language generation, KiCad repair, retained-evidence
replay, and procurement authorization add their own source, process, and trust
requirements. Follow the [Workflow Guide](WORKFLOWS.md) before enabling them.

## Next steps

- Route and inspect a real project with the [board and KiCad workflow](WORKFLOWS.md#board-routing).

- Bind organization constraints with [Physical Constraint Profiles](PHYSICAL_CONSTRAINT_PROFILE.md).

- Publish fabrication artifacts with the [Manufacturing Package](MANUFACTURING_PACKAGE.md).

- Add pull-request evidence with [GitHub Actions](INTEGRATIONS.md#github-actions).

- Review external-tool and authorization assumptions in the [Trust Model](TRUST_MODEL.md).

## Troubleshooting

**`kicad-cli` is unavailable:** Run `pcbex doctor`. Install KiCad or omit native
KiCad and manufacturing commands.

**A route remains incomplete:** Inspect the SVG, run `pcbex check`, and review
physical constraints and routing work limits. Do not use `--allow-unrouted` as
a release gate.

**An output already exists:** Some evidence and key commands are intentionally
no-clobber. Choose a new destination after verifying the existing artifact.

**A linked path is rejected:** Security-sensitive readers reject symbolic links
and reparse components by design. Use stable regular files and review
[CLI I/O Limits](CLI_IO_LIMITS.md).
