# Integrations

`pcbex` exposes the same validated core through several adapters. Choose the
adapter for transport and orchestration; do not assume that an adapter expands
the authority of the underlying command.

## GitHub Actions

The root composite Action analyzes a required KiCad board and can optionally
compare a baseline, publish SARIF, run native KiCad gates, and verify wider
pipeline evidence.

```yaml
name: Hardware

on:
  pull_request:

permissions:
  contents: read

jobs:
  pcb:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1

      - uses: penguin425/pcbex@5393473a33056302f2aa1e3ab65820247b4fb1c2 # v1.471.0
        with:
          board: hardware/controller.kicad_pcb
          fail-on-violations: "true"
          output-dir: pcbex-analysis
```

The Action builds the pinned pcbex source, produces an analysis directory, and
uploads it by default. It retains structured evidence before applying supported
final failure gates.

> [!IMPORTANT]
> Pin Actions to reviewed commit SHAs. A release tag is easier to read but can
> move; immutable references make the reviewed dependency exact. See
> [GitHub Actions Supply Chain](GITHUB_ACTIONS_SUPPLY_CHAIN.md).

### Focused Actions

Use a focused Action when the repository needs one narrow boundary instead of
the full board-centric surface.

| Action path | Purpose |
| --- | --- |
| `actions/native-kicad-erc` | Generate or freshly verify normalized schematic ERC evidence |
| `actions/native-kicad-drc` | Generate or freshly verify normalized PCB DRC evidence |
| `actions/ai-schematic-approval` | Prepare and gate evidence-bound AI schematic approval |
| `actions/fabrication-authorization` | Verify signed fabrication release decisions |

Read [AI Schematic Approval Action](AI_SCHEMATIC_APPROVAL_ACTION.md),
[Fabrication Authorization Action](FABRICATION_AUTHORIZATION_ACTION.md),
[Native KiCad ERC](NATIVE_KICAD_ERC.md), or
[Native KiCad DRC](NATIVE_KICAD_DRC.md) before enabling a focused gate.

### Permissions and comments

Keep pull-request analysis read-only. The trusted `workflow_run` publisher can
consume a small hash-bound result and update a bot-owned comment without giving
untrusted PR code write credentials.

SARIF upload requires `security-events: write`. PR comments require a separately
trusted job with `pull-requests: write`; do not pass that token into
pull-request-controlled analysis.

## MCP

Start the newline-delimited stdio server directly:

```sh
pcbex mcp-server
```

Point an MCP client at an absolute binary path:

```json
{
  "mcpServers": {
    "pcbex": {
      "command": "/opt/pcbex/bin/pcbex",
      "args": ["mcp-server"]
    }
  }
}
```

The server exposes versioned analysis tools and bounded asynchronous tasks. It
does not provide a network listener, add filesystem sandboxing, or make hidden
CLI commands public.

Use `pcbex capabilities` to discover the installed command inventory. Exact
frame, task, child-process, and cancellation limits live in
[CLI I/O Limits](CLI_IO_LIMITS.md).

## KiCad

`pcbex` invokes `kicad-cli` directly without a shell. Commands that use native
ERC/DRC or manufacturing export stage selected inputs and bind companion
identities into their reports.

Check local readiness:

```sh
pcbex doctor --require-kicad
```

Select a non-default executable explicitly when needed:

```sh
pcbex run-native-kicad-drc hardware/controller.kicad_pcb \
  --kicad-cli /opt/kicad/bin/kicad-cli \
  --output build/native-kicad-drc.json
```

The executable is deployment-selected. Process limits and normalized output do
not authenticate its binary, plugins, libraries, or installation.

## Python agent

Install the agent into a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ./agent
pcbex-agent --help
```

The agent coordinates four common adapter classes:

| Adapter | Role |
| --- | --- |
| Provider command | Propose structured circuit or review data through bounded stdin/stdout |
| pcbex replay command | Freshly reproduce Rust-owned evidence |
| KiCad command | Repair or validate a staged KiCad artifact |
| Authorization helper | Perform Rust-owned policy and cryptographic assessment |

Caller-selected commands run with the permissions of the current process. The
agent bounds their I/O, lifetime, and process tree, but does not sandbox their
filesystem or network access.

See [Python Agent Limits](PYTHON_AGENT_LIMITS.md) for ordering, capture,
publication, cleanup, and secret-boundary details.

## Shell completion

Generate definitions from the installed command inventory:

```sh
pcbex completion bash > pcbex.bash
pcbex completion zsh > _pcbex
pcbex completion fish > pcbex.fish
```

Load the generated file using the conventions of your shell and operating
system. Regenerate it after upgrading pcbex.

## Organization policy

Unsigned policy packs are useful for local validation. Production consumers
can sign a pack with a dedicated Ed25519 key, verify it against an externally
trusted public key, and retain monotonic trust state to reject rollback or
equivocation.

```sh
pcbex policy-pack-schema --output policy-pack.schema.json
pcbex validate-policy-pack policy-pack.json --output policy-pack.normalized.json
```

Policy validation does not establish who selected the pack. Distribution,
public-key trust, rotation, and custody remain deployment responsibilities.

## Operational checklist

- Pin the pcbex release or commit and verify release checksums.
- Run `doctor` in the target environment.
- Validate every organization-owned profile or policy before use.
- Keep secrets out of repositories, command output, and retained public reports.
- Retain negative evidence before applying an optional final CI gate.
- Re-run fresh verifiers at the actual handoff when the contract requires it.
- Read the [Trust Model](TRUST_MODEL.md) before connecting network or signing adapters.
