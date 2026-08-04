# Native KiCad schematic ERC

`pcbex run-native-kicad-erc` runs KiCad's own schematic electrical-rule
checker and retains a normalized, digest-bound report. It is independent of
pcbex's semantic electrical review and board DRC.

```sh
pcbex run-native-kicad-erc hardware/generated.kicad_sch \
  --output build/native-kicad-erc.json \
  --require-approved

pcbex native-kicad-erc-report-schema \
  --output build/native-kicad-erc.schema.json
```

Use `--kicad-cli /path/to/kicad-cli` when KiCad is not on `PATH`. The command
uses this fixed invocation:

```text
kicad-cli sch erc --format json --units mm --severity-error \
  --exit-code-violations --output <private-report> <private-input>
```

The gate is intentionally error-only. KiCad warnings are neither approval
criteria nor retained findings in this v1 report; they remain outside this
gate so a warning policy can be introduced separately without changing the
error contract. The generated circuit-spec fixture currently produces the
known 11 KiCad warnings under an all-severity invocation, but those warnings
do not weaken the zero-error requirement here. `--require-approved` returns a
non-zero status when an electrical error is found, after publishing the
rejected report. Without it, callers can inspect the report and decide how to
handle `approved: false`.

## Normalized report

The report is compact canonical JSON with one final newline. Its closed
top-level shape is:

```text
schema_version, engine, engine_version, kicad_version, source,
invocation, ignored_checks, findings, error_count, approved, run_sha256
```

`source` contains the exact input byte count and SHA-256. `run_sha256` is a
domain-separated digest of the normalized report identity; KiCad's timestamp
and staged source pathname are not included. Findings are sorted by sheet,
type, severity, description, and item identity. A report is approved exactly
when `error_count` is zero, and `error_count` equals the finding count.

The source schematic is read through the regular-file boundary (64 MiB
maximum), copied byte-for-byte to `input.kicad_sch` in a private temporary
directory, and the staged copy is rechecked after KiCad exits. The raw and
normalized reports are bounded to 32 MiB. KiCad receives private
`KICAD_CONFIG_HOME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, and `XDG_DATA_HOME`
directories and, on Windows, `USERPROFILE`, `APPDATA`, and `LOCALAPPDATA`
values rooted in the same temporary environment. No adjacent `.kicad_pro` or
other sidecar/project files are staged. Child stdout/stderr and execution time
are bounded by the CLI process supervisor. The output is a new regular file:
existing destinations, aliases, symlinks, and symlinked parents are refused.

The native report schema is available from the CLI (and can be retained as a
release asset). Consumers should validate the closed shape and verify both the
source identity and `run_sha256`; a report copied beside a different
schematic is not equivalent.

## AI approval binding

Native ERC is an optional fourth artifact in the AI review flow. A request that
includes it is request schema v3 with an artifact binding schema v2:

```json
{
  "artifact_binding": {
    "schema_version": 2,
    "generated_schematic": {"bytes": 123, "sha256": "..."},
    "pipeline": {"plan_source": {}, "plan_sha256": "...", "report": {}, "run_sha256": "..."},
    "native_kicad_erc": {
      "schema_version": 1,
      "report": {"bytes": 456, "sha256": "..."},
      "run_sha256": "..."
    }
  }
}
```

The native report identity is limited to 32 MiB and is covered by the
request's `request_sha256`. `prepare-ai-review` reruns KiCad and compares the
fresh normalized report with the retained report before constructing schema
v3. Signing and verification rerun the same check; the four live paths are
required at every boundary:

```sh
pcbex prepare-ai-review hardware/generated.kicad_sch \
  --electrical-review build/electrical-review.json \
  --policy-pack hardware/organization-policy-pack.json \
  --deterministic-pipeline-plan hardware/pipeline-plan.json \
  --deterministic-pipeline-report build/pipeline-report.json \
  --native-kicad-erc-report build/native-kicad-erc.json \
  --kicad-cli kicad-cli \
  --output build/ai-review-request-v3.json

pcbex sign-ai-review build/ai-review-request-v3.json build/reviewer.response.json \
  --generated-schematic hardware/generated.kicad_sch \
  --deterministic-pipeline-plan hardware/pipeline-plan.json \
  --deterministic-pipeline-report build/pipeline-report.json \
  --native-kicad-erc-report build/native-kicad-erc.json \
  --kicad-cli kicad-cli \
  --private-key .secrets/reviewer.key --signer-id reviewer-a \
  --output build/reviewer.approval.json

pcbex verify-ai-approval build/reviewer.approval.json \
  build/ai-review-request-v3.json build/reviewer.response.json \
  --generated-schematic hardware/generated.kicad_sch \
  --deterministic-pipeline-plan hardware/pipeline-plan.json \
  --deterministic-pipeline-report build/pipeline-report.json \
  --native-kicad-erc-report build/native-kicad-erc.json \
  --kicad-cli kicad-cli --public-key .secrets/reviewer.pub

pcbex verify-ai-quorum build/ai-review-request-v3.json \
  --generated-schematic hardware/generated.kicad_sch \
  --deterministic-pipeline-plan hardware/pipeline-plan.json \
  --deterministic-pipeline-report build/pipeline-report.json \
  --native-kicad-erc-report build/native-kicad-erc.json \
  --kicad-cli kicad-cli --approval build/reviewer.approval.json \
  --response build/reviewer.response.json \
  --policy-pack hardware/organization-policy-pack.json \
  --output build/ai-quorum.json
```

MCP exposes the same `native_kicad_erc_report` and `kicad_cli` arguments on
the prepare, sign, verify, and quorum tools. The Python adapter accepts v1,
v2, and v3 requests, treats the native identity as immutable evidence, and
continues to require response schema v1. The root composite Action accepts
`ai-review-native-kicad-erc-report` and `ai-review-kicad-cli`. It passes the
retained report to `verify-ai-quorum`, which reruns native ERC during quorum
verification, and publishes report bytes/SHA-256 plus the native run digest.
These integrations are opt-in.

The selected `kicad-cli` executable is part of the trusted toolchain. The
normalized report records KiCad's reported version but does not attest or hash
the executable and its dynamic dependencies. Protected CI should provision a
trusted KiCad installation and must not select an executable from
pull-request-controlled content.

Legacy request schema v1 remains unbound. Schema v2 continues to bind only
the generated schematic and deterministic pipeline artifacts; it must not be
mixed with an artifact binding schema v2 or a native ERC field. Upgrade to
schema v3 only after retaining and revalidating the native report.
