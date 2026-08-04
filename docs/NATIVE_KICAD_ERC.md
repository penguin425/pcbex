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

To make warnings part of the gate, supply an explicit closed warning policy.
Omitting the option preserves the error-only v1 invocation and report bytes:

```sh
pcbex run-native-kicad-erc hardware/generated.kicad_sch \
  --warning-policy examples/native-kicad-warning-policy.json \
  --output build/native-kicad-erc-warning.json \
  --require-approved

pcbex native-kicad-erc-warning-policy-schema \
  --output build/native-kicad-erc-warning-policy.schema.json
pcbex native-kicad-erc-warning-report-schema \
  --output build/native-kicad-erc-warning-report.schema.json
```

Use `--kicad-cli /path/to/kicad-cli` when KiCad is not on `PATH`. The command
uses this fixed invocation:

```text
kicad-cli sch erc --format json --units mm --severity-error \
  --exit-code-violations --output <private-report> <private-input>
```

Without `--warning-policy`, the gate is intentionally error-only. KiCad
warnings are neither approval criteria nor retained findings in the v1 report.
With a policy, pcbex instead invokes `--severity-error --severity-warning`
(never `--severity-all`, which also selects exclusions) and emits report
schema v2. KiCad exit status 5 then means that at least one selected finding
exists; it does not mean the warning policy rejected the report. pcbex derives
approval from the normalized findings: every error rejects, while warnings
must fit both the global and per-type budgets. `--require-approved` returns a
non-zero status only after publishing valid rejected evidence.

## Warning policy

The static policy schema v1 has exactly these fields:

```json
{
  "schema_version": 1,
  "id": "pcbex-generated-circuit-kicad-10",
  "maximum_total_warnings": 11,
  "warning_limits": [
    {"finding_type": "footprint_link_issues", "maximum_count": 4},
    {"finding_type": "lib_symbol_issues", "maximum_count": 4},
    {"finding_type": "multiple_net_names", "maximum_count": 3}
  ],
  "allowed_ignored_checks": [
    "footprint_filter",
    "four_way_junction",
    "simulation_model_issue",
    "single_global_label"
  ]
}
```

Lists must already be sorted and unique. A warning type absent from
`warning_limits` is denied, and an ignored-check key absent from
`allowed_ignored_checks` is denied. Counts refer to finding objects, not the
number of items attached to a finding. The policy is bounded to 1 MiB,
duplicate JSON keys and unknown fields are rejected, and errors cannot be
waived. The report retains both the exact policy source byte/SHA identity and
a domain-separated digest of its normalized meaning. This release deliberately
has no clock, expiry, wildcard, or default-allow behavior.

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
type, severity, description, and item identity. In report v1, approval means
`error_count` is zero, and `error_count` equals the finding count.

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

Warning report schema v2 adds `warning_count`, sorted `warning_counts`, the
normalized `warning_policy` evidence, and sorted `policy_failures`. Its
domain-separated run digest covers all of those fields. The policy and
schematic are stable-read around execution; fresh verification also
stable-reads the retained report and requires a byte-for-byte replay match.

## AI approval binding

Native ERC is an optional fourth artifact in the AI review flow. An error-only
report produces request schema v3 with artifact binding schema v2:

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
the prepare, sign, verify, and quorum tools. The Python adapter accepts v1
through v4 requests, treats the native identity as immutable evidence, and
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

For a warning-policy report, add the trusted policy path at every boundary:

```text
--native-kicad-erc-report build/native-kicad-erc-warning.json
--native-kicad-erc-warning-policy examples/native-kicad-warning-policy.json
--kicad-cli kicad-cli
```

This produces request schema v4, artifact-binding schema v3, and native
identity schema v2. Schema v3 accepts only the error-only native identity v1;
schema v4 accepts only the warning-policy native identity v2. The version
firewall prevents an old verifier from interpreting policy-bearing evidence
as the error-only contract. Prepare, sign, single-signature verification, and
quorum verification all require the trusted policy path and rerun KiCad.
MCP exposes the corresponding `warning_policy` and
`native_kicad_erc_warning_policy` arguments. The composite Action uses
`ai-review-native-kicad-erc-warning-policy` and publishes warning count,
policy-failure count, canonical policy digest, and exact policy-source
identity in addition to the existing native report outputs.

The policy path is a trust input. In protected CI it must resolve to
reviewed, non-PR-controlled bytes, just like the selected `kicad-cli`
executable. Schema v4 cryptographically binds the exact retained report and
therefore the policy identity, but it does not decide who is authorized to
write that policy; signed organization-level warning-policy distribution is a
separate governance boundary.
