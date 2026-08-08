# Native KiCad schematic ERC

`pcbex run-native-kicad-erc` runs KiCad's own schematic electrical-rule
checker and retains a normalized, digest-bound report. It is independent of
pcbex's semantic electrical review and board DRC.
Release v1.431.0 also hardens the Unix MCP Task path: cancellation reaches
the KiCad process group and descendants, and no incomplete report is
published. The synchronous CLI and composite-Action contracts are unchanged.
Release v1.432.0 adds a standalone fresh-replay boundary for retained native
ERC evidence. CLI, MCP, and the focused Action replay report schema v1 or v2
read-only, retain rejected evidence before an optional approval gate, and
stable-read the original schematic around the KiCad run. Existing native run
and AI-review contracts remain unchanged.
Release v1.451.0 adds a finite CLI replay timeout and lets the Python circuit
handoff replay bind retained native ERC evidence to an exactly reproduced
schematic without changing the retained handoff archive.
Release v1.452.0 can follow that optional native assertion with a separate
exact schema-v1 AI schematic quorum replay. It does not change the native
report or archive contracts, and AI-only handoff replay does not invoke KiCad.

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

## Boardless composite Action (introduced v1.428.0; replay in v1.432.0)

The focused public Action runs native ERC in repositories that have a KiCad
schematic but no PCB board. The caller must install a trusted KiCad CLI; the
Action builds the pinned pcbex source from its release and needs no `board`, AI
review, or deterministic-pipeline input:

```yaml
- id: native-erc
  uses: penguin425/pcbex/actions/native-kicad-erc@v1.432.0
  with:
    schematic: hardware/controller.kicad_sch
    require-approved: "true"
    # warning-policy: hardware/native-kicad-warning-policy.json
    # kicad-cli: kicad-cli
    # output-dir: pcbex-native-kicad-erc
    # artifact-name: pcbex-native-kicad-erc
    # upload-artifact: "true"
    # retention-days: "14"
```

`warning-policy` is optional. Omitting it selects the error-only v1 report;
supplying it selects the closed warning-policy v2 report. `kicad-cli` defaults
to `kicad-cli`, is invoked as a trusted executable without a shell, and must
not be selected from pull-request-controlled content. `require-approved`
defaults to `"false"`, so a valid rejected report can complete the Action for
review. When it is `"true"`, the Action first scans and uploads valid rejection
evidence and then the final `always()` enforcement step fails if the report is
absent or unapproved. Set distinct `output-dir` and `artifact-name` values for
multiple invocations in one job.

For an enabled valid run, the normalized report is retained at the fixed
`${output-dir}/native-kicad-erc.json` path and is included in the bounded
artifact tree and Job Summary. The Action additionally exposes `status` and
`artifact-dir`, plus these twelve root-compatible outputs:

| Output | Meaning |
| --- | --- |
| `native-kicad-erc-report` | Fixed retained report path |
| `native-kicad-erc-schema-version` | Report schema version (`1` or `2`) |
| `native-kicad-erc-approved` | Normalized approval decision |
| `native-kicad-erc-error-count` | Native error finding count |
| `native-kicad-erc-warning-count` | Warning finding count (empty for v1) |
| `native-kicad-erc-policy-failure-count` | Warning-policy failures (empty for v1) |
| `native-kicad-erc-warning-policy-sha256` | Canonical policy digest (empty for v1) |
| `native-kicad-erc-warning-policy-source-bytes` | Exact policy source bytes (empty for v1) |
| `native-kicad-erc-warning-policy-source-sha256` | Exact policy source SHA-256 (empty for v1) |
| `native-kicad-erc-run-sha256` | Domain-separated native run identity |
| `native-kicad-erc-report-bytes` | Exact retained report bytes |
| `native-kicad-erc-report-sha256` | Exact retained report SHA-256 |

The focused inputs and outputs are deliberately separate from the
`ai-review-native-kicad-erc-report` and other `ai-review-*` retained-report
inputs. Running this Action does not create a deterministic plan or
automatically connect the report to AI approval; callers must pass a retained
report through that separate flow explicitly.

The Action requires `output-dir` to be absent or an empty real directory. A
schematic and optional policy must be existing regular files addressed by
portable caller-workspace-relative paths; absolute paths, traversal, and
linked components are rejected before the build. Output-directory components
are restricted to ASCII letters, digits, dot, underscore, and hyphen so the
artifact uploader cannot reinterpret the verified directory as a glob. A
stale or aliased output, symlinked destination or parent, malformed compact
runner summary, digest mismatch, input mutation, fatal KiCad/runner error, or
other invalid native evidence fails closed and publishes no native report
identity. Valid rejected evidence is retained before the optional final gate,
so the artifact and summary remain available for diagnosis.

## Standalone fresh replay (v1.432.0)

Fresh replay is input-read-only: the retained report, original schematic, and
optional warning policy are never overwritten. The CLI command reruns the
bounded KiCad invocation, compares the newly normalized bytes with the
retained report, and returns the same approval decision without publishing a
replacement:

```sh
pcbex verify-native-kicad-erc-report \
  hardware/controller.kicad_sch build/native-kicad-erc.json \
  --kicad-cli kicad-cli --timeout-seconds 120 --require-approved

pcbex verify-native-kicad-erc-report \
  hardware/controller.kicad_sch build/native-kicad-erc-warning.json \
  --warning-policy examples/native-kicad-warning-policy.json \
  --kicad-cli kicad-cli --timeout-seconds 120 --require-approved
```

The first command replays fixed error-only report v1; supplying the same
closed warning policy selects report v2. Both forms stable-read the original
schematic before and after the child exits, and compare the retained report
under the bounded report limit. Any source, policy, retained-report, or
normalized-byte mutation fails closed while leaving retained evidence
untouched. `--require-approved` is evaluated only after a complete replay and
does not delete rejected evidence.

The standalone CLI verifier's `--timeout-seconds` value is a finite positive
number no greater than 600 and may be fractional. It is applied directly to the
fresh KiCad process tree; zero, negative, non-finite, over-limit, or values that
cannot be represented as a nonzero Rust duration are rejected before the run.
Omitting the option preserves the 600-second default. This option changes only
the synchronous `verify-native-kicad-erc-report` CLI path: existing native run,
MCP, Task, and Action timeout contracts continue to use their established
boundaries and defaults.

Version 1.451 also exposes this verifier as an optional final assertion on
`pcbex-agent replay-circuit-handoff-bundle`. That integration first reproduces
the canonical six-entry handoff ZIP exactly, then runs this verifier against
the reproduced schematic under the remaining aggregate deadline. The retained
report and optional exact policy remain bounded external sidecars; they are not
inserted into the archive. See
[Atomic circuit-generation to KiCad handoff bundle](CIRCUIT_HANDOFF_BUNDLE.md)
for its versioned, path-free replay-result contract and trust boundary.

Version 1.452 adds an independent complete non-session schema-v1 AI quorum
sidecar set to the same agent command. When both assertions are requested, the
native replay still runs immediately after exact archive reproduction; the
existing `verify-ai-quorum --schematic` boundary then runs over the exact
reproduced schematic and privately staged AI verifier inputs. After that child
exits, the native report and optional warning policy are reread again before a
combined path-free v3 result can be returned. This ordering prevents later AI
verification from leaving stale native evidence in the combined result.

AI replay does not convert native ERC into reviewer approval or vice versa.
The AI request's live-schematic check binds imported semantic IR, while native
ERC independently evaluates the exact staged file under the caller-selected
KiCad toolchain. Either assertion may be omitted. Session/routing contracts,
tool provenance, PCB DRC/DFM, and manufacturing authorization remain outside
the handoff replay; see the handoff-bundle document for the AI sidecar limits,
thresholds, exact report comparison, and v1/v2 compatibility rules.

MCP exposes the same boundary as
`verify_native_kicad_erc_report` with `input`, `retained_report`, optional
`warning_policy`, `kicad_cli`, and `require_approved` arguments. Its compact
summary authenticates the replayed schema, counts, report bytes/SHA-256, and
run identity without embedding report contents. Synchronous calls and
Task-backed calls use the same read-only verifier; Task cancellation reaches
the bounded KiCad process group.

The focused Action accepts `mode: verify` and a caller-relative `report`
input in addition to its existing `schematic` and optional `warning-policy`.
It reruns the same v1/v2 verifier and publishes a freshly authenticated,
no-clobber copy under the new `output-dir`. The copy and Job Summary remain
available for valid rejected evidence; the final `always()` gate applies
`require-approved` only after evidence has been retained. The root Action is
still run-only, and replay does not change its board-required contract.

## Root Action compatibility (v1.427.0 and later)

The root `penguin425/pcbex` Action retains its independent opt-in native ERC
gate and remains board-required. Existing callers can continue to use
`native-kicad-erc-schematic`, `native-kicad-erc-warning-policy`,
`native-kicad-erc-kicad-cli`, and `native-kicad-erc-require-approved`; its
twelve output names are identical to the focused Action. The root Action also
supports its separate hardware analysis, PR comment, deterministic-pipeline,
and AI review features. v1.432.0 does not change that contract.

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
domain-separated run digest covers all of those fields. Both report versions
stable-read the original schematic before and after KiCad execution; v2 also
stable-reads the warning-policy source. Fresh verification additionally
stable-reads the retained report and requires a byte-for-byte replay match.

## MCP Task cancellation

The MCP server exposes the native runner as `run_native_kicad_erc`, with the
same `input`, `output`, optional `warning_policy`, `kicad_cli`, and
`require_approved` controls as the CLI. Every MCP invocation calls the Rust
`run_native_kicad_erc` runner directly in the MCP worker (or its warning-policy
variant); Task calls additionally pass cancellation to the bounded process
supervisor. On Unix, cancelling the Task terminates the KiCad process-group
leader and every descendant, rather than leaving native work running. Output
is staged privately and published atomically only after a complete normalized
report has been validated, so cancellation cannot expose an incomplete report.

The read-only `verify_native_kicad_erc_report` tool accepts the retained report
and optional warning policy and uses the same runner boundary for schema v1 or
v2 replay. It never rewrites the retained report; Task cancellation also
reaches its bounded KiCad process group. The MCP response contract,
synchronous CLI behavior, focused replay Action, root Action, and existing
AI/run contracts remain unchanged.

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

Legacy request schema v1 remains unbound to artifact paths. The v1.442.0 live
signing boundary accepts a separate `--schematic` source for semantic and
fresh electrical-review verification, but does not add that path to the
request or native artifact binding. Schema v2 continues to bind only the
generated schematic and deterministic pipeline artifacts; it must not be
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
