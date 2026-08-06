# AI review artifact binding

Version 1.425 adds an opt-in AI review request schema v3 that can bind an
approval to one exact generated KiCad schematic, one exact successful
deterministic-pipeline execution, and one exact normalized native KiCad ERC
run. Version 1.426 adds request schema v4 for native ERC warning-policy
evidence. Version 1.442.0 added live signing parity: `sign-ai-review
--schematic` and MCP `sign_schematic_approval` accept one bounded live
schematic for schema-v1 semantic/fresh electrical-review verification
before the private key is read. Version 1.443.0 hardens that signing boundary:
the response, signer, optional session, all selected evidence inputs, and the
destination are validated before private-key access; valid rejected reviews
are still signed and published; and approval output uses atomic no-clobber
publication. Request schema v1 remains unbound to artifact paths; schema v2
remains backward-compatible when native ERC evidence is not supplied, and
schema v3 retains its error-only meaning.

## Bound identities

The closed `artifact_binding` object contains no filesystem paths. It records:

- the byte count and SHA-256 of the generated `.kicad_sch`;
- the byte count and SHA-256 of the raw deterministic-pipeline plan;
- the domain-separated normalized plan SHA-256;
- the byte count and SHA-256 of the retained pipeline report, including its
  final newline; and
- the domain-separated pipeline run SHA-256; and
- for schema v3 or v4, the byte count and SHA-256 of the retained native KiCad
  ERC report plus its domain-separated native run SHA-256. Report v2 itself
  binds the exact and normalized warning-policy identities.

These fields are covered by the request's normalized `request_sha256`.
Existing ordinary and session-bound Ed25519 approval envelopes already sign
that request digest, so their wire formats do not change. Request schema v2
through v4, and session-bound approval envelope schema v2, are independent
version numbers.

Paths are deliberately excluded. A byte-identical copied schematic is the
same approved artifact, while a one-byte change invalidates the binding.
Generated schematics are limited to 64 MiB, raw plans to 4 MiB, and retained
reports to 128 MiB including the publication newline. Native KiCad ERC reports
are limited to 32 MiB including their publication newline.
Reformatting a source plan or changing the runner engine version can therefore
invalidate a prior binding even when its semantic plan remains equivalent;
regenerate the request and approvals after either intentional change.

## Native KiCad ERC evidence (schema v3)

Run KiCad's fixed error-only ERC gate and retain its normalized report before
preparing a schema-v3 request:

```sh
pcbex run-native-kicad-erc generated.kicad_sch \
  --output native-kicad-erc.json --require-approved
```

The runner invokes `kicad-cli sch erc --format json --units mm
--severity-error --exit-code-violations` in a private staged directory. It
does not read a caller-side `.kicad_pro` or other project sidecar. KiCad
warnings are intentionally outside this v1 approval/report contract (the
current fixture has 11 known warnings under all-severity KiCad output); only
electrical errors determine `approved` and `error_count`. A rejected report is
still retained before `--require-approved` returns failure. The source digest,
normalized findings, and deterministic native `run_sha256` are all bound.
See [`NATIVE_KICAD_ERC.md`](NATIVE_KICAD_ERC.md) for the report schema,
limits, and isolated process boundary.

Adding `--native-kicad-erc-report native-kicad-erc.json` to
`prepare-ai-review` requires the deterministic plan/report pair as well. The
command reruns KiCad and compares the fresh normalized bytes before producing
request schema v3 with artifact binding schema v2:

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

Schema-v2 requests continue to require binding schema v1 and reject a native
field; schema-v3 requests require binding schema v2 and reject a mixed or
partial binding. Schema-v4 requests require binding schema v3 and native
identity schema v2; schema v3 accepts only native identity v1. This strict
matrix prevents warning evidence from being downgraded to the error-only
contract. The Python adapter accepts all four request versions,
treats these identities as immutable evidence rather than instructions, and
continues to require response schema v1.

## Warning-policy evidence (schema v4)

Use the same runner with a trusted policy to select errors and warnings while
leaving the v1 command behavior untouched:

```sh
pcbex run-native-kicad-erc generated.kicad_sch \
  --warning-policy examples/native-kicad-warning-policy.json \
  --output native-kicad-erc-warning.json \
  --require-approved
```

The closed policy has a global warning maximum, sorted unique per-finding-type
limits, and a sorted unique allowlist for KiCad ignored-check keys. Unlisted
warning types and ignored checks reject; all errors reject independently of
the policy. The report carries exact policy source bytes/SHA-256 and a
domain-separated canonical policy digest. Supplying the report to
`prepare-ai-review` also requires
`--native-kicad-erc-warning-policy <trusted-path>` and produces request v4.
Sign, single-approval verification, and quorum verification require the same
path and reproduce the report before accepting it. The policy file is an
external trust input and should not be controlled by an untrusted pull
request.

## Creating a bound request

First retain an approved deterministic report, then supply its plan and report
when preparing the AI request:

```sh
pcbex run-deterministic-pipeline pipeline-plan.json \
  --output deterministic-pipeline-report.json \
  --require-approved

pcbex run-native-kicad-erc generated.kicad_sch \
  --output native-kicad-erc.json \
  --require-approved

pcbex prepare-ai-review generated.kicad_sch \
  --electrical-review electrical-review.json \
  --policy-pack organization-policy-pack.json \
  --simulation-evidence power-rail.evidence.json \
  --deterministic-pipeline-plan pipeline-plan.json \
  --deterministic-pipeline-report deterministic-pipeline-report.json \
  --native-kicad-erc-report native-kicad-erc.json \
  --output ai-review-request.json \
  --session-output ai-review-session.json
```

`prepare-ai-review` does not trust the retained report. It stable-reads the
artifacts, parses the closed plan, executes the complete deterministic runner
again, and requires the newly rendered report to equal the retained bytes.
It also requires all of the following cross-bindings:

- the supplied schematic equals the plan's raw schematic descriptor;
- the report's unique schematic input evidence equals those raw bytes;
- the circuit-to-KiCad handoff identifies those same raw bytes;
- the request's raw electrical-review digest equals the plan descriptor; and
- the request's freshly recomputed electrical result equals the handoff
  result.

The deterministic report must be approved, and the native report must be a
fresh byte-for-byte match. Missing, rejected, stale, symlinked, oversized,
partially supplied, or independently valid but mixed artifacts fail before a
bound request is written. Omitting the native report keeps this flow at
request schema v2; supplying error-only native evidence produces schema v3;
supplying warning-policy native evidence and its trusted policy produces
schema v4.

## Signing and consuming the approval

Schema-v2 requests require the three live paths at every signing and
verification boundary. Schema-v3 requests additionally require
`--native-kicad-erc-report` and `--kicad-cli` when the executable is not on
`PATH`:

```sh
pcbex sign-ai-review ai-review-request.json ai-review-response.json \
  --generated-schematic generated.kicad_sch \
  --deterministic-pipeline-plan pipeline-plan.json \
  --deterministic-pipeline-report deterministic-pipeline-report.json \
  --private-key .secrets/schematic-approval.key \
  --signer-id production-ci \
  --session ai-review-session.json \
  --output signed-approval.json \
  --require-approved

pcbex verify-ai-approval \
  signed-approval.json ai-review-request.json ai-review-response.json \
  --generated-schematic generated.kicad_sch \
  --deterministic-pipeline-plan pipeline-plan.json \
  --deterministic-pipeline-report deterministic-pipeline-report.json \
  --public-key schematic-approval.pub \
  --session ai-review-session.json \
  --require-approved
```

For schema-v3, append these options to each sign, verify, and quorum command:

```sh
--native-kicad-erc-report native-kicad-erc.json --kicad-cli kicad-cli
```

For schema-v4, also append:

```sh
--native-kicad-erc-warning-policy examples/native-kicad-warning-policy.json
```

`verify-ai-quorum` accepts the same three flags, plus the native report and
optional executable override for schema v3, and performs live revalidation
once before checking any candidate signatures or thresholds. For schema-v1,
the separate `--schematic` path is a live semantic binding: signing and
verification import the bounded source and freshly recompute the deterministic
electrical review before accepting the response or signature. It does
not add a filesystem path or artifact identity to the request, and is mutually
exclusive with generated/native artifact paths. Schema-v1 requests reject
those artifact paths so callers cannot accidentally claim a binding that the
request does not contain. Schema-v2 requests reject omitted or partial paths.
Schema-v3 requests reject an omitted native report or incomplete base artifact
set and reject a report whose source identity or normalized run digest differs
from the request.

Live schema-v1 signing is available from the CLI and MCP:

```sh
pcbex sign-ai-review ai-review-request.json ai-review-response.json \
  --schematic hardware/controller.kicad_sch \
  --private-key .secrets/schematic-approval.key \
  --signer-id production-ci \
  --output signed-approval.json --require-approved
```

The equivalent MCP `sign_schematic_approval` call forwards `schematic` and
the same request/response/key/signer/output fields. Run this signing boundary
in an isolated workspace. Bounded reads can reject replacements observed
around verification, but verification, private-key access, and output
publication are not one atomic filesystem transaction and this flow does not
claim a race-free filesystem boundary.

### Signing preflight and publication (v1.443)

The CLI and MCP signing paths perform their complete public-input preflight
before opening the private key. This includes the request and selected live or
artifact-bound evidence, the response schema and bytes, the signer identity,
the optional session, its activity window and request binding, and the output destination.
Invalid, missing, linked, replaced, stale, or otherwise mismatched inputs are
rejected without reading the secret or changing the destination. The output
path must be a fresh no-clobber destination; a pre-existing regular file,
symbolic link, or other non-regular destination is left untouched.

Once preflight succeeds, a response that is valid but fails one or more review
gates is still a legitimate signed rejection. The approval envelope is staged,
flushed, synchronized, and atomically published before `--require-approved`
may return a non-zero status. A failed preflight never creates a partial or
replacement approval.

MCP preserves its existing fail-closed error shape. If
`require_approved: true` rejects an otherwise valid signed rejection, the
retained approval file is still published but the tool result reports
`structuredContent.approval` as `null`; callers that need the rejection
evidence must explicitly verify or consume that retained file.

This hardening changes no request, response, session, or signed-approval wire
schema. Schema-v2 through v4 continue to require their existing complete
artifact paths and fresh replay rules; the schema-v1 `--schematic` input remains
a live semantic source rather than a new artifact identity. The staged output
publication is atomic at the destination-file boundary, but verification,
private-key access, and publication are not one atomic filesystem transaction.
Use an isolated workspace when a hostile local writer is in scope.

Artifact binding prevents an approval from being presented beside a different
schematic or pipeline run. A review session remains necessary when a caller
also needs expiration and replay protection for repeated use of the exact same
artifacts.

## MCP and GitHub Actions

The existing MCP prepare, sign, verify, and quorum tools expose the optional
schematic/pipeline paths, the `native_kicad_erc_report`/`kicad_cli` pair, and
for schema v4 `native_kicad_erc_warning_policy`. The signing tool accepts a
schema-v1 `schematic` live path or the mutually exclusive schema-v2 through v4
artifact path group. Their tools remain synchronous and forbid MCP Tasks
because they handle review outputs, signing keys, or quorum reports. The
Python review adapter accepts request schemas v1 through v4,
treats artifact identities as untrusted evidence rather than instructions, and
continues to require response schema v1.

For the root composite Action, schema v1 can explicitly bind a live source by
setting `ai-review-schematic` with the complete AI quorum inputs and a policy
source. The Action passes the path to `verify-ai-quorum --schematic`, which
imports the live source and freshly recomputes the deterministic electrical
review before accepting signatures. `ai-review-live-schematic-verified`
becomes `true` only after that gate succeeds. This mode is mutually exclusive
with `ai-review-generated-schematic`, native ERC review evidence, and the
deterministic-pipeline intent, plan, and retained artifact inputs used by the
artifact-bound review path. An optional review session and the quorum
threshold inputs remain available.

The root Action reuses the CLI's bounded stable reads and semantic verifier,
but its general analysis workflow is not one atomic snapshot of every review
input. Use an isolated trusted workspace, and use the focused boardless Action
when the smaller aggregate-input snapshot and publication boundary is needed.

For schemas v2 through v4, set `ai-review-generated-schematic` together with
`deterministic-pipeline-plan` and the complete AI quorum inputs. To opt into
schema v3, also set `ai-review-native-kicad-erc-report` and optionally
`ai-review-kicad-cli`. The Action runs the deterministic pipeline, reads the
retained native report, and passes both artifacts to `verify-ai-quorum`, which
reruns native ERC before accepting signatures. It never accepts a
caller-asserted report as proof.

To opt into schema v4, also set
`ai-review-native-kicad-erc-warning-policy`. The Action publishes warning and
policy-failure counts, canonical policy SHA-256, and exact policy-source
byte/SHA identity after the CLI's fresh verification succeeds.

The Action output `ai-review-artifacts-verified` remains reserved for a
successful schema-v2-through-v4 artifact gate; it is not reused for the
schema-v1 live-source result. The raw plan source is reported separately as
`ai-review-pipeline-plan-source-bytes` and
`ai-review-pipeline-plan-source-sha256`; the normalized semantic identity is
`ai-review-pipeline-plan-sha256`. Generated-schematic and retained-report
byte/SHA outputs plus `ai-review-pipeline-run-sha256` complete the evidence.
When native ERC is enabled, `ai-review-native-kicad-erc-report-bytes`,
`ai-review-native-kicad-erc-report-sha256`, and
`ai-review-native-kicad-erc-run-sha256` are also published.
Existing request-schema-v1 Action workflows that omit `ai-review-schematic`
and `ai-review-generated-schematic` retain their prior unbound behavior.
