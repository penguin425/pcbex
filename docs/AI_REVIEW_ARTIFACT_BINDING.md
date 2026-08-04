# AI review artifact binding

Version 1.424 adds an opt-in AI review request schema v2 that binds an
approval to one exact generated KiCad schematic and one exact successful
deterministic-pipeline execution. The existing request schema v1 remains the
default when no pipeline artifacts are supplied.

## Bound identities

The closed `artifact_binding` object contains no filesystem paths. It records:

- the byte count and SHA-256 of the generated `.kicad_sch`;
- the byte count and SHA-256 of the raw deterministic-pipeline plan;
- the domain-separated normalized plan SHA-256;
- the byte count and SHA-256 of the retained pipeline report, including its
  final newline; and
- the domain-separated pipeline run SHA-256.

These fields are covered by the request's normalized `request_sha256`.
Existing ordinary and session-bound Ed25519 approval envelopes already sign
that request digest, so their wire formats do not change. Request schema v2
and session-bound approval envelope schema v2 are independent version
numbers.

Paths are deliberately excluded. A byte-identical copied schematic is the
same approved artifact, while a one-byte change invalidates the binding.
Generated schematics are limited to 64 MiB, raw plans to 4 MiB, and retained
reports to 128 MiB including the publication newline.
Reformatting a source plan or changing the runner engine version can therefore
invalidate a prior binding even when its semantic plan remains equivalent;
regenerate the request and approvals after either intentional change.

## Creating a bound request

First retain an approved deterministic report, then supply its plan and report
when preparing the AI request:

```sh
pcbex run-deterministic-pipeline pipeline-plan.json \
  --output deterministic-pipeline-report.json \
  --require-approved

pcbex prepare-ai-review generated.kicad_sch \
  --electrical-review electrical-review.json \
  --policy-pack organization-policy-pack.json \
  --simulation-evidence power-rail.evidence.json \
  --deterministic-pipeline-plan pipeline-plan.json \
  --deterministic-pipeline-report deterministic-pipeline-report.json \
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

The report must be approved. Missing, rejected, stale, symlinked, oversized,
partially supplied, or independently valid but mixed artifacts fail before a
bound request is written.

## Signing and consuming the approval

Schema-v2 requests require the three live paths at every signing and
verification boundary:

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

`verify-ai-quorum` accepts the same three flags and performs the live
revalidation once before checking any candidate signatures or thresholds.
Schema-v1 requests reject these paths so callers cannot accidentally claim a
binding that the request does not contain. Schema-v2 requests reject omitted
or partial paths.

Artifact binding prevents an approval from being presented beside a different
schematic or pipeline run. A review session remains necessary when a caller
also needs expiration and replay protection for repeated use of the exact same
artifacts.

## MCP and GitHub Actions

The existing MCP prepare, sign, verify, and quorum tools expose the same
optional pair or triple of path arguments. Their tools remain synchronous and
forbid MCP Tasks because they handle review outputs, signing keys, or quorum
reports. The Python review adapter accepts request schemas v1 and v2, treats
artifact identities as untrusted evidence rather than instructions, and
continues to require response schema v1.

For the root composite Action, set `ai-review-generated-schematic` together
with `deterministic-pipeline-plan` and the complete AI quorum inputs. The
Action runs the deterministic pipeline before quorum verification, retains
the fixed report under `output-dir`, and passes that fresh report to
`verify-ai-quorum`. It never accepts a caller-asserted report as proof.

The Action output `ai-review-artifacts-verified` becomes `true` only after the
live artifact gate succeeds. The raw plan source is reported separately as
`ai-review-pipeline-plan-source-bytes` and
`ai-review-pipeline-plan-source-sha256`; the normalized semantic identity is
`ai-review-pipeline-plan-sha256`. Generated-schematic and retained-report
byte/SHA outputs plus `ai-review-pipeline-run-sha256` complete the evidence.
Existing request-schema-v1 Action workflows omit
`ai-review-generated-schematic` and retain their prior behavior.
