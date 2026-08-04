# AI review artifact binding

Version 1.425 adds an opt-in AI review request schema v3 that can bind an
approval to one exact generated KiCad schematic, one exact successful
deterministic-pipeline execution, and one exact normalized native KiCad ERC
run. Request schema v1 remains the unbound default; schema v2 remains
backward-compatible when native ERC evidence is not supplied.

## Bound identities

The closed `artifact_binding` object contains no filesystem paths. It records:

- the byte count and SHA-256 of the generated `.kicad_sch`;
- the byte count and SHA-256 of the raw deterministic-pipeline plan;
- the domain-separated normalized plan SHA-256;
- the byte count and SHA-256 of the retained pipeline report, including its
  final newline; and
- the domain-separated pipeline run SHA-256; and
- for schema v3, the byte count and SHA-256 of the retained native KiCad ERC
  report plus its domain-separated native run SHA-256.

These fields are covered by the request's normalized `request_sha256`.
Existing ordinary and session-bound Ed25519 approval envelopes already sign
that request digest, so their wire formats do not change. Request schema v2
and v3, and session-bound approval envelope schema v2, are independent version
numbers.

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
partial binding. The Python adapter accepts all three request versions,
treats these identities as immutable evidence rather than instructions, and
continues to require response schema v1.

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
request schema v2; supplying it produces schema v3.

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

`verify-ai-quorum` accepts the same three flags, plus the native report and
optional executable override for schema v3, and performs live revalidation
once before checking any candidate signatures or thresholds.
Schema-v1 requests reject these paths so callers cannot accidentally claim a
binding that the request does not contain. Schema-v2 requests reject omitted
or partial paths. Schema-v3 requests reject an omitted native report or
incomplete base artifact set and reject a report whose source identity or
normalized run digest differs from the request.

Artifact binding prevents an approval from being presented beside a different
schematic or pipeline run. A review session remains necessary when a caller
also needs expiration and replay protection for repeated use of the exact same
artifacts.

## MCP and GitHub Actions

The existing MCP prepare, sign, verify, and quorum tools expose the optional
schematic/pipeline paths and, for schema v3, the
`native_kicad_erc_report`/`kicad_cli` pair. Their tools remain synchronous and
forbid MCP Tasks because they handle review outputs, signing keys, or quorum
reports. The Python review adapter accepts request schemas v1, v2, and v3,
treats artifact identities as untrusted evidence rather than instructions, and
continues to require response schema v1.

For the root composite Action, set `ai-review-generated-schematic` together
with `deterministic-pipeline-plan` and the complete AI quorum inputs. To opt
into schema v3, also set `ai-review-native-kicad-erc-report` and optionally
`ai-review-kicad-cli`. The Action runs the deterministic pipeline, reads the
retained native report, and passes both artifacts to `verify-ai-quorum`, which
reruns native ERC before accepting signatures. It never accepts a
caller-asserted report as proof.

The Action output `ai-review-artifacts-verified` becomes `true` only after the
live artifact gate succeeds. The raw plan source is reported separately as
`ai-review-pipeline-plan-source-bytes` and
`ai-review-pipeline-plan-source-sha256`; the normalized semantic identity is
`ai-review-pipeline-plan-sha256`. Generated-schematic and retained-report
byte/SHA outputs plus `ai-review-pipeline-run-sha256` complete the evidence.
When native ERC is enabled, `ai-review-native-kicad-erc-report-bytes`,
`ai-review-native-kicad-erc-report-sha256`, and
`ai-review-native-kicad-erc-run-sha256` are also published.
Existing request-schema-v1 Action workflows omit
`ai-review-generated-schematic` and retain their prior behavior.
