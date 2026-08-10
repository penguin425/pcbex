# Focused fabrication authorization verification Action

Version 1.461 exposes the v1.459 fresh fabrication-authorization verifier as
a standalone, boardless composite GitHub Action. It verifies already-signed
approvals and retains one audit report; it never signs, reads a private key,
constructs an authorization scope, contacts a factory, or places or pays for
an order.

```yaml
- name: Verify fabrication release authorization
  id: fabrication-authorization
  uses: penguin425/pcbex/actions/fabrication-authorization@v1.461.0
  with:
    plan: pipeline-plan.json
    retained-report: pipeline-report.json
    manufacturing-package: manufacturing.zip
    factory-receipt: factory-receipt.json
    policy-pack: organization-policy-pack.json
    approval-files: |
      fabrication-a.approval.json
      fabrication-b.approval.json
    require-authorized: "true"
```

`approval-files` contains one non-empty caller-workspace-relative path per
line and accepts 1–100 entries. The other five evidence paths are required.
Optional controls are:

| Input | Default | Meaning |
|---|---|---|
| `require-authorized` | `false` | Fail the final Action gate unless the fresh report is authorized |
| `output-dir` | `pcbex-fabrication-authorization` | Empty relative directory for the fixed report |
| `upload-artifact` | `true` | Upload the authenticated one-file evidence directory |
| `artifact-name` | `pcbex-fabrication-authorization` | Artifact service name |
| `retention-days` | `14` | Artifact retention, from 1 through 90 days |

The report filename is fixed as
`${output-dir}/fabrication-authorization.json`; callers cannot select another
filename. Existing report files, linked or non-directory output roots, and
non-empty output directories are rejected. An already existing empty output
directory is allowed.

## Decision and outputs

The wrapper output `status` is `ok` only when fresh verification and report
authentication completed. It is distinct from `authorization-status`, whose
closed values are `fabrication_authorized` and `not_authorized`, and from the
boolean `fabrication-authorized`. A valid submitted rejection, insufficient
quorum, or inactive validity window therefore produces `status: ok` and a
retained `not_authorized` report. `require-authorized: "true"` applies only in
the last step, after bounded validation, publication-time revalidation, and
optional upload.

The Action also returns `artifact-dir`,
`fabrication-authorization-report`, and the exact compact 23-field verifier
snapshot as scalar outputs:

- `schema-version`, `authorization-status`, and `fabrication-authorized`;
- `authorization-id`, `challenge`, `quantity`, `currency`,
  `maximum-total-minor-units`, `valid-from-unix`, `expires-at-unix`, and
  `evaluated-at-unix`;
- `approvals`, `rejections`, and `gate-failure-count`;
- `plan-sha256`, `run-sha256`, `manufacturing-package-sha256`,
  `factory-receipt-sha256`, and `policy-pack-sha256`;
- `quote-authenticity-verified`, `challenge-one-time-use-enforced`,
  `report-bytes`, and `report-sha256`.

The Action does not expose a full JSON summary output. Policy bodies, signed
approval envelopes, signatures, reasons, tickets, receipt provider/endpoint,
quote digest, and canonical policy identity remain only in the retained full
report.

## Execution and retention boundary

The composite Action performs these operations in order:

1. validates every explicit input and the fresh output boundary;
2. builds the locked release binary under bounded subprocess supervisors;
3. invokes `verify-fabrication-authorization` with attached options and `--`
   before the positional plan, without forwarding `require-authorized`;
4. authenticates the CLI's compact bridge against the complete retained
   report and snapshots all direct caller inputs;
5. scans exactly one regular report at depth one, with 128 MiB per-file and
   aggregate limits;
6. rereads the direct inputs and reauthenticates the report immediately before
   publication;
7. optionally uploads the pinned artifact; and
8. applies the final required-authorization gate.

Malformed JSON, duplicate keys, signature or evidence failure in the Rust
verifier, mismatched compact metadata, changed inputs/report, extra files, or
an unsafe output boundary produces `status: error` and exposes no artifact
path. The Python summary helper authenticates the trusted CLI bridge and full
report correspondence; it does not independently reimplement or replace the
Rust Ed25519 verifier.

## Security and operational limits

The uploaded full report contains the normalized policy pack, public keys,
signed envelopes, human reasons, and tickets. Repositories that treat those as
sensitive should set `upload-artifact: "false"` or apply appropriate artifact
access and retention controls.

`evaluated-at-unix` records one child-sampled verification instant. Neither the
report nor Action outputs are a reusable current authorization or a trusted
timestamp. A release consumer must freshly rerun the verifier from the
original artifacts and submitted approvals at the actual handoff boundary.
If cancellation occurs after atomic report publication, a complete file may
remain, but an incomplete Action run does not authenticate it; use a new output
path for a fresh run.

The input snapshots, publication-time report check, and GitHub artifact upload
are separate operations rather than one filesystem/service transaction. They
assume the normal isolated runner workspace and cannot exclude a concurrent
same-user process that rewrites files after the final check but before upload.
Do not share that workspace with untrusted processes, and never treat the
uploaded artifact by itself as current release authority.

The Action adds no signing/private-key input, evaluation-time override,
factory-submission/API input, quote authentication, challenge-consumption or
revocation ledger, inventory reservation, order placement, fabrication,
payment, or spend authority. It may use the network to install the stable Rust
toolchain, build with locked dependencies, and, when enabled, upload the
retained GitHub artifact. Its 128 MiB report ceiling is enforced, but this
release does not claim a near-limit 128 MiB end-to-end upload stress test.
