# Offline fabrication release authorization

Version 1.459 adds a Rust-native dual-control CLI boundary for releasing one
exact manufacturing package to a separately controlled fabrication handoff.
Version 1.460 exposes fresh verification, but never signing or private-key
access, through MCP. Version 1.461 adds the same verification-only boundary as
a focused boardless composite GitHub Action. Version 1.462 adds a separate
Unix-only cooperative reservation of an authorized challenge in one trusted
local ledger. None of these versions submits that package to a factory, places
an order, reserves inventory, executes payment, or contacts a fabrication API
as part of verification or reservation. The Action may still download its Rust
toolchain and upload the retained GitHub artifact.

The authorization starts from an existing factory-required deterministic
pipeline plan and retained report. pcbex runs that plan again in-process and
requires the fresh compact report plus trailing LF to equal the retained bytes
exactly. The report must be `approved: true`, use the factory-bound pipeline-v2
contract, and contain exactly one passing `factory-dfm` phase. A rejected or
non-factory pipeline cannot be overridden by human signatures.

## Organization policy

The exact `analysis_policy_pack` selected by the deterministic plan is the
authorization trust root. Its optional closed field is:

```json
{
  "fabrication_authorization_policy": {
    "minimum_approvals": 2,
    "maximum_validity_seconds": 3600,
    "trusted_keys": [
      {"signer_id": "fabrication-a", "public_key": "<64 lowercase hex>"},
      {"signer_id": "fabrication-b", "public_key": "<64 lowercase hex>"}
    ]
  }
}
```

`minimum_approvals` and the key list are limited to 2–100. The maximum
validity is positive and at most 604,800 seconds (seven days). Signer IDs and
public keys must be unique and cannot also hold AI-review or human-escalation
roles. Existing schema-v1 policy packs that omit the field retain their prior
normalized serialization and remain valid for their existing uses, but they
cannot authorize fabrication release.

The policy pack contains only public keys. Generate each approval keypair with
`approval-keygen`, distribute only the public key in the pack, and keep private
keys outside the repository. If organizational provenance matters, authenticate
the policy pack through the existing signed-policy-pack trust workflow before
using its normalized body here. This command binds the exact pack selected by
the plan but does not independently establish who selected or distributed that
trust root.

## Sign one decision

Each signer uses the same exact plan, retained report, ZIP, receipt, policy,
and scope:

```sh
pcbex sign-fabrication-approval pipeline-plan.json \
  --report pipeline-report.json \
  --manufacturing-package manufacturing.zip \
  --factory-receipt factory-receipt.json \
  --policy-pack organization-policy-pack.json \
  --private-key .secrets/fabrication-a.key \
  --signer-id fabrication-a \
  --decision approve \
  --authorization-id lot-2026-08-10-a \
  --challenge "$FABRICATION_CHALLENGE" \
  --quantity 20 \
  --currency USD \
  --maximum-total-minor-units 25000 \
  --valid-from-unix "$VALID_FROM_UNIX" \
  --expires-at-unix "$EXPIRES_AT_UNIX" \
  --reason 'Independent review approved this exact release scope.' \
  --ticket HW-1459 \
  --output fabrication-a.approval.json
```

The authorization ID is a bounded lowercase slug. The caller must set
`FABRICATION_CHALLENGE` from a cryptographically secure random source; pcbex
validates only that `challenge` is exactly 32 bytes encoded as 64 lowercase
hexadecimal digits and cannot prove its entropy. Quantity is 1–1,000,000;
currency is exactly three uppercase ASCII letters; and the positive monetary
ceiling is bounded to JSON's exact-integer range. The validity interval must be
positive and no longer than seven days. Policy may impose a shorter interval.

The signature uses the dedicated domain `pcbex-fabrication-approval-v1` and
covers all of the following:

- raw plan bytes/SHA-256 and its semantic `plan_sha256`;
- raw retained-report bytes/SHA-256 and `run_sha256`;
- the exact manufacturing ZIP byte count and SHA-256;
- the exact factory-receipt identity, normalized provider and HTTPS endpoint,
  and canonical digest of its opaque quote object;
- the exact policy-pack raw identity, normalized ID/revision, and canonical
  digest;
- every scope field, decision, reason, ticket, and signer ID.

The envelope additionally records `algorithm: ed25519` and the derived public
key. Verification requires that key to equal the dedicated trusted key for the
signed signer ID and verifies the domain-separated payload with that exact key;
the public-key string is not a separate field in the signed preimage.

The command reserves a new no-clobber output, validates and freshly reproduces
all public evidence, validates the dedicated signer role and scope, and only
then reads the private key. A trusted signer may deliberately sign `reject`;
that cryptographic decision is retained and can never count as approval.

## Verify the quorum

```sh
pcbex verify-fabrication-authorization pipeline-plan.json \
  --report pipeline-report.json \
  --manufacturing-package manufacturing.zip \
  --factory-receipt factory-receipt.json \
  --policy-pack organization-policy-pack.json \
  --approval fabrication-a.approval.json \
  --approval fabrication-b.approval.json \
  --output fabrication-authorization.json \
  --require-authorized
```

Verification re-runs the approved factory-bound pipeline, revalidates the ZIP,
receipt, and pack, parses each bounded duplicate-free approval, and requires:

- exact common evidence and scope across every approval;
- distinct trusted signer IDs and public keys;
- valid Ed25519 signatures under the dedicated policy role;
- at least the policy's minimum number of `approve` decisions;
- no submitted, valid human rejection in the decision set; and
- an evaluation time inside the signed window and a window no longer than the
  policy maximum.

The plan, retained report, ZIP, receipt, pack, and submitted approvals are
stable-read again before the current evaluation time is captured. The output
boundary is also rechecked against the same in-memory plan used by the fresh
run before publication. Invalid signatures, untrusted keys, mixed
evidence/scope, duplicate signers, malformed inputs, or mutation of those
authorization sources fail without a report. Structurally and
cryptographically valid policy outcomes are different: a submitted rejection,
insufficient quorum, an inactive window, or a policy-window excess produce a
closed `not_authorized` report. `--require-authorized` returns nonzero only
after that truthful report is retained.

The final report keeps the complete normalized policy pack, path-free evidence,
scope, evaluation time, counts, sorted gate failures, signer summaries, and the
full signer-sorted approval envelopes. The report is an audit snapshot produced
by that verification run, not an outer-signed timestamp or a reusable current
authorization. A consumer that will release bytes must run
`verify-fabrication-authorization` again from the original artifacts and signed
approvals at its current time; schema validation or editing and re-reading the
report alone is never an authorization check. Emit the two closed structural
contracts with:

```sh
pcbex signed-fabrication-approval-schema \
  --output signed-fabrication-approval.schema.json
pcbex fabrication-authorization-report-schema \
  --output fabrication-authorization-report.schema.json
```

Both schema outputs and operational artifacts are no-clobber. Reports do not
copy filesystem paths from inputs and never contain private keys; the explicit
human reason and ticket remain signed caller text.

## MCP verification parity

Version 1.460 exposes the closed MCP tool
`verify_fabrication_authorization`. It accepts the same plan, retained pipeline
report, manufacturing ZIP, factory receipt, policy pack, one to 100 signed
approvals, and new output path as the CLI verifier. Calls may run synchronously
or as optional MCP Tasks. The tool never accepts a private key, signer or
decision fields, a caller-selected evaluation time, or inline artifact bytes;
`sign-fabrication-approval` remains CLI-only.

Every call starts the existing CLI verifier as a bounded shell-free child. The
child freshly reproduces and revalidates the original artifacts, samples the
current time after its final source rereads, and atomically writes the complete
authorization report. A report may be as large as 128 MiB, so MCP does not
embed it. Instead, the child emits a compact path-free summary after
publication. The MCP bridge stable-reads the output, rejects duplicate-key or
malformed report/summary JSON, verifies the exact report byte count and
SHA-256, parses the complete typed report, and reruns its policy and signature
evaluation at the report's recorded `evaluated_at_unix` before accepting the
summary's exact correspondence to that report.

The compact snapshot has exactly 23 fields:

- schema, status, and `fabrication_authorized`;
- authorization ID, challenge, quantity, currency, maximum value, and validity
  window;
- `evaluated_at_unix`, approval/rejection counts, and gate-failure count;
- plan and run digests plus the raw manufacturing ZIP, factory-receipt source,
  and policy-pack source SHA-256 values;
- quote-authenticity and challenge-one-time-use flags; and
- retained report byte count and SHA-256.

In particular, `manufacturing_package_sha256`, `factory_receipt_sha256`, and
`policy_pack_sha256` name exact raw source identities. The snapshot does not
directly return the receipt provider, endpoint, or quote SHA-256, nor the policy
canonical SHA-256, ID, or revision. Those fields, the complete policy, approval
envelopes, signatures, reasons, and tickets remain in the retained report and
are checked by the full replay rather than copied into the MCP response.

`ok: true` means that fresh verification completed and produced an
authenticated report; it does not by itself mean that fabrication was
authorized. Callers must inspect
`structuredContent.report_summary.fabrication_authorized`, or set
`require_authorized: true`. A valid submitted rejection, insufficient quorum,
or expired/not-yet-valid window still leaves a truthful `not_authorized` report
before that optional gate returns an MCP error. Task queue time is part of real
elapsed time, so a scope may truthfully expire before a queued task is
evaluated.

`evaluated_at_unix` is an integrity-checked snapshot of when that child made its
decision, not a trusted timestamp or proof that the authorization is still
current when a later consumer acts. The output locator is operational metadata,
not an authorization artifact. Consumers must rerun this verifier from the
original sources and submitted approvals at the actual release boundary; a
retained summary or report is not reusable current authority.

Task cancellation and TTL expiry stop the bounded child and leave the Task in
the cancelled terminal state; later child completion cannot turn that Task into
a successful authenticated-summary result. If the child won the race and
atomically published its no-clobber report before cancellation was observed,
the file may remain rather than being deleted. That file is not authenticated
by the cancelled Task and must be treated only as a snapshot pending a fresh
verification into a new output path.

## Focused GitHub Action parity

Version 1.461 adds the standalone
`actions/fabrication-authorization` composite Action. It accepts the same five
required evidence paths plus 1–100 newline-separated `approval-files`, keeps
signing and private-key access CLI-only, and retains the fixed
`${output-dir}/fabrication-authorization.json` report. It is boardless and does
not expand the root hardware-analysis Action.

The Action authenticates the exact 23-field compact verifier bridge against
the full retained report, snapshots and rereads all direct inputs, requires a
one-file depth-one output within 128 MiB, and revalidates the report at the
publication boundary. Valid `not_authorized` evidence is retained and may be
uploaded before the optional `require-authorized` final gate fails. The full
report contains policy and human approval material; use
`upload-artifact: "false"` when that evidence should not enter the GitHub
artifact service.

See
[`FABRICATION_AUTHORIZATION_ACTION.md`](FABRICATION_AUTHORIZATION_ACTION.md)
for the exact inputs, outputs, sequencing, confidentiality warning, and
non-claims.

## Trusted local challenge reservation

Version 1.462 adds the CLI-only `reserve-fabrication-authorization` boundary.
It accepts the same original plan, retained pipeline report, manufacturing ZIP,
factory receipt, policy pack, and one to 100 signed approvals. It accepts no
fabrication-authorization output path, authorization gate, evaluation-time
override, private key, signer decision, network endpoint, factory credential,
order, or payment input. Standard output is empty on success; only a concise
non-sensitive status may be written to standard error.

The command freshly builds the complete authorization report in memory and
requires it to be `fabrication_authorized` before reserving anything. It then
retains only one path-free marker containing the existing 23-field compact
summary, including the exact full-report byte count and SHA-256. The full
policy pack, approvals, signatures, reasons, tickets, receipt details, and full
authorization report are not published by this command. Consumers that need
that audit evidence must separately run `verify-fabrication-authorization`
into a new no-clobber output.

The caller supplies an absolute `--reservation-ledger` and the 64-lowercase-hex
`--expected-ledger-id` selected from its fixed manifest. That ledger must
already exist on Unix as an effective-UID-owned real directory with mode
exactly `0700`; pcbex does not initialize or repair it. The complete marker is
file-synchronized, installed without replacement relative to the pinned ledger
descriptor under a challenge-derived fixed filename, and followed by
directory synchronization before success. Local wall-clock checks bracket the
installation and run once more after durability; an inactive pre-install
window leaves no marker, while expiry after installation burns the challenge
and returns an error. Those samples are not recorded as trusted time. Any
existing entry blocks the challenge. A failure after installation leaves the
final marker in place and makes subsequent attempts fail closed.

The exact five-key marker continues to report
`authorization_report_summary.challenge_one_time_use_enforced: false`. Its
scope is only `pinned-local-ledger-at-most-once-v1`: the approval signatures do
not bind the ledger identity, and another ledger, host, or runner has
independent state. Same-UID or administrative deletion, ledger replacement or
rollback, Windows, network/distributed/overlay/ephemeral filesystems, trusted
time, revocation or withheld-rejection discovery, global one-time use, factory
authenticity, submission, ordering, payment, and exactly-once side effects are
not provided. Without a separately controlled executor that owns the handoff
credentials and makes this reservation mandatory, the marker is cooperative
replay protection rather than a permission boundary.

See
[`FABRICATION_AUTHORIZATION_RESERVATION.md`](FABRICATION_AUTHORIZATION_RESERVATION.md)
for the exact manifest, marker, schema, synchronization, crash, and trust
contracts. This feature is not exposed through MCP, the focused verification
Action, or the root hardware Action.

## Receipt and authority limits

The existing factory receipt is locally normalized evidence. The verifier
requires its package/request identities to match the exact validated ZIP and
requires HTTPS, 2xx, acceptance, DFM pass, and the fail-closed severity policy.
It also binds the canonical opaque quote object. The receipt has no factory
signature, and raw response bytes are not retained for independent response
digest reconstruction. Accordingly, every report records
`quote_authenticity_verified: false`.

The signed quantity and monetary ceiling state what the humans approved; they
do not interpret tax, shipping, price breaks, or other fields inside the opaque
quote. A downstream order executor must compare its typed order terms against
this ceiling under its own trusted factory contract.

`challenge_one_time_use_enforced` is always false in ordinary authorization
reports, MCP/Action summaries, and the v1.462 local reservation marker. A
random challenge and expiration prevent accidental cross-scope reuse, but a
static offline verifier cannot know whether an authorization was already
consumed. Global one-time use, revocation, procurement authorization, supplier
authenticity, live inventory, and spend enforcement require a durable trusted
ledger and a separately controlled order executor. The v1.462 marker adds only
the bounded local cooperative reservation described above. MCP and the focused
GitHub Action provide fresh verification only; neither consumes the challenge
nor executes an order.

The verifier can veto only a valid rejection included in its submitted
approval set. It cannot discover a withheld decision or treat a later
same-signer rejection as revocation. Complete decision collection, rejection
discovery, and revocation also require the external durable ledger described
above.
