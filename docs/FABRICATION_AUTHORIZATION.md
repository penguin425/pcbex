# Offline fabrication release authorization

Version 1.459 adds a Rust-native, CLI-only dual-control boundary for releasing
one exact manufacturing package to a separately controlled fabrication
handoff. It does not submit that package, place an order, reserve inventory,
execute payment, or contact a network service.

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

`challenge_one_time_use_enforced` is always false. A random challenge and
expiration prevent accidental cross-scope reuse, but a static offline verifier
cannot know whether an authorization was already consumed. One-time use,
revocation, procurement authorization, supplier authenticity, live inventory,
and spend enforcement require a durable trusted ledger and a separate order
executor. Those capabilities, MCP verification, and a verification-only GitHub
Action are intentionally outside v1.459.

The verifier can veto only a valid rejection included in its submitted
approval set. It cannot discover a withheld decision or treat a later
same-signer rejection as revocation. Complete decision collection, rejection
discovery, and revocation also require the external durable ledger described
above.
