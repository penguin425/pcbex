# Witnessed Factory-release Registry History Checkpoints

Pin one audited registry head. Detect rollback and equivocation across retained
consumers.

The v1.502 contract preserves every v1.501 artifact and CLI verification path.
It adds structural admission of canonical remote-witness receipts into the
existing signed approval transparency chain.

> [!IMPORTANT]
> A checkpoint protects only consumers that retain and supply their previous
> trust state. It does not make the host filesystem append-only or prove global
> non-equivocation when independent consumers never compare observations.

## Key features

- **Replays before signing:** Audits the complete typed history from exact empty
  genesis before the retained root can sign its head.
- **Binds the full result:** Covers the audit SHA-256, final registry SHA-256,
  generation, final transition, active governance, current root, and issue
  time.
- **Pins monotonic trust:** Rejects generation rollback, same-generation
  equivocation, time reversal, and a later history that omits or changes the
  previously accepted prefix.
- **Requires fresh witnesses:** Verifies a configurable threshold of 2–100
  distinct identities and keys over one exact checkpoint.
- **Rotates without substitution:** Requires both retained-key authorization
  and successor-key possession before advancing one witness generation.
- **Acquires within hard bounds:** Uses HTTPS without redirects, a 1 MiB
  response ceiling, a 1–600 second deadline, and optional Bearer credentials
  read only from a named environment variable.
- **Verifies before retaining:** Replays the exact local history and checks the
  returned canonical witness before either output is published.
- **Binds the transport:** Records the exact history, checkpoint trust state,
  request, response, witness, endpoint, key mode, and evaluation time in a
  canonical receipt.
- **Publishes receipt history:** Normalizes the receipt, checkpoint, request,
  response, and witness identities into a signed append-only log snapshot.
- **Separates key roles:** Rejects checkpoint-witness keys reused by any current
  or historical registry root or embedded governance authority.
- **Retains negative evidence:** Writes a valid below-threshold quorum report
  before `--require-quorum` returns nonzero.

## Quick start

Start with the canonical portable history produced by the
[v1.498 history exporter](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_AUDIT.md).

### 1. Sign the audited head

Use the private key for the root retained at the history's final generation.
An old root fails after either a legacy or governed root rotation.

```bash
pcbex sign-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint \
  --history registry.history.json \
  --authority-private-key current-root.secret.hex \
  --issued-at-unix 1787702400 \
  --output registry.history.checkpoint.json
```

The command revalidates the history immediately before no-clobber publication.
Private-key bytes never enter the checkpoint.

### 2. Accept and retain monotonic trust

Accept the first checkpoint without a baseline:

```bash
pcbex accept-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint \
  --history registry.history.json \
  --checkpoint registry.history.checkpoint.json \
  --accepted-at-unix 1787702460 \
  --output registry.history.checkpoint-trust.json
```

For every later generation, supply the previously retained trust state:

```bash
pcbex accept-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint \
  --history registry.history.next.json \
  --checkpoint registry.history.next.checkpoint.json \
  --baseline registry.history.checkpoint-trust.json \
  --accepted-at-unix 1787706060 \
  --output registry.history.next.checkpoint-trust.json
```

Exact same-checkpoint retry returns the retained trust-state bytes. A different
checkpoint at the same generation fails as equivocation.

> [!TIP]
> Store accepted trust states in deployment-owned, rollback-resistant storage.
> Copying the newest file over an unprotected path does not preserve the
> monotonic guarantee.

### 3. Pin and rotate witness trust

Initialize one generation-zero trust state for each configured witness:

```bash
pcbex init-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-trust \
  --witness-id witness-a \
  --public-key witness-a.public.hex \
  --output witness-a.trust.0.json

pcbex init-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-trust \
  --witness-id witness-b \
  --public-key witness-b.public.hex \
  --output witness-b.trust.0.json
```

Rotate `witness-a` only after both the retained and successor private keys sign
the same transition:

```bash
pcbex sign-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-key-rotation \
  --trust-state witness-a.trust.0.json \
  --old-private-key witness-a.secret.hex \
  --new-private-key witness-a.next.secret.hex \
  --rotated-at-unix 1787702470 \
  --output witness-a.rotation.1.json

pcbex apply-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-key-rotation \
  --trust-state witness-a.trust.0.json \
  --rotation witness-a.rotation.1.json \
  --output witness-a.trust.1.json \
  --public-key-output witness-a.current.public.hex
```

The apply command verifies both signatures, the exact next generation, the
predecessor digest, and nondecreasing rotation time before publishing both
outputs atomically. Use the standalone export command when only the current
public key needs to be derived again:

```bash
pcbex export-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-key \
  --trust-state witness-a.trust.1.json \
  --output witness-a.current-again.public.hex
```

### 4. Create independent witnesses

Each witness independently receives both the complete history and checkpoint.
It replays the history before signing.

```bash
pcbex sign-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness \
  --history registry.history.json \
  --checkpoint registry.history.checkpoint.json \
  --witness-id witness-a \
  --witness-private-key witness-a.next.secret.hex \
  --witnessed-at-unix 1787702500 \
  --output registry.history.witness-a.json
```

Repeat with a different identity and key for `witness-b`.

### 5. Acquire a remote witness

Pin either a direct public key or one current witness trust state. Never supply
both modes in the same request.

```bash
export PCBEX_REGISTRY_WITNESS_TOKEN='replace-with-runtime-secret'

pcbex request-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness \
  --history registry.history.json \
  --checkpoint-trust-state registry.history.checkpoint-trust.json \
  --endpoint https://witness.example/v1/registry-history-checkpoint \
  --witness-key-trust-state witness-b.trust.0.json \
  --bearer-token-env PCBEX_REGISTRY_WITNESS_TOKEN \
  --timeout-seconds 30 \
  --output registry.history.witness-b.remote.json \
  --receipt-output registry.history.witness-b.remote-receipt.json
```

Use `--public-key witness-b.public.hex` instead of
`--witness-key-trust-state` for a directly pinned key. The complete 128 MiB
history stays local; the request sends only the accepted checkpoint trust
state. The client still replays that local history before the request and again
through witness verification before publishing either output.

> [!NOTE]
> Production endpoints must use HTTPS. The hidden loopback-HTTP switch exists
> only for hermetic tests. Redirects, URL userinfo, URL queries, non-JSON
> responses, oversized bodies, duplicate keys, unknown fields, and
> non-canonical witness bytes fail closed.

### 6. Publish the receipt history

Append a verified remote receipt to a new transparency-log snapshot:

```bash
pcbex init-approval-log \
  --log-id factory-release-registry-witness-receipts \
  --output receipt-log.0.json

pcbex append-approval-log receipt-log.0.json \
  --artifact registry.history.witness-b.remote-receipt.json \
  --kind remote-factory-release-registry-history-checkpoint-witness-receipt \
  --recorded-at-unix 1787702580 \
  --output receipt-log.1.json
```

Sign `receipt-log.1.json` with `sign-approval-log`. Existing approval-log
anchors, consistency proofs, gossip, and witness quorum then apply unchanged.
See [Receipt Transparency](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_TRANSPARENCY.md)
for the full trust boundary.

### 7. Verify the witness quorum

Supply the current trust state for every configured witness. Witness and trust
state order does not affect the canonical member order.

```bash
pcbex verify-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witnesses \
  --history registry.history.json \
  --checkpoint registry.history.checkpoint.json \
  --witness registry.history.witness-b.remote.json \
  --witness registry.history.witness-a.json \
  --witness-trust-state witness-b.trust.0.json \
  --witness-trust-state witness-a.trust.1.json \
  --minimum-witnesses 2 \
  --evaluated-at-unix 1787702600 \
  --require-quorum \
  --output registry.history.witness-quorum.json
```

Local and remotely acquired witnesses share the unchanged signed-witness wire
format and compose in one quorum. The direct v1.499 `--trusted-witness-id` and
`--trusted-witness-public-key` arguments remain supported. Direct keys and
trust states cannot be mixed in one verification.

## Verification flow

```text
portable v1.498 history
          │
          ├── replay all five event kinds ──▶ computed final registry
          │                                      │
          │                                      ▼
          └──────────────────────────────▶ retained-root checkpoint
                                                 │
                           ┌─────────────────────┼─────────────────────┐
                           ▼                     ▼                     ▼
                  checkpoint trust      witness A trust       witness B trust
                          │                     │                     │
                          │              dual-signed rotation         │
                          │                     │                     │
                          │                     ▼                     ▼
                          │                local witness       HTTPS endpoint
                          │                                           │
                          └──── complete-history replay ◀── remote witness
                                                │             + receipt
                                                ├── exact quorum ─────┘
                                                └── signed receipt log
```

Every signing and verification path calls the production history auditor. No
operation trusts a copied final registry or a caller-supplied audit result.

## Contracts and limits

| Artifact | Bound | Critical fields |
| --- | ---: | --- |
| Signed checkpoint | 32 KiB | Registry, generation, audit/final-state digests, final transition, governance, root, issue time, signature |
| Accepted trust state | 64 KiB | Exact checkpoint plus accepted generation and acceptance time |
| Signed witness | 32 KiB | Exact checkpoint SHA-256, witness identity/key, witness time, signature |
| Witness trust state | 32 KiB | Identity, generation, current key, last rotation digest and time |
| Signed witness-key rotation | 32 KiB | Adjacent generations, predecessor digest, old/new keys, rotation time, both signatures |
| Witness-quorum report | 128 KiB | Checkpoint and audit digests, evaluation time, threshold, sorted members, decision |
| Remote response | 1 MiB transport ceiling | Must also fit the unchanged 32 KiB canonical signed-witness contract |
| Remote transport receipt | 64 KiB | Endpoint, exact input/request/response/witness digests, key mode, times, verified result |
| Receipt transparency log | 100,000 entries and 128 MiB generic file ceiling | Monotonic sequence/time, predecessor/self digests, normalized receipt bindings |
| Witness/trust sets | 100 entries | Distinct identities and distinct non-weak Ed25519 keys |
| Acceptance delay | 24 hours | `accepted_at_unix - issued_at_unix` |
| Witness freshness | 24 hours | `evaluated_at_unix - witnessed_at_unix` |

All seven v1.499–v1.501 registry documents use canonical pretty JSON with one
trailing LF. Their parsers reject duplicate keys, unknown fields,
non-canonical formatting, weak keys, invalid self-signatures, oversized inputs,
and generation values above 4,096. The v1.502 event enters the existing bounded
approval-log format.

## Schemas and validators

Print the recursively closed schemas:

```bash
pcbex signed-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-schema
pcbex factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-trust-state-schema
pcbex signed-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-schema
pcbex remote-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-receipt-schema
pcbex factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-trust-state-schema
pcbex signed-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-key-rotation-schema
pcbex factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-quorum-schema
```

Each schema has a matching `validate-...` command. Validators authenticate the
self-contained checkpoint, witness, or both rotation signatures and preserve
canonical bytes. The trust-state and quorum-report validators check structure
and invariants. The receipt validator checks its closed canonical shape; use the
request command to create a verified receipt and full quorum verification to
replay witness evidence.

## What a passing result proves

A passing accepted checkpoint proves that:

- the supplied history replays from exact empty genesis through the production
  verifier;
- the checkpoint binds that exact audit and computed final registry;
- the signer controls the root retained at the final generation;
- when a baseline is supplied, the new history contains its exact previously
  accepted generation and state;
- an applied rotation was authorized by the retained key and proves possession
  of the distinct successor key over one exact next-generation payload;
- a successfully acquired remote witness was canonical, fresh, signed by the
  selected direct or trust-state key, bound to the accepted checkpoint, and
  role-disjoint from every key found by replaying the complete local history;
- its receipt hashes the exact local history and checkpoint trust-state bytes,
  exact HTTP request and response bytes, normalized witness, key mode, endpoint,
  and evaluation time;
- an appended receipt event binds the canonical compact receipt digest and its
  checkpoint, request, response, and witness identities into the exact signed
  log head;
- a verifier-bound append additionally replayed the exact complete history,
  reconstructed retained checkpoint trust and request bytes, matched the exact
  response and current trust generation, and re-verified freshness, role
  separation, and the witness signature at admission time;
- a passing quorum report contains fresh signatures from enough distinct,
  currently trusted, role-disjoint witness keys over one exact checkpoint.

## What it does not prove

The contract does not prove:

- rollback resistance when the consumer loses or replaces its baseline;
- rollback resistance when a witness trust state is lost or replaced;
- global non-equivocation among consumers that never exchange checkpoints;
- trusted wall-clock time or secure private-key custody;
- that configured keys belong to independent people or legal organizations;
- that the HTTPS operator is the intended legal entity or is operationally
  independent from any other witness;
- that the optional structural append replayed the retained history,
  checkpoint trust, response bytes, or witness signature;
- that verifier-bound input revalidation formed an atomic same-principal
  filesystem snapshot or protected any retained input from rollback;
- that a locally generated receipt was externally signed or globally observed;
- factory identity, capacity, order placement, payment, or exactly-once
  execution.

Version 1.504 should add atomic verifier-bound receipt admission quorum. Every
v1.503 command except the explicit v1.501 remote-request command remains
network-free.
