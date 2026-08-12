# Dual-control exact procurement release authorization

Version 1.471 adds a separate offline authorization boundary over one exact
retained v1.470 assembly and acquired supplier-offer composition. It requires
at least two distinct, role-disjoint Ed25519 signers to approve the same
bounded commercial scope. Only the public Python verifier constructs an
evaluated procurement-authorization report; the standalone renderer merely
checks and serializes an already supplied structural snapshot.

This boundary authorizes release of the exact covered component lines to a
separately controlled procurement handoff. It does not place an order, reserve
stock, pay a supplier, authorize fabrication or assembly, or turn an unsigned
receipt observation into an authenticated or current supplier statement.

## Commands and original evidence closure

Generate two dedicated approval keys with the existing Rust command and keep
the private keys outside the repository:

```sh
pcbex approval-keygen \
  --private-key .secrets/procurement-a.key \
  --public-key procurement-a.pub
pcbex approval-keygen \
  --private-key .secrets/procurement-b.key \
  --public-key procurement-b.pub
```

The public keys are 32-byte Ed25519 keys encoded as 64 lowercase hexadecimal
digits. The trusted helper accepts the private-key file only as one 32-byte
seed encoded by exactly 64 lowercase hexadecimal digits, with one trailing LF
permitted. On Unix the file must be owned by the effective UID and have exact
mode `0400` or `0600`; `approval-keygen` creates the compatible `0600` mode.
Procurement signer identifiers and public keys must be unique and
must not also hold an AI-review, human-escalation, or fabrication-authorization
role in the same organization policy pack.

Each signer receives the retained v1.470 result and every member of its exact
original closure. A representative approval command is:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent sign-procurement-approval \
  assembly-supplier-offer-evidence.json \
  circuit-handoff.zip board.kicad_pcb manufacturing.zip \
  --board-binding-report board-binding.json \
  --procurement-intent procurement-intent.json \
  --catalog-snapshot catalog-snapshot.json \
  --final-cpl-report final-cpl.json \
  --assembly-evidence assembly-evidence.json \
  --supplier-offer supplier-offer.json \
  --supplier-offer-fetch-receipt supplier-offer-fetch-receipt.json \
  --supplier-offer-coverage supplier-offer-coverage.json \
  --policy-pack organization-policy-pack.json \
  --expected-policy-pack-canonical-sha256 \
    "$EXPECTED_POLICY_PACK_CANONICAL_SHA256" \
  --requested-boards 100 \
  --evaluated-at-unix "$FETCHED_AT_UNIX" \
  --authorization-id release-2026-08-12-a \
  --challenge "$PROCUREMENT_CHALLENGE" \
  --maximum-component-subtotal-micros 2500000000 \
  --valid-from-unix "$VALID_FROM_UNIX" \
  --expires-at-unix "$EXPIRES_AT_UNIX" \
  --signer-id procurement-a \
  --decision approve \
  --reason 'Approved these exact covered component lines.' \
  --ticket HW-1471 \
  --private-key .secrets/procurement-a.key \
  --pcbex target/release/pcbex \
  --authorization-pcbex /opt/pcbex-trusted/bin/pcbex \
  --manufacturing-kicad-cli kicad-cli \
  --timeout-seconds 300 \
  --output procurement-a.approval.json
```

The second signer supplies the same evidence, policy digest pin, selectors,
authorization ID, challenge, commercial ceiling, and approval window, changing
only signer-specific fields and the private key. Reason and ticket must contain
non-whitespace text after trimming, reject NUL, and are bounded at 4,096 and
256 UTF-8 bytes respectively; their original signed text is retained. Verify
the submitted set with:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent \
  verify-procurement-authorization \
  assembly-supplier-offer-evidence.json \
  circuit-handoff.zip board.kicad_pcb manufacturing.zip \
  --board-binding-report board-binding.json \
  --procurement-intent procurement-intent.json \
  --catalog-snapshot catalog-snapshot.json \
  --final-cpl-report final-cpl.json \
  --assembly-evidence assembly-evidence.json \
  --supplier-offer supplier-offer.json \
  --supplier-offer-fetch-receipt supplier-offer-fetch-receipt.json \
  --supplier-offer-coverage supplier-offer-coverage.json \
  --policy-pack organization-policy-pack.json \
  --expected-policy-pack-canonical-sha256 \
    "$EXPECTED_POLICY_PACK_CANONICAL_SHA256" \
  --requested-boards 100 \
  --evaluated-at-unix "$FETCHED_AT_UNIX" \
  --approval procurement-a.approval.json \
  --approval procurement-b.approval.json \
  --pcbex target/release/pcbex \
  --authorization-pcbex /opt/pcbex-trusted/bin/pcbex \
  --manufacturing-kicad-cli kicad-cli \
  --timeout-seconds 300 \
  --output procurement-authorization.json \
  --require-authorized
```

The v1.470 replay options remain available: `--board-binding-policy`,
`--manufacturing-kicad-project`, `--manufacturing-kicad-rules`, at most one
of `--manufacturing-fab`, `--manufacturing-fab-profile`, or
`--manufacturing-physical-profile`, and the optional expected handoff archive
and logical-bundle SHA-256 roots. The authorization command accepts no
endpoint, bearer token, cart, order, payment, shipping, or tax option and
performs no intended network request.

The required `evaluated_at_unix` argument is the retained v1.470 replay
selector and must reproduce that original evidence; it does not let the caller
choose the authorization assessment instant. Public verification samples its
separate local assessment time internally.

Emit the two closed structural schemas with:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent \
  signed-procurement-approval-schema \
  --output signed-procurement-approval.schema.json
PYTHONPATH=agent/src python3 -m pcbex_agent \
  procurement-authorization-report-schema \
  --output procurement-authorization-report.schema.json
```

The public functions are `sign_procurement_approval`,
`evaluate_procurement_release_authorization` and its aliases
`build_procurement_release_authorization` and
`verify_procurement_authorization`,
`validate_procurement_release_authorization`,
`render_signed_procurement_approval`,
`render_procurement_authorization_report`,
`signed_procurement_approval_json_schema`, and
`procurement_authorization_report_json_schema`.

The exact signing parameter order and defaults are:

```python
sign_procurement_approval(
    evidence, handoff_bundle, board, manufacturing_package,
    retained_board_binding_report, retained_procurement_intent,
    catalog_snapshot, retained_final_cpl, retained_assembly_evidence,
    supplier_offer, retained_supplier_offer_fetch_receipt,
    retained_supplier_offer_coverage, policy_pack, private_key,
    pcbex="pcbex", authorization_pcbex="pcbex", *,
    requested_boards, evaluated_at_unix,
    expected_policy_pack_canonical_sha256,
    signer_id, decision, authorization_id, challenge,
    maximum_component_subtotal_micros, valid_from_unix, expires_at_unix,
    reason, ticket,
    board_binding_policy=None, kicad_cli="kicad-cli",
    manufacturing_kicad_project=None, manufacturing_kicad_rules=None,
    manufacturing_fab=None, manufacturing_fab_profile=None,
    manufacturing_physical_profile=None,
    expected_archive_sha256=None, expected_bundle_sha256=None,
    timeout_seconds=300.0, _clock=time.monotonic,
)
```

`evaluate_procurement_release_authorization`,
`build_procurement_release_authorization`, and
`verify_procurement_authorization` are aliases of the same function with this
exact signature:

```python
evaluate_procurement_release_authorization(
    evidence, handoff_bundle, board, manufacturing_package,
    retained_board_binding_report, retained_procurement_intent,
    catalog_snapshot, retained_final_cpl, retained_assembly_evidence,
    supplier_offer, retained_supplier_offer_fetch_receipt,
    retained_supplier_offer_coverage, policy_pack, approvals,
    pcbex="pcbex", authorization_pcbex="pcbex", *,
    requested_boards, evaluated_at_unix,
    expected_policy_pack_canonical_sha256,
    board_binding_policy=None, kicad_cli="kicad-cli",
    manufacturing_kicad_project=None, manufacturing_kicad_rules=None,
    manufacturing_fab=None, manufacturing_fab_profile=None,
    manufacturing_physical_profile=None,
    expected_archive_sha256=None, expected_bundle_sha256=None,
    timeout_seconds=300.0, _clock=time.monotonic,
    _wall_clock=time.time,
)
```

Fresh historical validation prepends the retained report and otherwise keeps
the verification order:

```python
validate_procurement_release_authorization(
    retained_authorization,
    evidence, handoff_bundle, board, manufacturing_package,
    retained_board_binding_report, retained_procurement_intent,
    catalog_snapshot, retained_final_cpl, retained_assembly_evidence,
    supplier_offer, retained_supplier_offer_fetch_receipt,
    retained_supplier_offer_coverage, policy_pack, approvals,
    pcbex="pcbex", authorization_pcbex="pcbex", *,
    requested_boards, evaluated_at_unix,
    expected_policy_pack_canonical_sha256,
    board_binding_policy=None, kicad_cli="kicad-cli",
    manufacturing_kicad_project=None, manufacturing_kicad_rules=None,
    manufacturing_fab=None, manufacturing_fab_profile=None,
    manufacturing_physical_profile=None,
    expected_archive_sha256=None, expected_bundle_sha256=None,
    timeout_seconds=300.0, _clock=time.monotonic,
)
```

The underscore-prefixed clocks are deterministic test hooks, not CLI options.
The retained validator uses the report's exact historical assessment time T
and therefore has no `_wall_clock` parameter. It validates that audit snapshot;
it does not renew authority. Call the evaluate/verify function to sample a new
assessment time for a release handoff.

## Dedicated organization policy

The existing schema-v1 `OrganizationPolicyPack` gains one optional closed
field:

```json
{
  "procurement_authorization_policy": {
    "minimum_approvals": 2,
    "currency": "USD",
    "maximum_validity_seconds": 3600,
    "maximum_receipt_observation_age_seconds": 900,
    "maximum_component_subtotal_micros": 2500000000,
    "trusted_keys": [
      {"signer_id": "procurement-a", "public_key": "<64 lowercase hex>"},
      {"signer_id": "procurement-b", "public_key": "<64 lowercase hex>"}
    ]
  }
}
```

The policy accepts 2–100 trusted keys and a quorum of 2–100 that cannot exceed
the key count.
Signer identifiers and keys are duplicate-free and disjoint from every other
approval role in the pack. `currency` is exactly three uppercase ASCII
letters. Validity and receipt-observation-age limits are each 1–604,800
seconds. The component-subtotal ceiling is an integer from 1 through
9,007,199,254,740,991 micros. Every procurement-role public key must decode as
a non-weak Ed25519 verification key. A pack that omits this optional field
remains valid for its earlier purposes but cannot authorize procurement
release.

Every signing and verification operation requires
`--expected-policy-pack-canonical-sha256`. The supplied 64-lowercase-hex digest
must equal the canonical digest of the strictly validated pack. This external
pin prevents the evidence or command from silently selecting a different
unsigned trust root. It does not prove who selected or distributed the pack or
pin. A deployment that needs policy authenticity must obtain and authenticate
the expected digest independently, for example through its separately trusted
signed-policy-pack governance, rather than accepting a digest chosen alongside
an untrusted pack. Every public report therefore keeps policy authenticity
false even when the pin matches.

That digest is SHA-256 of the compact JSON encoding of the validated Rust
policy struct in its declared field order. It is not the hash of the input
file, normalized pretty JSON, or a generic `sort_keys` encoding. One supported
workflow is to run `sign-policy-pack`, authenticate and extract it with
`verify-policy-pack`, and take the signed envelope's `policy_pack_sha256` as
the independently distributed pin while supplying the verified extracted pack
to this boundary.

The report retains the policy's raw source identity, canonical digest, ID, and
revision. Raw-byte equality and canonical semantic equality are distinct: a
caller cannot substitute a differently encoded pack while preserving only its
normalized fields.

## Exact signed scope

The domain-separated approval uses scope
`offline-exact-procurement-release-approval-v1`. It binds:

- the exact raw retained v1.470 report identity and its outer binding;
- the freshly reconstructed complete and covered commercial projection;
- supplier and offer identities, currency, and declared offer window;
- exact requested boards, component-lines-only subtotal in micros, and receipt
  `fetched_at_unix` observation;
- policy raw identity, canonical digest, ID, and revision;
- an authorization ID of 1–128 bytes matching the lowercase policy slug
  syntax, and a 64-lowercase-hex, 32-byte challenge;
- the signed currency, component-subtotal ceiling, inclusive approval window,
  decision, signer ID, reason, and ticket.

The Ed25519 preimage is compact UTF-8 JSON with this exact typed field order:
`domain`, `schema_version`, `scope`, `evidence`, `authorization_scope`,
`decision`, `reason`, `ticket`, `signer_id`, `algorithm`, and `public_key`.
`domain` is exactly `pcbex-procurement-approval-v1` with no trailing NUL;
`schema_version` is `1`, `scope` is the approval scope above, and `algorithm`
is `ed25519`. The final field is the lowercase public key derived from the
private seed and required to equal the signer ID's dedicated policy key. Thus
the version, scope, algorithm, and selected verification key are signed
context rather than mutable envelope metadata.

The frozen cross-language Rust fixture has request binding
`0a6be51dad43100e0de1721241745f5b5f8cb45549325fe5fc96627c3a9b7012`,
public key
`17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce`,
and hardened approval signature
`8b918860afd8420978f01a3703f40d69572caadfc6b80b5be76fe9d48a48157fc42dc0d6f6e424428e50999a8bd768a86ac2b1a5ede1ba8b44405519ea24f707`.
These bytes pin the exact field ordering and domain convention above; any
future schema, algorithm, or preimage change requires a new protocol domain.

The requested-board count and currency must equal the freshly replayed v1.470
commercial evidence and the policy currency. The signed monetary ceiling
covers only the retained sum of component-line `line_subtotal_micros` values.
It is neither a unit-price calculation nor a landed, invoice, shipping, tax,
duty, fee, tier, MOQ, discount, exchange-rate, or payment ceiling.

The signed approval window is inclusive: the local evaluation instant must be
within `[valid_from_unix, expires_at_unix]`. That whole interval must lie
inside the offer's declared half-open interval, so its start cannot precede
the offer start and `expires_at_unix` must be strictly less than the offer's
`valid_until_unix`. The approval duration cannot exceed the policy limit.
These local integer comparisons do not make the platform clock, receipt
observation, or offer window authentic.

## Two-child trust architecture

The public boundary deliberately uses two different executable roles:

- `--pcbex` is the existing v1.470 replay child. It remains a caller-selected,
  unauthenticated, unsandboxed executable and cannot make an authorization
  decision.
- `--authorization-pcbex` is a separate trusted computing-base component used
  only for strict request/policy validation and Ed25519 signing or assessment.
  A deployment must authenticate and isolate this executable as appropriate.

Python captures the retained v1.470 result and its complete original closure,
then freshly validates that exact result through the full public v1.470
validator. It constructs a closed, path-free cryptographic request only from
the resulting exact identities and commercial projection. The trusted Rust
child strictly validates the complete request, policy, mandatory digest pin,
output boundary, signer role, and all other public material before signing is
allowed to read the private-key file. Python never opens, reads, parses, or
copies private-key bytes.

After the trusted child returns, Python validates its bounded artifact and
freshly validates the same retained v1.470 result against the entire original
closure a second time. It requires the two replay results and the signed or
assessed request binding to agree exactly, rereads the staged and caller-visible
unions, and only then publishes the public artifact. Thus the trusted child is
not permitted to replace fresh Python replay, and the replay child is not
permitted to perform cryptographic authorization.

For verification, after the first replay Python privately stages and verifies
the exact request, policy, and approval bytes, then rereads the caller-source
union and samples local wall-clock `evaluated_at_unix = T`. A bounded
post-hook path-stability reread follows before Python constructs and runs the
trusted verifier command. The helper validates and records T and decides
whether policy was satisfied at that instant.
Retained-report validation instead reuses its historical T and does not
resample the wall clock. The mandatory second v1.470 replay is an
unchanged-evidence guard, not a second Rust assessment or a claim that the
signed window remains active when publication finishes. Consequently
`procurement_authorized: true` means the exact release satisfied the submitted
approval policy at retained assessment time T only.

The hidden Rust verification helper emits only the internal
`offline-exact-procurement-release-cryptographic-assessment-v1` policy and
signature assessment. It never emits a public authorization or v1.470 replay
claim. Direct invocation of either hidden Rust helper is internal and
non-authoritative without the surrounding Python pre/post replay and final
source checks. Python alone constructs the public
`offline-exact-procurement-release-authorization-v1` report.

The authorization child necessarily can read the named private key while
signing. The process boundary therefore does not claim private-key isolation,
hardware-backed key custody, signer-presence proof, binary provenance, or
protection from a compromised authorization TCB. Shell-free argv, staging,
deadlines, stream limits, and process-tree cleanup are not a CPU, memory,
filesystem, network, syscall, credential, or privilege sandbox.

For the public API, Python does not convert, freeze, or stat an arbitrary
private-key `PathLike` until the first complete fresh replay has succeeded and
an `approve` decision has passed the complete-and-covered pre-key gate. It then
freezes the key pathname once and rejects aliases with every data path and
normalized replay/KiCad/authorization command path candidates before starting
the trusted signing child; it still never reads the key contents. Candidates
are a direct whole-token path, the path after `@`, the suffix after the first
`=`, or a compact option's substring beginning at its first path separator
(for example `@file`, `--name=/path`, and `-I/path`). The CLI can do an earlier
lexical no-clobber preflight only for its output against built-in path inputs
(including the private-key path) and whole command tokens already recognized
as paths. It does not compare the private key with source paths or the
`@`/`=`/compact command candidates at that stage; the later API check above
does so after replay, the approve gate, and key-path freeze. Encoded paths,
environment, configuration, and other indirect access are not resolved by
this best-effort syntax check. A caller-selected
unsandboxed replay executable or KiCad process may access any filesystem path
including a known key path, so deployment isolation remains necessary. Alias
rejection prevents accidental forwarding and path-role overlap only; it is
not a key-secrecy boundary.

The Rust helper pins and revalidates the no-clobber parent of its private
staged output. Installation is descriptor-relative on Unix and uses a guarded
path on non-Unix platforms. Those guards are sequential, not an atomic
filesystem snapshot: a hostile same-principal rename after the final guard can
produce a committed-but-uncertain helper artifact in a moved or replacement
private staging directory. Python treats that child error as hard and
publishes no public approval or authorization report. The residual private
artifact may survive, so neither complete temporary cleanup nor rollback is a
claim. This internal staging behavior is distinct from the later atomic
no-clobber publication of a successfully validated public artifact.

## Decisions and failure classes

A public report sets `procurement_authorized: true` at its retained assessment
time only when the exact v1.470
result freshly replays as complete, its supplier-offer coverage is covered,
the submitted approvals share the exact evidence and scope, all signatures
and trusted roles are valid, the distinct approval quorum is met, no valid
submitted rejection is present, and every signed, policy, offer-window,
receipt-observation-age, currency, quantity, and component-subtotal gate passes
at the locally sampled evaluation time.

The following are valid `not_authorized` outcomes and remain inspectable in a
closed report:

- incomplete v1.470 composition or uncovered supplier-offer evidence;
- insufficient distinct approvals or a valid submitted rejection;
- local evaluation time outside the inclusive approval window or declared
  offer interval;
- a receipt observation in the local clock's future or older than
  `maximum_receipt_observation_age_seconds`;
- the component subtotal exceeding the signed or policy ceiling;
- a signed ceiling above the policy maximum; or
- a signed validity duration above the policy maximum.

The local receipt-age calculation is untrusted correlation. It is deliberately
called a receipt-observation-age gate and is not trusted-time verification.
Only rejections actually included in the submitted approval set veto that run;
withheld decisions and later revocation require an external trusted workflow.
The quorum proves distinct trusted signer identifiers and public keys only. It
does not detect or prevent one natural person or operator from controlling
multiple private keys; deployments that require distinct people need a
separate identity, custody, and ceremony control.

Malformed or duplicate-key JSON, mixed evidence or scopes, a missing or wrong
policy digest pin, an untrusted/duplicate/aliased signer or key, an invalid
signature, unsafe/aliased/oversized inputs or output, child or cleanup failure,
or observed source mutation is a hard failure with no public artifact. Approval
of incomplete or uncovered evidence is refused before private-key access; a
trusted signer may instead sign a rejection that remains valid negative
evidence. `--require-authorized` is only a final gate: it returns nonzero after
a valid `not_authorized` report has been atomically retained.

## Public artifacts

A signed approval has the exact ordered fields `schema_version`, `scope`,
`evidence`, `authorization_scope`, `decision`, `reason`, `ticket`, `signer_id`,
`algorithm`, `public_key`, and `signature`. The evidence object contains the
v1.470 raw identity and binding, the complete commercial projection, and the
raw/canonical policy projection described above. It does not contain a path or
private key. The renderer validates that closed shape and emits fixed-order
pretty UTF-8 JSON with one final LF; rendering alone does not verify a
signature.

The public report starts with `schema_version`, `scope`, `status`, and
`procurement_authorized`, followed by these exact constant-false fields in
order: `adapter_network_performed`, `current_availability_verified`,
`supplier_authenticity_verified`, `offer_authenticity_verified`,
`price_authenticity_verified`, `receipt_observation_authenticity_verified`,
`policy_pack_authenticity_verified`, `trusted_time_verified`,
`inventory_reserved`, `assembly_ready`, `assembly_authorized`,
`fabrication_authorized`, `order_ready`, `order_placed`, `payment_performed`,
`machine_operation_performed`, and `challenge_one_time_use_enforced`.

It then retains `evidence`, `authorization_scope`, the complete validated
`policy_pack`, assessment `evaluated_at_unix`, approval and rejection counts,
signer-sorted `members` and `signed_approvals`, lexically sorted
`gate_failures`, `validation`, and `binding_sha256`. Every successful report
construction sets these closed validation fields true:
`assembly_supplier_offer_evidence_replayed`, `evidence_complete_checked`,
`request_binding_validated`, `commercial_scope_cross_bound`,
`policy_pack_validated`, `approval_signatures_verified`,
`distinct_signers_verified`, and `caller_inputs_unchanged`. A true
`evidence_complete_checked` records that the gate was evaluated; a valid
negative may still retain `complete: false` or `covered: false`.

The final binding is SHA-256 over the ASCII domain
`pcbex:offline-exact-procurement-release-authorization-v1` followed by NUL and
the compact, fixed-order UTF-8 JSON encoding of every preceding report field.
Reports use the same fixed-order pretty JSON plus one final LF as approvals.
The standalone report renderer checks this self-contained structural binding
but does not replay evidence, authenticate policy, or verify signatures.

## Bounds and publication

All v1.470 role ceilings remain unchanged. Fresh validation accepts its full
789 MiB caller source union plus the retained v1.470 report under the existing
917 MiB aggregate. The policy pack is at most 64 MiB. Verification accepts one
to 100 approvals, each at most 1 MiB and together at most 32 MiB, for a
1,013 MiB direct aggregate ceiling. The derived private request is capped at
1 MiB and is not counted again as a caller source. The final closed report is
at most 128 MiB. Fresh validation of a retained authorization prepends that
outer report to the same direct verification union and is therefore capped at
1,141 MiB. Signing has no approval aggregate and consequently accepts a
strictly smaller union; 1,013 MiB is the common direct sign/verify ceiling,
not permission for signing to add absent approval inputs.

One byte/count/aggregate-bounded immutable caller-source baseline is captured
before the first injected monotonic-clock observation. Its trust order is the
original and optional v1.470 paths, raw offer, retained v1.470 path/bytes/
Mapping values, v1.471 evidence and policy path/bytes/Mapping values, retained
authorization outer value when validating, then the approval iterator and its
items. The retained outer deliberately precedes approvals so their iterator
cannot mutate it. Earlier mutable buffers and one-pass Mappings cannot change
the captured bytes; later observed path mutation is rejected.

This initial phase cannot preemptively time-bound arbitrary in-process
PathLike, iterator, or Mapping hooks. After that baseline, one finite 1–600
second monotonic deadline, defaulting to 300 seconds, covers subsequent
normalization and strict preparse, both complete v1.470 validations, private
staging, the trusted Rust child, artifact validation, cleanup, rendering, and
final staged and caller-visible rereads. Injected monotonic observations must
not move backwards. The existing 256-argument, 32,768-byte argv, 1 MiB
child-stream, and Windows 32,767-UTF-16-unit rendered-command ceilings remain
in force.

Every CLI artifact input must satisfy its distinct stable regular
link/reparse-safe path contract; the two executable roles may intentionally
name the same trusted release binary in a controlled test, though deployments
normally separate their trust. Public API path-backed inputs use the same
boundary; any supported copied bytes or bounded mapping snapshot has no
filesystem identity and remains subject to its role's runtime byte and
semantic limits. Publication is one atomic no-clobber write. The two fresh
replays and final rereads are sequential observations, not an atomic multi-file
snapshot against a hostile same-principal writer that changes and restores
bytes between checks.

The schemas are structural. Runtime validation remains authoritative for UTF-8
byte and aggregate bounds, strict JSON scalar types, canonical bytes, source
identities, the policy digest pin, role disjointness, signatures, exact scope,
non-weak Ed25519 keys, cross-bindings, arithmetic, time-window relationships,
decision equivalences, and final binding.

## Authority and nonclaims

Only the outer public `procurement_authorized` field may be true. Network
performance, current availability, supplier authenticity, offer authenticity,
price authenticity, receipt-observation authenticity, policy authenticity,
trusted time, inventory reservation, assembly readiness or authorization,
fabrication authorization, order readiness or placement, payment, machine
operation, and challenge one-time-use enforcement remain false.

Consequently a positive report does not prove current stock, supplier or offer
origin, price truth, MOQ, tiers, landed cost, invoice total, shipping, tax,
reservation, order acceptance, payment, spend, assembly, fabrication, or a
machine action. It authorizes no file beyond the exact raw identities and
signed component-line scope.

The retained report is a point-in-time audit snapshot, not reusable current
authority or an outer-signed trusted timestamp. A release consumer must rerun
`verify-procurement-authorization` from the original v1.470 closure, policy,
pin, and submitted approvals at its actual handoff boundary. Parsing, editing,
schema-validating, or replaying the retained report alone cannot confer
authority.
