# Exact assembly and acquired supplier-offer evidence composition

Version 1.470 adds one offline Python-only composition boundary over the full
retained v1.467 assembly-evidence result, v1.468 supplier-offer coverage
result, and v1.469 acquisition receipt. It captures the complete common
source union once, freshly validates both replay-bearing children from one
private staged snapshot, validates the receipt against the exact canonical
offer without making a network request, and hard-cross-binds the three
results.

This is evidence correlation, not a live quote, assembly-readiness decision,
or procurement authorization. In particular, the unsigned receipt cannot
prove its historical network, response, TLS, endpoint, or time observations.

## Commands and public API

Build and optionally gate one composed report with:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent \
  build-assembly-supplier-offer-evidence \
  circuit-handoff.zip board.kicad_pcb manufacturing.zip \
  --board-binding-report board-binding.json \
  --procurement-intent procurement-intent.json \
  --catalog-snapshot catalog-snapshot.json \
  --final-cpl-report final-cpl.json \
  --assembly-evidence assembly-evidence.json \
  --supplier-offer supplier-offer.json \
  --supplier-offer-fetch-receipt supplier-offer-fetch-receipt.json \
  --supplier-offer-coverage supplier-offer-coverage.json \
  --requested-boards 100 \
  --evaluated-at-unix "$FETCHED_AT_UNIX" \
  --pcbex target/release/pcbex \
  --manufacturing-kicad-cli kicad-cli \
  --timeout-seconds 300 \
  --output assembly-supplier-offer-evidence.json \
  --require-complete

PYTHONPATH=agent/src python3 -m pcbex_agent \
  assembly-supplier-offer-evidence-schema \
  --output assembly-supplier-offer-evidence.schema.json
```

The optional handoff/manufacturing inputs are unchanged from v1.467:
`--board-binding-policy`, `--manufacturing-kicad-project`,
`--manufacturing-kicad-rules`, and at most one of `--manufacturing-fab`,
`--manufacturing-fab-profile`, or `--manufacturing-physical-profile`.
Optional `--expected-handoff-archive-sha256` and
`--expected-handoff-bundle-sha256` values retain the existing external
handoff identity roots.

There is deliberately no independent circuit-generation path. The composer
extracts the exact `generation-bundle.json` entry from the captured and
validated handoff archive and supplies those bytes to the coverage replay.
There is also no endpoint, bearer-token, response-limit, or other network
option: this boundary is offline.

The public functions are `evaluate_assembly_supplier_offer_evidence` and its
artifact-oriented alias `build_assembly_supplier_offer_evidence`,
`validate_assembly_supplier_offer_evidence`,
`render_assembly_supplier_offer_evidence`, and
`assembly_supplier_offer_evidence_json_schema`. Hard failures use
`AssemblySupplierOfferEvidenceError`.

The evaluator's positional order is `handoff_bundle`, `board`,
`manufacturing_package`, `retained_board_binding_report`,
`retained_procurement_intent`, `catalog_snapshot`, `retained_final_cpl`,
`retained_assembly_evidence`, `supplier_offer`,
`retained_supplier_offer_fetch_receipt`,
`retained_supplier_offer_coverage`, then optional `pcbex`; the validator
prepends the retained outer `evidence`. `requested_boards` and
`evaluated_at_unix` are required keyword-only selectors. The remaining replay
policy, KiCad, manufacturing-sidecar, expected-handoff-digest, timeout, and
test-clock controls are keyword-only.

A retained path or bytes-like outer report must be canonical pretty UTF-8
JSON with exactly one final LF and match the fresh result byte-for-byte. A
Mapping is accepted only as a bounded one-pass semantic snapshot. The
standalone renderer validates the retained closed graph and canonical child
identities; the fresh validator remains authoritative for the original source
bytes and child executions.

The retained assembly, fetch-receipt, and coverage child parameters likewise
accept canonical path/bytes representations or bounded Mapping snapshots. The
handoff, board, package, board-binding report, procurement intent, historical
snapshot, final-CPL report, normalized offer, and optional replay sidecars are
path sources. CLI inputs are paths in every case.

Capture order is fixed. The complete inherited v1.467 path union is frozen and
captured first under its existing boundary. The raw offer PathLike is frozen
and its file read next. Each path-backed retained child is then classified,
frozen, and read immediately in positional order; the composer does not freeze
all child paths and defer their reads. The first alias check follows those
reads. Child bytes-like values are copied next, followed by child Mapping
snapshots. A retained outer validator artifact is intentionally classified and
captured wholly last regardless of representation. If that outer artifact is
path-backed, a second alias check rejects overlap with the already captured
direct union. Thus the path-before-child-Mapping rule deliberately excludes
the retained outer artifact. Caller hooks that change the working directory
are restored and rejected, and final rereads still detect observed mutation of
every path-backed source.

## One snapshot and fresh validation order

The evaluator starts one aggregate monotonic deadline, applies that capture
order, and validates the handoff archive and retained JSON shapes before a
caller-selected child can execute. It stages the whole captured source union
in one private workspace and performs these steps:

1. Validate the exact fetch receipt against the staged canonical offer. This
   is the existing offline v1.469 validator and performs no DNS, HTTP, TLS,
   clock, offer-window, or coverage operation.
2. Freshly run the complete public v1.467 assembly-evidence validator against
   the staged handoff, board, package, retained board-binding report,
   procurement intent, snapshot, final-CPL report, and assembly result.
3. Reread the complete staged union.
4. Freshly run the complete public v1.468 coverage validator against the same
   staged board, package, snapshot, procurement intent, and offer, plus the
   exact generation entry extracted from that handoff.
5. Reread the complete staged union, validate every child runtime contract,
   enforce all outer cross-bindings, and construct the result.
6. Take one bounded result snapshot, runtime-validate and render it, reread the
   complete staged union again, then reread every direct caller-visible source
   before success.

The independent assembly and coverage validations each replay the procurement
intent. One replay result is not reused as authority for the other. All child
execution remains direct and shell-free. A malformed child, noncanonical
retained result, replay mismatch, identity mismatch, deadline/cleanup failure,
or observed mutation is a hard failure with no outer report.

The finite outer timeout accepts 1 through 600 seconds and defaults to 300.
After bounded capture, receipt validation, archive parsing, and staging, the
assembly validator receives at most half of the remaining budget. After that
validator returns, the coverage validator receives the remaining budget minus
the smaller of 15 seconds or half of that remainder. This leaves a bounded
reserve for cross-binding, rendering, cleanup, and final union rereads. Both
children use the same injected monotonic clock and cannot extend the absolute
outer deadline.

## Exact cross-bindings

The composer requires more than three individually well-shaped reports. It
requires exact agreement for:

- the named board identity, including its portable basename;
- the manufacturing-package identity;
- the assembly result's handoff generation identity and the coverage result's
  generation identity;
- the historical catalog-snapshot identity;
- the exact raw retained procurement-intent identity;
- the complete compact procurement projections retained by v1.467 and
  v1.468, with strict JSON types and values;
- the exact canonical supplier-offer bytes and coverage source identity;
- the receipt's canonical-offer byte count and SHA-256, supplier, and exact
  procurement-intent digest;
- the receipt's recomputed credential-free request binding;
- the caller's requested-board selector and the coverage result; and
- the caller's evaluation timestamp, the coverage evaluation timestamp, and
  the receipt's recorded fetch timestamp.

Timestamp equality is only correlation between explicit and retained integer
fields. It does not make the platform clock trusted, prove when a request
occurred, or establish currentness. A supplier mismatch between the offer and
the historical procurement catalog remains a valid v1.468 `not_covered`
finding rather than becoming a hard outer failure; the receipt supplier is
bound to the offer supplier.

The response entity is not retained by v1.469. Consequently this offline
composer cannot recompute or authenticate the receipt's response byte count,
response digest, HTTP status, or historical network observation. It does not
invent a response-to-offer binding that the retained artifacts cannot prove.

The runtime contract also preserves the intentionally different network
states: v1.467 assembly and v1.468 coverage remain
`adapter_network_performed: false`, the nested acquisition receipt retains its
local `adapter_network_performed: true` observation, and this outer offline
composer itself remains false.

## Closed result and completion decision

The path-free result uses schema version 1 and scope
`offline-exact-board-assembly-supplier-offer-evidence-v1`. It retains the full
validated v1.467 assembly result, full v1.468 coverage result, and full v1.469
receipt rather than replacing them with hashes or new compact projections.
Its `sources` object contains exact identities for:

- `assembly_evidence`
- `board`
- `board_binding_report`
- `catalog_snapshot`
- `circuit_handoff_bundle`
- `final_cpl_report`
- `handoff_generation_bundle`
- `manufacturing_package`
- `procurement_intent`
- `supplier_offer`
- `supplier_offer_coverage`
- `supplier_offer_fetch_receipt`

Only `board` is a named identity. The other entries contain exact byte counts
and SHA-256 digests. The canonical nested assembly, coverage, receipt, and
offer bytes must reproduce their corresponding outer identities.

The exact outer validation flags are all true:

- `assembly_evidence_replayed`
- `supplier_offer_coverage_replayed`
- `supplier_offer_fetch_receipt_validated`
- `board_identity_cross_bound`
- `manufacturing_package_identity_cross_bound`
- `handoff_generation_identity_cross_bound`
- `catalog_snapshot_identity_cross_bound`
- `procurement_intent_identity_cross_bound`
- `procurement_projection_cross_bound`
- `supplier_offer_identity_cross_bound`
- `receipt_request_binding_validated`
- `evaluation_timestamp_cross_bound`
- `network_semantics_preserved`
- `caller_inputs_unchanged`

The outer status is `complete` exactly when both decision-bearing children are
positive:

```text
assembly_evidence.complete && supplier_offer_coverage.covered
```

A valid incomplete assembly result contributes
`assembly_evidence_incomplete` with message `the freshly replayed assembly
evidence is incomplete`; a valid uncovered offer contributes
`supplier_offer_not_covered` with message `the freshly replayed supplier-offer
coverage is not covered`. The applicable findings are uniquely and
lexicographically sorted. A valid receipt is mandatory and has no retained
negative form: acquisition failures publish no valid receipt and malformed or
misbound receipts are hard failures.

`--require-complete` is only a final gate. A canonical valid incomplete report
is atomically published to its new destination before the command exits
unsuccessfully. The output is limited to 128 MiB and receives a
domain-separated `binding_sha256` over every other material field.

The outer `adapter_network_performed`, `current_availability_verified`,
`supplier_authenticity_verified`, `offer_authenticity_verified`,
`price_authenticity_verified`, `trusted_time_verified`, `inventory_reserved`,
`assembly_ready`, `assembly_authorized`, `fabrication_authorized`,
`procurement_authorized`, `order_ready`, `order_placed`,
`payment_performed`, and `machine_operation_performed` fields are all constant
false. In particular, a positive composition does not authorize the component
subtotal retained by a covered child.

## Bounds, paths, and schema authority

All child ceilings remain unchanged: 224 MiB for the handoff archive; 128 MiB
each for the board and manufacturing package; 12 MiB plus one LF for the
board-binding report; 16 MiB each for procurement intent, final-CPL report,
and supplier-offer coverage; 4 MiB each for the historical snapshot and
normalized offer; 32 MiB for retained assembly evidence and the extracted
generation entry; and 1 MiB for the receipt. Existing optional
board/manufacturing sidecar ceilings remain in force.

The direct captured composition union is capped at 789 MiB: the complete
768 MiB v1.467 validation union plus the 4 MiB offer, 16 MiB coverage report,
and 1 MiB receipt. Fresh validation of a retained outer report additionally
admits that report under its 128 MiB ceiling, for a 917 MiB aggregate. The
derived generation entry is bounded separately and is not counted as a second
caller source.

The existing 256-argument, 32,768-UTF-8-byte argv, 1 MiB per-child-stream, and
Windows 32,767-UTF-16-unit command ceilings remain authoritative. The composer
adds no new process type.

Every path-backed source must be a distinct, nonempty stable regular file
accepted by the shared link/reparse-aware reader. Direct and lexical-ancestor
symbolic links, Windows reparse components, special files, path aliases, and a
CLI output that aliases any path input are rejected. Bytes-like inputs are
copied within their role ceiling; Mapping inputs are bounded canonical
snapshots and do not supply filesystem identity. Publication is one atomic
no-clobber write. Private staging and final rereads detect observed path
changes but are not an atomic multi-input snapshot against a same-principal
change-and-restore race.

The emitted Draft 2020-12 schema is closed and structurally embeds the three
existing child contracts without changing them. Runtime validation remains
authoritative for exact UTF-8 byte limits, strict scalar types, canonical
bytes, identities, checked selectors, cross-field equivalence, finding/status
invariants, aggregate limits, and the binding digest. Passing the schema or
standalone renderer cannot authenticate omitted raw sources, rerun child
tools, or authenticate the receipt's historical network observations.

## Deliberate nonclaims

This boundary performs no supplier fetch or other intended network operation.
It does not prove that the retained GET occurred or authenticate a DNS answer,
socket peer, TLS session, certificate, endpoint, supplier, offer, price,
response, or time. Timestamp equality and an offer's declared window establish
neither current inventory nor trusted time.

It does not prove stock, lifecycle, lead time, reservation, MOQ, tiers, order
multiples, unit-price or rounding truth, shipping, tax, duty, fees, discounts,
exchange rates, landed cost, invoice totals, or spend authority. It performs
no substitution, optimization, reservation, cart operation, order, or payment.

The requested-board count scales only the coverage child's commercial
quantities. It does not multiply or approve boards, panels, packages,
placements, batch yield, attrition, losses, or spares. It does not establish
BOM/CPL subset completeness, polarity, fiducials, panelization, vendor
coordinate transforms, feeder/nozzle selection, machine programming, assembly
readiness, or machine operation. It grants no assembly, fabrication,
manufacturing, or procurement authorization and adds no firmware evidence.

The caller-selected pcbex and KiCad commands remain unauthenticated and
unsandboxed. Shell-free argv, byte/time limits, private staging, and process
cleanup are not CPU, memory, filesystem, network, syscall, credential, or
privilege isolation. Their independent I/O is outside the outer adapter's
no-network claim. Use protected immutable inputs and an independent OS sandbox
when those properties matter.

The v1.467, v1.468, and v1.469 schemas and canonical serialized-byte contracts
remain unchanged.
