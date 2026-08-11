# Exact offline supplier-offer coverage

Version 1.468 adds a Python-only offline reconciliation boundary between one
exact procurement intent and one caller-normalized local supplier offer. It
freshly replays the complete v1.464 procurement intent from its board,
manufacturing package, generation bundle, and historical catalog snapshot
before it compares any commercial line. The adapter makes no supplier network
call and never treats the offer as authentic, current, reserved, authorized,
or ready to order.

## Commands and public API

Build and optionally gate one coverage report with:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent build-supplier-offer-coverage \
  board.kicad_pcb manufacturing.zip \
  --circuit-generation generation-bundle.json \
  --catalog-snapshot catalog-snapshot.json \
  --procurement-intent procurement-intent.json \
  --supplier-offer supplier-offer.json \
  --requested-boards 100 \
  --evaluated-at-unix 1785715200 \
  --pcbex target/release/pcbex \
  --timeout-seconds 120 \
  --output supplier-offer-coverage.json \
  --require-covered

PYTHONPATH=agent/src python3 -m pcbex_agent supplier-offer-schema \
  --output supplier-offer-v1.schema.json
PYTHONPATH=agent/src python3 -m pcbex_agent supplier-offer-coverage-schema \
  --output supplier-offer-coverage-v1.schema.json
```

The public functions are `evaluate_supplier_offer_coverage` and its
artifact-oriented alias `build_supplier_offer_coverage`,
`validate_supplier_offer_coverage`, `render_supplier_offer_coverage`,
`normalized_supplier_offer_json_schema`, and
`supplier_offer_coverage_json_schema`.

The output path is preflighted before any replay. Publication is atomic and
no-clobber. A valid `not_covered` result is published before
`--require-covered` exits unsuccessfully. Malformed, misbound, unsafe,
aliased, oversized, unreplayable, or observably mutated input produces no
report.

## Normalized offer input

The closed `offline-normalized-supplier-offer-v1` object has this shape:

```json
{
  "schema_version": 1,
  "scope": "offline-normalized-supplier-offer-v1",
  "procurement_intent_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "supplier": "example-supplier",
  "offer_id": "quote-123",
  "valid_from_unix": 1785715200,
  "valid_until_unix": 1785801600,
  "currency": "USD",
  "lines": [
    {
      "mpn": "RC0603FR-071KL",
      "supplier_part_number": "C12345",
      "catalog_part_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "quoted_quantity": 1000,
      "line_subtotal_micros": 1250000
    }
  ]
}
```

`procurement_intent_sha256` identifies the exact retained intent bytes, not
only their parsed JSON meaning. A mismatch is a hard source-binding error
before pcbex is started. The lines are strictly sorted and unique by the exact,
case-sensitive supplier part number. Each line carries the intent-facing MPN,
supplier part number, and historical catalog-part digest. The input may contain
at most 256 lines.

`currency` is exactly three uppercase ASCII letters. That is a syntax rule,
not proof that the code is registered or that any exchange rate is correct.
`line_subtotal_micros` is a nonnegative integer in a fixed scale of one
million units per named major currency unit. It is the subtotal for the exact
positive quoted quantity. Version 1 does not interpret a unit price, decimal
rounding, price break, MOQ, order multiple, discount, shipping, tax, duty, or
fee.

The declared validity interval is half-open:
`valid_from_unix <= evaluated_at_unix < valid_until_unix`. The evaluation
instant is an explicit caller input and is not a trusted clock observation.

## Replay and coverage decision

The evaluator captures six distinct stable regular non-link sources: the
board, manufacturing ZIP, generation bundle, historical catalog snapshot,
retained procurement intent, and normalized offer. It parses and binds the two
retained JSON inputs, recreates the exact replay inputs in private storage, and
calls the public `validate_procurement_intent` boundary. That child validation
regenerates the final BOM through the caller-selected pcbex command and fully
replays the historical catalog selection. The staged closure and every
caller-visible source are reread before success.

A covered result requires all of the following:

- the freshly replayed procurement intent is approved;
- the intent's supplier equals the normalized offer's supplier;
- the exact supplier-part-number sets agree;
- each common line has the same MPN and historical catalog-part digest;
- for each line, `required_quantity` equals the checked product of the
  intent's per-board quantity and `requested_boards`;
- every quoted quantity is at least its required quantity; and
- the explicit evaluation instant is inside the declared half-open window.

Larger quoted quantities are accepted and retained as `surplus_quantity`.
No spare, yield, loss, panel, or attrition multiplier is inferred.

The only stable finding codes are lexicographically sorted:

| Code | Meaning |
|---|---|
| `offer_line_identity_mismatch` | A common supplier part number has a different MPN or historical catalog-part digest. |
| `offer_line_set_mismatch` | The exact supplier-part-number sets differ. |
| `offer_outside_declared_window` | The explicit evaluation instant is outside the offer's half-open window. |
| `procurement_intent_rejected` | The exact freshly replayed procurement intent is technically rejected. |
| `quoted_quantity_shortfall` | At least one quoted quantity is less than the checked required quantity. |
| `supplier_mismatch` | The offer supplier differs from the replayed intent supplier. |

These are valid `not_covered` outcomes. They do not expose a partial cart or
order line set.

## Closed result

The result scope is `offline-procurement-supplier-offer-coverage-v1`. It
retains `status` (`covered` or `not_covered`) and the matching Boolean
`covered`, `requested_boards`, `evaluated_at_unix`, constant
`quantity_basis: "explicit_board_quantity"`, and constant
`cost_scope: "component_lines_only"`.

`sources` contains exact byte/SHA-256 identities for all six inputs.
`procurement` is the same compact projection used by v1.467: it retains the
complete validated procurement result except the nested full final-BOM object
and the original procurement binding digest that covered that omitted object.
The exact raw procurement-intent source identity and full fresh replay remain
authoritative. `supplier_offer` retains the complete normalized input.

Only a fully covered result retains non-empty `coverage_lines` and a non-null
`component_subtotal_micros`; a `not_covered` result retains the keys as `[]`
and `null`. Each coverage line retains the intent MPN, supplier part number,
catalog-part digest, footprint, references, per-board quantity,
requested board count, resulting required and quoted quantities, surplus, and
exact quoted-line subtotal. The component subtotal is the checked sum of those
line subtotals and is not landed cost or an authorized spend. The
`component_subtotal_checked` validation flag remains true when that bounded
internal sum succeeds even if a `not_covered` report keeps the public subtotal
null.

The result also retains closed validation flags, stable findings, and a
domain-separated SHA-256 binding over every material result field. All of
these authority/currentness fields are always false:

- `adapter_network_performed`
- `current_availability_verified`
- `supplier_authenticity_verified`
- `offer_authenticity_verified`
- `price_authenticity_verified`
- `trusted_time_verified`
- `inventory_reserved`
- `procurement_authorized`
- `order_ready`
- `order_placed`
- `payment_performed`

## Bounds and schema authority

The board, package, generation bundle, snapshot, and retained intent preserve
the existing 128 MiB, 128 MiB, 32 MiB, 4 MiB, and 16 MiB ceilings. The
normalized offer is at most 4 MiB, and the six-source direct-input aggregate
is at most 384 MiB. A coverage result is at most 16 MiB. Requested boards are
restricted to `1..1,000,000`; required and quoted quantities are restricted to
`1..2,147,483,647`; money and checked sums do not exceed
9,007,199,254,740,991. The caller command, argv, child streams, and Windows
command rendering retain the v1.464 process limits. The v1.468 outer deadline
is finite and restricted to 1–600 seconds.

The two emitted Draft 2020-12 schemas are closed structural contracts. Runtime
validation remains authoritative for UTF-8 byte limits, duplicate keys,
strict Boolean/integer separation, sorting and uniqueness, exact digests,
checked arithmetic, decision/finding equivalences, canonical rendering,
source capture, replay, aggregate bounds, and final rereads. Path/bytes retained
coverage evidence must equal canonical pretty JSON with exactly one LF. A
bounded Mapping snapshot may establish only structural and self-contained
consistency; `validate_supplier_offer_coverage` is required to authenticate it
against the six exact inputs and fresh procurement replay.

## Deliberate nonclaims

This result covers only one caller-normalized local observation. SHA-256 and
the result binding provide integrity and correlation, not origin or signature
authentication. The adapter itself performs no network operation, but the
caller-selected pcbex command remains unauthenticated and unsandboxed and its
independent I/O is outside that claim.

The report proves no current stock, supplier/manufacturer identity, offer or
transport authenticity, revocation status, lifecycle, lead time, reservation,
or guarantee that terms will be honored. It proves no unit-price truth,
rounding policy, price tier, MOQ, order multiple, discount, shipping, tax,
duty, fee, exchange rate, landed cost, invoice total, or payment amount. It
performs no substitution, multi-supplier optimization, inventory reservation,
cart submission, procurement/assembly/fabrication authorization, ordering,
payment, or spend. The explicit evaluation instant is untrusted. Sequential
capture and rereads detect observed changes but are not an atomic snapshot
against a same-principal change-and-restore race.

The v1.467 assembly-evidence result is deliberately not an input. Requiring it
would add unrelated board-binding, CPL, handoff, and KiCad replay while its
compact procurement projection still cannot replace fresh validation of the
original procurement intent. A later consumer may cross-bind the two reports
through the identical raw procurement-intent identity and compact procurement
projection.

Version 1.469 adds a separate
[bounded HTTPS acquisition](SUPPLIER_OFFER_ACQUISITION.md) pre-step for this
same normalized-offer schema. It may produce the exact offer file consumed
here plus an independent receipt whose `offer_sha256` can be compared with
`sources.supplier_offer.sha256`. This evaluator remains offline and its own
`adapter_network_performed` stays false. The acquisition receipt's network
observation does not authenticate a supplier, offer, price, endpoint,
transport, or time, and it adds no coverage, reservation, authorization,
ordering, or payment claim.

Version 1.470 adds the separate [exact assembly and acquired supplier-offer
evidence composition](ASSEMBLY_SUPPLIER_OFFER_EVIDENCE.md). It freshly invokes
this complete validator inside the private staged union also used for assembly
replay and receipt validation. Coverage consumes that union's board, package,
historical snapshot, raw intent, and canonical offer; its generation input is
the exact entry extracted from the validated handoff, not a second caller
path. The outer composer also requires the explicit coverage evaluation
instant to equal the receipt's recorded fetch instant;
that equality remains untrusted correlation and does not establish freshness.
A valid `not_covered` report stays evidence rather than becoming a hard
composition error. This schema, serialized bytes, and offline network flag
remain unchanged.
