# Catalog snapshots and MPN selection

v1.412 adds a reproducible supplier-catalog boundary to the Text-to-Circuit
flow. The catalog selector never queries a live supplier while resolving a
circuit. A caller supplies one local, closed catalog snapshot; pcbex normalizes
it, selects MPNs deterministically, and retains a digest-bound receipt. The
caller-supplied circuit-generation provider remains a separate process and is
not a network or filesystem sandbox; it must be trusted and constrained by the
caller. The snapshot is evidence about inventory and identity, not a datasheet
or fabrication approval.

## Snapshot v1

The snapshot is a JSON object with exactly these top-level fields:

```json
{
  "schema_version": 1,
  "supplier": "jlcpcb",
  "snapshot_id": "example-2026-08-04",
  "captured_at_unix": 1785715200,
  "expires_at_unix": 1786320000,
  "parts": [
    {
      "mpn": "C-100NF-0603",
      "supplier_part_number": "C14663",
      "description": "100 nF ceramic capacitor",
      "footprint": "Capacitor_SMD:C_0603_1608Metric",
      "tags": ["100nF", "capacitor"],
      "vendor": "Example Components",
      "stock": 5000,
      "basic": true,
      "datasheet_url": null
    }
  ]
}
```

Each part must contain exactly the nine shown fields. `supplier_part_number`
and `datasheet_url` may be null; a non-null datasheet URL must use HTTPS.
Supplier IDs are lowercase safe ASCII, snapshot IDs are bounded safe names,
and `expires_at_unix - captured_at_unix` is at most seven days. The evaluation
instant must lie within that window. The complete source is UTF-8 JSON, at
most 4 MiB, with no duplicate keys, non-finite values, unknown fields, or
duplicate MPNs (case-insensitive). Stock and collection sizes are bounded.

The snapshot may contain at most 100,000 parts, but selection also has a
separate deterministic work budget. A circuit has at most 256 parts; each
selection query is at most 4 KiB and 128 tokens, and candidate/token
comparisons are charged against a 1,000,000-unit ceiling before ranking
starts. Receipts contain at most 256 selections and at most 1 MiB of canonical
JSON. These limits also apply when a receipt is recomputed for verification.

The loader sorts tags and parts before hashing, so equivalent input ordering
produces the same normalized catalog digest. A file source is retained in
receipt evidence only as its basename, byte count, and SHA-256; injected JSON
has no path or secret-bearing name. The source bytes and normalized catalog
digest are independent evidence values.

The checked-in [catalog-snapshot-v1.json](../examples/catalog-snapshot-v1.json)
is illustrative inventory. Its seven-day validity window is intentionally
finite; refresh the timestamps and inventory when using it as a real snapshot.

The emitted JSON Schemas provide the closed structural contract and the bounds
JSON Schema can express. The Python loader/validator remains authoritative for
UTF-8 byte counts, duplicate keys, normalized text, HTTPS host/userinfo rules,
timestamp ordering/TTL, source basename correlation, sorted unique references,
the aggregate receipt byte limit, and recomputed digests.

## Selection and receipt

`select_catalog_parts` first verifies every prefilled MPN, including exact
footprint, stock, and `basic` policy. It then resolves missing MPNs in
case-insensitive reference order. Candidate text is drawn from the circuit
part's value, description, library ID, tags, and keywords and matched against
the catalog MPN, supplier part number, description, and tags. Positive text
matches rank first; stock availability and `basic` are policy filters, and
stable MPN tie-breakers make the result reproducible. Inventory is reserved
per MPN, including for prefilled parts, so a later reference cannot silently
reuse exhausted stock.

The result is a resolved `circuit-spec-v2` plus a receipt with schema version 1
and adapter `catalog-snapshot-v1`. The receipt records:

- snapshot supplier, ID, capture/expiry/evaluation timestamps, source evidence,
  and normalized catalog part count/digest;
- SHA-256 values for the input and resolved specs;
- the exact `require_available`, `require_basic`, and
  `allow_footprint_fallback` policy; and
- one reference-sorted selection per circuit part, with `assigned` or
  `verified` status, MPN, supplier part number, footprint, and a digest of the
  normalized catalog part. `selections_sha256` commits to that complete list.

`validate_catalog_receipt` recomputes selection, policy, source identity,
spec digests, and all selection digests. Editing either the snapshot, the
input/resolved spec, policy, or receipt therefore fails closed before source
publication.

## CLI flow

Emit the closed schemas before integrating a connector:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent catalog-snapshot-schema \
  --output catalog-snapshot-v1.schema.json
PYTHONPATH=agent/src python3 -m pcbex_agent catalog-selection-receipt-schema \
  --output catalog-selection-receipt-v1.schema.json
```

Pass the snapshot to the Rust-gated generation flow:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent generate-circuit \
  requirements.txt \
  --pcbex target/release/pcbex \
  --catalog-snapshot examples/catalog-snapshot-v1.json \
  --require-basic \
  --output build/circuit-generation.json \
  --skidl-output build/circuit.py \
  --provider-command ./structured-circuit-provider
```

`--allow-out-of-stock` disables the default `require_available` filter.
`--require-basic` restricts selected parts to `basic: true`.
`--allow-footprint-fallback` permits a deterministic footprint-only choice
when no positive catalog-text match exists. Fallback is opt-in and is recorded
in the receipt policy; it is never an implicit guess. These policy options
require `--catalog-snapshot` and are rejected when no snapshot is supplied.

`catalog-snapshot-schema` and `catalog-selection-receipt-schema` print to
stdout when `--output` is omitted. All destination writes follow the agent's
no-clobber and bounded-I/O policy.

## Two Rust review gates

With `--catalog-snapshot`, a generated provider candidate follows this chain:

```text
provider JSON
  -> Rust check-circuit-spec (v2 normalization + immutable ERC, zero errors)
  -> snapshot MPN verification/assignment + receipt recomputation
  -> Rust check-circuit-spec again on the resolved MPN-bearing spec
  -> final bundle and SKiDL publication
```

The second check is not optional. It proves that catalog resolution changed
only MPN fields and that the resolved circuit still passes the native
electrical floor. A catalog mismatch is retryable provider feedback; a
tampered receipt, changed electrical content, or failed second Rust review is
a hard generation failure. The bundle's attempt history distinguishes the
initial and resolved spec/check digests and records `catalog_receipt_sha256`.

Programmatic callers that inject a custom `catalog_selector` into
`generate_circuit_with_llm` must also provide a trusted
`catalog_receipt_validator`. The validator receives isolated copies and must
recompute the complete receipt against its trusted snapshot; selection cannot
proceed with only shape validation.

## Compatibility

The generation bundle is now `schema_version: 2` (schema ID
`circuit-generation-v2.json`). Consumers must accept the required nullable
`catalog_receipt` and `catalog_receipt_sha256` fields. Without a snapshot the
receipt fields remain null and the original single Rust gate is preserved;
with a snapshot, `spec` and `check` are the final resolved artifacts and the
receipt is non-null. Existing `circuit-spec-v2` input and native check schemas
are unchanged. Select the bundle contract by its `schema_version`, not by a
package release string.

The older `generate-skidl --catalog catalog.json` path remains available for
legacy vendor-neutral arrays of `CatalogPart` values. It returns only a
resolved spec and does not create a snapshot receipt. Its footprint fallback
is also opt-in with `--allow-footprint-fallback`; migrate production flows to
`generate-circuit --catalog-snapshot` for digest-bound evidence.

SKiDL does not receive an `mpn=` keyword. Instead, generated source contains a
sorted `_PCBEX_MPN_BY_REFERENCE` mapping and, when catalog selection was used,
`_PCBEX_CATALOG_RECEIPT_SHA256`. The map preserves MPN evidence without
changing SKiDL's part-construction API; downstream packaging or review tools
must consume that map and receipt digest explicitly.

Catalog selection does not verify electrical ratings, datasheet truth,
manufacturer identity, lifecycle status, or fabrication capability. Continue
through schematic import/ERC, simulation and approval, PCB DRC, manufacturing,
and pipeline gates before production.
