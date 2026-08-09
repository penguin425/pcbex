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

## Bounded HTTPS acquisition

v1.420 adds an explicit network pre-step for callers that maintain a catalog
feed. The endpoint must return the exact closed `catalog-snapshot-v1` object;
the fetcher does not accept an arbitrary supplier response or infer field
mappings. The declared `--provider` must equal the snapshot's `supplier`.

```sh
export PCBEX_CATALOG_TOKEN='deployment-owned-secret'
PYTHONPATH=agent/src python3 -m pcbex_agent fetch-catalog-snapshot \
  --endpoint https://inventory.example.test/catalog/v1 \
  --provider jlcpcb \
  --output build/catalog-snapshot.json \
  --receipt build/catalog-fetch-receipt.json \
  --timeout-seconds 30 \
  --maximum-response-bytes 4194304 \
  --bearer-token-environment PCBEX_CATALOG_TOKEN

PYTHONPATH=agent/src python3 -m pcbex_agent catalog-fetch-receipt-schema \
  --output build/catalog-fetch-receipt-v1.schema.json
```

Only an absolute HTTPS URL of at most 4 KiB without credentials, whitespace,
query, or fragment delimiters is accepted. Redirects are not followed. DNS is
resolved by a secret-free, output-bounded helper process that is terminated at
the same monotonic deadline; TCP and TLS setup use one capped connection slot
so a pathological late worker cannot accumulate across repeated calls. The
caller's network-phase deadline is at most 60 seconds. The declared and
streamed response are both bounded to at most 4 MiB and must have the
`application/json` media type. An exact `chunked` transfer is accepted as
framing, while other transfer encodings and duplicate framing headers are
rejected, as is `Content-Length` plus `Transfer-Encoding` ambiguity. An
optional bearer token is read only from a validated environment-variable name
and is bounded to 8 KiB. It is never passed to the resolver or retained in the
endpoint identity, request digest, receipt, output, or compact error text. HTTP
loopback accepts only literal `127.0.0.1` or `::1`, exists only as a
programmatic test switch, and is not exposed by the CLI.

Before the request, both distinct destinations are checked with the existing
regular-file, symlink/reparse-point, and no-clobber rules. The exact response
bytes pass through the authoritative snapshot loader at the fetch timestamp.
Equivalent part/tag order is then normalized to a stable UTF-8 JSON snapshot,
published atomically, and bound to a separate `catalog-fetch-receipt-v1` with
these exact fields:

- adapter/provider and a credential-free endpoint identity;
- canonical secret-free request SHA-256;
- exact HTTP status, response byte count, and response SHA-256;
- fetch and snapshot-expiry timestamps; and
- exact normalized snapshot byte count/SHA-256 plus the normalized catalog
  digest.

`validate_catalog_fetch_receipt` stable-reads the retained snapshot and
recomputes its exact bytes, provider, validity window, and catalog digest.
Publishing the snapshot and receipt is intentionally two per-file atomic
operations: if receipt publication loses a race, the already-published valid
snapshot is retained rather than unlinked and possibly confused with a
concurrent replacement.

This acquisition step is never called implicitly by catalog selection,
`generate-circuit`, the deterministic pipeline, MCP, or the root Action. Those
paths consume a retained local snapshot and remain replayable and network-free.
Supplier-native API mapping, search, autonomous substitution, reservation,
purchase, datasheet validation, and supplier qualification remain outside the
contract.

## Fetch-to-generation provenance

v1.421 adds an opt-in bridge from the retained v1.420 fetch evidence to the
existing offline selection and circuit-generation artifacts. It does not fetch
or refresh anything. Supply the exact normalized snapshot and its fetch receipt
when generating the circuit, and request a distinct provenance destination:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent \
  catalog-generation-provenance-schema \
  --output build/catalog-generation-provenance-v1.schema.json

PYTHONPATH=agent/src python3 -m pcbex_agent generate-circuit \
  requirements.txt \
  --pcbex target/release/pcbex \
  --catalog-snapshot build/catalog-snapshot.json \
  --catalog-fetch-receipt build/catalog-fetch-receipt.json \
  --catalog-provenance-output build/catalog-generation-provenance.json \
  --output build/circuit-generation.json \
  --skidl-output build/circuit.py \
  --provider-command ./structured-circuit-provider
```

`--catalog-fetch-receipt` and `--catalog-provenance-output` form one required
pair and also require `--catalog-snapshot`. Before the provider or native
checker starts, the CLI stable-reads the receipt and normalized snapshot,
rejects duplicate/non-finite JSON, recomputes the fetch binding, and fixes
selection evaluation to the receipt's fetch timestamp. Existing invocations
without this flag pair keep the same generation-v2 contract and behavior.

The closed `catalog-generation-provenance-v1` sidecar contains only the schema
and adapter IDs, provider, credential-free endpoint identity, evaluation time,
and SHA-256 values for:

- the exact retained fetch-receipt bytes and normalized-snapshot bytes;
- the normalized catalog and embedded catalog-selection receipt;
- the reconstructed pre-selection and final resolved circuit specs; and
- the exact published generation-bundle and generated-SKiDL bytes.

The builder and `validate_catalog_generation_provenance` parse all JSON with
closed fields and fixed byte limits, revalidate the fetch receipt and snapshot,
reconstruct `assigned` MPN fields as null in the pre-selection spec, recompute
the complete selection under its recorded policy, recheck the final bundle,
approval history, native check, and SKiDL digest, then compare every sidecar
field. A one-byte change in any retained artifact fails closed. Paths, bearer
tokens, provider output, and untrusted error text are not copied into the
sidecar.

All three output paths are preflighted as distinct, bounded, link-safe,
no-clobber destinations before provider execution. Each file is published
atomically; the provenance sidecar is published last. A late race on a later
destination does not delete an already-published valid bundle or SKiDL file.
This is per-file atomic publication, not a filesystem transaction.

## Exact handoff replay linkage

Version 1.453 can carry the retained fetch-to-generation relationship into an
exact circuit handoff replay without changing either the v1.421 provenance
sidecar or the six-entry handoff archive:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-circuit-handoff-bundle build/circuit-handoff.zip \
  --pcbex target/release/pcbex \
  --catalog-generation-provenance build/catalog-generation-provenance.json \
  --catalog-fetch-receipt build/catalog-fetch-receipt.json \
  --catalog-snapshot build/catalog-snapshot.json \
  --timeout-seconds 120

PYTHONPATH=agent/src python3 -m pcbex_agent \
  circuit-handoff-bundle-catalog-provenance-replay-result-schema
```

The three catalog options are an all-or-nothing set, and a catalog-backed
generation bundle is required. The provenance and receipt are bounded to 1 MiB
each, the snapshot to 4 MiB, and the complete group to 6 MiB. Exact inputs are
captured before producer replay, reread before and after the existing
`validate_catalog_generation_provenance` check, and kept outside the unchanged
canonical ZIP. File-origin snapshots are privately staged with the basename
recorded by the catalog receipt; no caller path is exposed in the result.

Only after the producer archive reproduces byte-for-byte and any independently
requested native-KiCad and AI-quorum assertions complete does the offline
validator recompute the retained fetch receipt, snapshot, selection, generation
history, bundle, and SKiDL digest graph. The closed path-free v4 result uses
scope `deterministic-electrical-handoff-chain-catalog-provenance-replay-v4`,
sets `validation.catalog_generation_provenance_replayed` to true, and retains
the 13 validated provenance-v1 fields directly under
`catalog_generation_provenance` plus closed
`sources.{provenance,fetch_receipt,snapshot}` `{bytes, sha256}` descriptors;
there is no `binding` wrapper. Omitting the complete catalog group preserves
the exact existing replay-result v1, v2, or v3 contract. The v4 schema ID
basename is
`circuit-generation-kicad-handoff-bundle-catalog-provenance-replay-result-v4.json`.

This is historical linkage at the retained fetch timestamp, not a live catalog
check. It does not authenticate the supplier, TLS transport, endpoint, or raw
HTTP response; establish current inventory, pricing, or reservation; authorize
procurement or fabrication; authenticate toolchain provenance; or approve a
board, layout, routing, PCB DRC/DFM, manufacturing package, or manufacturing
operation. See [Atomic circuit-generation to KiCad handoff
bundle](CIRCUIT_HANDOFF_BUNDLE.md) for execution order and the complete result
contract.

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

`catalog-snapshot-schema`, `catalog-selection-receipt-schema`,
`catalog-fetch-receipt-schema`, and
`catalog-generation-provenance-schema` print to stdout when `--output` is
omitted. All destination writes follow the agent's no-clobber and bounded-I/O
policy.

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
