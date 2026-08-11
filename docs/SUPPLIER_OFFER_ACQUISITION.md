# Bounded supplier-offer HTTPS acquisition

Version 1.469 adds an explicit network pre-step for the existing
`offline-normalized-supplier-offer-v1` contract. It acquires one already-
normalized offer, publishes the canonical offer bytes, and retains a separate
closed receipt describing the local adapter's request and response
observations. It does not change or run the v1.468 coverage evaluator.

This boundary is acquisition provenance, not supplier authenticity. A receipt
with `adapter_network_performed: true` records what this adapter observed while
it was running; it is not a signed or independently replayable proof that a
network operation occurred.

## CLI

```sh
export PCBEX_SUPPLIER_OFFER_TOKEN='deployment-owned-secret'
PYTHONPATH=agent/src python3 -m pcbex_agent fetch-supplier-offer \
  --endpoint https://offers.example.test/v1/quote \
  --supplier example-supplier \
  --procurement-intent-sha256 \
    0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --output supplier-offer.json \
  --receipt supplier-offer-fetch-receipt.json \
  --timeout-seconds 30 \
  --maximum-response-bytes 4194304 \
  --bearer-token-environment PCBEX_SUPPLIER_OFFER_TOKEN

PYTHONPATH=agent/src python3 -m pcbex_agent \
  supplier-offer-fetch-receipt-schema \
  --output supplier-offer-fetch-receipt.schema.json
```

The CLI does not expose the test-only insecure-loopback switch or the injected
fetch time. On success it prints only the exact response-entity and
canonical-offer SHA-256 digests. Errors do not include the endpoint, token,
response body, header values, or provider-controlled exception text.

## Input and request boundary

The caller declares:

- a credential-free absolute HTTPS endpoint;
- the expected supplier identifier;
- the SHA-256 of the exact procurement-intent bytes that the offer must name;
- two distinct new destinations for the normalized offer and receipt;
- an integer network timeout from 1 through 60 seconds;
- an integer response ceiling from 1 through 4 MiB; and
- optionally, the name of an environment variable containing a bearer token.

The endpoint is ASCII and at most 4,096 bytes. It contains no whitespace,
control character, user information, query, fragment, or backslash. The
canonical identity lowercases the scheme and host, preserves a valid numeric
explicit port from 1 through 65,535 and the path's exact escaping, and uses
`/` for an empty path. An empty, zero, nonnumeric, or out-of-range explicit
port is invalid. A bracketed authority must contain a literal IPv6 address;
bracketed DNS names and IPvFuture spellings are rejected rather than rewritten.
Production use accepts HTTPS only. A programmatic test switch
accepts HTTP only for literal `127.0.0.1` or `::1`; the CLI cannot enable it.
There is no private-address denylist for production HTTPS, so this operation
must not be exposed through MCP or an untrusted GitHub Action input.

The adapter sends one shell-free, no-retry, no-redirect GET with
`Accept: application/json`. An optional token is loaded only from a validated
environment-variable name. `SystemRoot` is reserved case-insensitively because
Windows passes only that runtime variable to the isolated resolver. The token
value is ASCII, nonblank, at most 8,192 bytes, and sent only as
`Authorization: Bearer ...`. Neither the token name nor value is retained.
For a hostname endpoint on Windows, acquisition also fails before DNS if the
exact token bytes occur anywhere in the bounded `SystemRoot` value that would
be forwarded to the resolver; literal-IP endpoints do not invoke that helper.
Exact token bytes are rejected if they occur in the raw entity body or
canonical offer; encoded, transformed, split, status-line, or header reflection
is not claimed.

The credential-free request identity is domain-separated. It covers exactly
the adapter ID, canonical endpoint, method `GET`, expected procurement-intent
digest, and expected supplier. It excludes the token and its environment name,
timeout, size limit, time, and output paths.

## HTTP and deadline boundary

DNS, TCP connection, platform-default TLS, request, headers, and entity-body
reads share one absolute monotonic deadline. Hostname resolution occurs in a
secret-free bounded helper process; on Windows it receives only a validated
`SystemRoot` needed by the platform runtime. Cleanup time is reserved inside
the same deadline. A one-slot transaction gate prevents a later acquisition
from reaching DNS or connect while a prior request/response worker remains
active. A separate one-slot connect-worker gate caps a connect that outlives
its caller-visible deadline. Both gates and workers are independent of the
older catalog acquisition adapter.

The response must satisfy all of these conditions:

- one CRLF-terminated HTTP/1.0 or HTTP/1.1 status in `200..299` other than
  bodyless `204` or `205`, with literal-space separators, an optional printable
  ASCII reason phrase, and no interim response;
- at most 64 header fields and 64 KiB of combined header name/value bytes;
- CRLF-terminated, parser-clean header fields with valid names and no control
  bytes in values;
- exactly one `Content-Type` field whose media type is `application/json`;
- absent or single case-insensitive `identity` content encoding;
- absent transfer encoding or, for HTTP/1.1 only, an exact comma-token list
  containing only `chunked`;
- for chunked bodies, bare hexadecimal size lines, exact CRLF data
  terminators, no chunk extensions, an empty trailer section, and a checked
  cumulative declared size within the caller ceiling;
- at most one decimal `Content-Length` and never both length and transfer
  encoding;
- declared and streamed sizes within the caller ceiling; and
- exact declared/actual length agreement when a length is present.

The entity body, after the Python HTTP stack decodes transfer framing, must be
nonempty strict UTF-8 JSON with no duplicate object keys, non-finite numbers,
unknown fields, Boolean-as-integer aliases, or invalid normalized-offer value.
Its `supplier` and `procurement_intent_sha256` must equal the two caller
expectations. The offer window, quantities, and commercial coverage are not
gated here; v1.468 handles those after acquisition.

## Outputs and publication order

The response is normalized through the existing authoritative supplier-offer
runtime contract. The offer output is pretty UTF-8 JSON with sorted keys and
exactly one final LF, at most 4 MiB. The response identity covers the exact
pre-normalization entity body; the offer identity covers the exact published
canonical bytes. No raw-response artifact is published.

Both destinations are frozen and preflighted before environment lookup, DNS,
or supplier contact. They must be distinct, absent, regular-file-safe paths
without symbolic-link or Windows reparse traversal. Publication uses the
existing atomic no-clobber writer in this order:

1. canonical normalized offer;
2. canonical acquisition receipt.

The pair is deliberately not a transaction. If offer publication fails, no
receipt is written. If receipt publication later loses a race, the valid offer
remains; it is not unlinked or confused with a concurrent replacement.

## Closed receipt

The receipt scope is `https-supplier-offer-acquisition-receipt-v1`, the
adapter is `supplier-offer-http-v1`, and the canonical receipt is at most
1 MiB. It contains exactly:

- `schema_version`, `scope`, and `adapter`;
- expected `supplier` and `procurement_intent_sha256`;
- credential-free `endpoint_id` and domain-separated `request_sha256`;
- response `status`, exact entity-body `response_bytes`, and
  `response_sha256`;
- local `fetched_at_unix`;
- canonical `offer_bytes` and `offer_sha256`;
- `adapter_network_performed: true`; and
- constant-false currentness, authenticity, reservation, authorization,
  readiness, ordering, and payment fields.

The false fields are:

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

The closed Draft 2020-12 schema is structural. Runtime construction and
validation remain authoritative for exact built-in scalar types, byte bounds,
endpoint canonicality, request-digest recomputation, canonical offer and
receipt bytes, strict offer normalization, source identities, aliases, and
observed final rereads.

`validate_supplier_offer_fetch_receipt` is offline and performs no network,
clock, offer-window, or coverage operation. It captures the offer before any
stateful receipt Mapping, recomputes the request and canonical-offer identities,
and final-rereads path sources. Path/bytes receipts must equal canonical pretty
JSON plus one LF; a bounded Mapping is only a one-pass structural snapshot.
Because the raw response and transport evidence are not retained, the
validator can only type and bound the recorded status, response identity,
network flag, and fetch time. It cannot authenticate those observations.

## Failure and side-effect phases

- Invalid scalar, URL, token, or destination input fails before supplier
  contact and before publication.
- DNS, TCP, TLS, timeout, status, header, framing, or response-size failure may
  follow partial contact but publishes nothing.
- Invalid JSON, normalized-offer, supplier/digest binding, or token-reflection
  failure follows one response observation but publishes nothing.
- Offer publication failure produces no receipt.
- Receipt publication failure may leave the canonical offer.
- Receipt validation is read-only and performs no network or write.

## Deliberate nonclaims

The receipt is unsigned local adapter evidence. It does not retain the raw
response, HTTP headers, wire framing, DNS answer, socket peer, TLS transcript,
certificate chain, OCSP/revocation result, or signature. Normal platform CA
and hostname verification during HTTPS is not a retained proof. The receipt
does not independently prove that a request occurred or authenticate the
supplier, business identity, endpoint, transport, offer, price, or time.

Acquisition proves no current stock, lifecycle, lead time, reservation, MOQ,
order multiple, tier, unit-price or rounding truth, discount, shipping, tax,
duty, fee, exchange rate, landed cost, invoice total, procurement or assembly
authorization, order readiness, ordering, payment, or spend. It performs no
search, substitution, cart creation, POST, reservation, order, payment, or
supplier-native mapping.

Sequential path checks, reads, and two-file publication are not an atomic
filesystem snapshot against an administrator or same-principal change-and-
restore race. The network phase has a deadline, but earlier preflight/token
lookup and later normalization, hashing, fsync, and publication are not covered
by that network deadline. System CA roots and TLS behavior are platform-
dependent.

v1.468 remains a separate offline consumer. Even when its offer originated
from this pre-step, its own `adapter_network_performed` remains false. A later
consumer may cross-bind `receipt.offer_sha256` to
`coverage.sources.supplier_offer.sha256`; v1.469 does not compose, authorize,
or order those artifacts.

Version 1.470 performs that correlation inside the separate [exact assembly
and acquired supplier-offer evidence
composition](ASSEMBLY_SUPPLIER_OFFER_EVIDENCE.md). It runs only the offline
receipt validator against the canonical offer, then freshly validates the
unchanged coverage and assembly children from one staged source union. The
nested receipt retains its local network-observation flag while the coverage,
assembly, and outer composer flags remain false. Because the response entity
and transport evidence are not retained, v1.470 still cannot authenticate the
recorded response digest/status, network event, endpoint, TLS, or fetch time.
This receipt schema and its canonical bytes remain unchanged.
