# Local procurement authorization reservation

Reserve one approved procurement challenge. Once.

`pcbex-agent reserve-procurement-authorization` freshly replays a retained
v1.471 authorization from its complete original closure, then asks a trusted
Rust helper to admit that challenge to one caller-selected local ledger.

> [!IMPORTANT]
> This boundary proves local at-most-once admission inside one exact ledger.
> It does not prove global one-time use, reserve supplier inventory, place an
> order, authorize payment, or confirm any external side effect.

## What changes

- **Replays authority:** Revalidates the canonical v1.471 report, all original
  v1.470 sources, the pinned policy, and every submitted approval.

- **Pins one ledger:** Requires an existing absolute Unix directory owned by
  the effective UID with exact mode `0700`.

- **Rejects unreviewed storage:** Accepts reviewed local Linux filesystems and
  macOS filesystems marked local by the kernel. Unknown, network, clustered,
  and FUSE filesystems fail closed.

- **Commits without replacement:** Installs one deterministic marker through a
  pinned directory descriptor, then synchronizes the file and directory.

- **Burns collisions:** Treats every existing marker name as used, even when
  the existing bytes are corrupt, truncated, or schema-invalid.

- **Rechecks time:** Tests the approval window, offer window, and receipt-age
  bound before installation, after installation, and after durability.

The v1.471 authorization report stays unchanged. Its
`challenge_one_time_use_enforced` field remains `false`.

## Boundary ownership

| Layer | Responsibility |
| --- | --- |
| `pcbex-agent` | Freshly replay the complete v1.471 authorization and build the exact path-free marker |
| hidden Rust helper | Validate the marker, pin the ledger, verify its manifest and local filesystem, and commit durably without replacement |
| deployment | Protect the ledger, choose and distribute its expected ID, retain the full authorization report, and control same-UID writers |
| supplier or ordering system | Reserve inventory, enforce server-side idempotency, accept an order, and process payment |

Direct use of `internal-reserve-procurement-authorization` is not an
authorization boundary. It cannot replay the original v1.470 closure and is
hidden from help and capability discovery.

## Prepare the ledger

Create the directory before the release operation. Keep it outside every
authorization input path.

```sh
ledger=/var/lib/pcbex/procurement-reservations
ledger_id=$(openssl rand -hex 32)

install -d -m 0700 "$ledger"
python3 - "$ledger" "$ledger_id" <<'PY'
import json
from pathlib import Path
import sys

ledger, ledger_id = sys.argv[1:]
manifest = {
    "schema_version": 1,
    "ledger_scope": (
        "pinned-local-procurement-authorization-ledger-at-most-once-v1"
    ),
    "ledger_id": ledger_id,
}
Path(ledger, ".pcbex-procurement-authorization-reservation-ledger-v1.json").write_text(
    json.dumps(manifest, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
```

Store `ledger_id` in protected executor configuration. The manifest cannot
select its own trusted identity because the command requires an independent
`--expected-ledger-id` value.

> [!NOTE]
> The ledger manifest is not a signed trust root. The external expected ID
> prevents accidental ledger substitution relative to the configured value;
> deployment policy must protect that value and the directory itself.

## Reserve an authorization

Supply the retained authorized report, both approvals, and the same complete
source closure used by v1.471.

```sh
pcbex-agent reserve-procurement-authorization \
  assembly-supplier-offer-evidence.json \
  handoff.zip board.kicad_pcb manufacturing.zip \
  --board-binding-report board-binding.json \
  --procurement-intent procurement-intent.json \
  --catalog-snapshot catalog.json \
  --final-cpl-report final-cpl.json \
  --assembly-evidence assembly.json \
  --supplier-offer supplier-offer.json \
  --supplier-offer-fetch-receipt offer-receipt.json \
  --supplier-offer-coverage offer-coverage.json \
  --policy-pack policy-pack.json \
  --report procurement-authorization.json \
  --approval procurement-a.json \
  --approval procurement-b.json \
  --requested-boards 25 \
  --evaluated-at-unix 1786600000 \
  --expected-policy-pack-canonical-sha256 "$policy_digest" \
  --reservation-ledger "$ledger" \
  --expected-ledger-id "$ledger_id" \
  --pcbex pcbex \
  --authorization-pcbex pcbex \
  --timeout-seconds 300
```

The command returns success only after durable completion. It publishes no new
authorization report and never rewrites the retained v1.471 report.

## Marker identity

The destination name is fixed by the verified challenge:

```text
procurement-authorization-reservation-v1-<64-lowercase-hex-challenge>.json
```

The marker is closed, path-free JSON. It retains a compact summary rather than
copying policy text, reasons, tickets, approvals, or the complete report.

```json
{
  "schema_version": 1,
  "reservation_scope": "pinned-local-procurement-authorization-ledger-at-most-once-v1",
  "status": "local_reservation_committed",
  "local_challenge_reserved": true,
  "adapter_network_performed": false,
  "global_challenge_one_time_use_enforced": false,
  "inventory_reserved": false,
  "order_placed": false,
  "payment_performed": false,
  "ledger_id": "<64 lowercase hex>",
  "authorization_report_summary": {
    "authorization_id": "release-1472",
    "challenge": "<64 lowercase hex>",
    "supplier": "supplier-a",
    "offer_id": "offer-1",
    "requested_boards": 25,
    "currency": "USD",
    "component_subtotal_micros": 10000000,
    "maximum_component_subtotal_micros": 11000000,
    "approvals": 2,
    "report_bytes": 12345,
    "report_sha256": "<64 lowercase hex>",
    "report_binding_sha256": "<64 lowercase hex>"
  }
}
```

The real summary also retains the offer, receipt, authorization, and evaluation
timestamps; maximum receipt-observation age; zero rejection/gate counts; and
the relevant v1.471 false authenticity, currentness, trusted-time, and
one-time-use claims.

## Commit protocol

The helper follows one fail-closed sequence:

1. **Pin:** Open the existing absolute ledger and retain its directory
   descriptor.
2. **Validate:** Require effective-UID ownership, exact `0700`, a reviewed local
   filesystem, and the fixed manifest/expected-ID match.
3. **Separate:** Reject a ledger that contains, aliases, or is contained by any
   replay input or the privately staged marker.
4. **Parse:** Stable-read the canonical marker under 16 KiB and validate every
   bound and nonclaim.
5. **Stage:** Create a private temporary marker through the pinned directory and
   write the exact validated bytes.
6. **Recheck:** Revalidate the ledger, manifest, source bytes, input separation,
   authorization window, offer window, and receipt-age gate.
7. **Install:** Use descriptor-relative no-replace installation. An existing
   leaf always returns “already reserved”; its content is never trusted.
8. **Sync:** Synchronize the file and directory, then repeat time and ledger
   checks after installation and at completion.

Once the final name exists, pcbex never removes it. A post-install validation,
cleanup, clock, or sync failure reports that the challenge remains reserved.

> [!WARNING]
> Do not retry a committed-but-uncertain result with a new challenge. Inspect
> the deterministic marker name in the same pinned ledger and reconcile the
> release procedure first.

## Time semantics

The retained v1.471 report is a historical point-in-time authorization. The
reservation command cryptographically revalidates it from the full closure,
then evaluates every remaining dynamic time condition at commit.

The approval interval is inclusive. The supplier-offer interval remains
half-open, and the receipt observation must not be in the future or older than
the policy bound.

Local wall-clock checks do not make `trusted_time_verified` true. A controlled
or incorrect host clock can still influence admission.

## Failure semantics

| Condition | Result |
| --- | --- |
| Retained report is negative, malformed, changed, or mismatched | No marker |
| Policy pin, source closure, or approval verification fails | No marker |
| Ledger is relative, insecure, substituted, unreviewed, remote, FUSE-backed, or overlaps an input | No marker |
| Authorization, offer, or receipt-age gate is inactive before install | No marker |
| Deterministic marker name already exists, regardless of bytes | Challenge remains burned; existing bytes stay unchanged |
| Final name installs but a later check or durability step fails | Error reports committed uncertainty; challenge remains reserved |
| Windows or an unreviewed Unix target | Fail closed before reservation |

Python uses one whole-operation deadline. It reserves a final slice for the
ledger helper after the full retained-report replay.

## Limits

| Item | Limit |
| --- | ---: |
| Marker | 16 KiB |
| Ledger manifest | 4 KiB |
| Retained v1.471 report | 128 MiB |
| Protected paths forwarded to the helper | 128 |
| Approval count | 2–100 for an authorized marker |
| Authorization duration | 604,800 seconds |
| Command timeout | 3–600 seconds |

The underlying v1.471 source limits and 1,141 MiB retained-validation aggregate
remain unchanged. The marker and private staging file are derived artifacts,
not additional caller-source capacity.

## What this does not prove

The marker does not prove any of the following:

- **Global uniqueness:** Another ledger, host, namespace, or copied directory
  can admit the same challenge.
- **Immutable custody:** A same-UID principal can add, replace, rename, or delete
  ledger material outside this command.
- **Supplier state:** Stock, lifecycle, lead time, MOQ, price, endpoint, TLS,
  response, or offer authenticity remains unverified.
- **Total spend:** The ceiling covers component lines only, not shipping, tax,
  duty, fees, discounts, exchange, landed cost, or invoice total.
- **Order execution:** No cart, reservation, supplier idempotency key, order,
  payment, refund, or settlement operation occurs.
- **Trusted time:** Host and receipt timestamps remain unauthenticated.
- **Distinct people:** Distinct trusted signer IDs and keys do not establish
  separate natural-person control.
- **Atomic world state:** Sequential filesystem and source rereads detect many
  mutations but cannot create an atomic multi-file snapshot against a
  same-principal change-and-restore race.

Use a supplier-side signed quote, server-side idempotency key, authenticated
inventory reservation, and payment-specific policy before implementing an
ordering boundary.

## Discover the schemas

```sh
pcbex procurement-authorization-reservation-schema \
  --output procurement-reservation.schema.json

pcbex procurement-authorization-reservation-ledger-schema \
  --output procurement-reservation-ledger.schema.json
```

Both schemas are Draft 2020-12, recursively closed, and bounded. The installed
binary remains authoritative for the exact command and schema surface.

## Related contracts

- [Procurement Authorization](PROCUREMENT_AUTHORIZATION.md)
- [Fabrication Authorization Reservation](FABRICATION_AUTHORIZATION_RESERVATION.md)
- [Python Agent Limits](PYTHON_AGENT_LIMITS.md)
- [CLI I/O Limits](CLI_IO_LIMITS.md)
- [Trust Model](TRUST_MODEL.md)
