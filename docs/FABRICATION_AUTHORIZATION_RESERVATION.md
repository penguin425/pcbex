# Local fabrication-authorization challenge reservation

Version 1.462 adds a Unix-only CLI boundary that freshly verifies one
fabrication authorization and records its challenge in one trusted local
ledger. The guarantee is deliberately narrow: after this command successfully
returns, one exact marker for that challenge has been installed without
replacement and synchronized in that one ledger directory. This is a local
at-most-once reservation, not a global one-time-use or order-execution proof.

## Provision the ledger

The ledger is deployment state, not an ordinary build output. It must already
exist as an absolute, real directory owned by the effective Unix user running
`pcbex`, with mode exactly `0700`. pcbex never creates the directory, changes
its owner or mode, initializes its identity, or repairs it.

The executor must also ensure that platform ACLs, capabilities, or other
alternate access grants do not broaden access. pcbex validates the effective
UID and POSIX mode bits only; it does not enumerate or prove the absence of
extended ACL entries on every supported Unix filesystem.

The ledger must remain separate from the direct authorization inputs, every
plan-selected input, and the exact firmware bundle directory. A contained,
containing, or identical canonical path fails before reservation so ledger
state cannot also serve as replay input or firmware evidence.

The directory must contain the regular, non-symlink manifest
`.pcbex-fabrication-authorization-reservation-ledger-v1.json`. The manifest is
limited to 4,096 bytes and is a closed duplicate-free object with exactly these
keys. It is opened without following links and stable-read relative to the
pinned ledger descriptor:

```json
{
  "schema_version": 1,
  "ledger_scope": "pinned-local-ledger-at-most-once-v1",
  "ledger_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

`ledger_id` is 32 bytes encoded as 64 lowercase hexadecimal digits. Provision
it from a cryptographically secure random source and retain that exact value in
the trusted executor configuration. The command requires it again through
`--expected-ledger-id`, so accidentally selecting another well-formed ledger
fails closed. The manifest is not signed, and keeping the expected ID beside a
caller-writable ledger would not create an independent trust root.

Emit the two closed structural schemas with:

```sh
pcbex fabrication-authorization-reservation-schema \
  --output fabrication-authorization-reservation.schema.json
pcbex fabrication-authorization-reservation-ledger-schema \
  --output fabrication-authorization-reservation-ledger.schema.json
```

Schema outputs use the ordinary no-clobber output boundary. They do not create
or initialize a ledger.

## Reserve an authorized challenge

Use the original verifier inputs and place the positional plan after `--`:

```sh
pcbex reserve-fabrication-authorization \
  --report pipeline-report.json \
  --manufacturing-package manufacturing.zip \
  --factory-receipt factory-receipt.json \
  --policy-pack organization-policy-pack.json \
  --approval fabrication-a.approval.json \
  --approval fabrication-b.approval.json \
  --reservation-ledger /var/lib/pcbex/fabrication-reservations \
  --expected-ledger-id "$LEDGER_ID" \
  -- pipeline-plan.json
```

The command accepts one to 100 signed approval inputs under the existing
per-source limits; a successful reservation still requires the policy's
two-or-more approval quorum. It freshly reproduces the factory-required deterministic pipeline,
revalidates the exact manufacturing ZIP, receipt, policy pack, approvals, and
current authorization window, and proceeds only when the resulting full
authorization report is `fabrication_authorized`. A valid rejection,
insufficient quorum, inactive window, malformed signature, changed input, or
other verifier failure creates no new reservation marker. There is no
`--output`, `--require-authorized`, evaluation-time override, private-key
input, or signing mode. Success writes no standard output; a concise
non-sensitive status may be written to standard error.

The fixed marker name is:

```text
fabrication-authorization-reservation-v1-<challenge>.json
```

The signed 64-character lowercase challenge is the complete per-ledger
reservation key. Scope, authorization ID, report digest, or caller path is not
part of the filename, so reusing one challenge with another authorization
scope in the same ledger remains blocked.

## Marker contract

The marker is a pretty-printed JSON object followed by exactly one LF, limited
to 16 KiB. It is path-free, duplicate-free, closed to exactly five top-level
keys, and the installed file uses mode `0600`. It has this shape:

```json
{
  "schema_version": 1,
  "reservation_scope": "pinned-local-ledger-at-most-once-v1",
  "status": "local_reservation_committed",
  "ledger_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "authorization_report_summary": {
    "schema_version": 1,
    "status": "fabrication_authorized",
    "fabrication_authorized": true,
    "authorization_id": "lot-2026-08-10-a",
    "challenge": "<64 lowercase hexadecimal digits>",
    "quantity": 20,
    "currency": "USD",
    "maximum_total_minor_units": 25000,
    "valid_from_unix": 1786320000,
    "expires_at_unix": 1786323600,
    "evaluated_at_unix": 1786320100,
    "approvals": 2,
    "rejections": 0,
    "gate_failure_count": 0,
    "plan_sha256": "<64 lowercase hexadecimal digits>",
    "run_sha256": "<64 lowercase hexadecimal digits>",
    "manufacturing_package_sha256": "<64 lowercase hexadecimal digits>",
    "factory_receipt_sha256": "<64 lowercase hexadecimal digits>",
    "policy_pack_sha256": "<64 lowercase hexadecimal digits>",
    "quote_authenticity_verified": false,
    "challenge_one_time_use_enforced": false,
    "report_bytes": 12345,
    "report_sha256": "<64 lowercase hexadecimal digits>"
  }
}
```

`authorization_report_summary` is the exact existing 23-field compact summary
of the freshly rendered full authorization report. Reservation additionally
requires its decision to be authorized, zero submitted rejections, zero gate
failures, an unauthenticated factory quote, and the unchanged false one-time
flag. The nested `report_bytes` and `report_sha256` bind the freshly verified
full report bytes; the reservation command retains only the bounded compact
marker, not the full policy pack, approval envelopes, signatures, reasons,
tickets, receipt endpoint, quote body, private keys, or any host path.
The marker is therefore not a substitute for the full authorization report and
its signed approval envelopes. Run `verify-fabrication-authorization`
first into a distinct new output path when that complete audit evidence must
be retained. That earlier verifier run samples its own evaluation instant, so
its report hash need not equal the in-memory report hash recorded by the later
reservation.

## Commit and crash semantics

On Unix, pcbex pins the already validated ledger directory by descriptor. It
writes the complete private temporary marker in that directory, synchronizes
the file, installs the deterministic final name through a descriptor-relative
no-replace operation, and synchronizes the same pinned directory before
returning success. The no-replace installation is the reservation's
linearization point; an advisory lock file is not the authority.

pcbex samples the local wall clock before starting publication, immediately
before and after the no-replace installation, and again after file and
directory durability have completed. A pre-install inactive window leaves no
final marker. If the window becomes inactive after installation, the final
marker is retained, the challenge is burned, and the command returns an error;
success therefore requires the post-durability sample to remain within the
signed window. These are local freshness gates only: the marker keeps the full
report's earlier `evaluated_at_unix`, and none of the local samples is a
trusted or externally authenticated timestamp. The bracketing inference
assumes the local wall clock does not move backward between samples; clock
rollback is outside this contract.

Any entry already occupying the fixed marker name blocks the operation without
being followed, parsed as retry permission, replaced, or deleted. This applies
to a valid or malformed file, an empty file, directory, symlink, or other
entry. It sacrifices availability rather than treating ambiguous state as an
unused challenge.

Before final installation, an uncommitted private temporary file may be
cleaned up. After installation, a directory-sync, cleanup, process, or output
error never authorizes automatic removal of the final marker. The caller may
therefore receive an error or lose the process after the challenge became
reserved. A retry must fail closed. Conversely, success is not returned until
the file and directory synchronization steps complete under the local
filesystem's contract. These are at-most-once admission semantics, not
exactly-once completion or retry semantics.

The Unix no-replace operation may temporarily give the synchronized inode both
a private temporary name and the fixed final name. A process crash or cleanup
failure can leave that private alias in the `0700` ledger. It does not represent
a second reservation: only the deterministic final challenge name is the
commit record. Operators must never treat cleanup of a private temporary alias
as permission to delete or recreate the final marker.

## Trust boundary and non-claims

This feature is useful only when a separately controlled executor owns both
the private ledger and the credentials or capability needed to perform the
fabrication handoff, and makes successful reservation mandatory. Running the
CLI beside an unrestricted caller who can submit the package directly does not
create a permission boundary.

The following remain explicitly outside the v1.462 guarantee:

- global one-time use, or one-time use across a second ledger, host, runner,
  container, workspace, restored backup, or filesystem snapshot;
- protection from the ledger owner, the same effective UID, an administrator,
  or root deleting or replacing a marker, renaming and recreating the ledger,
  changing permissions, adding hard links, or rolling state back between
  invocations;
- validation or enforcement of extended ACLs, capabilities, or other access
  controls beyond the checked effective UID and exact POSIX mode bits;
- NFS, SMB, FUSE, distributed, network, overlay, or ephemeral filesystems, and
  storage or hardware that does not honor successful exclusive-create and
  synchronization operations;
- Windows. The command fails closed there rather than claiming equivalent
  descriptor-relative no-replace and directory-durability semantics;
- a trusted clock or timestamp, current authorization after the recorded
  evaluation instant, challenge entropy, decision revocation, withheld or
  later rejection discovery, or a signed consumption-domain identity;
- factory or quote authenticity, live inventory, current pricing, submission,
  reservation of supplier capacity, fabrication, ordering, payment, spend
  authority, or exactly-once external side effects; and
- MCP, MCP Tasks, the focused verification Action, or the root hardware Action.

In particular, the existing signed approval scope does not bind `ledger_id`.
The same otherwise-valid approval set can be independently reserved in two
separate ledgers. `challenge_one_time_use_enforced` therefore remains false in
the nested authorization summary and in every ordinary verification report.
The marker proves only that this cooperative local ledger commit completed
under the stated assumptions; it is not reusable current authority or an
outer-signed audit receipt.
