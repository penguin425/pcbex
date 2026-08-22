# Policy-pinned routing, DRC, and fabrication release

Authorize one exact offline release candidate.

The v1.478 boundary freshly reproduces the complete v1.477 routing, native-DRC,
and manufacturing result. It then requires the same manufacturing ZIP to pass
one factory-required deterministic pipeline and a policy-pinned fabrication
authorization quorum.

## Quick start

Create the v1.477 handoff, factory-required pipeline report, policy pack, and
signed fabrication approvals first. Then replay the complete release boundary:

```sh
pcbex-agent replay-routing-drc-fabrication-release \
  board.placed.kicad_pcb board.routed.kicad_pcb \
  --convergence-report board.convergence.json \
  --routing-verification-report board.routing-verification.json \
  --manufacturing-package build/manufacturing/manufacturing.zip \
  --routing-manufacturing-handoff-report board.routing-manufacturing.json \
  --native-drc-report board.native-drc.json \
  --routing-drc-manufacturing-handoff-report board.routing-drc-manufacturing.json \
  --deterministic-pipeline-plan factory-required-plan.json \
  --deterministic-pipeline-report factory-required-report.json \
  --approval fabrication-a.json \
  --approval fabrication-b.json \
  --expected-policy-pack-canonical-sha256 "$POLICY_DIGEST" \
  --pcbex /opt/pcbex/bin/pcbex \
  --authorization-pcbex /opt/pcbex/bin/pcbex \
  --kicad-project board.kicad_pro \
  --kicad-rules board.kicad_dru \
  --output board.fabrication-release.json \
  --require-authorized
```

> [!IMPORTANT]
> Supply the expected canonical policy digest from protected deployment
> configuration. A digest copied from the submitted policy or approval does
> not establish an independent trust root.

Discover the closed report schema without running a replay:

```sh
pcbex-agent routing-drc-fabrication-release-report-schema \
  --output routing-drc-fabrication-release-v1.schema.json
```

## What a positive report proves

A `release_authorized` result establishes one narrow relationship:

- **Fresh routing evidence:** The complete retained v1.477 report reproduces
  byte for byte from its original routing, project, rules, DFM, package, and
  native-DRC closure.

- **One exact package:** The package accepted by v1.477 equals the
  `manufacturing_package` selected by the deterministic pipeline plan.

- **Factory-required pipeline:** The retained pipeline requires and binds an
  exact normalized factory receipt plus an organization policy pack.

- **Pinned policy:** The fabrication report's canonical policy digest equals
  the caller-supplied expected digest.

- **Exact approval set:** The trusted Rust verifier retains the complete
  submitted approval envelopes, verifies their Ed25519 signatures, and meets
  the dedicated fabrication quorum at its retained evaluation instant.

- **Conjunctive decision:** `release_authorized` is true only when both
  `routing_drc_manufacturing_ready` and `fabrication_authorized` are true.

The Python composer does not reimplement routing, native DRC, pipeline, policy,
or cryptography rules. The v1.477 Python boundary remains routing authority;
the explicit `--authorization-pcbex` binary remains the fabrication
cryptography and policy authority.

## Required evidence

| Role | Maximum |
| --- | ---: |
| Original and routed KiCad boards | 128 MiB each |
| Convergence report | 16 MiB |
| Fresh routing-verification report | 32 MiB |
| Manufacturing ZIP | 128 MiB |
| Routing/manufacturing handoff | 4 MiB |
| Native KiCad DRC report | 32 MiB |
| Routing/DRC/manufacturing handoff | 1 MiB |
| Deterministic pipeline plan | 4 MiB |
| Deterministic pipeline retained report | 128 MiB |
| One signed fabrication approval | 1 MiB |
| All signed approvals | 100 files and 100 MiB |
| Final release report | 4 MiB |

The complete direct and plan-selected source union is capped at 1,469 MiB.
The bound consists of the v1.477 closure, deterministic pipeline closure, and
approval aggregate. Inputs must be nonempty, bounded, stable regular files.
Symbolic links, special files, duplicate JSON keys, unsafe relative plan paths,
unexpected firmware entries, and cross-role approval aliases fail closed.

The plan must set `require_factory:true` and include both
`factory_receipt` and `analysis_policy_pack`. Its package bytes must equal the
captured v1.477 package before any selected executable runs.

## Replay order

1. **Capture the routing closure.** Freeze and bounded-read the complete direct
   v1.477 source set and its retained report.
2. **Capture the pipeline closure.** Resolve every plan descriptor and exact
   firmware entry before consuming the approval sequence.
3. **Capture approvals.** Bound every approval individually and in aggregate,
   reject top-level and pipeline-role aliases, and parse duplicate-free JSON.
4. **Freeze commands.** Normalize the routing, authorization, and KiCad command
   arguments and reject path candidates that alias evidence.
5. **Start one deadline.** After immutable capture, start one finite
   `0 < seconds <= 600` deadline for replay, child execution, rereads, and
   cleanup.
6. **Replay v1.477 privately.** Require the freshly rendered report to equal the
   retained bytes exactly.
7. **Verify authorization privately.** Invoke
   `verify-fabrication-authorization` without a shell against the staged plan,
   report, package, receipt, policy, and approvals.
8. **Cross-check the child.** Require canonical summary bytes, exact report and
   source identities, the expected policy pin, and the complete signer-sorted
   submitted approval envelopes.
9. **Reread and publish.** Reopen every staged and caller source, then render
   one path-free, no-clobber outer report.

The v1.477 child receives half of the remaining budget. Fabrication
authorization receives the later remainder minus a bounded cleanup and final
reread reserve. The authorization child gets at most 64 KiB stdout and 1 MiB
stderr; its public report remains separately bounded at 128 MiB.

These checks detect sequential callback-driven substitutions. They do not form
an atomic multi-file filesystem snapshot or defeat an independently concurrent
same-principal writer.

## Outcomes

| Status | Outer gate failures | Meaning |
| --- | --- | --- |
| `release_authorized` | `[]` | Exact routing/DRC/package replay is ready and exact fabrication approval is active |
| `not_authorized` | `routing_drc_manufacturing_not_ready` | Valid routing evidence is incomplete or native DRC rejected it |
| `not_authorized` | `fabrication_not_authorized` | Valid fabrication evidence lacks an active approving quorum |
| `not_authorized` | both failures, in that order | Neither independent gate is positive |

Insufficient quorum, a valid submitted rejection, or an inactive authorization
window remains a valid fabrication `not_authorized` result. The outer CLI
retains that report before `--require-authorized` returns nonzero.

Malformed signatures, mixed scopes, package or policy substitution, invalid
pipeline evidence, an incorrect expected pin, source mutation, child/report
forgery, and deadline or cleanup failure produce no outer report.

## Report contract

The schema-v1 report retains:

- byte count and SHA-256 for the v1.477 report, plan, pipeline report, package,
  receipt, policy, and every signed approval;
- bounded routing and fabrication projections;
- the exact expected canonical policy digest and successful match;
- two independent gate decisions and stable failures;
- eight explicit validation flags; and
- one domain-separated SHA-256 over every preceding field.

The report ends with one LF. It contains no caller path or private key.

## Nonclaims

Only the three decision fields may become true:

- `routing_drc_manufacturing_ready`
- `fabrication_authorized`
- `release_authorized`

These fields always remain false:

- `source_authenticity_verified`
- `toolchain_authenticity_verified`
- `policy_pack_authenticity_verified`
- `factory_receipt_authenticity_verified`
- `manufacturability_verified`
- `external_submission_performed`
- `capacity_reserved`
- `order_placed`
- `payment_performed`
- `challenge_one_time_use_enforced`

The factory receipt is still a normalized unsigned observation. The report
does not authenticate its endpoint, response, quote, factory identity, or
time. It does not prove yield, panelization, signal integrity, current factory
capacity, price, shipping, tax, lead time, or external acceptance.

The selected pcbex and KiCad executables remain caller-controlled,
unauthenticated, and unsandboxed. Distinct signing IDs and keys do not prove
that different natural people control them. Challenge reuse, key custody,
policy distribution, revocation, and handoff-time clock trust remain deployment
responsibilities.

> [!TIP]
> Treat the report as a point-in-time offline release snapshot. Rerun the full
> boundary immediately before any external submission, then hand the exact
> package and report to a separately controlled executor.
