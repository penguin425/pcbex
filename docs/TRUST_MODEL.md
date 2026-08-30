# Trust model

`pcbex` makes strong claims about deterministic computation and exact artifact
identity. It makes narrower claims about external tools, network observations,
human decisions, and real-world side effects.

Use this guide to identify the boundary you have, the boundary you still need,
and the assumptions your deployment must supply.

## The central rule

**Evidence records what a bounded verifier observed. Authority decides what may
happen next.**

A routed board, clean DRC report, valid signature, and procurement authorization
answer different questions. Combining them requires explicit cross-binding; a
consumer must not promote one result into another kind of claim.

## Claim matrix

| Artifact or boundary | Establishes | Does not establish |
| --- | --- | --- |
| Internal board check | Deterministic findings for one validated board model | KiCad parity, manufacturability at a selected factory, or electrical correctness |
| Routing convergence verification | Fresh reproduction of one retained bounded decision plus exact routed JSON/KiCad bytes and captured source identities | Source authenticity, native KiCad DRC, manufacturability, global optimality, or release authority |
| Routing/manufacturing handoff | The freshly verified routed KiCad board and shared sidecars reproduce one exact retained manufacturing ZIP | Source or tool authenticity, separate native DRC evidence, manufacturability, fabrication approval, or release authority |
| Routing/native-DRC/manufacturing handoff | The exact v1.476 handoff and normalized native DRC report freshly replay against one routed board and companion set | Source/tool authenticity, manufacturability, fabrication approval, external submission, or release authority |
| Policy-pinned routing/DRC fabrication release | One exact v1.477 package also satisfies a factory-required pipeline and dedicated fabrication quorum under an expected canonical policy digest | Source/tool/policy/receipt authenticity, manufacturability, external submission, capacity, order, payment, or one-time challenge use |
| Executable-pinned fabrication release | One retained v1.478 evidence/approval subject was freshly reassessed while three resolved native entrypoint byte streams matched independent deployment SHA-256 pins | Historical decision reuse, executable origin/signatures, libraries, plugins, loader/OS state, full toolchain provenance, sandboxing, same-principal race exclusion, or external factory effects |
| Signed factory-receipt release | One exact normalized receipt and package were signed by the dedicated factory key selected by an externally pinned policy, around a fresh v1.479 replay | Factory legal identity, TLS/raw-response authenticity, trusted time, current capacity, submission, order, payment, or one-time use |
| Signed release reservation marker | One selected local Unix ledger admitted one freshly authenticated v1.480 signed challenge without replacement | Global uniqueness, cross-host coordination, trusted time, capacity, submission, order, payment, or exactly-once execution |
| Signed factory-release adapter receipt | One durable local intent produced one bounded POST attempt or one GET reconciliation observation, bound to the reserved release and exact ZIP | Server-side idempotency enforcement, legal factory identity, transport/raw-response authenticity, capacity, order, payment, or exactly-once execution |
| Authenticated factory-release response report | One exact adapter response status, JSON body, and covered request context verified under a factory/provider key from an externally pinned policy | Trusted time, TLS or legal identity, key custody, server-side idempotency, capacity, order, payment, or exactly-once execution |
| Monotonic factory-release state chain | Every retained signed state links from genesis to the selected local head without rollback, equivocation, gaps, forks, identity changes, or terminal mutation | Global non-equivocation, rollback resistance for the selected ledger, trusted time, capacity, order, payment, or exactly-once execution |
| Factory-release state transparency report | The exact fully verified current state appears in one fresh-at-evaluation Ed25519-signed Merkle view selected by a separately pinned policy | Global non-equivocation, consistency between tree heads, ledger rollback resistance, trusted time, transport/legal identity, order, payment, or exactly-once execution |
| Factory-release transparency consistency report | Two fully reverified views from the same policy-pinned log have valid signatures and an RFC 6962-shaped proof that the newer tree strictly extends the retained tree; every selected-ledger predecessor back to one v1.485 anchor was reloaded | Global non-equivocation across observers, selected-ledger rollback resistance, trusted time, transport/legal identity, order, payment, or exactly-once execution |
| Factory-release transparency witness quorum | Distinct configured organization, witness, and key tuples met an externally pinned threshold by signing one exact latest v1.486 report and embedded tree head | Global non-equivocation, real organizational independence or legal identity, selected-ledger rollback resistance, trusted time, transport identity, order, payment, or exactly-once execution |
| Factory-release transparency external anchor | The exact latest v1.487 witness-quorum report appears in one fresh-at-evaluation signed Merkle view selected by a separate externally pinned log policy | Append-only consistency or global non-equivocation for the external log, selected-ledger rollback resistance, trusted time, real organizational independence, transport/legal identity, order, payment, or exactly-once execution |
| Factory-release transparency external consistency | Every selected signed external view strictly extends the retained v1.488 anchor or exact preceding v1.489 head under one pinned log key and bounded RFC 6962-shaped proof | Global non-equivocation across independent observers, selected-ledger rollback resistance, trusted time, real organizational independence, transport/legal identity, order, payment, or exactly-once execution |
| Factory-release transparency external gossip | One separately pinned observer signed an authenticated external-log head that is identical to, precedes, or consistently extends the exact latest v1.489 head; same-size divergent roots are rejected | Global non-equivocation beyond the selected views, observer quorum, real organizational independence or key custody, selected-ledger rollback resistance, trusted time, transport/legal identity, order, payment, or exactly-once execution |
| Factory-release transparency external gossip quorum | Bounded remote observations and hash-bound transport receipts were replayed against the exact latest v1.489 head, and a policy-pinned threshold of distinct organization/observer/key tuples agreed on one exact signed external head | Global non-equivocation beyond the selected views, real organizational independence or key custody, selected-ledger rollback resistance, trusted time, endpoint/legal identity, server idempotency, order, payment, or exactly-once execution |
| Factory-release external-gossip observer rotation | Every current observer key derives from its immutable base-policy member through a complete selected-ledger chain of exact one-generation, digest-linked, old/new dual-signed transitions; the durable v1.491 quorum embeds the resulting exact effective policy | Host-ledger rollback resistance, global non-equivocation, trusted time, real organizational independence or key custody, endpoint/legal identity, order, payment, or exactly-once execution |
| Factory-release external-gossip organization registry and authority rotation | One independently pinned genesis starts a complete selected-ledger transition/rotation history; every authority handoff has old/new Ed25519 signatures, never reuses a historical authority key, remains role-disjoint from observer history, and preserves active exact v1.492 admissions | Threshold authorization, host-ledger rollback resistance, global non-equivocation, trusted time, real organizational independence or key custody, factory/legal identity, order, payment, or exactly-once execution |
| Factory-release external-gossip registry threshold governance | One retained-root-signed policy fixes 2–100 distinct administrator keys and a threshold of at least two; every post-activation decision carries enough valid distinct-key approvals, mixed history replays from pinned genesis, and root-only mutation is locked out | Independent human or organization control of keys, governance rotation, host-ledger rollback resistance, global non-equivocation, trusted time, legal identity, order, payment, or exactly-once execution |
| Factory-release external-gossip registry governance rotation | One root-signed successor policy binds the exact active registry state, and both the retained and successor policies satisfy their own distinct-key threshold over one next-generation handoff before the active digest changes | Independent governance control, registry-root rotation, host-ledger rollback resistance, global non-equivocation, trusted time, legal identity, order, payment, or exactly-once execution |
| Factory-release external-gossip governed registry-root rotation | A distinct prospective root signs successor governance for the exact active state, and retained plus successor governance quorums approve one payload before root and active governance change atomically; complete five-event replay rejects historical root reuse | Independent governance control or key custody, host-ledger rollback resistance, global non-equivocation, trusted time, legal identity, order, payment, or exactly-once execution |
| Portable factory-release external-gossip registry history audit | The supplied exact empty genesis and every typed event artifact replay through the production verifiers into one deterministic final registry; per-event exact and semantic identities bind the audited chain | Proof that the supplied generation is the selected latest head, host-ledger rollback resistance, global non-equivocation, trusted time, independent organization/key control, legal identity, order, payment, or exactly-once execution |
| Witnessed factory-release external-gossip registry history checkpoint | The retained final root signs one exact portable-history audit and computed registry; a retained baseline rejects rollback, same-generation equivocation, and nonextending histories, while 2–100 fresh distinct witness keys endorse the exact checkpoint without reusing registry-root or governance keys | Rollback resistance if the baseline is lost or replaced, global non-equivocation among consumers that do not compare heads, trusted time, independent people or legal organizations, secure key custody, order, payment, or exactly-once execution |
| Factory-release registry-history checkpoint witness rotation | One retained identity-bound trust state advances exactly one generation only when its current and successor Ed25519 keys sign the same domain-separated, predecessor-linked rotation; quorum verification resolves the current key and rejects stale trust as substitution | Rollback resistance if the witness trust state is lost or replaced, proof that different keys have independent custodians, trusted time, global non-equivocation, legal identity, order, payment, or exactly-once execution |
| Remote factory-release registry-history checkpoint witness | One explicit no-redirect HTTPS POST sends the accepted checkpoint trust state, bounds the response to 1 MiB and the deadline to 1–600 seconds, then retains a canonical witness and hash-bound receipt only after replaying the exact complete local history and verifying freshness, checkpoint binding, the selected direct or rotatable key, and separation from every historical root/governance role | Trusted time, protected local history or trust-state storage, endpoint legal identity, operational independence, global non-equivocation, external signature or publication of the local transport receipt, capacity, order, payment, or exactly-once execution |
| Factory-release registry witness receipt transparency | One canonical v1.501 receipt passes closed structural validation and its exact normalized receipt, checkpoint, request, response, and witness identities enter a signed append-only log that can reuse existing anchor, consistency, gossip, and witness controls | Re-verification of retained history, checkpoint trust, exact response bytes, or witness signature during append; protected log storage; trusted time; endpoint or receipt authenticity; global publication or non-equivocation; independent operation; legal identity; order, payment, or exactly-once execution |
| Verifier-bound factory-release registry receipt admission | One dedicated append path independently replays the canonical complete history, reconstructs retained checkpoint trust and request bytes, matches the exact retained response, requires direct or current generation-bound witness trust, and re-verifies freshness, role separation, and the Ed25519 signature before publishing the unchanged normalized receipt event | Multi-receipt admission quorum; an atomic snapshot across same-principal input files; protected history, trust-state, response, or log storage; trusted time; endpoint or receipt authenticity; global publication or non-equivocation; independent operation; legal identity; order, payment, or exactly-once execution |
| Verifier-bound factory-release registry receipt admission quorum | One complete history/checkpoint context and every exact receipt, response, and direct or generation-bound key source are independently reverified; a configurable 2–100 threshold requires distinct identities, keys, receipt/response/witness digests, then binds the canonical member set to the exact resulting log | An atomic same-principal filesystem snapshot; protected history, trust-state, response, report, or log storage; trusted time; proof of organizational independence; endpoint or legal identity; global publication or non-equivocation; order, payment, or exactly-once execution |
| Quorum-bound factory receipt-log signing | A dedicated gate validates a met canonical report, the complete approval-log chain and exact ID/count/head/digest, plus every ordered factory-receipt suffix binding before reading the private key and emitting the unchanged generic checkpoint format | Re-verification of raw history, receipts, responses, trust states, or witness signatures at signing time; protected report, log, or key storage; a receipt-quorum-specific signature domain; trusted time; independent operation; global publication or non-equivocation; order, payment, or exactly-once execution |
| Domain-separated factory receipt-quorum checkpoint | One trusted Ed25519 key signed the exact normalized quorum-report digest, registry checkpoint, threshold/result, approval-log identity/count/head/digest, and signer under the factory receipt-quorum domain; generic or approval-registry checkpoint signatures cannot substitute | Re-verification of raw history, receipts, responses, trust states, or witness signatures at checkpoint time; protected files or keys; independent checkpoint witnesses; trusted time; independent operation; global publication or non-equivocation; order, payment, or exactly-once execution |
| Independent factory receipt-quorum checkpoint witness quorum | Every supplied witness independently reverified the exact successful report/log/suffix and trusted dedicated checkpoint before signing its exact checkpoint/log identity; 2–100 fresh distinct configured keys met the threshold without reusing the checkpoint signing key | Proof of separate people, organizations, systems, or key custody; generation-chained witness trust; protected files or keys; trusted time; global publication or non-equivocation; legal identity; order, payment, or exactly-once execution |
| Factory receipt-quorum checkpoint witness rotation | One retained identity-bound trust state advanced exactly one generation after the current and successor Ed25519 keys signed the same domain-separated, predecessor-linked transition; the unchanged witness quorum resolved only the current trusted key | Rollback resistance if retained trust is lost or replaced; proof of independent operators or key custody; protected files or keys; trusted time; global publication or non-equivocation; legal identity; order, payment, or exactly-once execution |
| Remote factory receipt-quorum checkpoint witness | Exact public report/log/checkpoint evidence passed the local dedicated-checkpoint verifier before one no-redirect HTTPS request; the canonical response then passed the unchanged witness signature, freshness, key-role, and direct/current-trust checks, and a credential-free receipt bound the exchange | Protected local files, trust states, or keys; trusted time; endpoint legal identity or availability; proof of independent operation; global publication or non-equivocation; transport-receipt signature; order, payment, or exactly-once execution |
| Factory checkpoint-witness receipt transparency | One canonical v1.509 receipt passes closed structural validation and its exact normalized receipt, checkpoint, request, response, and witness identities enter the existing signed append-only log with unchanged anchor, consistency, gossip, and witness controls | Replay of the receipt-quorum report, approval log, dedicated checkpoint, response, witness signature, or current trust during append; protected log state; trusted time; endpoint or receipt authenticity; global publication/non-equivocation; independent operation; legal identity; order, payment, or exactly-once execution |
| Verifier-bound factory checkpoint-witness receipt admission | One dedicated append path replays the exact quorum report, complete approval log and factory-domain checkpoint, reconstructs the compact request, matches the raw response, requires direct or current generation-bound witness trust, and re-verifies freshness, role separation, and the Ed25519 signature before publishing the unchanged normalized event | Multi-receipt admission quorum; an atomic snapshot across same-principal inputs; protected evidence, trust, or log storage; trusted time; endpoint or receipt authenticity; global publication/non-equivocation; independent operation; legal identity; order, payment, or exactly-once execution |
| Verifier-bound factory checkpoint-witness receipt admission quorum | One shared report/log/checkpoint context is production-verified once; every exact receipt, response, and uniform direct or generation-bound trust source is independently bound; the production witness quorum enforces a configurable 2–100 threshold, freshness, role separation, and distinct identities and keys; duplicate receipt/response/witness digests fail; and a canonical report binds the sorted unchanged event suffix to the resulting log | An atomic same-principal snapshot or globally atomic two-file commit; protected evidence, trust, key, report, or log storage; trusted time; proof of operator independence; endpoint or legal identity; global publication or non-equivocation; order, payment, or exactly-once execution |
| Quorum-bound factory checkpoint-witness receipt-log signing | A dedicated gate validates a met canonical v1.512 report, the complete admission-log chain and exact ID/count/head/digest, plus every sorted checkpoint-witness receipt suffix binding before reading the private key and emitting the unchanged generic checkpoint format | Replay of raw receipts, responses, report inputs, dedicated checkpoint, witness signatures, or trust states at signing time; protected report, log, state, or key storage; a dedicated signature domain; trusted time; independent operation; global publication or non-equivocation; order, payment, or exactly-once execution |
| Domain-separated factory checkpoint-witness receipt-quorum checkpoint | One trusted Ed25519 key signed the normalized v1.512 report digest, registry checkpoint, prior factory receipt-quorum checkpoint, threshold/result, and exact admission-log state under a new checkpoint-witness receipt-quorum domain; generic and v1.506 signatures cannot substitute | Replay of raw receipts, responses, witness signatures, or trust states at checkpoint time; protected files or keys; trusted time; independent operation; global publication or non-equivocation; legal identity; order, payment, or exactly-once execution |
| Independent factory checkpoint-witness receipt-quorum checkpoint witness quorum | Every supplied witness reverified the exact successful v1.512 report, complete admission log and suffix, trusted v1.514 checkpoint, and checkpoint key before signing the exact checkpoint/log identity; 2–100 fresh distinct configured keys met the threshold without reusing the checkpoint signing key | Proof of separate people, organizations, systems, or key custody; generation-chained witness trust; protected files or keys; trusted time; global publication or non-equivocation; legal identity; order, payment, or exactly-once execution |
| Native KiCad ERC/DRC report | Normalized output from the selected staged KiCad invocation | Authenticity or safety of the KiCad executable, plugins, or host |
| Manufacturing package | Canonical staged outputs and source/profile identity after the package gates pass | Factory acceptance, assembly success, or order placement |
| Provider or factory receipt | Bounded response bytes plus declared transport observations | Truth, currentness, endpoint identity beyond the adapter contract, or future availability |
| Signed approval | A policy-mapped key signed one exact payload | Signer presence, independent natural persons, key custody, or absence of withheld rejection |
| Fabrication authorization | Exact evidence met a retained human release policy | Machine execution, inventory, payment, or one-time challenge consumption |
| Procurement authorization | Exact covered component lines met policy at one retained local instant | Supplier authenticity, current stock, reservation, landed cost, order, or payment |
| Procurement reservation marker | One selected local ledger admitted one freshly replayed challenge without replacement | Global one-time use, immutable same-UID custody, supplier inventory, order, payment, or exactly-once execution |

> [!WARNING]
> A cryptographically valid artifact can still be operationally inappropriate.
> Verify the trust root, time model, evidence freshness, signer custody, and
> intended handoff before acting on it.

## Determinism

The core uses validated typed inputs, integer geometry, deterministic ordering,
and explicit work budgets. Equivalent accepted inputs on the documented engine
surface produce reproducible logical results.

Determinism does not freeze the operating system, filesystem, current clock,
third-party executable, network, or caller-selected provider. Focused replay
contracts capture and compare those observations where required.

## File and process boundaries

Rust and Python readers bound file sizes, reject unsafe file types and link
components, verify stable identity, and reread sensitive inputs. Publishers use
staged atomic replacement or no-clobber commits according to each artifact's
contract.

Child processes run without a shell, with bounded input, output, time, and
process-tree cleanup. These controls are not an OS sandbox, and a set of
multiple published files is not automatically one filesystem transaction.

An independently concurrent same-principal writer may still race sequential
checks on platforms or filesystems where stronger primitives are unavailable.
Run mutually untrusted tools under separate OS isolation.

Read [CLI I/O Limits](CLI_IO_LIMITS.md) and
[Python Agent Limits](PYTHON_AGENT_LIMITS.md) for exact ceilings and residuals.

## External executables

`kicad-cli`, provider commands, factory repair wrappers, and replay binaries are
selected by the deployment. `pcbex` can constrain invocation and validate
outputs, but it does not attest executable provenance or sandbox the process.

Pin and verify binaries outside pcbex. Use containers, virtual machines, or
separate accounts when a tool must not share filesystem or network authority
with the verifier.

## Network observations

Factory and supplier adapters can retain exact response bytes, hashes, status,
and bounded timing observations. Those records support replay and correlation;
they do not turn an unsigned response into an authenticated commercial promise.

The v1.483 response boundary can verify an RFC 9421 application signature and
RFC 9530 body digest under an externally pinned key. TLS configuration,
endpoint ownership, legal identity, trusted timestamping, availability,
lifecycle, lead time, and price authenticity still require separate trust
contracts. Supplier coverage remains a component-line correlation, not a
landed-cost or order-readiness calculation.

## Signatures and policy

Ed25519 verification proves that a matching private key signed the exact
domain-separated payload. Policy packs map trusted public keys to roles,
thresholds, limits, and bounded scope.

The verifier cannot prove that two keys belong to two natural people, that a
signer was present, or that a key was stored safely. Custody, identity proofing,
revocation distribution, and separation of duties remain organization controls.

An externally pinned key or canonical policy digest prevents caller-selected
substitution only when the pin itself comes from a protected configuration.
The artifact cannot bootstrap trust in its own root.

## Time and replay

Some decisions retain a local evaluation instant and compare it with declared
windows. Unless a focused contract says otherwise, the clock is not a trusted
timestamp service and a remote observation time is not authenticated.

A retained authorization is an audit snapshot. Freshly replay the complete
verifier at the actual release handoff when current policy, inputs, or windows
matter. A local reservation marker adds ledger-scoped admission, not current
supplier state or an external execution result.

Random challenges bind approvals to an exact scope. A stateless verifier does
not enforce one-time use; use a trusted reservation ledger or execution system
when replay prevention is required.

## Negative evidence and hard failure

Many gates distinguish two outcomes:

- **Valid negative:** The inputs are well-formed and cross-bound, but policy is
  not satisfied. The command may retain a rejected report before an optional
  `--require-*` gate exits unsuccessfully.

- **Hard failure:** An input is malformed, unsafe, oversized, aliased, mutated,
  incorrectly signed, or bound to different evidence. The command publishes no
  trusted report.

This distinction keeps policy rejection inspectable without laundering invalid
data into a normal decision artifact. The focused contract defines the exact
classification for each command.

## Operational responsibilities

Your deployment must decide and enforce:

- which pcbex binary, KiCad installation, provider, and helper are trusted;
- which public keys and policy digests form the trust root;
- how private keys are generated, stored, rotated, and revoked;
- whether local time is sufficient for the decision;
- where network access is permitted and how endpoints are authenticated;
- how approved handoffs become reservations, orders, payments, or machine work;
- how one-time execution and crash recovery are recorded; and
- which retained evidence must be freshly replayed before action.

## Find the exact contract

| Boundary | Contract |
| --- | --- |
| Native schematic ERC | [Native KiCad ERC](NATIVE_KICAD_ERC.md) |
| Native board DRC | [Native KiCad DRC](NATIVE_KICAD_DRC.md) |
| Routed board to manufacturing ZIP | [Fresh Routing-to-Manufacturing Handoff](ROUTING_MANUFACTURING_HANDOFF.md) |
| AI review | [AI Review Artifact Binding](AI_REVIEW_ARTIFACT_BINDING.md) |
| Manufacturing | [Manufacturing Package](MANUFACTURING_PACKAGE.md) |
| Factory submission | [Factory Connector](FACTORY_CONNECTOR.md) |
| Hardware pipeline | [Pipeline Gate](PIPELINE_GATE.md) |
| Fabrication decision | [Fabrication Authorization](FABRICATION_AUTHORIZATION.md) |
| Supplier observation | [Supplier Offer Acquisition](SUPPLIER_OFFER_ACQUISITION.md) |
| Supplier correlation | [Supplier Offer Coverage](SUPPLIER_OFFER_COVERAGE.md) |
| Procurement decision | [Procurement Authorization](PROCUREMENT_AUTHORIZATION.md) |
| Procurement local admission | [Procurement Authorization Reservation](PROCUREMENT_AUTHORIZATION_RESERVATION.md) |

Report security issues through the private process in the repository
[Security Policy](../SECURITY.md).
