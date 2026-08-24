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
