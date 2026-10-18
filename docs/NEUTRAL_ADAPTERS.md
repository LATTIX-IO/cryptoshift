# Gate E1 / FOSS-446 — Neutral adapter fixtures

## Status and trust boundary

Cryptoshift now exposes a **Cryptoshift-owned v1 neutral Rust fixture contract** for cryptographic inventory, graph evidence, source ChangeSets, and source-reported policy evaluations. This is deliberately **not a native Cryptomap or Cryptopolicy interchange implementation**. On the October 18, 2026 integration baseline, Cryptomap's FOSS-316 / FOSS-340–344 shared Cryptoshift handoff was still in Backlog. Cryptopolicy had independently versioned permit/deny/indeterminate evaluation fixtures, but no source-verified Cryptoshift adapter. E1 uses those concepts without claiming its DTOs can deserialize unreviewed upstream formats.

No new runtime dependencies, network clients, cross-repository imports, secret stores, policy enforcement, migration executor, source signatures, independent peer/PKI validation, or release/publishing paths are introduced.

**All source IDs, UTC timestamps and SHA-256 digests are content/version claims, not producer authentication, verified execution or permission to migrate.** A production consumer must independently authenticate and pin the source's digest, identity, policy authority and revision outside this library.

## Neutral inventory and graph projection

`NeutralInventoryInput` names the exact `NEUTRAL_INVENTORY_VERSION = 1` fixture, source, source revision and tenant, with an existing `VersionedEnvelope` of Cryptoshift `CSHIFT01` canonical inventory bytes and typed `GraphNode` / `GraphEdge` facts.

`NeutralInventoryAdapter::project(input, expected_inventory_digest, limits, at_utc)` validates the snapshot using `ValidatedInventorySnapshot::import_verified`, including canonical byte framing, identity and normalization v1, source/tenant references and evidence closure; rejects future source collection observations; and validates the entire graph using `EvidenceGraph::new`. Its `NeutralInventoryPins` contains separate canonical inventory digest, graph fingerprint and source-qualified composite handoff digest.

`NeutralInventoryAdapter::import_pinned(..., independently_expected_pins, ...)` rejects any changed inventory, graph or source/tenant/revision. The fixture producer's own `project` pins do not authenticate that producer; the consumer needs a separate authoritative digest channel.

Classifications remain the exact `CryptoUseKind` variants `ActiveUse`, `LibraryCapability`, `ConfiguredProtocol`, `NegotiatedProtocol` and `Unknown`. A configured protocol does not imply an observed handshake; `DependsOn` is only an operational graph dependency. Evidence remains independent across `EvidenceBasis`, collection runs, `ConflictState` and `CollectionCompleteness`. Scoped `AbsenceRecord` status `Tentative` is never promoted to `Confirmed` by a partial or failed scan.

**Transport limitation:** Canonical inventory bytes have a real validated decoder via `ValidatedInventorySnapshot::import_verified`. The neutral graph metadata projection is an independently bounded **typed Rust fixture DTO**, not a self-deserializing Cryptomap graph wire message. Its composite SHA-256 binds the graph's canonical fingerprint. E2 should test an actual published upstream transport when available rather than guessing its schema here.

## Evidence-backed source ChangeSet

`NeutralChangeSet::new(old_projection, new_projection, NeutralChangeSetInput, limits)` takes separately pinned before/after handoff identities. Both versions must have the same producer/tenant and distinct source revision claims.

Each `NeutralChangeClaim` names a real source run and source-local evidence IDs, plus an exact asset and optional observation. The five kinds are `ObservationAdded`, `ObservationModified`, `ObservationConflicted`, `TentativeAbsent`, `ConfirmedAbsent`.

The adapter verifies observations against the actual prior/current snapshots, forbids future-evidence inheritance and rejects missing source runs, wrong-run evidence, forged additions or modifications, and duplicate events. **Confirmed absence requires a complete current scoped run, a matching current confirmed absence, and an asset observed in the previous snapshot without a current sighting.** An unknown or partial rescan cannot report deletion. The result is an immutable, sorted, digest-identified and bounded export. It is a source-declared **set of changes**: an empty set is not proof that an uninspected asset is unchanged.

The ChangeSet v1 export is canonical length-prefixed binary content for digests and fixtures, not a general-purpose upstream binary importer. No cryptographic removal or migration execution is performed.

## Neutral policy review

`NeutralPolicyInput` carries `NEUTRAL_POLICY_VERSION = 1`, source/policy ID and revision, original source-policy SHA-256, immutable Cryptoshift `TargetProfile` digest, tenant, explicit UTC evaluation/expiry, and per-algorithm `NeutralPolicyDecision` records with `{source_id, evidence_id, source_revision}` evidence triples and opaque reason codes.

The outcomes are `PermitClaimed`, `DenyClaimed` and `Indeterminate`. Their labels deliberately distinguish external policy evaluation **claims** from cryptographic proof of authorization. Source `PermitClaimed` cannot override a target `Forbidden` constraint, cannot permit an undeclared target constraint, and cannot create a new `TargetProfile`. Duplicate decisions, missing source provenance for permit/deny, expired profiles, wrong tenant or changed digests fail closed. Identity-preserving algorithm IDs use the exact recognized FIPS parameter set; unknown aliases are rejected.

`NeutralPolicyReview::gate_for(&trusted_target, algorithm_id)` returns exactly `Prohibited` or `Unverified`, never `Permit`, `Approved` or `Ready`. Denied source or forbidden target yields `Prohibited`; unknown, absent, or claimed permit remains `Unverified`. `import_pinned` additionally checks a separately supplied policy digest and result digest, but cannot establish policy issuer authority.

**Transport limitation:** This is a *typed* fixture surface informed by Cryptopolicy's source outcomes (`permit`, `deny`, `indeterminate`), not a parser of Cryptopolicy's versioned JSON. E2 must add a separately verified mapping for any actual upstream JSON schema and evaluate lossless provenance/unknown behavior.

## Standalone external Cargo consumer

The independently rooted project at `acceptance/neutral-consumer` depends only on `../../crates/cryptoshift`, with its own `[workspace]` and Rust 2024 / Rust 1.85 settings.

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo fmt --manifest-path acceptance/neutral-consumer/Cargo.toml -- --check
cargo run --offline --manifest-path acceptance/neutral-consumer/Cargo.toml
```

Expected consumer lines: `neutral inventory: 1`, `neutral delta claims: 1`, `neutral policy gate: Unverified`. This consumer does **not** use private Lattix services and cannot approve a migration. The GitHub CI job separately runs it under stable Rust and Rust 1.85, alongside release safety, RustSec, cargo-deny and SemVer.

## FOSS-446 SDD test traceability

| Requirement | Source/acceptance | Fail-closed control |
| --- | --- | --- |
| Versioned inventory with exact source, scope, ID and provenance | `neutral_inventory_contract` + external Cargo consumer | Unsupported versions, tampered digest, cross-scope/run and unknown evidence |
| Graph relationship preservation | Typed `EvidenceGraph` projection | Edge, node and evidence closure; graph digest pin |
| Configured vs negotiated | `configured_protocol_and_new_negotiation_are_distinct_observations` | No inferred handshake or Cryptomap readiness |
| Incomplete scans, confirmed/tentative changes | `neutral_inventory_contract` | Partial/failure cannot confirm removals |
| Previous/current ChangeSet digest and version | `neutral_inventory_contract` | Changed source/handoff and repeated event IDs rejected |
| Policy source target coherence | `neutral_policy_contract` + consumer | Wrong target, tenant, expiry or policy digest rejected |
| Deny vs permit vs unknown | `neutral_policy_contract` | Permit never becomes authorization; forbidden policy cannot be overridden |
| Bounded determinism / offline reuse | Canonical fixture exports, replay and tight-budget tests | No network or new dependencies; Rust 1.85 and stable |
| Release integrity | Existing manual release gate | `publish = false` until FOSS-456 |

## Gate E2 handoff

FOSS-448 should broaden the synthetic enterprise conformance corpus across inventory, PKI, protocol and KMS paths, introduce hostile parser/fuzz inputs and platform checks, and integrate authentic **published** Cryptomap / Cryptopolicy handoffs only once upstream contracts are completed and independently reviewed. FOSS-450 can proceed in parallel on atomic diagnostics, independent of these adapter DTOs.

No change in this increment discharges FOSS-441/442 blockers, FOSS-444 residual risks or exception approval gates.
