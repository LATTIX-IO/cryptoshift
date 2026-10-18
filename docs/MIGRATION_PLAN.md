# FOSS-444 — Immutable MigrationPlan and nonauthoritative exceptions

**Gate D3** consolidates Cryptoshift's validated inventory, graph, risk, desired PQ target, peer evidence, blocker/actions and dependency-safe candidate waves into one auditable draft. It is **not** a migration execution plan or permission to deploy. All inputs remain offline and potentially untrusted.

## Version-one public contracts

- `MigrationPlanner::input_pins(topology, remediation, wave, target, capability_catalogs, score, limits)` computes the complete `PlanSourcePins` tuple. It validates that D1, D2, topology and target describe one exact scope/revision, checks catalog scope and evidence freshness at D1's explicit time, and canonicalizes order-independent catalog sources. Consumers must compare the returned pins to **independently trusted** pins; calculating hashes from the same untrusted inputs does not authenticate them.
- `MigrationPlanner::build(..., MigrationPlanRequest, limits)` compares every expected pin before emitting an immutable `MigrationPlanDraft`. No partial outputs are returned for mismatched, stale or oversized inputs. The plan exposes its pinned inputs, nonauthoritative status, unchanged D2 waves/readiness gates, exact D1 blocker/action IDs, residual-risk facets, exception requests, SHA-256 identifier and bounded canonical export.
- `PlanSourcePins` includes inventory/graph/SCC topology/risk/target hashes, FOSS-441 remediation hash, FOSS-438 combined compatibility-set hash, FOSS-442 wave hash, explicit tenant and evaluation time, the standards catalog version and exact editions, canonical capability-catalog ID/revision/hash set and optional scoring-profile ID/version/hash of all ten weights.
- `PlanAssessmentState` has `Blocked`, `Partial`, `ExternalApprovalPending`, and `CompleteEvidenceForReview`. **None** means Ready, Approved, AcceptedRisk, authenticated interoperability or authorized rollout. Invalidated/stale inputs are typed errors rather than an apparently usable plan in an invalid state.

## Source citations and risk

Every `ResidualRiskFacet` has a typed risk/approval category, the exact SCC (if any), original D1 blocker/action IDs where applicable, the original inventory, external capability, compatibility or exception source/evidence/revision tuple, required verification gates and source-defined deadline if present. Source evidence is attributable **not authenticated**.

The risk register preserves policy/quantum/context issues, missing owner, peer/PKI uncertainty, vendor availability, dependency prerequisites, data-quality gaps, explicit change approval, maintenance and rollback requirements. `DependsOn` is an operational prerequisite only; it cannot establish a cryptographic handshake. Unsatisfied `Unverified` and `Blocked` D2 units stay unresolved in D3. No residual-risk facet supplies a guessed probability or treats unknown risk as zero.

D3 treats each provided capability claim as unverified by this library, even if the host or catalog declares `DeployedAndVerified`. The absence of a catalog is explicitly a missing-capability-evidence facet. A named scoring profile is content-bound metadata, not independent proof of the upstream risk assessment's authority.

## Exception requests — never an approval

`PlanExceptionRequest` must identify the exact tenant, indivisible SCC, existing target constraint (algorithm ID, protocol ID or certificate profile), unique bounded source record ID, a matching **claimed** accountable D1 owner, original justification reference, request time, expiry and optional `ClaimedExceptionApproval` (issuer/receipt/revision/time).

Accepted/Approved is deliberately **not** a `PlanExceptionState`. The only outputs are `Requested`, `ClaimedApprovalUnverified` or `Expired`. A receipt is just a source claim; Cryptoshift does not verify signature, certificate authority, approver identity, authorization scope, independence of governance powers or risk acceptance. Self-issued claims, unknown owner/tenant/target scope, future claims, invalid expiry and duplicate IDs are rejected. Expired or purported approval records **never** discharge D1 blockers, D2 unit readiness gates, change approval, maintenance windows, PKI, peer proof, rollback conditions or prohibited classical downgrade.

The requester/owner name match enforces *scope consistency*, not authenticated ownership. Only a separately built and reviewed authority verifier could elevate an external approval receipt; such a verifier is **out of scope** for D3.

## Semantic diffs and replay

`MigrationPlanDraft::semantic_diff(next,limits)` returns typed changes in scope/time, inventory, graph, topology, risk, target, remediation, peer evidence, candidate wave, standards, capabilities, scoring, unit state, blocker/action IDs, residual facets and exceptions. It includes changed SCC/blocker/action/exception/facet IDs. Reordered equivalent inputs produce identical bytes; changing one material input or claimed approval rotates the complete plan digest and yields an explainable diff.

Version-one output is domain-separated `CSHIFT_MIGRATION_PLAN_V1` with checked length-prefix encoding and SHA-256 content identity. It never copies secret evidence payloads: only user-supplied **opaque references** are recorded. Callers must keep credentials, PII and secret material out of reference identifiers because references **are exported**. D1/D2 pinning is revalidated on every build, and old authorization assertions cannot be reused after a changed compatibility proof.

## Verification commands

From the workspace root:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo run -p cryptoshift --example migration_plan --locked
```

The regression suite covers digest substitution, tenant/owner/target constraints, claims versus authorizations, replay, claim and catalog ordering, expired exceptions, malformed time and forged receipts, plan diffs, cyclic SCC preservation, residual-risk provenance, limits, canonical SHA-256 fixture and a runnable offline consumer.

CI also requires Rust 1.85 MSRV, RustSec, cargo-deny, SemVer compatibility, release safety and no unsafe code.

## Remaining limitations and E1 handoff

D3 does not perform network discovery, source attestation, cert chain validation, trusted exception acceptance, migration execution, rollout scheduling, production readiness approval or crates.io publishing. Some FOSS-438 compatibility results remain inherently conditional/unverified. FOSS-446 must exercise cryptomap and cryptopolicy neutral adapter fixtures without discarding provenance or converting untrusted assertions to approvals; FOSS-450 strengthens atomic diagnostics. Publishing remains `publish = false` until explicit FOSS-456 gates.
