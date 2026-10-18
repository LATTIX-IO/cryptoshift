# FOSS-442 - Bounded SCC wave planning and review gates

Gate D2 constructs an offline **advisory candidate sequence**, never an authorized migration plan. No network scanners, PKI validation, external approval issuance, workload changes, or publishing.

## Public API

WavePlanner::input_bindings(topology, remediation, target, limits) constructs independent input content identities: D1 inventory/graph/topology/risk/target digests, immutable D1 report digest, the exact compatibility_set_digest from peer evidence and scope. The caller MUST authenticate those expected content identities independently; calculating the hashes from the same untrusted inputs is not authentication.

WavePlanner::plan(topology, remediation, target, request, limits) returns immutable WavePlanDraft, with waves(), readiness(), bindings(), digest() and bounded export(). WavePlanRequest supplies schema version, capacity_systems_per_wave, max_waves, expected_bindings, and submitted_for_review_units.

MigrationWave reports one-based ordinal, sorted SCC unit IDs, and occupied SYSTEM slots. A two-system SCC needs two slots and cannot be split. UnitReadiness reports system IDs, exact FOSS-441 blocker/action IDs, original provenance-qualified evidence, direct SCC prerequisites, source-qualified deadline, owner claim and pending gates.

## No implicit trust or readiness

All precedence comes from FOSS-422 DependencyTopology. A DependsOn edge is an **operational prerequisite, not evidence that two systems communicate cryptographically**. Prerequisites must appear in strictly earlier waves. Independent SCC candidates may share a wave under capacity; after a wave closes, newly unlocked candidates can be placed in the next wave. Kahn scheduling and deterministic lexical tie-breaking avoid combinatorial searches. No provider, trust-anchor or client/server relationships are guessed.

UnitReadinessStatus values:

- Blocked: explicit policy prohibition, attributed conflict, or blocked predecessor.
- Unverified: unresolved D1 source evidence, ownership, negotiation/PKI/vendor requirement, or upstream external approval.
- EligibleForReview: no known D1 blocker or upstream constraint; external review still required.
- AwaitingExternalApproval: an untrusted claim that an otherwise eligible unit was submitted for human review; still not an approval.

submitted_for_review_units is a **workflow hint**. It can NEVER discharge, authenticate or override a blocker. Every unit retains IndependentUnitReview, ChangeApproval, MaintenanceWindow and RollbackPlan gates derived from its D1 ReviewUnitGate. All are outstanding and do not assert operational Ready. FOSS-438 Conditional/Transitional observations remain nonauthoritative.

Every D2 result pins FOSS-441 source bindings and the compatibility-set digest independently. Replayed risk, inventory, graph, target, negotiated peer evidence, D1 report, ownership or cross-tenant content is rejected when it differs from the caller's independently trusted pins. Source-defined deadlines are reproduced but never override SCC ordering or safety policy.

Any indivisible SCC exceeding wave system capacity, infeasible maximum-wave limit, foreign/missing prerequisites, expired target, duplicate review claims, incomplete D1 review controls, insufficient evidence/action budget or output-size limit must fail without a partial result.

## Developer verification

Run from the repository root:

    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-features --locked
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
    cargo run -p cryptoshift --example wave_plan --locked

Tests in crates/cryptoshift/tests/wave_contract.rs cover 3-unit chain and branching DAG, multi-system SCC, bounded capacity and waves, explicit approval/rollback gates, monotonic failed evidence, source deadline precedence, replayed inputs, schema, resource budgets, deterministic output, and a frozen version-one SHA-256 binary fixture. The existing CI independently checks Rust 1.85 MSRV, release safety, RustSec, cargo-deny and SemVer.

## D3 handoff and exclusions

D2 produces no authenticated approval receipts, risk waivers, verification of chain/revocation/negotiated protocols, operational readiness, change tickets, migration execution or deployment instructions. FOSS-444 supplies the immutable MigrationPlan and exception/residual risk lifecycle. The Rust crate remains publish = false; FOSS-456 controls any crates.io publication.
