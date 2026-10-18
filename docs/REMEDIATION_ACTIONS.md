# FOSS-441 — Advisory blocker and remediation analysis v1

Cryptoshift's Gate D1 creates **offline remediation proposals**, not migration execution plans or authorization. It consumes validated inventory, typed graph, SCC dependency topology, source-qualified risk factors, a versioned target and optional immutable FOSS-438 compatibility analyses.

## API and replay boundaries

`RemediationAnalyzer::input_bindings(..., evaluated_at_unix_secs, limits)` computes complete SHA-256 content bindings for inventory, graph, topology, risk report and target. Callers must verify these digests through a **separately trusted channel**. Computing a digest from the same untrusted source is *not* authentication.

`RemediationAnalyzer::analyze(..., &[&CompatibilityAnalysis], pinned, limits)` validates exact graph/inventory/target/risk/topology context, the risk model version, SCC units, observed source evidence and optional compatibility peer node bindings. A compatibility report is bound to *both* participating SCCs. An unverified `Conditional` or `Transitional` result remains a blocker, never proof of mutual interoperability.

`RemediationAnalysis` exposes immutable, stable `BlockerFinding` and nonexecuting `RemediationAction` lists, a complete input-digest record (also copied into each independently extractable blocker/action), bounded canonical bytes, and a SHA-256 export identifier. The writer uses `CSHIFT_REMEDIATION_REPORT_V1` domain separation. Finding and action identities rotate with content changes.

## Blockers, provenance and ownership

- Missing/ambiguous accountable owners are reported from actual `OwnedBy` graph edges with their exact inventory source/run/evidence IDs, not selected automatically.
- All ten risk factors remain distinct; unknown, assumed, or elevated factors require separate risk review. A score cannot override a missing or assumed factor.
- Compatibility findings retain their typed reason and original `source_id,evidence_id,source_revision` triples. Inventory evidence retains `source_id,run_id,evidence_id`; external risk assessment references remain opaque, never assigned a fabricated publisher.
- Unsigned handshake receipts, vendor-roadmap statuses, missing PKI/revocation proof and unapproved downgrade claims remain blocking.
- `DependsOn` means **operational prerequisite**, not demonstrated protocol communication. Without an explicitly supplied, scope-bound `CompatibilityAnalysis`, D1 never invents a peer handshake, PKI chain, or `PeerCompatibilityMissing` finding for a dependency edge; the source-attributed `DependencyGate` is still retained. Explicit peer requirements must be introduced with their own trusted contract in a future increment.
- Two exact peer endpoint identities may have separate candidate profiles, protocols or roles. Their coexistence alone is not an evidence contradiction; only source-qualified `CompatibilityCode::EvidenceConflict`/`CapabilityConflict` findings can establish that condition.
- Only an explicitly applicable target deadline is shown, preserving the deadline's separate source reference rather than conflating it with the target-document provenance. No release date, effort estimate, chosen product upgrade, policy exception or new hybrid combiner is invented.
- `RemediationActionKind::ReviewUnitGate` (gate `RemediationGate::ReviewUnitReadiness`) is an *action to request human evaluation*, never a declaration of `Ready`. It depends on all blocker actions in its own SCC plus prerequisite unit gate actions. Cycles collapse to one indivisible SCC before action planning.
- `change_approval_required`, `maintenance: ReviewedWindowRequired` and `rollback: ReviewedPlanRequired` on unit gates encode future procedural requirements, not approval itself.

The library performs no I/O, PKI verification, product scanning, lifecycle changes, network connections or maintenance operations.

## Acceptance

Run in the root workspace:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo run -p cryptoshift --example remediation_actions --locked
```

Integration contract tests (`tests/remediation_contract.rs`) cover missing owners, SCC cycles and prerequisite gates, source-backed peer evidence, unsafe fallbacks, model/tenant/digest mismatch, risk score tampering, opaque risk evidence, output determinism, target deadline handling, bounded action/diagnostic/export budgets, and frozen canonical export. CI also runs MSRV 1.85, RustSec, cargo-deny and cargo-semver-checks.

## Current limitations and D2 handoff

D1 does **not** build migration waves, approve residual risk, authenticate external evidence, decide when systems are Ready, prepare infrastructure patches or publish the crate. FOSS-442 must consume blockers, verification gates, and unit gate action dependencies to produce a bounded wave plan with explicit readiness conditions and independent review.

The existing repository release guard (`publish = false`) remains unchanged. FOSS-456 remains the publication gate.
