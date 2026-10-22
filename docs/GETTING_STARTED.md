# Cryptoshift v1: Developer Guide

Cryptoshift is an offline, evidence-bound Rust library for **advisory** cryptographic migration planning. Its planned post-quantum transition stages are deterministic and source-pinned. It does not scan your environment, encrypt data, authenticate vendors or operators, modify workloads, publish packages, or grant permission to migrate.

## Build and Inspect

The package is currently unpublished and the Cargo manifest deliberately contains `publish = false`. From a clean Git checkout with Rust 1.85 or newer:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo run -p cryptoshift --example migration_plan --locked
```

The example constructs one synthetic inventory snapshot, a directed evidence graph, and a scoped target, then computes SCC topology, cryptographic risk, remediation blockers, nonauthorizing waves, and an immutable plan. It runs the same fixture through `AnalysisRunner::analyze` and requires the atomic plan digest to equal the manually composed plan digest. It also checks a forged graph source pin is rejected **without a partial plan**.

Expected behavioral lines include:

```text
migration plan state: Partial
readiness: Unverified
atomic analysis state: Partial
forged graph pin: Failed
This is not an authorization to execute, migrate, or approve changes.
```

Do not interpret `Partial` as a failed test: it correctly records missing owner/capability evidence and authority. `Complete`, `Warnings`, and the associated external-review classification remain reserved in v1 because this library cannot independently authenticate those facts. Those states must not be synthesized from unverified claims.

## Public API Boundaries

| Stage | Entry point | Contract |
|---|---|---|
| Source admission | `ValidatedInventorySnapshot`, `NeutralInventoryAdapter` | Scoped, bounded, versioned source facts; not collector authentication |
| Graph | `EvidenceGraph` | Typed, evidence-bound edges, canonical fingerprint |
| Dependencies | `DependencyAnalysis::analyze` | Iterative SCCs and prerequisite-first order |
| Risk | `RiskAnalysis::analyze` | Evidence-qualified factor vector, not an authorization score |
| Desired state | `TargetProfile`, `CapabilityCatalog` | Explicit algorithm/protocol constraints and untrusted vendor source attributes |
| Peer assessment | `CompatibilityAnalyzer::analyze` | Hostile negotiation, PKI and downgrade checks, never authoritative interoperability |
| Remediation | `RemediationAnalyzer` | Blocker and prerequisite-linked review actions; no execution |
| Waves | `WavePlanner` | Bounded, prerequisite-preserving advisory waves |
| Plan | `MigrationPlanner` | Digest-bound immutable plan, residual risk and claimed exception records |
| Atomic facade | `AnalysisRunner::analyze` | One complete advisory draft or one typed failure with no partial artifact |

All public schema/version constants are exported from `cryptoshift::`. Use the version constants and explicit `Limits` rather than guessing wire formats. Source-content SHA-256 fingerprints detect changes but are **not signatures** or identity attestations. A caller must obtain expected digests from an independently trusted channel. All sample timestamps are explicit synthetic UTC Unix seconds. An expired profile or cross-tenant/stale source must not be silently accepted.

The neutral handoff adapters currently use Cryptoshift-owned fixture structures; real Cryptomap and Cryptopolicy native interoperability is outside this release's verified acceptance. FOSS-513 tracks a separate trusted-evidence capability for any eventual actionable Complete/Warnings outcome.

## Clean-Room Package Adoption

A repo-relative Rust path dependency does not verify that a downstream developer can use the actual crates.io-shaped archive. FOSS-454 includes `scripts/package_consumer_check.py` to exercise the archive itself.

```sh
python3 -m unittest scripts.test_package_consumer_check -v
python3 scripts/package_consumer_check.py
python3 scripts/package_consumer_check.py --toolchain 1.85.0
```

The script performs `cargo package --offline --locked` without publishing, checks package identity and declared MSRV, validates bounded extraction paths and archive types, creates an **isolated temporary Cargo project outside this repository**, and compiles the existing inventory-to-plan example against the unpacked crate. It generates a detached consumer lockfile offline, executes with `--frozen` twice, checks exact output determinism, and compares the key behavior against `tests/acceptance/packaged-consumer.golden`. The acceptance script prints the SHA-256 of the package archive and consumer output as traceability data. The temporary project is removed when validation finishes.

The consumer depends on the *unpacked archive*, not the workspace, and uses no crates.io registry publishing token. Cargo's offline flag makes missing cached dependencies a reproducible setup error rather than an implicit network operation. The package remains marked `publish = false` throughout this acceptance process.

## Verification Limits

The suite covers Linux stable, Linux Rust 1.85, Windows stable and Windows Rust 1.85 via CI. The Windows acceptance also replays versioned E2 source/enterprise conformance and checks the detached neutral consumer. FOSS-453 provides performance smoke and frozen semantic identities, not execution authorization or timing-based CI thresholds.

Before any public crate release, the owner must separately approve the release version, package ownership, branch protections, verified reproducible artifacts, dependency/security report, SBOM and provenance, and an explicit restricted publishing operation (FOSS-456). Nothing in this guide authorizes publication.
