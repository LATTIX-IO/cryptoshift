# FOSS-438 — Peer, protocol and PKI compatibility v1

This module is an **offline, deterministic, source-attributed compatibility planning contract**, not a TLS implementation, X.509 validator, hardware attestation service, product scanner or cryptographic authority.

## Inputs

`CompatibilityAnalyzer::analyze(request, graph, target, initiator_catalog, responder_catalog, evaluated_at_unix_secs, limits)` accepts already validated immutable inputs, with separately supplied **expected SHA-256 content digests** for each. Callers must authenticate their sources *before* relying on any assertion. A content digest is not a signature.

The request identifies two distinct exact runtime endpoints, their graph System nodes, scope, product, build, OS/platform, proposed algorithm and role, protocol and extension revision, and optional exact certificate and hybrid profiles. Observations are separately attributed using `(source_id, evidence_id, source_revision)` namespaces. A host verification receipt reference is **never accepted as proof of authentication**.

The typed graph does not assert peer communication merely because a `DependsOn` relationship is present. A distinct, exact `PeerLinkObservation` is required to claim peer connectivity.

## Outcomes and security boundaries

- `Compatible` is reserved for a future authenticated negotiation and PKI verification trust boundary and is **not emitted by this implementation**.
- `Conditional`: no verified hard contradiction, but actual authentication and negotiation evidence remain outstanding.
- `Transitional`: the target explicitly names a hybrid construction and a peer-specific source asserts matching combiner and selected profile; independent authentication is still required.
- `Incompatible`: explicit forbidden target, unapproved protocol/certificate/hybrid candidate, or attempted classical fallback.
- `Unknown`: absent, stale, contradictory, mismatched or insufficient exact source facts.

A reported `DeployedAndVerified` provider status does not prove successful peer negotiation. Even when the source supplies a host-verification receipt and digest, Cryptoshift does not authenticate the receipt, certificate signature or trust anchor.

No algorithm downgrade, implicit classical fallback, invented hybrid combiner, cross-tenant match, cross-runtime reuse, missing trust anchor, or future-dated evidence can establish successful interoperability.

The v1 `KnownAlgorithm` set is limited to pinned FIPS 203/204/205 asymmetric parameter sets. Legacy classical algorithms are not modeled as permitted values; classical fallback is explicitly rejected, not silently accepted.

## Output contract

`CompatibilityAnalysis` exposes scoped source digests, caller-selected UTC evaluation time, a typed outcome, sorted findings and missing prerequisites, both original capability record-ID sets, globally disambiguated evidence triples, canonical bytes and a deterministic SHA-256 digest. Canonical export is domain-separated with `CSHIFT_COMPATIBILITY_V1`.

Outputs preserve contradictory source references, but no secret-bearing input is returned in diagnostic messages. This module performs no I/O. Resource admission checks the input and evidence counts, metadata fields, analysis budget, and serialized result size; all input limits are caller-configurable under compiled ceilings.

## Acceptance and checks

Run from repository root:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
python3 scripts/release_safety.py --with-cargo
```

The standalone example is independently executed by CI:

```text
cargo run -p cryptoshift --example peer_compatibility --locked
```

Expected output includes `status: Unknown`, `NegotiationMissing`, and an explicit statement that no protocol negotiation was authenticated.

The frozen v1 report fixture is `crates/cryptoshift/tests/fixtures/compatibility_v1.sha256`: SHA-256 `87df1c01c72506ef9eeebc6f8b5bfc6b08f4050172cbd1f9fb72d38cd00ef986` over 881 canonical bytes. This is a regression identity, not an authentication signature. Changes to canonical framing require an explicit schema-version review.

Contract tests in `crates/cryptoshift/tests/compatibility_contract.rs` cover advertised-only support, purported handshakes, runtime/scope substitution, unsafe downgrade, unapproved protocol, tampered graph identity, stale evidence, deterministic observation order, duplicate provenance, and resource exhaustion.

## Not implemented

No authenticated negotiation evidence adapter, trust-chain parser/validator, certificate revocation verifier, protocol-specific hybrid adapter, automatic traffic discovery, migration execution, remediation actions, or migration-wave planner. Follow-on work must introduce a separately defined, testable proof-verifier trust boundary before emitting authoritative `Compatible`.

Publication remains disabled pending FOSS-456.

## CI qualification

CI checks Rust stable (fmt, check, strict Clippy, tests, rustdoc), pinned Rust 1.85 MSRV check and tests, direct example execution, release-safety regressions, RustSec, cargo-deny and cargo-semver-checks. Both Rust and supply-chain checks must be green on the exact PR head. The branch ruleset currently enforces only `Rust checks`; additional checks must be reviewed manually until governance is upgraded.
