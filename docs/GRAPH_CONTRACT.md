# FOSS-420 - Evidence-bound typed dependency graph

This increment adds a deterministic directed graph over exactly one validated
Cryptoshift inventory snapshot. It does not scrape infrastructure, score
post-quantum cryptographic exposure, choose replacement algorithms, or
approve/invoke migrations.

## Model

Node kinds: System, CryptoUse, Library, Certificate, TrustAnchor, Key, Hsm,
Data, Owner and Vendor. Every node has an opaque unique ID and at least one
reference to provenance evidence in the source snapshot.

CryptoUse nodes additionally require an observation_id linked one-to-one to
a known inventory observation, with evidence IDs restricted to that observation.
Other node kinds must not supply an observation binding. This avoids
interpreting library capability or configured protocol as active crypto use.

GraphRelation is typed and directional:
- ExposesUse: System -> CryptoUse
- LoadsLibrary: System -> Library
- ImplementsUse: Library -> CryptoUse
- UsesCertificate: System -> Certificate
- IssuedBy: Certificate -> TrustAnchor
- HoldsKey: Hsm -> Key
- ProtectsData: Key -> Data
- OwnedBy: System / Data / Key / Certificate / Hsm -> Owner
- SuppliedBy: System / Library / Hsm -> Vendor
- DependsOn: System -> System

Unsupported type combinations or reversed edges return typed errors; there is
no implicit edge casting. Every edge requires evidence from the source snapshot.
Duplicate (from, to, relation) edges are refused instead of silently merged.
Unknown or duplicate evidence references, conflicting graph IDs, malformed
identifiers and dangling source/target references are rejected.

Cycles including self-relationships are preserved for future SCC/migration
unit analysis under FOSS-422; FOSS-420 does not traverse or resolve them.

## Canonical representation

EvidenceGraph::new checks supplied Limits, maps IDs using BTreeMaps/sets,
and returns immutable, lexicographically sorted nodes, sorted evidence IDs, and
edges sorted by (from, to, relation). The input inventory's own SHA-256 digest
is bound to the graph through source_digest(); it is a content identity, not a
collector signature. The graph is not a new independent persisted wire schema.

Resource limits apply to node count, edge count and cumulative source evidence
references. Do not allocate unbounded candidate paths or derive policy
decisions from this module.

## Verification

Run from repository root:

    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-features --locked
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
    python3 scripts/release_safety.py --with-cargo
    python3 -m unittest discover -s scripts -p "test_release_safety.py" -v

Unit/integration tests demonstrate sorting invariance, wrong-direction edges,
unknown endpoints, missing evidence, invalid observation bindings, duplicate
nodes/edges/evidence, resource-limit failures, allowed cycles and no promotion
of library capability to active use.

## Remaining

FOSS-422 handles bounded SCC analysis, shared dependencies and migration units.
FOSS-427 adds explainable factor-vector risk analysis. Cryptomap FOSS-316
external handoff adapters remain separate. This module accepts a validated
Cryptoshift-local inventory from FOSS-418.

Security regression: dense evidence source sets use binary search over the canonical sorted
inventory evidence IDs rather than quadratic per-reference linear scans.
