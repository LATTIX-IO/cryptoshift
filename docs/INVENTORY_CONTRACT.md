# Canonical inventory contract v1 — FOSS-418

This is an independently usable Cryptoshift-local **binary DTO** for cryptographic
inventory evidence. It is not yet identical to the prospective Cryptomap
ShiftInventoryV1 JSON handoff (Cryptomap FOSS-316/340–344). Future adapter work
must map explicitly, version and test the two formats; do **not** claim that a
Cryptomap exporter can already be imported without an adapter.

## Data model

InventorySnapshot has identity_version=1, normalization_version=1, one opaque
scope_id, collection runs, evidence, cryptographic observations and scoped
absence assertions. Each evidence record references its run and source. Each
observation references one or more distinct evidence records. A single asset may
have multiple observations, contradictory algorithms, and independent evidence.

CryptoUseKind distinguishes ActiveUse, LibraryCapability, ConfiguredProtocol,
NegotiatedProtocol and Unknown. A library merely *supporting* a scheme cannot be
silently promoted into active use. EvidenceBasis distinguishes Direct, Inferred
and Unknown, while ConflictState remains independent of confidence and use type.

Every run has a declared completeness (Complete/Partial/Failed). An absence is
Tentative or Confirmed; Confirmed is only possible for a Complete run matching
the same collection scope. This is still a source claim, not an independently
verified removal or successful migration.

## Canonical encoding

- Tag: eight ASCII bytes CSHIFT01
- Wire schema version: two big-endian u16 values 1,0
- Identity and normalization versions: two big-endian u16 values 1,1
- Snapshot scope: byte-length-prefixed UTF-8 string (u16 big-endian)
- Runs, evidence, observations and absences in that order, each prefixed by
  a u32 BE count
- All strings use u16 BE byte length followed by exact UTF-8 bytes
- Times are i64 BE Unix seconds; confidence is u16 BE basis points
- Enumerations use the tagged u8 values in inventory_codec.rs; unknown tags fail
- Records sorted by opaque ID; observation evidence refs sorted; absences sorted
  by (run_id, asset_id). Duplicate identity or dangling source refs is an error
- Any extra trailing bytes, incorrect lengths, invalid UTF-8, unrecognized
  tags, noncanonical ordering, conflicting scopes or unsupported versions fail
- No private key bytes, collector raw logs or secret-bearing locators are part
  of the public schema

The content identifier is SHA-256 from RustCrypto sha2 v0.10.9 applied to the
**complete canonical byte buffer**, including tag, wire version, identity,
normalization, scope, evidence, coverage and absence semantics. The external
representation is lowercase sha256:<64 hex bytes>.

A digest is **not a signature, authorization token, proof of authenticity, or
semantic attestation**. Always obtain the expected digest from an independent
trusted channel; computing one from the received bytes and treating it as
trusted adds no security. Trust in a collector is explicitly out of scope.

## Validation workflow

1. Construct an untrusted VersionedEnvelope with SchemaKind::InventorySnapshot
   and SchemaVersion::V1_0. Metadata preflight runs first with finite Limits,
   caller-supplied evaluation time and critical-profile expiry checking.
2. Use ValidatedInventorySnapshot::import_verified with expected trusted digest.
   Verification checks SHA-256 before attempting to deserialize, then uses
   bounded record decoding, UTF-8 checking and referential validation.
3. Decoder reconstructs a snapshot; constructor independently validates limits,
   exact identity versions, unique IDs, evidence-to-run/source, collection
   scope and confirmed absence conditions.
4. Re-encoding must yield exactly the imported bytes. All rejected inputs emit
   typed DiagnosticCode with static/redacted messages and no imported strings.

Changes in a normalized identity, origin reference, partial coverage, or
conflict state yield a different digest and require review.

## Local validation

    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-features --locked
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
    cargo run --example inventory_snapshot --locked

Expected tests demonstrate insertion-order invariant digest, exact roundtrip,
tamper rejection, incomplete-removal denial, evidence/source separation,
cross-scope denial, explicit unsupported identity, and resource limits.

## Future compatibility

Cryptomap ShiftInventoryV1 is not finalized. FOSS-446/FOSS-316 must specify
JSON/DTO adapter compatibility and ChangeSet bindings separately. No automatic
network discovery, PQC risk scoring, policy override, graph migration planning,
or infrastructure mutation is performed in this increment.
