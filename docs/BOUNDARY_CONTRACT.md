# FOSS-416 admission contract and verification

## Version model

`SchemaKind` identifies the document family; `SchemaVersion` identifies the
*outer envelope schema*, not an algorithm, NIST standard, or sector profile.
This development increment supports outer version `1.0` for the five defined
families as a pre-1.0 contract. Unsupported majors and minors fail closed.

`CriticalProfileReference` carries a profile ID, family, schema version,
source metadata and optional expiry. Every such reference must be attributable
and must use the explicitly supported schema version. An expired profile
cannot pass preflight at the caller's explicit evaluation timestamp.

These metadata checks do not verify the referenced profile's signature, body,
semantics, or deployed implementation. Source IDs are only asserted metadata.

## Developer usage

Call `VersionedEnvelope::preflight` on a short, size-bounded raw payload before
parsing it; call `PreflightedEnvelope::preflight_json_nesting` for JSON-like
payloads; then run an actual bounded full-format decoder with matching
`ParseBudget` and domain schema checks. Only the latter may produce typed,
validated inventory or policy records. Do not treat a `PreflightedEnvelope`
as sufficient to plan, approve or authorize any migration.

All methods operate offline and deterministically; they take an explicit
Unix evaluation time and do not access ambient system state.

## Manual regression commands

From repository root, on stable Rust and on Rust 1.85:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
cargo run --example preflight --locked
python3 scripts/release_safety.py --with-cargo
```

Expected: all commands exit 0; the sample prints a preflight success but
explicitly notes that the input body is not yet validated. Test names are
listed in `THREAT_MODEL.md` and cover positive, exact-boundary, malformed,
unknown-version, stale-profile, oversized-count and overflow cases.

## Limit semantics

Configured `Limits` have sensible finite defaults and hard ceilings; the
caller may tighten or increase limits within those ceilings. `Limits::check`
always validates configuration before comparing an observed count. Counter
addition and multiplication are checked and then bounded. Parser adapters
must meter depth and tokens during parsing, not only after deserialization.

These caps prevent unbounded cardinality and depth, but they are not a complete
CPU or wall-clock budget. Future implementations must meter traversal work and
avoid nondeterministic iteration or unbounded retry/candidate loops.
