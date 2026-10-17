# FOSS-430 — Pinned algorithm and target profile constraints

Status: **unpublished contract**, FOSS-430; no cryptographic implementation,
deployment attestation, compliance certification, or migration authority.

## Boundary and provenance

Cryptoshift exposes two deliberately distinct contracts:

1. `standards.rs`: an offline, immutable **published-identifier catalog** pinned to
   FIPS 203/204/205 final editions (August 13, 2024) and a separately
   recognizable NSA CNSA Suite 2.0 advisory (September 2022 v1.0). A
   published standard does not assert application suitability, certified
   implementation, CNSA applicability, protocol interoperability, or safety.
2. `target.rs`: a caller-attributed, versioned **desired target policy**
   stating exact algorithm dispositions, security-category floors, protocol
   and certificate profiles, and optionally an explicitly selected CNSA
   general-purpose asymmetric subset. Validation is structural and
   conservative; it does not authorize an infrastructure change.

Source metadata points to external documents. The provided issuer, document
revision, and optional source SHA-256 are **claims only** and must be
authenticated or verified independently by a consuming organization. The
target content digest is an integrity identity, not a publisher signature.

## Verified edition catalog and frozen sources

| Pinned source | Recognized algorithm parameter sets | Document |
| --- | --- | --- |
| NIST-FIPS-203:2024-08-13 | ML-KEM-512, ML-KEM-768, ML-KEM-1024 | https://csrc.nist.gov/pubs/fips/203/final |
| NIST-FIPS-204:2024-08-13 | ML-DSA-44, ML-DSA-65, ML-DSA-87 | https://csrc.nist.gov/pubs/fips/204/final |
| NIST-FIPS-205:2024-08-13 | SLH-DSA-SHA2-{128,192,256}{s,f}; SLH-DSA-SHAKE-{128,192,256}{s,f} | https://csrc.nist.gov/pubs/fips/205/final |
| NSA-CNSA-2.0:2022-v1.0 | **Separate overlay**, limited to recognized general-purpose asymmetric parameters ML-KEM-1024 and ML-DSA-87 | https://www.nsa.gov/Press-Room/Digital-Media-Center/Document-Gallery/igphoto/2003728741/ |

NIST security categories are **1, 3 and 5**, not substitute
measurements of cryptographic implementations. The 18 exact identifiers
and roles have a deterministic catalog order. Unknown names, typos, vendor
aliases, unreviewed revisions, and future parameter sets are rejected rather
than silently mapped. FIPS 203/204 have published errata planning notes;
this catalog **pins the originally published editions**, not automatically
the latest corrections. Updating them requires a new reviewed increment.

NSA CNSA Suite 2.0's broader asymmetric/symmetric/hash and
firmware-signing requirements are **not** fully modeled here. In particular
this increment does not infer CNSA compliance from FIPS-standardized SLH-DSA,
does not model AES-256/SHA-384/SHA-512/LMS/XMSS, and does not assert a
CNSA protocol/certificate transition profile is interoperable. The
`Cnsa20Overlay` is opt-in with an explicit applicability source. It accepts
positive target algorithm constraints only for ML-KEM-1024 and ML-DSA-87,
and never silently adds either algorithm or any deadline. Users must not
treat passing the subset validation as full CNSA accreditation.

NIST SP 800-227 describes additional KEM and multi-algorithm guidance
(https://csrc.nist.gov/pubs/sp/800/227/final). It does **not** imply that
every application should use hybrid KEM. Here, hybrid is `None` by default.
A nonempty explicit second primitive and combiner reference are required
to record an asserted hybrid. The library does **not** validate the combiner
construction or downstream implementation support; FOSS-438 must do
protocol/peer compatibility work.

## Typed v1 schema

`TargetProfileDraft` is the only mutable input. `TargetProfile::new` checks
and consumes it to return an immutable, private-field `TargetProfile` with:
- `schema_version` exactly 1, nonzero `revision`, stable `profile_id`,
  scope/tenant boundary, issuer and external document reference/revision;
- explicit supported `StandardEdition` entries; every selected algorithm
  must have its corresponding FIPS edition included;
- exact `AlgorithmConstraint` (named parameter, role, disposition
  Required/Permitted/Forbidden, optional minimum NIST security category);
- `ProtocolConstraint` with named protocol ID, **exact** revision, role,
  algorithm, and an optional explicit hybrid specification;
- `CertificateConstraint` with named certificate profile, revision,
  signature-only algorithm, and external encoding/binding specification;
- optional `Cnsa20Overlay` declaring separate policy source and
  applicability, not inferred from the presence of a FIPS document;
- optional `ExplicitDeadline` carrying a specific use-case/stage, integer
  UTC time and authoritative caller-supplied source. **No global deadlines**;
- optional source-defined expiry, evaluated only against a
  caller-supplied time. If an expiring source is supplied without an
  evaluation time, validation fails closed. No ambient clock or
  auto-updating rules.

A Forbidden algorithm must have no positive category threshold. Required
and Permitted constraints must have a threshold no greater than the
algorithm's published category. Duplicate or conflicting algorithm
entries are invalid, as are duplicate (protocol, revision, role) or
(certificate profile, revision) identities. A protocol/certificate cannot
reference absent or Forbidden algorithms, nor substitute a signature for
a KEM (or vice versa).

`TargetProfile::disposition("ML-KEM-1024")` returns Required, Permitted,
Forbidden, or **NotSpecified**. NotSpecified is not an authorization to
deploy and is not converted to Permitted. Unknown exact identifiers
are rejected. These distinctions must be preserved by FOSS-436/438 and the
eventual planner.

## Deterministic identity and replay

The producer validates and sorts standards, algorithm entries, protocols
and certificate requirements before canonical encoding. `export()` emits
length-prefixed, domain-separated v1 binary bytes with all source/profile
fields, optional hybrid/overlay/deadline/expiry fields, and exact type tags.
SHA-256 of those bytes yields `TargetProfile::digest()`.

A frozen historical fixture asserts:

- bytes: 428;
- SHA-256:
  `f7d2087540e5caae06ea61f7ce3b70f0cdebea91d430242593810202002bc6c3`.

Reordering semantically identical input arrays does not change the bytes
or digest. Changing target revision, scope, category requirement, provenance,
CNSA applicability or a deadline does change it.
`verify_expected_digest` only checks a digest obtained independently by
the caller. It is **not** an authentication mechanism.

This increment has a *canonical export* but **no untrusted wire-format
deserializer**. An external JSON/YAML/binary adapter must first pass
`VersionedEnvelope` preflight and implement full v1 parsing, field validation,
and an independently verified digest before constructing a target.
In particular, parsing bytes by positional guesses is explicitly not
supported.

## Resource and failure guarantees

- `Limits::ProfileReferences` bounds total standards, algorithm constraints,
  protocol and certificate entries plus optional overlay/deadline **before
  sort, allocation, or digest computation**.
- `Limits::InputBytes` bounds total supplied metadata strings before
  canonicalization; identifiers must be nonempty, 256-byte maximum,
  printable ASCII and whitespace-free.
- `Limits::ExportBytes` bounds canonical emitted bytes during construction
  and later export. Every addition uses checked arithmetic; overflow or
  limit exhaustion yields a typed, source-redacted `Diagnostic`.
- No secrets, arbitrary filesystem access, live downloads, provider probing,
  key generation, network calls, agent execution, compliance waivers or
  release automation.
- Unknown versions, duplicate/conflicting constraints, role/category
  mismatches, undeclared standards, non-opt-in CNSA, and expired critical
  source revisions fail closed.
- Supplied provenance and claimed source digest are unverified facts; the
  caller owns issuer identity, signature verification, revision trust,
  validity selection and changes to policy.

## Test-to-requirement matrix

| Requirement | Public integration test |
| --- | --- |
| All 18 exact parameter sets/roles/categories; no ambiguous alias | catalog_enumerates_exact_fips_identifiers_and_categories |
| Unsupported source revision or v2 schema must be rejected | historic_edition_identifiers_are_pinned_and_future_versions_rejected |
| Canonical ordering, unlisted known=NotSpecified, unknown ID rejected, frozen digest replay | canonical_reordering_and_explicit_target_lookup |
| Content identity changes with revision, source, scope, category | immutable_revision_and_provenance_changes_rotate_content_identity |
| No role/category downgrade or undeclared source | role_and_category_constraints_are_not_silently_relaxed |
| Reject contradictory, duplicate or forbidden references | duplicate_and_conflicting_requirements_fail_closed |
| FIPS standards distinct from opted-in CNSA 2.0 constraints | cnsa20_overlay_is_opt_in_and_not_equivalent_to_fips_approval |
| Named protocol/cert, no generic hybrid default, bad combiner fails | exact_protocol_certificate_and_hybrid_constraints_are_explicit |
| No implicit dates, explicit validity test time only | deadlines_and_expiration_are_opt_in_with_explicit_evaluation |
| Bounded profile/input/output; redacted diagnostics | external_metadata_and_resource_budgets_reject_without_leaking_strings |

## Independent acceptance

From the repo root on Rust stable (MSRV 1.85):

```powershell
cargo run -p cryptoshift --example target_profile --locked
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
$env:RUSTDOCFLAGS="-D warnings"
cargo doc --workspace --all-features --no-deps --locked
python scripts/release_safety.py --with-cargo
python -m unittest discover -s scripts -p "test_release_safety.py" -v
```

Expected indicative example output:

```text
target: synthetic-nss-profile
source scope: offline-demonstration
standards: 3
ML-KEM-1024: Required
ML-DSA-87: Required
No implicit hybrid, global deadline, deployment or compliance claim.
```

The example is an offline synthetic target only; actual NSA authority,
provider deployments, certificate encoding compatibility, peer support and
transition readiness remain unverified. GitHub must pass exact-head
"Rust checks" and "Supply chain and SemVer", followed by post-merge main CI.
`publish = false` and manual release-PR-only controls remain mandatory.

## Follow-on integration

- FOSS-436 consumes typed target constraints plus **externally evidenced**
  provider/product/version/role/platform capabilities; it cannot promote
  roadmap or vendor assertions to deployed readiness.
- FOSS-438 uses exact protocol/certificate revisions and peer evidence
  to determine compatible vs unsupported transitions. This target module
  must not infer protocol or PKI support from FIPS catalog entries alone.
- FOSS-441 uses separately validated policy and compatibility to emit hard
  blockers/remediations. No score under FOSS-427 overrides those blockers.
- FOSS-442 gates actual migration planning/rollback on explicit readiness.
- FOSS-476 remains an independent pinned CI dependency-maintenance issue.
