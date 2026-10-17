# FOSS-436 — Evidence-bound provider and runtime capability catalog v1

**Status:** experimental, offline, unpublished cryptographic capability **evidence**
contract. Not a hardware/firmware attestation verifier, provider discovery agent,
FIPS 140 module validation service, CNSA compliance determination, protocol
negotiation engine, authorization gate, or migration planner.

## Source and policy boundaries

FOSS-430 supplies immutable **desired target** constraints: exact FIPS 203/204/205
algorithm parameter IDs, NIST security categories, source editions, named
protocol/certificate profiles, and optional CNSA 2.0 subset. FOSS-436 does not
rewrite that catalog, normalize Kyber/Dilithium marketing aliases, or infer
that a provider supports or has activated a scheme simply because NIST
standardized it.

FOSS-436 introduces CAPABILITY_CATALOG_VERSION = 1 and two public contracts:

- CapabilityCatalogDraft is untrusted caller-supplied provider/product/runtime
  facts. CapabilityCatalog::new validates, canonicalizes, and seals source
  attribution into a SHA-256 content digest. Its fields are immutable after
  creation, though source claims remain **unverified externally supplied facts**.
- CapabilityCatalog::match_target(target, exact_selector, explicit_time, limits)
  returns target disposition **and** raw evidence state. It does not evaluate
  full readiness. TargetDisposition Required or Permitted does not mean a
  product implements, activates, or negotiates the algorithm. Returning a
  DeployedAndVerified *source state* is not cryptographic attestation by the
  library.

No network, service discovery, key material, credentials, runtime probes,
certificate parsing, policy execution, automatic status escalation or
deployment occurs in this increment.

## Evidence identity and provenance

Every CapabilityRecord retains:
- Stable record ID, provider ID, product ID, exact product version/build,
  platform ID, tenant/deployment scope ID, optional exact runtime/image
  identity, KnownAlgorithm, AlgorithmRole, and CapabilityState.
- CapabilityEvidence source ID, evidence ID, exact source revision,
  CapabilityEvidenceBasis, EvidenceVerification, optional verification
  receipt ID and artifact SHA-256, observation time and optional expiry.
- A bounded outer catalog ID, source issuer, source document/revision,
  source digest (optional, not authenticated), exact scope and revision.

All identity/reference strings are nonempty, at most 256 bytes, and restricted
to opaque nonsecret ASCII characters [A-Za-z0-9._:/-]. Literal credentials,
embedded URLs containing '@', query tokens, whitespace or control characters
are rejected; no source text is returned in Diagnostic. Hosts must also
avoid sending secrets into these metadata fields.

**A SHA-256 evidence digest is not a signature.** EvidenceVerification::VerifiedByHost
is a caller **assertion**, not proof that Cryptoshift authenticated the host or
trust anchor. Only trusted external verification adapters can assign this state.
DeployedAndVerified additionally requires:
- Exact nonempty runtime ID, platform/product/version/scope and role.
- RuntimeTest or RuntimeAttestation provenance, never vendor documentation,
  vendor assertion or inference.
- VerifiedByHost with external verification reference **and** artifact digest.
- An explicit observation timestamp, finite expiration and caller-supplied
  evaluation time. Future-dated/expired results fail at admission.

A DeployedAndVerified claim is kept as **a claimed runtime observation**.
Consumers must authenticate evidence before trusting it for security decisions.
It never proves a cryptographic handshake, a FIPS-validated implementation,
CNSA applicability or peer compatibility. These belong to FOSS-438 and
downstream security controls.

## Lifecycle distinctions and exact matching

CapabilityState has six distinct values: DeployedAndVerified, Available,
Preview, Roadmap, Unsupported and Unknown. They are **not an ordinal scale**,
and the library never promotes one to another. A missing match is NoEvidence,
not Unsupported. A vendor Available assertion is not a runtime observation.
Roadmap and Preview remain their asserted maturity. Source Inference cannot
be used to assert deployed verification.

A CapabilitySelector requires exact tenant scope, provider, product, version,
platform, runtime (None or a specific ID), KnownAlgorithm and role. A
non-runtime claim with runtime_id=None does not match a runtime-specific
query. No fallback between provider releases, operating systems, tenants,
algorithm variants or signature/KEM roles exists.

CapabilityMatchState:
- NoEvidence — no matching facts; do not interpret as Unsupported.
- Consistent(state) — all currently valid matching source records report
  the **same original state**. This is not an authorization or truth proof.
- Conflicting — distinct current source claims disagree; every original
  record and evidence ID remains inspectable, no winner is chosen.
- Stale — at least one matching source is expired or future-dated at
  the explicitly supplied query time; no current state is asserted.

A match retains source catalog digest, immutable target digest, exact target
disposition, canonical record IDs and canonical source evidence IDs. A
Forbidden target still reports facts **without permitting use**.

## Versioning, serialization and denial behavior

- Schema version 1 only; unsupported versions and zero revisions rejected.
- Records are sorted by exact record ID, duplicates rejected. Distinct
  contradictory records remain present and contribute to the canonical digest.
- Binary export is domain-separated CSHIFT_CAPABILITY_V1, uses explicit
  length/optional-field framing, stable numeric tags, UTC seconds, source
  revisions, status and evidence types. SHA-256 binds **all** those fields.
  Reversing input record order is byte-identical; changes in provider/version,
  source revision, status or proof digest rotate the hash.
- A frozen, independent v1 fixture for a single vendor Available claim
  serializes to **300 bytes**, SHA-256
  `e141eeb7fc3190e8de82f8402ebcf559977ab9e5426874974b5fa9b6c598eba4`.
  Changes to framing require explicit schema-version review.
- Export is not a wire deserializer. External adapters must parse untrusted
  bytes against a versioned schema and independently verify issuer/source
  authenticity and trusted expected digest before passing a draft.
- Limits::EvidenceRecords and ProfileReferences bound catalog record count,
  InputBytes bounds the cumulative input strings **before sort/copy/indexing**,
  ExportBytes bounds canonical serialization and emitted lookup references.
  Arithmetic overflow and exhaustion fail closed with redacted Diagnostic.
- If source expiry is present, an evaluation timestamp is mandatory and
  expired source data is rejected. Query time is mandatory and **rechecks**
  both capability evidence expiry and the target profile's own expiry, so
  neither a once-valid runtime claim nor an expired desired-state policy is
  silently treated as current.
- No implicit freshness defaults, global deadlines, assumed platform
  compatibility, hybrid/PQC handshake, or namespace merging.

## Test-to-requirement traceability

| Acceptance requirement | Consumer regression |
| --- | --- |
| Canonical hash/bytes independent of insertion order; changes are visible | canonical_identity_is_order_independent_and_provenance_sensitive |
| Immutable v1 binary golden fixture prevents silent codec changes | frozen_v1_binary_fixture_is_stable_across_revisions |
| Advertised product != exact deployed runtime; verified claim retains evidence | advertised_capability_is_neither_deployed_nor_negotiated |
| Exact provider/version/platform/scope/role match without fallback | incompatible_version_platform_provider_scope_and_role_never_inherit_claims |
| Roadmap, Preview, Unsupported, Unknown, NoEvidence and Forbidden separate | roadmap_preview_unsupported_unknown_and_missing_are_distinct |
| Preserve independent contradictory evidence and stable source IDs | disagreeing_sources_are_preserved_not_overwritten |
| Reject absent verification, missing proof, inference and missing runtime | verified_deployment_claim_requires_runtime_and_checked_evidence |
| Explicit-time expiry, historical replay, future-source denial | explicit_clock_blocks_stale_future_and_unbounded_runtime_claims |
| Target profile expiry rechecked at lookup time | target_expiry_is_rechecked_at_lookup_without_a_clock_default |
| Duplicate evidence identities, invalid/secret-bearing IDs, unknown algorithm, schema | duplicate_records_revisions_and_secret_bearing_identifiers_fail_closed |
| Resource exhaustion denies without partial result | bounded_input_record_count_output_and_lookup_fail_closed |

Run from repository root:

~~~powershell
cargo run -p cryptoshift --example capability_catalog --locked
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
$env:RUSTDOCFLAGS="-D warnings"
cargo doc --workspace --all-features --no-deps --locked
python scripts/release_safety.py --with-cargo
python -m unittest discover -s scripts -p "test_release_safety.py" -v
~~~

Example output (statuses remain **claims**):

~~~text
target: synthetic-pqc-target
vendor offering: Consistent(Available)
exact runtime: Consistent(DeployedAndVerified)
unobserved runtime: NoEvidence
no peer/PKI interoperability or migration approval
~~~

Required GitHub jobs: Rust checks (release guard, all Rust tests/lints/docs)
and Supply chain and SemVer (RustSec, cargo-deny and SemVer). No new
dependencies, publishing, credentials, infrastructure, or release trigger.

## Remaining work

- FOSS-438 must establish independently verified peer- and protocol-level
  evidence, certificate/PKI constraints and documented transition support
  before any compatibility result can be trusted.
- FOSS-441 classifies hard blockers and evidence-linked remediation; it
  cannot equate an Available or Roadmap fact with deployed readiness.
- FOSS-442 gates migration waves on readiness, rollback, and external
  approval, not mere catalog membership.
