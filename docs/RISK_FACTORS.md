# FOSS-427 — Evidence-first post-quantum risk factors v1

Status: experimental, offline **analysis contract**, not a migration approval,
security certification, cryptographic standards registry or risk policy.

## Purpose and precise boundary

FOSS-427 consumes the immutable, canonical inventory (FOSS-418), typed
evidence graph (FOSS-420), and SCC topology (FOSS-422). The **inventory digest**
must match across all three, and the SCC topology must additionally carry
the SHA-256 fingerprint of the **exact typed graph** used for its construction.
RiskAnalysis::analyze rejects either mismatch, including two different graphs
constructed from the same inventory. The canonical graph fingerprint covers
node/edge type tags, use-site/observation bindings, identities, all source
evidence references, and the original inventory digest. It is a content
identity, not a signature.
The result retains every raw dimension, uncertainty, source reference, typed
finding and any explicitly supplied scoring profile. It does not gather
cryptographic inventory, call a provider, consult a registry, sign a source,
set an authorization decision or execute a migration.

An opaque source_reference is evidence attribution only. The library **does not
authenticate** external reviewers, algorithm classifications or deadlines.
The host must independently source, govern and verify claimed facts.

## Factor version 1

RISK_FACTOR_VERSION = 1 has exactly ten dimensions, in positional order:

| Index | Factor | Source / limitation |
| --- | --- | --- |
| 0 | quantum_exposure | From graph System -> CryptoUse ExposesUse, validated inventory use kind, and **explicit** per-observation quantum classification |
| 1 | confidentiality_lifetime | Caller-supplied, assessed retention/confidentiality exposure; no automatic years-to-risk rule |
| 2 | signature_lifetime | Caller-supplied post-expiration verification exposure; no automatic calendar inference |
| 3 | operational_criticality | Caller-supplied business/mission impact assessment |
| 4 | evidence_quality | Direct versus inferred evidence, conflicts and collection coverage in the current inventory |
| 5 | migration_readiness | Caller-supplied readiness assessment; topology membership does not mean ready |
| 6 | dependency_complexity | From SCC cycles and direct condensation prerequisite count |
| 7 | deadline_pressure | Caller-supplied assessment; no ambient clock or implicit compliance deadline |
| 8 | interoperability | Caller-supplied peer/protocol compatibility assessment |
| 9 | change_complexity | Caller-supplied deployment/change/rollback complexity assessment |

ContextAssessment provides only the seven nonderived factors (1, 2, 3, 5,
7, 8, 9). A claim must match a canonical SCC unit ID, have a unique
(unit, factor) pair, a concrete RiskLevel, a nonempty bounded source_reference,
and ClaimOrigin::AnalystAssessment or ScenarioAssumption. Attempts to override
quantum_exposure, evidence_quality or dependency_complexity are rejected.

QuantumAssessment is explicitly keyed to a known inventory observation,
the **exact observation algorithm ID**, and the canonical inventory digest.
ContextAssessment is likewise bound to that exact source digest. A stale
assessment from a changed inventory is rejected rather than reinterpreted
against a new algorithm or migration-unit context. Posture is Susceptible,
CandidateResistant or Unknown, **never inferred from the algorithm name**.
It cannot promote ConfiguredProtocol or LibraryCapability
to active/negotiated use. Only ActiveUse and NegotiatedProtocol qualify for
a known exposure level. Susceptible maps to Severe; CandidateResistant maps
to Moderate, explicitly **not** safe or approved. Without a usable
classification, quantum_exposure remains unknown. Separate active observations
without classifications remain unresolved even if one other observation has
known Severe exposure. Inferred evidence, collection incompleteness, reported
conflicts and scenario assumptions are preserved as uncertainties and prevent
aggregate scoring.

EvidenceQuality starts Low only when relevant source evidence is present and
direct, the relevant observations are not conflicted, and all collection runs
claim complete coverage. Weak/inferred evidence, conflicting observations or
partial/failed runs elevate it to High and mark unresolved. These are
source claims, not proof of collector authenticity or complete infrastructure
discovery. A graph with no relevant evidence reports missing assessment.

DependencyComplexity uses only typed topology: cyclic SCC -> Severe;
3+ distinct direct prerequisite units -> High; 1-2 -> Moderate; 0 -> Low.
Incomplete collection reports uncertainty even when the derived degree is 0.
These thresholds are **illustrative model-v1 conventions** and are neither
a security control nor a claim that any unit is ready to migrate.

## Unknowns, findings and scoring

A RiskFactor contains both optional level and optional uncertainty:
- level=None is unknown, not Low or zero; uncertainty explains what is absent.
- A known Severe factor may carry uncertainty about another use-site; its
  severity is still visible but a score is **withheld**.
- All ten factors are always emitted in canonical order. Missing context is
  included as an explicit Unknown, never silently skipped.
- RiskFindingCode exposes UnresolvedFactor, ElevatedFactor, SusceptibleUse
  and ScenarioDependent; findings reference the underlying full factor.
  Finding counts obey Limits::max_diagnostics.

Scoring is **optional** via ScoreProfile::new(id, version, weights):
- SCORE_PROFILE_VERSION=1 only.
- Ten positive, individually bounded u16 basis-point weights, sum exactly
  10,000. An absent/zero/oversized/unsupported profile is rejected.
- Per known factor, ordinal levels Low=0, Moderate=1, High=2, Severe=3.
- score_bps = round_half_up(sum(weight_i * ordinal_i) / 3), in 0..=10,000.
  The output is a *pressure heuristic*, **not** loss probability or safety.
- No score unless **all ten factors** have known levels with no uncertainty.
  Assumed inputs, partial scope, conflicting or inferred source evidence,
  unclassified crypto uses and missing contextual inputs prevent a score.
- Every report includes the entire source factor vector and, if requested,
  the full score profile. Changing weights changes the score without
  overwriting raw factors or findings. Host systems own profile authenticity,
  approval/version immutability and applicability.

A reported pressure of zero is **not** an authorization to use an algorithm,
a statement of cryptographic correctness or a migration approval. A score
does not replace hard blockers under FOSS-441 or readiness/rollback under
FOSS-442.

## Determinism and security properties

- Reject cross-snapshot joins using the canonical SHA-256 inventory digest,
  and reject cross-graph joins with the separately bound canonical graph
  fingerprint. Neither digest authenticates a collector or external review.
- Deduplicate and sort provenance IDs, observations and factor sources without
  conflating independent collectors.
- Reject duplicate quantum profiles and contextual factors, incorrect unit
  references, stale claim digests, changed observation algorithm identities,
  source IDs containing control bytes, unknown observations and unauthorized
  overrides of derived factors.
- Bound supplied profiles/claims, aggregate external source-reference
  bytes before indexing, cumulative graph evidence references and
  **per-system endpoint evidence-index entries**, ten-factor-per-unit work,
  diagnostics and emitted ID/reference bytes with existing Limits and checked
  arithmetic. A System -> System dependency reference counts at *both*
  endpoints before any BTreeSet construction. On failure return one typed
  redacted Diagnostic and **no partial report**.
- No external endpoints, dynamic registry updates, environment clock,
  migration writes, unauthenticated policy overrides or secret key bytes.
- Inferred/unknown basis and partial collection remain visible even where
  an explicit high-severity classification exists.

## Test-to-requirement traceability

| Requirement | Test |
| --- | --- |
| Unknown algorithm classification and omitted context never score | absent_context_and_unclassified_algorithm_stay_unknown |
| Canonical factor order, deterministic reordering and numeric scoring | fully_attributed_inputs_yield_inspectable_versioned_score |
| Weight change affects score only, not findings/factors | fully_attributed_inputs_yield_inspectable_versioned_score |
| Configured/library capability cannot become active | configured_or_library_capability_never_becomes_active_use |
| Conflict and inferred evidence still visible next to Severe exposure | uncertainty_survives_known_severe_exposure |
| Scenario assumptions and partial collection cannot score | incomplete_collection_and_scenario_assumptions_never_score |
| Missing second quantum profile cannot be masked by one Severe claim | missing_second_profile_cannot_be_masked_by_a_known_severe_use |
| Duplicate/missing/derived-overridden claims, stale source digests and wrong algorithms fail | invalid_sources_duplicates_and_derived_factor_overrides_rejected |
| Cross-snapshot mixing denied | mismatched_source_digests_fail_closed |
| Same-inventory graph/topology substitution denied; canonical graph identity invariant to node insertion order | topology_must_match_exact_graph_not_only_inventory_digest |
| System-to-system evidence indexing must charge both endpoints before allocation | both_endpoints_of_dependency_edge_must_charge_evidence_index_budget |
| Unsupported score version, weights and resource exhaustion denied | invalid_profiles_and_tight_resource_budgets_fail_closed |
| Excessive external claim-reference bytes rejected before indexing | external_source_text_is_bounded_before_building_assessment_indexes |

Run from repository root:

    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-features --locked
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
    cargo run --example risk_factors --locked
    python3 scripts/release_safety.py --with-cargo
    python3 -m unittest discover -s scripts -p "test_release_safety.py" -v

The example is fully **synthetic**, with externally supplied algorithm and
context claims. Its illustrative equal-weight profile produces pressure
3333 bps for a single Severe quantum-exposure factor and seven Moderate
context factors, with EvidenceQuality and DependencyComplexity at Low.
It prints the full factor vector and source digest.

GitHub exact-head required jobs remain Rust checks and Supply chain and
SemVer, including RustSec, dependency policy and SemVer. Publishing remains
prohibited (Cargo publish=false and release workflow manual release-pr only).

## Non-goals and follow-on dependencies

- No authoritative quantum algorithm classification or FIPS/NIST registry.
  Do not infer algorithm security from text such as RSA, ML-KEM, TLS or ECDSA.
- No parsing of business records, compliance dates, regulatory policy,
  system owner approvals, SLA/maintenance windows or signature retention.
  Such adapters must be separately sourced, versioned and reviewed.
- No alternative risk aggregation that can ignore hard blockers, missing
  factors or incomplete source coverage.
- FOSS-441 adds blocker taxonomy and evidence-linked remediation and must
  also receive peer/PKI compatibility findings from FOSS-438.
- FOSS-442 adds wave-planning readiness and rollback controls; no part of
  this scoring increment enables execution.
- Cryptomap FOSS-316 and the explicit adapter issue govern cross-project
  inventory interoperability; this increment only consumes local validated
  contract types.
