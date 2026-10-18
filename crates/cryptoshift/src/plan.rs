//! Immutable, replay-fenced migration-plan *drafts* (FOSS-444).
//!
//! Plan identity and source citations are not signatures. External exception
//! claims cannot waive blockers, and no API represents execution authority.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    BlockerCode, BlockerFinding, BlockerSeverity, CapabilityCatalog, DependencyTopology,
    Diagnostic, DiagnosticCode, Limits, ReadinessGateKind, RemediationAnalysis,
    RemediationEvidence, RemediationGate, RemediationOwner, ResourceKind,
    RiskFactorKind, ScoreProfile, SnapshotDigest, StandardEdition, TargetProfile,
    UnitReadiness, UnitReadinessStatus, WavePlanDraft, WavePlanner,
    STANDARDS_CATALOG_VERSION,
};

/// Version of the frozen, domain-separated plan and exception contract.
pub const MIGRATION_PLAN_VERSION: u16 = 1;

/// A declared capability catalog source; no proof of deployed functionality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanCatalogPin {
    /// Catalog publisher-assigned identity.
    pub catalog_id: String,
    /// Source-declared revision; not an authenticated monotonic counter.
    pub revision: u32,
    /// SHA-256 of the validated, immutable catalog body.
    pub digest: SnapshotDigest,
}

/// A fully specified optional risk scoring configuration, not a risk waiver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanScorePin {
    /// Caller-supplied score profile identity.
    pub profile_id: String,
    /// Exact schema revision of the scoring profile.
    pub version: u16,
    /// Digest of profile identity, schema and all ten exact weights.
    pub digest: SnapshotDigest,
}

/// Exact externally pinned upstream content identities and declared standards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanSourcePins {
    /// Tenant/scope identity; never inherited from another deployment.
    pub scope_id: String,
    /// Explicit caller-selected evaluation time; no system clock is read.
    pub evaluated_at_unix_secs: i64,
    /// Content-bound D2 wave draft.
    pub wave_digest: SnapshotDigest,
    /// Full-content D1 blocker and remediation report.
    pub remediation_digest: SnapshotDigest,
    /// FOSS-438/441 combined peer evidence hash.
    pub compatibility_set_digest: SnapshotDigest,
    /// Validated inventory content hash.
    pub inventory_digest: SnapshotDigest,
    /// Exact typed graph fingerprint.
    pub graph_digest: SnapshotDigest,
    /// SCC topology content hash.
    pub topology_digest: SnapshotDigest,
    /// Exact scoped target revision content hash.
    pub target_digest: SnapshotDigest,
    /// Full factor-vector risk content digest.
    pub risk_digest: SnapshotDigest,
    /// Exact standards catalog generation.
    pub standards_catalog_version: u16,
    /// Required standards (not independently authenticated).
    pub standards: Vec<StandardEdition>,
    /// Scoped capability source set, sorted by source identity.
    pub catalogs: Vec<PlanCatalogPin>,
    /// Digest over all capability catalog names, revisions, and bodies.
    pub catalog_set_digest: SnapshotDigest,
    /// Optional named, versioned score weighting scheme.
    pub scoring: Option<PlanScorePin>,
}

/// A source-claimed approval that is **never** verified by Cryptoshift.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedExceptionApproval {
    /// Claimed independent authority identity.
    pub issuer_id: String,
    /// Opaque external purported approval record; not a signature.
    pub receipt_reference: String,
    /// Exact revision of the claimed record.
    pub source_revision: String,
    /// Claimed observation time in UTC Unix seconds.
    pub observed_at_unix_secs: i64,
}

/// External request to document an exception; never a policy exception grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanExceptionRequest {
    /// Caller-issued record identity unique to one plan scope.
    pub request_id: String,
    /// Exact target tenant/scope.
    pub scope_id: String,
    /// A known, indivisible migration SCC.
    pub unit_id: String,
    /// Exact known target algorithm, protocol or certificate identifier.
    pub target_constraint_id: String,
    /// Owner-claim identity, not authenticated user principal.
    pub requester_source_id: String,
    /// Opaque source record; do not embed justification or secrets.
    pub justification_reference: String,
    /// Original requested time (explicit; no ambient clock).
    pub requested_at_unix_secs: i64,
    /// Exact external expiry; no inferred grace period.
    pub expires_at_unix_secs: i64,
    /// Claim only; no trusted signer, chain or authority validation exists.
    pub claimed_approval: Option<ClaimedExceptionApproval>,
}

/// No accepted/approved state exists without a real authority verifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PlanExceptionState {
    /// Pending independently authorized treatment and review.
    Requested = 1,
    /// A claimed receipt is present but explicitly unauthenticated.
    ClaimedApprovalUnverified = 2,
    /// Deadline passed; this never discharges an obligation.
    Expired = 3,
}

/// Immutable, canonical request record and derived nonauthoritative state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanExceptionRecord {
    /// Original supplied request, validated and sorted by request ID.
    pub request: PlanExceptionRequest,
    /// Derived from timestamp and caller claims without trust elevation.
    pub state: PlanExceptionState,
}

/// Namespaced evidence references, preserving original source distinctions.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PlanEvidenceRef {
    /// Exact D1 original provenance, never downgraded to bare local ID.
    Remediation(RemediationEvidence),
    /// Capability claim from source, evidence and revision.
    Capability {
        /// External claim publisher ID.
        source_id: String,
        /// Publisher-local evidence ID.
        evidence_id: String,
        /// Explicit evidence revision.
        source_revision: String,
    },
    /// Exception source record, not an endorsement.
    Exception {
        /// Claiming or requesting source identity.
        source_id: String,
        /// Original opaque source record.
        reference_id: String,
        /// Exact source revision, if independently stated.
        revision: String,
    },
}

/// Typed residual obligation; not a quantified probability of breach.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ResidualRiskKind {
    /// Required cryptographic/policy constraints remain unresolved.
    PolicyConstraint = 1,
    /// Quantum exposure or context risk is unresolved.
    QuantumOrContextRisk = 2,
    /// Peer negotiations or runtime interoperability need proof.
    PeerProtocol = 3,
    /// PKI chains, profiles, revocation or anchors need validation.
    PkiTrust = 4,
    /// Vendor/runtime capability is not independently authenticated.
    VendorCapability = 5,
    /// Unit ownership is missing or ambiguous.
    Ownership = 6,
    /// Upstream SCC needs independent acceptance.
    Dependency = 7,
    /// Source provenance, freshness or completeness requires review.
    EvidenceQuality = 8,
    /// Change-control authority is outstanding.
    ChangeApproval = 9,
    /// A reviewed maintenance window is outstanding.
    Maintenance = 10,
    /// Validated rollback/contingency approval is outstanding.
    Rollback = 11,
    /// Independently authenticated unit review is outstanding.
    UnitReview = 12,
    /// An explicit source-defined deadline requires handling.
    Deadline = 13,
    /// Unverified exception claim never dismisses underlying findings.
    ExceptionUnverified = 14,
    /// No scoped capability catalog was submitted.
    MissingCapabilityEvidence = 15,
}

/// One individually traceable residual risk/required action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidualRiskFacet {
    /// Source-bound stable record ID, rotating with upstream evidence.
    pub id: String,
    /// Scope-wide facets have no SCC; otherwise exact SCC unit ID.
    pub unit_id: Option<String>,
    /// Stable typed facet classification.
    pub kind: ResidualRiskKind,
    /// Exact original D1 blocker, if applicable.
    pub blocker_id: Option<String>,
    /// Exact original D1 action, if applicable.
    pub action_id: Option<String>,
    /// Exact directly dependent upstream SCC, if applicable.
    pub prerequisite_unit_id: Option<String>,
    /// Evidence original source namespaces and revisions.
    pub evidence: Vec<PlanEvidenceRef>,
    /// Exact unsatisfied external evidence/approval gates.
    pub validation_gates: Vec<RemediationGate>,
    /// External source-defined due date; never inferred.
    pub due_at_unix_secs: Option<i64>,
}

/// A plan *draft* state; none implies an approved or safe execution.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PlanAssessmentState {
    /// At least one hard-policy/contradiction blocker is present.
    Blocked = 1,
    /// Some essential source evidence or proof remains unresolved.
    Partial = 2,
    /// All modeled prerequisites lack an authenticated final approval.
    ExternalApprovalPending = 3,
    /// Evidence is modeled for external review only; NEVER authorization.
    CompleteEvidenceForReview = 4,
}

/// User-supplied expected content identities plus *untrusted* requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationPlanRequest {
    /// Stable schema revision; must match MIGRATION_PLAN_VERSION.
    pub schema_version: u16,
    /// Complete externally pinned source/plan versions.
    pub expected_pins: PlanSourcePins,
    /// Untrusted proposed exception requests, accepted neither here nor upstream.
    pub exceptions: Vec<PlanExceptionRequest>,
}

/// Immutable, auditable proposal; no authorization or execution API.
#[derive(Clone, Debug)]
pub struct MigrationPlanDraft {
    pins: PlanSourcePins,
    status: PlanAssessmentState,
    waves: Vec<crate::MigrationWave>,
    readiness: Vec<UnitReadiness>,
    blockers: Vec<String>,
    actions: Vec<String>,
    residual_risks: Vec<ResidualRiskFacet>,
    exceptions: Vec<PlanExceptionRecord>,
    canonical: Vec<u8>,
    digest: SnapshotDigest,
}

impl MigrationPlanDraft {
    /// Full upstream data provenance and version contract.
    #[must_use]
    pub fn pins(&self) -> &PlanSourcePins { &self.pins }
    /// Non-authoritative plan evidence completeness status.
    #[must_use]
    pub const fn status(&self) -> PlanAssessmentState { self.status }
    /// Immutable original D2 candidate waves, never an execution schedule.
    #[must_use]
    pub fn waves(&self) -> &[crate::MigrationWave] { &self.waves }
    /// Exact unmodified D2 per-unit review conditions.
    #[must_use]
    pub fn readiness(&self) -> &[UnitReadiness] { &self.readiness }
    /// Source-bound FOSS-441 blocker identity set.
    #[must_use]
    pub fn blocker_ids(&self) -> &[String] { &self.blockers }
    /// Source-bound FOSS-441 action identity set.
    #[must_use]
    pub fn action_ids(&self) -> &[String] { &self.actions }
    /// Source-attributed, unresolved evidence and operational obligations.
    #[must_use]
    pub fn residual_risks(&self) -> &[ResidualRiskFacet] { &self.residual_risks }
    /// Unverified exception proposals and claimed approvals, never grants.
    #[must_use]
    pub fn exceptions(&self) -> &[PlanExceptionRecord] { &self.exceptions }
    /// SHA-256 of frozen version-one canonical bytes.
    #[must_use]
    pub const fn digest(&self) -> SnapshotDigest { self.digest }
    /// Export only under an active output byte limit.
    pub fn export(&self, limits:&Limits) -> Result<Vec<u8>,Diagnostic> {
        limits.check(ResourceKind::ExportBytes,self.canonical.len())?;
        Ok(self.canonical.clone())
    }
}
