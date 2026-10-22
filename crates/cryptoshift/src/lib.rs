//! Deterministic cryptographic-migration planning contracts.
//!
//! This unpublished Rust library validates versioned inventory and evidence
//! graphs, analyzes dependency SCCs and cryptographic risk, models desired
//! post-quantum profiles and source-qualified vendor capabilities, and generates
//! immutable non-executing migration plans with explicit unresolved gates.
//!
//! [`AnalysisRunner`] composes topology, risk, remediation, advisory waves and a
//! source-pinned [`MigrationPlanDraft`] into an atomic result. Input digests bind
//! bytes and scope, but **do not authenticate** collectors, vendors, peers,
//! policy approvals, PKI, source claims or control-plane authority.
//! Unverified capability evidence remains `Partial` in v1. The public
//! `Complete` and `Warnings` enum cases are reserved for future trusted
//! evidence support and cannot currently be returned by the runner.
//!
//! For a complete tested example, run
//! `cargo run -p cryptoshift --example migration_plan --locked`. The same
//! example also runs outside this workspace against the *packaged* crate.
//!
//! # Example
//!
//! ```
//! use cryptoshift::{Limits, SchemaKind, SchemaVersion, VersionedEnvelope};
//!
//! let input = VersionedEnvelope {
//!     schema: SchemaKind::InventorySnapshot,
//!     version: SchemaVersion::V1_0,
//!     payload: b"{}",
//!     source_id: "example-fixture",
//!     critical_profiles: &[],
//! };
//! let admitted = input.preflight(&Limits::default(), 0)?;
//! assert_eq!(admitted.unparsed_payload(), b"{}");
//! # Ok::<(), cryptoshift::Diagnostic>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod analysis;
mod capability;
mod compatibility;
mod diagnostic;
mod envelope;
mod graph;
mod inventory;
mod inventory_codec;
mod limits;
mod neutral_codec;
mod neutral_inventory;
mod neutral_policy;
mod plan;
mod remediation;
mod risk_analysis;
mod risk_model;
mod standards;
mod target;
mod topology;
mod wave;

pub use analysis::{
    ANALYSIS_RESULT_VERSION, AnalysisFinding, AnalysisFindingCode, AnalysisMetrics,
    AnalysisOutcome, AnalysisPhase, AnalysisRequest, AnalysisResult, AnalysisRunner,
};

pub use diagnostic::{Diagnostic, DiagnosticCode};
pub use envelope::{
    CriticalProfileReference, PreflightedEnvelope, SchemaKind, SchemaVersion, VersionedEnvelope,
};
pub use limits::{Limits, ParseBudget, ResourceKind};

pub use inventory::{
    AbsenceRecord, AbsenceStatus, CollectionCompleteness, CollectionRun, ConflictState,
    CryptoObservation, CryptoUseKind, EvidenceBasis, EvidenceRecord, IDENTITY_VERSION,
    InventoryArtifact, InventorySnapshot, NORMALIZATION_VERSION, SnapshotDigest,
    ValidatedInventorySnapshot,
};

pub use graph::{EvidenceGraph, GraphEdge, GraphNode, GraphNodeKind, GraphRelation};

pub use topology::{
    DependencyAnalysis, DependencyTopology, DirectFanout, DirectOutgoingFanout, MigrationUnit,
    PrerequisiteArc,
};

pub use risk_analysis::RiskAnalysis;
pub use risk_model::{
    ClaimOrigin, ContextAssessment, QuantumAssessment, QuantumPosture, RISK_FACTOR_VERSION,
    RiskFactor, RiskFactorKind, RiskFinding, RiskFindingCode, RiskLevel, RiskReport, RiskScore,
    RiskUncertainty, SCORE_PROFILE_VERSION, ScoreProfile, UnitRiskVector,
};

pub use standards::{
    AlgorithmRole, KnownAlgorithm, STANDARDS_CATALOG_VERSION, SecurityCategory, StandardEdition,
};
pub use target::{
    AlgorithmConstraint, CertificateConstraint, Cnsa20Overlay, ConstraintDisposition,
    ExplicitDeadline, HybridConstruction, ProfileProvenance, ProtocolConstraint,
    TARGET_PROFILE_VERSION, TargetDisposition, TargetProfile, TargetProfileDraft,
};

pub use capability::{
    CAPABILITY_CATALOG_VERSION, CapabilityCatalog, CapabilityCatalogDraft, CapabilityEvidence,
    CapabilityEvidenceBasis, CapabilityEvidenceRef, CapabilityMatch, CapabilityMatchState,
    CapabilityRecord, CapabilitySelector, CapabilityState, EvidenceVerification,
};

// Conservative offline peer and PKI compatibility analysis.
pub use compatibility::{
    COMPATIBILITY_ANALYSIS_VERSION, CertificateSelection, CompatibilityAnalysis,
    CompatibilityAnalyzer, CompatibilityBindings, CompatibilityCode, CompatibilityFinding,
    CompatibilityObservation, CompatibilityPrerequisite, CompatibilityRequest, CompatibilitySource,
    CompatibilityStatus, CompatibilitySubject, EndpointIdentity, HybridSelection,
    NegotiationObservation, PeerLinkObservation, PkiObservation,
};

// Advisory, digest-bound migration blocker and action planning (FOSS-441).
pub use remediation::{
    BlockerCode, BlockerEvidenceState, BlockerFinding, BlockerSeverity, MaintenanceRequirement,
    REMEDIATION_ANALYSIS_VERSION, RemediationAction, RemediationActionKind, RemediationAnalysis,
    RemediationAnalyzer, RemediationBindings, RemediationEvidence, RemediationGate,
    RemediationOwner, RollbackRequirement,
};

// Offline, nonauthorizing SCC wave and readiness proposals (FOSS-442).
pub use wave::{
    MigrationWave, ReadinessGate, ReadinessGateKind, UnitReadiness, UnitReadinessStatus,
    WAVE_PLAN_VERSION, WavePlanBindings, WavePlanDraft, WavePlanRequest, WavePlanner,
};

// Auditable, immutable plan drafts and untrusted exception record lifecycle (FOSS-444).
pub use plan::{
    ClaimedExceptionApproval, MIGRATION_PLAN_VERSION, MigrationPlanDraft, MigrationPlanRequest,
    MigrationPlanner, PlanAssessmentState, PlanCatalogPin, PlanChangeKind, PlanDiff,
    PlanEvidenceRef, PlanExceptionRecord, PlanExceptionRequest, PlanExceptionState,
    PlanFacetSubject, PlanScorePin, PlanSourcePins, ResidualRiskFacet, ResidualRiskKind,
};

// Versioned fixture-only neutral Cryptomap/Cryptopolicy handoff (FOSS-446).
// Not a native integration with any pending upstream transport contract.
pub use neutral_inventory::{
    NEUTRAL_CHANGE_VERSION, NEUTRAL_INVENTORY_VERSION, NeutralChangeClaim, NeutralChangeKind,
    NeutralChangeSet, NeutralChangeSetInput, NeutralInventoryAdapter, NeutralInventoryInput,
    NeutralInventoryPins, NeutralInventoryProjection,
};
pub use neutral_policy::{
    NEUTRAL_POLICY_VERSION, NeutralPolicyDecision, NeutralPolicyEvidence, NeutralPolicyGate,
    NeutralPolicyInput, NeutralPolicyOutcome, NeutralPolicyReview,
};
