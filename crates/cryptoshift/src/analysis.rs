//! Atomic, offline analysis orchestration and privacy-bounded operational diagnostics.
//!
//! A complete *analysis* is not an approved migration. All inputs remain untrusted
//! unless their supplied content pins were authenticated by the calling host.
use crate::{
    CapabilityCatalog, CompatibilityAnalysis, ContextAssessment, DependencyAnalysis,
    Diagnostic, DiagnosticCode, EvidenceGraph, Limits, MIGRATION_PLAN_VERSION,
    MigrationPlanDraft, MigrationPlanRequest, MigrationPlanner, PlanAssessmentState,
    PlanExceptionRequest, QuantumAssessment, RemediationAnalyzer, ResourceKind,
    RiskAnalysis, ScoreProfile, SnapshotDigest, TargetProfile, ValidatedInventorySnapshot,
    WAVE_PLAN_VERSION, WavePlanRequest, WavePlanner,
};

/// Public contract revision for the atomic analysis API.
pub const ANALYSIS_RESULT_VERSION: u16 = 1;

/// End-to-end outcome. Even `Complete` never means deployment authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisOutcome {
    /// All modeled evidence is complete for *external review*, not execution.
    Complete,
    /// Review-ready evidence exists with separately disclosed residual risks.
    Warnings,
    /// Essential evidence or independent approval is still outstanding.
    Partial,
    /// A hard-policy or contradictory constraint prevents this plan.
    Infeasible,
    /// No committed plan exists because validation or a computation failed.
    Failed,
}

/// The precise stage at which a failure or review condition occurred.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AnalysisPhase {
    /// Caller input and externally supplied digest validation.
    Admission,
    /// Directed graph and strongly connected migration units.
    Topology,
    /// Explainable risk factor evaluation.
    Risk,
    /// Evidence-bound blockers and review-only remediation.
    Remediation,
    /// Advisory, bounded wave sequencing.
    Waves,
    /// Full source-pinned immutable plan.
    Plan,
}

/// Stable, non-sensitive result-level diagnostic classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisFindingCode {
    /// The underlying computation failed; the `failure()` accessor is authoritative.
    ValidationFailed,
    /// At least one hard prohibition or conflicting requirement is unresolved.
    HardConstraint,
    /// Additional source or peer evidence is required.
    EvidenceIncomplete,
    /// A separate authority must evaluate a requested change.
    ExternalReviewRequired,
    /// Some residual risk survives otherwise complete evidence for review.
    ResidualRisk,
}

impl AnalysisFindingCode {
    /// Stable ASCII code for integrations; never includes source identifiers.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidationFailed => "CSHIFT_ANALYSIS_FAILED",
            Self::HardConstraint => "CSHIFT_ANALYSIS_INFEASIBLE",
            Self::EvidenceIncomplete => "CSHIFT_ANALYSIS_PARTIAL",
            Self::ExternalReviewRequired => "CSHIFT_ANALYSIS_EXTERNAL_REVIEW",
            Self::ResidualRisk => "CSHIFT_ANALYSIS_WARNINGS",
        }
    }
}

/// One typed, bounded diagnostic with no source content, IDs or credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisFinding {
    /// Stable code.
    pub code: AnalysisFindingCode,
    /// Originating phase.
    pub phase: AnalysisPhase,
}

/// Optional count-only, deterministic metrics. There are no timestamps,
/// user-supplied identifiers, source texts, or per-asset labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisMetrics {
    /// Number of admitted inventory observations.
    pub observations: usize,
    /// Number of validated graph nodes.
    pub graph_nodes: usize,
    /// Number of validated graph edges.
    pub graph_edges: usize,
    /// Number of strongly connected migration units.
    pub migration_units: usize,
    /// Number of risk vectors evaluated.
    pub risk_vectors: usize,
    /// Number of review-only remediation blockers.
    pub blockers: usize,
    /// Number of advisory waves.
    pub waves: usize,
    /// Number of unresolved residual-risk facets.
    pub residual_risks: usize,
}

/// Untrusted, caller-owned analysis inputs with *independently provisioned* pins.
/// Computing expected digests from the same untrusted inputs is not authentication.
pub struct AnalysisRequest<'a> {
    /// Versioned validated inventory.
    pub inventory: &'a ValidatedInventorySnapshot,
    /// Same-scope typed dependency graph.
    pub graph: &'a EvidenceGraph,
    /// Immutable desired target profile.
    pub target: &'a TargetProfile,
    /// Independently provisioned expected inventory SHA-256.
    pub expected_inventory_digest: SnapshotDigest,
    /// Independently provisioned expected graph SHA-256.
    pub expected_graph_digest: SnapshotDigest,
    /// Independently provisioned target SHA-256.
    pub expected_target_digest: SnapshotDigest,
    /// Optional externally scoped peer compatibility analyses.
    pub compatibilities: &'a [&'a CompatibilityAnalysis],
    /// Optional externally scoped capability catalogs.
    pub capability_catalogs: &'a [&'a CapabilityCatalog],
    /// Optional source-attributed quantum risk facts.
    pub quantum: &'a [QuantumAssessment],
    /// Optional source-attributed contextual risk facts.
    pub context: &'a [ContextAssessment],
    /// Optional deterministic scoring profile.
    pub scoring: Option<&'a ScoreProfile>,
    /// Explicit UTC Unix analysis instant; no wall-clock reads.
    pub evaluated_at_unix_secs: i64,
    /// Maximum system slots per advisory wave.
    pub capacity_systems_per_wave: usize,
    /// Maximum number of advisory waves.
    pub max_waves: usize,
    /// Unit IDs submitted for review, not approvals.
    pub submitted_for_review_units: &'a [String],
    /// Exception *requests* only; no claimed approval is accepted as authority.
    pub exceptions: &'a [PlanExceptionRequest],
    /// Emit only aggregate deterministic counts; false produces no metrics.
    pub include_metrics: bool,
}

/// Either one fully committed immutable draft or a failure with no draft.
/// A failure never leaks a partially produced graph, risk, wave or plan.
#[derive(Clone, Debug)]
pub struct AnalysisResult {
    outcome: AnalysisOutcome,
    plan: Option<MigrationPlanDraft>,
    findings: Vec<AnalysisFinding>,
    failure: Option<Diagnostic>,
    metrics: Option<AnalysisMetrics>,
}

impl AnalysisResult {
    /// Full stage-completion outcome; not evidence of permission to migrate.
    #[must_use]
    pub const fn outcome(&self) -> AnalysisOutcome {
        self.outcome
    }

    /// Present only after all stages and export limits have passed.
    #[must_use]
    pub fn plan(&self) -> Option<&MigrationPlanDraft> {
        self.plan.as_ref()
    }

    /// Bounded stable diagnostics, never containing source strings.
    #[must_use]
    pub fn findings(&self) -> &[AnalysisFinding] {
        &self.findings
    }

    /// Redacted source-independent failure diagnostic, if any.
    #[must_use]
    pub const fn failure(&self) -> Option<Diagnostic> {
        self.failure
    }

    /// Optional count-only metadata emitted only on successful commit.
    #[must_use]
    pub const fn metrics(&self) -> Option<AnalysisMetrics> {
        self.metrics
    }
}

/// Stateless, all-or-nothing migration analysis entry point.
pub struct AnalysisRunner;

impl AnalysisRunner {
    /// Build all intermediate phases privately and publish a plan only after
    /// exact source/version validation, bounded processing and canonical export.
    ///
    /// Errors are returned as `Failed` without intermediate artifacts. The
    /// returned plan remains an advisory draft requiring external review.
    #[must_use]
    pub fn analyze(request: &AnalysisRequest<'_>, limits: &Limits) -> AnalysisResult {
        let mut phase = AnalysisPhase::Admission;
        let completed = (|| -> Result<(MigrationPlanDraft, AnalysisMetrics), Diagnostic> {
            limits.validate()?;
            limits.check(ResourceKind::GraphNodes, request.graph.nodes().len())?;
            limits.check(ResourceKind::GraphEdges, request.graph.edges().len())?;
            limits.check(ResourceKind::EvidenceRecords, request.compatibilities.len())?;
            limits.check(ResourceKind::ProfileReferences, request.capability_catalogs.len())?;
            limits.check(ResourceKind::ProfileReferences, request.exceptions.len())?;
            limits.check(ResourceKind::GraphNodes, request.submitted_for_review_units.len())?;

            // Account for fields copied into D2/D3 requests before cloning them.
            let mut bytes = 0_usize;
            for unit in request.submitted_for_review_units {
                bytes = limits.checked_add(ResourceKind::InputBytes, bytes, unit.len())?;
            }
            for item in request.exceptions {
                for field in [
                    &item.request_id,
                    &item.scope_id,
                    &item.unit_id,
                    &item.target_constraint_id,
                    &item.requester_source_id,
                    &item.justification_reference,
                ] {
                    bytes = limits.checked_add(ResourceKind::InputBytes, bytes, field.len())?;
                }
                if let Some(approval) = &item.claimed_approval {
                    for field in [
                        &approval.issuer_id,
                        &approval.receipt_reference,
                        &approval.source_revision,
                    ] {
                        bytes = limits.checked_add(ResourceKind::InputBytes, bytes, field.len())?;
                    }
                }
            }
            // Independently pinned source identities are mandatory for this API.
            let inventory_digest = request.inventory.export(limits)?.digest;
            if inventory_digest != request.expected_inventory_digest
                || inventory_digest != request.graph.source_digest()
                || request.graph.fingerprint() != request.expected_graph_digest
                || request.target.digest() != request.expected_target_digest
            {
                return Err(Diagnostic::new(
                    DiagnosticCode::IntegrityMismatch,
                    "analysis_input_pins",
                    "independently supplied inventory, graph and target pins must match",
                ));
            }

            phase = AnalysisPhase::Topology;
            let topology = DependencyAnalysis::analyze(request.graph, limits)?;
            phase = AnalysisPhase::Risk;
            let risk = RiskAnalysis::analyze(
                request.inventory,
                request.graph,
                &topology,
                request.quantum,
                request.context,
                request.scoring,
                limits,
            )?;
            phase = AnalysisPhase::Remediation;
            let bindings = RemediationAnalyzer::input_bindings(
                request.inventory,
                request.graph,
                &topology,
                &risk,
                request.target,
                request.evaluated_at_unix_secs,
                limits,
            )?;
            let remediation = RemediationAnalyzer::analyze(
                request.inventory,
                request.graph,
                &topology,
                &risk,
                request.target,
                request.compatibilities,
                bindings,
                limits,
            )?;
            phase = AnalysisPhase::Waves;
            let wave_bindings =
                WavePlanner::input_bindings(&topology, &remediation, request.target, limits)?;
            let wave = WavePlanner::plan(
                &topology,
                &remediation,
                request.target,
                &WavePlanRequest {
                    schema_version: WAVE_PLAN_VERSION,
                    capacity_systems_per_wave: request.capacity_systems_per_wave,
                    max_waves: request.max_waves,
                    expected_bindings: wave_bindings,
                    submitted_for_review_units: request.submitted_for_review_units.to_vec(),
                },
                limits,
            )?;
            phase = AnalysisPhase::Plan;
            let pins = MigrationPlanner::input_pins(
                &topology,
                &remediation,
                &wave,
                request.target,
                request.capability_catalogs,
                request.scoring,
                limits,
            )?;
            let plan = MigrationPlanner::build(
                &topology,
                &remediation,
                &wave,
                request.target,
                request.capability_catalogs,
                request.scoring,
                &MigrationPlanRequest {
                    schema_version: MIGRATION_PLAN_VERSION,
                    expected_pins: pins,
                    exceptions: request.exceptions.to_vec(),
                },
                limits,
            )?;
            let _ = plan.export(limits)?; // Fail before committing any externally visible plan.
            let metrics = AnalysisMetrics {
                observations: request.inventory.snapshot().observations.len(),
                graph_nodes: request.graph.nodes().len(),
                graph_edges: request.graph.edges().len(),
                migration_units: topology.units().len(),
                risk_vectors: risk.units.len(),
                blockers: remediation.blockers().len(),
                waves: wave.waves().len(),
                residual_risks: plan.residual_risks().len(),
            };
            Ok((plan, metrics))
        })();
        match completed {
            Err(failure) => AnalysisResult {
                outcome: AnalysisOutcome::Failed,
                plan: None,
                findings: vec![AnalysisFinding {
                    code: AnalysisFindingCode::ValidationFailed,
                    phase,
                }],
                failure: Some(failure),
                metrics: None,
            },
            Ok((plan, metrics)) => {
                let (outcome, code) = classify(plan.status(), plan.residual_risks().len());
                AnalysisResult {
                    outcome,
                    plan: Some(plan),
                    findings: code
                        .map(|code| vec![AnalysisFinding { code, phase: AnalysisPhase::Plan }])
                        .unwrap_or_default(),
                    failure: None,
                    metrics: request.include_metrics.then_some(metrics),
                }
            }
        }
    }
}

fn classify(
    status: PlanAssessmentState,
    residual_risks: usize,
) -> (AnalysisOutcome, Option<AnalysisFindingCode>) {
    match status {
        PlanAssessmentState::Blocked => (
            AnalysisOutcome::Infeasible,
            Some(AnalysisFindingCode::HardConstraint),
        ),
        PlanAssessmentState::Partial => (
            AnalysisOutcome::Partial,
            Some(AnalysisFindingCode::EvidenceIncomplete),
        ),
        PlanAssessmentState::ExternalApprovalPending => (
            AnalysisOutcome::Partial,
            Some(AnalysisFindingCode::ExternalReviewRequired),
        ),
        PlanAssessmentState::CompleteEvidenceForReview if residual_risks > 0 => (
            AnalysisOutcome::Warnings,
            Some(AnalysisFindingCode::ResidualRisk),
        ),
        PlanAssessmentState::CompleteEvidenceForReview => (AnalysisOutcome::Complete, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_five_outcomes_keep_external_approval_separate() {
        assert_eq!(classify(PlanAssessmentState::Blocked, 0).0, AnalysisOutcome::Infeasible);
        assert_eq!(classify(PlanAssessmentState::Partial, 0).0, AnalysisOutcome::Partial);
        assert_eq!(
            classify(PlanAssessmentState::ExternalApprovalPending, 0).1,
            Some(AnalysisFindingCode::ExternalReviewRequired)
        );
        assert_eq!(
            classify(PlanAssessmentState::CompleteEvidenceForReview, 1).0,
            AnalysisOutcome::Warnings
        );
        assert_eq!(
            classify(PlanAssessmentState::CompleteEvidenceForReview, 0).0,
            AnalysisOutcome::Complete
        );
        assert_eq!(AnalysisFindingCode::ValidationFailed.as_str(), "CSHIFT_ANALYSIS_FAILED");
    }
}
