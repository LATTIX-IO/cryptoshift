//! Deterministic evidence-bound blocker classification and remediation proposals.
//!
//! This module creates *advisory* work items. It does not authenticate a source,
//! waive mandatory policy, approve migrations, resolve risk, or execute changes.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CapabilityEvidenceRef, CompatibilityAnalysis, CompatibilityCode, CompatibilityPrerequisite,
    CompatibilityStatus, DependencyTopology, Diagnostic, DiagnosticCode, EvidenceGraph,
    GraphRelation, Limits, RISK_FACTOR_VERSION, ResourceKind, RiskFactorKind, RiskFindingCode,
    RiskLevel, RiskReport, RiskUncertainty, SnapshotDigest, TargetProfile, ValidatedInventorySnapshot,
};

/// Version of the immutable remediation finding, action, and export contract.
pub const REMEDIATION_ANALYSIS_VERSION: u16 = 1;

/// Source namespaces are not authenticated; their meaning must not be conflated.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RemediationEvidence {
    /// Inventory evidence attributed to a collection source and run.
    Inventory {
        /// Original collection source identifier.
        source_id: String,
        /// Original collection-run identifier; a source run, not a signature.
        run_id: String,
        /// Original source-local evidence identifier.
        evidence_id: String,
    },
    /// Compatibility source's independently qualified evidence triple.
    Compatibility {
        /// Independent source namespace.
        source_id: String,
        /// Source-local evidence ID.
        evidence_id: String,
        /// Exact evidence revision, not automatically authenticated.
        source_revision: String,
    },
    /// Opaque externally declared assessment reference, not a source signature.
    RiskAssessment {
        /// Original source reference string from RiskAnalysis.
        reference_id: String,
    },
    /// The versioned target issuer/document/revision provenance.
    TargetDocument {
        /// Target issuer claim.
        issuer_id: String,
        /// Target document identity.
        document_id: String,
        /// Target document source revision.
        source_revision: String,
    },
    /// Exact separately sourced deadline claim, never a fabricated date.
    TargetDeadline {
        /// Original deadline-policy source reference.
        reference_id: String,
    },
}

/// No ordinal confidence inference from source verification claims.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum BlockerEvidenceState {
    /// An applicable fact is missing or insufficiently authenticated.
    Unknown = 1,
    /// Multiple attributed claims or a direct contradiction need reconciliation.
    Contradicted = 2,
    /// A named, scoped prohibition or fail-closed transition constraint applies.
    Prohibited = 3,
    /// An observed source claim requires independent operational validation.
    Claimed = 4,
}

/// Impact classification, distinct from source confidence and risk scoring.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum BlockerSeverity {
    /// Target-constraint conflict; cannot bypass without external approval.
    HardPolicy = 1,
    /// Missing evidence or validation gate blocks an authorized readiness claim.
    Verification = 2,
    /// An unresolved contextual risk or deadline requires owner assessment.
    RiskReview = 3,
}

/// Typed blocking reasons. Codes are versioned, not free-form vendor advice.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BlockerCode {
    /// No accountable owner covers each system in a migration unit.
    OwnerMissing,
    /// Different owner claims exist for one indivisible SCC migration unit.
    OwnerAmbiguous,
    /// An unresolved or assumed risk factor remains non-authoritative.
    RiskUnresolved(RiskFactorKind),
    /// A high/severe risk factor requires deliberate risk treatment.
    RiskElevated(RiskFactorKind),
    /// Compatibility report did not establish authenticated interoperability.
    PeerProofUnverified,
    /// Exact runtime/peer analysis is missing for a declared dependency edge.
    PeerCompatibilityMissing,
    /// One typed, source-attributed compatibility contradiction or gap.
    Compatibility(CompatibilityCode),
    /// Named compatibility verification prerequisite remains outstanding.
    CompatibilityGate(CompatibilityPrerequisite),
    /// A prerequisite SCC unit has not been independently accepted.
    DependencyGate,
    /// Source-defined deadline has already been reached.
    DeadlinePassed,
}

/// Type of validation the owner must arrange before a blocker can be resolved.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RemediationGate {
    /// Confirm accountable ownership from the designated governance source.
    AssignOwner = 1,
    /// Reconcile source claims and re-collect or authenticate evidence.
    VerifyEvidence = 2,
    /// Independently validate exact negotiated peer/protocol/runtime proof.
    AuthenticatePeer = 3,
    /// Verify trust path, certificate profile, anchor and revocation evidence.
    ValidatePki = 4,
    /// Obtain explicit and separately authorized target-profile correction.
    ApprovePolicyAlternative = 5,
    /// Establish exact vendor/product/build/runtime production availability.
    VerifyProvider = 6,
    /// Confirm named combiner and wire-format on both peers.
    VerifyHybrid = 7,
    /// Validate the upstream migration unit before dependent unit readiness.
    ValidatePrerequisite = 8,
    /// Obtain a sourced risk assessment or reviewed risk treatment.
    ReviewRisk = 9,
    /// Confirm source-defined deadline and prioritize owner response.
    ReviewDeadline = 10,
    /// Independently review all unit-level blocker/action prerequisites.
    ReviewUnitReadiness = 11,
}

/// Action classification; there is no execution operation in this API.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RemediationActionKind {
    /// Request source-backed owner assignment or clarify an ambiguous owner.
    ResolveOwner = 1,
    /// Reassess incomplete, assumed, or high-impact risk evidence.
    AssessRisk = 2,
    /// Authenticate both runtime endpoints' negotiation and link evidence.
    VerifyPeer = 3,
    /// Resolve source-backed PKI chain, trust anchor or revocation claims.
    VerifyPki = 4,
    /// Review an exact approved algorithm/protocol/certificate target instead.
    ReviewPolicy = 5,
    /// Confirm independently sourced provider availability for exact runtime.
    VerifyProvider = 6,
    /// Reconcile stale, conflicting, future or missing source evidence.
    ReconcileEvidence = 7,
    /// Confirm a named hybrid protocol/combiner on both endpoints.
    VerifyHybrid = 8,
    /// Validate prerequisite unit externally before advancing downstream.
    ValidateDependency = 9,
    /// Triage a source-defined deadline with accountable owner.
    ReviewDeadline = 10,
    /// Review all evidence and prerequisites, never assert Ready automatically.
    ReviewUnitGate = 11,
}

/// Owner attribution derived from graph claims, not authenticated IAM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemediationOwner {
    /// At least one required system has no source-qualified owner edge.
    Missing,
    /// Exactly one owner ID covers every system of the indivisible unit.
    Claimed(String),
    /// Multiple owner nodes are present; no automatic lead is invented.
    Ambiguous(Vec<String>),
}

/// Maintenance precondition for any later externally authorized change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MaintenanceRequirement {
    /// Collecting or reviewing evidence requires no service maintenance window.
    EvidenceOnly = 1,
    /// A separately approved maintenance window is required before a migration.
    ReviewedWindowRequired = 2,
}

/// Rollback requirement attached to an *advisory* action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RollbackRequirement {
    /// Evidence gathering/review has no managed infrastructure side effect.
    EvidenceOnly = 1,
    /// Before any future change, externally approve maintenance and rollback.
    ReviewedPlanRequired = 2,
}

/// Stable blocker bound to all source versions and exact migration-unit identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockerFinding {
    /// Exact versioned source/input digests, independently inspectable per finding.
    pub source_bindings: RemediationBindings,
    /// Full-content-derived stable ID.
    pub id: String,
    /// Indivisible topology migration-unit ID.
    pub unit_id: String,
    /// Typed reason including exact compatibility/risk subtype.
    pub code: BlockerCode,
    /// Evidence quality state, not automatically assigned probability.
    pub evidence_state: BlockerEvidenceState,
    /// Impact without conflating confidence or risk scores.
    pub severity: BlockerSeverity,
    /// Sorted and deduplicated actual source-qualified references.
    pub evidence: Vec<RemediationEvidence>,
    /// Unsatisfied validation conditions.
    pub required_gates: Vec<RemediationGate>,
    /// Accountable owner assertion, if uniquely modeled.
    pub owner: RemediationOwner,
}

/// Deterministic advisory remediation, never an approved operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemediationAction {
    /// Exact versioned source/input digests, independently inspectable per action.
    pub source_bindings: RemediationBindings,
    /// Digest-derived identity rotates with semantic input versions.
    pub id: String,
    /// Exact SCC migration unit.
    pub unit_id: String,
    /// Typed proposed review/evidence/approval task.
    pub kind: RemediationActionKind,
    /// IDs of blocking findings for which this is a *proposed* action.
    pub resolves_blocker_ids: Vec<String>,
    /// Real prerequisite action IDs, including upstream unit gate actions.
    pub prerequisite_action_ids: Vec<String>,
    /// Explicit attributed owner state (never auto-assigned).
    pub owner: RemediationOwner,
    /// Required evidence gates; completing a task does not waive these.
    pub validation_gates: Vec<RemediationGate>,
    /// Future separately authorized maintenance precondition.
    pub maintenance: MaintenanceRequirement,
    /// Future external rollback approval obligation.
    pub rollback: RollbackRequirement,
    /// A proposed change cannot proceed without separate change approval.
    pub change_approval_required: bool,
    /// Full qualified provenance, even where the action is still speculative.
    pub evidence: Vec<RemediationEvidence>,
    /// Only a source-defined applicable deadline; never an invented estimate.
    pub due_at_unix_secs: Option<i64>,
}

/// Fully pinned model versions. Equality is content identity, not attestation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemediationBindings {
    /// Validated inventory export SHA-256.
    pub inventory_digest: SnapshotDigest,
    /// Complete typed graph fingerprint.
    pub graph_digest: SnapshotDigest,
    /// Complete SCC topology content fingerprint.
    pub topology_digest: SnapshotDigest,
    /// Fully attributed risk-vector content fingerprint.
    pub risk_digest: SnapshotDigest,
    /// Exact immutable desired target.
    pub target_digest: SnapshotDigest,
    /// Explicit caller-provided analysis UTC time.
    pub evaluated_at_unix_secs: i64,
}

/// Immutable, deterministic blocker/action report; never an authorization.
#[derive(Clone, Debug)]
pub struct RemediationAnalysis {
    bindings: RemediationBindings,
    blockers: Vec<BlockerFinding>,
    actions: Vec<RemediationAction>,
    canonical: Vec<u8>,
    digest: SnapshotDigest,
}

impl RemediationAnalysis {
    /// Pinned versions of every upstream analysis input.
    #[must_use]
    pub const fn bindings(&self) -> RemediationBindings {
        self.bindings
    }
    /// Sorted source-attributed unit blockers.
    #[must_use]
    pub fn blockers(&self) -> &[BlockerFinding] {
        &self.blockers
    }
    /// Sorted non-executing actions and prerequisite action IDs.
    #[must_use]
    pub fn actions(&self) -> &[RemediationAction] {
        &self.actions
    }
    /// Domain-separated SHA-256 over the canonical v1 report bytes.
    #[must_use]
    pub const fn digest(&self) -> SnapshotDigest {
        self.digest
    }
    /// Return immutable canonical bytes within caller-configured export bounds.
    pub fn export(&self, limits: &Limits) -> Result<Vec<u8>, Diagnostic> {
        limits.check(ResourceKind::ExportBytes, self.canonical.len())?;
        Ok(self.canonical.clone())
    }
}

/// Stateless offline planner-assistance analyzer; no migration execution.
pub struct RemediationAnalyzer;

type BlockKey = (String, BlockerCode);
type BlockValues = (
    BlockerEvidenceState,
    BlockerSeverity,
    BTreeSet<RemediationEvidence>,
    BTreeSet<RemediationGate>,
);

impl RemediationAnalyzer {
    /// Compute a deterministic fingerprint for the exact SCC/unit topology.
    ///
    /// Fingerprinting supplies neither graph authenticity nor endorsement.
    pub fn topology_digest(
        topology: &DependencyTopology,
        limits: &Limits,
    ) -> Result<SnapshotDigest, Diagnostic> {
        limits.check(ResourceKind::GraphNodes, topology.units().len())?;
        limits.check(ResourceKind::GraphEdges, topology.prerequisites().len())?;
        let mut enc = Encoder::new(limits);
        enc.raw(b"CSHIFT_TOPOLOGY_D1_V1")?;
        enc.digest(topology.source_digest())?;
        enc.digest(topology.graph_fingerprint())?;
        let mut units: Vec<_> = topology.units().iter().collect();
        units.sort_by(|a, b| a.id.cmp(&b.id));
        enc.count(units.len())?;
        for unit in units {
            enc.string(&unit.id)?;
            enc.flag(unit.cyclic)?;
            enc.strings(&unit.system_ids)?;
            enc.strings(&unit.internal_dependency_evidence_ids)?;
        }
        let mut arcs: Vec<_> = topology.prerequisites().iter().collect();
        arcs.sort_by(|a, b| {
            (&a.dependent_unit, &a.prerequisite_unit)
                .cmp(&(&b.dependent_unit, &b.prerequisite_unit))
        });
        enc.count(arcs.len())?;
        for arc in arcs {
            enc.string(&arc.dependent_unit)?;
            enc.string(&arc.prerequisite_unit)?;
            enc.strings(&arc.evidence_ids)?;
        }
        Ok(SnapshotDigest::hash(&enc.finish()))
    }

    /// Canonically fingerprint the *entire* mutable risk report, not only scores.
    ///
    /// Reordered unit collections preserve identity; changed model details do not.
    pub fn risk_digest(risk: &RiskReport, limits: &Limits) -> Result<SnapshotDigest, Diagnostic> {
        limits.check(ResourceKind::GraphNodes, risk.units.len())?;
        // The report is publicly mutable: re-admit nested reference counts
        // before cloning/sorting source references for canonical serialization.
        let mut attached = 0_usize;
        for unit in &risk.units {
            limits.check(ResourceKind::ProfileReferences, unit.factors.len())?;
            for factor in &unit.factors {
                attached = limits.checked_add(
                    ResourceKind::EvidenceRecords,
                    attached,
                    factor.inventory_evidence_ids.len(),
                )?;
                attached = limits.checked_add(
                    ResourceKind::EvidenceRecords,
                    attached,
                    factor.assessment_references.len(),
                )?;
            }
        }
        limits.check(ResourceKind::EvidenceRecords, attached)?;
        let mut enc = Encoder::new(limits);
        enc.raw(b"CSHIFT_RISK_INPUT_D1_V1")?;
        enc.u16(risk.model_version)?;
        enc.digest(risk.source_digest)?;
        enc.digest(risk.graph_fingerprint)?;
        if let Some(profile) = &risk.score_profile {
            enc.flag(true)?;
            enc.string(profile.id())?;
            enc.u16(profile.version())?;
            for value in profile.weights_bps() {
                enc.u16(*value)?;
            }
        } else {
            enc.flag(false)?;
        }
        let mut units: Vec<_> = risk.units.iter().collect();
        units.sort_by(|a, b| a.unit_id.cmp(&b.unit_id));
        enc.count(units.len())?;
        for unit in units {
            enc.string(&unit.unit_id)?;
            enc.count(unit.factors.len())?;
            for factor in &unit.factors {
                enc.raw(&[factor.kind as u8])?;
                enc.raw(&[factor.level.map_or(0, |level| level as u8 + 1)])?;
                enc.raw(&[risk_uncertainty_tag(factor.uncertainty)])?;
                let mut inventory_refs = factor.inventory_evidence_ids.clone();
                inventory_refs.sort();
                let mut assessment_refs = factor.assessment_references.clone();
                assessment_refs.sort();
                enc.strings(&inventory_refs)?;
                enc.strings(&assessment_refs)?;
            }
            enc.count(unit.findings.len())?;
            let mut findings = unit.findings.clone();
            findings.sort_by_key(|v| (v.factor, v.code));
            for finding in findings {
                enc.raw(&[finding.factor as u8])?;
                enc.raw(&[risk_finding_code_tag(finding.code)])?;
            }
            if let Some(score) = &unit.score {
                enc.flag(true)?;
                enc.u16(score.pressure_bps)?;
                enc.string(&score.profile_id)?;
                enc.u16(score.profile_version)?;
            } else {
                enc.flag(false)?;
            }
        }
        Ok(SnapshotDigest::hash(&enc.finish()))
    }

    /// Prepare exact replay-pinning content digests for a *separately trusted*
    /// source. Computing these from the same untrusted input is not validation.
    pub fn input_bindings(
        inventory: &ValidatedInventorySnapshot,
        graph: &EvidenceGraph,
        topology: &DependencyTopology,
        risk: &RiskReport,
        target: &TargetProfile,
        evaluated_at_unix_secs: i64,
        limits: &Limits,
    ) -> Result<RemediationBindings, Diagnostic> {
        Ok(RemediationBindings {
            inventory_digest: inventory.export(limits)?.digest,
            graph_digest: graph.fingerprint(),
            topology_digest: Self::topology_digest(topology, limits)?,
            risk_digest: Self::risk_digest(risk, limits)?,
            target_digest: target.digest(),
            evaluated_at_unix_secs,
        })
    }

    /// Produce advisory blockers/actions against independently pinned inputs.
    ///
    /// Exactly scoped compatibility evidence is attributed to each endpoint's
    /// owning SCC; a dependency edge alone never proves network negotiation.
    #[allow(clippy::too_many_arguments)]
    pub fn analyze(
        inventory: &ValidatedInventorySnapshot,
        graph: &EvidenceGraph,
        topology: &DependencyTopology,
        risk: &RiskReport,
        target: &TargetProfile,
        compatibilities: &[&CompatibilityAnalysis],
        pinned: RemediationBindings,
        limits: &Limits,
    ) -> Result<RemediationAnalysis, Diagnostic> {
        limits.validate()?;
        limits.check(ResourceKind::GraphNodes, graph.nodes().len())?;
        limits.check(ResourceKind::GraphEdges, graph.edges().len())?;
        limits.check(ResourceKind::GraphNodes, topology.units().len())?;
        limits.check(ResourceKind::GraphNodes, risk.units.len())?;
        limits.check(ResourceKind::EvidenceRecords, compatibilities.len())?;
        // Re-admit source references from reports accepted under looser limits
        // *before* duplicating them into finding/action provenance indexes.
        let mut referenced = 0_usize;
        for unit in &risk.units {
            for factor in &unit.factors {
                referenced = limits.checked_add(
                    ResourceKind::EvidenceRecords,
                    referenced,
                    factor.inventory_evidence_ids.len(),
                )?;
                referenced = limits.checked_add(
                    ResourceKind::EvidenceRecords,
                    referenced,
                    factor.assessment_references.len(),
                )?;
            }
        }
        for analysis in compatibilities {
            referenced = limits.checked_add(
                ResourceKind::EvidenceRecords,
                referenced,
                analysis.evidence_refs().len(),
            )?;
            for finding in analysis.findings() {
                referenced = limits.checked_add(
                    ResourceKind::EvidenceRecords,
                    referenced,
                    finding.evidence_refs.len(),
                )?;
            }
        }
        limits.check(ResourceKind::EvidenceRecords, referenced)?;
        limits.checked_mul(ResourceKind::PlannerCandidates, topology.units().len(), 14)?;
        limits.checked_add(
            ResourceKind::PlannerCandidates,
            compatibilities.len(),
            topology.prerequisites().len(),
        )?;

        let actual = Self::input_bindings(
            inventory,
            graph,
            topology,
            risk,
            target,
            pinned.evaluated_at_unix_secs,
            limits,
        )?;
        if pinned != actual
            || actual.inventory_digest != graph.source_digest()
            || actual.inventory_digest != topology.source_digest()
            || actual.graph_digest != topology.graph_fingerprint()
            || actual.inventory_digest != risk.source_digest
            || actual.graph_digest != risk.graph_fingerprint
        {
            return Err(problem(
                DiagnosticCode::IntegrityMismatch,
                "remediation_inputs",
                "pinned inventory, graph, topology, risk and target revisions must agree",
            ));
        }
        if graph.source_scope_id() != inventory.snapshot().scope_id
            || graph.source_scope_id() != target.content().scope_id
        {
            return Err(problem(
                DiagnosticCode::InvalidReference,
                "remediation_scope",
                "inventory, graph and target tenant scopes must agree",
            ));
        }
        if risk.model_version != RISK_FACTOR_VERSION {
            return Err(problem(
                DiagnosticCode::UnsupportedSchemaVersion,
                "remediation_risk_version",
                "risk model version is incompatible with remediation v1",
            ));
        }
        if target
            .content()
            .expires_at_unix_secs
            .is_some_and(|expiry| actual.evaluated_at_unix_secs >= expiry)
        {
            return Err(problem(
                DiagnosticCode::StaleCriticalProfile,
                "remediation_target_expiry",
                "target profile is expired for the explicit analysis time",
            ));
        }
        let snap = inventory.snapshot();
        let sources: BTreeMap<&str, _> = snap.evidence.iter().map(|v| (v.id.as_str(), v)).collect();
        let mut unit_by_system = BTreeMap::<&str, &str>::new();
        let mut units = BTreeSet::new();
        for unit in topology.units() {
            units.insert(unit.id.as_str());
            for system in &unit.system_ids {
                if unit_by_system
                    .insert(system.as_str(), unit.id.as_str())
                    .is_some()
                {
                    return Err(problem(
                        DiagnosticCode::DuplicateRecord,
                        "remediation_system",
                        "system is assigned to multiple SCC units",
                    ));
                }
            }
        }
        if risk.units.len() != topology.units().len()
            || risk
                .units
                .iter()
                .map(|unit| unit.unit_id.as_str())
                .collect::<BTreeSet<_>>()
                != units
        {
            return Err(problem(
                DiagnosticCode::InvalidReference,
                "remediation_risk_units",
                "risk report must cover every exact topology SCC unit once",
            ));
        }
        for unit in &risk.units {
            if unit.factors.len() != RiskFactorKind::ALL.len()
                || unit
                    .factors
                    .iter()
                    .enumerate()
                    .any(|(index, factor)| factor.kind != RiskFactorKind::ALL[index])
            {
                return Err(problem(
                    DiagnosticCode::InvalidStateTransition,
                    "remediation_risk_factors",
                    "risk factor vector has missing, duplicated or reordered dimensions",
                ));
            }
            for factor in &unit.factors {
                if factor
                    .inventory_evidence_ids
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != factor.inventory_evidence_ids.len()
                    || factor
                        .assessment_references
                        .iter()
                        .collect::<BTreeSet<_>>()
                        .len()
                        != factor.assessment_references.len()
                {
                    return Err(problem(
                        DiagnosticCode::DuplicateRecord,
                        "remediation_risk_reference",
                        "risk source reference cannot repeat inside one factor",
                    ));
                }
                for id in &factor.inventory_evidence_ids {
                    if !sources.contains_key(id.as_str()) {
                        return Err(problem(
                            DiagnosticCode::InvalidReference,
                            "remediation_risk_evidence",
                            "risk factor names evidence absent from the exact inventory",
                        ));
                    }
                }
            }
            let computed = risk
                .score_profile
                .as_ref()
                .and_then(|profile| profile.score(&unit.factors));
            match (computed, &unit.score) {
                (None, None) => {}
                (Some(value), Some(score))
                    if value == score.pressure_bps
                        && risk.score_profile.as_ref().is_some_and(|profile| {
                            score.profile_id == profile.id()
                                && score.profile_version == profile.version()
                        }) => {}
                _ => {
                    return Err(problem(
                        DiagnosticCode::InvalidStateTransition,
                        "remediation_risk_score",
                        "risk aggregate is inconsistent with explicit factors or score profile",
                    ));
                }
            }
            for factor in &unit.factors {
                for reference in &factor.assessment_references {
                    valid_identifier(reference, "remediation_risk_reference")?;
                }
            }
        }
        let mut compat_by_unit = BTreeMap::<String, Vec<&CompatibilityAnalysis>>::new();
        let mut seen_reports = BTreeSet::new();
        let mut peers = BTreeMap::<(String, String), SnapshotDigest>::new();
        let mut contradictory_units = BTreeSet::new();
        for analysis in compatibilities {
            let bindings = analysis.bindings();
            if bindings.inventory_digest != pinned.inventory_digest
                || bindings.graph_digest != pinned.graph_digest
                || bindings.target_digest != pinned.target_digest
                || bindings.evaluated_at_unix_secs != pinned.evaluated_at_unix_secs
            {
                return Err(problem(
                    DiagnosticCode::IntegrityMismatch,
                    "remediation_compatibility",
                    "compatibility output is foreign, stale or independently mismatched",
                ));
            }
            if !seen_reports.insert(analysis.digest().as_bytes()) {
                return Err(problem(
                    DiagnosticCode::DuplicateRecord,
                    "remediation_compatibility",
                    "same compatibility artifact cannot be included twice",
                ));
            }
            let a = analysis.initiator().system_node_id.as_str();
            let b = analysis.responder().system_node_id.as_str();
            let from = unit_by_system.get(a).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "remediation_peer",
                    "compatibility initiator not in exact SCC topology",
                )
            })?;
            let to = unit_by_system.get(b).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "remediation_peer",
                    "compatibility responder not in exact SCC topology",
                )
            })?;
            // A protocol evidence pair is exact to the two participating
            // graph systems; reverse-direction observations still describe
            // the same peer relationship for completeness accounting.
            let pair = if a <= b {
                (a.to_owned(), b.to_owned())
            } else {
                (b.to_owned(), a.to_owned())
            };
            if peers.insert(pair, analysis.digest()).is_some() {
                contradictory_units.insert((*from).to_owned());
                contradictory_units.insert((*to).to_owned());
            }
            compat_by_unit
                .entry((*from).to_owned())
                .or_default()
                .push(analysis);
            if from != to {
                compat_by_unit
                    .entry((*to).to_owned())
                    .or_default()
                    .push(analysis);
            }
        }

        // Index owner claims once; do not scan every graph edge for each node.
        let mut owners_by_system = BTreeMap::<&str, BTreeSet<&str>>::new();
        let mut owner_evidence_by_system = BTreeMap::<&str, BTreeSet<&str>>::new();
        for edge in graph
            .edges()
            .iter()
            .filter(|edge| edge.relation == GraphRelation::OwnedBy)
        {
            owners_by_system
                .entry(&edge.from)
                .or_default()
                .insert(&edge.to);
            owner_evidence_by_system
                .entry(edge.from.as_str())
                .or_default()
                .extend(edge.evidence_ids.iter().map(String::as_str));
        }
        let mut owner_by_unit = BTreeMap::<String, RemediationOwner>::new();
        let mut owner_evidence_by_unit = BTreeMap::<String, Vec<RemediationEvidence>>::new();
        for unit in topology.units() {
            let mut owners = BTreeSet::new();
            let mut owner_refs = BTreeSet::new();
            let mut missing = false;
            for system in &unit.system_ids {
                let found = owners_by_system
                    .get(system.as_str())
                    .cloned()
                    .unwrap_or_default();
                if found.is_empty() {
                    missing = true;
                }
                owners.extend(found.into_iter().map(str::to_owned));
                if let Some(evidence_ids) = owner_evidence_by_system.get(system.as_str()) {
                    for id in evidence_ids {
                        owner_refs.insert(inventory_evidence(id, &sources)?);
                    }
                }
            }
            let owner = if missing {
                RemediationOwner::Missing
            } else if owners.len() == 1 {
                RemediationOwner::Claimed(owners.into_iter().next().unwrap_or_default())
            } else {
                RemediationOwner::Ambiguous(owners.into_iter().collect())
            };
            owner_evidence_by_unit.insert(unit.id.clone(), owner_refs.into_iter().collect());
            owner_by_unit.insert(unit.id.clone(), owner);
        }

        let mut pending = BTreeMap::<BlockKey, BlockValues>::new();
        let mut push = |unit: &str,
                        code: BlockerCode,
                        state: BlockerEvidenceState,
                        severity: BlockerSeverity,
                        evidence: Vec<RemediationEvidence>,
                        gate: RemediationGate| {
            let value = pending
                .entry((unit.to_owned(), code))
                .or_insert_with(|| (state, severity, BTreeSet::new(), BTreeSet::new()));
            // A prohibiting conflict must never be replaced by a weaker
            // source claim during canonical evidence aggregation.
            if evidence_rank(state) > evidence_rank(value.0) {
                value.0 = state;
            }
            if severity < value.1 {
                value.1 = severity;
            }
            value.2.extend(evidence);
            value.3.insert(gate);
        };
        for unit in topology.units() {
            let owner = owner_by_unit.get(&unit.id).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "remediation_unit_owner",
                    "an SCC unit has no associated owner assessment",
                )
            })?;
            match owner {
                RemediationOwner::Missing => push(
                    &unit.id,
                    BlockerCode::OwnerMissing,
                    BlockerEvidenceState::Unknown,
                    BlockerSeverity::Verification,
                    owner_evidence_by_unit
                        .get(&unit.id)
                        .cloned()
                        .unwrap_or_default(),
                    RemediationGate::AssignOwner,
                ),
                RemediationOwner::Ambiguous(_) => push(
                    &unit.id,
                    BlockerCode::OwnerAmbiguous,
                    BlockerEvidenceState::Contradicted,
                    BlockerSeverity::Verification,
                    owner_evidence_by_unit
                        .get(&unit.id)
                        .cloned()
                        .unwrap_or_default(),
                    RemediationGate::AssignOwner,
                ),
                RemediationOwner::Claimed(_) => {}
            }
            let risk_unit = risk
                .units
                .iter()
                .find(|v| v.unit_id == unit.id)
                .ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "remediation_risk_unit",
                        "missing required topology risk vector",
                    )
                })?;
            for factor in &risk_unit.factors {
                let mut refs = Vec::new();
                for id in &factor.inventory_evidence_ids {
                    refs.push(inventory_evidence(id, &sources)?);
                }
                refs.extend(factor.assessment_references.iter().map(|reference| {
                    RemediationEvidence::RiskAssessment {
                        reference_id: reference.clone(),
                    }
                }));
                if factor.level.is_none() || factor.uncertainty.is_some() {
                    push(
                        &unit.id,
                        BlockerCode::RiskUnresolved(factor.kind),
                        BlockerEvidenceState::Unknown,
                        BlockerSeverity::RiskReview,
                        refs.clone(),
                        RemediationGate::ReviewRisk,
                    );
                }
                if factor.level.is_some_and(|v| v >= RiskLevel::High) {
                    push(
                        &unit.id,
                        BlockerCode::RiskElevated(factor.kind),
                        BlockerEvidenceState::Claimed,
                        BlockerSeverity::RiskReview,
                        refs,
                        RemediationGate::ReviewRisk,
                    );
                }
            }
            let applicable_deadline = target.content().deadline.as_ref().filter(|deadline| {
                deadline.applies_to == unit.id
                    || deadline.applies_to == target.content().scope_id
                    || deadline.applies_to == target.content().profile_id
            });
            if let Some(deadline) =
                applicable_deadline.filter(|d| d.due_at_unix_secs <= pinned.evaluated_at_unix_secs)
            {
                push(
                    &unit.id,
                    BlockerCode::DeadlinePassed,
                    BlockerEvidenceState::Claimed,
                    BlockerSeverity::RiskReview,
                    vec![
                        target_reference(target),
                        RemediationEvidence::TargetDeadline {
                            reference_id: deadline.source_reference.clone(),
                        },
                    ],
                    RemediationGate::ReviewDeadline,
                );
            }
            let report_set = compat_by_unit.get(&unit.id);
            if contradictory_units.contains(&unit.id) {
                push(
                    &unit.id,
                    BlockerCode::PeerProofUnverified,
                    BlockerEvidenceState::Contradicted,
                    BlockerSeverity::Verification,
                    vec![],
                    RemediationGate::VerifyEvidence,
                );
            }
            if let Some(reports) = report_set {
                for analysis in reports {
                    let references = analysis
                        .evidence_refs()
                        .iter()
                        .map(compat_reference)
                        .collect::<Vec<_>>();
                    if analysis.status() != CompatibilityStatus::Compatible {
                        push(
                            &unit.id,
                            BlockerCode::PeerProofUnverified,
                            BlockerEvidenceState::Unknown,
                            BlockerSeverity::Verification,
                            references,
                            RemediationGate::AuthenticatePeer,
                        );
                    }
                    for item in analysis.findings() {
                        let (state, severity, gate) = classify_compat(item.code);
                        let evidence = item.evidence_refs.iter().map(compat_reference).collect();
                        push(
                            &unit.id,
                            BlockerCode::Compatibility(item.code),
                            state,
                            severity,
                            evidence,
                            gate,
                        );
                    }
                    for prerequisite in analysis.prerequisites() {
                        push(
                            &unit.id,
                            BlockerCode::CompatibilityGate(*prerequisite),
                            BlockerEvidenceState::Unknown,
                            BlockerSeverity::Verification,
                            vec![],
                            gate_for_compat(*prerequisite),
                        );
                    }
                }
            }
        }
        // A report on some other peer of the same SCC cannot satisfy a
        // dependent-to-prerequisite communication relationship. Walk graph
        // edges once, bounded by the existing GraphEdges limit.
        let mut missing_dependency_units = BTreeSet::new();
        for edge in graph
            .edges()
            .iter()
            .filter(|edge| edge.relation == GraphRelation::DependsOn)
        {
            let dependent = unit_by_system.get(edge.from.as_str()).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "remediation_dependency_source",
                    "dependency source must belong to an exact SCC",
                )
            })?;
            let prerequisite = unit_by_system.get(edge.to.as_str()).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "remediation_dependency_target",
                    "dependency target must belong to an exact SCC",
                )
            })?;
            let pair = if edge.from <= edge.to {
                (edge.from.clone(), edge.to.clone())
            } else {
                (edge.to.clone(), edge.from.clone())
            };
            if dependent != prerequisite && !peers.contains_key(&pair) {
                missing_dependency_units.insert((*dependent).to_owned());
            }
        }
        for arc in topology.prerequisites() {
            let source = arc
                .evidence_ids
                .iter()
                .map(|id| inventory_evidence(id, &sources))
                .collect::<Result<Vec<_>, _>>()?;
            push(
                &arc.dependent_unit,
                BlockerCode::DependencyGate,
                BlockerEvidenceState::Unknown,
                BlockerSeverity::Verification,
                source,
                RemediationGate::ValidatePrerequisite,
            );
            if missing_dependency_units.contains(&arc.dependent_unit) {
                push(
                    &arc.dependent_unit,
                    BlockerCode::PeerCompatibilityMissing,
                    BlockerEvidenceState::Unknown,
                    BlockerSeverity::Verification,
                    vec![],
                    RemediationGate::AuthenticatePeer,
                );
            }
        }

        limits.check(ResourceKind::Diagnostics, pending.len())?;
        let number_of_actions = limits.checked_add(
            ResourceKind::PlanActions,
            pending.len(),
            topology.units().len(),
        )?;
        limits.check(ResourceKind::PlanActions, number_of_actions)?;
        let mut blockers = Vec::with_capacity(pending.len());
        let mut actions = Vec::with_capacity(number_of_actions);
        let mut own_action_ids = BTreeMap::<String, Vec<String>>::new();
        for ((unit_id, code), (state, severity, sources, gates)) in pending {
            let evidence: Vec<_> = sources.into_iter().collect();
            let gates: Vec<_> = gates.into_iter().collect();
            let mut id_data = Encoder::new(limits);
            id_data.raw(b"CSHIFT_BLOCKER_D1_V1")?;
            id_data.bindings(pinned)?;
            id_data.string(&unit_id)?;
            id_data.code(code)?;
            id_data.evidences(&evidence)?;
            let blocker_id = format!(
                "blocker-{}",
                SnapshotDigest::hash(&id_data.finish())
                    .as_identifier()
                    .trim_start_matches("sha256:")
            );
            let owner = owner_by_unit.get(&unit_id).cloned().ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "remediation_action_owner",
                    "unknown owner unit",
                )
            })?;
            let mut action_id_data = Encoder::new(limits);
            action_id_data.raw(b"CSHIFT_ACTION_D1_V1")?;
            action_id_data.string(&blocker_id)?;
            let action_id = format!(
                "action-{}",
                SnapshotDigest::hash(&action_id_data.finish())
                    .as_identifier()
                    .trim_start_matches("sha256:")
            );
            let action_kind = kind_for_blocker(code);
            own_action_ids
                .entry(unit_id.clone())
                .or_default()
                .push(action_id.clone());
            actions.push(RemediationAction {
                source_bindings: pinned,
                id: action_id,
                unit_id: unit_id.clone(),
                kind: action_kind,
                resolves_blocker_ids: vec![blocker_id.clone()],
                prerequisite_action_ids: vec![],
                owner: owner.clone(),
                validation_gates: gates.clone(),
                maintenance: MaintenanceRequirement::EvidenceOnly,
                rollback: RollbackRequirement::EvidenceOnly,
                change_approval_required: matches!(
                    action_kind,
                    RemediationActionKind::ReviewPolicy
                ),
                evidence: evidence.clone(),
                due_at_unix_secs: deadline_for(target, &unit_id),
            });
            blockers.push(BlockerFinding {
                source_bindings: pinned,
                id: blocker_id,
                unit_id,
                code,
                evidence_state: state,
                severity,
                evidence,
                required_gates: gates,
                owner,
            });
        }
        let mut unit_gate_ids = BTreeMap::new();
        for unit in topology.units() {
            let mut enc = Encoder::new(limits);
            enc.raw(b"CSHIFT_UNIT_REVIEW_D1_V1")?;
            enc.bindings(pinned)?;
            enc.string(&unit.id)?;
            unit_gate_ids.insert(
                unit.id.clone(),
                format!(
                    "action-{}",
                    SnapshotDigest::hash(&enc.finish())
                        .as_identifier()
                        .trim_start_matches("sha256:")
                ),
            );
        }
        for unit in topology.units() {
            let mut before = own_action_ids.remove(&unit.id).unwrap_or_default();
            for arc in topology
                .prerequisites()
                .iter()
                .filter(|arc| arc.dependent_unit == unit.id)
            {
                let upstream = unit_gate_ids.get(&arc.prerequisite_unit).ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "remediation_dependency",
                        "dependency action is not an existing SCC unit gate",
                    )
                })?;
                before.push(upstream.clone());
            }
            before.sort();
            before.dedup();
            limits.check(ResourceKind::PlannerCandidates, before.len())?;
            let owner = owner_by_unit.get(&unit.id).cloned().ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "remediation_unit_owner",
                    "SCC owner not found",
                )
            })?;
            actions.push(RemediationAction {
                source_bindings: pinned,
                id: unit_gate_ids.get(&unit.id).cloned().ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "remediation_unit_gate",
                        "unit gate missing",
                    )
                })?,
                unit_id: unit.id.clone(),
                kind: RemediationActionKind::ReviewUnitGate,
                resolves_blocker_ids: vec![],
                prerequisite_action_ids: before,
                owner,
                validation_gates: vec![RemediationGate::ReviewUnitReadiness],
                maintenance: MaintenanceRequirement::ReviewedWindowRequired,
                rollback: RollbackRequirement::ReviewedPlanRequired,
                change_approval_required: true,
                evidence: vec![],
                due_at_unix_secs: deadline_for(target, &unit.id),
            });
        }
        actions.sort_by(|a, b| (&a.unit_id, &a.id).cmp(&(&b.unit_id, &b.id)));
        blockers.sort_by(|a, b| (&a.unit_id, &a.code, &a.id).cmp(&(&b.unit_id, &b.code, &b.id)));
        // Enforce all action prerequisite references and the absence of cycles.
        verify_action_dag(&actions, limits)?;
        let mut writer = Encoder::new(limits);
        writer.raw(b"CSHIFT_REMEDIATION_REPORT_V1")?;
        writer.u16(REMEDIATION_ANALYSIS_VERSION)?;
        writer.bindings(pinned)?;
        let mut digests: Vec<_> = compatibilities
            .iter()
            .map(|v| v.digest().as_bytes())
            .collect();
        digests.sort();
        writer.count(digests.len())?;
        for digest in digests {
            writer.raw(&digest)?;
        }
        writer.count(blockers.len())?;
        for blocker in &blockers {
            writer.blocker(blocker)?;
        }
        writer.count(actions.len())?;
        for action in &actions {
            writer.action(action)?;
        }
        let canonical = writer.finish();
        let digest = SnapshotDigest::hash(&canonical);
        Ok(RemediationAnalysis {
            bindings: pinned,
            blockers,
            actions,
            canonical,
            digest,
        })
    }
}

fn problem(code: DiagnosticCode, subject: &'static str, reason: &'static str) -> Diagnostic {
    Diagnostic::new(code, subject, reason)
}

fn valid_identifier(input: &str, subject: &'static str) -> Result<(), Diagnostic> {
    if input.is_empty()
        || input.len() > 256
        || !input
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:/-".contains(&c))
    {
        return Err(problem(
            DiagnosticCode::InvalidIdentifier,
            subject,
            "identifier or source attribution has unsupported characters or length",
        ));
    }
    Ok(())
}

fn inventory_evidence(
    id: &str,
    sources: &BTreeMap<&str, &crate::EvidenceRecord>,
) -> Result<RemediationEvidence, Diagnostic> {
    let item = sources.get(id).ok_or_else(|| {
        problem(
            DiagnosticCode::InvalidReference,
            "remediation_evidence",
            "referenced evidence must exist in the exact inventory",
        )
    })?;
    Ok(RemediationEvidence::Inventory {
        source_id: item.source_id.clone(),
        run_id: item.run_id.clone(),
        evidence_id: item.id.clone(),
    })
}

fn compat_reference(value: &CapabilityEvidenceRef) -> RemediationEvidence {
    RemediationEvidence::Compatibility {
        source_id: value.source_id.clone(),
        evidence_id: value.evidence_id.clone(),
        source_revision: value.source_revision.clone(),
    }
}

fn target_reference(target: &TargetProfile) -> RemediationEvidence {
    let source = &target.content().provenance;
    RemediationEvidence::TargetDocument {
        issuer_id: source.issuer_id.clone(),
        document_id: source.document_id.clone(),
        source_revision: source.revision.clone(),
    }
}

fn deadline_for(target: &TargetProfile, unit: &str) -> Option<i64> {
    target
        .content()
        .deadline
        .as_ref()
        .filter(|deadline| {
            deadline.applies_to == unit
                || deadline.applies_to == target.content().scope_id
                || deadline.applies_to == target.content().profile_id
        })
        .map(|deadline| deadline.due_at_unix_secs)
}

// The v1 risk schema uses fixed tags, independent of Rust Debug names or
// declaration order. Any change requires a reviewed schema generation.
fn risk_uncertainty_tag(value: Option<RiskUncertainty>) -> u8 {
    match value {
        None => 0,
        Some(RiskUncertainty::MissingAssessment) => 1,
        Some(RiskUncertainty::NoConfirmedUse) => 2,
        Some(RiskUncertainty::UnconfirmedUse) => 3,
        Some(RiskUncertainty::WeakEvidence) => 4,
        Some(RiskUncertainty::ConflictingEvidence) => 5,
        Some(RiskUncertainty::IncompleteCoverage) => 6,
        Some(RiskUncertainty::ScenarioAssumption) => 7,
    }
}

fn risk_finding_code_tag(value: RiskFindingCode) -> u8 {
    match value {
        RiskFindingCode::UnresolvedFactor => 1,
        RiskFindingCode::ElevatedFactor => 2,
        RiskFindingCode::SusceptibleUse => 3,
        RiskFindingCode::ScenarioDependent => 4,
    }
}

fn evidence_rank(value: BlockerEvidenceState) -> u8 {
    match value {
        BlockerEvidenceState::Claimed => 1,
        BlockerEvidenceState::Unknown => 2,
        BlockerEvidenceState::Contradicted => 3,
        BlockerEvidenceState::Prohibited => 4,
    }
}

fn classify_compat(
    code: CompatibilityCode,
) -> (BlockerEvidenceState, BlockerSeverity, RemediationGate) {
    use CompatibilityCode as C;
    match code {
        C::AlgorithmForbidden
        | C::ProtocolNotApproved
        | C::CertificateNotApproved
        | C::HybridNotApproved
        | C::DowngradeRejected => (
            BlockerEvidenceState::Prohibited,
            BlockerSeverity::HardPolicy,
            RemediationGate::ApprovePolicyAlternative,
        ),
        C::NegotiationMismatch | C::PkiMismatch | C::EvidenceConflict | C::CapabilityConflict => (
            BlockerEvidenceState::Contradicted,
            BlockerSeverity::Verification,
            RemediationGate::VerifyEvidence,
        ),
        C::PkiMissing | C::PkiUnverified => (
            BlockerEvidenceState::Unknown,
            BlockerSeverity::Verification,
            RemediationGate::ValidatePki,
        ),
        C::HybridProofMissing => (
            BlockerEvidenceState::Unknown,
            BlockerSeverity::Verification,
            RemediationGate::VerifyHybrid,
        ),
        C::CapabilityMissing | C::CapabilityUnproven | C::CapabilityStale => (
            BlockerEvidenceState::Unknown,
            BlockerSeverity::Verification,
            RemediationGate::VerifyProvider,
        ),
        C::EvidenceStale | C::EvidenceBindingMismatch => (
            BlockerEvidenceState::Unknown,
            BlockerSeverity::Verification,
            RemediationGate::VerifyEvidence,
        ),
        C::TargetNotSpecified => (
            BlockerEvidenceState::Unknown,
            BlockerSeverity::HardPolicy,
            RemediationGate::ApprovePolicyAlternative,
        ),
        C::PeerLinkMissing | C::NegotiationMissing | C::NegotiationUnauthenticated => (
            BlockerEvidenceState::Unknown,
            BlockerSeverity::Verification,
            RemediationGate::AuthenticatePeer,
        ),
    }
}

fn gate_for_compat(value: CompatibilityPrerequisite) -> RemediationGate {
    use CompatibilityPrerequisite as P;
    match value {
        P::VerifyPeerLink | P::VerifyNegotiation => RemediationGate::AuthenticatePeer,
        P::VerifyInitiator | P::VerifyResponder => RemediationGate::VerifyProvider,
        P::VerifyPki | P::VerifyRevocation => RemediationGate::ValidatePki,
        P::VerifyHybrid => RemediationGate::VerifyHybrid,
        P::ChangeTarget => RemediationGate::ApprovePolicyAlternative,
        P::ReconcileEvidence => RemediationGate::VerifyEvidence,
    }
}

fn kind_for_blocker(code: BlockerCode) -> RemediationActionKind {
    match code {
        BlockerCode::OwnerMissing | BlockerCode::OwnerAmbiguous => {
            RemediationActionKind::ResolveOwner
        }
        BlockerCode::RiskUnresolved(_) | BlockerCode::RiskElevated(_) => {
            RemediationActionKind::AssessRisk
        }
        BlockerCode::DeadlinePassed => RemediationActionKind::ReviewDeadline,
        BlockerCode::DependencyGate => RemediationActionKind::ValidateDependency,
        BlockerCode::PeerProofUnverified | BlockerCode::PeerCompatibilityMissing => {
            RemediationActionKind::VerifyPeer
        }
        BlockerCode::CompatibilityGate(value) => kind_for_gate(gate_for_compat(value)),
        BlockerCode::Compatibility(value) => kind_for_gate(classify_compat(value).2),
    }
}

fn kind_for_gate(gate: RemediationGate) -> RemediationActionKind {
    match gate {
        RemediationGate::AssignOwner => RemediationActionKind::ResolveOwner,
        RemediationGate::VerifyEvidence => RemediationActionKind::ReconcileEvidence,
        RemediationGate::AuthenticatePeer => RemediationActionKind::VerifyPeer,
        RemediationGate::ValidatePki => RemediationActionKind::VerifyPki,
        RemediationGate::ApprovePolicyAlternative => RemediationActionKind::ReviewPolicy,
        RemediationGate::VerifyProvider => RemediationActionKind::VerifyProvider,
        RemediationGate::VerifyHybrid => RemediationActionKind::VerifyHybrid,
        RemediationGate::ValidatePrerequisite => RemediationActionKind::ValidateDependency,
        RemediationGate::ReviewRisk => RemediationActionKind::AssessRisk,
        RemediationGate::ReviewDeadline => RemediationActionKind::ReviewDeadline,
        RemediationGate::ReviewUnitReadiness => RemediationActionKind::ReviewUnitGate,
    }
}

fn verify_action_dag(actions: &[RemediationAction], limits: &Limits) -> Result<(), Diagnostic> {
    limits.check(ResourceKind::PlanActions, actions.len())?;
    let ids: BTreeSet<_> = actions.iter().map(|item| item.id.as_str()).collect();
    if ids.len() != actions.len() {
        return Err(problem(
            DiagnosticCode::DuplicateRecord,
            "remediation_action",
            "generated action identity collision",
        ));
    }
    let mut incoming = BTreeMap::<&str, usize>::new();
    let mut fanout = BTreeMap::<&str, Vec<&str>>::new();
    let mut edge_count = 0usize;
    for item in actions {
        incoming.insert(item.id.as_str(), item.prerequisite_action_ids.len());
        edge_count = limits.checked_add(
            ResourceKind::PlannerCandidates,
            edge_count,
            item.prerequisite_action_ids.len(),
        )?;
        for prereq in &item.prerequisite_action_ids {
            if prereq == &item.id || !ids.contains(prereq.as_str()) {
                return Err(problem(
                    DiagnosticCode::InvalidReference,
                    "remediation_action_dependency",
                    "action prerequisite must be a different existing action",
                ));
            }
            fanout.entry(prereq).or_default().push(&item.id);
        }
    }
    let mut ready: BTreeSet<&str> = incoming
        .iter()
        .filter_map(|(id, n)| (*n == 0).then_some(*id))
        .collect();
    let mut visited = 0usize;
    while let Some(first) = ready.iter().next().copied() {
        ready.remove(first);
        visited += 1;
        for dependent in fanout.get(first).into_iter().flat_map(|v| v.iter()) {
            let degree = incoming.get_mut(*dependent).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "remediation_action_dependency",
                    "dependent action disappeared",
                )
            })?;
            *degree = degree.checked_sub(1).ok_or_else(|| {
                problem(
                    DiagnosticCode::ArithmeticOverflow,
                    "remediation_action_dependency",
                    "dependency count underflow",
                )
            })?;
            if *degree == 0 {
                ready.insert(dependent);
            }
        }
    }
    if visited != actions.len() {
        return Err(problem(
            DiagnosticCode::InvalidStateTransition,
            "remediation_action_cycle",
            "action dependency graph cannot be cyclic",
        ));
    }
    Ok(())
}

/// Bounded report assembler; checks each byte range *before* allocation.
struct Encoder<'a> {
    bytes: Vec<u8>,
    limits: &'a Limits,
}
impl<'a> Encoder<'a> {
    fn new(limits: &'a Limits) -> Self {
        Self {
            bytes: Vec::new(),
            limits,
        }
    }
    fn raw(&mut self, data: &[u8]) -> Result<(), Diagnostic> {
        let next =
            self.limits
                .checked_add(ResourceKind::ExportBytes, self.bytes.len(), data.len())?;
        self.limits.check(ResourceKind::ExportBytes, next)?;
        self.bytes.extend_from_slice(data);
        Ok(())
    }
    fn flag(&mut self, flag: bool) -> Result<(), Diagnostic> {
        self.raw(&[u8::from(flag)])
    }
    fn u16(&mut self, value: u16) -> Result<(), Diagnostic> {
        self.raw(&value.to_be_bytes())
    }
    fn u32(&mut self, value: u32) -> Result<(), Diagnostic> {
        self.raw(&value.to_be_bytes())
    }
    fn i64(&mut self, value: i64) -> Result<(), Diagnostic> {
        self.raw(&value.to_be_bytes())
    }
    fn count(&mut self, len: usize) -> Result<(), Diagnostic> {
        let n = u32::try_from(len).map_err(|_| {
            problem(
                DiagnosticCode::ArithmeticOverflow,
                "remediation_export_count",
                "collection exceeds serialized count range",
            )
        })?;
        self.u32(n)
    }
    fn digest(&mut self, digest: SnapshotDigest) -> Result<(), Diagnostic> {
        self.raw(&digest.as_bytes())
    }
    fn string(&mut self, value: &str) -> Result<(), Diagnostic> {
        self.count(value.len())?;
        self.raw(value.as_bytes())
    }
    fn strings(&mut self, items: &[String]) -> Result<(), Diagnostic> {
        self.count(items.len())?;
        for item in items {
            self.string(item)?;
        }
        Ok(())
    }
    fn bindings(&mut self, b: RemediationBindings) -> Result<(), Diagnostic> {
        for digest in [
            b.inventory_digest,
            b.graph_digest,
            b.topology_digest,
            b.risk_digest,
            b.target_digest,
        ] {
            self.digest(digest)?;
        }
        self.i64(b.evaluated_at_unix_secs)
    }
    fn evidence(&mut self, value: &RemediationEvidence) -> Result<(), Diagnostic> {
        match value {
            RemediationEvidence::Inventory {
                source_id,
                run_id,
                evidence_id,
            } => {
                self.raw(&[1])?;
                for part in [source_id, run_id, evidence_id] {
                    self.string(part)?;
                }
            }
            RemediationEvidence::Compatibility {
                source_id,
                evidence_id,
                source_revision,
            } => {
                self.raw(&[2])?;
                for part in [source_id, evidence_id, source_revision] {
                    self.string(part)?;
                }
            }
            RemediationEvidence::RiskAssessment { reference_id } => {
                self.raw(&[3])?;
                self.string(reference_id)?;
            }
            RemediationEvidence::TargetDocument {
                issuer_id,
                document_id,
                source_revision,
            } => {
                self.raw(&[4])?;
                for part in [issuer_id, document_id, source_revision] {
                    self.string(part)?;
                }
            }
            RemediationEvidence::TargetDeadline { reference_id } => {
                self.raw(&[5])?;
                self.string(reference_id)?;
            }
        }
        Ok(())
    }
    fn evidences(&mut self, items: &[RemediationEvidence]) -> Result<(), Diagnostic> {
        self.count(items.len())?;
        for item in items {
            self.evidence(item)?;
        }
        Ok(())
    }
    fn code(&mut self, code: BlockerCode) -> Result<(), Diagnostic> {
        match code {
            BlockerCode::OwnerMissing => self.raw(&[1]),
            BlockerCode::OwnerAmbiguous => self.raw(&[2]),
            BlockerCode::RiskUnresolved(kind) => self.raw(&[3, kind as u8]),
            BlockerCode::RiskElevated(kind) => self.raw(&[4, kind as u8]),
            BlockerCode::PeerProofUnverified => self.raw(&[5]),
            BlockerCode::PeerCompatibilityMissing => self.raw(&[6]),
            BlockerCode::Compatibility(kind) => self.raw(&[7, kind as u8]),
            BlockerCode::CompatibilityGate(kind) => self.raw(&[8, kind as u8]),
            BlockerCode::DependencyGate => self.raw(&[9]),
            BlockerCode::DeadlinePassed => self.raw(&[10]),
        }
    }
    fn owner(&mut self, value: &RemediationOwner) -> Result<(), Diagnostic> {
        match value {
            RemediationOwner::Missing => self.raw(&[1]),
            RemediationOwner::Claimed(value) => {
                self.raw(&[2])?;
                self.string(value)
            }
            RemediationOwner::Ambiguous(items) => {
                self.raw(&[3])?;
                self.strings(items)
            }
        }
    }
    fn gates(&mut self, items: &[RemediationGate]) -> Result<(), Diagnostic> {
        self.count(items.len())?;
        for item in items {
            self.raw(&[*item as u8])?;
        }
        Ok(())
    }
    fn blocker(&mut self, blocker: &BlockerFinding) -> Result<(), Diagnostic> {
        self.bindings(blocker.source_bindings)?;
        self.string(&blocker.id)?;
        self.string(&blocker.unit_id)?;
        self.code(blocker.code)?;
        self.raw(&[blocker.evidence_state as u8, blocker.severity as u8])?;
        self.evidences(&blocker.evidence)?;
        self.gates(&blocker.required_gates)?;
        self.owner(&blocker.owner)
    }
    fn action(&mut self, action: &RemediationAction) -> Result<(), Diagnostic> {
        self.bindings(action.source_bindings)?;
        self.string(&action.id)?;
        self.string(&action.unit_id)?;
        self.raw(&[action.kind as u8])?;
        self.strings(&action.resolves_blocker_ids)?;
        self.strings(&action.prerequisite_action_ids)?;
        self.owner(&action.owner)?;
        self.gates(&action.validation_gates)?;
        self.raw(&[action.maintenance as u8, action.rollback as u8])?;
        self.flag(action.change_approval_required)?;
        self.evidences(&action.evidence)?;
        if let Some(due) = action.due_at_unix_secs {
            self.flag(true)?;
            self.i64(due)
        } else {
            self.flag(false)
        }
    }
    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
