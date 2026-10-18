//! Bounded SCC wave proposals, distinct from any authorization to migrate.
//!
//! D2 only orders *candidates* and reports unsatisfied external controls. A
//! review-submitted hint never authenticates an approval or discharges a gate.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    BlockerEvidenceState, BlockerSeverity, DependencyTopology, Diagnostic, DiagnosticCode, Limits,
    MaintenanceRequirement, RemediationAction, RemediationActionKind, RemediationAnalysis,
    RemediationAnalyzer, RemediationBindings, RemediationEvidence, RemediationGate,
    RemediationOwner, ResourceKind, RollbackRequirement, SnapshotDigest, TargetProfile,
};

/// Canonical output generation; changing any encoded field requires a review.
pub const WAVE_PLAN_VERSION: u16 = 1;

/// Non-authoritative classifications of review eligibility.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum UnitReadinessStatus {
    /// An explicit policy prohibition, contradiction or blocked ancestor exists.
    Blocked = 1,
    /// Source evidence, prerequisite assurance or owner is unresolved.
    Unverified = 2,
    /// Review was requested, but no externally authenticated approval exists.
    AwaitingExternalApproval = 3,
    /// No known D1 blocker remains; external review is still required.
    EligibleForReview = 4,
}

/// Unsatisfied external and structural gates. None are execution permissions.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ReadinessGateKind {
    /// One source-qualified blocker requires an independent resolution.
    UnresolvedBlocker = 1,
    /// A prerequisite unit has not been independently approved.
    UpstreamUnitApproval = 2,
    /// The migration-unit readiness review remains external.
    IndependentUnitReview = 3,
    /// Separate change-control approval is required.
    ChangeApproval = 4,
    /// A maintenance window needs approval.
    MaintenanceWindow = 5,
    /// A validated rollback or contingency plan is required.
    RollbackPlan = 6,
    /// An evidence or verification action must be completed and checked.
    ActionValidation = 7,
}

/// One non-authoritative readiness gate, retaining exact source references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessGate {
    /// Typed unsatisfied condition.
    pub kind: ReadinessGateKind,
    /// Exact D1 blocker, when the gate represents a blocker.
    pub blocker_id: Option<String>,
    /// Exact D1 action, when the gate represents an action.
    pub action_id: Option<String>,
    /// Exact upstream SCC ID for an upstream-approval gate.
    pub upstream_unit_id: Option<String>,
    /// Qualified source references; not authentication.
    pub evidence: Vec<RemediationEvidence>,
    /// Required FOSS-441 verification conditions for this gate.
    pub validations: Vec<RemediationGate>,
}

/// One proposed SCC unit and its readiness evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitReadiness {
    /// Exact SCC identity from FOSS-422.
    pub unit_id: String,
    /// All systems that must move together as an indivisible SCC.
    pub system_ids: Vec<String>,
    /// Candidate wave number, one-based; never an execution order.
    pub wave_number: usize,
    /// Review-only status; there is no operational Ready status.
    pub status: UnitReadinessStatus,
    /// Direct upstream SCC requirements.
    pub prerequisite_unit_ids: Vec<String>,
    /// Exact blocker IDs from D1.
    pub blocker_ids: Vec<String>,
    /// Exact action IDs, including the unit's review gate.
    pub action_ids: Vec<String>,
    /// Unfulfilled review, policy, proof and rollback controls.
    pub gates: Vec<ReadinessGate>,
    /// Claimed source-qualified ownership, never authenticated IAM.
    pub owner: RemediationOwner,
    /// Explicitly applicable source deadline, if present.
    pub due_at_unix_secs: Option<i64>,
}

/// Deterministic capacity-constrained candidate wave.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationWave {
    /// One-based candidate wave number.
    pub number: usize,
    /// SCC unit IDs selected for this wave, lexicographically sorted.
    pub unit_ids: Vec<String>,
    /// Number of system slots used, counting every member of an SCC.
    pub occupied_system_slots: usize,
}

/// Full replay-fence. Digests are content identities, not signatures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WavePlanBindings {
    /// Exact input tenant/application scope.
    pub scope_id: String,
    /// Original inventory/graph/topology/risk/target versions from D1.
    pub remediation_bindings: RemediationBindings,
    /// Immutable SHA-256 identity of the complete D1 report.
    pub remediation_digest: SnapshotDigest,
    /// Independent peer-evidence-set SHA-256 from FOSS-441.
    pub compatibility_set_digest: SnapshotDigest,
    /// Exact SCC input fingerprint, independently recomputed.
    pub topology_digest: SnapshotDigest,
    /// Exact target requirements content hash.
    pub target_digest: SnapshotDigest,
}

/// Bounded user-selected planning configuration; no authenticated approvals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WavePlanRequest {
    /// Versioned canonical planner schema.
    pub schema_version: u16,
    /// Number of individual system slots available in one proposed wave.
    pub capacity_systems_per_wave: usize,
    /// Highest permitted number of candidate waves.
    pub max_waves: usize,
    /// Source-bound content pins obtained from a separately trusted channel.
    pub expected_bindings: WavePlanBindings,
    /// User-supplied *workflow hint*, NOT an approval receipt.
    ///
    /// A review submission can change only EligibleForReview to
    /// AwaitingExternalApproval; it never dismisses blockers or verifies PKI.
    pub submitted_for_review_units: Vec<String>,
}

/// Immutable advisory wave and readiness report.
#[derive(Clone, Debug)]
pub struct WavePlanDraft {
    bindings: WavePlanBindings,
    waves: Vec<MigrationWave>,
    readiness: Vec<UnitReadiness>,
    canonical: Vec<u8>,
    digest: SnapshotDigest,
}

impl WavePlanDraft {
    /// All exact input identities required to independently validate this plan.
    #[must_use]
    pub fn bindings(&self) -> &WavePlanBindings {
        &self.bindings
    }
    /// Dependency-first, capacity-bounded candidate waves.
    #[must_use]
    pub fn waves(&self) -> &[MigrationWave] {
        &self.waves
    }
    /// Stable unit ordering with explicit unsatisfied gates.
    #[must_use]
    pub fn readiness(&self) -> &[UnitReadiness] {
        &self.readiness
    }
    /// Domain-separated v1 canonical report SHA-256.
    #[must_use]
    pub const fn digest(&self) -> SnapshotDigest {
        self.digest
    }
    /// Export already-built bytes only under caller's active size budget.
    pub fn export(&self, limits: &Limits) -> Result<Vec<u8>, Diagnostic> {
        limits.check(ResourceKind::ExportBytes, self.canonical.len())?;
        Ok(self.canonical.clone())
    }
}

/// Stateless, deterministic SCC wave sequencer; never executes changes.
pub struct WavePlanner;

impl WavePlanner {
    /// Compute content pins that the caller must verify independently.
    ///
    /// Computing this value from the same untrusted inputs does not make
    /// those inputs authentic and does not grant approval.
    pub fn input_bindings(
        topology: &DependencyTopology,
        remediation: &RemediationAnalysis,
        target: &TargetProfile,
        limits: &Limits,
    ) -> Result<WavePlanBindings, Diagnostic> {
        limits.validate()?;
        let actual_topology = RemediationAnalyzer::topology_digest(topology, limits)?;
        let original = remediation.bindings();
        if actual_topology != original.topology_digest
            || topology.source_digest() != original.inventory_digest
            || topology.graph_fingerprint() != original.graph_digest
            || target.digest() != original.target_digest
        {
            return Err(problem(
                DiagnosticCode::IntegrityMismatch,
                "wave_input_integrity",
                "topology, target and D1 inputs must match the same original graph and inventory",
            ));
        }
        // A report admitted under looser limits must fail if its bytes no longer fit.
        let _ = remediation.export(limits)?;
        let evaluated = original.evaluated_at_unix_secs;
        if target
            .content()
            .expires_at_unix_secs
            .is_some_and(|expiry| evaluated >= expiry)
        {
            return Err(problem(
                DiagnosticCode::StaleCriticalProfile,
                "wave_target_expiry",
                "target requirements expired at the exact evaluation time",
            ));
        }
        Ok(WavePlanBindings {
            scope_id: target.content().scope_id.clone(),
            remediation_bindings: original,
            remediation_digest: remediation.digest(),
            compatibility_set_digest: remediation.compatibility_set_digest(),
            topology_digest: actual_topology,
            target_digest: target.digest(),
        })
    }

    /// Produce a candidate dependency-first wave plan with unresolved gates.
    ///
    /// No gate is authenticated or discharged here. A returned plan is never
    /// a change-control, PKI, migration or deployment authorization.
    pub fn plan(
        topology: &DependencyTopology,
        remediation: &RemediationAnalysis,
        target: &TargetProfile,
        request: &WavePlanRequest,
        limits: &Limits,
    ) -> Result<WavePlanDraft, Diagnostic> {
        limits.validate()?;
        if request.schema_version != WAVE_PLAN_VERSION {
            return Err(problem(
                DiagnosticCode::UnsupportedSchemaVersion,
                "wave_schema",
                "unsupported wave planner schema version",
            ));
        }
        if request.capacity_systems_per_wave == 0 || request.max_waves == 0 {
            return Err(problem(
                DiagnosticCode::InvalidLimit,
                "wave_capacity",
                "capacity and maximum waves must both be positive",
            ));
        }
        limits.check(ResourceKind::GraphNodes, request.capacity_systems_per_wave)?;
        limits.check(ResourceKind::PlanWaves, request.max_waves)?;
        limits.check(ResourceKind::GraphNodes, topology.units().len())?;
        // SCC grouping must not bypass a tighter caller's original graph-node
        // budget: count every system member before allocating wave/ready data.
        let mut system_count = 0_usize;
        for unit in topology.units() {
            system_count = limits.checked_add(
                ResourceKind::GraphNodes,
                system_count,
                unit.system_ids.len(),
            )?;
        }
        limits.check(ResourceKind::GraphEdges, topology.prerequisites().len())?;
        limits.check(ResourceKind::PlanActions, remediation.actions().len())?;
        limits.check(ResourceKind::Diagnostics, remediation.blockers().len())?;
        limits.check(
            ResourceKind::ProfileReferences,
            request.submitted_for_review_units.len(),
        )?;
        let expected = Self::input_bindings(topology, remediation, target, limits)?;
        if request.expected_bindings != expected {
            return Err(problem(
                DiagnosticCode::IntegrityMismatch,
                "wave_replay_pin",
                "wave input evidence revisions differ from independently pinned inputs",
            ));
        }
        if topology.units().is_empty() {
            return Err(problem(
                DiagnosticCode::EmptyPayload,
                "wave_units",
                "no migration units are present to construct a wave plan",
            ));
        }
        let mut submitted = BTreeSet::new();
        for id in &request.submitted_for_review_units {
            if !submitted.insert(id.as_str()) {
                return Err(problem(
                    DiagnosticCode::DuplicateRecord,
                    "wave_review_submission",
                    "each review submission unit may appear only once",
                ));
            }
        }
        let mut units = BTreeMap::new();
        for unit in topology.units() {
            if units.insert(unit.id.as_str(), unit).is_some() {
                return Err(problem(
                    DiagnosticCode::DuplicateRecord,
                    "wave_units",
                    "a topology unit appears more than once",
                ));
            }
            if unit.system_ids.is_empty() {
                return Err(problem(
                    DiagnosticCode::InvalidReference,
                    "wave_scc",
                    "an indivisible SCC unit cannot be empty",
                ));
            }
            if unit.system_ids.len() > request.capacity_systems_per_wave {
                return Err(problem(
                    DiagnosticCode::ResourceLimitExceeded,
                    "wave_scc_capacity",
                    "an indivisible SCC exceeds system slots available in any one wave",
                ));
            }
        }
        if submitted.iter().any(|id| !units.contains_key(*id)) {
            return Err(problem(
                DiagnosticCode::InvalidReference,
                "wave_review_submission",
                "review submission references an unknown SCC unit",
            ));
        }

        let mut blockers = BTreeMap::<&str, Vec<&crate::BlockerFinding>>::new();
        let mut actions = BTreeMap::<&str, Vec<&RemediationAction>>::new();
        let mut action_ids = BTreeSet::new();
        let mut blocker_ids = BTreeSet::new();
        for blocker in remediation.blockers() {
            if !units.contains_key(blocker.unit_id.as_str()) {
                return Err(problem(
                    DiagnosticCode::InvalidReference,
                    "wave_blocker_unit",
                    "D1 blocker refers to an unknown SCC",
                ));
            }
            if blocker.source_bindings != expected.remediation_bindings
                || blocker.compatibility_set_digest != expected.compatibility_set_digest
            {
                return Err(problem(
                    DiagnosticCode::IntegrityMismatch,
                    "wave_blocker_binding",
                    "blocker must retain exact source and peer-evidence revisions",
                ));
            }
            if !blocker_ids.insert(blocker.id.as_str()) {
                return Err(problem(
                    DiagnosticCode::DuplicateRecord,
                    "wave_blocker_id",
                    "blocker identities must be unique",
                ));
            }
            blockers.entry(&blocker.unit_id).or_default().push(blocker);
        }
        for action in remediation.actions() {
            if !units.contains_key(action.unit_id.as_str()) {
                return Err(problem(
                    DiagnosticCode::InvalidReference,
                    "wave_action_unit",
                    "D1 action refers to an unknown SCC",
                ));
            }
            if action.source_bindings != expected.remediation_bindings
                || action.compatibility_set_digest != expected.compatibility_set_digest
            {
                return Err(problem(
                    DiagnosticCode::IntegrityMismatch,
                    "wave_action_binding",
                    "action must retain exact source and peer-evidence revisions",
                ));
            }
            if !action_ids.insert(action.id.as_str()) {
                return Err(problem(
                    DiagnosticCode::DuplicateRecord,
                    "wave_action_id",
                    "D1 action identities must be unique",
                ));
            }
            for id in &action.resolves_blocker_ids {
                if !blocker_ids.contains(id.as_str()) {
                    return Err(problem(
                        DiagnosticCode::InvalidReference,
                        "wave_action_blocker",
                        "an action may only reference a blocker in the exact D1 report",
                    ));
                }
            }
            actions.entry(&action.unit_id).or_default().push(action);
        }
        let mut prereqs = BTreeMap::<&str, BTreeSet<&str>>::new();
        let mut dependents = BTreeMap::<&str, BTreeSet<&str>>::new();
        for arc in topology.prerequisites() {
            if !units.contains_key(arc.dependent_unit.as_str())
                || !units.contains_key(arc.prerequisite_unit.as_str())
                || arc.dependent_unit == arc.prerequisite_unit
            {
                return Err(problem(
                    DiagnosticCode::InvalidReference,
                    "wave_prerequisite",
                    "SCC prerequisites must reference different existing units",
                ));
            }
            if !prereqs
                .entry(&arc.dependent_unit)
                .or_default()
                .insert(&arc.prerequisite_unit)
            {
                return Err(problem(
                    DiagnosticCode::DuplicateRecord,
                    "wave_prerequisite",
                    "duplicate SCC prerequisite is not allowed",
                ));
            }
            dependents
                .entry(&arc.prerequisite_unit)
                .or_default()
                .insert(&arc.dependent_unit);
        }

        // Validate D1 unit gate semantics before using its readiness assertions.
        for id in units.keys() {
            let list = actions.get(id).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "wave_unit_gate",
                    "every SCC requires one D1 unit review action",
                )
            })?;
            let gates: Vec<_> = list
                .iter()
                .filter(|a| a.kind == RemediationActionKind::ReviewUnitGate)
                .collect();
            if gates.len() != 1 {
                return Err(problem(
                    DiagnosticCode::InvalidStateTransition,
                    "wave_unit_gate",
                    "each SCC must have exactly one change-controlled review action",
                ));
            }
            let gate = gates[0];
            if !gate.change_approval_required
                || gate.maintenance != MaintenanceRequirement::ReviewedWindowRequired
                || gate.rollback != RollbackRequirement::ReviewedPlanRequired
                || !gate
                    .validation_gates
                    .contains(&RemediationGate::ReviewUnitReadiness)
            {
                return Err(problem(
                    DiagnosticCode::InvalidStateTransition,
                    "wave_safety_gate",
                    "unit review must retain change, maintenance and rollback obligations",
                ));
            }
            // No readiness can be borrowed from a different unit or evidence set.
            for action in list {
                for blocker_id in &action.resolves_blocker_ids {
                    if !blockers
                        .get(id)
                        .is_some_and(|v| v.iter().any(|b| b.id == *blocker_id))
                    {
                        return Err(problem(
                            DiagnosticCode::InvalidReference,
                            "wave_action_resolution",
                            "an action cannot claim to resolve a different SCC blocker",
                        ));
                    }
                }
                for prior in &action.prerequisite_action_ids {
                    if !action_ids.contains(prior.as_str()) {
                        return Err(problem(
                            DiagnosticCode::InvalidReference,
                            "wave_action_dependency",
                            "action prerequisite must exist in the bound D1 report",
                        ));
                    }
                }
            }
        }

        // Iterative Kahn ready queue; nodes released after a wave cannot enter
        // the same wave. Capacity counts system members, not SCC group count.
        let mut unmet: BTreeMap<&str, usize> = units
            .keys()
            .map(|id| (*id, prereqs.get(id).map_or(0, BTreeSet::len)))
            .collect();
        let mut ready: BTreeSet<&str> = unmet
            .iter()
            .filter_map(|(id, n)| (*n == 0).then_some(*id))
            .collect();
        let mut waves = Vec::new();
        let mut unit_wave = BTreeMap::<&str, usize>::new();
        let mut considered = 0_usize;
        while unit_wave.len() < units.len() {
            if waves.len() >= request.max_waves {
                return Err(problem(
                    DiagnosticCode::ResourceLimitExceeded,
                    "wave_count",
                    "the requested maximum number of waves cannot fit all SCC units",
                ));
            }
            let mut selected = Vec::<&str>::new();
            let mut occupied = 0_usize;
            for id in &ready {
                considered = limits.checked_add(ResourceKind::PlannerCandidates, considered, 1)?;
                let members = units
                    .get(id)
                    .ok_or_else(|| {
                        problem(
                            DiagnosticCode::InvalidReference,
                            "wave_ready_unit",
                            "ready unit is absent",
                        )
                    })?
                    .system_ids
                    .len();
                let left = request
                    .capacity_systems_per_wave
                    .checked_sub(occupied)
                    .ok_or_else(|| {
                        problem(
                            DiagnosticCode::ArithmeticOverflow,
                            "wave_slots",
                            "capacity arithmetic underflow",
                        )
                    })?;
                if members <= left {
                    occupied = limits.checked_add(ResourceKind::GraphNodes, occupied, members)?;
                    selected.push(*id);
                }
            }
            if selected.is_empty() {
                return Err(problem(
                    DiagnosticCode::InvalidStateTransition,
                    "wave_graph",
                    "no dependency-ready SCC can fit within the requested wave capacity",
                ));
            }
            for id in &selected {
                ready.remove(id);
            }
            let number = waves.len() + 1;
            for id in &selected {
                unit_wave.insert(id, number);
            }
            let mut sorted_ids: Vec<String> = selected.iter().map(|id| (*id).to_owned()).collect();
            sorted_ids.sort();
            waves.push(MigrationWave {
                number,
                unit_ids: sorted_ids,
                occupied_system_slots: occupied,
            });
            for id in selected {
                if let Some(next) = dependents.get(id) {
                    for child in next {
                        let count = unmet.get_mut(child).ok_or_else(|| {
                            problem(
                                DiagnosticCode::InvalidReference,
                                "wave_dependent",
                                "dependent SCC must be present in the condensation graph",
                            )
                        })?;
                        *count = count.checked_sub(1).ok_or_else(|| {
                            problem(
                                DiagnosticCode::ArithmeticOverflow,
                                "wave_dependency_count",
                                "prerequisite count underflow",
                            )
                        })?;
                        if *count == 0 {
                            ready.insert(child);
                        }
                    }
                }
            }
        }
        limits.check(ResourceKind::PlanWaves, waves.len())?;

        let mut readiness = Vec::with_capacity(units.len());
        let mut prior_status = BTreeMap::<&str, UnitReadinessStatus>::new();
        let mut total_gates = 0_usize;
        for wave in &waves {
            for id in &wave.unit_ids {
                let unit = units.get(id.as_str()).ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "wave_readiness_unit",
                        "scheduled unit not in exact SCC topology",
                    )
                })?;
                let item_blockers = blockers.get(id.as_str()).cloned().unwrap_or_default();
                let item_actions = actions.get(id.as_str()).ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "wave_readiness_action",
                        "unit action evidence is missing",
                    )
                })?;
                let mut gates = Vec::new();
                let mut blockers_ids = Vec::new();
                for blocker in &item_blockers {
                    blockers_ids.push(blocker.id.clone());
                    gates.push(ReadinessGate {
                        kind: ReadinessGateKind::UnresolvedBlocker,
                        blocker_id: Some(blocker.id.clone()),
                        action_id: None,
                        upstream_unit_id: None,
                        evidence: blocker.evidence.clone(),
                        validations: blocker.required_gates.clone(),
                    });
                }
                let mut action_ids_for_unit = Vec::new();
                let mut owner = RemediationOwner::Missing;
                let mut due = None;
                for action in item_actions {
                    action_ids_for_unit.push(action.id.clone());
                    if action.kind == RemediationActionKind::ReviewUnitGate {
                        owner = action.owner.clone();
                        due = action.due_at_unix_secs;
                        for (kind, condition) in [
                            (
                                ReadinessGateKind::IndependentUnitReview,
                                RemediationGate::ReviewUnitReadiness,
                            ),
                            (
                                ReadinessGateKind::ChangeApproval,
                                RemediationGate::ReviewUnitReadiness,
                            ),
                            (
                                ReadinessGateKind::MaintenanceWindow,
                                RemediationGate::ReviewUnitReadiness,
                            ),
                            (
                                ReadinessGateKind::RollbackPlan,
                                RemediationGate::ReviewUnitReadiness,
                            ),
                        ] {
                            gates.push(ReadinessGate {
                                kind,
                                blocker_id: None,
                                action_id: Some(action.id.clone()),
                                upstream_unit_id: None,
                                evidence: action.evidence.clone(),
                                validations: vec![condition],
                            });
                        }
                    } else {
                        gates.push(ReadinessGate {
                            kind: ReadinessGateKind::ActionValidation,
                            blocker_id: None,
                            action_id: Some(action.id.clone()),
                            upstream_unit_id: None,
                            evidence: action.evidence.clone(),
                            validations: action.validation_gates.clone(),
                        });
                    }
                }
                let predecessors = prereqs.get(id.as_str()).cloned().unwrap_or_default();
                for upstream in &predecessors {
                    let upstream_wave = unit_wave.get(upstream).ok_or_else(|| {
                        problem(
                            DiagnosticCode::InvalidReference,
                            "wave_predecessor",
                            "prerequisite SCC was not included in the wave plan",
                        )
                    })?;
                    if *upstream_wave >= wave.number {
                        return Err(problem(
                            DiagnosticCode::InvalidStateTransition,
                            "wave_order",
                            "upstream SCC must occur in an earlier wave",
                        ));
                    }
                    gates.push(ReadinessGate {
                        kind: ReadinessGateKind::UpstreamUnitApproval,
                        blocker_id: None,
                        action_id: None,
                        upstream_unit_id: Some((*upstream).to_owned()),
                        evidence: vec![],
                        validations: vec![RemediationGate::ValidatePrerequisite],
                    });
                }
                total_gates = limits.checked_add(
                    ResourceKind::PlannerCandidates,
                    total_gates,
                    gates.len(),
                )?;
                let hard = item_blockers.iter().any(|b| {
                    b.severity == BlockerSeverity::HardPolicy
                        || matches!(
                            b.evidence_state,
                            BlockerEvidenceState::Prohibited | BlockerEvidenceState::Contradicted
                        )
                });
                let upstream_hard = predecessors
                    .iter()
                    .any(|id| prior_status.get(id) == Some(&UnitReadinessStatus::Blocked));
                // An upstream *scheduled* in an earlier wave has not been
                // approved. It always remains an external readiness gate.
                let status = if hard || upstream_hard {
                    UnitReadinessStatus::Blocked
                } else if !item_blockers.is_empty() || !predecessors.is_empty() {
                    UnitReadinessStatus::Unverified
                } else if submitted.contains(id.as_str()) {
                    UnitReadinessStatus::AwaitingExternalApproval
                } else {
                    UnitReadinessStatus::EligibleForReview
                };
                prior_status.insert(id.as_str(), status);
                blockers_ids.sort();
                action_ids_for_unit.sort();
                gates.sort_by(|a, b| {
                    (&a.kind, &a.blocker_id, &a.action_id, &a.upstream_unit_id).cmp(&(
                        &b.kind,
                        &b.blocker_id,
                        &b.action_id,
                        &b.upstream_unit_id,
                    ))
                });
                readiness.push(UnitReadiness {
                    unit_id: id.clone(),
                    system_ids: unit.system_ids.clone(),
                    wave_number: wave.number,
                    status,
                    prerequisite_unit_ids: predecessors.into_iter().map(str::to_owned).collect(),
                    blocker_ids: blockers_ids,
                    action_ids: action_ids_for_unit,
                    gates,
                    owner,
                    due_at_unix_secs: due,
                });
            }
        }
        readiness.sort_by(|a, b| a.unit_id.cmp(&b.unit_id));
        let mut enc = Encoder::new(limits);
        enc.raw(b"CSHIFT_WAVE_PLAN_V1")?;
        enc.u16(WAVE_PLAN_VERSION)?;
        enc.bindings(&expected)?;
        enc.count(request.capacity_systems_per_wave)?;
        enc.count(request.max_waves)?;
        enc.count(submitted.len())?;
        for id in submitted {
            enc.string(id)?;
        }
        enc.count(waves.len())?;
        for wave in &waves {
            enc.count(wave.number)?;
            enc.count(wave.occupied_system_slots)?;
            enc.strings(&wave.unit_ids)?;
        }
        enc.count(readiness.len())?;
        for unit in &readiness {
            enc.unit(unit)?;
        }
        let canonical = enc.finish();
        let digest = SnapshotDigest::hash(&canonical);
        Ok(WavePlanDraft {
            bindings: expected,
            waves,
            readiness,
            canonical,
            digest,
        })
    }
}

fn problem(code: DiagnosticCode, subject: &'static str, reason: &'static str) -> Diagnostic {
    Diagnostic::new(code, subject, reason)
}

/// Bounded binary export; charges every emitted byte before copying it.
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
        let len =
            self.limits
                .checked_add(ResourceKind::ExportBytes, self.bytes.len(), data.len())?;
        self.limits.check(ResourceKind::ExportBytes, len)?;
        self.bytes.extend_from_slice(data);
        Ok(())
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
    fn flag(&mut self, value: bool) -> Result<(), Diagnostic> {
        self.raw(&[u8::from(value)])
    }
    fn count(&mut self, value: usize) -> Result<(), Diagnostic> {
        let small = u32::try_from(value).map_err(|_| {
            problem(
                DiagnosticCode::ArithmeticOverflow,
                "wave_export_count",
                "wave export exceeds the canonical count encoding",
            )
        })?;
        self.u32(small)
    }
    fn digest(&mut self, value: SnapshotDigest) -> Result<(), Diagnostic> {
        self.raw(&value.as_bytes())
    }
    fn string(&mut self, value: &str) -> Result<(), Diagnostic> {
        self.count(value.len())?;
        self.raw(value.as_bytes())
    }
    fn strings(&mut self, values: &[String]) -> Result<(), Diagnostic> {
        self.count(values.len())?;
        for item in values {
            self.string(item)?;
        }
        Ok(())
    }
    fn bindings(&mut self, value: &WavePlanBindings) -> Result<(), Diagnostic> {
        self.string(&value.scope_id)?;
        let b = value.remediation_bindings;
        for digest in [
            b.inventory_digest,
            b.graph_digest,
            b.topology_digest,
            b.risk_digest,
            b.target_digest,
            value.remediation_digest,
            value.compatibility_set_digest,
            value.topology_digest,
            value.target_digest,
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
                for item in [source_id, run_id, evidence_id] {
                    self.string(item)?;
                }
            }
            RemediationEvidence::Compatibility {
                source_id,
                evidence_id,
                source_revision,
            } => {
                self.raw(&[2])?;
                for item in [source_id, evidence_id, source_revision] {
                    self.string(item)?;
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
                for item in [issuer_id, document_id, source_revision] {
                    self.string(item)?;
                }
            }
            RemediationEvidence::TargetDeadline { reference_id } => {
                self.raw(&[5])?;
                self.string(reference_id)?;
            }
        }
        Ok(())
    }
    fn gate(&mut self, value: &ReadinessGate) -> Result<(), Diagnostic> {
        self.raw(&[value.kind as u8])?;
        for item in [&value.blocker_id, &value.action_id, &value.upstream_unit_id] {
            if let Some(id) = item {
                self.flag(true)?;
                self.string(id)?;
            } else {
                self.flag(false)?;
            }
        }
        self.count(value.evidence.len())?;
        for item in &value.evidence {
            self.evidence(item)?;
        }
        self.count(value.validations.len())?;
        for item in &value.validations {
            self.raw(&[*item as u8])?;
        }
        Ok(())
    }
    fn owner(&mut self, value: &RemediationOwner) -> Result<(), Diagnostic> {
        match value {
            RemediationOwner::Missing => self.raw(&[1]),
            RemediationOwner::Claimed(id) => {
                self.raw(&[2])?;
                self.string(id)
            }
            RemediationOwner::Ambiguous(ids) => {
                self.raw(&[3])?;
                self.strings(ids)
            }
        }
    }
    fn unit(&mut self, value: &UnitReadiness) -> Result<(), Diagnostic> {
        self.string(&value.unit_id)?;
        self.strings(&value.system_ids)?;
        self.count(value.wave_number)?;
        self.raw(&[value.status as u8])?;
        self.strings(&value.prerequisite_unit_ids)?;
        self.strings(&value.blocker_ids)?;
        self.strings(&value.action_ids)?;
        self.owner(&value.owner)?;
        if let Some(due) = value.due_at_unix_secs {
            self.flag(true)?;
            self.i64(due)?;
        } else {
            self.flag(false)?;
        }
        self.count(value.gates.len())?;
        for gate in &value.gates {
            self.gate(gate)?;
        }
        Ok(())
    }
    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
