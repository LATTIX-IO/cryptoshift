//! Offline consumer: inventory -> SCC -> remediation -> wave -> immutable plan.
//!
//! Run: cargo run -p cryptoshift --example migration_plan --locked
use cryptoshift::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits::default();
    let at = 1_800_000_000_i64;
    let inventory = ValidatedInventorySnapshot::new(
        InventorySnapshot {
            identity_version: IDENTITY_VERSION,
            normalization_version: NORMALIZATION_VERSION,
            scope_id: "sample-tenant".into(),
            runs: vec![CollectionRun {
                id: "run-1".into(),
                source_id: "collector".into(),
                scope_id: "sample-tenant".into(),
                collected_at_unix_secs: at - 100,
                completeness: CollectionCompleteness::Partial,
            }],
            evidence: vec![EvidenceRecord {
                id: "evidence-1".into(),
                run_id: "run-1".into(),
                source_id: "collector".into(),
                basis: EvidenceBasis::Direct,
                confidence_bps: 9000,
                observed_at_unix_secs: at - 100,
            }],
            observations: vec![],
            absences: vec![],
        },
        &limits,
    )?;
    let graph = EvidenceGraph::new(
        &inventory,
        vec![GraphNode {
            id: "application".into(),
            kind: GraphNodeKind::System,
            evidence_ids: vec!["evidence-1".into()],
            observation_id: None,
            observation_kind: None,
        }],
        vec![],
        &limits,
    )?;
    let topology = DependencyAnalysis::analyze(&graph, &limits)?;
    let risk = RiskAnalysis::analyze(&inventory, &graph, &topology, &[], &[], None, &limits)?;
    let target = TargetProfile::new(
        TargetProfileDraft {
            schema_version: TARGET_PROFILE_VERSION,
            profile_id: "pqc-target".into(),
            revision: 1,
            scope_id: "sample-tenant".into(),
            provenance: ProfileProvenance {
                issuer_id: "policy-office".into(),
                document_id: "approved-profile".into(),
                revision: "v1".into(),
                source_digest: None,
            },
            standards: vec![StandardEdition::Fips203_2024],
            algorithms: vec![AlgorithmConstraint {
                algorithm: KnownAlgorithm::MlKem1024,
                role: AlgorithmRole::KeyEncapsulation,
                minimum_category: Some(SecurityCategory::Five),
                disposition: ConstraintDisposition::Required,
            }],
            protocols: vec![ProtocolConstraint {
                protocol_id: "application-protocol".into(),
                revision: "profile-1".into(),
                role: AlgorithmRole::KeyEncapsulation,
                algorithm: KnownAlgorithm::MlKem1024,
                hybrid: None,
            }],
            certificates: vec![],
            cnsa20: None,
            deadline: None,
            expires_at_unix_secs: Some(at + 100),
        },
        &limits,
        Some(at),
    )?;
    // A production caller must independently authenticate and pin these
    // inputs. Here, everything is synthetic and created in one process.
    let expected = RemediationAnalyzer::input_bindings(
        &inventory, &graph, &topology, &risk, &target, at, &limits,
    )?;
    let report = RemediationAnalyzer::analyze(
        &inventory,
        &graph,
        &topology,
        &risk,
        &target,
        &[],
        expected,
        &limits,
    )?;
    if report.blockers().is_empty()
        || !report
            .blockers()
            .iter()
            .any(|blocker| blocker.code == BlockerCode::OwnerMissing)
    {
        return Err("an unowned, incomplete inventory must produce blockers".into());
    }
    if !report.actions().iter().any(|action| {
        action.kind == RemediationActionKind::ReviewUnitGate && action.change_approval_required
    }) {
        return Err("a migration unit must not be auto-authorized".into());
    }
    let independent = WavePlanner::input_bindings(&topology, &report, &target, &limits)?;
    let request = WavePlanRequest {
        schema_version: WAVE_PLAN_VERSION,
        capacity_systems_per_wave: 1,
        max_waves: 1,
        expected_bindings: independent,
        submitted_for_review_units: vec![],
    };
    let draft = WavePlanner::plan(&topology, &report, &target, &request, &limits)?;
    if draft.waves().len() != 1
        || draft.readiness().len() != 1
        || draft.readiness()[0].status != UnitReadinessStatus::Unverified
        || !draft.readiness()[0]
            .gates
            .iter()
            .any(|gate| gate.kind == ReadinessGateKind::ChangeApproval)
    {
        return Err("an incomplete/unowned system must not be granted readiness".into());
    }
    // This is a synthetic, non-authenticated example. Production consumers
    // obtain and validate expected SHA-256 source pins independently.
    let expected_pins =
        MigrationPlanner::input_pins(&topology, &report, &draft, &target, &[], None, &limits)?;
    let input = MigrationPlanRequest {
        schema_version: MIGRATION_PLAN_VERSION,
        expected_pins,
        exceptions: vec![],
    };
    let plan = MigrationPlanner::build(
        &topology,
        &report,
        &draft,
        &target,
        &[],
        None,
        &input,
        &limits,
    )?;
    if plan.status() != PlanAssessmentState::Partial
        || plan.residual_risks().is_empty()
        || !plan
            .residual_risks()
            .iter()
            .any(|risk| risk.kind == ResidualRiskKind::ChangeApproval)
        || !plan
            .residual_risks()
            .iter()
            .any(|risk| risk.kind == ResidualRiskKind::MissingCapabilityEvidence)
    {
        return Err("an unowned system may not be declared authorized or complete".into());
    }
    println!("migration plan state: {:?}", plan.status());
    println!("residual risk facets: {}", plan.residual_risks().len());
    println!("migration plan digest: {}", plan.digest().as_identifier());
    println!("candidate waves: {}", draft.waves().len());
    println!("readiness: {:?}", draft.readiness()[0].status);
    println!("wave digest: {}", draft.digest().as_identifier());
    println!("blockers: {}", report.blockers().len());
    println!("proposed actions: {}", report.actions().len());
    println!("digest: {}", report.digest().as_identifier());
    // The public all-or-nothing runner must preserve the manual plan's
    // semantic identity and retain the same unverified state.
    let atomic = AnalysisRunner::analyze(
        &AnalysisRequest {
            inventory: &inventory,
            graph: &graph,
            target: &target,
            expected_inventory_digest: inventory.export(&limits)?.digest,
            expected_graph_digest: graph.fingerprint(),
            expected_target_digest: target.digest(),
            compatibilities: &[],
            capability_catalogs: &[],
            quantum: &[],
            context: &[],
            scoring: None,
            evaluated_at_unix_secs: at,
            capacity_systems_per_wave: 1,
            max_waves: 1,
            submitted_for_review_units: &[],
            exceptions: &[],
            include_metrics: true,
        },
        &limits,
    );
    if atomic.outcome() != AnalysisOutcome::Partial
        || atomic.plan().map(MigrationPlanDraft::digest) != Some(plan.digest())
        || atomic.metrics().is_none()
    {
        return Err("atomic planning must match the manually pinned advisory plan".into());
    }
    // A forged upstream graph fingerprint cannot return a partial draft.
    let rejected = AnalysisRunner::analyze(
        &AnalysisRequest {
            inventory: &inventory,
            graph: &graph,
            target: &target,
            expected_inventory_digest: inventory.export(&limits)?.digest,
            expected_graph_digest: SnapshotDigest::from_bytes([0; 32]),
            expected_target_digest: target.digest(),
            compatibilities: &[],
            capability_catalogs: &[],
            quantum: &[],
            context: &[],
            scoring: None,
            evaluated_at_unix_secs: at,
            capacity_systems_per_wave: 1,
            max_waves: 1,
            submitted_for_review_units: &[],
            exceptions: &[],
            include_metrics: true,
        },
        &limits,
    );
    if rejected.outcome() != AnalysisOutcome::Failed
        || rejected.plan().is_some()
        || rejected.metrics().is_some()
    {
        return Err("forged plan input pins must fail atomically".into());
    }
    println!("atomic analysis state: {:?}", atomic.outcome());
    println!("forged graph pin: {:?}", rejected.outcome());
    println!("This is not an authorization to execute, migrate, or approve changes.");
    Ok(())
}
