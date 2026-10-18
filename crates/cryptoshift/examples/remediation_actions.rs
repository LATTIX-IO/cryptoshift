//! Offline consumer journey: evidence graph -> SCC -> risk -> remediation actions.
//!
//! Run: cargo run -p cryptoshift --example remediation_actions --locked
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
    println!("blockers: {}", report.blockers().len());
    println!("proposed actions: {}", report.actions().len());
    println!("digest: {}", report.digest().as_identifier());
    println!("No changes have been executed, approved, or scheduled.");
    Ok(())
}
