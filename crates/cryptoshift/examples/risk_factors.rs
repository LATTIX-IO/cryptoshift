//! Synthetic offline walk-through of evidence-first PQC risk factor analysis.

use cryptoshift::{
    ClaimOrigin, CollectionCompleteness, CollectionRun, ConflictState, ContextAssessment,
    CryptoObservation, CryptoUseKind, DependencyAnalysis, Diagnostic, EvidenceBasis, EvidenceGraph,
    EvidenceRecord, GraphEdge, GraphNode, GraphNodeKind, GraphRelation, IDENTITY_VERSION,
    InventorySnapshot, Limits, NORMALIZATION_VERSION, QuantumAssessment, QuantumPosture,
    RiskAnalysis, RiskFactorKind, RiskLevel, SCORE_PROFILE_VERSION, ScoreProfile,
    ValidatedInventorySnapshot,
};

fn main() -> Result<(), Diagnostic> {
    let limits = Limits::default();
    let inventory = ValidatedInventorySnapshot::new(
        InventorySnapshot {
            identity_version: IDENTITY_VERSION,
            normalization_version: NORMALIZATION_VERSION,
            scope_id: "offline-synthetic".into(),
            runs: vec![CollectionRun {
                id: "scan-1".into(),
                source_id: "synthetic-collector".into(),
                scope_id: "offline-synthetic".into(),
                collected_at_unix_secs: 10,
                completeness: CollectionCompleteness::Complete,
            }],
            evidence: vec![EvidenceRecord {
                id: "ev-1".into(),
                run_id: "scan-1".into(),
                source_id: "synthetic-collector".into(),
                basis: EvidenceBasis::Direct,
                confidence_bps: 9000,
                observed_at_unix_secs: 10,
            }],
            observations: vec![CryptoObservation {
                id: "rsa-observation".into(),
                asset_id: "frontend".into(),
                algorithm_id: "RSA-2048".into(),
                kind: CryptoUseKind::ActiveUse,
                conflict: ConflictState::Uncontested,
                evidence_ids: vec!["ev-1".into()],
            }],
            absences: vec![],
        },
        &limits,
    )?;
    let graph = EvidenceGraph::new(
        &inventory,
        vec![
            GraphNode {
                id: "frontend".into(),
                kind: GraphNodeKind::System,
                evidence_ids: vec!["ev-1".into()],
                observation_id: None,
                observation_kind: None,
            },
            GraphNode {
                id: "rsa-use-site".into(),
                kind: GraphNodeKind::CryptoUse,
                evidence_ids: vec!["ev-1".into()],
                observation_id: Some("rsa-observation".into()),
                observation_kind: Some(CryptoUseKind::ActiveUse),
            },
        ],
        vec![GraphEdge {
            from: "frontend".into(),
            to: "rsa-use-site".into(),
            relation: GraphRelation::ExposesUse,
            evidence_ids: vec!["ev-1".into()],
        }],
        &limits,
    )?;
    let topology = DependencyAnalysis::analyze(&graph, &limits)?;

    // This source assertion is explicit; the library never guesses the
    // quantum security of an algorithm solely from the text of its name.
    let profile = [QuantumAssessment {
        observation_id: "rsa-observation".into(),
        posture: QuantumPosture::Susceptible,
        origin: ClaimOrigin::AnalystAssessment,
        source_reference: "synthetic-algorithm-review".into(),
    }];
    let context: Vec<ContextAssessment> = RiskFactorKind::ALL
        .iter()
        .copied()
        .filter(|kind| kind.requires_context())
        .map(|kind| ContextAssessment {
            unit_id: "frontend".into(),
            factor: kind,
            level: RiskLevel::Moderate,
            origin: ClaimOrigin::AnalystAssessment,
            source_reference: format!("synthetic-review-{}", kind.as_str()),
        })
        .collect();
    let weights = ScoreProfile::new(
        "illustrative-v1-equal".into(),
        SCORE_PROFILE_VERSION,
        [1000; 10],
    )?;
    let report = RiskAnalysis::analyze(
        &inventory,
        &graph,
        &topology,
        &profile,
        &context,
        Some(&weights),
        &limits,
    )?;
    println!("inventory: {}", report.source_digest.as_identifier());
    for unit in &report.units {
        println!("unit: {}", unit.unit_id);
        for factor in &unit.factors {
            println!(
                "  {}: {:?} | uncertain: {:?}",
                factor.kind.as_str(),
                factor.level,
                factor.uncertainty,
            );
        }
        println!(
            "optional pressure: {:?}",
            unit.score.as_ref().map(|s| s.pressure_bps)
        );
        println!("findings: {}", unit.findings.len());
    }
    println!("Synthetic, attributed assessments only; no policy or migration approval.");
    Ok(())
}
