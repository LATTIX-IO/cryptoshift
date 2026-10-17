//! Public, synthetic end-to-end prerequisite analysis (no network or changes).
use cryptoshift::{
    CollectionCompleteness, CollectionRun, DependencyAnalysis, Diagnostic, EvidenceBasis,
    EvidenceGraph, EvidenceRecord, GraphEdge, GraphNode, GraphNodeKind, GraphRelation,
    IDENTITY_VERSION, InventorySnapshot, Limits, NORMALIZATION_VERSION, ValidatedInventorySnapshot,
};

fn system(id: &str) -> GraphNode {
    GraphNode {
        id: id.into(),
        kind: GraphNodeKind::System,
        evidence_ids: vec!["fixture-evidence".into()],
        observation_id: None,
        observation_kind: None,
    }
}

fn dependency(from: &str, to: &str) -> GraphEdge {
    GraphEdge {
        from: from.into(),
        to: to.into(),
        relation: GraphRelation::DependsOn,
        evidence_ids: vec!["fixture-evidence".into()],
    }
}

fn main() -> Result<(), Diagnostic> {
    let limits = Limits::default();
    let snapshot = ValidatedInventorySnapshot::new(
        InventorySnapshot {
            identity_version: IDENTITY_VERSION,
            normalization_version: NORMALIZATION_VERSION,
            scope_id: "offline-fixture".into(),
            runs: vec![CollectionRun {
                id: "fixture-run".into(),
                source_id: "offline-collector".into(),
                scope_id: "offline-fixture".into(),
                collected_at_unix_secs: 10,
                completeness: CollectionCompleteness::Partial,
            }],
            evidence: vec![EvidenceRecord {
                id: "fixture-evidence".into(),
                run_id: "fixture-run".into(),
                source_id: "offline-collector".into(),
                basis: EvidenceBasis::Inferred,
                confidence_bps: 5_000,
                observed_at_unix_secs: 10,
            }],
            observations: vec![],
            absences: vec![],
        },
        &limits,
    )?;
    let graph = EvidenceGraph::new(
        &snapshot,
        vec![system("frontend"), system("api"), system("database")],
        vec![dependency("frontend", "api"), dependency("api", "database")],
        &limits,
    )?;
    let topology = DependencyAnalysis::analyze(&graph, &limits)?;
    println!("inventory: {}", topology.source_digest().as_identifier());
    println!("dependency first: {:?}", topology.dependency_first_order());
    println!(
        "frontend prerequisites: {:?}",
        topology.prerequisite_chain("frontend", &limits)?
    );
    println!(
        "cycles: {}",
        topology.units().iter().filter(|unit| unit.cyclic).count()
    );
    println!("No policy decision, readiness assessment, or infrastructure change.");
    Ok(())
}
