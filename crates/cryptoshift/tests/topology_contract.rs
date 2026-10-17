//! Public API contract and adversarial acceptance tests for SCC topology.

use cryptoshift::{
    CollectionCompleteness, CollectionRun, ConflictState, CryptoObservation, CryptoUseKind,
    DependencyAnalysis, Diagnostic, DiagnosticCode, EvidenceBasis, EvidenceGraph, EvidenceRecord,
    GraphEdge, GraphNode, GraphNodeKind, GraphRelation, IDENTITY_VERSION, InventorySnapshot,
    Limits, NORMALIZATION_VERSION, ResourceKind, ValidatedInventorySnapshot,
};

fn snapshot() -> Result<ValidatedInventorySnapshot, Diagnostic> {
    ValidatedInventorySnapshot::new(
        InventorySnapshot {
            identity_version: IDENTITY_VERSION,
            normalization_version: NORMALIZATION_VERSION,
            scope_id: "synthetic-scope".to_owned(),
            runs: vec![CollectionRun {
                id: "run-1".into(),
                source_id: "collector-1".into(),
                scope_id: "synthetic-scope".into(),
                collected_at_unix_secs: 1,
                completeness: CollectionCompleteness::Partial,
            }],
            evidence: vec![
                EvidenceRecord {
                    id: "ev-direct".into(),
                    run_id: "run-1".into(),
                    source_id: "collector-1".into(),
                    basis: EvidenceBasis::Direct,
                    confidence_bps: 9_000,
                    observed_at_unix_secs: 1,
                },
                EvidenceRecord {
                    id: "ev-inferred".into(),
                    run_id: "run-1".into(),
                    source_id: "collector-1".into(),
                    basis: EvidenceBasis::Inferred,
                    confidence_bps: 2_000,
                    observed_at_unix_secs: 1,
                },
            ],
            observations: vec![CryptoObservation {
                id: "obs-configured".into(),
                asset_id: "app-a".into(),
                algorithm_id: "RSA-2048".into(),
                kind: CryptoUseKind::ConfiguredProtocol,
                conflict: ConflictState::Unresolved,
                evidence_ids: vec!["ev-inferred".into()],
            }],
            absences: vec![],
        },
        &Limits::default(),
    )
}

fn node(id: &str, kind: GraphNodeKind) -> GraphNode {
    GraphNode {
        id: id.to_owned(),
        kind,
        evidence_ids: vec!["ev-direct".into()],
        observation_id: None,
        observation_kind: None,
    }
}

fn link(from: &str, to: &str, relation: GraphRelation) -> GraphEdge {
    GraphEdge {
        from: from.to_owned(),
        to: to.to_owned(),
        relation,
        evidence_ids: vec!["ev-inferred".into()],
    }
}

fn dependency(from: &str, to: &str) -> GraphEdge {
    link(from, to, GraphRelation::DependsOn)
}

fn graph(nodes: Vec<GraphNode>, edges: Vec<GraphEdge>) -> Result<EvidenceGraph, Diagnostic> {
    EvidenceGraph::new(&snapshot()?, nodes, edges, &Limits::default())
}

#[test]
fn chain_has_prerequisites_first_and_is_order_invariant() -> Result<(), Diagnostic> {
    let vertices = vec![
        node("A", GraphNodeKind::System),
        node("C", GraphNodeKind::System),
        node("B", GraphNodeKind::System),
    ];
    let edges = vec![dependency("A", "B"), dependency("B", "C")];
    let baseline = graph(vertices.clone(), edges.clone())?;
    let topology = DependencyAnalysis::analyze(&baseline, &Limits::default())?;
    assert_eq!(topology.dependency_first_order(), ["C", "B", "A"]);
    assert_eq!(
        topology.prerequisite_chain("A", &Limits::default())?,
        ["C", "B"]
    );
    assert_eq!(
        topology.prerequisite_chain("C", &Limits::default())?,
        Vec::<String>::new()
    );
    assert_eq!(topology.source_digest(), baseline.source_digest());
    assert_eq!(topology.prerequisites().len(), 2);
    assert_eq!(topology.prerequisites()[0].evidence_ids, ["ev-inferred"]);

    let mut reverse_vertices = vertices;
    reverse_vertices.reverse();
    let mut reverse_edges = edges;
    reverse_edges.reverse();
    let reversed =
        DependencyAnalysis::analyze(&graph(reverse_vertices, reverse_edges)?, &Limits::default())?;
    assert_eq!(topology.units(), reversed.units());
    assert_eq!(topology.prerequisites(), reversed.prerequisites());
    assert_eq!(
        topology.dependency_first_order(),
        reversed.dependency_first_order()
    );
    Ok(())
}

#[test]
fn diamond_chain_has_unique_dependency_first_order() -> Result<(), Diagnostic> {
    let nodes = ["D", "B", "A", "C"]
        .into_iter()
        .map(|id| node(id, GraphNodeKind::System))
        .collect();
    let edges = vec![
        dependency("A", "C"),
        dependency("C", "D"),
        dependency("A", "B"),
        dependency("B", "D"),
    ];
    let topology = DependencyAnalysis::analyze(&graph(nodes, edges)?, &Limits::default())?;
    assert_eq!(topology.dependency_first_order(), ["D", "B", "C", "A"]);
    assert_eq!(
        topology.prerequisite_chain("A", &Limits::default())?,
        ["D", "B", "C"]
    );
    assert_eq!(topology.prerequisite_chain("B", &Limits::default())?, ["D"]);
    Ok(())
}

#[test]
fn nontrivial_cycles_self_loops_and_isolated_systems_preserved() -> Result<(), Diagnostic> {
    let systems = ["A", "B", "C", "D", "E", "F", "G"]
        .into_iter()
        .map(|id| node(id, GraphNodeKind::System))
        .collect();
    let edges = vec![
        dependency("A", "B"),
        dependency("B", "C"),
        dependency("C", "A"),
        dependency("D", "D"),
        dependency("F", "G"),
        dependency("G", "F"),
        dependency("E", "A"),
    ];
    let topology = DependencyAnalysis::analyze(&graph(systems, edges)?, &Limits::default())?;
    assert_eq!(topology.units().len(), 4);
    assert_eq!(topology.units()[0].system_ids, ["A", "B", "C"]);
    assert!(topology.units()[0].cyclic);
    assert_eq!(
        topology.units()[0].internal_dependency_evidence_ids,
        ["ev-inferred"]
    );
    assert_eq!(topology.units()[1].system_ids, ["D"]);
    assert!(topology.units()[1].cyclic);
    assert_eq!(topology.units()[2].system_ids, ["E"]);
    assert!(!topology.units()[2].cyclic);
    assert_eq!(topology.units()[3].system_ids, ["F", "G"]);
    assert!(topology.units()[3].cyclic);
    assert_eq!(topology.dependency_first_order(), ["A", "D", "E", "F"]);
    assert_eq!(topology.prerequisites().len(), 1);
    assert_eq!(topology.prerequisites()[0].dependent_unit, "E");
    assert_eq!(topology.prerequisites()[0].prerequisite_unit, "A");
    assert_eq!(topology.prerequisite_chain("E", &Limits::default())?, ["A"]);
    Ok(())
}

#[test]
fn structural_shared_infrastructure_is_direct_not_transitive() -> Result<(), Diagnostic> {
    let nodes = vec![
        node("app-a", GraphNodeKind::System),
        node("app-b", GraphNodeKind::System),
        node("shared-lib", GraphNodeKind::Library),
        node("cert-a", GraphNodeKind::Certificate),
        node("cert-b", GraphNodeKind::Certificate),
        node("root", GraphNodeKind::TrustAnchor),
        node("shared-hsm", GraphNodeKind::Hsm),
        node("key-1", GraphNodeKind::Key),
        node("key-2", GraphNodeKind::Key),
        node("vendor", GraphNodeKind::Vendor),
    ];
    let edges = vec![
        link("app-a", "shared-lib", GraphRelation::LoadsLibrary),
        link("app-b", "shared-lib", GraphRelation::LoadsLibrary),
        link("app-a", "cert-a", GraphRelation::UsesCertificate),
        link("app-b", "cert-b", GraphRelation::UsesCertificate),
        link("cert-a", "root", GraphRelation::IssuedBy),
        link("cert-b", "root", GraphRelation::IssuedBy),
        link("app-a", "shared-hsm", GraphRelation::UsesHsm),
        link("app-b", "shared-hsm", GraphRelation::UsesHsm),
        link("shared-hsm", "key-1", GraphRelation::HoldsKey),
        link("shared-hsm", "key-2", GraphRelation::HoldsKey),
        link("shared-lib", "vendor", GraphRelation::SuppliedBy),
    ];
    let topology = DependencyAnalysis::analyze(&graph(nodes, edges)?, &Limits::default())?;
    assert_eq!(topology.units().len(), 2);
    assert!(topology.prerequisites().is_empty());
    let by_target: std::collections::BTreeMap<&str, _> = topology
        .direct_fanout()
        .iter()
        .map(|item| (item.target_node_id.as_str(), item))
        .collect();
    for id in ["shared-lib", "root", "shared-hsm"] {
        let item = by_target.get(id).ok_or(Diagnostic {
            code: DiagnosticCode::InvalidReference,
            subject: "test_target",
            reason: "expected structural target missing",
            observed: None,
            maximum: None,
        })?;
        assert_eq!(item.incoming_edge_count, 2);
        assert_eq!(item.distinct_source_count, 2);
        assert_eq!(item.evidence_ids, ["ev-inferred"]);
    }
    assert_eq!(by_target["vendor"].incoming_edge_count, 1);
    assert_eq!(by_target["key-1"].incoming_edge_count, 1);
    assert_eq!(by_target["key-2"].incoming_edge_count, 1);
    assert!(!by_target.contains_key("app-a"));
    let by_source: std::collections::BTreeMap<&str, _> = topology
        .direct_outgoing_fanout()
        .iter()
        .map(|item| (item.source_node_id.as_str(), item))
        .collect();
    assert_eq!(by_source["shared-hsm"].source_kind, GraphNodeKind::Hsm);
    assert_eq!(by_source["shared-hsm"].outgoing_edge_count, 2);
    assert_eq!(by_source["shared-hsm"].distinct_target_count, 2);
    assert_eq!(by_source["app-a"].outgoing_edge_count, 3);
    assert_eq!(by_source["shared-lib"].outgoing_edge_count, 1);
    assert_eq!(by_source["shared-hsm"].evidence_ids, ["ev-inferred"]);
    Ok(())
}

#[test]
fn structural_crypto_use_retains_original_configured_classification() -> Result<(), Diagnostic> {
    let mut use_site = node("use-1", GraphNodeKind::CryptoUse);
    use_site.observation_id = Some("obs-configured".into());
    use_site.observation_kind = Some(CryptoUseKind::ConfiguredProtocol);
    use_site.evidence_ids = vec!["ev-inferred".into()];
    let nodes = vec![node("app-a", GraphNodeKind::System), use_site];
    let edges = vec![link("app-a", "use-1", GraphRelation::ExposesUse)];
    let graph = graph(nodes, edges)?;
    let topology = DependencyAnalysis::analyze(&graph, &Limits::default())?;
    assert_eq!(topology.units().len(), 1);
    assert_eq!(topology.direct_fanout().len(), 1);
    assert_eq!(
        graph.nodes()[1].observation_kind,
        Some(CryptoUseKind::ConfiguredProtocol)
    );
    assert_eq!(topology.direct_fanout()[0].evidence_ids, ["ev-inferred"]);
    Ok(())
}

#[test]
fn bounded_analysis_and_chain_fail_closed() -> Result<(), Diagnostic> {
    let base = graph(
        ["A", "B", "C"]
            .into_iter()
            .map(|id| node(id, GraphNodeKind::System))
            .collect(),
        vec![dependency("A", "B"), dependency("B", "C")],
    )?;
    let limits = Limits {
        max_planner_candidates: 4,
        ..Limits::default()
    };
    assert_eq!(
        DependencyAnalysis::analyze(&base, &limits)
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    let limits = Limits {
        max_graph_nodes: 2,
        ..Limits::default()
    };
    assert_eq!(
        DependencyAnalysis::analyze(&base, &limits)
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    let limits = Limits {
        max_graph_edges: 1,
        ..Limits::default()
    };
    assert_eq!(
        DependencyAnalysis::analyze(&base, &limits)
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    // Edge count (2) is in range, but the three node + two edge
    // evidence references exceed this stricter caller budget.
    let limits = Limits {
        max_graph_edges: 4,
        ..Limits::default()
    };
    assert_eq!(
        DependencyAnalysis::analyze(&base, &limits)
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    let limits = Limits {
        max_export_bytes: 1,
        ..Limits::default()
    };
    assert_eq!(
        DependencyAnalysis::analyze(&base, &limits)
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    let topology = DependencyAnalysis::analyze(&base, &Limits::default())?;
    let limits = Limits {
        max_planner_candidates: 2,
        ..Limits::default()
    };
    assert_eq!(
        topology
            .prerequisite_chain("A", &limits)
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    assert_eq!(
        topology
            .prerequisite_chain("nonexistent", &Limits::default())
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::InvalidReference)
    );
    assert_eq!(
        ResourceKind::PlannerCandidates.as_str(),
        "planner_candidates"
    );
    Ok(())
}

#[test]
fn ten_thousand_systems_analyze_iteratively_without_stack_overflow() -> Result<(), Diagnostic> {
    let node_count = 10_000_usize;
    let vertices: Vec<GraphNode> = (0..node_count)
        .map(|i| node(&format!("system-{i:05}"), GraphNodeKind::System))
        .collect();
    let mut edges = Vec::with_capacity(node_count - 1);
    for i in 0..(node_count - 1) {
        edges.push(dependency(
            &format!("system-{i:05}"),
            &format!("system-{:05}", i + 1),
        ));
    }
    let source = graph(vertices, edges)?;
    let topology = DependencyAnalysis::analyze(&source, &Limits::default())?;
    assert_eq!(topology.units().len(), node_count);
    assert_eq!(topology.prerequisites().len(), node_count - 1);
    assert_eq!(topology.dependency_first_order().len(), node_count);
    assert_eq!(
        topology.dependency_first_order()[0],
        format!("system-{:05}", node_count - 1)
    );
    assert_eq!(
        topology.dependency_first_order()[node_count - 1],
        "system-00000"
    );
    Ok(())
}

#[test]
fn hardware_use_relation_rejects_invalid_direction_or_kind() -> Result<(), Diagnostic> {
    let nodes = vec![
        node("service", GraphNodeKind::System),
        node("hardware", GraphNodeKind::Hsm),
        node("library", GraphNodeKind::Library),
    ];
    let wrong_source = graph(
        nodes.clone(),
        vec![link("library", "hardware", GraphRelation::UsesHsm)],
    );
    assert_eq!(
        wrong_source.err().map(|e| e.code),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    let reversed = graph(
        nodes,
        vec![link("hardware", "service", GraphRelation::UsesHsm)],
    );
    assert_eq!(
        reversed.err().map(|e| e.code),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    Ok(())
}
