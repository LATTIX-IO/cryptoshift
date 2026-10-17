//! Public graph consumer tests verifying topology and evidence constraints.

use cryptoshift::{
    AbsenceRecord, AbsenceStatus, CollectionCompleteness, CollectionRun, ConflictState,
    CryptoObservation, CryptoUseKind, Diagnostic, DiagnosticCode, EvidenceBasis, EvidenceGraph,
    EvidenceRecord, GraphEdge, GraphNode, GraphNodeKind, GraphRelation, IDENTITY_VERSION,
    InventorySnapshot, Limits, NORMALIZATION_VERSION, ValidatedInventorySnapshot,
};

fn source() -> Result<ValidatedInventorySnapshot, Diagnostic> {
    let snapshot = InventorySnapshot {
        identity_version: IDENTITY_VERSION,
        normalization_version: NORMALIZATION_VERSION,
        scope_id: "synthetic-tenant".to_string(),
        runs: vec![CollectionRun {
            id: "run-a".into(),
            source_id: "collector-a".into(),
            scope_id: "synthetic-tenant".into(),
            collected_at_unix_secs: 10,
            completeness: CollectionCompleteness::Partial,
        }],
        evidence: vec![
            EvidenceRecord {
                id: "ev-z".into(),
                run_id: "run-a".into(),
                source_id: "collector-a".into(),
                basis: EvidenceBasis::Direct,
                confidence_bps: 9000,
                observed_at_unix_secs: 10,
            },
            EvidenceRecord {
                id: "ev-a".into(),
                run_id: "run-a".into(),
                source_id: "collector-a".into(),
                basis: EvidenceBasis::Inferred,
                confidence_bps: 3000,
                observed_at_unix_secs: 10,
            },
        ],
        observations: vec![CryptoObservation {
            id: "obs-1".into(),
            asset_id: "system-1".into(),
            algorithm_id: "RSA-2048".into(),
            kind: CryptoUseKind::ConfiguredProtocol,
            conflict: ConflictState::Unresolved,
            evidence_ids: vec!["ev-z".into()],
        }],
        absences: vec![AbsenceRecord {
            run_id: "run-a".into(),
            asset_id: "missing".into(),
            status: AbsenceStatus::Tentative,
        }],
    };
    ValidatedInventorySnapshot::new(snapshot, &Limits::default())
}

fn simple() -> (Vec<GraphNode>, Vec<GraphEdge>) {
    let nodes = vec![
        GraphNode {
            id: "use-1".into(),
            kind: GraphNodeKind::CryptoUse,
            observation_id: Some("obs-1".into()),
            observation_kind: Some(CryptoUseKind::ConfiguredProtocol),
            evidence_ids: vec!["ev-z".into()],
        },
        GraphNode {
            id: "system-1".into(),
            kind: GraphNodeKind::System,
            observation_id: None,
            observation_kind: None,
            evidence_ids: vec!["ev-z".into(), "ev-a".into()],
        },
    ];
    let edges = vec![GraphEdge {
        from: "system-1".into(),
        to: "use-1".into(),
        relation: GraphRelation::ExposesUse,
        evidence_ids: vec!["ev-z".into()],
    }];
    (nodes, edges)
}

#[test]
fn graph_is_deterministic_and_bound_to_verified_inventory() -> Result<(), Diagnostic> {
    let inventory = source()?;
    let (nodes, edges) = simple();
    let graph = EvidenceGraph::new(&inventory, nodes.clone(), edges.clone(), &Limits::default())?;
    assert_eq!(graph.nodes()[0].id, "system-1");
    assert_eq!(graph.nodes()[1].id, "use-1");
    assert_eq!(graph.nodes()[0].evidence_ids, ["ev-a", "ev-z"]);
    assert_eq!(graph.edges()[0].relation, GraphRelation::ExposesUse);
    assert_eq!(
        graph.source_digest(),
        inventory.export(&Limits::default())?.digest
    );
    let (mut reordering, edges) = simple();
    reordering.reverse();
    reordering[1].evidence_ids.reverse();
    let again = EvidenceGraph::new(&inventory, reordering, edges, &Limits::default())?;
    assert_eq!(graph.nodes(), again.nodes());
    assert_eq!(graph.edges(), again.edges());
    Ok(())
}

#[test]
fn invalid_topology_and_missing_evidence_fail_closed() -> Result<(), Diagnostic> {
    let inventory = source()?;
    let (nodes, mut edges) = simple();
    edges[0].from = "use-1".into();
    edges[0].to = "system-1".into();
    let result = EvidenceGraph::new(&inventory, nodes, edges, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::InvalidStateTransition)
    );

    let (nodes, mut edges) = simple();
    edges[0].to = "nonexistent".into();
    let result = EvidenceGraph::new(&inventory, nodes, edges, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::InvalidReference)
    );

    let (mut nodes, edges) = simple();
    nodes[0].evidence_ids = vec!["unknown".into()];
    let result = EvidenceGraph::new(&inventory, nodes, edges, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::InvalidReference)
    );
    Ok(())
}

#[test]
fn observation_binding_and_source_specificity_are_mandatory() -> Result<(), Diagnostic> {
    let inventory = source()?;
    let (mut nodes, edges) = simple();
    nodes[0].observation_id = None;
    let result = EvidenceGraph::new(&inventory, nodes, edges, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::InvalidReference)
    );

    let (mut nodes, edges) = simple();
    nodes[0].evidence_ids = vec!["ev-a".into()];
    let result = EvidenceGraph::new(&inventory, nodes, edges, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::InvalidReference)
    );

    let (mut nodes, edges) = simple();
    nodes[1].observation_id = Some("obs-1".into());
    let result = EvidenceGraph::new(&inventory, nodes, edges, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::InvalidReference)
    );
    Ok(())
}

#[test]
fn duplicate_nodes_edges_and_evidence_references_are_rejected() -> Result<(), Diagnostic> {
    let inventory = source()?;
    let (mut nodes, edges) = simple();
    nodes.push(nodes[0].clone());
    let result = EvidenceGraph::new(&inventory, nodes, edges, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::DuplicateRecord)
    );

    let (nodes, mut edges) = simple();
    edges.push(edges[0].clone());
    let result = EvidenceGraph::new(&inventory, nodes, edges, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::DuplicateRecord)
    );

    let (mut nodes, edges) = simple();
    nodes[1].evidence_ids.push("ev-z".into());
    let result = EvidenceGraph::new(&inventory, nodes, edges, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::DuplicateRecord)
    );
    Ok(())
}

#[test]
fn limits_prevent_excess_graph_work() -> Result<(), Diagnostic> {
    let inventory = source()?;
    let (nodes, edges) = simple();
    let limits = Limits {
        max_graph_nodes: 1,
        ..Limits::default()
    };
    let result = EvidenceGraph::new(&inventory, nodes, edges, &limits);
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );

    let (nodes, edges) = simple();
    let limits = Limits {
        max_graph_edges: 2,
        ..Limits::default()
    };
    let result = EvidenceGraph::new(&inventory, nodes, edges, &limits);
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    Ok(())
}

#[test]
fn cycles_are_preserved_for_later_scc_analysis() -> Result<(), Diagnostic> {
    let inventory = source()?;
    let nodes = vec![
        GraphNode {
            id: "system-a".into(),
            kind: GraphNodeKind::System,
            evidence_ids: vec!["ev-z".into()],
            observation_id: None,
            observation_kind: None,
        },
        GraphNode {
            id: "system-b".into(),
            kind: GraphNodeKind::System,
            evidence_ids: vec!["ev-a".into()],
            observation_id: None,
            observation_kind: None,
        },
    ];
    let edges = vec![
        GraphEdge {
            from: "system-b".into(),
            to: "system-a".into(),
            relation: GraphRelation::DependsOn,
            evidence_ids: vec!["ev-a".into()],
        },
        GraphEdge {
            from: "system-a".into(),
            to: "system-b".into(),
            relation: GraphRelation::DependsOn,
            evidence_ids: vec!["ev-z".into()],
        },
    ];
    let graph = EvidenceGraph::new(&inventory, nodes, edges, &Limits::default())?;
    assert_eq!(graph.edges().len(), 2);
    assert_eq!(graph.edges()[0].from, "system-a");
    assert_eq!(graph.edges()[1].from, "system-b");
    Ok(())
}

#[test]
fn library_capability_does_not_imply_active_cryptographic_use() -> Result<(), Diagnostic> {
    let inventory = source()?;
    let nodes = vec![
        GraphNode {
            id: "system".into(),
            kind: GraphNodeKind::System,
            evidence_ids: vec!["ev-z".into()],
            observation_id: None,
            observation_kind: None,
        },
        GraphNode {
            id: "library".into(),
            kind: GraphNodeKind::Library,
            evidence_ids: vec!["ev-z".into()],
            observation_id: None,
            observation_kind: None,
        },
    ];
    let edges = vec![GraphEdge {
        from: "system".into(),
        to: "library".into(),
        relation: GraphRelation::LoadsLibrary,
        evidence_ids: vec!["ev-z".into()],
    }];
    let graph = EvidenceGraph::new(&inventory, nodes, edges, &Limits::default())?;
    assert_eq!(graph.nodes().len(), 2);
    assert_eq!(graph.edges()[0].relation, GraphRelation::LoadsLibrary);
    assert!(
        graph
            .nodes()
            .iter()
            .all(|node| node.kind != GraphNodeKind::CryptoUse)
    );
    Ok(())
}

#[test]
fn spoofed_observed_use_classification_fails_closed() -> Result<(), Diagnostic> {
    let inventory = source()?;
    let (mut nodes, edges) = simple();
    nodes[0].observation_kind = Some(CryptoUseKind::ActiveUse);
    let result = EvidenceGraph::new(&inventory, nodes, edges, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    let (mut nodes, edges) = simple();
    nodes[1].observation_kind = Some(CryptoUseKind::LibraryCapability);
    let result = EvidenceGraph::new(&inventory, nodes, edges, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::InvalidReference)
    );
    Ok(())
}

#[test]
fn dense_evidence_references_stay_exact_and_source_scoped() -> Result<(), Diagnostic> {
    let mut model = source()?.snapshot().clone();
    for index in 0..2048 {
        let id = format!("dense-{index:04}");
        model.evidence.push(EvidenceRecord {
            id: id.clone(),
            run_id: "run-a".into(),
            source_id: "collector-a".into(),
            basis: EvidenceBasis::Direct,
            confidence_bps: 9000,
            observed_at_unix_secs: 10,
        });
        model.observations[0].evidence_ids.push(id);
    }
    let verified = ValidatedInventorySnapshot::new(model, &Limits::default())?;
    let (mut nodes, edges) = simple();
    nodes[0].evidence_ids = verified.snapshot().observations[0].evidence_ids.clone();
    let graph = EvidenceGraph::new(&verified, nodes.clone(), edges.clone(), &Limits::default())?;
    assert_eq!(graph.nodes()[1].evidence_ids.len(), 2049);
    nodes[0].evidence_ids.push("ev-a".into());
    let result = EvidenceGraph::new(&verified, nodes, edges, &Limits::default());
    assert_eq!(
        result.err().map(|error| error.code),
        Some(DiagnosticCode::InvalidReference)
    );
    Ok(())
}

#[test]
fn all_directional_relationship_families_have_valid_endpoints() -> Result<(), Diagnostic> {
    let inventory = source()?;
    let entries = [
        ("system", GraphNodeKind::System),
        ("use", GraphNodeKind::CryptoUse),
        ("library", GraphNodeKind::Library),
        ("certificate", GraphNodeKind::Certificate),
        ("anchor", GraphNodeKind::TrustAnchor),
        ("key", GraphNodeKind::Key),
        ("hsm", GraphNodeKind::Hsm),
        ("data", GraphNodeKind::Data),
        ("owner", GraphNodeKind::Owner),
        ("vendor", GraphNodeKind::Vendor),
    ];
    let nodes: Vec<GraphNode> = entries
        .into_iter()
        .map(|(id, kind)| GraphNode {
            id: id.into(),
            kind,
            evidence_ids: vec!["ev-z".into()],
            observation_id: (kind == GraphNodeKind::CryptoUse).then(|| "obs-1".into()),
            observation_kind: (kind == GraphNodeKind::CryptoUse)
                .then_some(CryptoUseKind::ConfiguredProtocol),
        })
        .collect();
    let relations = [
        ("system", "use", GraphRelation::ExposesUse),
        ("system", "library", GraphRelation::LoadsLibrary),
        ("library", "use", GraphRelation::ImplementsUse),
        ("system", "certificate", GraphRelation::UsesCertificate),
        ("certificate", "anchor", GraphRelation::IssuedBy),
        ("hsm", "key", GraphRelation::HoldsKey),
        ("key", "data", GraphRelation::ProtectsData),
        ("data", "owner", GraphRelation::OwnedBy),
        ("library", "vendor", GraphRelation::SuppliedBy),
        ("system", "system", GraphRelation::DependsOn),
    ];
    let edges: Vec<GraphEdge> = relations
        .into_iter()
        .map(|(from, to, relation)| GraphEdge {
            from: from.into(),
            to: to.into(),
            relation,
            evidence_ids: vec!["ev-z".into()],
        })
        .collect();
    let graph = EvidenceGraph::new(&inventory, nodes, edges, &Limits::default())?;
    assert_eq!(graph.nodes().len(), 10);
    assert_eq!(graph.edges().len(), 10);
    Ok(())
}
