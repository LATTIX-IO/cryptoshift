#![allow(clippy::unwrap_used, clippy::expect_used)] // Synthetic acceptance fixtures.
use cryptoshift::*;

const NOW: i64 = 1_800_000_000;

struct Fixture {
    inventory: ValidatedInventorySnapshot,
    graph: EvidenceGraph,
    topology: DependencyTopology,
    risk: RiskReport,
    target: TargetProfile,
}

fn fixture(with_owner_a: bool, cyclic: bool) -> Fixture {
    let limits = Limits::default();
    let inventory = ValidatedInventorySnapshot::new(
        InventorySnapshot {
            identity_version: IDENTITY_VERSION,
            normalization_version: NORMALIZATION_VERSION,
            scope_id: "tenant-a".into(),
            runs: vec![CollectionRun {
                id: "run-1".into(),
                source_id: "collector".into(),
                scope_id: "tenant-a".into(),
                collected_at_unix_secs: NOW - 100,
                completeness: CollectionCompleteness::Complete,
            }],
            evidence: vec![EvidenceRecord {
                id: "ev-1".into(),
                run_id: "run-1".into(),
                source_id: "collector".into(),
                basis: EvidenceBasis::Direct,
                confidence_bps: 9500,
                observed_at_unix_secs: NOW - 100,
            }],
            observations: vec![],
            absences: vec![],
        },
        &limits,
    )
    .unwrap();

    let mut edges = vec![
        GraphEdge {
            from: "a".into(),
            to: "b".into(),
            relation: GraphRelation::DependsOn,
            evidence_ids: vec!["ev-1".into()],
        },
        GraphEdge {
            from: "b".into(),
            to: "owner".into(),
            relation: GraphRelation::OwnedBy,
            evidence_ids: vec!["ev-1".into()],
        },
    ];
    if cyclic {
        edges.push(GraphEdge {
            from: "b".into(),
            to: "a".into(),
            relation: GraphRelation::DependsOn,
            evidence_ids: vec!["ev-1".into()],
        });
    }
    if with_owner_a {
        edges.push(GraphEdge {
            from: "a".into(),
            to: "owner".into(),
            relation: GraphRelation::OwnedBy,
            evidence_ids: vec!["ev-1".into()],
        });
    }
    let graph = EvidenceGraph::new(
        &inventory,
        vec![
            GraphNode {
                id: "a".into(),
                kind: GraphNodeKind::System,
                evidence_ids: vec!["ev-1".into()],
                observation_id: None,
                observation_kind: None,
            },
            GraphNode {
                id: "b".into(),
                kind: GraphNodeKind::System,
                evidence_ids: vec!["ev-1".into()],
                observation_id: None,
                observation_kind: None,
            },
            GraphNode {
                id: "owner".into(),
                kind: GraphNodeKind::Owner,
                evidence_ids: vec!["ev-1".into()],
                observation_id: None,
                observation_kind: None,
            },
        ],
        edges,
        &limits,
    )
    .unwrap();

    let topology = DependencyAnalysis::analyze(&graph, &limits).unwrap();
    let risk =
        RiskAnalysis::analyze(&inventory, &graph, &topology, &[], &[], None, &limits).unwrap();
    let target = TargetProfile::new(
        TargetProfileDraft {
            schema_version: TARGET_PROFILE_VERSION,
            profile_id: "target".into(),
            revision: 1,
            scope_id: "tenant-a".into(),
            provenance: ProfileProvenance {
                issuer_id: "owner".into(),
                document_id: "policy".into(),
                revision: "r1".into(),
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
                protocol_id: "protocol".into(),
                revision: "r1".into(),
                role: AlgorithmRole::KeyEncapsulation,
                algorithm: KnownAlgorithm::MlKem1024,
                hybrid: None,
            }],
            certificates: vec![],
            cnsa20: None,
            deadline: None,
            expires_at_unix_secs: Some(NOW + 1000),
        },
        &limits,
        Some(NOW),
    )
    .unwrap();
    Fixture {
        inventory,
        graph,
        topology,
        risk,
        target,
    }
}

fn bindings(f: &Fixture) -> RemediationBindings {
    RemediationAnalyzer::input_bindings(
        &f.inventory,
        &f.graph,
        &f.topology,
        &f.risk,
        &f.target,
        NOW,
        &Limits::default(),
    )
    .unwrap()
}

fn run<'a>(
    f: &Fixture,
    reports: &[&'a CompatibilityAnalysis],
) -> Result<RemediationAnalysis, Diagnostic> {
    RemediationAnalyzer::analyze(
        &f.inventory,
        &f.graph,
        &f.topology,
        &f.risk,
        &f.target,
        reports,
        bindings(f),
        &Limits::default(),
    )
}

fn claim(provider: &str, runtime: &str) -> CapabilityCatalog {
    CapabilityCatalog::new(
        CapabilityCatalogDraft {
            schema_version: CAPABILITY_CATALOG_VERSION,
            catalog_id: format!("catalog-{provider}"),
            revision: 1,
            scope_id: "tenant-a".into(),
            provenance: ProfileProvenance {
                issuer_id: "vendor".into(),
                document_id: "catalog".into(),
                revision: "v1".into(),
                source_digest: None,
            },
            records: vec![CapabilityRecord {
                record_id: format!("record-{provider}"),
                provider_id: provider.into(),
                product_id: "server".into(),
                product_version: "v1".into(),
                platform_id: "linux".into(),
                scope_id: "tenant-a".into(),
                runtime_id: Some(runtime.into()),
                algorithm: KnownAlgorithm::MlKem1024,
                role: AlgorithmRole::KeyEncapsulation,
                state: CapabilityState::Available,
                evidence: CapabilityEvidence {
                    source_id: "vendor".into(),
                    evidence_id: format!("doc-{provider}"),
                    source_revision: "v1".into(),
                    basis: CapabilityEvidenceBasis::VendorDocumentation,
                    verification: EvidenceVerification::Unverified,
                    verification_reference: None,
                    artifact_digest: None,
                    observed_at_unix_secs: NOW - 100,
                    expires_at_unix_secs: Some(NOW + 900),
                },
            }],
        },
        &Limits::default(),
        Some(NOW),
    )
    .unwrap()
}

fn peer_analysis(f: &Fixture, fallback: bool) -> CompatibilityAnalysis {
    let left = claim("vendor-a", "runtime-a");
    let right = claim("vendor-b", "runtime-b");
    let request = CompatibilityRequest {
        schema_version: COMPATIBILITY_ANALYSIS_VERSION,
        scope_id: "tenant-a".into(),
        expected_graph_digest: f.graph.fingerprint(),
        expected_target_digest: f.target.digest(),
        expected_initiator_catalog_digest: left.digest(),
        expected_responder_catalog_digest: right.digest(),
        initiator: EndpointIdentity {
            system_node_id: "a".into(),
            provider_id: "vendor-a".into(),
            product_id: "server".into(),
            product_version: "v1".into(),
            platform_id: "linux".into(),
            runtime_id: "runtime-a".into(),
        },
        responder: EndpointIdentity {
            system_node_id: "b".into(),
            provider_id: "vendor-b".into(),
            product_id: "server".into(),
            product_version: "v1".into(),
            platform_id: "linux".into(),
            runtime_id: "runtime-b".into(),
        },
        protocol_id: "protocol".into(),
        protocol_revision: "r1".into(),
        extension_revision: "extension-1".into(),
        algorithm: KnownAlgorithm::MlKem1024,
        role: AlgorithmRole::KeyEncapsulation,
        certificate: None,
        hybrid: None,
        classical_fallback: fallback,
        observations: vec![],
    };
    CompatibilityAnalyzer::analyze(
        &request,
        &f.graph,
        &f.target,
        &left,
        &right,
        NOW,
        &Limits::default(),
    )
    .unwrap()
}

fn has(report: &RemediationAnalysis, unit: &str, code: BlockerCode) -> bool {
    report
        .blockers()
        .iter()
        .any(|b| b.unit_id == unit && b.code == code)
}

#[test]
fn missing_owner_and_dependency_are_never_silently_cleared() {
    let f = fixture(false, false);
    let report = run(&f, &[]).unwrap();
    assert!(has(&report, "a", BlockerCode::OwnerMissing));
    assert!(has(&report, "a", BlockerCode::DependencyGate));
    assert!(has(&report, "a", BlockerCode::PeerCompatibilityMissing));
    assert!(!has(&report, "b", BlockerCode::OwnerMissing));
    let gate_a = report
        .actions()
        .iter()
        .find(|x| x.unit_id == "a" && x.kind == RemediationActionKind::ReviewUnitGate)
        .unwrap();
    let gate_b = report
        .actions()
        .iter()
        .find(|x| x.unit_id == "b" && x.kind == RemediationActionKind::ReviewUnitGate)
        .unwrap();
    assert!(gate_a.prerequisite_action_ids.contains(&gate_b.id));
    assert!(!gate_b.prerequisite_action_ids.contains(&gate_a.id));
    assert!(gate_a.change_approval_required);
    assert_eq!(gate_a.rollback, RollbackRequirement::ReviewedPlanRequired);
    assert_eq!(
        report.bindings().inventory_digest,
        f.inventory.export(&Limits::default()).unwrap().digest
    );
}

#[test]
fn every_remediation_action_is_proposal_not_execution() {
    let f = fixture(true, false);
    let report = run(&f, &[]).unwrap();
    assert!(!report.actions().is_empty());
    for action in report.actions() {
        assert!(!action.id.is_empty());
        assert!(action.due_at_unix_secs.is_none());
        if action.kind != RemediationActionKind::ReviewUnitGate {
            assert_eq!(action.rollback, RollbackRequirement::EvidenceOnly);
        }
    }
    for blocker in report.blockers() {
        assert!(!blocker.required_gates.is_empty());
        assert!(!blocker.id.is_empty());
    }
}

#[test]
fn claimed_vendor_availability_never_authenticates_peer_negotiation() {
    let f = fixture(true, false);
    let compat = peer_analysis(&f, false);
    assert_ne!(compat.status(), CompatibilityStatus::Compatible);
    let report = run(&f, &[&compat]).unwrap();
    assert!(has(&report, "a", BlockerCode::PeerProofUnverified));
    assert!(has(&report, "b", BlockerCode::PeerProofUnverified));
    assert!(has(
        &report,
        "a",
        BlockerCode::Compatibility(CompatibilityCode::NegotiationMissing)
    ));
    assert!(report.actions().iter().any(|a| {
        a.kind == RemediationActionKind::VerifyPeer
            && a.validation_gates
                .contains(&RemediationGate::AuthenticatePeer)
    }));
}

#[test]
fn forbidden_classical_downgrade_is_hard_policy_blocker() {
    let f = fixture(true, false);
    let compat = peer_analysis(&f, true);
    let report = run(&f, &[&compat]).unwrap();
    let blocker = report
        .blockers()
        .iter()
        .find(|b| b.code == BlockerCode::Compatibility(CompatibilityCode::DowngradeRejected))
        .unwrap();
    assert_eq!(blocker.severity, BlockerSeverity::HardPolicy);
    assert_eq!(blocker.evidence_state, BlockerEvidenceState::Prohibited);
    let action = report
        .actions()
        .iter()
        .find(|a| a.resolves_blocker_ids.contains(&blocker.id))
        .unwrap();
    assert_eq!(action.kind, RemediationActionKind::ReviewPolicy);
    assert!(action.change_approval_required);
    assert!(
        action
            .validation_gates
            .contains(&RemediationGate::ApprovePolicyAlternative)
    );
}

#[test]
fn source_bound_hard_block_never_becomes_ready_when_other_evidence_is_missing() {
    let f = fixture(false, false);
    let compat = peer_analysis(&f, true);
    let result = run(&f, &[&compat]).unwrap();
    assert!(has(&result, "a", BlockerCode::OwnerMissing));
    assert!(has(
        &result,
        "a",
        BlockerCode::Compatibility(CompatibilityCode::DowngradeRejected)
    ));
    assert!(
        !result
            .actions()
            .iter()
            .any(|a| a.kind == RemediationActionKind::ReviewUnitGate
                && a.prerequisite_action_ids.is_empty())
    );
}

#[test]
fn scc_is_one_indivisible_review_unit_without_prerequisite_cycle() {
    let f = fixture(true, true);
    assert_eq!(f.topology.units().len(), 1);
    assert!(f.topology.units()[0].cyclic);
    let result = run(&f, &[]).unwrap();
    let gates: Vec<_> = result
        .actions()
        .iter()
        .filter(|a| a.kind == RemediationActionKind::ReviewUnitGate)
        .collect();
    assert_eq!(gates.len(), 1);
    assert!(result.actions().iter().all(|a| a.unit_id == "a"));
    assert!(!has(&result, "a", BlockerCode::DependencyGate));
}

#[test]
fn mutated_graph_topology_and_risk_digest_are_rejected() {
    let f = fixture(true, false);
    let mut pinned = bindings(&f);
    pinned.graph_digest = SnapshotDigest::from_bytes([0; 32]);
    assert_eq!(
        RemediationAnalyzer::analyze(
            &f.inventory,
            &f.graph,
            &f.topology,
            &f.risk,
            &f.target,
            &[],
            pinned,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::IntegrityMismatch
    );
    pinned = bindings(&f);
    pinned.risk_digest = SnapshotDigest::from_bytes([0; 32]);
    assert_eq!(
        RemediationAnalyzer::analyze(
            &f.inventory,
            &f.graph,
            &f.topology,
            &f.risk,
            &f.target,
            &[],
            pinned,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::IntegrityMismatch
    );
    pinned = bindings(&f);
    pinned.topology_digest = SnapshotDigest::from_bytes([0; 32]);
    assert_eq!(
        RemediationAnalyzer::analyze(
            &f.inventory,
            &f.graph,
            &f.topology,
            &f.risk,
            &f.target,
            &[],
            pinned,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::IntegrityMismatch
    );
}

#[test]
fn foreign_compatibility_report_and_duplicate_artifact_fail_closed() {
    let f = fixture(true, false);
    let compat = peer_analysis(&f, false);
    assert_eq!(
        run(&f, &[&compat, &compat]).unwrap_err().code,
        DiagnosticCode::DuplicateRecord
    );
    let mut pinned = bindings(&f);
    pinned.evaluated_at_unix_secs = NOW + 1;
    assert_eq!(
        RemediationAnalyzer::analyze(
            &f.inventory,
            &f.graph,
            &f.topology,
            &f.risk,
            &f.target,
            &[&compat],
            pinned,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::IntegrityMismatch
    );
}

#[test]
fn reordered_compatible_input_reports_are_canonical() {
    let f = fixture(true, false);
    let baseline = run(&f, &[]).unwrap();
    let repeat = run(&f, &[]).unwrap();
    assert_eq!(baseline.digest(), repeat.digest());
    assert_eq!(
        baseline.export(&Limits::default()).unwrap(),
        repeat.export(&Limits::default()).unwrap()
    );
    let mut changed_risk = f.risk.clone();
    changed_risk.units.reverse();
    let changed_bindings = RemediationAnalyzer::input_bindings(
        &f.inventory,
        &f.graph,
        &f.topology,
        &changed_risk,
        &f.target,
        NOW,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(changed_bindings.risk_digest, bindings(&f).risk_digest);
    let changed = RemediationAnalyzer::analyze(
        &f.inventory,
        &f.graph,
        &f.topology,
        &changed_risk,
        &f.target,
        &[],
        changed_bindings,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(baseline.digest(), changed.digest());
}

#[test]
fn changing_risk_evidence_rotates_digest_without_guessing_zero_risk() {
    let f = fixture(true, false);
    let baseline = run(&f, &[]).unwrap();
    let mut changed = f.risk.clone();
    changed.units[0].factors[1]
        .assessment_references
        .push("assessment-v2".into());
    let binding = RemediationAnalyzer::input_bindings(
        &f.inventory,
        &f.graph,
        &f.topology,
        &changed,
        &f.target,
        NOW,
        &Limits::default(),
    )
    .unwrap();
    assert_ne!(binding.risk_digest, baseline.bindings().risk_digest);
    let report = RemediationAnalyzer::analyze(
        &f.inventory,
        &f.graph,
        &f.topology,
        &changed,
        &f.target,
        &[],
        binding,
        &Limits::default(),
    )
    .unwrap();
    assert_ne!(report.digest(), baseline.digest());
    assert!(report.blockers().iter().any(|block|block.evidence.iter().any(|e|
        matches!(e,RemediationEvidence::RiskAssessment{reference_id} if reference_id=="assessment-v2"))));
}

#[test]
fn rejected_risk_score_forgery_and_invalid_risk_dimensions() {
    let f = fixture(true, false);
    let mut bad = f.risk.clone();
    bad.units[0].factors.swap(0, 1);
    let binding = RemediationAnalyzer::input_bindings(
        &f.inventory,
        &f.graph,
        &f.topology,
        &bad,
        &f.target,
        NOW,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        RemediationAnalyzer::analyze(
            &f.inventory,
            &f.graph,
            &f.topology,
            &bad,
            &f.target,
            &[],
            binding,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::InvalidStateTransition
    );
    let mut bad = f.risk.clone();
    bad.units[0].score = Some(RiskScore {
        pressure_bps: 0,
        profile_id: "invented".into(),
        profile_version: 1,
    });
    let binding = RemediationAnalyzer::input_bindings(
        &f.inventory,
        &f.graph,
        &f.topology,
        &bad,
        &f.target,
        NOW,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        RemediationAnalyzer::analyze(
            &f.inventory,
            &f.graph,
            &f.topology,
            &bad,
            &f.target,
            &[],
            binding,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::InvalidStateTransition
    );
}

#[test]
fn source_qualified_evidence_survives_compatibility_mapping() {
    let f = fixture(true, false);
    let compat = peer_analysis(&f, false);
    let report = run(&f, &[&compat]).unwrap();
    assert!(
        report
            .actions()
            .iter()
            .any(|action| action.evidence.iter().any(
                |ref_| matches!(ref_,RemediationEvidence::Compatibility{source_id,evidence_id,..}
            if source_id=="vendor" && evidence_id=="doc-vendor-a")
            ))
    );
}

#[test]
fn expired_target_is_rejected_at_explicit_analysis_time() {
    let f = fixture(true, false);
    let mut pinned = bindings(&f);
    pinned.evaluated_at_unix_secs = NOW + 1000;
    assert_eq!(
        RemediationAnalyzer::analyze(
            &f.inventory,
            &f.graph,
            &f.topology,
            &f.risk,
            &f.target,
            &[],
            pinned,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::StaleCriticalProfile
    );
}

#[test]
fn explicit_source_deadline_does_not_invent_other_unit_dates() {
    let mut f = fixture(true, false);
    let mut draft = f.target.content().clone();
    draft.deadline = Some(ExplicitDeadline {
        applies_to: "a".into(),
        due_at_unix_secs: NOW,
        source_reference: "deadline-doc-1".into(),
    });
    f.target = TargetProfile::new(draft, &Limits::default(), Some(NOW)).unwrap();
    let result = run(&f, &[]).unwrap();
    assert!(has(&result, "a", BlockerCode::DeadlinePassed));
    assert!(!has(&result, "b", BlockerCode::DeadlinePassed));
    assert!(
        result
            .actions()
            .iter()
            .filter(|a| a.unit_id == "a")
            .all(|a| a.due_at_unix_secs == Some(NOW))
    );
    assert!(
        result
            .actions()
            .iter()
            .filter(|a| a.unit_id == "b")
            .all(|a| a.due_at_unix_secs.is_none())
    );
}

#[test]
fn output_is_bounded_without_partial_success() {
    let f = fixture(true, false);
    let report = run(&f, &[]).unwrap();
    let bytes = report.export(&Limits::default()).unwrap();
    let mut limits = Limits::default();
    limits.max_plan_actions = 1;
    assert_eq!(
        RemediationAnalyzer::analyze(
            &f.inventory,
            &f.graph,
            &f.topology,
            &f.risk,
            &f.target,
            &[],
            bindings(&f),
            &limits
        )
        .unwrap_err()
        .code,
        DiagnosticCode::ResourceLimitExceeded
    );
    let mut limits = Limits::default();
    limits.max_diagnostics = 1;
    assert_eq!(
        RemediationAnalyzer::analyze(
            &f.inventory,
            &f.graph,
            &f.topology,
            &f.risk,
            &f.target,
            &[],
            bindings(&f),
            &limits
        )
        .unwrap_err()
        .code,
        DiagnosticCode::ResourceLimitExceeded
    );
    assert!(bytes.len() > f.inventory.export(&Limits::default()).unwrap().bytes.len());
    let mut limits = Limits::default();
    limits.max_export_bytes = bytes.len() - 1;
    assert_eq!(
        RemediationAnalyzer::analyze(
            &f.inventory,
            &f.graph,
            &f.topology,
            &f.risk,
            &f.target,
            &[],
            bindings(&f),
            &limits
        )
        .unwrap_err()
        .code,
        DiagnosticCode::ResourceLimitExceeded
    );
}

#[test]
fn frozen_v1_remediation_report_digest_and_length() {
    let f = fixture(true, false);
    let result = run(&f, &[]).unwrap();
    let bytes = result.export(&Limits::default()).unwrap();
    assert!(bytes.starts_with(b"CSHIFT_REMEDIATION_REPORT_V1"));
    assert_eq!(
        format!("{} {}", result.digest().as_identifier(), bytes.len()),
        include_str!("fixtures/remediation_v1.sha256").trim(),
    );
}
