//! FOSS-442 contract, security and regression tests for offline wave planning.
#![allow(clippy::unwrap_used, clippy::expect_used)] // Bounded synthetic fixtures.
use cryptoshift::*;

const NOW: i64 = 1_800_000_000;

struct Fixture {
    inventory: ValidatedInventorySnapshot,
    graph: EvidenceGraph,
    topology: DependencyTopology,
    risk: RiskReport,
    target: TargetProfile,
    remediation: RemediationAnalysis,
}

fn fixture(
    systems: &[&str],
    dependencies: &[(&str, &str)],
    assigned_owner: bool,
    deadline: Option<(&str, i64)>,
) -> Fixture {
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
    let mut nodes: Vec<_> = systems
        .iter()
        .map(|id| GraphNode {
            id: (*id).into(),
            kind: GraphNodeKind::System,
            evidence_ids: vec!["ev-1".into()],
            observation_id: None,
            observation_kind: None,
        })
        .collect();
    let mut edges: Vec<_> = dependencies
        .iter()
        .map(|(a, b)| GraphEdge {
            from: (*a).into(),
            to: (*b).into(),
            relation: GraphRelation::DependsOn,
            evidence_ids: vec!["ev-1".into()],
        })
        .collect();
    if assigned_owner {
        nodes.push(GraphNode {
            id: "owner".into(),
            kind: GraphNodeKind::Owner,
            evidence_ids: vec!["ev-1".into()],
            observation_id: None,
            observation_kind: None,
        });
        for id in systems {
            edges.push(GraphEdge {
                from: (*id).into(),
                to: "owner".into(),
                relation: GraphRelation::OwnedBy,
                evidence_ids: vec!["ev-1".into()],
            });
        }
    }
    let graph = EvidenceGraph::new(&inventory, nodes, edges, &limits).unwrap();
    let topology = DependencyAnalysis::analyze(&graph, &limits).unwrap();
    let risk =
        RiskAnalysis::analyze(&inventory, &graph, &topology, &[], &[], None, &limits).unwrap();
    let target = TargetProfile::new(
        TargetProfileDraft {
            schema_version: TARGET_PROFILE_VERSION,
            profile_id: "approved-pq".into(),
            revision: 1,
            scope_id: "tenant-a".into(),
            provenance: ProfileProvenance {
                issuer_id: "policy-office".into(),
                document_id: "profile-v1".into(),
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
                protocol_id: "transport".into(),
                revision: "v1".into(),
                role: AlgorithmRole::KeyEncapsulation,
                algorithm: KnownAlgorithm::MlKem1024,
                hybrid: None,
            }],
            certificates: vec![],
            cnsa20: None,
            deadline: deadline.map(|(unit, secs)| ExplicitDeadline {
                applies_to: unit.into(),
                due_at_unix_secs: secs,
                source_reference: "deadline-notice".into(),
            }),
            expires_at_unix_secs: Some(NOW + 1000),
        },
        &limits,
        Some(NOW),
    )
    .unwrap();
    let pinned = RemediationAnalyzer::input_bindings(
        &inventory, &graph, &topology, &risk, &target, NOW, &limits,
    )
    .unwrap();
    let remediation = RemediationAnalyzer::analyze(
        &inventory,
        &graph,
        &topology,
        &risk,
        &target,
        &[],
        pinned,
        &limits,
    )
    .unwrap();
    Fixture {
        inventory,
        graph,
        topology,
        risk,
        target,
        remediation,
    }
}

fn with_complete_source_claims(f: &mut Fixture) {
    // Synthetic scenario claims are NOT verified security observations.
    // They only exercise the nonauthorizing "eligible for review" branch.
    for unit in &mut f.risk.units {
        for factor in &mut unit.factors {
            factor.level = Some(RiskLevel::Low);
            factor.uncertainty = None;
            factor.assessment_references.push("scenario-1".into());
        }
        unit.findings.clear();
        unit.score = None;
    }
    let limits = Limits::default();
    let pinned = RemediationAnalyzer::input_bindings(
        &f.inventory,
        &f.graph,
        &f.topology,
        &f.risk,
        &f.target,
        NOW,
        &limits,
    )
    .unwrap();
    f.remediation = RemediationAnalyzer::analyze(
        &f.inventory,
        &f.graph,
        &f.topology,
        &f.risk,
        &f.target,
        &[],
        pinned,
        &limits,
    )
    .unwrap();
}

fn request(f: &Fixture, capacity: usize, max_waves: usize, review: &[&str]) -> WavePlanRequest {
    WavePlanRequest {
        schema_version: WAVE_PLAN_VERSION,
        capacity_systems_per_wave: capacity,
        max_waves,
        expected_bindings: WavePlanner::input_bindings(
            &f.topology,
            &f.remediation,
            &f.target,
            &Limits::default(),
        )
        .unwrap(),
        submitted_for_review_units: review.iter().map(|v| (*v).to_owned()).collect(),
    }
}

fn plan(f: &Fixture, capacity: usize, max_waves: usize, review: &[&str]) -> WavePlanDraft {
    let q = request(f, capacity, max_waves, review);
    WavePlanner::plan(
        &f.topology,
        &f.remediation,
        &f.target,
        &q,
        &Limits::default(),
    )
    .unwrap()
}

fn unit<'a>(p: &'a WavePlanDraft, id: &str) -> &'a UnitReadiness {
    p.readiness().iter().find(|v| v.unit_id == id).unwrap()
}

#[test]
fn three_unit_chain_preserves_dependency_first_wave_order() {
    let f = fixture(&["c", "b", "a"], &[("c", "b"), ("b", "a")], true, None);
    let p = plan(&f, 3, 3, &[]);
    assert_eq!(p.waves().len(), 3);
    assert_eq!(p.waves()[0].unit_ids, vec!["a"]);
    assert_eq!(p.waves()[1].unit_ids, vec!["b"]);
    assert_eq!(p.waves()[2].unit_ids, vec!["c"]);
    assert_eq!(unit(&p, "c").prerequisite_unit_ids, vec!["b"]);
    assert_eq!(unit(&p, "c").status, UnitReadinessStatus::Unverified);
    assert!(
        unit(&p, "b")
            .gates
            .iter()
            .any(|g| g.kind == ReadinessGateKind::UpstreamUnitApproval
                && g.upstream_unit_id.as_deref() == Some("a"))
    );
}

#[test]
fn branching_dag_packs_only_units_whose_prerequisites_precede_wave() {
    let f = fixture(
        &["root", "leaf-b", "leaf-a"],
        &[("leaf-a", "root"), ("leaf-b", "root")],
        true,
        None,
    );
    let p = plan(&f, 2, 2, &[]);
    assert_eq!(p.waves().len(), 2);
    assert_eq!(p.waves()[0].unit_ids, vec!["root"]);
    assert_eq!(p.waves()[1].unit_ids, vec!["leaf-a", "leaf-b"]);
    assert_eq!(p.waves()[1].occupied_system_slots, 2);
}

#[test]
fn disconnected_units_use_lexicographic_deterministic_first_fit() {
    let f = fixture(&["c", "a", "b"], &[], true, None);
    let p = plan(&f, 2, 2, &[]);
    assert_eq!(p.waves()[0].unit_ids, vec!["a", "b"]);
    assert_eq!(p.waves()[1].unit_ids, vec!["c"]);
}

#[test]
fn cyclic_scc_is_indivisible_and_capacity_counts_system_slots() {
    let f = fixture(
        &["a", "b", "c"],
        &[("a", "b"), ("b", "a"), ("c", "b")],
        true,
        None,
    );
    assert_eq!(f.topology.units().len(), 2);
    let p = plan(&f, 2, 2, &[]);
    assert_eq!(p.waves()[0].unit_ids, vec!["a"]);
    assert_eq!(p.waves()[0].occupied_system_slots, 2);
    assert_eq!(unit(&p, "a").system_ids, vec!["a", "b"]);
    assert_eq!(p.waves()[1].unit_ids, vec!["c"]);
    let q = request(&f, 1, 3, &[]);
    assert_eq!(
        WavePlanner::plan(
            &f.topology,
            &f.remediation,
            &f.target,
            &q,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::ResourceLimitExceeded
    );
}

#[test]
fn infeasible_wave_count_is_error_not_truncated_or_ready() {
    let f = fixture(&["c", "b", "a"], &[("c", "b"), ("b", "a")], true, None);
    let q = request(&f, 3, 2, &[]);
    assert_eq!(
        WavePlanner::plan(
            &f.topology,
            &f.remediation,
            &f.target,
            &q,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::ResourceLimitExceeded
    );
}

#[test]
fn every_review_gate_remains_unsatisfied_even_if_dependency_order_is_valid() {
    let f = fixture(&["b", "a"], &[("b", "a")], true, None);
    let p = plan(&f, 2, 2, &[]);
    let a = unit(&p, "a");
    assert_eq!(a.status, UnitReadinessStatus::Unverified);
    for kind in [
        ReadinessGateKind::ChangeApproval,
        ReadinessGateKind::MaintenanceWindow,
        ReadinessGateKind::RollbackPlan,
        ReadinessGateKind::IndependentUnitReview,
    ] {
        assert!(a.gates.iter().any(|g| g.kind == kind));
    }
    let b = unit(&p, "b");
    assert_ne!(b.status, UnitReadinessStatus::EligibleForReview);
    assert!(
        b.gates
            .iter()
            .any(|g| g.kind == ReadinessGateKind::UpstreamUnitApproval)
    );
}

#[test]
fn review_submission_hint_never_resolves_missing_owner_or_evidence() {
    let f = fixture(&["a"], &[], false, None);
    let before = plan(&f, 1, 1, &[]);
    let after = plan(&f, 1, 1, &["a"]);
    assert_eq!(unit(&before, "a").status, UnitReadinessStatus::Unverified);
    assert_eq!(unit(&after, "a").status, UnitReadinessStatus::Unverified);
    assert!(
        unit(&after, "a")
            .gates
            .iter()
            .any(|g| g.kind == ReadinessGateKind::UnresolvedBlocker)
    );
    assert_ne!(before.digest(), after.digest());
}

#[test]
fn eligible_for_review_never_means_approved_or_ready() {
    let mut f = fixture(&["a"], &[], true, None);
    with_complete_source_claims(&mut f);
    assert!(f.remediation.blockers().is_empty());
    let eligible = plan(&f, 1, 1, &[]);
    assert_eq!(
        unit(&eligible, "a").status,
        UnitReadinessStatus::EligibleForReview
    );
    let awaiting = plan(&f, 1, 1, &["a"]);
    assert_eq!(
        unit(&awaiting, "a").status,
        UnitReadinessStatus::AwaitingExternalApproval
    );
    assert!(
        unit(&awaiting, "a")
            .gates
            .iter()
            .any(|g| g.kind == ReadinessGateKind::ChangeApproval)
    );
    assert!(
        unit(&awaiting, "a")
            .gates
            .iter()
            .any(|g| g.kind == ReadinessGateKind::RollbackPlan)
    );
}

#[test]
fn stricter_blocker_never_increases_review_eligibility() {
    let mut f = fixture(&["a"], &[], true, None);
    with_complete_source_claims(&mut f);
    let eligible = plan(&f, 1, 1, &[]);
    assert_eq!(
        unit(&eligible, "a").status,
        UnitReadinessStatus::EligibleForReview
    );
    // Removing the context claims changes the D1 report and restores uncertainty.
    let unresolved = fixture(&["a"], &[], true, None);
    let after = plan(&unresolved, 1, 1, &[]);
    assert_eq!(unit(&after, "a").status, UnitReadinessStatus::Unverified);
}

#[test]
fn unrelated_earlier_deadline_does_not_reorder_mandatory_predecessor() {
    let f = fixture(&["b", "a"], &[("b", "a")], true, Some(("b", NOW - 1)));
    let p = plan(&f, 2, 2, &[]);
    assert_eq!(p.waves()[0].unit_ids, vec!["a"]);
    assert_eq!(p.waves()[1].unit_ids, vec!["b"]);
    assert_eq!(unit(&p, "b").due_at_unix_secs, Some(NOW - 1));
    assert!(
        unit(&p, "b")
            .gates
            .iter()
            .any(|g| g.kind == ReadinessGateKind::UnresolvedBlocker)
    );
}

#[test]
fn rejected_stale_replay_and_foreign_pins_preserve_fail_closed() {
    let f = fixture(&["a"], &[], true, None);
    let mut q = request(&f, 1, 1, &[]);
    q.expected_bindings.compatibility_set_digest = SnapshotDigest::from_bytes([0; 32]);
    assert_eq!(
        WavePlanner::plan(
            &f.topology,
            &f.remediation,
            &f.target,
            &q,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::IntegrityMismatch
    );
    let mut q = request(&f, 1, 1, &[]);
    q.expected_bindings.scope_id = "other-tenant".into();
    assert_eq!(
        WavePlanner::plan(
            &f.topology,
            &f.remediation,
            &f.target,
            &q,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::IntegrityMismatch
    );
    let mut q = request(&f, 1, 1, &[]);
    q.expected_bindings.remediation_digest = SnapshotDigest::from_bytes([0; 32]);
    assert_eq!(
        WavePlanner::plan(
            &f.topology,
            &f.remediation,
            &f.target,
            &q,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::IntegrityMismatch
    );
    let mut q = request(&f, 1, 1, &[]);
    q.expected_bindings.topology_digest = SnapshotDigest::from_bytes([0; 32]);
    assert_eq!(
        WavePlanner::plan(
            &f.topology,
            &f.remediation,
            &f.target,
            &q,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::IntegrityMismatch
    );
}

#[test]
fn review_submission_rejects_unknown_or_duplicate_unit_and_schema() {
    let f = fixture(&["a"], &[], true, None);
    let mut q = request(&f, 1, 1, &["unknown"]);
    assert_eq!(
        WavePlanner::plan(
            &f.topology,
            &f.remediation,
            &f.target,
            &q,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::InvalidReference
    );
    q = request(&f, 1, 1, &["a", "a"]);
    assert_eq!(
        WavePlanner::plan(
            &f.topology,
            &f.remediation,
            &f.target,
            &q,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::DuplicateRecord
    );
    q = request(&f, 1, 1, &[]);
    q.schema_version += 1;
    assert_eq!(
        WavePlanner::plan(
            &f.topology,
            &f.remediation,
            &f.target,
            &q,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::UnsupportedSchemaVersion
    );
}

#[test]
fn caller_constraints_and_resource_budgets_are_enforced() {
    let f = fixture(&["a", "b"], &[], true, None);
    let q = request(&f, 2, 2, &[]);
    let limits = Limits {
        max_plan_waves: 1,
        ..Limits::default()
    };
    assert_eq!(
        WavePlanner::plan(&f.topology, &f.remediation, &f.target, &q, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::ResourceLimitExceeded
    );
    let limits = Limits {
        max_planner_candidates: 1,
        ..Limits::default()
    };
    assert_eq!(
        WavePlanner::plan(&f.topology, &f.remediation, &f.target, &q, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::ResourceLimitExceeded
    );
    let limits = Limits {
        max_diagnostics: 1,
        ..Limits::default()
    };
    assert_eq!(
        WavePlanner::plan(&f.topology, &f.remediation, &f.target, &q, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::ResourceLimitExceeded
    );
    let mut q = request(&f, 2, 2, &[]);
    q.capacity_systems_per_wave = 0;
    assert_eq!(
        WavePlanner::plan(
            &f.topology,
            &f.remediation,
            &f.target,
            &q,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::InvalidLimit
    );
}

#[test]
fn output_bytes_and_canonical_order_are_bounded() {
    let f = fixture(&["b", "a"], &[], true, None);
    let a = plan(&f, 1, 2, &["b", "a"]);
    let b = plan(&f, 1, 2, &["a", "b"]);
    assert_eq!(a.digest(), b.digest());
    assert_eq!(
        a.export(&Limits::default()).unwrap(),
        b.export(&Limits::default()).unwrap()
    );
    let len = a.export(&Limits::default()).unwrap().len();
    let limits = Limits {
        max_export_bytes: len - 1,
        ..Limits::default()
    };
    let q = request(&f, 1, 2, &[]);
    assert_eq!(
        WavePlanner::plan(&f.topology, &f.remediation, &f.target, &q, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::ResourceLimitExceeded
    );
}

#[test]
fn golden_v1_advisory_wave_export() {
    let f = fixture(&["b", "a"], &[("b", "a")], true, None);
    let p = plan(&f, 2, 2, &[]);
    let bytes = p.export(&Limits::default()).unwrap();
    assert!(bytes.starts_with(b"CSHIFT_WAVE_PLAN_V1"));
    assert_eq!(
        format!("{} {}", p.digest().as_identifier(), bytes.len()),
        include_str!("fixtures/wave_v1.sha256").trim()
    );
}

fn catalog(provider: &str, runtime: &str) -> CapabilityCatalog {
    CapabilityCatalog::new(
        CapabilityCatalogDraft {
            schema_version: CAPABILITY_CATALOG_VERSION,
            catalog_id: format!("catalog-{provider}"),
            revision: 1,
            scope_id: "tenant-a".into(),
            provenance: ProfileProvenance {
                issuer_id: "vendor".into(),
                document_id: "catalog".into(),
                revision: "1".into(),
                source_digest: None,
            },
            records: vec![CapabilityRecord {
                record_id: format!("record-{provider}"),
                provider_id: provider.into(),
                product_id: "server".into(),
                product_version: "1".into(),
                platform_id: "linux".into(),
                scope_id: "tenant-a".into(),
                runtime_id: Some(runtime.into()),
                algorithm: KnownAlgorithm::MlKem1024,
                role: AlgorithmRole::KeyEncapsulation,
                state: CapabilityState::Available,
                evidence: CapabilityEvidence {
                    source_id: "vendor".into(),
                    evidence_id: format!("evidence-{provider}"),
                    source_revision: "1".into(),
                    basis: CapabilityEvidenceBasis::VendorDocumentation,
                    verification: EvidenceVerification::Unverified,
                    verification_reference: None,
                    artifact_digest: None,
                    observed_at_unix_secs: NOW - 10,
                    expires_at_unix_secs: Some(NOW + 100),
                },
            }],
        },
        &Limits::default(),
        Some(NOW),
    )
    .unwrap()
}

fn peer_report(f: &Fixture, classical_fallback: bool, certificate: bool) -> CompatibilityAnalysis {
    let left = catalog("vendor-a", "runtime-a");
    let right = catalog("vendor-b", "runtime-b");
    let selected_certificate = certificate.then(|| CertificateSelection {
        profile_id: "x509-profile".into(),
        revision: "v1".into(),
        certificate_id: "leaf-1".into(),
        chain_id: "chain-1".into(),
        trust_anchor_id: "root-1".into(),
        signature_algorithm: KnownAlgorithm::MlDsa87,
    });
    let req = CompatibilityRequest {
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
            product_version: "1".into(),
            platform_id: "linux".into(),
            runtime_id: "runtime-a".into(),
        },
        responder: EndpointIdentity {
            system_node_id: "b".into(),
            provider_id: "vendor-b".into(),
            product_id: "server".into(),
            product_version: "1".into(),
            platform_id: "linux".into(),
            runtime_id: "runtime-b".into(),
        },
        protocol_id: "transport".into(),
        protocol_revision: "v1".into(),
        extension_revision: "extension-1".into(),
        algorithm: KnownAlgorithm::MlKem1024,
        role: AlgorithmRole::KeyEncapsulation,
        certificate: selected_certificate,
        hybrid: None,
        classical_fallback,
        observations: vec![],
    };
    CompatibilityAnalyzer::analyze(
        &req,
        &f.graph,
        &f.target,
        &left,
        &right,
        NOW,
        &Limits::default(),
    )
    .unwrap()
}

fn bind_peer(f: &mut Fixture, report: &CompatibilityAnalysis) {
    let limits = Limits::default();
    let pinned = RemediationAnalyzer::input_bindings(
        &f.inventory,
        &f.graph,
        &f.topology,
        &f.risk,
        &f.target,
        NOW,
        &limits,
    )
    .unwrap();
    f.remediation = RemediationAnalyzer::analyze(
        &f.inventory,
        &f.graph,
        &f.topology,
        &f.risk,
        &f.target,
        &[report],
        pinned,
        &limits,
    )
    .unwrap();
}

#[test]
fn peer_mlkem_1024_advertisements_without_handshake_remain_unverified() {
    let mut f = fixture(&["a", "b"], &[], true, None);
    let reported = peer_report(&f, false, false);
    assert_ne!(reported.status(), CompatibilityStatus::Compatible);
    bind_peer(&mut f, &reported);
    let p = plan(&f, 2, 1, &["a", "b"]);
    for id in ["a", "b"] {
        assert_eq!(unit(&p, id).status, UnitReadinessStatus::Unverified);
        assert!(
            unit(&p, id)
                .gates
                .iter()
                .any(|gate| gate.kind == ReadinessGateKind::UnresolvedBlocker)
        );
        assert!(
            unit(&p, id)
                .gates
                .iter()
                .any(|gate| gate.kind == ReadinessGateKind::ChangeApproval)
        );
    }
}

#[test]
fn unapproved_classical_fallback_blocks_both_peers() {
    let mut f = fixture(&["a", "b"], &[], true, None);
    let reported = peer_report(&f, true, false);
    bind_peer(&mut f, &reported);
    let p = plan(&f, 2, 1, &[]);
    assert_eq!(unit(&p, "a").status, UnitReadinessStatus::Blocked);
    assert_eq!(unit(&p, "b").status, UnitReadinessStatus::Blocked);
    assert!(p.readiness().iter().all(|unit| {
        unit.gates
            .iter()
            .any(|gate| gate.kind == ReadinessGateKind::UnresolvedBlocker)
    }));
}

#[test]
fn changing_only_peer_proof_invalidates_existing_wave_input_pins() {
    let mut f = fixture(&["a", "b"], &[], true, None);
    let old = request(&f, 2, 1, &[]);
    let compat = peer_report(&f, false, false);
    bind_peer(&mut f, &compat);
    assert_eq!(
        WavePlanner::plan(
            &f.topology,
            &f.remediation,
            &f.target,
            &old,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::IntegrityMismatch
    );
    let renewed = plan(&f, 2, 1, &[]);
    assert_eq!(
        renewed.bindings().compatibility_set_digest,
        f.remediation.compatibility_set_digest()
    );
    assert_ne!(
        renewed.bindings().remediation_digest,
        old.expected_bindings.remediation_digest
    );
}

#[test]
fn required_certificate_profile_without_pki_validation_never_ready() {
    let mut f = fixture(&["a", "b"], &[], true, None);
    let mut draft = f.target.content().clone();
    draft.standards.push(StandardEdition::Fips204_2024);
    draft.algorithms.push(AlgorithmConstraint {
        algorithm: KnownAlgorithm::MlDsa87,
        role: AlgorithmRole::Signature,
        minimum_category: Some(SecurityCategory::Five),
        disposition: ConstraintDisposition::Required,
    });
    draft.certificates.push(CertificateConstraint {
        profile_id: "x509-profile".into(),
        revision: "v1".into(),
        signature_algorithm: KnownAlgorithm::MlDsa87,
        specification_reference: "pkix-profile-source".into(),
    });
    f.target = TargetProfile::new(draft, &Limits::default(), Some(NOW)).unwrap();
    let reported = peer_report(&f, false, true);
    assert_ne!(reported.status(), CompatibilityStatus::Compatible);
    assert!(
        reported
            .findings()
            .iter()
            .any(|item| item.code == CompatibilityCode::PkiMissing)
    );
    bind_peer(&mut f, &reported);
    let p = plan(&f, 2, 1, &[]);
    assert!(p.readiness().iter().all(|unit| {
        unit.status == UnitReadinessStatus::Unverified
            && unit
                .gates
                .iter()
                .any(|gate| gate.validations.contains(&RemediationGate::ValidatePki))
    }));
}


#[test]
fn tight_graph_budget_counts_all_systems_inside_multiple_sccs() {
    let f=fixture(
        &["a","b","c","d"],
        &[("a","b"),("b","a"),("c","d"),("d","c")],
        true,None
    );
    assert_eq!(f.topology.units().len(),2);
    assert_eq!(f.topology.units().iter().map(|u|u.system_ids.len()).sum::<usize>(),4);
    let q=request(&f,2,2,&[]);
    let tight=Limits{max_graph_nodes:3,..Limits::default()};
    assert_eq!(WavePlanner::plan(
        &f.topology,&f.remediation,&f.target,&q,&tight,
    ).unwrap_err().code,DiagnosticCode::ResourceLimitExceeded);
    let normal=plan(&f,2,2,&[]);
    assert_eq!(normal.waves().len(),2);
    assert!(normal.waves().iter().all(|w|w.occupied_system_slots==2));
}
