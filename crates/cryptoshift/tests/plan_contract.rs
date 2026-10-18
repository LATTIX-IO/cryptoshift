//! FOSS-444 immutable plan identity, exception, diff and security acceptance.
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

fn catalog(provider: &str, version: &str) -> CapabilityCatalog {
    CapabilityCatalog::new(
        CapabilityCatalogDraft {
            schema_version: CAPABILITY_CATALOG_VERSION,
            catalog_id: format!("catalog-{provider}"),
            revision: 1,
            scope_id: "tenant-a".into(),
            provenance: ProfileProvenance {
                issuer_id: provider.into(),
                document_id: "catalog".into(),
                revision: version.into(),
                source_digest: None,
            },
            records: vec![CapabilityRecord {
                record_id: format!("runtime-{provider}"),
                provider_id: provider.into(),
                product_id: "server".into(),
                product_version: "v1".into(),
                platform_id: "linux".into(),
                scope_id: "tenant-a".into(),
                runtime_id: Some("runtime-a".into()),
                algorithm: KnownAlgorithm::MlKem1024,
                role: AlgorithmRole::KeyEncapsulation,
                state: CapabilityState::Available,
                evidence: CapabilityEvidence {
                    source_id: provider.into(),
                    evidence_id: "external-claim".into(),
                    source_revision: version.into(),
                    basis: CapabilityEvidenceBasis::VendorDocumentation,
                    verification: EvidenceVerification::Unverified,
                    verification_reference: None,
                    artifact_digest: None,
                    observed_at_unix_secs: NOW - 100,
                    expires_at_unix_secs: Some(NOW + 100),
                },
            }],
        },
        &Limits::default(),
        Some(NOW),
    )
    .unwrap()
}

fn scoring() -> ScoreProfile {
    ScoreProfile::new("scoring-v1".into(), SCORE_PROFILE_VERSION, [1000; 10]).unwrap()
}

fn source_pins(
    f: &Fixture,
    wave: &WavePlanDraft,
    catalogs: &[&CapabilityCatalog],
    score: Option<&ScoreProfile>,
) -> PlanSourcePins {
    MigrationPlanner::input_pins(
        &f.topology,
        &f.remediation,
        wave,
        &f.target,
        catalogs,
        score,
        &Limits::default(),
    )
    .unwrap()
}

fn build(
    f: &Fixture,
    wave: &WavePlanDraft,
    catalogs: &[&CapabilityCatalog],
    score: Option<&ScoreProfile>,
    exceptions: Vec<PlanExceptionRequest>,
) -> MigrationPlanDraft {
    let pins = source_pins(f, wave, catalogs, score);
    MigrationPlanner::build(
        &f.topology,
        &f.remediation,
        wave,
        &f.target,
        catalogs,
        score,
        &MigrationPlanRequest {
            schema_version: MIGRATION_PLAN_VERSION,
            expected_pins: pins,
            exceptions,
        },
        &Limits::default(),
    )
    .unwrap()
}

fn proposal(id: &str) -> PlanExceptionRequest {
    PlanExceptionRequest {
        request_id: id.into(),
        scope_id: "tenant-a".into(),
        unit_id: "a".into(),
        target_constraint_id: KnownAlgorithm::MlKem1024.id().into(),
        requester_source_id: "owner".into(),
        justification_reference: format!("justification-{id}"),
        requested_at_unix_secs: NOW - 10,
        expires_at_unix_secs: NOW + 100,
        claimed_approval: None,
    }
}

fn purported_approval() -> ClaimedExceptionApproval {
    ClaimedExceptionApproval {
        issuer_id: "independent-reviewer".into(),
        receipt_reference: "claimed-external-receipt".into(),
        source_revision: "revision-1".into(),
        observed_at_unix_secs: NOW - 2,
    }
}

#[test]
fn plan_identity_binds_all_d1_d2_source_revisions_and_score() {
    let f = fixture(&["a", "b"], &[("b", "a")], true, None);
    let wave = plan(&f, 2, 2, &[]);
    let catalog = catalog("vendor-a", "r1");
    let score = scoring();
    let draft = build(&f, &wave, &[&catalog], Some(&score), vec![]);
    let pins = draft.pins();
    assert_eq!(pins.scope_id, "tenant-a");
    assert_eq!(pins.wave_digest, wave.digest());
    assert_eq!(pins.remediation_digest, f.remediation.digest());
    assert_eq!(
        pins.compatibility_set_digest,
        f.remediation.compatibility_set_digest()
    );
    assert_eq!(pins.target_digest, f.target.digest());
    assert_eq!(
        pins.inventory_digest,
        f.remediation.bindings().inventory_digest
    );
    assert_eq!(pins.graph_digest, f.remediation.bindings().graph_digest);
    assert_eq!(
        pins.topology_digest,
        f.remediation.bindings().topology_digest
    );
    assert_eq!(pins.risk_digest, f.remediation.bindings().risk_digest);
    assert_eq!(pins.standards_catalog_version, STANDARDS_CATALOG_VERSION);
    assert_eq!(pins.standards, vec![StandardEdition::Fips203_2024]);
    assert_eq!(pins.catalogs[0].digest, catalog.digest());
    assert_eq!(
        pins.scoring.as_ref().unwrap().digest,
        MigrationPlanner::scoring_digest(&score, &Limits::default()).unwrap()
    );
    assert_eq!(draft.waves(), wave.waves());
    assert_eq!(draft.readiness(), wave.readiness());
    assert_ne!(draft.digest(), SnapshotDigest::from_bytes([0; 32]));
    assert!(
        draft
            .export(&Limits::default())
            .unwrap()
            .starts_with(b"CSHIFT_MIGRATION_PLAN_V1")
    );
}

#[test]
fn unresolved_risks_and_external_controls_survive_plan_creation() {
    let f = fixture(&["a", "b"], &[("b", "a")], false, None);
    let wave = plan(&f, 2, 2, &[]);
    let draft = build(&f, &wave, &[], None, vec![]);
    assert_eq!(draft.status(), PlanAssessmentState::Partial);
    for kind in [
        ResidualRiskKind::Ownership,
        ResidualRiskKind::QuantumOrContextRisk,
        ResidualRiskKind::Dependency,
        ResidualRiskKind::ChangeApproval,
        ResidualRiskKind::Maintenance,
        ResidualRiskKind::Rollback,
        ResidualRiskKind::UnitReview,
        ResidualRiskKind::MissingCapabilityEvidence,
    ] {
        assert!(
            draft.residual_risks().iter().any(|f| f.kind == kind),
            "missing: {kind:?}"
        );
    }
    assert_eq!(draft.blocker_ids().len(), f.remediation.blockers().len());
    assert_eq!(draft.action_ids().len(), f.remediation.actions().len());
    assert!(
        draft
            .residual_risks()
            .iter()
            .filter_map(|facet| facet.blocker_id.as_ref())
            .all(|id| draft.blocker_ids().contains(id))
    );
}

#[test]
fn proposal_and_approval_receipt_claims_never_dismiss_blockers() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    let baseline = build(&f, &wave, &[], None, vec![]);
    let initial = build(&f, &wave, &[], None, vec![proposal("request-1")]);
    assert_eq!(initial.exceptions()[0].state, PlanExceptionState::Requested);
    let mut requested = proposal("request-1");
    requested.claimed_approval = Some(purported_approval());
    let claimed = build(&f, &wave, &[], None, vec![requested]);
    assert_eq!(
        claimed.exceptions()[0].state,
        PlanExceptionState::ClaimedApprovalUnverified
    );
    assert_eq!(claimed.status(), PlanAssessmentState::Partial);
    assert_eq!(baseline.blocker_ids(), claimed.blocker_ids());
    assert_eq!(baseline.action_ids(), claimed.action_ids());
    assert!(claimed.residual_risks().iter().any(|r| {
        r.kind == ResidualRiskKind::ExceptionUnverified
            && r.evidence.iter().any(|e| {
                matches!(e,PlanEvidenceRef::Exception{source_id,..}
            if source_id=="independent-reviewer")
            })
    }));
    assert_ne!(baseline.digest(), initial.digest());
    assert_ne!(initial.digest(), claimed.digest());
}

#[test]
fn expired_exception_claim_cannot_be_an_approval() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    let mut req = proposal("expired");
    req.expires_at_unix_secs = NOW - 1;
    req.claimed_approval = Some(purported_approval());
    let draft = build(&f, &wave, &[], None, vec![req]);
    assert_eq!(draft.exceptions()[0].state, PlanExceptionState::Expired);
    assert!(
        draft
            .residual_risks()
            .iter()
            .any(|r| r.kind == ResidualRiskKind::ExceptionUnverified)
    );
}

#[test]
fn wrong_tenant_unit_constraint_or_owner_rejects_exception() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    for change in 0..4 {
        let mut req = proposal("wrong");
        match change {
            0 => req.scope_id = "foreign".into(),
            1 => req.unit_id = "absent".into(),
            2 => req.target_constraint_id = "unknown-policy".into(),
            _ => req.requester_source_id = "other-owner".into(),
        }
        let pins = source_pins(&f, &wave, &[], None);
        let err = MigrationPlanner::build(
            &f.topology,
            &f.remediation,
            &wave,
            &f.target,
            &[],
            None,
            &MigrationPlanRequest {
                schema_version: MIGRATION_PLAN_VERSION,
                expected_pins: pins,
                exceptions: vec![req],
            },
            &Limits::default(),
        )
        .unwrap_err();
        assert_eq!(err.code, DiagnosticCode::InvalidReference);
    }
}

#[test]
fn ownerless_unit_cannot_sponsor_exception() {
    let f = fixture(&["a"], &[], false, None);
    let wave = plan(&f, 1, 1, &[]);
    let pins = source_pins(&f, &wave, &[], None);
    assert_eq!(
        MigrationPlanner::build(
            &f.topology,
            &f.remediation,
            &wave,
            &f.target,
            &[],
            None,
            &MigrationPlanRequest {
                schema_version: MIGRATION_PLAN_VERSION,
                expected_pins: pins,
                exceptions: vec![proposal("orphan")]
            },
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::InvalidReference
    );
}

#[test]
fn forged_same_party_or_future_receipt_is_rejected_without_waiver() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    for case in 0..3 {
        let mut req = proposal("bad-claim");
        let mut claim = purported_approval();
        match case {
            0 => claim.issuer_id = req.requester_source_id.clone(),
            1 => claim.observed_at_unix_secs = NOW + 1,
            _ => claim.observed_at_unix_secs = NOW - 100,
        }
        req.claimed_approval = Some(claim);
        let err = MigrationPlanner::build(
            &f.topology,
            &f.remediation,
            &wave,
            &f.target,
            &[],
            None,
            &MigrationPlanRequest {
                schema_version: MIGRATION_PLAN_VERSION,
                expected_pins: source_pins(&f, &wave, &[], None),
                exceptions: vec![req],
            },
            &Limits::default(),
        )
        .unwrap_err();
        assert_eq!(err.code, DiagnosticCode::InvalidStateTransition);
    }
}

#[test]
fn replayed_wave_risk_target_compat_and_scope_pins_fail_closed() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    for part in 0..6 {
        let mut pinned = source_pins(&f, &wave, &[], None);
        match part {
            0 => pinned.wave_digest = SnapshotDigest::from_bytes([1; 32]),
            1 => pinned.remediation_digest = SnapshotDigest::from_bytes([2; 32]),
            2 => pinned.compatibility_set_digest = SnapshotDigest::from_bytes([3; 32]),
            3 => pinned.risk_digest = SnapshotDigest::from_bytes([4; 32]),
            4 => pinned.target_digest = SnapshotDigest::from_bytes([5; 32]),
            _ => pinned.scope_id = "other-tenant".into(),
        }
        let err = MigrationPlanner::build(
            &f.topology,
            &f.remediation,
            &wave,
            &f.target,
            &[],
            None,
            &MigrationPlanRequest {
                schema_version: MIGRATION_PLAN_VERSION,
                expected_pins: pinned,
                exceptions: vec![],
            },
            &Limits::default(),
        )
        .unwrap_err();
        assert_eq!(err.code, DiagnosticCode::IntegrityMismatch);
    }
}

#[test]
fn reordered_catalogs_and_exceptions_are_byte_equivalent() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    let a = catalog("vendor-a", "v1");
    let b = catalog("vendor-b", "v1");
    let first = build(
        &f,
        &wave,
        &[&a, &b],
        None,
        vec![proposal("request-a"), proposal("request-b")],
    );
    let second = build(
        &f,
        &wave,
        &[&b, &a],
        None,
        vec![proposal("request-b"), proposal("request-a")],
    );
    assert_eq!(first.digest(), second.digest());
    assert_eq!(
        first.export(&Limits::default()).unwrap(),
        second.export(&Limits::default()).unwrap()
    );
    assert!(
        first
            .semantic_diff(&second, &Limits::default())
            .unwrap()
            .changes
            .is_empty()
    );
}

#[test]
fn changed_capability_revision_rotates_plan_and_yields_semantic_diff() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    let old = catalog("vendor", "rev1");
    let newer = catalog("vendor", "rev2");
    let a = build(&f, &wave, &[&old], None, vec![]);
    let b = build(&f, &wave, &[&newer], None, vec![]);
    let changes = a.semantic_diff(&b, &Limits::default()).unwrap();
    assert!(changes.changes.contains(&PlanChangeKind::Capabilities));
    assert!(changes.changes.contains(&PlanChangeKind::ResidualRisk));
    assert_ne!(a.digest(), b.digest());
}

#[test]
fn changed_scoring_weights_are_source_bound() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    let a = scoring();
    let b = ScoreProfile::new(
        "scoring-v1".into(),
        SCORE_PROFILE_VERSION,
        [1100, 900, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000],
    )
    .unwrap();
    let previous = build(&f, &wave, &[], Some(&a), vec![]);
    let newer = build(&f, &wave, &[], Some(&b), vec![]);
    let changes = previous.semantic_diff(&newer, &Limits::default()).unwrap();
    assert!(changes.changes.contains(&PlanChangeKind::Scoring));
    assert_ne!(previous.digest(), newer.digest());
}

#[test]
fn exception_revision_and_expiry_are_semantically_diffed() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    let first = build(&f, &wave, &[], None, vec![proposal("req-1")]);
    let mut edited = proposal("req-1");
    edited.claimed_approval = Some(purported_approval());
    let next = build(&f, &wave, &[], None, vec![edited]);
    let diff = first.semantic_diff(&next, &Limits::default()).unwrap();
    assert_eq!(diff.changed_exception_ids, vec!["req-1"]);
    assert!(diff.changes.contains(&PlanChangeKind::Exceptions));
    assert_ne!(first.digest(), next.digest());
}

#[test]
fn repeated_exception_or_catalog_names_are_rejected() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    let pin = source_pins(&f, &wave, &[], None);
    let err = MigrationPlanner::build(
        &f.topology,
        &f.remediation,
        &wave,
        &f.target,
        &[],
        None,
        &MigrationPlanRequest {
            schema_version: MIGRATION_PLAN_VERSION,
            expected_pins: pin,
            exceptions: vec![proposal("dup"), proposal("dup")],
        },
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(err.code, DiagnosticCode::DuplicateRecord);
    let c = catalog("vendor", "r1");
    assert_eq!(
        MigrationPlanner::input_pins(
            &f.topology,
            &f.remediation,
            &wave,
            &f.target,
            &[&c, &c],
            None,
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::DuplicateRecord
    );
}

#[test]
fn invalid_request_timestamps_and_revision_fail_closed() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    for bad in 0..2 {
        let mut req = proposal("timing");
        if bad == 0 {
            req.requested_at_unix_secs = NOW + 10;
        } else {
            req.expires_at_unix_secs = req.requested_at_unix_secs;
        }
        let error = MigrationPlanner::build(
            &f.topology,
            &f.remediation,
            &wave,
            &f.target,
            &[],
            None,
            &MigrationPlanRequest {
                schema_version: MIGRATION_PLAN_VERSION,
                expected_pins: source_pins(&f, &wave, &[], None),
                exceptions: vec![req],
            },
            &Limits::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, DiagnosticCode::InvalidStateTransition);
    }
    let error = MigrationPlanner::build(
        &f.topology,
        &f.remediation,
        &wave,
        &f.target,
        &[],
        None,
        &MigrationPlanRequest {
            schema_version: MIGRATION_PLAN_VERSION + 1,
            expected_pins: source_pins(&f, &wave, &[], None),
            exceptions: vec![],
        },
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, DiagnosticCode::UnsupportedSchemaVersion);
}

#[test]
fn bounded_output_exception_and_risk_facet_limits() {
    let f = fixture(&["a", "b"], &[("b", "a")], true, None);
    let wave = plan(&f, 2, 2, &[]);
    let baseline = build(&f, &wave, &[], None, vec![]);
    let length = baseline.export(&Limits::default()).unwrap().len();
    let limit = Limits {
        max_export_bytes: length - 1,
        ..Limits::default()
    };
    let err = MigrationPlanner::build(
        &f.topology,
        &f.remediation,
        &wave,
        &f.target,
        &[],
        None,
        &MigrationPlanRequest {
            schema_version: MIGRATION_PLAN_VERSION,
            expected_pins: source_pins(&f, &wave, &[], None),
            exceptions: vec![],
        },
        &limit,
    )
    .unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ResourceLimitExceeded);
    assert_eq!(
        baseline.export(&limit).unwrap_err().code,
        DiagnosticCode::ResourceLimitExceeded
    );
    let tight = Limits {
        max_diagnostics: 1,
        ..Limits::default()
    };
    assert_eq!(
        MigrationPlanner::build(
            &f.topology,
            &f.remediation,
            &wave,
            &f.target,
            &[],
            None,
            &MigrationPlanRequest {
                schema_version: MIGRATION_PLAN_VERSION,
                expected_pins: source_pins(&f, &wave, &[], None),
                exceptions: vec![]
            },
            &tight
        )
        .unwrap_err()
        .code,
        DiagnosticCode::ResourceLimitExceeded
    );
    let tight = Limits {
        max_profile_references: 1,
        ..Limits::default()
    };
    assert_eq!(
        MigrationPlanner::build(
            &f.topology,
            &f.remediation,
            &wave,
            &f.target,
            &[],
            None,
            &MigrationPlanRequest {
                schema_version: MIGRATION_PLAN_VERSION,
                expected_pins: source_pins(&f, &wave, &[], None),
                exceptions: vec![proposal("x"), proposal("y")]
            },
            &tight
        )
        .unwrap_err()
        .code,
        DiagnosticCode::ResourceLimitExceeded
    );
}

#[test]
fn cyclic_scc_unit_and_prerequisite_remain_intact() {
    let f = fixture(
        &["a", "b", "c"],
        &[("a", "b"), ("b", "a"), ("c", "a")],
        true,
        None,
    );
    let wave = plan(&f, 2, 2, &[]);
    let draft = build(&f, &wave, &[], None, vec![]);
    assert_eq!(draft.waves().len(), 2);
    assert_eq!(draft.waves()[0].occupied_system_slots, 2);
    assert_eq!(
        draft
            .readiness()
            .iter()
            .find(|r| r.unit_id == "a")
            .unwrap()
            .system_ids,
        vec!["a", "b"]
    );
    assert!(
        draft
            .residual_risks()
            .iter()
            .any(|f| f.unit_id.as_deref() == Some("c") && f.kind == ResidualRiskKind::Dependency)
    );
}

#[test]
fn golden_v1_migration_plan_export() {
    let f = fixture(&["a", "b"], &[("b", "a")], true, None);
    let wave = plan(&f, 2, 2, &[]);
    let report = build(&f, &wave, &[], None, vec![proposal("request-1")]);
    let bytes = report.export(&Limits::default()).unwrap();
    assert!(bytes.starts_with(b"CSHIFT_MIGRATION_PLAN_V1"));
    assert_eq!(
        format!("{} {}", report.digest().as_identifier(), bytes.len()),
        include_str!("fixtures/plan_v1.sha256").trim()
    );
}
