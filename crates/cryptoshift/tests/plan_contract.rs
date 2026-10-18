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

#[test]
fn different_claim_state_with_identical_evidence_reference_rotates_facet_ids() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    let original = catalog("vendor", "source-r1");
    let mut changed = original.content().clone();
    changed.records[0].state = CapabilityState::Roadmap;
    let revised = CapabilityCatalog::new(changed, &Limits::default(), Some(NOW)).unwrap();
    let old = build(&f, &wave, &[&original], None, vec![]);
    let new = build(&f, &wave, &[&revised], None, vec![]);
    assert_ne!(original.digest(), revised.digest());
    assert_ne!(old.digest(), new.digest());
    let delta = old.semantic_diff(&new, &Limits::default()).unwrap();
    assert!(delta.changes.contains(&PlanChangeKind::Capabilities));
    assert!(delta.changes.contains(&PlanChangeKind::ResidualRisk));
    let old_vendor: Vec<_> = old
        .residual_risks()
        .iter()
        .filter(|v| v.kind == ResidualRiskKind::VendorCapability)
        .map(|v| v.id.as_str())
        .collect();
    let new_vendor: Vec<_> = new
        .residual_risks()
        .iter()
        .filter(|v| v.kind == ResidualRiskKind::VendorCapability)
        .map(|v| v.id.as_str())
        .collect();
    assert_ne!(old_vendor, new_vendor);
}

#[test]
fn foreign_catalog_and_expired_capability_evidence_are_rejected() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    let c = catalog("vendor", "rev1");
    let mut altered = c.content().clone();
    altered.scope_id = "tenant-b".into();
    altered.records[0].scope_id = "tenant-b".into();
    let foreign = CapabilityCatalog::new(altered, &Limits::default(), Some(NOW)).unwrap();
    assert_eq!(
        MigrationPlanner::input_pins(
            &f.topology,
            &f.remediation,
            &wave,
            &f.target,
            &[&foreign],
            None,
            &Limits::default(),
        )
        .unwrap_err()
        .code,
        DiagnosticCode::InvalidReference
    );
    let mut stale = c.content().clone();
    stale.records[0].evidence.expires_at_unix_secs = Some(NOW - 1);
    let old = CapabilityCatalog::new(stale, &Limits::default(), Some(NOW - 5)).unwrap();
    assert_eq!(
        MigrationPlanner::input_pins(
            &f.topology,
            &f.remediation,
            &wave,
            &f.target,
            &[&old],
            None,
            &Limits::default(),
        )
        .unwrap_err()
        .code,
        DiagnosticCode::StaleCriticalProfile
    );
}

#[test]
fn a_changed_exception_target_cannot_reuse_risk_facet_identity() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    let old = build(&f, &wave, &[], None, vec![proposal("req")]);
    let mut different = proposal("req");
    different.target_constraint_id = "transport".into();
    let new = build(&f, &wave, &[], None, vec![different]);
    assert_ne!(old.digest(), new.digest());
    let old_id = old
        .residual_risks()
        .iter()
        .find(|r| r.kind == ResidualRiskKind::ExceptionUnverified)
        .unwrap()
        .id
        .clone();
    let new_id = new
        .residual_risks()
        .iter()
        .find(|r| r.kind == ResidualRiskKind::ExceptionUnverified)
        .unwrap()
        .id
        .clone();
    assert_ne!(old_id, new_id);
    let delta = old.semantic_diff(&new, &Limits::default()).unwrap();
    assert!(delta.changes.contains(&PlanChangeKind::Exceptions));
    assert!(delta.changes.contains(&PlanChangeKind::ResidualRisk));
}

#[test]
fn changed_wave_review_hints_rotate_plan_identity_even_when_readiness_unchanged() {
    let f = fixture(&["a"], &[], false, None);
    let first = plan(&f, 1, 1, &[]);
    let next = plan(&f, 1, 1, &["a"]);
    assert_eq!(first.readiness(), next.readiness());
    assert_ne!(first.digest(), next.digest());
    let p = build(&f, &first, &[], None, vec![]);
    let q = build(&f, &next, &[], None, vec![]);
    assert_ne!(p.digest(), q.digest());
    let delta = p.semantic_diff(&q, &Limits::default()).unwrap();
    assert!(delta.changes.contains(&PlanChangeKind::WavePlan));
    assert!(delta.changes.contains(&PlanChangeKind::ResidualRisk));
}

#[test]
fn a_recomputed_risk_vector_invalidates_old_plan_pins() {
    let mut f = fixture(&["a"], &[], true, None);
    let initial_wave = plan(&f, 1, 1, &[]);
    let pinned = source_pins(&f, &initial_wave, &[], None);
    let old = build(&f, &initial_wave, &[], None, vec![]);
    with_complete_source_claims(&mut f);
    let new_wave = plan(&f, 1, 1, &[]);
    let fresh = build(&f, &new_wave, &[], None, vec![]);
    assert_eq!(pinned.inventory_digest, fresh.pins().inventory_digest);
    assert_eq!(pinned.graph_digest, fresh.pins().graph_digest);
    assert_ne!(pinned.risk_digest, fresh.pins().risk_digest);
    let stale = MigrationPlanner::build(
        &f.topology,
        &f.remediation,
        &new_wave,
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
    assert_eq!(stale.code, DiagnosticCode::IntegrityMismatch);
    let delta = old.semantic_diff(&fresh, &Limits::default()).unwrap();
    assert!(delta.changes.contains(&PlanChangeKind::Risk));
    assert!(delta.changes.contains(&PlanChangeKind::Remediation));
}

#[test]
fn residual_risk_identifiers_reject_stale_scoring_profile_bindings() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    let previous = scoring();
    let altered = ScoreProfile::new(
        "scoring-v1".into(),
        SCORE_PROFILE_VERSION,
        [900, 1100, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000],
    )
    .unwrap();
    let prior = build(&f, &wave, &[], Some(&previous), vec![]);
    let next = build(&f, &wave, &[], Some(&altered), vec![]);
    assert_ne!(prior.residual_risks()[0].id, next.residual_risks()[0].id);
    assert_ne!(prior.digest(), next.digest());
}

fn peer_catalog(provider: &str, runtime: &str) -> CapabilityCatalog {
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
    let left = peer_catalog("vendor-a", "runtime-a");
    let right = peer_catalog("vendor-b", "runtime-b");
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
fn peer_advertisements_without_authenticated_negotiation_cannot_complete_plan() {
    let mut f = fixture(&["a", "b"], &[], true, None);
    let peer = peer_report(&f, false, false);
    assert_ne!(peer.status(), CompatibilityStatus::Compatible);
    bind_peer(&mut f, &peer);
    let draft = build(&f, &plan(&f, 2, 1, &[]), &[], None, vec![]);
    assert_eq!(draft.status(), PlanAssessmentState::Partial);
    assert!(
        draft
            .residual_risks()
            .iter()
            .any(|risk| risk.kind == ResidualRiskKind::PeerProtocol
                || risk.kind == ResidualRiskKind::EvidenceQuality)
    );
    assert!(
        draft
            .readiness()
            .iter()
            .all(|u| u.status != UnitReadinessStatus::EligibleForReview)
    );
}

#[test]
fn claimed_exception_cannot_override_prohibited_classical_fallback() {
    let mut f = fixture(&["a", "b"], &[], true, None);
    let peer = peer_report(&f, true, false);
    bind_peer(&mut f, &peer);
    let wave = plan(&f, 2, 1, &[]);
    assert!(
        wave.readiness()
            .iter()
            .all(|u| u.status == UnitReadinessStatus::Blocked)
    );
    let blocked = build(&f, &wave, &[], None, vec![]);
    let mut exception = proposal("fallback-request");
    exception.claimed_approval = Some(purported_approval());
    let still_blocked = build(&f, &wave, &[], None, vec![exception]);
    assert_eq!(blocked.status(), PlanAssessmentState::Blocked);
    assert_eq!(still_blocked.status(), PlanAssessmentState::Blocked);
    assert_eq!(blocked.blocker_ids(), still_blocked.blocker_ids());
    assert_eq!(blocked.action_ids(), still_blocked.action_ids());
    assert_eq!(
        still_blocked.exceptions()[0].state,
        PlanExceptionState::ClaimedApprovalUnverified
    );
}

#[test]
fn missing_certificate_chain_and_revocation_preserve_pki_residual_risk() {
    let mut f = fixture(&["a", "b"], &[], true, None);
    let mut target = f.target.content().clone();
    target.standards.push(StandardEdition::Fips204_2024);
    target.algorithms.push(AlgorithmConstraint {
        algorithm: KnownAlgorithm::MlDsa87,
        role: AlgorithmRole::Signature,
        minimum_category: Some(SecurityCategory::Five),
        disposition: ConstraintDisposition::Required,
    });
    target.certificates.push(CertificateConstraint {
        profile_id: "x509-profile".into(),
        revision: "v1".into(),
        signature_algorithm: KnownAlgorithm::MlDsa87,
        specification_reference: "profile-authority".into(),
    });
    f.target = TargetProfile::new(target, &Limits::default(), Some(NOW)).unwrap();
    let peer = peer_report(&f, false, true);
    assert_ne!(peer.status(), CompatibilityStatus::Compatible);
    bind_peer(&mut f, &peer);
    let draft = build(&f, &plan(&f, 2, 1, &[]), &[], None, vec![]);
    assert_eq!(draft.status(), PlanAssessmentState::Partial);
    assert!(draft.residual_risks().iter().any(|risk| {
        risk.kind == ResidualRiskKind::PkiTrust
            && risk
                .validation_gates
                .contains(&RemediationGate::ValidatePki)
    }));
}

#[test]
fn shared_vendor_document_yields_independent_capability_facet_identities() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    let original = catalog("vendor", "source-1");
    let mut draft = original.content().clone();
    let mut second = draft.records[0].clone();
    second.record_id = "runtime-v2".into();
    second.product_version = "v2".into();
    // Two independently addressable capability claims cite one source record.
    assert_eq!(second.evidence, draft.records[0].evidence);
    draft.records.push(second);
    let multi = CapabilityCatalog::new(draft, &Limits::default(), Some(NOW)).unwrap();
    let plan = build(&f, &wave, &[&multi], None, vec![]);
    let mut facets: Vec<_> = plan
        .residual_risks()
        .iter()
        .filter(|item| item.kind == ResidualRiskKind::VendorCapability)
        .collect();
    facets.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(facets.len(), 2);
    assert_ne!(facets[0].id, facets[1].id);
    assert_ne!(facets[0].subject, facets[1].subject);
    assert!(
        facets
            .iter()
            .all(|item| matches!(&item.subject, Some(PlanFacetSubject::Capability { .. })))
    );
}

#[test]
fn shared_exception_justification_never_collapses_distinct_request_ids() {
    let f = fixture(&["a"], &[], true, None);
    let wave = plan(&f, 1, 1, &[]);
    let first = proposal("exception-1");
    let mut second = proposal("exception-2");
    second.justification_reference = first.justification_reference.clone();
    second.target_constraint_id = "transport".into();
    assert_eq!(first.expires_at_unix_secs, second.expires_at_unix_secs);
    let draft = build(&f, &wave, &[], None, vec![second, first]);
    let facets: Vec<_> = draft
        .residual_risks()
        .iter()
        .filter(|item| item.kind == ResidualRiskKind::ExceptionUnverified)
        .collect();
    assert_eq!(facets.len(), 2);
    assert_ne!(facets[0].id, facets[1].id);
    assert_ne!(facets[0].subject, facets[1].subject);
    let subjects: Vec<_> = facets
        .iter()
        .filter_map(|item| match &item.subject {
            Some(PlanFacetSubject::Exception {
                request_id,
                target_constraint_id,
            }) => Some((request_id.as_str(), target_constraint_id.as_str())),
            _ => None,
        })
        .collect();
    assert!(subjects.contains(&("exception-1", KnownAlgorithm::MlKem1024.id())));
    assert!(subjects.contains(&("exception-2", "transport")));
}
