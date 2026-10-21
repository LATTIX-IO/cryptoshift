//! A clean-room offline Cargo consumer. No Cryptomap/Cryptopolicy dependency.
use cryptoshift::*;

const NOW: i64 = 1_800_000_000;
const PUBLISHER: &str = "synthetic-offline-fixture";

fn inventory(current: bool) -> Result<NeutralInventoryProjection, Diagnostic> {
    let run = if current { "run-2" } else { "run-1" };
    let ev = if current { "evidence-2" } else { "evidence-1" };
    let snapshot = InventorySnapshot {
        identity_version: IDENTITY_VERSION,
        normalization_version: NORMALIZATION_VERSION,
        scope_id: "example-tenant".into(),
        runs: vec![CollectionRun {
            id: run.into(),
            source_id: PUBLISHER.into(),
            scope_id: "example-tenant".into(),
            collected_at_unix_secs: NOW - 10,
            completeness: if current {
                CollectionCompleteness::Partial
            } else {
                CollectionCompleteness::Complete
            },
        }],
        evidence: vec![EvidenceRecord {
            id: ev.into(),
            source_id: PUBLISHER.into(),
            run_id: run.into(),
            basis: EvidenceBasis::Direct,
            confidence_bps: 9000,
            observed_at_unix_secs: NOW - 10,
        }],
        observations: vec![CryptoObservation {
            id: "use-1".into(),
            asset_id: "app-1".into(),
            algorithm_id: if current { "ML-KEM-1024" } else { "RSA-2048" }.into(),
            kind: if current {
                CryptoUseKind::ConfiguredProtocol
            } else {
                CryptoUseKind::ActiveUse
            },
            conflict: ConflictState::Uncontested,
            evidence_ids: vec![ev.into()],
        }],
        absences: vec![],
    };
    let limit = Limits::default();
    let serialized = ValidatedInventorySnapshot::new(snapshot, &limit)?.export(&limit)?;
    let nodes = vec![GraphNode {
        id: "app-1".into(),
        kind: GraphNodeKind::System,
        evidence_ids: vec![ev.into()],
        observation_id: None,
        observation_kind: None,
    }];
    let input = NeutralInventoryInput {
        schema_version: NEUTRAL_INVENTORY_VERSION,
        producer_id: PUBLISHER,
        producer_revision: if current { "r2" } else { "r1" },
        scope_id: "example-tenant",
        inventory: VersionedEnvelope {
            schema: SchemaKind::InventorySnapshot,
            version: SchemaVersion::V1_0,
            payload: &serialized.bytes,
            source_id: PUBLISHER,
            critical_profiles: &[],
        },
        nodes: &nodes,
        edges: &[],
    };
    // In this synthetic fixture the manifest is generated locally. A real
    // consumer must obtain these expected digests from a trusted channel.
    let self_reported = NeutralInventoryAdapter::project(&input, serialized.digest, &limit, NOW)?;
    NeutralInventoryAdapter::import_pinned(&input, self_reported.pins(), &limit, NOW)
}

fn target() -> Result<TargetProfile, Diagnostic> {
    TargetProfile::new(
        TargetProfileDraft {
            schema_version: TARGET_PROFILE_VERSION,
            profile_id: "pq-profile".into(),
            revision: 1,
            scope_id: "example-tenant".into(),
            provenance: ProfileProvenance {
                issuer_id: "governance-source".into(),
                document_id: "profile-1".into(),
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
            protocols: vec![],
            certificates: vec![],
            cnsa20: None,
            deadline: None,
            expires_at_unix_secs: Some(NOW + 100),
        },
        &Limits::default(),
        Some(NOW),
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let old = inventory(false)?;
    let new = inventory(true)?;
    let delta = NeutralChangeSet::new(
        &old,
        &new,
        NeutralChangeSetInput {
            schema_version: NEUTRAL_CHANGE_VERSION,
            scope_id: "example-tenant".into(),
            producer_id: PUBLISHER.into(),
            producer_revision: "r2".into(),
            expected_before: old.pins().handoff_digest,
            expected_after: new.pins().handoff_digest,
            changes: vec![NeutralChangeClaim {
                asset_id: "app-1".into(),
                kind: NeutralChangeKind::ObservationModified,
                observation_id: Some("use-1".into()),
                run_id: "run-2".into(),
                evidence_ids: vec!["evidence-2".into()],
            }],
        },
        &Limits::default(),
    )?;
    let t = target()?;
    let from_policy = NeutralPolicyInput {
        schema_version: NEUTRAL_POLICY_VERSION,
        source_id: "synthetic-policy".into(),
        policy_id: "org:policy".into(),
        policy_revision: "1.0.0".into(),
        policy_digest: SnapshotDigest::from_bytes([4; 32]),
        target_digest: t.digest(),
        scope_id: "example-tenant".into(),
        evaluated_at_unix_secs: NOW,
        expires_at_unix_secs: NOW + 50,
        decisions: vec![NeutralPolicyDecision {
            algorithm: KnownAlgorithm::MlKem1024,
            outcome: NeutralPolicyOutcome::PermitClaimed,
            reason_code: "source-rule-match".into(),
            evidence: vec![NeutralPolicyEvidence {
                source_id: "synthetic-policy".into(),
                evidence_id: "source-observation".into(),
                source_revision: "r1".into(),
            }],
        }],
    };
    let self_reported = NeutralPolicyReview::new(from_policy.clone(), &t, &Limits::default())?;
    let review = NeutralPolicyReview::import_pinned(
        from_policy,
        &t,
        self_reported.policy_digest(),
        self_reported.digest(),
        &Limits::default(),
    )?;
    assert_eq!(
        review.gate_for(&t, "ML-KEM-1024")?,
        NeutralPolicyGate::Unverified,
    );
    assert_eq!(
        new.inventory().snapshot().observations[0].kind,
        CryptoUseKind::ConfiguredProtocol,
    );
    println!(
        "neutral inventory: {}",
        new.inventory().snapshot().observations.len()
    );
    println!("neutral delta claims: {}", delta.changes().len());
    println!(
        "neutral policy gate: {:?}",
        review.gate_for(&t, "ML-KEM-1024")?
    );
    let limit = Limits::default();
    // Independent, detached Cargo consumer of the full all-or-nothing
    // orchestration API. Fixture pins below are self-generated and therefore
    // *not* independent publisher authentication.
    let checked = AnalysisRunner::analyze(
        &AnalysisRequest {
            inventory: new.inventory(),
            graph: new.graph(),
            target: &t,
            expected_inventory_digest: new.pins().inventory_digest,
            expected_graph_digest: new.pins().graph_digest,
            expected_target_digest: t.digest(),
            compatibilities: &[],
            capability_catalogs: &[],
            quantum: &[],
            context: &[],
            scoring: None,
            evaluated_at_unix_secs: NOW,
            capacity_systems_per_wave: 1,
            max_waves: 1,
            submitted_for_review_units: &[],
            exceptions: &[],
            include_metrics: true,
        },
        &limit,
    );
    assert_ne!(checked.outcome(), AnalysisOutcome::Failed);
    assert!(checked.plan().is_some());
    assert!(checked.metrics().is_some());
    assert!(checked.failure().is_none());
    let expected = checked.plan().unwrap().digest();

    let repeated = AnalysisRunner::analyze(
        &AnalysisRequest {
            inventory: new.inventory(),
            graph: new.graph(),
            target: &t,
            expected_inventory_digest: new.pins().inventory_digest,
            expected_graph_digest: new.pins().graph_digest,
            expected_target_digest: t.digest(),
            compatibilities: &[],
            capability_catalogs: &[],
            quantum: &[],
            context: &[],
            scoring: None,
            evaluated_at_unix_secs: NOW,
            capacity_systems_per_wave: 1,
            max_waves: 1,
            submitted_for_review_units: &[],
            exceptions: &[],
            include_metrics: false,
        },
        &limit,
    );
    assert_eq!(repeated.plan().unwrap().digest(), expected);
    assert!(repeated.metrics().is_none());

    // A forged graph pin must fail atomically with no plan or metrics.
    let denied = AnalysisRunner::analyze(
        &AnalysisRequest {
            inventory: new.inventory(),
            graph: new.graph(),
            target: &t,
            expected_inventory_digest: new.pins().inventory_digest,
            expected_graph_digest: SnapshotDigest::from_bytes([0; 32]),
            expected_target_digest: t.digest(),
            compatibilities: &[],
            capability_catalogs: &[],
            quantum: &[],
            context: &[],
            scoring: None,
            evaluated_at_unix_secs: NOW,
            capacity_systems_per_wave: 1,
            max_waves: 1,
            submitted_for_review_units: &[],
            exceptions: &[],
            include_metrics: true,
        },
        &limit,
    );
    assert_eq!(denied.outcome(), AnalysisOutcome::Failed);
    assert!(denied.plan().is_none());
    assert!(denied.metrics().is_none());
    assert_eq!(denied.failure().unwrap().code, DiagnosticCode::IntegrityMismatch);
    assert_eq!(denied.findings()[0].phase, AnalysisPhase::Admission);
    println!("atomic analysis: {:?} (unverified, not authorized)", checked.outcome());
    println!(
        "No authentication, negotiated peer proof, migration approval, or publishing occurred."
    );
    Ok(())
}
