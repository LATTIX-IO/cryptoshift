//! External-public-API acceptance for independently versioned neutral fixtures.

use cryptoshift::*;

const NOW: i64 = 1_800_000_000;
const PRODUCER: &str = "synthetic-collector";

fn snapshot(new: bool, complete: bool) -> InventorySnapshot {
    let run = if new { "scan-new" } else { "scan-old" };
    let evidence = if new { "ev-new" } else { "ev-old" };
    let scope = "tenant-a";
    let mut observations = vec![CryptoObservation {
        id: "obs-proto".into(),
        asset_id: "srv".into(),
        algorithm_id: "RSA-2048".into(),
        kind: CryptoUseKind::ConfiguredProtocol,
        conflict: if new {
            ConflictState::Conflicted
        } else {
            ConflictState::Uncontested
        },
        evidence_ids: vec![evidence.into()],
    }];
    if !new {
        observations.push(CryptoObservation {
            id: "obs-legacy".into(),
            asset_id: "legacy".into(),
            algorithm_id: "RSA-2048".into(),
            kind: CryptoUseKind::ActiveUse,
            conflict: ConflictState::Uncontested,
            evidence_ids: vec![evidence.into()],
        });
    } else {
        observations.push(CryptoObservation {
            id: "obs-negotiated".into(),
            asset_id: "srv".into(),
            algorithm_id: "ML-KEM-1024".into(),
            kind: CryptoUseKind::NegotiatedProtocol,
            conflict: ConflictState::Uncontested,
            evidence_ids: vec![evidence.into()],
        });
    }
    InventorySnapshot {
        identity_version: IDENTITY_VERSION,
        normalization_version: NORMALIZATION_VERSION,
        scope_id: scope.into(),
        runs: vec![CollectionRun {
            id: run.into(),
            source_id: PRODUCER.into(),
            scope_id: scope.into(),
            collected_at_unix_secs: if new { NOW - 10 } else { NOW - 100 },
            completeness: if new {
                if complete {
                    CollectionCompleteness::Complete
                } else {
                    CollectionCompleteness::Partial
                }
            } else {
                CollectionCompleteness::Complete
            },
        }],
        evidence: vec![EvidenceRecord {
            id: evidence.into(),
            run_id: run.into(),
            source_id: PRODUCER.into(),
            basis: EvidenceBasis::Direct,
            confidence_bps: 9500,
            observed_at_unix_secs: if new { NOW - 10 } else { NOW - 100 },
        }],
        observations,
        absences: if new {
            vec![AbsenceRecord {
                run_id: run.into(),
                asset_id: "legacy".into(),
                status: if complete {
                    AbsenceStatus::Confirmed
                } else {
                    AbsenceStatus::Tentative
                },
            }]
        } else {
            vec![]
        },
    }
}

fn nodes(evidence: &str) -> (Vec<GraphNode>, Vec<GraphEdge>) {
    (
        vec![
            GraphNode {
                id: "srv".into(),
                kind: GraphNodeKind::System,
                evidence_ids: vec![evidence.into()],
                observation_id: None,
                observation_kind: None,
            },
            GraphNode {
                id: "owner".into(),
                kind: GraphNodeKind::Owner,
                evidence_ids: vec![evidence.into()],
                observation_id: None,
                observation_kind: None,
            },
        ],
        vec![GraphEdge {
            from: "srv".into(),
            to: "owner".into(),
            relation: GraphRelation::OwnedBy,
            evidence_ids: vec![evidence.into()],
        }],
    )
}

fn project(new: bool, complete: bool) -> NeutralInventoryProjection {
    let raw = ValidatedInventorySnapshot::new(snapshot(new, complete), &Limits::default())
        .unwrap()
        .export(&Limits::default())
        .unwrap();
    let rev = if new { "r2" } else { "r1" };
    let (nodes, edges) = nodes(if new { "ev-new" } else { "ev-old" });
    let input = NeutralInventoryInput {
        schema_version: NEUTRAL_INVENTORY_VERSION,
        producer_id: PRODUCER,
        producer_revision: rev,
        scope_id: "tenant-a",
        inventory: VersionedEnvelope {
            schema: SchemaKind::InventorySnapshot,
            version: SchemaVersion::V1_0,
            payload: &raw.bytes,
            source_id: PRODUCER,
            critical_profiles: &[],
        },
        nodes: &nodes,
        edges: &edges,
    };
    let observed =
        NeutralInventoryAdapter::project(&input, raw.digest, &Limits::default(), NOW).unwrap();
    let checked =
        NeutralInventoryAdapter::import_pinned(&input, observed.pins(), &Limits::default(), NOW)
            .unwrap();
    assert_eq!(checked.pins(), observed.pins());
    assert_eq!(
        checked.export(&Limits::default()).unwrap(),
        observed.export(&Limits::default()).unwrap()
    );
    checked
}

fn claim(kind: NeutralChangeKind, id: Option<&str>, asset: &str) -> NeutralChangeClaim {
    NeutralChangeClaim {
        kind,
        asset_id: asset.into(),
        observation_id: id.map(str::to_owned),
        run_id: "scan-new".into(),
        evidence_ids: vec!["ev-new".into()],
    }
}

fn input(
    before: &NeutralInventoryProjection,
    after: &NeutralInventoryProjection,
    changes: Vec<NeutralChangeClaim>,
) -> NeutralChangeSetInput {
    NeutralChangeSetInput {
        schema_version: NEUTRAL_CHANGE_VERSION,
        scope_id: "tenant-a".into(),
        producer_id: PRODUCER.into(),
        producer_revision: "r2".into(),
        expected_before: before.pins().handoff_digest,
        expected_after: after.pins().handoff_digest,
        changes,
    }
}

#[test]
fn cryptoshift_v1_inventory_bytes_roundtrip_with_independent_pin() {
    let one = project(false, true);
    assert_eq!(one.producer_id(), PRODUCER);
    assert_eq!(one.inventory().snapshot().observations.len(), 2);
    assert_eq!(one.graph().nodes().len(), 2);
    assert!(
        one.export(&Limits::default())
            .unwrap()
            .starts_with(b"CSHIFT_NEUTRAL_INV_V1")
    );
    assert_eq!(
        one.inventory().snapshot().observations[1].kind,
        CryptoUseKind::ConfiguredProtocol
    );
    let two = project(false, true);
    assert_eq!(one.pins(), two.pins());
}

#[test]
fn configured_protocol_and_new_negotiation_are_distinct_observations() {
    let after = project(true, false);
    let snapshot = after.inventory().snapshot();
    assert_eq!(
        snapshot.observations[0].kind,
        CryptoUseKind::NegotiatedProtocol
    );
    assert_eq!(
        snapshot.observations[1].kind,
        CryptoUseKind::ConfiguredProtocol
    );
    assert_eq!(snapshot.absences[0].status, AbsenceStatus::Tentative);
    assert_eq!(
        snapshot.runs[0].completeness,
        CollectionCompleteness::Partial
    );
}

#[test]
fn unknown_or_wrong_source_versions_and_graph_are_rejected() {
    let raw = ValidatedInventorySnapshot::new(snapshot(false, true), &Limits::default())
        .unwrap()
        .export(&Limits::default())
        .unwrap();
    let (nodes, edges) = nodes("ev-old");
    let base = NeutralInventoryInput {
        schema_version: NEUTRAL_INVENTORY_VERSION,
        producer_id: PRODUCER,
        producer_revision: "r1",
        scope_id: "tenant-a",
        inventory: VersionedEnvelope {
            schema: SchemaKind::InventorySnapshot,
            version: SchemaVersion::V1_0,
            payload: &raw.bytes,
            source_id: PRODUCER,
            critical_profiles: &[],
        },
        nodes: &nodes,
        edges: &edges,
    };
    let good =
        NeutralInventoryAdapter::project(&base, raw.digest, &Limits::default(), NOW).unwrap();
    let mut bad = base.clone();
    bad.schema_version = 7;
    assert_eq!(
        NeutralInventoryAdapter::project(&bad, raw.digest, &Limits::default(), NOW)
            .unwrap_err()
            .code,
        DiagnosticCode::UnsupportedSchemaVersion
    );
    bad = base.clone();
    bad.scope_id = "tenant-b";
    assert_eq!(
        NeutralInventoryAdapter::project(&bad, raw.digest, &Limits::default(), NOW)
            .unwrap_err()
            .code,
        DiagnosticCode::UnsupportedIdentityVersion
    );
    bad = base.clone();
    bad.inventory.source_id = "different-publisher";
    assert_eq!(
        NeutralInventoryAdapter::project(&bad, raw.digest, &Limits::default(), NOW)
            .unwrap_err()
            .code,
        DiagnosticCode::InvalidReference
    );
    let mut trusted = good.pins();
    trusted.graph_digest = SnapshotDigest::from_bytes([9; 32]);
    assert_eq!(
        NeutralInventoryAdapter::import_pinned(&base, trusted, &Limits::default(), NOW)
            .unwrap_err()
            .code,
        DiagnosticCode::IntegrityMismatch
    );
    trusted = good.pins();
    trusted.handoff_digest = SnapshotDigest::from_bytes([8; 32]);
    assert_eq!(
        NeutralInventoryAdapter::import_pinned(&base, trusted, &Limits::default(), NOW)
            .unwrap_err()
            .code,
        DiagnosticCode::IntegrityMismatch
    );
    bad = base.clone();
    bad.inventory.version = SchemaVersion { major: 2, minor: 0 };
    assert!(NeutralInventoryAdapter::project(&bad, raw.digest, &Limits::default(), NOW).is_err());
}

#[test]
fn future_or_unreferenced_graph_evidence_is_not_accepted() {
    let raw = ValidatedInventorySnapshot::new(snapshot(false, true), &Limits::default())
        .unwrap()
        .export(&Limits::default())
        .unwrap();
    let (mut nodes, edges) = nodes("ev-old");
    nodes[1].evidence_ids = vec!["unknown".into()];
    let doc = NeutralInventoryInput {
        schema_version: 1,
        producer_id: PRODUCER,
        producer_revision: "r1",
        scope_id: "tenant-a",
        inventory: VersionedEnvelope {
            schema: SchemaKind::InventorySnapshot,
            version: SchemaVersion::V1_0,
            payload: &raw.bytes,
            source_id: PRODUCER,
            critical_profiles: &[],
        },
        nodes: &nodes,
        edges: &edges,
    };
    assert_eq!(
        NeutralInventoryAdapter::project(&doc, raw.digest, &Limits::default(), NOW)
            .unwrap_err()
            .code,
        DiagnosticCode::InvalidReference
    );
    let (nodes, edges) = nodes("ev-old");
    let doc = NeutralInventoryInput {
        nodes: &nodes,
        edges: &edges,
        ..doc
    };
    assert_eq!(
        NeutralInventoryAdapter::project(&doc, raw.digest, &Limits::default(), NOW - 200)
            .unwrap_err()
            .code,
        DiagnosticCode::InvalidStateTransition
    );
}

#[test]
fn partial_run_never_claims_confirmed_removal() {
    let mut invalid = snapshot(true, false);
    invalid.absences[0].status = AbsenceStatus::Confirmed;
    assert_eq!(
        ValidatedInventorySnapshot::new(invalid, &Limits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::InvalidStateTransition
    );
}

#[test]
fn tentative_changes_and_added_negotiation_have_exact_evidence() {
    let before = project(false, true);
    let after = project(true, false);
    let changes = vec![
        claim(NeutralChangeKind::TentativeAbsent, None, "legacy"),
        claim(
            NeutralChangeKind::ObservationAdded,
            Some("obs-negotiated"),
            "srv",
        ),
        claim(
            NeutralChangeKind::ObservationModified,
            Some("obs-proto"),
            "srv",
        ),
        claim(
            NeutralChangeKind::ObservationConflicted,
            Some("obs-proto"),
            "srv",
        ),
    ];
    let one = NeutralChangeSet::new(
        &before,
        &after,
        input(&before, &after, changes.clone()),
        &Limits::default(),
    )
    .unwrap();
    let mut reversed = changes;
    reversed.reverse();
    let two = NeutralChangeSet::new(
        &before,
        &after,
        input(&before, &after, reversed),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(one.digest(), two.digest());
    assert_eq!(one.changes().len(), 4);
    assert_eq!(
        one.export(&Limits::default()).unwrap(),
        two.export(&Limits::default()).unwrap()
    );
    assert_eq!(one.before_digest(), before.pins().handoff_digest);
    assert_eq!(one.after_digest(), after.pins().handoff_digest);
}

#[test]
fn complete_rescan_claims_absence_only_if_previously_observed() {
    let before = project(false, true);
    let after = project(true, true);
    let correct = claim(NeutralChangeKind::ConfirmedAbsent, None, "legacy");
    assert!(
        NeutralChangeSet::new(
            &before,
            &after,
            input(&before, &after, vec![correct]),
            &Limits::default()
        )
        .is_ok()
    );
    let partial = project(true, false);
    let false_claim = claim(NeutralChangeKind::ConfirmedAbsent, None, "legacy");
    assert_eq!(
        NeutralChangeSet::new(
            &before,
            &partial,
            input(&before, &partial, vec![false_claim]),
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::InvalidStateTransition
    );
    let false_asset = claim(NeutralChangeKind::ConfirmedAbsent, None, "never-known");
    assert_eq!(
        NeutralChangeSet::new(
            &before,
            &after,
            input(&before, &after, vec![false_asset]),
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::InvalidStateTransition
    );
}

#[test]
fn duplicate_and_replayed_or_wrong_revision_changes_fail_closed() {
    let before = project(false, true);
    let after = project(true, false);
    let change = claim(NeutralChangeKind::TentativeAbsent, None, "legacy");
    let mut duplicate = input(&before, &after, vec![change.clone(), change]);
    assert_eq!(
        NeutralChangeSet::new(&before, &after, duplicate.clone(), &Limits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::DuplicateRecord
    );
    duplicate.changes.truncate(1);
    duplicate.expected_before = after.pins().handoff_digest;
    assert_eq!(
        NeutralChangeSet::new(&before, &after, duplicate.clone(), &Limits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::IntegrityMismatch
    );
    duplicate.expected_before = before.pins().handoff_digest;
    duplicate.producer_revision = "r0".into();
    assert_eq!(
        NeutralChangeSet::new(&before, &after, duplicate, &Limits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::InvalidReference
    );
}

#[test]
fn wrong_evidence_run_and_transition_type_are_rejected() {
    let before = project(false, true);
    let after = project(true, false);
    let mut c = claim(
        NeutralChangeKind::ObservationAdded,
        Some("obs-negotiated"),
        "srv",
    );
    c.evidence_ids = vec!["ev-old".into()];
    assert_eq!(
        NeutralChangeSet::new(
            &before,
            &after,
            input(&before, &after, vec![c]),
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::InvalidReference
    );
    let c = claim(
        NeutralChangeKind::ObservationAdded,
        Some("obs-proto"),
        "srv",
    );
    assert_eq!(
        NeutralChangeSet::new(
            &before,
            &after,
            input(&before, &after, vec![c]),
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::InvalidStateTransition
    );
}

#[test]
fn tight_limits_reject_existing_snapshot_graph_and_delta() {
    let raw = ValidatedInventorySnapshot::new(snapshot(false, true), &Limits::default())
        .unwrap()
        .export(&Limits::default())
        .unwrap();
    let (nodes, edges) = nodes("ev-old");
    let doc = NeutralInventoryInput {
        schema_version: 1,
        producer_id: PRODUCER,
        producer_revision: "r1",
        scope_id: "tenant-a",
        inventory: VersionedEnvelope {
            schema: SchemaKind::InventorySnapshot,
            version: SchemaVersion::V1_0,
            payload: &raw.bytes,
            source_id: PRODUCER,
            critical_profiles: &[],
        },
        nodes: &nodes,
        edges: &edges,
    };
    let tight = Limits {
        max_graph_nodes: 1,
        ..Limits::default()
    };
    assert_eq!(
        NeutralInventoryAdapter::project(&doc, raw.digest, &tight, NOW)
            .unwrap_err()
            .code,
        DiagnosticCode::ResourceLimitExceeded
    );
    let tight = Limits {
        max_input_bytes: raw.bytes.len() - 1,
        ..Limits::default()
    };
    assert_eq!(
        NeutralInventoryAdapter::project(&doc, raw.digest, &tight, NOW)
            .unwrap_err()
            .code,
        DiagnosticCode::ResourceLimitExceeded
    );
    let before = project(false, true);
    let after = project(true, false);
    let tight = Limits {
        max_evidence_records: 1,
        ..Limits::default()
    };
    assert_eq!(
        NeutralChangeSet::new(
            &before,
            &after,
            input(
                &before,
                &after,
                vec![
                    claim(
                        NeutralChangeKind::ObservationAdded,
                        Some("obs-negotiated"),
                        "srv"
                    ),
                    claim(NeutralChangeKind::TentativeAbsent, None, "legacy"),
                ]
            ),
            &tight
        )
        .unwrap_err()
        .code,
        DiagnosticCode::ResourceLimitExceeded
    );
}
