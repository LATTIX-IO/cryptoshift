//! Public-consumer contract tests using only exported Cryptoshift types.

use sha2::{Digest, Sha256};

use cryptoshift::{
    AbsenceRecord, AbsenceStatus, CollectionCompleteness, CollectionRun, ConflictState,
    CryptoObservation, CryptoUseKind, DiagnosticCode, EvidenceBasis, EvidenceRecord,
    IDENTITY_VERSION, InventorySnapshot, Limits, NORMALIZATION_VERSION, ResourceKind, SchemaKind,
    SchemaVersion, SnapshotDigest, ValidatedInventorySnapshot, VersionedEnvelope,
};

fn fixture() -> InventorySnapshot {
    InventorySnapshot {
        identity_version: IDENTITY_VERSION,
        normalization_version: NORMALIZATION_VERSION,
        scope_id: "tenant-a".into(),
        runs: vec![
            CollectionRun {
                id: "scan-2".into(),
                source_id: "scanner-b".into(),
                scope_id: "tenant-a".into(),
                collected_at_unix_secs: 210,
                completeness: CollectionCompleteness::Partial,
            },
            CollectionRun {
                id: "scan-1".into(),
                source_id: "scanner-a".into(),
                scope_id: "tenant-a".into(),
                collected_at_unix_secs: 200,
                completeness: CollectionCompleteness::Complete,
            },
        ],
        evidence: vec![
            EvidenceRecord {
                id: "ev-2".into(),
                run_id: "scan-2".into(),
                source_id: "scanner-b".into(),
                basis: EvidenceBasis::Inferred,
                confidence_bps: 5000,
                observed_at_unix_secs: 210,
            },
            EvidenceRecord {
                id: "ev-1".into(),
                run_id: "scan-1".into(),
                source_id: "scanner-a".into(),
                basis: EvidenceBasis::Direct,
                confidence_bps: 9500,
                observed_at_unix_secs: 200,
            },
        ],
        observations: vec![
            CryptoObservation {
                id: "cap".into(),
                asset_id: "svc-1".into(),
                algorithm_id: "ML-KEM-1024".into(),
                kind: CryptoUseKind::LibraryCapability,
                conflict: ConflictState::Uncontested,
                evidence_ids: vec!["ev-1".into()],
            },
            CryptoObservation {
                id: "use".into(),
                asset_id: "svc-1".into(),
                algorithm_id: "RSA-2048".into(),
                kind: CryptoUseKind::ConfiguredProtocol,
                conflict: ConflictState::Conflicted,
                evidence_ids: vec!["ev-2".into(), "ev-1".into()],
            },
        ],
        absences: vec![AbsenceRecord {
            run_id: "scan-2".into(),
            asset_id: "previous-asset".into(),
            status: AbsenceStatus::Tentative,
        }],
    }
}
#[test]
fn deterministic_sorting_digest_and_immutable_roundtrip() -> Result<(), cryptoshift::Diagnostic> {
    let limits = Limits::default();
    let a = ValidatedInventorySnapshot::new(fixture(), &limits)?;
    let artifact = a.export(&limits)?;
    let mut reversed = fixture();
    reversed.observations.reverse();
    reversed.evidence.reverse();
    reversed.runs.reverse();
    reversed.observations[1].evidence_ids.reverse();
    let b = ValidatedInventorySnapshot::new(reversed, &limits)?;
    assert_eq!(artifact, b.export(&limits)?);
    assert!(artifact.digest.as_identifier().starts_with("sha256:"));
    assert_eq!(artifact.digest.as_identifier().len(), 71);
    let envelope = VersionedEnvelope {
        schema: SchemaKind::InventorySnapshot,
        version: SchemaVersion::V1_0,
        payload: &artifact.bytes,
        source_id: "external-fixture",
        critical_profiles: &[],
    };
    let checked =
        ValidatedInventorySnapshot::import_verified(&envelope, artifact.digest, &limits, 220)?;
    assert_eq!(checked.snapshot(), a.snapshot());
    assert_eq!(checked.export(&limits)?, artifact);
    Ok(())
}

#[test]
fn hash_mismatch_and_envelope_schema_fail_closed() -> Result<(), cryptoshift::Diagnostic> {
    let limits = Limits::default();
    let artifact = ValidatedInventorySnapshot::new(fixture(), &limits)?.export(&limits)?;
    let mut tampered = artifact.bytes.clone();
    tampered[20] ^= 1;
    let document = VersionedEnvelope {
        schema: SchemaKind::InventorySnapshot,
        version: SchemaVersion::V1_0,
        payload: &tampered,
        source_id: "fixture",
        critical_profiles: &[],
    };
    let result =
        ValidatedInventorySnapshot::import_verified(&document, artifact.digest, &limits, 1);
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::IntegrityMismatch)
    );
    let wrong_schema = VersionedEnvelope {
        schema: SchemaKind::TargetProfile,
        payload: &artifact.bytes,
        ..document
    };
    let result =
        ValidatedInventorySnapshot::import_verified(&wrong_schema, artifact.digest, &limits, 1);
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::UnsupportedSchemaVersion)
    );
    Ok(())
}

#[test]
fn partial_scope_and_invalid_evidence_cannot_be_silently_accepted() {
    let mut input = fixture();
    input.absences[0].status = AbsenceStatus::Confirmed;
    let result = ValidatedInventorySnapshot::new(input, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    let mut input = fixture();
    input.runs[0].scope_id = "other-tenant".into();
    let result = ValidatedInventorySnapshot::new(input, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::InvalidReference)
    );
    let mut input = fixture();
    input.observations[0].evidence_ids = vec!["nonexistent".into()];
    let result = ValidatedInventorySnapshot::new(input, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::InvalidReference)
    );
}

#[test]
fn duplicates_unsupported_identity_and_bounded_output_fail_closed() {
    let mut input = fixture();
    input.evidence[1].id = input.evidence[0].id.clone();
    let result = ValidatedInventorySnapshot::new(input, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::DuplicateRecord)
    );
    let mut input = fixture();
    input.normalization_version = 99;
    let result = ValidatedInventorySnapshot::new(input, &Limits::default());
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::UnsupportedIdentityVersion)
    );
    let limit = Limits {
        max_graph_nodes: 1,
        ..Limits::default()
    };
    let result = ValidatedInventorySnapshot::new(fixture(), &limit);
    assert_eq!(
        result.err().map(|e| e.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    assert_eq!(ResourceKind::GraphNodes.as_str(), "graph_nodes");
}

#[test]
fn independent_evidence_and_configured_vs_capability_are_preserved()
-> Result<(), cryptoshift::Diagnostic> {
    let checked = ValidatedInventorySnapshot::new(fixture(), &Limits::default())?;
    let snapshot = checked.snapshot();
    assert_eq!(snapshot.evidence.len(), 2);
    assert_eq!(snapshot.observations.len(), 2);
    assert_eq!(
        snapshot.observations[0].kind,
        CryptoUseKind::LibraryCapability
    );
    assert_eq!(
        snapshot.observations[1].kind,
        CryptoUseKind::ConfiguredProtocol
    );
    assert_eq!(snapshot.observations[1].conflict, ConflictState::Conflicted);
    assert_eq!(snapshot.observations[1].evidence_ids, vec!["ev-1", "ev-2"]);
    assert_eq!(snapshot.absences[0].status, AbsenceStatus::Tentative);
    Ok(())
}

fn recompute_digest(bytes: &[u8]) -> SnapshotDigest {
    let hash = Sha256::digest(bytes);
    let mut value = [0_u8; 32];
    value.copy_from_slice(&hash);
    SnapshotDigest::from_bytes(value)
}

#[test]
fn malformed_payload_is_rejected_even_with_matching_digest() -> Result<(), cryptoshift::Diagnostic>
{
    let limits = Limits::default();
    let artifact = ValidatedInventorySnapshot::new(fixture(), &limits)?.export(&limits)?;
    let mut bad_magic = artifact.bytes.clone();
    bad_magic[0] ^= 0x40;
    let mut unknown_status = artifact.bytes.clone();
    if let Some(last) = unknown_status.last_mut() {
        *last = 250;
    }
    let mut invalid_utf8 = artifact.bytes.clone();
    invalid_utf8[18] = 255;
    let mut truncated = artifact.bytes.clone();
    truncated.pop();
    let mut trailing = artifact.bytes.clone();
    trailing.push(99);
    for bytes in [bad_magic, unknown_status, invalid_utf8, truncated, trailing] {
        let envelope = VersionedEnvelope {
            schema: SchemaKind::InventorySnapshot,
            version: SchemaVersion::V1_0,
            payload: &bytes,
            source_id: "synthetic",
            critical_profiles: &[],
        };
        let result = ValidatedInventorySnapshot::import_verified(
            &envelope,
            recompute_digest(&bytes),
            &limits,
            250,
        );
        assert_eq!(
            result.err().map(|e| e.code),
            Some(DiagnosticCode::MalformedStructure)
        );
    }
    let mut wrong_wire_version = artifact.bytes.clone();
    wrong_wire_version[9] = 2;
    let envelope = VersionedEnvelope {
        schema: SchemaKind::InventorySnapshot,
        version: SchemaVersion::V1_0,
        payload: &wrong_wire_version,
        source_id: "synthetic",
        critical_profiles: &[],
    };
    assert_eq!(
        ValidatedInventorySnapshot::import_verified(
            &envelope,
            recompute_digest(&wrong_wire_version),
            &limits,
            250
        )
        .err()
        .map(|e| e.code),
        Some(DiagnosticCode::UnsupportedSchemaVersion)
    );
    Ok(())
}
