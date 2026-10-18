//! Independent neutral-policy fixture conformance: no Permit -> authorization.

#![allow(clippy::unwrap_used, clippy::expect_used)] // Bounded synthetic fixture assertions.
use cryptoshift::*;

const AT: i64 = 1_800_000_000;

fn target() -> TargetProfile {
    TargetProfile::new(
        TargetProfileDraft {
            schema_version: TARGET_PROFILE_VERSION,
            profile_id: "tenant-pq-policy".into(),
            revision: 1,
            scope_id: "tenant-a".into(),
            provenance: ProfileProvenance {
                issuer_id: "policy-office".into(),
                document_id: "policy-document".into(),
                revision: "r1".into(),
                source_digest: None,
            },
            standards: vec![StandardEdition::Fips203_2024],
            algorithms: vec![
                AlgorithmConstraint {
                    algorithm: KnownAlgorithm::MlKem1024,
                    role: AlgorithmRole::KeyEncapsulation,
                    minimum_category: Some(SecurityCategory::Five),
                    disposition: ConstraintDisposition::Required,
                },
                AlgorithmConstraint {
                    algorithm: KnownAlgorithm::MlKem768,
                    role: AlgorithmRole::KeyEncapsulation,
                    minimum_category: None,
                    disposition: ConstraintDisposition::Forbidden,
                },
            ],
            protocols: vec![],
            certificates: vec![],
            cnsa20: None,
            deadline: None,
            expires_at_unix_secs: Some(AT + 100),
        },
        &Limits::default(),
        Some(AT),
    )
    .unwrap()
}

fn evidence(name: &str) -> NeutralPolicyEvidence {
    NeutralPolicyEvidence {
        source_id: "synthetic-policy-adapter".into(),
        evidence_id: name.into(),
        source_revision: "source-r1".into(),
    }
}

fn result(target: &TargetProfile) -> NeutralPolicyInput {
    NeutralPolicyInput {
        schema_version: NEUTRAL_POLICY_VERSION,
        source_id: "synthetic-policy-adapter".into(),
        policy_id: "policy-fixture".into(),
        policy_revision: "1.0.0".into(),
        policy_digest: SnapshotDigest::from_bytes([7; 32]),
        target_digest: target.digest(),
        scope_id: "tenant-a".into(),
        evaluated_at_unix_secs: AT,
        expires_at_unix_secs: AT + 60,
        decisions: vec![
            NeutralPolicyDecision {
                algorithm: KnownAlgorithm::MlKem1024,
                outcome: NeutralPolicyOutcome::PermitClaimed,
                reason_code: "rule-pass".into(),
                evidence: vec![evidence("scan-1")],
            },
            NeutralPolicyDecision {
                algorithm: KnownAlgorithm::MlKem768,
                outcome: NeutralPolicyOutcome::DenyClaimed,
                reason_code: "forbidden-algorithm".into(),
                evidence: vec![evidence("source-2")],
            },
        ],
    }
}

#[test]
fn source_permit_never_means_migration_ready() {
    let target = target();
    let review = NeutralPolicyReview::new(result(&target), &target, &Limits::default()).unwrap();
    assert_eq!(review.scope_id(), "tenant-a");
    assert_eq!(review.decisions().len(), 2);
    assert_eq!(
        review.gate_for(&target, "ML-KEM-1024").unwrap(),
        NeutralPolicyGate::Unverified
    );
    assert_eq!(
        review.gate_for(&target, "ML-KEM-768").unwrap(),
        NeutralPolicyGate::Prohibited
    );
    assert_eq!(
        review.gate_for(&target, "ML-KEM-512").unwrap(),
        NeutralPolicyGate::Unverified
    );
    assert!(
        review
            .export(&Limits::default())
            .unwrap()
            .starts_with(b"CSHIFT_NEUTRAL_POLICY_V1")
    );
}

#[test]
fn independently_pinned_policy_result_roundtrip() {
    let t = target();
    let first = NeutralPolicyReview::new(result(&t), &t, &Limits::default()).unwrap();
    let verified = NeutralPolicyReview::import_pinned(
        result(&t),
        &t,
        first.policy_digest(),
        first.digest(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(verified.digest(), first.digest());
    assert_eq!(
        verified.export(&Limits::default()).unwrap(),
        first.export(&Limits::default()).unwrap()
    );
    assert_eq!(first.target_digest(), t.digest());
}

#[test]
fn equivalent_reordered_input_and_evidence_are_canonical() {
    let t = target();
    let a = NeutralPolicyReview::new(result(&t), &t, &Limits::default()).unwrap();
    let mut shuffled = result(&t);
    shuffled.decisions.reverse();
    let b = NeutralPolicyReview::new(shuffled, &t, &Limits::default()).unwrap();
    assert_eq!(a.digest(), b.digest());
    assert_eq!(
        a.export(&Limits::default()).unwrap(),
        b.export(&Limits::default()).unwrap()
    );
}

#[test]
fn indeterminate_and_unattributed_unknown_never_become_permitted() {
    let t = target();
    let mut input = result(&t);
    input.decisions[0].outcome = NeutralPolicyOutcome::Indeterminate;
    input.decisions[0].evidence.clear();
    let reviewed = NeutralPolicyReview::new(input, &t, &Limits::default()).unwrap();
    assert_eq!(
        reviewed.gate_for(&t, "ML-KEM-1024").unwrap(),
        NeutralPolicyGate::Unverified
    );
    assert_eq!(
        reviewed.gate_for(&t, "ML-KEM-768").unwrap(),
        NeutralPolicyGate::Prohibited
    );
}

#[test]
fn source_permit_conflicting_with_forbidden_target_rejected() {
    let t = target();
    let mut input = result(&t);
    input.decisions[1].outcome = NeutralPolicyOutcome::PermitClaimed;
    let err = NeutralPolicyReview::new(input, &t, &Limits::default()).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::InvalidStateTransition);
}

#[test]
fn source_denial_is_conservative_even_when_target_requires_algorithm() {
    let t = target();
    let mut input = result(&t);
    input.decisions[0].outcome = NeutralPolicyOutcome::DenyClaimed;
    let reviewed = NeutralPolicyReview::new(input, &t, &Limits::default()).unwrap();
    assert_eq!(
        reviewed.gate_for(&t, "ML-KEM-1024").unwrap(),
        NeutralPolicyGate::Prohibited
    );
}

#[test]
fn wrong_scope_target_or_policy_digest_cannot_be_inherited() {
    let t = target();
    let mut input = result(&t);
    input.scope_id = "other-tenant".into();
    assert_eq!(
        NeutralPolicyReview::new(input, &t, &Limits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::InvalidReference
    );
    let mut input = result(&t);
    input.target_digest = SnapshotDigest::from_bytes([8; 32]);
    assert_eq!(
        NeutralPolicyReview::new(input, &t, &Limits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::IntegrityMismatch
    );
    let mut input = result(&t);
    input.policy_digest = SnapshotDigest::from_bytes([0; 32]);
    assert_eq!(
        NeutralPolicyReview::new(input, &t, &Limits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::MissingProvenance
    );
    let review = NeutralPolicyReview::new(result(&t), &t, &Limits::default()).unwrap();
    assert_eq!(
        NeutralPolicyReview::import_pinned(
            result(&t),
            &t,
            SnapshotDigest::from_bytes([9; 32]),
            review.digest(),
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::IntegrityMismatch
    );
    assert_eq!(
        NeutralPolicyReview::import_pinned(
            result(&t),
            &t,
            review.policy_digest(),
            SnapshotDigest::from_bytes([9; 32]),
            &Limits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::IntegrityMismatch
    );
}

#[test]
fn expiry_and_unknown_schema_fail_closed() {
    let t = target();
    let mut input = result(&t);
    input.schema_version = 2;
    assert_eq!(
        NeutralPolicyReview::new(input, &t, &Limits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::UnsupportedSchemaVersion
    );
    let mut input = result(&t);
    input.expires_at_unix_secs = AT;
    assert_eq!(
        NeutralPolicyReview::new(input, &t, &Limits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::StaleCriticalProfile
    );
    let mut input = result(&t);
    input.evaluated_at_unix_secs = AT + 120;
    input.expires_at_unix_secs = AT + 130;
    assert_eq!(
        NeutralPolicyReview::new(input, &t, &Limits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::StaleCriticalProfile
    );
}

#[test]
fn unsupported_normalized_algorithm_is_not_aliased() {
    let t = target();
    let review = NeutralPolicyReview::new(result(&t), &t, &Limits::default()).unwrap();
    assert_eq!(
        review.gate_for(&t, "kyber1024").unwrap_err().code,
        DiagnosticCode::InvalidReference
    );
}

#[test]
fn duplicate_records_or_missing_source_evidence_rejected() {
    let t = target();
    let mut input = result(&t);
    input.decisions.push(input.decisions[0].clone());
    assert_eq!(
        NeutralPolicyReview::new(input, &t, &Limits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::DuplicateRecord
    );
    let mut input = result(&t);
    input.decisions[0].evidence.clear();
    assert_eq!(
        NeutralPolicyReview::new(input, &t, &Limits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::MissingProvenance
    );
    let mut input = result(&t);
    let duplicate_evidence = input.decisions[0].evidence[0].clone();
    input.decisions[0].evidence.push(duplicate_evidence);
    assert_eq!(
        NeutralPolicyReview::new(input, &t, &Limits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::DuplicateRecord
    );
}

#[test]
fn changed_source_evidence_rotates_policy_review_digest() {
    let t = target();
    let first = NeutralPolicyReview::new(result(&t), &t, &Limits::default()).unwrap();
    let mut input = result(&t);
    input.decisions[0].evidence[0].source_revision = "source-r2".into();
    let second = NeutralPolicyReview::new(input, &t, &Limits::default()).unwrap();
    assert_ne!(first.digest(), second.digest());
    assert_ne!(
        first.export(&Limits::default()).unwrap(),
        second.export(&Limits::default()).unwrap()
    );
}

#[test]
fn bounded_source_references_and_outputs_fail_closed() {
    let t = target();
    let mut input = result(&t);
    input.decisions[0].evidence[0].evidence_id = "X".repeat(257);
    assert_eq!(
        NeutralPolicyReview::new(input, &t, &Limits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::InvalidIdentifier
    );
    let tight = Limits {
        max_profile_references: 1,
        ..Limits::default()
    };
    assert_eq!(
        NeutralPolicyReview::new(result(&t), &t, &tight)
            .unwrap_err()
            .code,
        DiagnosticCode::ResourceLimitExceeded
    );
    let report = NeutralPolicyReview::new(result(&t), &t, &Limits::default()).unwrap();
    let len = report.export(&Limits::default()).unwrap().len();
    let tight = Limits {
        max_export_bytes: len - 1,
        ..Limits::default()
    };
    assert_eq!(
        report.export(&tight).unwrap_err().code,
        DiagnosticCode::ResourceLimitExceeded
    );
    assert_eq!(
        NeutralPolicyReview::new(result(&t), &t, &tight)
            .unwrap_err()
            .code,
        DiagnosticCode::ResourceLimitExceeded
    );
}
