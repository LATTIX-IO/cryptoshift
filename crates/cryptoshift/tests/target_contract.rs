//! Public contract, deterministic replay and negative-security tests.

use cryptoshift::{
    AlgorithmConstraint, AlgorithmRole, CertificateConstraint, Cnsa20Overlay,
    ConstraintDisposition, Diagnostic, DiagnosticCode, ExplicitDeadline, HybridConstruction,
    KnownAlgorithm, Limits, ProfileProvenance, ProtocolConstraint, STANDARDS_CATALOG_VERSION,
    SecurityCategory, SnapshotDigest, StandardEdition, TARGET_PROFILE_VERSION, TargetDisposition,
    TargetProfile, TargetProfileDraft,
};

fn source() -> ProfileProvenance {
    ProfileProvenance {
        issuer_id: "synthetic-institute".into(),
        document_id: "test-target".into(),
        revision: "2026-10-16-r1".into(),
        source_digest: None,
    }
}

fn constraint(
    algorithm: KnownAlgorithm,
    disposition: ConstraintDisposition,
) -> AlgorithmConstraint {
    AlgorithmConstraint {
        algorithm,
        role: algorithm.role(),
        minimum_category: if disposition == ConstraintDisposition::Forbidden {
            None
        } else {
            Some(algorithm.category())
        },
        disposition,
    }
}

fn draft() -> TargetProfileDraft {
    TargetProfileDraft {
        schema_version: TARGET_PROFILE_VERSION,
        profile_id: "illustrative-pqc-profile".into(),
        revision: 1,
        scope_id: "test-tenant-1".into(),
        provenance: source(),
        standards: vec![
            StandardEdition::Fips205_2024,
            StandardEdition::Fips204_2024,
            StandardEdition::Fips203_2024,
        ],
        algorithms: vec![
            constraint(
                KnownAlgorithm::SlhDsaSha2_256s,
                ConstraintDisposition::Forbidden,
            ),
            constraint(KnownAlgorithm::MlDsa87, ConstraintDisposition::Required),
            constraint(KnownAlgorithm::MlKem1024, ConstraintDisposition::Permitted),
        ],
        protocols: vec![ProtocolConstraint {
            protocol_id: "example-secure-channel".into(),
            revision: "profile-1.0".into(),
            role: AlgorithmRole::KeyEncapsulation,
            algorithm: KnownAlgorithm::MlKem1024,
            hybrid: None,
        }],
        certificates: vec![CertificateConstraint {
            profile_id: "example-certificate-format".into(),
            revision: "binding-1.0".into(),
            signature_algorithm: KnownAlgorithm::MlDsa87,
            specification_reference: "synthetic-pki-review-r1".into(),
        }],
        cnsa20: None,
        deadline: None,
        expires_at_unix_secs: None,
    }
}

fn code(result: Result<TargetProfile, Diagnostic>) -> Option<DiagnosticCode> {
    result.err().map(|err| err.code)
}

fn check(d: TargetProfileDraft) -> Result<TargetProfile, Diagnostic> {
    TargetProfile::new(d, &Limits::default(), Some(100))
}

#[test]
fn catalog_enumerates_exact_fips_identifiers_and_categories() -> Result<(), Diagnostic> {
    assert_eq!(STANDARDS_CATALOG_VERSION, 1);
    assert_eq!(KnownAlgorithm::ALL.len(), 18);
    let mut unique = std::collections::BTreeSet::new();
    for algorithm in KnownAlgorithm::ALL {
        assert!(unique.insert(algorithm.id()));
        assert_eq!(KnownAlgorithm::parse_exact(algorithm.id())?, algorithm);
        assert_ne!(algorithm.standard(), StandardEdition::Cnsa20_2022v1);
        assert!(matches!(
            algorithm.category(),
            SecurityCategory::One | SecurityCategory::Three | SecurityCategory::Five
        ));
        assert!(
            algorithm
                .standard()
                .source_url()
                .starts_with("https://csrc.nist.gov/")
        );
    }
    for unknown in [
        "Kyber1024",
        "CRYSTALS-Kyber",
        "ML-KEM-256",
        "ML-DSA-99",
        "SLH-DSA-128s",
        "SLH-DSA-SHA2-512s",
        "ml-kem-1024",
        "ML-KEM-1024 ",
        "",
    ] {
        assert_eq!(
            KnownAlgorithm::parse_exact(unknown).err().map(|e| e.code),
            Some(DiagnosticCode::InvalidReference)
        );
    }
    assert_eq!(KnownAlgorithm::MlKem512.category(), SecurityCategory::One);
    assert_eq!(KnownAlgorithm::MlKem768.category(), SecurityCategory::Three);
    assert_eq!(KnownAlgorithm::MlKem1024.category(), SecurityCategory::Five);
    assert_eq!(KnownAlgorithm::MlDsa44.category(), SecurityCategory::One);
    assert_eq!(KnownAlgorithm::MlDsa65.category(), SecurityCategory::Three);
    assert_eq!(KnownAlgorithm::MlDsa87.category(), SecurityCategory::Five);
    assert_eq!(
        KnownAlgorithm::SlhDsaSha2_256s.standard(),
        StandardEdition::Fips205_2024
    );
    Ok(())
}

#[test]
fn historic_edition_identifiers_are_pinned_and_future_versions_rejected() -> Result<(), Diagnostic>
{
    let original = [
        StandardEdition::Fips203_2024,
        StandardEdition::Fips204_2024,
        StandardEdition::Fips205_2024,
        StandardEdition::Cnsa20_2022v1,
    ];
    for edition in original {
        assert_eq!(StandardEdition::parse_exact(edition.id())?, edition);
        assert!(edition.source_url().starts_with("https://"));
    }
    for unsupported in [
        "NIST-FIPS-203:2025-11-17",
        "NIST-FIPS-204:2026-07-31",
        "NIST-FIPS-206:2024-08-13",
        "NSA-CNSA-2.0:2026-v3",
        "NSA-CNSA-2.0",
    ] {
        assert_eq!(
            StandardEdition::parse_exact(unsupported)
                .err()
                .map(|e| e.code),
            Some(DiagnosticCode::UnsupportedSchemaVersion)
        );
    }
    let mut changed = draft();
    changed.schema_version = 2;
    assert_eq!(
        code(check(changed)),
        Some(DiagnosticCode::UnsupportedSchemaVersion)
    );
    let mut changed = draft();
    changed.schema_version = 0;
    assert_eq!(
        code(check(changed)),
        Some(DiagnosticCode::UnsupportedSchemaVersion)
    );
    Ok(())
}

#[test]
fn canonical_reordering_and_explicit_target_lookup() -> Result<(), Diagnostic> {
    let a = check(draft())?;
    let mut reordered = draft();
    reordered.standards.reverse();
    reordered.algorithms.reverse();
    assert_eq!(a.content(), check(reordered)?.content());
    assert_eq!(
        a.export(&Limits::default())?,
        check(draft())?.export(&Limits::default())?
    );
    assert_eq!(a.digest(), check(draft())?.digest());
    // Independent frozen v1 binary fixture: detects accidental wire-format
    // or canonical-order changes even when producer and consumer agree.
    assert_eq!(a.export(&Limits::default())?.len(), 428);
    assert_eq!(
        a.digest().as_identifier(),
        "sha256:f7d2087540e5caae06ea61f7ce3b70f0cdebea91d430242593810202002bc6c3"
    );
    assert_eq!(a.disposition("ML-KEM-1024")?, TargetDisposition::Permitted);
    assert_eq!(a.disposition("ML-DSA-87")?, TargetDisposition::Required);
    assert_eq!(
        a.disposition("SLH-DSA-SHA2-256s")?,
        TargetDisposition::Forbidden
    );
    assert_eq!(
        a.disposition("ML-KEM-768")?,
        TargetDisposition::NotSpecified
    );
    assert_eq!(
        a.disposition("RSA-2048").err().map(|e| e.code),
        Some(DiagnosticCode::InvalidReference)
    );
    assert_eq!(&a.export(&Limits::default())?[..17], b"CSHIFT_TARGET_V1\0");
    a.verify_expected_digest(a.digest())?;
    assert_eq!(
        a.verify_expected_digest(SnapshotDigest::from_bytes([0; 32]))
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::IntegrityMismatch)
    );
    Ok(())
}

#[test]
fn immutable_revision_and_provenance_changes_rotate_content_identity() -> Result<(), Diagnostic> {
    let old = check(draft())?;
    let mut later = draft();
    later.revision = 2;
    assert_ne!(old.digest(), check(later)?.digest());
    let mut cited = draft();
    cited.provenance.source_digest = Some(SnapshotDigest::from_bytes([3; 32]));
    assert_ne!(old.digest(), check(cited)?.digest());
    let mut scoped = draft();
    scoped.scope_id = "different-tenant".into();
    assert_ne!(old.digest(), check(scoped)?.digest());
    let mut change = draft();
    change.algorithms[1].minimum_category = Some(SecurityCategory::Three);
    assert_ne!(old.digest(), check(change)?.digest());
    assert_eq!(
        check(draft())?.export(&Limits::default())?,
        old.export(&Limits::default())?
    );
    Ok(())
}

#[test]
fn role_and_category_constraints_are_not_silently_relaxed() {
    let mut bad = draft();
    bad.algorithms[1].role = AlgorithmRole::KeyEncapsulation;
    assert_eq!(
        code(check(bad)),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    let mut bad = draft();
    bad.algorithms[2].minimum_category = Some(SecurityCategory::Five);
    bad.algorithms[2].algorithm = KnownAlgorithm::MlKem768;
    assert_eq!(
        code(check(bad)),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    let mut bad = draft();
    bad.algorithms[1].minimum_category = None;
    assert_eq!(
        code(check(bad)),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    let mut bad = draft();
    bad.algorithms[0].minimum_category = Some(SecurityCategory::One);
    assert_eq!(
        code(check(bad)),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    let mut bad = draft();
    bad.standards
        .retain(|edition| *edition != StandardEdition::Fips204_2024);
    assert_eq!(code(check(bad)), Some(DiagnosticCode::InvalidReference));
}

#[test]
fn duplicate_and_conflicting_requirements_fail_closed() {
    let mut d = draft();
    d.algorithms.push(constraint(
        KnownAlgorithm::MlDsa87,
        ConstraintDisposition::Forbidden,
    ));
    assert_eq!(code(check(d)), Some(DiagnosticCode::DuplicateRecord));
    let mut d = draft();
    d.standards.push(StandardEdition::Fips203_2024);
    assert_eq!(code(check(d)), Some(DiagnosticCode::DuplicateRecord));
    let mut d = draft();
    d.protocols[0].algorithm = KnownAlgorithm::MlKem768;
    assert_eq!(code(check(d)), Some(DiagnosticCode::InvalidStateTransition));
    let mut d = draft();
    d.certificates[0].signature_algorithm = KnownAlgorithm::MlKem1024;
    assert_eq!(code(check(d)), Some(DiagnosticCode::InvalidStateTransition));
    let mut d = draft();
    d.algorithms
        .retain(|a| a.algorithm != KnownAlgorithm::MlKem1024);
    assert_eq!(code(check(d)), Some(DiagnosticCode::InvalidStateTransition));
    let mut d = draft();
    for entry in &mut d.algorithms {
        if entry.algorithm == KnownAlgorithm::MlDsa87 {
            entry.disposition = ConstraintDisposition::Forbidden;
        }
    }
    assert_eq!(code(check(d)), Some(DiagnosticCode::InvalidStateTransition));
    let mut d = draft();
    d.protocols.push(d.protocols[0].clone());
    assert_eq!(code(check(d)), Some(DiagnosticCode::DuplicateRecord));
    let mut d = draft();
    d.certificates.push(d.certificates[0].clone());
    assert_eq!(code(check(d)), Some(DiagnosticCode::DuplicateRecord));
}

#[test]
fn cnsa20_overlay_is_opt_in_and_not_equivalent_to_fips_approval() -> Result<(), Diagnostic> {
    let fips_only = check(draft())?;
    assert!(fips_only.content().cnsa20.is_none());
    let mut cnsa = draft();
    cnsa.standards.push(StandardEdition::Cnsa20_2022v1);
    cnsa.cnsa20 = Some(Cnsa20Overlay {
        edition: StandardEdition::Cnsa20_2022v1,
        applicability_reference: "synthetic-nss-target-assertion".into(),
    });
    let scoped = check(cnsa.clone())?;
    assert_eq!(
        scoped.disposition("ML-KEM-1024")?,
        TargetDisposition::Permitted
    );
    assert_eq!(
        scoped.disposition("ML-DSA-87")?,
        TargetDisposition::Required
    );
    assert_ne!(scoped.digest(), fips_only.digest());

    cnsa.algorithms[0].disposition = ConstraintDisposition::Permitted;
    cnsa.algorithms[0].minimum_category = Some(SecurityCategory::Five);
    assert_eq!(
        code(check(cnsa)),
        Some(DiagnosticCode::InvalidStateTransition)
    );

    let mut invalid = draft();
    invalid.cnsa20 = Some(Cnsa20Overlay {
        edition: StandardEdition::Cnsa20_2022v1,
        applicability_reference: "synthetic-nss-target-assertion".into(),
    });
    assert_eq!(
        code(check(invalid)),
        Some(DiagnosticCode::UnsupportedSchemaVersion)
    );
    let mut incomplete = draft();
    incomplete.standards.push(StandardEdition::Cnsa20_2022v1);
    assert_eq!(
        code(check(incomplete)),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    Ok(())
}

#[test]
fn exact_protocol_certificate_and_hybrid_constraints_are_explicit() -> Result<(), Diagnostic> {
    let input = draft();
    assert!(input.protocols[0].hybrid.is_none());
    let mut declared = input.clone();
    declared.protocols[0].hybrid = Some(HybridConstruction {
        companion_algorithm_id: "X25519".into(),
        combiner_reference: "explicit-SP-800-227-profile-2025".into(),
    });
    assert_ne!(check(declared)?.digest(), check(input.clone())?.digest());
    let mut wrong = input.clone();
    wrong.protocols[0].role = AlgorithmRole::Signature;
    assert_eq!(
        code(check(wrong)),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    let mut same = input.clone();
    same.protocols[0].hybrid = Some(HybridConstruction {
        companion_algorithm_id: "ML-KEM-1024".into(),
        combiner_reference: "explicit-combiner".into(),
    });
    assert_eq!(
        code(check(same)),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    let mut no_combiner = input.clone();
    no_combiner.protocols[0].hybrid = Some(HybridConstruction {
        companion_algorithm_id: "X25519".into(),
        combiner_reference: "".into(),
    });
    assert_eq!(
        code(check(no_combiner)),
        Some(DiagnosticCode::InvalidIdentifier)
    );
    let mut missing_cert_source = input;
    missing_cert_source.certificates[0]
        .specification_reference
        .clear();
    assert_eq!(
        code(check(missing_cert_source)),
        Some(DiagnosticCode::InvalidIdentifier)
    );
    Ok(())
}

#[test]
fn deadlines_and_expiration_are_opt_in_with_explicit_evaluation() -> Result<(), Diagnostic> {
    let base = check(draft())?;
    assert!(base.content().deadline.is_none());
    let mut asserted = draft();
    asserted.deadline = Some(ExplicitDeadline {
        applies_to: "example-rollout-stage".into(),
        due_at_unix_secs: 1893456000,
        source_reference: "explicit-enterprise-policy-r2".into(),
    });
    assert_ne!(base.digest(), check(asserted.clone())?.digest());
    asserted.expires_at_unix_secs = Some(1000);
    assert_eq!(
        TargetProfile::new(asserted.clone(), &Limits::default(), None)
            .err().map(|e| e.code),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    assert!(TargetProfile::new(asserted.clone(), &Limits::default(), Some(999)).is_ok());
    assert_eq!(
        TargetProfile::new(asserted, &Limits::default(), Some(1000))
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::StaleCriticalProfile)
    );
    Ok(())
}

#[test]
fn external_metadata_and_resource_budgets_reject_without_leaking_strings() -> Result<(), Diagnostic>
{
    let mut bad = draft();
    bad.provenance.issuer_id = "secret\nunsafe".into();
    let outcome = check(bad);
    assert_eq!(
        outcome.as_ref().err().map(|e| e.code),
        Some(DiagnosticCode::InvalidIdentifier)
    );
    if let Err(err) = outcome {
        assert!(!err.to_string().contains("secret"));
    }
    let mut too_many = draft();
    too_many.algorithms.extend(
        KnownAlgorithm::ALL
            .iter()
            .take(3)
            .map(|id| constraint(*id, ConstraintDisposition::Forbidden)),
    );
    let limits = Limits {
        max_profile_references: 6,
        ..Limits::default()
    };
    assert_eq!(
        TargetProfile::new(too_many, &limits, None)
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    let limits = Limits {
        max_input_bytes: 10,
        ..Limits::default()
    };
    assert_eq!(
        TargetProfile::new(draft(), &limits, None)
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    let accepted = check(draft())?;
    let limits = Limits {
        max_export_bytes: 64,
        ..Limits::default()
    };
    assert_eq!(
        accepted.export(&limits).err().map(|e| e.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    Ok(())
}
