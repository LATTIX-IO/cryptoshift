//! Public consumer contract tests for source-attributed capabilities.

use cryptoshift::{
    AlgorithmConstraint, AlgorithmRole, CAPABILITY_CATALOG_VERSION, CapabilityCatalog,
    CapabilityCatalogDraft, CapabilityEvidence, CapabilityEvidenceBasis, CapabilityMatchState,
    CapabilityRecord, CapabilitySelector, CapabilityState, ConstraintDisposition, Diagnostic,
    DiagnosticCode, EvidenceVerification, KnownAlgorithm, Limits, ProfileProvenance, ResourceKind,
    SecurityCategory, SnapshotDigest, StandardEdition, TARGET_PROFILE_VERSION, TargetDisposition,
    TargetProfile, TargetProfileDraft,
};

fn source() -> ProfileProvenance {
    ProfileProvenance {
        issuer_id: "synthetic-review-team".into(),
        document_id: "capability-sample".into(),
        revision: "2026-10-17-r1".into(),
        source_digest: None,
    }
}

fn target(scope: &str, disposition: ConstraintDisposition) -> Result<TargetProfile, Diagnostic> {
    TargetProfile::new(
        TargetProfileDraft {
            schema_version: TARGET_PROFILE_VERSION,
            profile_id: "synthetic-pqc-target".into(),
            revision: 1,
            scope_id: scope.into(),
            provenance: source(),
            standards: vec![StandardEdition::Fips203_2024],
            algorithms: vec![AlgorithmConstraint {
                algorithm: KnownAlgorithm::MlKem1024,
                role: AlgorithmRole::KeyEncapsulation,
                minimum_category: (disposition != ConstraintDisposition::Forbidden)
                    .then_some(SecurityCategory::Five),
                disposition,
            }],
            protocols: vec![],
            certificates: vec![],
            cnsa20: None,
            deadline: None,
            expires_at_unix_secs: None,
        },
        &Limits::default(),
        Some(50),
    )
}

fn evidence(id: &str) -> CapabilityEvidence {
    CapabilityEvidence {
        source_id: "vendor-documentation".into(),
        evidence_id: id.into(),
        source_revision: "revision-1".into(),
        basis: CapabilityEvidenceBasis::VendorDocumentation,
        verification: EvidenceVerification::Unverified,
        verification_reference: None,
        artifact_digest: None,
        observed_at_unix_secs: 10,
        expires_at_unix_secs: None,
    }
}

fn vendor(id: &str, state: CapabilityState) -> CapabilityRecord {
    CapabilityRecord {
        record_id: id.into(),
        provider_id: "vendor-1".into(),
        product_id: "edge-client".into(),
        product_version: "3.4.1".into(),
        platform_id: "linux-x86_64".into(),
        scope_id: "tenant-alpha".into(),
        runtime_id: None,
        algorithm: KnownAlgorithm::MlKem1024,
        role: AlgorithmRole::KeyEncapsulation,
        state,
        evidence: evidence(&format!("evidence-{id}")),
    }
}

fn deployed() -> CapabilityRecord {
    let mut record = vendor("runtime-proof", CapabilityState::DeployedAndVerified);
    record.runtime_id = Some("pod-image-sha256-abc".into());
    record.evidence = CapabilityEvidence {
        source_id: "external-validation-team".into(),
        evidence_id: "test-run-472".into(),
        source_revision: "runtime-check-r1".into(),
        basis: CapabilityEvidenceBasis::RuntimeTest,
        verification: EvidenceVerification::VerifiedByHost,
        verification_reference: Some("external-approval-472".into()),
        artifact_digest: Some(SnapshotDigest::from_bytes([7_u8; 32])),
        observed_at_unix_secs: 10,
        expires_at_unix_secs: Some(100),
    };
    record
}

fn draft(records: Vec<CapabilityRecord>) -> CapabilityCatalogDraft {
    CapabilityCatalogDraft {
        schema_version: CAPABILITY_CATALOG_VERSION,
        catalog_id: "example-catalog".into(),
        revision: 1,
        scope_id: "tenant-alpha".into(),
        provenance: source(),
        records,
    }
}

fn build(records: Vec<CapabilityRecord>) -> Result<CapabilityCatalog, Diagnostic> {
    CapabilityCatalog::new(draft(records), &Limits::default(), Some(50))
}

fn select<'a>(runtime_id: Option<&'a str>) -> CapabilitySelector<'a> {
    CapabilitySelector {
        scope_id: "tenant-alpha",
        provider_id: "vendor-1",
        product_id: "edge-client",
        product_version: "3.4.1",
        platform_id: "linux-x86_64",
        runtime_id,
        algorithm: KnownAlgorithm::MlKem1024,
        role: AlgorithmRole::KeyEncapsulation,
    }
}

fn error_code(result: Result<CapabilityCatalog, Diagnostic>) -> Option<DiagnosticCode> {
    result.err().map(|problem| problem.code)
}

#[test]
fn canonical_identity_is_order_independent_and_provenance_sensitive() -> Result<(), Diagnostic> {
    let a = build(vec![
        vendor("z-available", CapabilityState::Available),
        vendor("a-preview", CapabilityState::Preview),
    ])?;
    let b = build(vec![
        vendor("a-preview", CapabilityState::Preview),
        vendor("z-available", CapabilityState::Available),
    ])?;
    assert_eq!(a.digest(), b.digest());
    assert_eq!(a.export(&Limits::default())?, b.export(&Limits::default())?);
    assert_eq!(a.content().records[0].record_id, "a-preview");
    assert_eq!(
        &a.export(&Limits::default())?[..21],
        b"CSHIFT_CAPABILITY_V1\0"
    );
    a.verify_expected_digest(a.digest())?;
    assert_eq!(
        a.verify_expected_digest(SnapshotDigest::from_bytes([0_u8; 32]))
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::IntegrityMismatch)
    );
    let mut changed = a.content().clone();
    changed.revision = 2;
    assert_ne!(
        a.digest(),
        CapabilityCatalog::new(changed, &Limits::default(), Some(50))?.digest()
    );
    let mut changed = a.content().clone();
    changed.records[0].product_version = "3.4.2".into();
    assert_ne!(
        a.digest(),
        CapabilityCatalog::new(changed, &Limits::default(), Some(50))?.digest()
    );
    let mut changed = a.content().clone();
    changed.provenance.source_digest = Some(SnapshotDigest::from_bytes([2_u8; 32]));
    assert_ne!(
        a.digest(),
        CapabilityCatalog::new(changed, &Limits::default(), Some(50))?.digest()
    );
    Ok(())
}

#[test]
fn frozen_v1_binary_fixture_is_stable_across_revisions() -> Result<(), Diagnostic> {
    // Independently constructed v1 reference fixture. Any modification to
    // framing or content identity requires explicit schema-version review.
    let catalog = build(vec![vendor("fact-one", CapabilityState::Available)])?;
    assert_eq!(catalog.export(&Limits::default())?.len(), 300);
    assert_eq!(
        catalog.digest().as_identifier(),
        "sha256:e141eeb7fc3190e8de82f8402ebcf559977ab9e5426874974b5fa9b6c598eba4"
    );
    Ok(())
}

#[test]
fn advertised_capability_is_neither_deployed_nor_negotiated() -> Result<(), Diagnostic> {
    let target = target("tenant-alpha", ConstraintDisposition::Required)?;
    let catalog = build(vec![
        vendor("vendor-listed", CapabilityState::Available),
        deployed(),
    ])?;
    let vendor_result = catalog.match_target(&target, select(None), 50, &Limits::default())?;
    assert_eq!(
        vendor_result.target_disposition,
        TargetDisposition::Required
    );
    assert_eq!(
        vendor_result.state,
        CapabilityMatchState::Consistent(CapabilityState::Available)
    );
    assert_eq!(vendor_result.record_ids, ["vendor-listed"]);
    let runtime = catalog.match_target(
        &target,
        select(Some("pod-image-sha256-abc")),
        50,
        &Limits::default(),
    )?;
    assert_eq!(
        runtime.state,
        CapabilityMatchState::Consistent(CapabilityState::DeployedAndVerified)
    );
    assert_eq!(runtime.record_ids, ["runtime-proof"]);
    assert_eq!(runtime.evidence_refs.len(), 1);
    assert_eq!(
        runtime.evidence_refs[0].source_id,
        "external-validation-team"
    );
    assert_eq!(runtime.evidence_refs[0].evidence_id, "test-run-472");
    assert_eq!(runtime.evidence_refs[0].source_revision, "runtime-check-r1");
    assert_eq!(runtime.catalog_digest, catalog.digest());
    assert_eq!(runtime.target_digest, target.digest());
    // The separately advertised product cannot satisfy a runtime lookup.
    let unknown_instance = catalog.match_target(
        &target,
        select(Some("unobserved-runtime")),
        50,
        &Limits::default(),
    )?;
    assert_eq!(unknown_instance.state, CapabilityMatchState::NoEvidence);
    assert!(unknown_instance.record_ids.is_empty());
    Ok(())
}

#[test]
fn incompatible_version_platform_provider_scope_and_role_never_inherit_claims()
-> Result<(), Diagnostic> {
    let c = build(vec![deployed()])?;
    let t = target("tenant-alpha", ConstraintDisposition::Required)?;
    let runtime = Some("pod-image-sha256-abc");
    let mut s = select(runtime);
    s.product_version = "3.4.2";
    assert_eq!(
        c.match_target(&t, s, 50, &Limits::default())?.state,
        CapabilityMatchState::NoEvidence
    );
    let mut s = select(runtime);
    s.platform_id = "windows-x64";
    assert_eq!(
        c.match_target(&t, s, 50, &Limits::default())?.state,
        CapabilityMatchState::NoEvidence
    );
    let mut s = select(runtime);
    s.provider_id = "different-vendor";
    assert_eq!(
        c.match_target(&t, s, 50, &Limits::default())?.state,
        CapabilityMatchState::NoEvidence
    );
    let mut s = select(runtime);
    s.role = AlgorithmRole::Signature;
    assert_eq!(
        c.match_target(&t, s, 50, &Limits::default())
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    let mut s = select(runtime);
    s.scope_id = "tenant-beta";
    assert_eq!(
        c.match_target(&t, s, 50, &Limits::default())
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::InvalidReference)
    );
    let wrong_target = target("tenant-beta", ConstraintDisposition::Required)?;
    assert_eq!(
        c.match_target(&wrong_target, select(runtime), 50, &Limits::default())
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::InvalidReference)
    );
    Ok(())
}

#[test]
fn roadmap_preview_unsupported_unknown_and_missing_are_distinct() -> Result<(), Diagnostic> {
    let t = target("tenant-alpha", ConstraintDisposition::Required)?;
    for state in [
        CapabilityState::Roadmap,
        CapabilityState::Preview,
        CapabilityState::Unsupported,
        CapabilityState::Unknown,
    ] {
        let catalog = build(vec![vendor("one-fact", state)])?;
        assert_eq!(
            catalog
                .match_target(&t, select(None), 50, &Limits::default())?
                .state,
            CapabilityMatchState::Consistent(state)
        );
        assert_eq!(
            catalog
                .match_target(&t, select(Some("runtime-absent")), 50, &Limits::default())?
                .state,
            CapabilityMatchState::NoEvidence
        );
    }
    let forbidden = target("tenant-alpha", ConstraintDisposition::Forbidden)?;
    let advertised = build(vec![vendor("one-fact", CapabilityState::Available)])?;
    let status = advertised.match_target(&forbidden, select(None), 50, &Limits::default())?;
    assert_eq!(status.target_disposition, TargetDisposition::Forbidden);
    assert_eq!(
        status.state,
        CapabilityMatchState::Consistent(CapabilityState::Available)
    );
    Ok(())
}

#[test]
fn disagreeing_sources_are_preserved_not_overwritten() -> Result<(), Diagnostic> {
    let t = target("tenant-alpha", ConstraintDisposition::Required)?;
    let a = build(vec![
        vendor("v1", CapabilityState::Available),
        vendor("v2", CapabilityState::Unsupported),
    ])?;
    let result = a.match_target(&t, select(None), 50, &Limits::default())?;
    assert_eq!(result.state, CapabilityMatchState::Conflicting);
    assert_eq!(result.record_ids, ["v1", "v2"]);
    assert_eq!(
        result
            .evidence_refs
            .iter()
            .map(|item| item.evidence_id.as_str())
            .collect::<Vec<_>>(),
        ["evidence-v1", "evidence-v2"]
    );
    let same = build(vec![
        vendor("v1", CapabilityState::Available),
        vendor("v2", CapabilityState::Available),
    ])?;
    assert_eq!(
        same.match_target(&t, select(None), 50, &Limits::default())?
            .state,
        CapabilityMatchState::Consistent(CapabilityState::Available)
    );
    assert_ne!(a.digest(), same.digest());
    Ok(())
}

#[test]
fn independent_evidence_namespaces_survive_equal_evidence_ids() -> Result<(), Diagnostic> {
    let target = target("tenant-alpha", ConstraintDisposition::Required)?;
    let a = vendor("claim-a", CapabilityState::Available);
    let mut b = vendor("claim-b", CapabilityState::Available);
    b.evidence.source_id = "separate-independent-source".into();
    b.evidence.evidence_id = a.evidence.evidence_id.clone();
    b.evidence.source_revision = "review-v2".into();
    let catalog = build(vec![b, a])?;
    let found = catalog.match_target(&target, select(None), 50, &Limits::default())?;
    assert_eq!(
        found.state,
        CapabilityMatchState::Consistent(CapabilityState::Available)
    );
    assert_eq!(found.record_ids, ["claim-a", "claim-b"]);
    assert_eq!(found.evidence_refs.len(), 2);
    assert_eq!(
        found.evidence_refs[0].source_id,
        "separate-independent-source"
    );
    assert_eq!(found.evidence_refs[1].source_id, "vendor-documentation");
    assert_eq!(
        found.evidence_refs[0].evidence_id,
        found.evidence_refs[1].evidence_id
    );
    assert_ne!(
        found.evidence_refs[0].source_revision,
        found.evidence_refs[1].source_revision
    );
    Ok(())
}

#[test]
fn verified_deployment_claim_requires_runtime_and_checked_evidence() -> Result<(), Diagnostic> {
    let valid = deployed();
    build(vec![valid.clone()])?;
    for variant in 0..7 {
        let mut record = valid.clone();
        match variant {
            0 => record.runtime_id = None,
            1 => record.evidence.basis = CapabilityEvidenceBasis::VendorDocumentation,
            2 => record.evidence.basis = CapabilityEvidenceBasis::Inference,
            3 => record.evidence.verification = EvidenceVerification::Unverified,
            4 => record.evidence.verification_reference = None,
            5 => record.evidence.artifact_digest = None,
            _ => record.evidence.expires_at_unix_secs = None,
        }
        assert!(
            build(vec![record]).is_err(),
            "unverified or insufficient runtime evidence cannot be admitted"
        );
    }
    let mut forged = vendor("forged", CapabilityState::Available);
    forged.evidence.verification = EvidenceVerification::VerifiedByHost;
    assert_eq!(
        error_code(build(vec![forged])),
        Some(DiagnosticCode::MissingProvenance)
    );
    Ok(())
}

#[test]
fn explicit_clock_blocks_stale_future_and_unbounded_runtime_claims() -> Result<(), Diagnostic> {
    let good = deployed();
    assert_eq!(
        error_code(CapabilityCatalog::new(
            draft(vec![good.clone()]),
            &Limits::default(),
            None
        )),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    assert_eq!(
        error_code(CapabilityCatalog::new(
            draft(vec![good.clone()]),
            &Limits::default(),
            Some(100)
        )),
        Some(DiagnosticCode::StaleCriticalProfile)
    );
    assert_eq!(
        error_code(CapabilityCatalog::new(
            draft(vec![good.clone()]),
            &Limits::default(),
            Some(9)
        )),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    let c = build(vec![good.clone()])?;
    let t = target("tenant-alpha", ConstraintDisposition::Required)?;
    assert_eq!(
        c.match_target(
            &t,
            select(Some("pod-image-sha256-abc")),
            100,
            &Limits::default()
        )?
        .state,
        CapabilityMatchState::Stale
    );
    assert_eq!(
        c.match_target(
            &t,
            select(Some("pod-image-sha256-abc")),
            9,
            &Limits::default()
        )?
        .state,
        CapabilityMatchState::Stale
    );
    let mut backwards = good;
    backwards.evidence.expires_at_unix_secs = Some(10);
    assert_eq!(
        error_code(build(vec![backwards])),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    Ok(())
}

#[test]
fn target_expiry_is_rechecked_at_lookup_without_a_clock_default() -> Result<(), Diagnostic> {
    let mut input = target("tenant-alpha", ConstraintDisposition::Required)?
        .content()
        .clone();
    input.expires_at_unix_secs = Some(100);
    let time_bound_target = TargetProfile::new(input, &Limits::default(), Some(50))?;
    let catalog = build(vec![deployed()])?;
    let selector = select(Some("pod-image-sha256-abc"));
    assert_eq!(
        catalog
            .match_target(&time_bound_target, selector, 99, &Limits::default())?
            .state,
        CapabilityMatchState::Consistent(CapabilityState::DeployedAndVerified)
    );
    let rejected = catalog.match_target(&time_bound_target, selector, 100, &Limits::default());
    assert_eq!(
        rejected.err().map(|e| e.code),
        Some(DiagnosticCode::StaleCriticalProfile)
    );
    // A time-independent target without an expiry is still evaluated with
    // an explicit query time; runtime evidence expiry remains independent.
    Ok(())
}

#[test]
fn duplicate_records_revisions_and_secret_bearing_identifiers_fail_closed() -> Result<(), Diagnostic>
{
    let a = vendor("same-id", CapabilityState::Available);
    let mut duplicate = a.clone();
    duplicate.state = CapabilityState::Roadmap;
    assert_eq!(
        error_code(build(vec![a, duplicate])),
        Some(DiagnosticCode::DuplicateRecord)
    );
    let mut bad = vendor("one", CapabilityState::Available);
    bad.evidence.source_id = "https://admin:secret@provider".into();
    let e = build(vec![bad]);
    assert_eq!(
        e.as_ref().err().map(|x| x.code),
        Some(DiagnosticCode::InvalidIdentifier)
    );
    if let Err(problem) = e {
        assert!(!problem.to_string().contains("secret"));
    }
    let mut bad = vendor("one", CapabilityState::Available);
    bad.product_id = "edge\ncredential".into();
    assert_eq!(
        error_code(build(vec![bad])),
        Some(DiagnosticCode::InvalidIdentifier)
    );
    let mut bad = vendor("one", CapabilityState::Available);
    bad.scope_id = "tenant-beta".into();
    assert_eq!(
        error_code(build(vec![bad])),
        Some(DiagnosticCode::InvalidReference)
    );
    let mut bad = vendor("one", CapabilityState::Available);
    bad.role = AlgorithmRole::Signature;
    assert_eq!(
        error_code(build(vec![bad])),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    assert_eq!(
        KnownAlgorithm::parse_exact("ML-KEM-unknown")
            .err()
            .map(|x| x.code),
        Some(DiagnosticCode::InvalidReference)
    );
    let mut unsupported = draft(vec![vendor("one", CapabilityState::Available)]);
    unsupported.schema_version = 2;
    assert_eq!(
        error_code(CapabilityCatalog::new(
            unsupported,
            &Limits::default(),
            Some(50)
        )),
        Some(DiagnosticCode::UnsupportedSchemaVersion)
    );
    Ok(())
}

#[test]
fn bounded_input_record_count_output_and_lookup_fail_closed() -> Result<(), Diagnostic> {
    let records = vec![
        vendor("fact-one", CapabilityState::Available),
        vendor("fact-two", CapabilityState::Unknown),
    ];
    let case = [
        Limits {
            max_profile_references: 1,
            ..Limits::default()
        },
        Limits {
            max_evidence_records: 1,
            ..Limits::default()
        },
        Limits {
            max_input_bytes: 10,
            ..Limits::default()
        },
        Limits {
            max_export_bytes: 30,
            ..Limits::default()
        },
    ];
    for limits in case {
        assert_eq!(
            error_code(CapabilityCatalog::new(
                draft(records.clone()),
                &limits,
                Some(50)
            )),
            Some(DiagnosticCode::ResourceLimitExceeded)
        );
    }
    let c = build(records)?;
    let too_small = Limits {
        max_export_bytes: 20,
        ..Limits::default()
    };
    assert_eq!(
        c.export(&too_small).err().map(|x| x.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    let t = target("tenant-alpha", ConstraintDisposition::Required)?;
    let result = c.match_target(&t, select(None), 50, &too_small);
    // Only the emitted IDs are counted; small budgets fail without partial reports.
    assert_eq!(
        result.err().map(|x| x.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    let limited = Limits {
        max_profile_references: 1,
        ..Limits::default()
    };
    assert_eq!(
        c.match_target(&t, select(None), 50, &limited)
            .err()
            .map(|x| x.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    let limited = Limits {
        max_input_bytes: 10,
        ..Limits::default()
    };
    assert_eq!(
        c.match_target(&t, select(None), 50, &limited)
            .err()
            .map(|x| x.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    assert!(ResourceKind::ProfileReferences.ceiling() > 1);
    Ok(())
}
