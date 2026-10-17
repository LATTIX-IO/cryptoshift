//! Offline synthetic provider-vs-runtime capability evidence demonstration.

use cryptoshift::{
    AlgorithmConstraint, AlgorithmRole, CAPABILITY_CATALOG_VERSION, CapabilityCatalog,
    CapabilityCatalogDraft, CapabilityEvidence, CapabilityEvidenceBasis, CapabilityRecord,
    CapabilitySelector, CapabilityState, ConstraintDisposition, Diagnostic, EvidenceVerification,
    KnownAlgorithm, Limits, ProfileProvenance, SecurityCategory, SnapshotDigest, StandardEdition,
    TARGET_PROFILE_VERSION, TargetProfile, TargetProfileDraft,
};

fn main() -> Result<(), Diagnostic> {
    let limits = Limits::default();
    let provenance = ProfileProvenance {
        issuer_id: "synthetic-security-lab".into(),
        document_id: "offline-claims-only".into(),
        revision: "2026-10-17-v1".into(),
        source_digest: None,
    };
    let target = TargetProfile::new(
        TargetProfileDraft {
            schema_version: TARGET_PROFILE_VERSION,
            profile_id: "synthetic-pqc-target".into(),
            revision: 1,
            scope_id: "tenant-alpha".into(),
            provenance: provenance.clone(),
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
            expires_at_unix_secs: None,
        },
        &limits,
        Some(50),
    )?;
    let mut offering = CapabilityRecord {
        record_id: "vendor-offering".into(),
        provider_id: "vendor-1".into(),
        product_id: "edge-client".into(),
        product_version: "3.4.1".into(),
        platform_id: "linux-x86_64".into(),
        scope_id: "tenant-alpha".into(),
        runtime_id: None,
        algorithm: KnownAlgorithm::MlKem1024,
        role: AlgorithmRole::KeyEncapsulation,
        state: CapabilityState::Available,
        evidence: CapabilityEvidence {
            source_id: "synthetic-vendor-docs".into(),
            evidence_id: "spec-revision-1".into(),
            source_revision: "spec-v1".into(),
            basis: CapabilityEvidenceBasis::VendorDocumentation,
            verification: EvidenceVerification::Unverified,
            verification_reference: None,
            artifact_digest: None,
            observed_at_unix_secs: 10,
            expires_at_unix_secs: None,
        },
    };
    let mut runtime = offering.clone();
    runtime.record_id = "exact-runtime-observation".into();
    runtime.runtime_id = Some("pod-image-sha256-abc".into());
    runtime.state = CapabilityState::DeployedAndVerified;
    runtime.evidence = CapabilityEvidence {
        source_id: "synthetic-external-checker".into(),
        evidence_id: "runtime-test-1".into(),
        source_revision: "test-revision-1".into(),
        basis: CapabilityEvidenceBasis::RuntimeTest,
        // This is an externally *claimed* verification. Cryptoshift cannot
        // authenticate it without a separately trusted proof verifier.
        verification: EvidenceVerification::VerifiedByHost,
        verification_reference: Some("external-receipt-1".into()),
        artifact_digest: Some(SnapshotDigest::from_bytes([3_u8; 32])),
        observed_at_unix_secs: 10,
        expires_at_unix_secs: Some(100),
    };
    let catalog = CapabilityCatalog::new(
        CapabilityCatalogDraft {
            schema_version: CAPABILITY_CATALOG_VERSION,
            catalog_id: "synthetic-provider-catalog".into(),
            revision: 1,
            scope_id: "tenant-alpha".into(),
            provenance,
            records: vec![runtime, offering.clone()],
        },
        &limits,
        Some(50),
    )?;
    println!("target: {}", target.content().profile_id);
    println!("catalog digest: {}", catalog.digest().as_identifier());
    let query = |runtime_id| CapabilitySelector {
        scope_id: "tenant-alpha",
        provider_id: "vendor-1",
        product_id: "edge-client",
        product_version: "3.4.1",
        platform_id: "linux-x86_64",
        runtime_id,
        algorithm: KnownAlgorithm::MlKem1024,
        role: AlgorithmRole::KeyEncapsulation,
    };
    let vendor = catalog.match_target(&target, query(None), 50, &limits)?;
    let verified =
        catalog.match_target(&target, query(Some("pod-image-sha256-abc")), 50, &limits)?;
    let missing = catalog.match_target(&target, query(Some("never-observed")), 50, &limits)?;
    println!("vendor offering: {:?}", vendor.state);
    println!("exact runtime: {:?}", verified.state);
    println!("unobserved runtime: {:?}", missing.state);
    println!("no peer/PKI interoperability or migration approval");
    offering.product_version = "3.4.2".into();
    let _ = offering; // The immutable catalog cannot be changed by editing inputs.
    Ok(())
}
