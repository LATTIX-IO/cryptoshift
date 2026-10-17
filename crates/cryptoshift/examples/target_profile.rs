//! Synthetic offline example of pinned FIPS and scoped CNSA profile targets.

use cryptoshift::{
    AlgorithmConstraint, AlgorithmRole, CertificateConstraint, Cnsa20Overlay,
    ConstraintDisposition, Diagnostic, KnownAlgorithm, Limits, ProfileProvenance,
    ProtocolConstraint, SecurityCategory, StandardEdition, TargetDisposition,
    TargetProfile, TargetProfileDraft, TARGET_PROFILE_VERSION,
};

fn main() -> Result<(), Diagnostic> {
    // This is an illustrative target *assertion*, not an NSA endorsement,
    // live crypto deployment scan, protocol conformance test, or approval.
    let draft = TargetProfileDraft {
        schema_version: TARGET_PROFILE_VERSION,
        profile_id: "synthetic-nss-profile".into(),
        revision: 1,
        scope_id: "offline-demonstration".into(),
        provenance: ProfileProvenance {
            issuer_id: "synthetic-reviewer".into(),
            document_id: "illustrative-policy-only".into(),
            revision: "v1".into(),
            source_digest: None,
        },
        standards: vec![
            StandardEdition::Cnsa20_2022v1,
            StandardEdition::Fips204_2024,
            StandardEdition::Fips203_2024,
        ],
        algorithms: vec![
            AlgorithmConstraint {
                algorithm: KnownAlgorithm::MlDsa87,
                role: AlgorithmRole::Signature,
                minimum_category: Some(SecurityCategory::Five),
                disposition: ConstraintDisposition::Required,
            },
            AlgorithmConstraint {
                algorithm: KnownAlgorithm::MlKem1024,
                role: AlgorithmRole::KeyEncapsulation,
                minimum_category: Some(SecurityCategory::Five),
                disposition: ConstraintDisposition::Required,
            },
        ],
        protocols: vec![ProtocolConstraint {
            protocol_id: "synthetic-channel".into(),
            revision: "synthetic-profile-1".into(),
            role: AlgorithmRole::KeyEncapsulation,
            algorithm: KnownAlgorithm::MlKem1024,
            hybrid: None,
        }],
        certificates: vec![CertificateConstraint {
            profile_id: "synthetic-ml-dsa-certificate-binding".into(),
            revision: "1".into(),
            signature_algorithm: KnownAlgorithm::MlDsa87,
            specification_reference: "synthetic-external-encoding-review".into(),
        }],
        cnsa20: Some(Cnsa20Overlay {
            edition: StandardEdition::Cnsa20_2022v1,
            applicability_reference: "synthetic-applicability-record".into(),
        }),
        deadline: None,
        expires_at_unix_secs: None,
    };
    let limits = Limits::default();
    let profile = TargetProfile::new(draft, &limits, Some(0))?;
    println!("target: {}", profile.content().profile_id);
    println!("source scope: {}", profile.content().scope_id);
    println!("digest: {}", profile.digest().as_identifier());
    println!("standards: {}", profile.content().standards.len());
    println!(
        "ML-KEM-1024: {:?}",
        profile.disposition("ML-KEM-1024")?
    );
    println!(
        "ML-DSA-87: {:?}",
        profile.disposition("ML-DSA-87")?
    );
    assert_eq!(
        profile.disposition("ML-KEM-1024")?,
        TargetDisposition::Required
    );
    assert!(profile.content().protocols[0].hybrid.is_none());
    assert!(profile.content().deadline.is_none());
    profile.verify_expected_digest(profile.digest())?;
    println!("No implicit hybrid, global deadline, deployment or compliance claim.");
    Ok(())
}
