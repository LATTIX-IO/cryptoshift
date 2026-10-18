//! Standalone, offline external-consumer example of conservative peer compatibility.
//!
//! Run: cargo run -p cryptoshift --example peer_compatibility --locked
use cryptoshift::*;

const NOW: i64 = 1_800_000_000;

fn catalog(
    provider: &str,
    runtime: &str,
    limits: &Limits,
) -> Result<CapabilityCatalog, Diagnostic> {
    CapabilityCatalog::new(
        CapabilityCatalogDraft {
            schema_version: CAPABILITY_CATALOG_VERSION,
            catalog_id: format!("catalog-{provider}"),
            revision: 1,
            scope_id: "example-tenant".to_owned(),
            provenance: ProfileProvenance {
                issuer_id: "vendor".into(),
                document_id: "specification".into(),
                revision: "1".into(),
                source_digest: None,
            },
            records: vec![CapabilityRecord {
                record_id: format!("claim-{provider}"),
                provider_id: provider.into(),
                product_id: "node".into(),
                product_version: "1.0".into(),
                platform_id: "linux".into(),
                scope_id: "example-tenant".into(),
                runtime_id: Some(runtime.into()),
                algorithm: KnownAlgorithm::MlKem1024,
                role: AlgorithmRole::KeyEncapsulation,
                state: CapabilityState::Available,
                evidence: CapabilityEvidence {
                    source_id: "vendor".into(),
                    evidence_id: format!("document-{provider}"),
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
        limits,
        Some(NOW),
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits::default();
    let snapshot = ValidatedInventorySnapshot::new(
        InventorySnapshot {
            identity_version: IDENTITY_VERSION,
            normalization_version: NORMALIZATION_VERSION,
            scope_id: "example-tenant".into(),
            runs: vec![CollectionRun {
                id: "run-1".into(),
                source_id: "collector".into(),
                scope_id: "example-tenant".into(),
                collected_at_unix_secs: NOW - 10,
                completeness: CollectionCompleteness::Complete,
            }],
            evidence: vec![EvidenceRecord {
                id: "source-1".into(),
                run_id: "run-1".into(),
                source_id: "collector".into(),
                basis: EvidenceBasis::Direct,
                confidence_bps: 9500,
                observed_at_unix_secs: NOW - 10,
            }],
            observations: vec![],
            absences: vec![],
        },
        &limits,
    )?;
    let graph = EvidenceGraph::new(
        &snapshot,
        vec![
            GraphNode {
                id: "client".into(),
                kind: GraphNodeKind::System,
                evidence_ids: vec!["source-1".into()],
                observation_id: None,
                observation_kind: None,
            },
            GraphNode {
                id: "server".into(),
                kind: GraphNodeKind::System,
                evidence_ids: vec!["source-1".into()],
                observation_id: None,
                observation_kind: None,
            },
        ],
        vec![],
        &limits,
    )?;
    let target = TargetProfile::new(
        TargetProfileDraft {
            schema_version: TARGET_PROFILE_VERSION,
            profile_id: "pqc-target".into(),
            revision: 1,
            scope_id: "example-tenant".into(),
            provenance: ProfileProvenance {
                issuer_id: "owner".into(),
                document_id: "approved-target".into(),
                revision: "1".into(),
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
                protocol_id: "example-protocol".into(),
                revision: "rev-1".into(),
                role: AlgorithmRole::KeyEncapsulation,
                algorithm: KnownAlgorithm::MlKem1024,
                hybrid: None,
            }],
            certificates: vec![],
            cnsa20: None,
            deadline: None,
            expires_at_unix_secs: Some(NOW + 100),
        },
        &limits,
        Some(NOW),
    )?;
    let initiator = catalog("provider-client", "runtime-client", &limits)?;
    let responder = catalog("provider-server", "runtime-server", &limits)?;
    let request = CompatibilityRequest {
        schema_version: COMPATIBILITY_ANALYSIS_VERSION,
        scope_id: "example-tenant".into(),
        expected_graph_digest: graph.fingerprint(),
        expected_target_digest: target.digest(),
        expected_initiator_catalog_digest: initiator.digest(),
        expected_responder_catalog_digest: responder.digest(),
        initiator: EndpointIdentity {
            system_node_id: "client".into(),
            provider_id: "provider-client".into(),
            product_id: "node".into(),
            product_version: "1.0".into(),
            platform_id: "linux".into(),
            runtime_id: "runtime-client".into(),
        },
        responder: EndpointIdentity {
            system_node_id: "server".into(),
            provider_id: "provider-server".into(),
            product_id: "node".into(),
            product_version: "1.0".into(),
            platform_id: "linux".into(),
            runtime_id: "runtime-server".into(),
        },
        protocol_id: "example-protocol".into(),
        protocol_revision: "rev-1".into(),
        extension_revision: "extension-1".into(),
        algorithm: KnownAlgorithm::MlKem1024,
        role: AlgorithmRole::KeyEncapsulation,
        certificate: None,
        hybrid: None,
        classical_fallback: false,
        observations: vec![],
    };

    let result = CompatibilityAnalyzer::analyze(
        &request, &graph, &target, &initiator, &responder, NOW, &limits,
    )?;
    if result.status() != CompatibilityStatus::Unknown {
        return Err("a missing peer link and handshake must never establish compatibility".into());
    }

    println!("status: {:?}", result.status());
    println!("digest: {}", result.digest().as_identifier());
    for finding in result.findings() {
        println!("finding: {:?} {:?}", finding.subject, finding.code);
    }
    for required in result.prerequisites() {
        println!("required: {required:?}");
    }
    println!("No protocol negotiation was authenticated; this is not an authorization decision.");
    Ok(())
}
