#![allow(clippy::unwrap_used, clippy::expect_used)] // Test fixtures intentionally assert construction success.
//! Offline consumer acceptance for unverified peer, protocol and PKI evidence.
use cryptoshift::*;

const TIME: i64 = 1_800_000_000;

fn limits() -> Limits {
    Limits::default()
}

fn fixture() -> (
    EvidenceGraph,
    TargetProfile,
    CapabilityCatalog,
    CapabilityCatalog,
    CompatibilityRequest,
) {
    let l = limits();
    let inventory = ValidatedInventorySnapshot::new(
        InventorySnapshot {
            identity_version: IDENTITY_VERSION,
            normalization_version: NORMALIZATION_VERSION,
            scope_id: "tenant-a".into(),
            runs: vec![CollectionRun {
                id: "run1".into(),
                source_id: "collector".into(),
                scope_id: "tenant-a".into(),
                collected_at_unix_secs: TIME - 100,
                completeness: CollectionCompleteness::Complete,
            }],
            evidence: vec![EvidenceRecord {
                id: "ev1".into(),
                run_id: "run1".into(),
                source_id: "collector".into(),
                basis: EvidenceBasis::Direct,
                confidence_bps: 9500,
                observed_at_unix_secs: TIME - 100,
            }],
            observations: vec![],
            absences: vec![],
        },
        &l,
    )
    .unwrap();
    let graph = EvidenceGraph::new(
        &inventory,
        vec![
            GraphNode {
                id: "a".into(),
                kind: GraphNodeKind::System,
                evidence_ids: vec!["ev1".into()],
                observation_id: None,
                observation_kind: None,
            },
            GraphNode {
                id: "b".into(),
                kind: GraphNodeKind::System,
                evidence_ids: vec!["ev1".into()],
                observation_id: None,
                observation_kind: None,
            },
        ],
        vec![],
        &l,
    )
    .unwrap();
    let profile = TargetProfile::new(
        TargetProfileDraft {
            schema_version: TARGET_PROFILE_VERSION,
            profile_id: "target".into(),
            revision: 1,
            scope_id: "tenant-a".into(),
            provenance: ProfileProvenance {
                issuer_id: "policy".into(),
                document_id: "requirements".into(),
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
                protocol_id: "protocol".into(),
                revision: "1".into(),
                role: AlgorithmRole::KeyEncapsulation,
                algorithm: KnownAlgorithm::MlKem1024,
                hybrid: None,
            }],
            certificates: vec![],
            cnsa20: None,
            deadline: None,
            expires_at_unix_secs: Some(TIME + 500),
        },
        &l,
        Some(TIME),
    )
    .unwrap();
    let make_catalog = |provider: &str, runtime: &str| {
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
                        evidence_id: format!("ev-{provider}"),
                        source_revision: "1".into(),
                        basis: CapabilityEvidenceBasis::VendorDocumentation,
                        verification: EvidenceVerification::Unverified,
                        verification_reference: None,
                        artifact_digest: None,
                        observed_at_unix_secs: TIME - 200,
                        expires_at_unix_secs: Some(TIME + 300),
                    },
                }],
            },
            &l,
            Some(TIME),
        )
        .unwrap()
    };
    let left = make_catalog("vendor-a", "runtime-a");
    let right = make_catalog("vendor-b", "runtime-b");
    let request = CompatibilityRequest {
        schema_version: COMPATIBILITY_ANALYSIS_VERSION,
        scope_id: "tenant-a".into(),
        expected_graph_digest: graph.fingerprint(),
        expected_target_digest: profile.digest(),
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
        protocol_id: "protocol".into(),
        protocol_revision: "1".into(),
        extension_revision: "ext-1".into(),
        algorithm: KnownAlgorithm::MlKem1024,
        role: AlgorithmRole::KeyEncapsulation,
        certificate: None,
        hybrid: None,
        classical_fallback: false,
        observations: vec![],
    };
    (graph, profile, left, right, request)
}
fn analyze(
    graph: &EvidenceGraph,
    target: &TargetProfile,
    left: &CapabilityCatalog,
    right: &CapabilityCatalog,
    req: &CompatibilityRequest,
) -> Result<CompatibilityAnalysis, Diagnostic> {
    CompatibilityAnalyzer::analyze(req, graph, target, left, right, TIME, &limits())
}
fn src(id: &str) -> CompatibilitySource {
    CompatibilitySource {
        source_id: "monitor".into(),
        evidence_id: id.into(),
        source_revision: "1".into(),
        observed_at_unix_secs: TIME - 10,
        expires_at_unix_secs: Some(TIME + 10),
        verification_reference: Some("unverified-host-receipt".into()),
        artifact_digest: None,
    }
}
fn link() -> CompatibilityObservation {
    CompatibilityObservation::PeerLink(PeerLinkObservation {
        source: src("link"),
        scope_id: "tenant-a".into(),
        initiator_node_id: "a".into(),
        responder_node_id: "b".into(),
        protocol_id: "protocol".into(),
        protocol_revision: "1".into(),
    })
}
fn negotiation() -> CompatibilityObservation {
    CompatibilityObservation::Negotiation(NegotiationObservation {
        source: src("handshake"),
        scope_id: "tenant-a".into(),
        initiator_runtime_id: "runtime-a".into(),
        responder_runtime_id: "runtime-b".into(),
        protocol_id: "protocol".into(),
        protocol_revision: "1".into(),
        extension_revision: "ext-1".into(),
        initiator_offers: vec![KnownAlgorithm::MlKem1024],
        responder_offers: vec![KnownAlgorithm::MlKem1024],
        selected_algorithm: Some(KnownAlgorithm::MlKem1024),
        selected_signature: None,
        hybrid_companion_id: None,
        hybrid_combiner_reference: None,
        classical_fallback_used: false,
    })
}
fn has(report: &CompatibilityAnalysis, code: CompatibilityCode) -> bool {
    report.findings().iter().any(|finding| finding.code == code)
}

#[test]
fn advertised_algorithms_without_negotiation_never_compatible() {
    let (g, t, l, r, req) = fixture();
    let result = analyze(&g, &t, &l, &r, &req).unwrap();
    assert_eq!(result.status(), CompatibilityStatus::Unknown);
    assert!(has(&result, CompatibilityCode::NegotiationMissing));
    assert!(has(&result, CompatibilityCode::PeerLinkMissing));
    assert_eq!(result.bindings().graph_digest, g.fingerprint());
}

#[test]
fn asserted_handshake_and_host_receipt_do_not_prove_compatibility() {
    let (g, t, l, r, mut req) = fixture();
    req.observations = vec![link(), negotiation()];
    let result = analyze(&g, &t, &l, &r, &req).unwrap();
    assert_eq!(result.status(), CompatibilityStatus::Conditional);
    assert!(has(&result, CompatibilityCode::NegotiationUnauthenticated));
    assert!(
        result
            .prerequisites()
            .contains(&CompatibilityPrerequisite::VerifyNegotiation)
    );
}

#[test]
fn unsupported_algorithm_version_and_tenant_do_not_inherit_evidence() {
    let (g, t, l, r, mut req) = fixture();
    req.responder.product_version = "2".into();
    let result = analyze(&g, &t, &l, &r, &req).unwrap();
    assert_eq!(result.status(), CompatibilityStatus::Unknown);
    assert!(has(&result, CompatibilityCode::CapabilityMissing));
    req.scope_id = "tenant-b".into();
    assert_eq!(
        analyze(&g, &t, &l, &r, &req).unwrap_err().code,
        DiagnosticCode::InvalidReference
    );
}

#[test]
fn unapproved_fallback_and_protocol_are_incompatible() {
    let (g, t, l, r, mut req) = fixture();
    req.classical_fallback = true;
    let result = analyze(&g, &t, &l, &r, &req).unwrap();
    assert_eq!(result.status(), CompatibilityStatus::Incompatible);
    assert!(has(&result, CompatibilityCode::DowngradeRejected));
    req.classical_fallback = false;
    req.protocol_revision = "2".into();
    let result = analyze(&g, &t, &l, &r, &req).unwrap();
    assert_eq!(result.status(), CompatibilityStatus::Incompatible);
    assert!(has(&result, CompatibilityCode::ProtocolNotApproved));
}

#[test]
fn wrong_graph_digest_cannot_be_replayed() {
    let (g, t, l, r, mut req) = fixture();
    req.expected_graph_digest = SnapshotDigest::from_bytes([0; 32]);
    assert_eq!(
        analyze(&g, &t, &l, &r, &req).unwrap_err().code,
        DiagnosticCode::IntegrityMismatch
    );
}

#[test]
fn stale_source_and_cross_runtime_claim_fail_closed() {
    let (g, t, l, r, mut req) = fixture();
    let mut hand = negotiation();
    if let CompatibilityObservation::Negotiation(ref mut item) = hand {
        item.source.expires_at_unix_secs = Some(TIME);
    }
    req.observations = vec![link(), hand];
    let result = analyze(&g, &t, &l, &r, &req).unwrap();
    assert_eq!(result.status(), CompatibilityStatus::Unknown);
    assert!(has(&result, CompatibilityCode::EvidenceStale));
    req.observations = vec![link(), negotiation()];
    if let CompatibilityObservation::Negotiation(ref mut item) = req.observations[1] {
        item.responder_runtime_id = "different-runtime".into();
    }
    let result = analyze(&g, &t, &l, &r, &req).unwrap();
    assert_eq!(result.status(), CompatibilityStatus::Unknown);
    assert!(has(&result, CompatibilityCode::EvidenceBindingMismatch));
}

#[test]
fn ordering_of_distinct_observations_and_offer_lists_is_canonical() {
    let (g, t, l, r, mut req) = fixture();
    req.observations = vec![link(), negotiation()];
    let first = analyze(&g, &t, &l, &r, &req).unwrap();
    req.observations.reverse();
    let second = analyze(&g, &t, &l, &r, &req).unwrap();
    assert_eq!(first.digest(), second.digest());
    assert_eq!(
        first.export(&limits()).unwrap(),
        second.export(&limits()).unwrap()
    );
}

#[test]
fn duplicate_source_namespaces_and_oversized_limits_are_rejected() {
    let (g, t, l, r, mut req) = fixture();
    req.observations = vec![link(), link()];
    assert_eq!(
        analyze(&g, &t, &l, &r, &req).unwrap_err().code,
        DiagnosticCode::DuplicateRecord
    );
    req.observations = vec![link(), negotiation()];
    let mut cap = limits();
    cap.max_evidence_records = 1;
    assert_eq!(
        CompatibilityAnalyzer::analyze(&req, &g, &t, &l, &r, TIME, &cap)
            .unwrap_err()
            .code,
        DiagnosticCode::ResourceLimitExceeded
    );
}
