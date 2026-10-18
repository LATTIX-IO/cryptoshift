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


fn with_certificate(target: &TargetProfile, request: &mut CompatibilityRequest) -> TargetProfile {
    let mut draft = target.content().clone();
    draft.standards.push(StandardEdition::Fips204_2024);
    draft.algorithms.push(AlgorithmConstraint {
        algorithm: KnownAlgorithm::MlDsa87,
        role: AlgorithmRole::Signature,
        minimum_category: Some(SecurityCategory::Five),
        disposition: ConstraintDisposition::Required,
    });
    draft.certificates.push(CertificateConstraint {
        profile_id: "x509-profile".into(),
        revision: "v1".into(),
        signature_algorithm: KnownAlgorithm::MlDsa87,
        specification_reference: "pki-requirement-1".into(),
    });
    let changed = TargetProfile::new(draft, &limits(), Some(TIME)).unwrap();
    request.expected_target_digest = changed.digest();
    request.certificate = Some(CertificateSelection {
        profile_id: "x509-profile".into(),
        revision: "v1".into(),
        certificate_id: "leaf-1".into(),
        chain_id: "chain-1".into(),
        trust_anchor_id: "root-1".into(),
        signature_algorithm: KnownAlgorithm::MlDsa87,
    });
    changed
}

fn with_hybrid(target: &TargetProfile, request: &mut CompatibilityRequest) -> TargetProfile {
    let mut draft = target.content().clone();
    draft.protocols[0].hybrid = Some(HybridConstruction {
        companion_algorithm_id: "X25519".into(),
        combiner_reference: "hybrid-combiner-v1".into(),
    });
    let changed = TargetProfile::new(draft, &limits(), Some(TIME)).unwrap();
    request.expected_target_digest = changed.digest();
    request.hybrid = Some(HybridSelection {
        companion_algorithm_id: "X25519".into(),
        combiner_reference: "hybrid-combiner-v1".into(),
    });
    changed
}

fn pki() -> CompatibilityObservation {
    CompatibilityObservation::Pki(PkiObservation {
        source: src("chain-proof"),
        scope_id: "tenant-a".into(),
        initiator_runtime_id: "runtime-a".into(),
        responder_runtime_id: "runtime-b".into(),
        profile_id: "x509-profile".into(),
        revision: "v1".into(),
        certificate_id: "leaf-1".into(),
        chain_id: "chain-1".into(),
        trust_anchor_id: "root-1".into(),
        signature_algorithm: KnownAlgorithm::MlDsa87,
        chain_valid: Some(true),
        revocation_checked: true,
        validation_at_unix_secs: TIME - 10,
    })
}

#[test]
fn certificate_and_chain_evidence_remain_untrusted_even_when_claimed_valid() {
    let (g, t, l, r, mut req) = fixture();
    let target = with_certificate(&t, &mut req);
    let mut hand = negotiation();
    if let CompatibilityObservation::Negotiation(ref mut obs) = hand {
        obs.selected_signature = Some(KnownAlgorithm::MlDsa87);
    }
    req.observations = vec![link(), hand, pki()];
    let report = analyze(&g, &target, &l, &r, &req).unwrap();
    assert_eq!(report.status(), CompatibilityStatus::Conditional);
    assert!(report.prerequisites().contains(&CompatibilityPrerequisite::VerifyPki));
    assert!(report.prerequisites().contains(&CompatibilityPrerequisite::VerifyNegotiation));
    assert!(has(&report, CompatibilityCode::PkiUnverified));
    assert!(!has(&report, CompatibilityCode::PkiMismatch));
}

#[test]
fn missing_or_wrong_chain_anchor_and_signature_cannot_pass() {
    let (g, t, l, r, mut req) = fixture();
    let target = with_certificate(&t, &mut req);
    req.observations = vec![link(), negotiation()];
    let absent = analyze(&g, &target, &l, &r, &req).unwrap();
    assert_eq!(absent.status(), CompatibilityStatus::Unknown);
    assert!(has(&absent, CompatibilityCode::PkiMissing));

    let mut wrong = pki();
    if let CompatibilityObservation::Pki(ref mut obs) = wrong {
        obs.trust_anchor_id = "different-root".into();
        obs.chain_valid = Some(false);
        obs.revocation_checked = false;
    }
    req.observations.push(wrong);
    let mismatched = analyze(&g, &target, &l, &r, &req).unwrap();
    assert_eq!(mismatched.status(), CompatibilityStatus::Unknown);
    assert!(has(&mismatched, CompatibilityCode::PkiMismatch));
    assert!(has(&mismatched, CompatibilityCode::PkiUnverified));

    req.certificate.as_mut().unwrap().signature_algorithm = KnownAlgorithm::MlDsa65;
    let unapproved = analyze(&g, &target, &l, &r, &req).unwrap();
    assert_eq!(unapproved.status(), CompatibilityStatus::Incompatible);
    assert!(has(&unapproved, CompatibilityCode::CertificateNotApproved));
}

#[test]
fn certificate_evidence_from_future_or_wrong_runtime_is_unknown() {
    let (g, t, l, r, mut req) = fixture();
    let target = with_certificate(&t, &mut req);
    let mut bad = pki();
    if let CompatibilityObservation::Pki(ref mut obs) = bad {
        obs.source.observed_at_unix_secs = TIME + 1;
        obs.validation_at_unix_secs = TIME + 1;
    }
    req.observations = vec![link(), negotiation(), bad];
    let future = analyze(&g, &target, &l, &r, &req).unwrap();
    assert_eq!(future.status(), CompatibilityStatus::Unknown);
    assert!(has(&future, CompatibilityCode::EvidenceStale));

    if let CompatibilityObservation::Pki(ref mut obs) = req.observations[2] {
        obs.source.observed_at_unix_secs = TIME - 10;
        obs.validation_at_unix_secs = TIME - 10;
        obs.responder_runtime_id = "foreign-runtime".into();
    }
    let foreign = analyze(&g, &target, &l, &r, &req).unwrap();
    assert_eq!(foreign.status(), CompatibilityStatus::Unknown);
    assert!(has(&foreign, CompatibilityCode::EvidenceBindingMismatch));
}

#[test]
fn hybrid_is_only_transitional_with_named_combiner_and_peer_binding() {
    let (g, t, l, r, mut req) = fixture();
    let target = with_hybrid(&t, &mut req);
    let mut hand = negotiation();
    if let CompatibilityObservation::Negotiation(ref mut obs) = hand {
        obs.hybrid_companion_id = Some("X25519".into());
        obs.hybrid_combiner_reference = Some("hybrid-combiner-v1".into());
    }
    req.observations = vec![link(), hand];
    let report = analyze(&g, &target, &l, &r, &req).unwrap();
    assert_eq!(report.status(), CompatibilityStatus::Transitional);
    assert!(report.prerequisites().contains(&CompatibilityPrerequisite::VerifyHybrid));
    assert!(report.prerequisites().contains(&CompatibilityPrerequisite::VerifyNegotiation));

    if let CompatibilityObservation::Negotiation(ref mut obs) = req.observations[1] {
        obs.hybrid_combiner_reference = Some("unreviewed-combiner".into());
    }
    let unproven = analyze(&g, &target, &l, &r, &req).unwrap();
    assert_eq!(unproven.status(), CompatibilityStatus::Unknown);
    assert!(has(&unproven, CompatibilityCode::HybridProofMissing));

    req.classical_fallback = true;
    let downgrade = analyze(&g, &target, &l, &r, &req).unwrap();
    assert_eq!(downgrade.status(), CompatibilityStatus::Incompatible);
    assert!(has(&downgrade, CompatibilityCode::DowngradeRejected));
}

#[test]
fn hybrid_absent_from_target_is_incompatible_even_if_peer_claims_it() {
    let (g, t, l, r, mut req) = fixture();
    req.hybrid = Some(HybridSelection {
        companion_algorithm_id: "X25519".into(),
        combiner_reference: "unknown-combiner".into(),
    });
    req.observations = vec![link(), negotiation()];
    let report = analyze(&g, &t, &l, &r, &req).unwrap();
    assert_eq!(report.status(), CompatibilityStatus::Incompatible);
    assert!(has(&report, CompatibilityCode::HybridNotApproved));
}

#[test]
fn contradictory_negotiation_sources_preserve_both_namespaces() {
    let (g, t, l, r, mut req) = fixture();
    let mut conflicting = negotiation();
    if let CompatibilityObservation::Negotiation(ref mut item) = conflicting {
        item.source.source_id = "other-monitor".into();
        item.source.evidence_id = "handshake".into();
        item.selected_algorithm = Some(KnownAlgorithm::MlKem768);
    }
    req.observations = vec![link(), negotiation(), conflicting];
    let report = analyze(&g, &t, &l, &r, &req).unwrap();
    assert_eq!(report.status(), CompatibilityStatus::Unknown);
    assert!(has(&report, CompatibilityCode::EvidenceConflict));
    assert!(has(&report, CompatibilityCode::NegotiationMismatch));
    assert!(report.evidence_refs().iter().any(|ref_| ref_.source_id == "monitor" && ref_.evidence_id == "handshake"));
    assert!(report.evidence_refs().iter().any(|ref_| ref_.source_id == "other-monitor" && ref_.evidence_id == "handshake"));
}

#[test]
fn equivalent_renegotiation_offer_order_is_canonical_but_duplicates_fail() {
    let (g, t, l, r, mut req) = fixture();
    let mut hand = negotiation();
    if let CompatibilityObservation::Negotiation(ref mut item) = hand {
        item.initiator_offers = vec![KnownAlgorithm::MlKem1024, KnownAlgorithm::MlKem768];
        item.responder_offers = vec![KnownAlgorithm::MlKem768, KnownAlgorithm::MlKem1024];
    }
    req.observations = vec![link(), hand];
    let first = analyze(&g, &t, &l, &r, &req).unwrap();
    if let CompatibilityObservation::Negotiation(ref mut item) = req.observations[1] {
        item.initiator_offers.reverse();
        item.responder_offers.reverse();
    }
    let second = analyze(&g, &t, &l, &r, &req).unwrap();
    assert_eq!(first.digest(), second.digest());

    if let CompatibilityObservation::Negotiation(ref mut item) = req.observations[1] {
        item.responder_offers.push(KnownAlgorithm::MlKem1024);
    }
    assert_eq!(analyze(&g, &t, &l, &r, &req).unwrap_err().code, DiagnosticCode::DuplicateRecord);
}

#[test]
fn source_provenance_and_result_digest_change_on_semantic_revision() {
    let (g, t, l, r, mut req) = fixture();
    req.observations = vec![link(), negotiation()];
    let first = analyze(&g, &t, &l, &r, &req).unwrap();
    if let CompatibilityObservation::Negotiation(ref mut item) = req.observations[1] {
        item.source.source_revision = "2".into();
    }
    let next = analyze(&g, &t, &l, &r, &req).unwrap();
    assert_ne!(first.digest(), next.digest());
}

#[test]
fn report_output_and_diagnostics_are_bounded_before_commit() {
    let (g, t, l, r, mut req) = fixture();
    req.observations = vec![link(), negotiation()];
    let result = analyze(&g, &t, &l, &r, &req).unwrap();
    let bytes = result.export(&limits()).unwrap();
    assert_eq!(SnapshotDigest::from_bytes(result.digest().as_bytes()), result.digest());
    let mut caps = limits();
    caps.max_export_bytes = bytes.len() - 1;
    let err = CompatibilityAnalyzer::analyze(&req, &g, &t, &l, &r, TIME, &caps).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ResourceLimitExceeded);
    let mut caps = limits();
    caps.max_diagnostics = 1;
    assert_eq!(CompatibilityAnalyzer::analyze(&req, &g, &t, &l, &r, TIME, &caps).unwrap_err().code, DiagnosticCode::ResourceLimitExceeded);
}

#[test]
fn invalid_role_and_stale_target_or_catalog_claims_fail_closed() {
    let (g, t, l, r, mut req) = fixture();
    req.role = AlgorithmRole::Signature;
    assert_eq!(analyze(&g, &t, &l, &r, &req).unwrap_err().code, DiagnosticCode::InvalidStateTransition);
    req.role = AlgorithmRole::KeyEncapsulation;
    let stale_catalog = CompatibilityAnalyzer::analyze(&req, &g, &t, &l, &r, TIME + 301, &limits()).unwrap();
    assert_eq!(stale_catalog.status(), CompatibilityStatus::Unknown);
    assert!(has(&stale_catalog, CompatibilityCode::CapabilityStale));
    assert_eq!(CompatibilityAnalyzer::analyze(&req, &g, &t, &l, &r, TIME + 501, &limits()).unwrap_err().code, DiagnosticCode::StaleCriticalProfile);
}

#[test]
fn frozen_v1_compatibility_export_digest_and_length() {
    let (g, t, l, r, mut req) = fixture();
    req.observations = vec![link(), negotiation()];
    let report = analyze(&g, &t, &l, &r, &req).unwrap();
    let bytes = report.export(&limits()).unwrap();
    assert!(bytes.starts_with(b"CSHIFT_COMPATIBILITY_V1"));
    let observed = format!("{} {}", report.digest().as_identifier(), bytes.len());
    assert_eq!(observed, include_str!("fixtures/compatibility_v1.sha256").trim());
}


fn graph_for_scope(scope: &str, with_dependency: bool) -> EvidenceGraph {
    let l = limits();
    let inventory = ValidatedInventorySnapshot::new(
        InventorySnapshot {
            identity_version: IDENTITY_VERSION,
            normalization_version: NORMALIZATION_VERSION,
            scope_id: scope.to_owned(),
            runs: vec![CollectionRun {
                id: "run1".into(),
                source_id: "collector".into(),
                scope_id: scope.to_owned(),
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
    let nodes = ["a", "b"]
        .iter()
        .map(|node_id| GraphNode {
            id: (*node_id).into(),
            kind: GraphNodeKind::System,
            evidence_ids: vec!["ev1".into()],
            observation_id: None,
            observation_kind: None,
        })
        .collect();
    let edges = if with_dependency {
        vec![GraphEdge {
            from: "a".into(),
            to: "b".into(),
            relation: GraphRelation::DependsOn,
            evidence_ids: vec!["ev1".into()],
        }]
    } else {
        vec![]
    };
    EvidenceGraph::new(&inventory, nodes, edges, &l).unwrap()
}

#[test]
fn matching_graph_digest_cannot_mask_cross_tenant_inventory() {
    let (_g, t, l, r, mut req) = fixture();
    let foreign = graph_for_scope("tenant-b", false);
    req.expected_graph_digest = foreign.fingerprint();
    assert_eq!(foreign.source_scope_id(), "tenant-b");
    assert_eq!(
        analyze(&foreign, &t, &l, &r, &req).unwrap_err().code,
        DiagnosticCode::InvalidReference
    );
}

#[test]
fn changing_graph_topology_invalidates_pinned_dependency_context() {
    let (_g, t, l, r, req) = fixture();
    let changed = graph_for_scope("tenant-a", true);
    assert_eq!(
        analyze(&changed, &t, &l, &r, &req).unwrap_err().code,
        DiagnosticCode::IntegrityMismatch
    );
}

#[test]
fn invalid_provenance_is_rejected_without_echoing_sensitive_input() {
    let (g, t, l, r, mut req) = fixture();
    let mut suspect = link();
    if let CompatibilityObservation::PeerLink(ref mut value) = suspect {
        value.source.source_id = "password=secret value".into();
    }
    req.observations.push(suspect);
    let error = analyze(&g, &t, &l, &r, &req).unwrap_err();
    assert_eq!(error.code, DiagnosticCode::InvalidIdentifier);
    assert!(!error.to_string().contains("secret"));
}

#[test]
fn all_known_algorithm_candidates_remain_non_authoritative() {
    let (g, t, l, r, mut req) = fixture();
    for algorithm in KnownAlgorithm::ALL {
        req.algorithm = algorithm;
        req.role = algorithm.role();
        let report = analyze(&g, &t, &l, &r, &req).unwrap();
        assert_ne!(report.status(), CompatibilityStatus::Compatible);
    }
}
