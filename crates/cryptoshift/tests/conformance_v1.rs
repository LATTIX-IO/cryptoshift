//! FOSS-448 Gate E2: external-API conformance of synthetic enterprise scenarios.
//! Fixture pins check regression stability, not external producer authentication.
#![allow(clippy::unwrap_used, clippy::expect_used)] // Synthetic, bounded acceptance corpus.

use cryptoshift::*;
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;

const NOW: i64 = 1_800_000_000;
const TENANT: &str = "synthetic-enterprise";
const PRODUCER: &str = "synthetic-collector";
const CASES: &str = include_str!("../../../tests/conformance/v1/scenarios.tsv");
const GOLDEN: &str = include_str!("../../../tests/conformance/v1/full_pipeline.golden");

#[derive(Clone, Copy)]
struct Case {
    id: &'static str,
    system: &'static str,
    algorithm: &'static str,
    kind: CryptoUseKind,
    basis: EvidenceBasis,
    complete: CollectionCompleteness,
}

fn cases() -> Vec<Case> {
    let mut lines = CASES
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    assert_eq!(
        lines.next(),
        Some("v1|scenario|system|algorithm|use|evidence|collection"),
        "fixture schema/revision must be reviewed before updating the reader"
    );
    let cases: Vec<_> = lines
        .map(|line| {
            let columns: Vec<_> = line.split('|').collect();
            assert_eq!(columns.len(), 7, "fixture has unknown or missing fields");
            assert_eq!(columns[0], "v1");
            Case {
                id: columns[1],
                system: columns[2],
                algorithm: columns[3],
                kind: match columns[4] {
                    "ActiveUse" => CryptoUseKind::ActiveUse,
                    "ConfiguredProtocol" => CryptoUseKind::ConfiguredProtocol,
                    "LibraryCapability" => CryptoUseKind::LibraryCapability,
                    _ => panic!("unknown observation classification"),
                },
                basis: match columns[5] {
                    "Direct" => EvidenceBasis::Direct,
                    "Inferred" => EvidenceBasis::Inferred,
                    _ => panic!("unknown evidence basis"),
                },
                complete: match columns[6] {
                    "Complete" => CollectionCompleteness::Complete,
                    "Partial" => CollectionCompleteness::Partial,
                    _ => panic!("unknown collection state"),
                },
            }
        })
        .collect();
    assert_eq!(
        cases.len(),
        5,
        "all five enterprise domains must be present"
    );
    assert_eq!(
        cases
            .iter()
            .map(|c| c.id)
            .collect::<std::collections::BTreeSet<_>>(),
        ["transport", "pki", "codesign", "kms", "vendor"]
            .into_iter()
            .collect()
    );
    cases
}

fn shuffled<T>(items: &mut [T], seed: u64) {
    let mut state = seed | 1;
    for i in (1..items.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        items.swap(i, (state as usize) % (i + 1));
    }
}

fn node(id: &str, kind: GraphNodeKind, ev: &str) -> GraphNode {
    GraphNode {
        id: id.into(),
        kind,
        evidence_ids: vec![ev.into()],
        observation_id: None,
        observation_kind: None,
    }
}

fn edge(from: &str, to: &str, relation: GraphRelation, ev: &str) -> GraphEdge {
    GraphEdge {
        from: from.into(),
        to: to.into(),
        relation,
        evidence_ids: vec![ev.into()],
    }
}

fn target(limits: &Limits) -> TargetProfile {
    TargetProfile::new(
        TargetProfileDraft {
            schema_version: TARGET_PROFILE_VERSION,
            profile_id: "enterprise-pqc-target".into(),
            revision: 1,
            scope_id: TENANT.into(),
            provenance: ProfileProvenance {
                issuer_id: "synthetic-policy-office".into(),
                document_id: "review-only-requirements".into(),
                revision: "r1".into(),
                source_digest: None,
            },
            standards: vec![StandardEdition::Fips203_2024, StandardEdition::Fips204_2024],
            algorithms: vec![
                AlgorithmConstraint {
                    algorithm: KnownAlgorithm::MlKem1024,
                    role: AlgorithmRole::KeyEncapsulation,
                    minimum_category: Some(SecurityCategory::Five),
                    disposition: ConstraintDisposition::Required,
                },
                AlgorithmConstraint {
                    algorithm: KnownAlgorithm::MlDsa87,
                    role: AlgorithmRole::Signature,
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
            protocols: vec![ProtocolConstraint {
                protocol_id: "enterprise-tls".into(),
                revision: "r1".into(),
                role: AlgorithmRole::KeyEncapsulation,
                algorithm: KnownAlgorithm::MlKem1024,
                hybrid: None,
            }],
            certificates: vec![CertificateConstraint {
                profile_id: "pki-transition".into(),
                revision: "r1".into(),
                signature_algorithm: KnownAlgorithm::MlDsa87,
                specification_reference: "synthetic-cert-policy".into(),
            }],
            cnsa20: None,
            deadline: None,
            expires_at_unix_secs: Some(NOW + 600),
        },
        limits,
        Some(NOW),
    )
    .unwrap()
}

fn vendor_catalog(provider: &str, runtime: &str, limits: &Limits) -> CapabilityCatalog {
    CapabilityCatalog::new(
        CapabilityCatalogDraft {
            schema_version: CAPABILITY_CATALOG_VERSION,
            catalog_id: format!("catalog-{provider}"),
            revision: 1,
            scope_id: TENANT.into(),
            provenance: ProfileProvenance {
                issuer_id: "synthetic-vendor".into(),
                document_id: "product-roadmap".into(),
                revision: "r1".into(),
                source_digest: None,
            },
            records: vec![CapabilityRecord {
                record_id: format!("vendor-claim-{provider}"),
                provider_id: provider.into(),
                product_id: "transport-stack".into(),
                product_version: "r1".into(),
                platform_id: "portable".into(),
                scope_id: TENANT.into(),
                runtime_id: Some(runtime.into()),
                algorithm: KnownAlgorithm::MlKem1024,
                role: AlgorithmRole::KeyEncapsulation,
                state: CapabilityState::Available,
                evidence: CapabilityEvidence {
                    source_id: "synthetic-vendor".into(),
                    evidence_id: format!("catalog-entry-{provider}"),
                    source_revision: "r1".into(),
                    basis: CapabilityEvidenceBasis::VendorDocumentation,
                    verification: EvidenceVerification::Unverified,
                    verification_reference: None,
                    artifact_digest: None,
                    observed_at_unix_secs: NOW - 100,
                    expires_at_unix_secs: Some(NOW + 300),
                },
            }],
        },
        limits,
        Some(NOW),
    )
    .unwrap()
}

fn peer_request(
    graph: &EvidenceGraph,
    target: &TargetProfile,
    left: &CapabilityCatalog,
    right: &CapabilityCatalog,
) -> CompatibilityRequest {
    CompatibilityRequest {
        schema_version: COMPATIBILITY_ANALYSIS_VERSION,
        scope_id: TENANT.into(),
        expected_graph_digest: graph.fingerprint(),
        expected_target_digest: target.digest(),
        expected_initiator_catalog_digest: left.digest(),
        expected_responder_catalog_digest: right.digest(),
        initiator: EndpointIdentity {
            system_node_id: "edge-gateway".into(),
            provider_id: "client-vendor".into(),
            product_id: "transport-stack".into(),
            product_version: "r1".into(),
            platform_id: "portable".into(),
            runtime_id: "gateway-runtime".into(),
        },
        responder: EndpointIdentity {
            system_node_id: "cloud-kms".into(),
            provider_id: "kms-vendor".into(),
            product_id: "transport-stack".into(),
            product_version: "r1".into(),
            platform_id: "portable".into(),
            runtime_id: "kms-runtime".into(),
        },
        protocol_id: "enterprise-tls".into(),
        protocol_revision: "r1".into(),
        extension_revision: "ext-pq1".into(),
        algorithm: KnownAlgorithm::MlKem1024,
        role: AlgorithmRole::KeyEncapsulation,
        certificate: Some(CertificateSelection {
            profile_id: "pki-transition".into(),
            revision: "r1".into(),
            certificate_id: "cert-chain".into(),
            chain_id: "enterprise-chain".into(),
            trust_anchor_id: "root-ca".into(),
            signature_algorithm: KnownAlgorithm::MlDsa87,
        }),
        hybrid: None,
        classical_fallback: false,
        observations: vec![],
    }
}

fn policy_input(target: &TargetProfile) -> NeutralPolicyInput {
    let evidence = |id: &str| {
        vec![NeutralPolicyEvidence {
            source_id: "synthetic-policy".into(),
            evidence_id: id.into(),
            source_revision: "r1".into(),
        }]
    };
    NeutralPolicyInput {
        schema_version: NEUTRAL_POLICY_VERSION,
        source_id: "synthetic-policy".into(),
        policy_id: "pq-evaluation".into(),
        policy_revision: "r1".into(),
        policy_digest: SnapshotDigest::from_bytes([7; 32]),
        target_digest: target.digest(),
        scope_id: TENANT.into(),
        evaluated_at_unix_secs: NOW,
        expires_at_unix_secs: NOW + 60,
        decisions: vec![
            NeutralPolicyDecision {
                algorithm: KnownAlgorithm::MlKem1024,
                outcome: NeutralPolicyOutcome::PermitClaimed,
                reason_code: "external-allow-claim".into(),
                evidence: evidence("claimed-approval"),
            },
            NeutralPolicyDecision {
                algorithm: KnownAlgorithm::MlKem768,
                outcome: NeutralPolicyOutcome::DenyClaimed,
                reason_code: "forbidden".into(),
                evidence: evidence("source-denial"),
            },
        ],
    }
}

struct Pipeline {
    source: NeutralInventoryProjection,
    topology: DependencyTopology,
    risk: RiskReport,
    target: TargetProfile,
    left: CapabilityCatalog,
    right: CapabilityCatalog,
    compatibility: CompatibilityAnalysis,
    remediation: RemediationAnalysis,
    wave: WavePlanDraft,
    plan: MigrationPlanDraft,
    policy: NeutralPolicyReview,
}

fn build(seed: u64, changed_source: bool) -> Pipeline {
    let limits = Limits::default();
    let mut cases = cases();
    shuffled(&mut cases, seed);
    let runs = cases
        .iter()
        .map(|c| CollectionRun {
            id: format!("run-{}", c.id),
            source_id: PRODUCER.into(),
            scope_id: TENANT.into(),
            collected_at_unix_secs: NOW - 100,
            completeness: c.complete,
        })
        .collect();
    let evidence = cases
        .iter()
        .map(|c| EvidenceRecord {
            id: format!("ev-{}", c.id),
            run_id: format!("run-{}", c.id),
            source_id: PRODUCER.into(),
            basis: c.basis,
            confidence_bps: 9200,
            observed_at_unix_secs: NOW - 100,
        })
        .collect();
    let mut observations: Vec<_> = cases
        .iter()
        .map(|c| CryptoObservation {
            id: format!("obs-{}", c.id),
            asset_id: c.system.into(),
            algorithm_id: c.algorithm.into(),
            kind: c.kind,
            conflict: ConflictState::Uncontested,
            evidence_ids: vec![format!("ev-{}", c.id)],
        })
        .collect();
    // Directly reported is still a source claim, not authenticated negotiation.
    observations.push(CryptoObservation {
        id: "obs-transport-negotiated".into(),
        asset_id: "edge-gateway".into(),
        algorithm_id: KnownAlgorithm::MlKem1024.id().into(),
        kind: CryptoUseKind::NegotiatedProtocol,
        conflict: ConflictState::Uncontested,
        evidence_ids: vec!["ev-transport".into()],
    });
    if changed_source {
        observations
            .iter_mut()
            .find(|o| o.id == "obs-codesign")
            .unwrap()
            .algorithm_id = "RSA-3072".into();
    }
    let inventory = ValidatedInventorySnapshot::new(
        InventorySnapshot {
            identity_version: IDENTITY_VERSION,
            normalization_version: NORMALIZATION_VERSION,
            scope_id: TENANT.into(),
            runs,
            evidence,
            observations,
            absences: vec![],
        },
        &limits,
    )
    .unwrap();
    let mut nodes = vec![node("owner-security", GraphNodeKind::Owner, "ev-transport")];
    let mut edges = Vec::new();
    for case in &cases {
        let ev = format!("ev-{}", case.id);
        nodes.push(node(case.system, GraphNodeKind::System, &ev));
        nodes.push(GraphNode {
            id: format!("use-{}", case.id),
            kind: GraphNodeKind::CryptoUse,
            evidence_ids: vec![ev.clone()],
            observation_id: Some(format!("obs-{}", case.id)),
            observation_kind: Some(case.kind),
        });
        edges.push(edge(
            case.system,
            &format!("use-{}", case.id),
            GraphRelation::ExposesUse,
            &ev,
        ));
        edges.push(edge(
            case.system,
            "owner-security",
            GraphRelation::OwnedBy,
            &ev,
        ));
    }
    nodes.push(GraphNode {
        id: "use-transport-negotiated".into(),
        kind: GraphNodeKind::CryptoUse,
        evidence_ids: vec!["ev-transport".into()],
        observation_id: Some("obs-transport-negotiated".into()),
        observation_kind: Some(CryptoUseKind::NegotiatedProtocol),
    });
    edges.push(edge(
        "edge-gateway",
        "use-transport-negotiated",
        GraphRelation::ExposesUse,
        "ev-transport",
    ));
    for (id, kind, ev) in [
        ("cert-chain", GraphNodeKind::Certificate, "ev-pki"),
        ("root-ca", GraphNodeKind::TrustAnchor, "ev-pki"),
        ("hsm-device", GraphNodeKind::Hsm, "ev-kms"),
        ("key-reference", GraphNodeKind::Key, "ev-kms"),
        ("protected-data", GraphNodeKind::Data, "ev-kms"),
        ("external-supplier", GraphNodeKind::Vendor, "ev-vendor"),
    ] {
        nodes.push(node(id, kind, ev));
    }
    for (from, to, relation, ev) in [
        (
            "pki-service",
            "cert-chain",
            GraphRelation::UsesCertificate,
            "ev-pki",
        ),
        ("cert-chain", "root-ca", GraphRelation::IssuedBy, "ev-pki"),
        ("cloud-kms", "hsm-device", GraphRelation::UsesHsm, "ev-kms"),
        (
            "hsm-device",
            "key-reference",
            GraphRelation::HoldsKey,
            "ev-kms",
        ),
        (
            "key-reference",
            "protected-data",
            GraphRelation::ProtectsData,
            "ev-kms",
        ),
        (
            "hsm-device",
            "external-supplier",
            GraphRelation::SuppliedBy,
            "ev-vendor",
        ),
        (
            "edge-gateway",
            "cloud-kms",
            GraphRelation::DependsOn,
            "ev-transport",
        ),
        (
            "cloud-kms",
            "edge-gateway",
            GraphRelation::DependsOn,
            "ev-kms",
        ),
        (
            "pki-service",
            "edge-gateway",
            GraphRelation::DependsOn,
            "ev-pki",
        ),
        (
            "release-signer",
            "cloud-kms",
            GraphRelation::DependsOn,
            "ev-codesign",
        ),
        (
            "vendor-connector",
            "pki-service",
            GraphRelation::DependsOn,
            "ev-vendor",
        ),
    ] {
        edges.push(edge(from, to, relation, ev));
    }
    let raw = inventory.export(&limits).unwrap();
    let profiles = [
        CriticalProfileReference {
            id: "enterprise-pqc-target",
            kind: SchemaKind::TargetProfile,
            version: SchemaVersion::V1_0,
            source_id: "synthetic-policy-office",
            expires_at_unix_secs: Some(NOW + 600),
        },
        CriticalProfileReference {
            id: "vendor-readiness",
            kind: SchemaKind::CapabilityCatalog,
            version: SchemaVersion::V1_0,
            source_id: "synthetic-vendor",
            expires_at_unix_secs: Some(NOW + 300),
        },
    ];
    let input = NeutralInventoryInput {
        schema_version: NEUTRAL_INVENTORY_VERSION,
        producer_id: PRODUCER,
        producer_revision: "r1",
        scope_id: TENANT,
        inventory: VersionedEnvelope {
            schema: SchemaKind::InventorySnapshot,
            version: SchemaVersion::V1_0,
            payload: &raw.bytes,
            source_id: PRODUCER,
            critical_profiles: &profiles,
        },
        nodes: &nodes,
        edges: &edges,
    };
    let projected = NeutralInventoryAdapter::project(&input, raw.digest, &limits, NOW).unwrap();
    let source =
        NeutralInventoryAdapter::import_pinned(&input, projected.pins(), &limits, NOW).unwrap();
    let topology = DependencyAnalysis::analyze(source.graph(), &limits).unwrap();
    let risk = RiskAnalysis::analyze(
        source.inventory(),
        source.graph(),
        &topology,
        &[],
        &[],
        None,
        &limits,
    )
    .unwrap();
    let target = target(&limits);
    let policy = NeutralPolicyReview::new(policy_input(&target), &target, &limits).unwrap();
    let left = vendor_catalog("client-vendor", "gateway-runtime", &limits);
    let right = vendor_catalog("kms-vendor", "kms-runtime", &limits);
    let compatibility = CompatibilityAnalyzer::analyze(
        &peer_request(source.graph(), &target, &left, &right),
        source.graph(),
        &target,
        &left,
        &right,
        NOW,
        &limits,
    )
    .unwrap();
    let input_bindings = RemediationAnalyzer::input_bindings(
        source.inventory(),
        source.graph(),
        &topology,
        &risk,
        &target,
        NOW,
        &limits,
    )
    .unwrap();
    let remediation = RemediationAnalyzer::analyze(
        source.inventory(),
        source.graph(),
        &topology,
        &risk,
        &target,
        &[&compatibility],
        input_bindings,
        &limits,
    )
    .unwrap();
    let wave_bindings =
        WavePlanner::input_bindings(&topology, &remediation, &target, &limits).unwrap();
    let wave = WavePlanner::plan(
        &topology,
        &remediation,
        &target,
        &WavePlanRequest {
            schema_version: WAVE_PLAN_VERSION,
            capacity_systems_per_wave: 3,
            max_waves: 8,
            expected_bindings: wave_bindings,
            submitted_for_review_units: vec![],
        },
        &limits,
    )
    .unwrap();
    let catalogs = [&left, &right];
    let plan_pins = MigrationPlanner::input_pins(
        &topology,
        &remediation,
        &wave,
        &target,
        &catalogs,
        None,
        &limits,
    )
    .unwrap();
    let plan = MigrationPlanner::build(
        &topology,
        &remediation,
        &wave,
        &target,
        &catalogs,
        None,
        &MigrationPlanRequest {
            schema_version: MIGRATION_PLAN_VERSION,
            expected_pins: plan_pins,
            exceptions: vec![],
        },
        &limits,
    )
    .unwrap();
    Pipeline {
        source,
        topology,
        risk,
        target,
        left,
        right,
        compatibility,
        remediation,
        wave,
        plan,
        policy,
    }
}

impl Pipeline {
    fn manifest(&self) -> String {
        let limits = Limits::default();
        let source_digest: [u8; 32] = Sha256::digest(CASES.as_bytes()).into();
        let sources = [
            ("source-file", SnapshotDigest::from_bytes(source_digest)),
            ("inventory", self.source.pins().inventory_digest),
            ("graph", self.source.pins().graph_digest),
            ("handoff", self.source.pins().handoff_digest),
            (
                "risk",
                RemediationAnalyzer::risk_digest(&self.risk, &limits).unwrap(),
            ),
            (
                "topology",
                RemediationAnalyzer::topology_digest(&self.topology, &limits).unwrap(),
            ),
            ("target", self.target.digest()),
            ("policy", self.policy.digest()),
            ("left-catalog", self.left.digest()),
            ("right-catalog", self.right.digest()),
            ("compatibility", self.compatibility.digest()),
            ("remediation", self.remediation.digest()),
            ("wave", self.wave.digest()),
            ("plan", self.plan.digest()),
        ];
        let mut output =
            format!("CSHIFT_E2_FROZEN_V1\nscope={TENANT}\nevaluation_utc={NOW}\nscenarios=5\n");
        for (name, digest) in sources {
            writeln!(&mut output, "{name}={}", digest.as_identifier()).unwrap();
        }
        writeln!(&mut output, "assessment={:?}", self.plan.status()).unwrap();
        writeln!(&mut output, "peer={:?}", self.compatibility.status()).unwrap();
        writeln!(&mut output, "units={}", self.topology.units().len()).unwrap();
        writeln!(&mut output, "waves={}", self.wave.waves().len()).unwrap();
        writeln!(
            &mut output,
            "blockers={}",
            self.remediation.blockers().len()
        )
        .unwrap();
        writeln!(&mut output, "residual={}", self.plan.residual_risks().len()).unwrap();
        output
    }
}

#[test]
fn complete_enterprise_pipeline_matches_reviewed_full_phase_golden() {
    let pipeline = build(0, false);
    assert_eq!(pipeline.source.inventory().snapshot().observations.len(), 6);
    assert_eq!(pipeline.source.graph().nodes().len(), 18);
    assert_eq!(
        pipeline.topology.units().len(),
        4,
        "edge/kms cycle must remain atomic"
    );
    assert!(
        pipeline
            .topology
            .units()
            .iter()
            .any(|u| u.cyclic && u.system_ids.len() == 2)
    );
    assert!(!pipeline.remediation.blockers().is_empty());
    assert!(!pipeline.plan.residual_risks().is_empty());
    assert_ne!(
        pipeline.compatibility.status(),
        CompatibilityStatus::Compatible
    );
    assert_eq!(
        pipeline
            .policy
            .gate_for(&pipeline.target, KnownAlgorithm::MlKem1024.id())
            .unwrap(),
        NeutralPolicyGate::Unverified
    );
    assert_eq!(
        pipeline
            .policy
            .gate_for(&pipeline.target, KnownAlgorithm::MlKem768.id())
            .unwrap(),
        NeutralPolicyGate::Prohibited
    );
    assert!(pipeline.wave.readiness().iter().all(|r| {
        matches!(
            r.status,
            UnitReadinessStatus::Blocked
                | UnitReadinessStatus::Unverified
                | UnitReadinessStatus::AwaitingExternalApproval
                | UnitReadinessStatus::EligibleForReview
        )
    }));
    assert_eq!(pipeline.plan.pins().scope_id, TENANT);
    assert_eq!(pipeline.plan.pins().evaluated_at_unix_secs, NOW);
    assert_eq!(
        pipeline.manifest().trim_end(),
        GOLDEN.trim_end(),
        "canonical cross-phase golden changed: review fixture, expected digests and semantics; actual=\n{}",
        pipeline.manifest()
    );
}

#[test]
fn seeded_permutations_preserve_full_phase_canonical_bytes() {
    let first = build(0, false);
    let golden_plan = first.plan.export(&Limits::default()).unwrap();
    let golden_source = first.source.export(&Limits::default()).unwrap();
    let golden_policy = first.policy.export(&Limits::default()).unwrap();
    for seed in 1..=48 {
        let run = build(seed, false);
        assert_eq!(run.manifest(), first.manifest(), "seed {seed}");
        assert_eq!(
            run.plan.export(&Limits::default()).unwrap(),
            golden_plan,
            "seed {seed}"
        );
        assert_eq!(
            run.source.export(&Limits::default()).unwrap(),
            golden_source,
            "seed {seed}"
        );
        assert_eq!(
            run.policy.export(&Limits::default()).unwrap(),
            golden_policy,
            "seed {seed}"
        );
    }
}

#[test]
fn source_mutation_rotates_pins_and_produces_typed_semantic_diff() {
    let old = build(0, false);
    let changed = build(31, true);
    assert_ne!(old.source.pins(), changed.source.pins());
    assert_ne!(old.plan.digest(), changed.plan.digest());
    let diff = old
        .plan
        .semantic_diff(&changed.plan, &Limits::default())
        .unwrap();
    assert!(diff.changes.contains(&PlanChangeKind::Inventory));
    assert!(diff.changes.contains(&PlanChangeKind::Graph));
    assert_eq!(old.target.digest(), changed.target.digest());
}

#[test]
fn bounded_planning_and_source_export_reject_smaller_consumer_budgets() {
    let p = build(0, false);
    let mut limits = Limits {
        max_graph_nodes: 3,
        ..Limits::default()
    };
    assert_eq!(
        DependencyAnalysis::analyze(p.source.graph(), &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::ResourceLimitExceeded
    );
    limits = Limits {
        max_export_bytes: 32,
        ..Limits::default()
    };
    assert_eq!(
        p.source.export(&limits).unwrap_err().code,
        DiagnosticCode::ResourceLimitExceeded
    );
    limits = Limits {
        max_export_bytes: 32,
        ..Limits::default()
    };
    assert_eq!(
        p.plan.export(&limits).unwrap_err().code,
        DiagnosticCode::ResourceLimitExceeded
    );
    limits = Limits {
        max_planner_candidates: 2,
        ..Limits::default()
    };
    assert_eq!(
        RiskAnalysis::analyze(
            p.source.inventory(),
            p.source.graph(),
            &p.topology,
            &[],
            &[],
            None,
            &limits
        )
        .unwrap_err()
        .code,
        DiagnosticCode::ResourceLimitExceeded
    );
}

#[test]
fn invalid_and_untrusted_evidence_does_not_upgrade_authority() {
    let p = build(0, false);
    let limits = Limits::default();
    let req = peer_request(p.source.graph(), &p.target, &p.left, &p.right);
    let baseline = CompatibilityAnalyzer::analyze(
        &req,
        p.source.graph(),
        &p.target,
        &p.left,
        &p.right,
        NOW,
        &limits,
    )
    .unwrap();
    assert_eq!(baseline.status(), CompatibilityStatus::Unknown);
    assert!(
        baseline
            .findings()
            .iter()
            .any(|f| f.code == CompatibilityCode::NegotiationMissing)
    );
    let mut downgrade = req.clone();
    downgrade.classical_fallback = true;
    let denied = CompatibilityAnalyzer::analyze(
        &downgrade,
        p.source.graph(),
        &p.target,
        &p.left,
        &p.right,
        NOW,
        &limits,
    )
    .unwrap();
    assert_eq!(denied.status(), CompatibilityStatus::Incompatible);
    assert!(
        denied
            .findings()
            .iter()
            .any(|f| f.code == CompatibilityCode::DowngradeRejected)
    );
    let mut hybrid = req.clone();
    hybrid.hybrid = Some(HybridSelection {
        companion_algorithm_id: "ECDH-P256".into(),
        combiner_reference: "unreviewed-combiner".into(),
    });
    let denied = CompatibilityAnalyzer::analyze(
        &hybrid,
        p.source.graph(),
        &p.target,
        &p.left,
        &p.right,
        NOW,
        &limits,
    )
    .unwrap();
    assert_eq!(denied.status(), CompatibilityStatus::Incompatible);
    assert!(
        denied
            .findings()
            .iter()
            .any(|f| f.code == CompatibilityCode::HybridNotApproved)
    );
    let mut cross_tenant = req.clone();
    cross_tenant.scope_id = "attacker-tenant".into();
    assert_eq!(
        CompatibilityAnalyzer::analyze(
            &cross_tenant,
            p.source.graph(),
            &p.target,
            &p.left,
            &p.right,
            NOW,
            &limits
        )
        .unwrap_err()
        .code,
        DiagnosticCode::InvalidReference
    );
    let mut replay = req;
    replay.expected_target_digest = SnapshotDigest::from_bytes([99; 32]);
    assert_eq!(
        CompatibilityAnalyzer::analyze(
            &replay,
            p.source.graph(),
            &p.target,
            &p.left,
            &p.right,
            NOW,
            &limits
        )
        .unwrap_err()
        .code,
        DiagnosticCode::IntegrityMismatch
    );
}

#[test]
fn schema_digest_expiry_and_policy_claim_tampering_fail_closed() {
    let limits = Limits::default();
    let p = build(0, false);
    let raw = p.source.inventory().export(&limits).unwrap();
    let mut data = raw.bytes.clone();
    data.pop();
    let profiles = [CriticalProfileReference {
        id: "enterprise-pqc-target",
        kind: SchemaKind::TargetProfile,
        version: SchemaVersion::V1_0,
        source_id: "synthetic-policy-office",
        expires_at_unix_secs: Some(NOW + 600),
    }];
    let mut env = VersionedEnvelope {
        schema: SchemaKind::InventorySnapshot,
        version: SchemaVersion::V1_0,
        payload: &data,
        source_id: PRODUCER,
        critical_profiles: &profiles,
    };
    assert_eq!(
        ValidatedInventorySnapshot::import_verified(&env, raw.digest, &limits, NOW)
            .unwrap_err()
            .code,
        DiagnosticCode::IntegrityMismatch
    );
    env.version = SchemaVersion { major: 1, minor: 1 };
    assert_eq!(
        env.preflight(&limits, NOW).unwrap_err().code,
        DiagnosticCode::UnsupportedSchemaVersion
    );
    env.version = SchemaVersion { major: 2, minor: 0 };
    assert_eq!(
        env.preflight(&limits, NOW).unwrap_err().code,
        DiagnosticCode::UnsupportedSchemaVersion
    );
    env.version = SchemaVersion::V1_0;
    let expired = [CriticalProfileReference {
        expires_at_unix_secs: Some(NOW),
        ..profiles[0]
    }];
    env.critical_profiles = &expired;
    assert_eq!(
        env.preflight(&limits, NOW).unwrap_err().code,
        DiagnosticCode::StaleCriticalProfile
    );
    let mut policy = policy_input(&p.target);
    policy.decisions[1].outcome = NeutralPolicyOutcome::PermitClaimed;
    assert_eq!(
        NeutralPolicyReview::new(policy, &p.target, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::InvalidStateTransition
    );
    let mut policy = policy_input(&p.target);
    policy.target_digest = SnapshotDigest::from_bytes([44; 32]);
    assert_eq!(
        NeutralPolicyReview::new(policy, &p.target, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::IntegrityMismatch
    );
    let mut policy = policy_input(&p.target);
    policy.expires_at_unix_secs = NOW;
    assert_eq!(
        NeutralPolicyReview::new(policy, &p.target, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::StaleCriticalProfile
    );
    let mut policy = policy_input(&p.target);
    policy.schema_version += 1;
    assert_eq!(
        NeutralPolicyReview::new(policy, &p.target, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::UnsupportedSchemaVersion
    );
}

#[test]
fn deterministic_bounded_parser_mutations_never_treat_framing_as_schema_validation() {
    let limits = Limits::default();
    let mut state = 0x4f00_d12b_u64;
    for iteration in 0..192 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let depth = ((state as usize) % (limits.max_parse_depth + 4)).max(1);
        let raw = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let env = VersionedEnvelope {
            schema: SchemaKind::InventorySnapshot,
            version: SchemaVersion::V1_0,
            payload: raw.as_bytes(),
            source_id: "mutator-v1",
            critical_profiles: &[],
        };
        let result = env
            .preflight(&limits, NOW)
            .unwrap()
            .preflight_json_nesting(&limits);
        assert_eq!(
            result.is_ok(),
            depth <= limits.max_parse_depth,
            "case {iteration}"
        );
        if result.is_ok() {
            // Balanced brackets are not a valid Cryptoshift CSHIFT01 snapshot.
            let fake_hash: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
            assert!(
                ValidatedInventorySnapshot::import_verified(
                    &env,
                    SnapshotDigest::from_bytes(fake_hash),
                    &limits,
                    NOW
                )
                .is_err()
            );
        }
    }
    for hostile in [
        b"{]".as_slice(),
        b"[[}".as_slice(),
        b"{\"open\": [}".as_slice(),
    ] {
        let env = VersionedEnvelope {
            schema: SchemaKind::InventorySnapshot,
            version: SchemaVersion::V1_0,
            payload: hostile,
            source_id: "mutator-v1",
            critical_profiles: &[],
        };
        assert_eq!(
            env.preflight(&limits, NOW)
                .unwrap()
                .preflight_json_nesting(&limits)
                .unwrap_err()
                .code,
            DiagnosticCode::MalformedStructure
        );
    }
}
