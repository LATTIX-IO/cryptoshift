//! FOSS-453: offline evidence-first phase scaling, without migration execution.
//! Build release-mode timings with `cargo bench --bench phase_scaling`.
//! Use `--smoke` for deterministic CI semantic replay (no time threshold).
#![allow(clippy::unwrap_used, clippy::expect_used)] // Fixed synthetic developer benchmark.

use cryptoshift::*;
use std::hint::black_box;
use std::time::{Duration, Instant};

const NOW: i64 = 1_800_000_000;
const SCOPE: &str = "benchmark-synthetic";
const SEMANTIC_GOLDEN: &str = include_str!("../../../tests/perf/v1/identity.golden");
const SIZES: [(&str, usize); 3] = [("small", 8), ("standard", 24), ("large", 64)];

#[derive(Clone, Debug, Eq, PartialEq)]
struct Identity {
    inventory: String,
    graph: String,
    topology: String,
    risk: String,
    compatibility: String,
    remediation: String,
    wave: String,
    plan: String,
    units: usize,
    waves: usize,
    status: PlanAssessmentState,
}

#[derive(Clone, Copy, Debug, Default)]
struct Times {
    graph: Duration,
    topology: Duration,
    risk: Duration,
    compatibility: Duration,
    remediation: Duration,
    wave: Duration,
    plan: Duration,
}

impl Times {
    fn add(&mut self, other: Self) {
        self.graph += other.graph;
        self.topology += other.topology;
        self.risk += other.risk;
        self.compatibility += other.compatibility;
        self.remediation += other.remediation;
        self.wave += other.wave;
        self.plan += other.plan;
    }

    fn print_average(&self, label: &str, size: usize, iterations: u32) {
        let ms = |duration: Duration| duration.as_secs_f64() * 1000.0 / f64::from(iterations);
        println!(
            "profile={label} nodes={size} iterations={iterations} graph_ms={:.3} topology_ms={:.3} risk_ms={:.3} compatibility_ms={:.3} remediation_ms={:.3} waves_ms={:.3} plan_ms={:.3}",
            ms(self.graph),
            ms(self.topology),
            ms(self.risk),
            ms(self.compatibility),
            ms(self.remediation),
            ms(self.wave),
            ms(self.plan),
        );
    }
}

fn system_id(index: usize) -> String {
    format!("system-{index:05}")
}

/// Intentionally bounded generator: one real source-qualified evidence ID
/// supports each graph system/edge; no runtime crypto is ever authenticated.
fn fixture(
    systems: usize,
    reversed: bool,
    limits: &Limits,
) -> Result<(ValidatedInventorySnapshot, EvidenceGraph), Diagnostic> {
    let inventory = ValidatedInventorySnapshot::new(
        InventorySnapshot {
            identity_version: IDENTITY_VERSION,
            normalization_version: NORMALIZATION_VERSION,
            scope_id: SCOPE.into(),
            runs: vec![CollectionRun {
                id: "scan-1".into(),
                source_id: "synthetic-collector".into(),
                scope_id: SCOPE.into(),
                collected_at_unix_secs: NOW - 100,
                completeness: CollectionCompleteness::Partial,
            }],
            evidence: vec![EvidenceRecord {
                id: "source-evidence".into(),
                run_id: "scan-1".into(),
                source_id: "synthetic-collector".into(),
                basis: EvidenceBasis::Direct,
                confidence_bps: 8800,
                observed_at_unix_secs: NOW - 100,
            }],
            observations: vec![],
            absences: vec![],
        },
        limits,
    )?;
    let mut nodes = (0..systems)
        .map(|index| GraphNode {
            id: system_id(index),
            kind: GraphNodeKind::System,
            evidence_ids: vec!["source-evidence".into()],
            observation_id: None,
            observation_kind: None,
        })
        .collect::<Vec<_>>();
    let mut edges = Vec::new();
    let mut dependency = |from: usize, to: usize| {
        edges.push(GraphEdge {
            from: system_id(from),
            to: system_id(to),
            relation: GraphRelation::DependsOn,
            evidence_ids: vec!["source-evidence".into()],
        });
    };
    // Bounded dependency chain. Four-system SCCs make cycle condensation
    // visible and avoid pretending a cyclic deployment can be atomized.
    for i in 1..systems {
        dependency(i, i - 1);
    }
    for first in (0..systems).step_by(4) {
        if first + 3 < systems {
            dependency(first, first + 3);
        }
    }
    if reversed {
        nodes.reverse();
        edges.reverse();
    }
    let graph = EvidenceGraph::new(&inventory, nodes, edges, limits)?;
    Ok((inventory, graph))
}

fn target(limits: &Limits) -> Result<TargetProfile, Diagnostic> {
    TargetProfile::new(
        TargetProfileDraft {
            schema_version: TARGET_PROFILE_VERSION,
            profile_id: "benchmark-target".into(),
            revision: 1,
            scope_id: SCOPE.into(),
            provenance: ProfileProvenance {
                issuer_id: "synthetic-policy-owner".into(),
                document_id: "synthetic-profile".into(),
                revision: "v1".into(),
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
                protocol_id: "benchmark-protocol".into(),
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
        limits,
        Some(NOW),
    )
}

fn catalog(name: &str, runtime: &str, limits: &Limits) -> Result<CapabilityCatalog, Diagnostic> {
    CapabilityCatalog::new(
        CapabilityCatalogDraft {
            schema_version: CAPABILITY_CATALOG_VERSION,
            catalog_id: format!("catalog-{name}"),
            revision: 1,
            scope_id: SCOPE.into(),
            provenance: ProfileProvenance {
                issuer_id: "synthetic-vendor".into(),
                document_id: "synthetic-datasheet".into(),
                revision: "v1".into(),
                source_digest: None,
            },
            records: vec![CapabilityRecord {
                record_id: format!("claim-{name}"),
                provider_id: name.into(),
                product_id: "transport".into(),
                product_version: "v1".into(),
                platform_id: "portable".into(),
                scope_id: SCOPE.into(),
                runtime_id: Some(runtime.into()),
                algorithm: KnownAlgorithm::MlKem1024,
                role: AlgorithmRole::KeyEncapsulation,
                state: CapabilityState::Available,
                evidence: CapabilityEvidence {
                    source_id: "synthetic-vendor".into(),
                    evidence_id: format!("evidence-{name}"),
                    source_revision: "v1".into(),
                    basis: CapabilityEvidenceBasis::VendorDocumentation,
                    verification: EvidenceVerification::Unverified,
                    verification_reference: None,
                    artifact_digest: None,
                    observed_at_unix_secs: NOW - 100,
                    expires_at_unix_secs: Some(NOW + 100),
                },
            }],
        },
        limits,
        Some(NOW),
    )
}

fn peer_request(
    graph: &EvidenceGraph,
    desired: &TargetProfile,
    left: &CapabilityCatalog,
    right: &CapabilityCatalog,
) -> CompatibilityRequest {
    let peer = |index: usize, provider: &str, runtime: &str| EndpointIdentity {
        system_node_id: system_id(index),
        provider_id: provider.into(),
        product_id: "transport".into(),
        product_version: "v1".into(),
        platform_id: "portable".into(),
        runtime_id: runtime.into(),
    };
    CompatibilityRequest {
        schema_version: COMPATIBILITY_ANALYSIS_VERSION,
        scope_id: SCOPE.into(),
        expected_graph_digest: graph.fingerprint(),
        expected_target_digest: desired.digest(),
        expected_initiator_catalog_digest: left.digest(),
        expected_responder_catalog_digest: right.digest(),
        initiator: peer(0, "left", "runtime-left"),
        responder: peer(1, "right", "runtime-right"),
        protocol_id: "benchmark-protocol".into(),
        protocol_revision: "rev-1".into(),
        extension_revision: "extension-1".into(),
        algorithm: KnownAlgorithm::MlKem1024,
        role: AlgorithmRole::KeyEncapsulation,
        certificate: None,
        hybrid: None,
        classical_fallback: false,
        observations: vec![],
    }
}

fn measure(
    systems: usize,
    reversed: bool,
    limits: &Limits,
) -> Result<(Identity, Times), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let (inventory, graph) = fixture(systems, reversed, limits)?;
    let graph_time = start.elapsed();
    let start = Instant::now();
    let topology = DependencyAnalysis::analyze(&graph, limits)?;
    let topology_time = start.elapsed();
    let start = Instant::now();
    let risk = RiskAnalysis::analyze(&inventory, &graph, &topology, &[], &[], None, limits)?;
    let risk_time = start.elapsed();
    let desired = target(limits)?;
    let left = catalog("left", "runtime-left", limits)?;
    let right = catalog("right", "runtime-right", limits)?;
    let start = Instant::now();
    let compatibility = CompatibilityAnalyzer::analyze(
        &peer_request(&graph, &desired, &left, &right),
        &graph,
        &desired,
        &left,
        &right,
        NOW,
        limits,
    )?;
    let compatibility_time = start.elapsed();
    if compatibility.status() != CompatibilityStatus::Unknown {
        return Err("unproven peer negotiation was promoted to compatibility".into());
    }
    let start = Instant::now();
    let expected = RemediationAnalyzer::input_bindings(
        &inventory, &graph, &topology, &risk, &desired, NOW, limits,
    )?;
    let remediation = RemediationAnalyzer::analyze(
        &inventory,
        &graph,
        &topology,
        &risk,
        &desired,
        &[&compatibility],
        expected,
        limits,
    )?;
    let remediation_time = start.elapsed();
    let start = Instant::now();
    let bindings = WavePlanner::input_bindings(&topology, &remediation, &desired, limits)?;
    let wave = WavePlanner::plan(
        &topology,
        &remediation,
        &desired,
        &WavePlanRequest {
            schema_version: WAVE_PLAN_VERSION,
            capacity_systems_per_wave: 4,
            max_waves: 128,
            expected_bindings: bindings,
            submitted_for_review_units: vec![],
        },
        limits,
    )?;
    let wave_time = start.elapsed();
    let start = Instant::now();
    let catalogs = [&left, &right];
    let pins = MigrationPlanner::input_pins(
        &topology,
        &remediation,
        &wave,
        &desired,
        &catalogs,
        None,
        limits,
    )?;
    let plan = MigrationPlanner::build(
        &topology,
        &remediation,
        &wave,
        &desired,
        &catalogs,
        None,
        &MigrationPlanRequest {
            schema_version: MIGRATION_PLAN_VERSION,
            expected_pins: pins,
            exceptions: vec![],
        },
        limits,
    )?;
    let _ = plan.export(limits)?;
    let plan_time = start.elapsed();
    if plan.status() == PlanAssessmentState::CompleteEvidenceForReview {
        return Err("incomplete synthetic inventory cannot be complete for review".into());
    }
    if topology.units().len() != systems / 4 {
        return Err("the four-system dependency cycles were not preserved as SCCs".into());
    }
    let identity = Identity {
        inventory: inventory.export(limits)?.digest.as_identifier(),
        graph: graph.fingerprint().as_identifier(),
        topology: RemediationAnalyzer::topology_digest(&topology, limits)?.as_identifier(),
        risk: RemediationAnalyzer::risk_digest(&risk, limits)?.as_identifier(),
        compatibility: compatibility.digest().as_identifier(),
        remediation: remediation.digest().as_identifier(),
        wave: wave.digest().as_identifier(),
        plan: plan.digest().as_identifier(),
        units: topology.units().len(),
        waves: wave.waves().len(),
        status: plan.status(),
    };
    Ok((
        identity,
        Times {
            graph: graph_time,
            topology: topology_time,
            risk: risk_time,
            compatibility: compatibility_time,
            remediation: remediation_time,
            wave: wave_time,
            plan: plan_time,
        },
    ))
}

/// Exercise all three deterministic profiles; measured durations never gate correctness.
pub fn run(smoke: bool) -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits::default();
    let iterations: u32 = if smoke { 1 } else { 10 };
    let mut semantic_lines = String::new();
    for (label, systems) in SIZES {
        let (baseline, first) = measure(systems, false, &limits)?;
        let (reversed, _) = measure(systems, true, &limits)?;
        if baseline != reversed {
            return Err(
                format!("{label}: semantic identity differs after input permutation").into(),
            );
        }
        // Negative-budget smoke: an already accepted graph must not be
        // processed by a consumer with a smaller node budget.
        let (_, graph) = fixture(systems, false, &limits)?;
        let small = Limits {
            max_graph_nodes: systems - 1,
            ..limits
        };
        let failure = DependencyAnalysis::analyze(&graph, &small)
            .expect_err("undersized consumer graph budget must fail closed");
        if failure.code != DiagnosticCode::ResourceLimitExceeded {
            return Err("unexpected failed-budget diagnostic code".into());
        }
        let mut timings = first;
        for _ in 1..iterations {
            let (again, sample) = measure(systems, false, &limits)?;
            if baseline != again {
                return Err(format!("{label}: nondeterministic semantic regression").into());
            }
            black_box(&again);
            timings.add(sample);
        }
        let identity_line = format!(
            "scaling:v1 profile={label} nodes={systems} units={} waves={} assessment={:?} graph={} risk={} compatibility={} remediation={} wave={} plan={}",
            baseline.units,
            baseline.waves,
            baseline.status,
            baseline.graph,
            baseline.risk,
            baseline.compatibility,
            baseline.remediation,
            baseline.wave,
            baseline.plan,
        );
        println!("{identity_line}");
        semantic_lines.push_str(&identity_line);
        semantic_lines.push('\n');
        timings.print_average(label, systems, iterations);
    }
    // This file is reviewed v1 regression evidence, not a live-run expectation.
    // Both optimized and test profiles must preserve these exact phase identities.
    if semantic_lines != SEMANTIC_GOLDEN {
        return Err(format!(
            "frozen phase semantics changed; independently review any expected update:\n{semantic_lines}"
        )
        .into());
    }
    println!("scaling:v1 PASS; synthetic hashes are identities, not authorization");
    Ok(())
}

fn main() {
    let smoke = match std::env::args().nth(1).as_deref() {
        Some("--smoke") => true,
        None => false,
        Some(other) => {
            eprintln!("unknown argument: {other}; expected --smoke or no arguments");
            std::process::exit(2);
        }
    };
    if let Err(error) = run(smoke) {
        eprintln!("scaling benchmark failed: {error}");
        std::process::exit(1);
    }
}
