//! Deterministic evidence-first cryptographic risk factor analysis.
//!
//! Only explicitly observed/negotiated crypto use is eligible for a
//! quantum-posture inference. Non-derivable contextual factors require
//! source-attributed assessments. Unknowns never convert to zero-risk scores.

use std::collections::{BTreeMap, BTreeSet};

use crate::risk_model::{
    ClaimOrigin, ContextAssessment, QuantumAssessment, QuantumPosture, RISK_FACTOR_VERSION,
    RiskFactor, RiskFactorKind, RiskFinding, RiskFindingCode, RiskLevel, RiskReport, RiskScore,
    RiskUncertainty, ScoreProfile, UnitRiskVector,
};
use crate::{
    CollectionCompleteness, ConflictState, CryptoObservation, CryptoUseKind, DependencyTopology,
    Diagnostic, DiagnosticCode, EvidenceBasis, EvidenceGraph, EvidenceRecord, GraphNode,
    GraphNodeKind, GraphRelation, Limits, ResourceKind, ValidatedInventorySnapshot,
};

/// Offline, stateless analysis of evidence and explicitly attributed claims.
pub struct RiskAnalysis;

impl RiskAnalysis {
    /// Return complete, canonical risk vectors for every SCC migration unit.
    ///
    /// A missing contextual claim remains unknown. The optional score is
    /// withheld if ANY factor is unknown, assumed or evidentially uncertain.
    /// No algorithm-name heuristics, policy decisions or network calls occur.
    pub fn analyze(
        inventory: &ValidatedInventorySnapshot,
        graph: &EvidenceGraph,
        topology: &DependencyTopology,
        quantum: &[QuantumAssessment],
        context: &[ContextAssessment],
        scoring: Option<&ScoreProfile>,
        limits: &Limits,
    ) -> Result<RiskReport, Diagnostic> {
        limits.validate()?;
        limits.check(ResourceKind::GraphNodes, graph.nodes().len())?;
        limits.check(ResourceKind::GraphEdges, graph.edges().len())?;
        limits.check(ResourceKind::GraphNodes, topology.units().len())?;
        let digest = inventory.export(limits)?.digest;
        if digest != graph.source_digest() || digest != topology.source_digest() {
            return Err(problem(
                DiagnosticCode::IntegrityMismatch,
                "risk_source",
                "risk inputs must share the same canonical inventory digest",
            ));
        }
        limits.checked_mul(
            ResourceKind::PlannerCandidates,
            topology.units().len(),
            RiskFactorKind::ALL.len(),
        )?;
        limits.checked_add(ResourceKind::EvidenceRecords, quantum.len(), context.len())?;

        // Meter source-attributed structured inputs before indexing them.
        // Caller-owned arrays may have been materialized under looser limits.
        let mut supplied_bytes = 0_usize;
        for profile in quantum {
            supplied_bytes = limits.checked_add(
                ResourceKind::InputBytes,
                supplied_bytes,
                profile.observation_id.len(),
            )?;
            supplied_bytes = limits.checked_add(
                ResourceKind::InputBytes,
                supplied_bytes,
                profile.algorithm_id.len(),
            )?;
            supplied_bytes = limits.checked_add(
                ResourceKind::InputBytes,
                supplied_bytes,
                profile.source_reference.len(),
            )?;
        }
        for claim in context {
            supplied_bytes = limits.checked_add(
                ResourceKind::InputBytes,
                supplied_bytes,
                claim.unit_id.len(),
            )?;
            supplied_bytes = limits.checked_add(
                ResourceKind::InputBytes,
                supplied_bytes,
                claim.source_reference.len(),
            )?;
        }

        // Re-admit under caller limits, even if graph was constructed under
        // looser limits. Do so before building indexes or duplicating refs.
        let mut attached = 0_usize;
        for node in graph.nodes() {
            attached =
                limits.checked_add(ResourceKind::GraphEdges, attached, node.evidence_ids.len())?;
        }
        for edge in graph.edges() {
            attached =
                limits.checked_add(ResourceKind::GraphEdges, attached, edge.evidence_ids.len())?;
        }

        // Each system-to-system edge is indexed at BOTH endpoints. Account
        // for that work independently of the graph's original edge/reference
        // count, before allocating any evidence-index BTreeSets.
        let mut projected = 0_usize;
        for node in graph.nodes() {
            if node.kind == GraphNodeKind::System {
                projected = limits.checked_add(
                    ResourceKind::GraphEdges,
                    projected,
                    node.evidence_ids.len(),
                )?;
            }
        }
        for edge in graph.edges() {
            let from = graph
                .nodes()
                .binary_search_by(|node| node.id.as_str().cmp(edge.from.as_str()))
                .map_err(|_| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "risk_graph_from",
                        "risk graph contains unknown edge source",
                    )
                })?;
            let to = graph
                .nodes()
                .binary_search_by(|node| node.id.as_str().cmp(edge.to.as_str()))
                .map_err(|_| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "risk_graph_to",
                        "risk graph contains unknown edge target",
                    )
                })?;
            if graph.nodes()[from].kind == GraphNodeKind::System {
                projected = limits.checked_add(
                    ResourceKind::GraphEdges,
                    projected,
                    edge.evidence_ids.len(),
                )?;
            }
            if graph.nodes()[to].kind == GraphNodeKind::System {
                projected = limits.checked_add(
                    ResourceKind::GraphEdges,
                    projected,
                    edge.evidence_ids.len(),
                )?;
            }
        }
        let graph_fingerprint = graph.fingerprint();
        if graph_fingerprint != topology.graph_fingerprint() {
            return Err(problem(
                DiagnosticCode::IntegrityMismatch,
                "risk_graph_topology",
                "topology must be derived from the exact supplied typed graph",
            ));
        }

        let snap = inventory.snapshot();
        let observations: BTreeMap<&str, &CryptoObservation> = snap
            .observations
            .iter()
            .map(|o| (o.id.as_str(), o))
            .collect();
        let evidence: BTreeMap<&str, &EvidenceRecord> =
            snap.evidence.iter().map(|e| (e.id.as_str(), e)).collect();
        let nodes: BTreeMap<&str, &GraphNode> = graph
            .nodes()
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect();
        let units: BTreeSet<&str> = topology
            .units()
            .iter()
            .map(|unit| unit.id.as_str())
            .collect();

        let mut profiles = BTreeMap::<&str, &QuantumAssessment>::new();
        for profile in quantum {
            valid_ref(&profile.observation_id, "quantum_observation")?;
            valid_ref(&profile.algorithm_id, "quantum_algorithm")?;
            valid_ref(&profile.source_reference, "quantum_reference")?;
            let observed = observations
                .get(profile.observation_id.as_str())
                .ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "quantum_observation",
                        "quantum classification must name an inventory observation",
                    )
                })?;
            if profile.source_digest != digest || profile.algorithm_id != observed.algorithm_id {
                return Err(problem(
                    DiagnosticCode::IntegrityMismatch,
                    "quantum_classification",
                    "classification must match source digest and exact algorithm identity",
                ));
            }
            if profiles
                .insert(profile.observation_id.as_str(), profile)
                .is_some()
            {
                return Err(problem(
                    DiagnosticCode::DuplicateRecord,
                    "quantum_observation",
                    "duplicate quantum classification for one observation",
                ));
            }
        }
        let mut claims = BTreeMap::<(&str, RiskFactorKind), &ContextAssessment>::new();
        for claim in context {
            valid_ref(&claim.unit_id, "risk_unit")?;
            valid_ref(&claim.source_reference, "context_reference")?;
            if claim.source_digest != digest {
                return Err(problem(
                    DiagnosticCode::IntegrityMismatch,
                    "context_snapshot",
                    "context assessment must match exact source digest",
                ));
            }
            if !units.contains(claim.unit_id.as_str()) {
                return Err(problem(
                    DiagnosticCode::InvalidReference,
                    "risk_unit",
                    "context claim refers to an unknown migration unit",
                ));
            }
            if !claim.factor.requires_context() {
                return Err(problem(
                    DiagnosticCode::InvalidStateTransition,
                    "context_factor",
                    "externally supplied claim cannot override an evidence-derived factor",
                ));
            }
            if claims
                .insert((claim.unit_id.as_str(), claim.factor), claim)
                .is_some()
            {
                return Err(problem(
                    DiagnosticCode::DuplicateRecord,
                    "context_factor",
                    "duplicate context claim for same unit and factor",
                ));
            }
        }

        // A single graph pass indexes explicitly typed use-site edges and
        // relevant unit evidence, avoiding one full edge scan per SCC.
        let mut exposed = BTreeMap::<&str, Vec<&GraphNode>>::new();
        let mut relevant = BTreeMap::<&str, BTreeSet<&str>>::new();
        for node in graph.nodes() {
            if node.kind == GraphNodeKind::System {
                relevant
                    .entry(node.id.as_str())
                    .or_default()
                    .extend(node.evidence_ids.iter().map(String::as_str));
            }
        }
        for edge in graph.edges() {
            if edge.relation == GraphRelation::ExposesUse {
                let target = nodes.get(edge.to.as_str()).ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "quantum_use",
                        "graph use-site endpoint must exist",
                    )
                })?;
                exposed.entry(edge.from.as_str()).or_default().push(target);
            }
            if let Some(refs) = relevant.get_mut(edge.from.as_str()) {
                refs.extend(edge.evidence_ids.iter().map(String::as_str));
            }
            if let Some(refs) = relevant.get_mut(edge.to.as_str()) {
                refs.extend(edge.evidence_ids.iter().map(String::as_str));
            }
        }

        let incomplete = snap
            .runs
            .iter()
            .any(|run| run.completeness != CollectionCompleteness::Complete);
        let dependency_links = dependency_details(topology, limits)?;
        let mut results = Vec::with_capacity(topology.units().len());
        let mut diagnostic_count = 0_usize;
        let mut output_bytes = 0_usize;
        for unit in topology.units() {
            let mut factors: Vec<RiskFactor> = RiskFactorKind::ALL
                .iter()
                .map(|&kind| unknown(kind, RiskUncertainty::MissingAssessment))
                .collect();
            factors[RiskFactorKind::QuantumExposure.index()] = quantum_factor(
                &unit.system_ids,
                &exposed,
                &observations,
                &profiles,
                &evidence,
                incomplete,
            )?;
            factors[RiskFactorKind::EvidenceQuality.index()] = evidence_factor(
                &unit.system_ids,
                &relevant,
                &evidence,
                &observations,
                &exposed,
                incomplete,
            )?;
            let mut dependency_evidence = BTreeSet::new();
            dependency_evidence.extend(unit.internal_dependency_evidence_ids.iter().cloned());
            if let Some((_, evidence)) = dependency_links.get(unit.id.as_str()) {
                dependency_evidence.extend(evidence.iter().map(|id| (*id).to_owned()));
            }
            factors[RiskFactorKind::DependencyComplexity.index()] = dependency_factor(
                unit.cyclic,
                dependency_links
                    .get(unit.id.as_str())
                    .map_or(0, |(count, _)| *count),
                incomplete,
                dependency_evidence.into_iter().collect(),
            );
            for &kind in &RiskFactorKind::ALL {
                if kind.requires_context() {
                    if let Some(claim) = claims.get(&(unit.id.as_str(), kind)) {
                        factors[kind.index()] = RiskFactor {
                            kind,
                            level: Some(claim.level),
                            uncertainty: (claim.origin == ClaimOrigin::ScenarioAssumption)
                                .then_some(RiskUncertainty::ScenarioAssumption),
                            inventory_evidence_ids: Vec::new(),
                            assessment_references: vec![claim.source_reference.clone()],
                        };
                    }
                }
            }

            let mut findings = Vec::new();
            for factor in &factors {
                if factor.level.is_none() || factor.uncertainty.is_some() {
                    findings.push(RiskFinding {
                        code: RiskFindingCode::UnresolvedFactor,
                        factor: factor.kind,
                    });
                }
                if factor.level.is_some_and(|value| value >= RiskLevel::High) {
                    findings.push(RiskFinding {
                        code: RiskFindingCode::ElevatedFactor,
                        factor: factor.kind,
                    });
                }
                if factor.kind == RiskFactorKind::QuantumExposure
                    && factor.level == Some(RiskLevel::Severe)
                {
                    findings.push(RiskFinding {
                        code: RiskFindingCode::SusceptibleUse,
                        factor: factor.kind,
                    });
                }
                if factor.uncertainty == Some(RiskUncertainty::ScenarioAssumption) {
                    findings.push(RiskFinding {
                        code: RiskFindingCode::ScenarioDependent,
                        factor: factor.kind,
                    });
                }
            }
            diagnostic_count =
                limits.checked_add(ResourceKind::Diagnostics, diagnostic_count, findings.len())?;

            charge(limits, &mut output_bytes, &unit.id)?;
            for factor in &factors {
                charge(limits, &mut output_bytes, factor.kind.as_str())?;
                for reference in &factor.inventory_evidence_ids {
                    charge(limits, &mut output_bytes, reference)?;
                }
                for reference in &factor.assessment_references {
                    charge(limits, &mut output_bytes, reference)?;
                }
            }

            let score = scoring
                .and_then(|profile| profile.score(&factors))
                .map(|pressure_bps| RiskScore {
                    pressure_bps,
                    profile_id: scoring.map_or(String::new(), |profile| profile.id().to_owned()),
                    profile_version: scoring.map_or(0, ScoreProfile::version),
                });
            if let Some(ref scored) = score {
                charge(limits, &mut output_bytes, &scored.profile_id)?;
            }
            results.push(UnitRiskVector {
                unit_id: unit.id.clone(),
                factors,
                findings,
                score,
            });
        }

        Ok(RiskReport {
            model_version: RISK_FACTOR_VERSION,
            source_digest: digest,
            graph_fingerprint,
            score_profile: scoring.cloned(),
            units: results,
        })
    }
}

fn quantum_factor(
    systems: &[String],
    exposed: &BTreeMap<&str, Vec<&GraphNode>>,
    observations: &BTreeMap<&str, &CryptoObservation>,
    profiles: &BTreeMap<&str, &QuantumAssessment>,
    evidence: &BTreeMap<&str, &EvidenceRecord>,
    incomplete: bool,
) -> Result<RiskFactor, Diagnostic> {
    let mut factor = unknown(
        RiskFactorKind::QuantumExposure,
        RiskUncertainty::NoConfirmedUse,
    );
    let mut seen = BTreeSet::<&str>::new();
    let mut evidence_ids = BTreeSet::<&str>::new();
    let mut assessment_ids = BTreeSet::<&str>::new();
    let mut had_site = false;
    for system in systems {
        if let Some(use_sites) = exposed.get(system.as_str()) {
            for node in use_sites {
                let id = node.observation_id.as_deref().ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "quantum_use",
                        "crypto use-site lacks inventory observation identity",
                    )
                })?;
                if !seen.insert(id) {
                    continue;
                }
                if !had_site {
                    // NoConfirmedUse only applies when there are no direct
                    // use-site edges. Never let it hide later unknown profiles.
                    factor.uncertainty = None;
                    had_site = true;
                }
                let observation = observations.get(id).ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "quantum_observation",
                        "graph use-site is not in inventory",
                    )
                })?;
                evidence_ids.extend(observation.evidence_ids.iter().map(String::as_str));
                if observation.conflict != ConflictState::Uncontested {
                    uncertain(&mut factor, RiskUncertainty::ConflictingEvidence);
                }
                for ev in &observation.evidence_ids {
                    if evidence
                        .get(ev.as_str())
                        .is_some_and(|e| e.basis != EvidenceBasis::Direct)
                    {
                        uncertain(&mut factor, RiskUncertainty::WeakEvidence);
                    }
                }
                if !matches!(
                    observation.kind,
                    CryptoUseKind::ActiveUse | CryptoUseKind::NegotiatedProtocol
                ) {
                    uncertain(&mut factor, RiskUncertainty::UnconfirmedUse);
                    continue;
                }
                if let Some(profile) = profiles.get(id) {
                    assessment_ids.insert(profile.source_reference.as_str());
                    if profile.origin == ClaimOrigin::ScenarioAssumption {
                        uncertain(&mut factor, RiskUncertainty::ScenarioAssumption);
                    }
                    match profile.posture {
                        QuantumPosture::Susceptible => {
                            maximum(&mut factor, RiskLevel::Severe);
                        }
                        QuantumPosture::CandidateResistant => {
                            maximum(&mut factor, RiskLevel::Moderate);
                        }
                        QuantumPosture::Unknown => {
                            uncertain(&mut factor, RiskUncertainty::MissingAssessment);
                        }
                    }
                } else {
                    uncertain(&mut factor, RiskUncertainty::MissingAssessment);
                }
            }
        }
    }
    if incomplete {
        uncertain(&mut factor, RiskUncertainty::IncompleteCoverage);
    }
    factor.inventory_evidence_ids = evidence_ids.into_iter().map(str::to_owned).collect();
    factor.assessment_references = assessment_ids.into_iter().map(str::to_owned).collect();
    Ok(factor)
}

fn evidence_factor(
    systems: &[String],
    relevant: &BTreeMap<&str, BTreeSet<&str>>,
    evidence: &BTreeMap<&str, &EvidenceRecord>,
    observations: &BTreeMap<&str, &CryptoObservation>,
    exposed: &BTreeMap<&str, Vec<&GraphNode>>,
    incomplete: bool,
) -> Result<RiskFactor, Diagnostic> {
    let mut factor = unknown(
        RiskFactorKind::EvidenceQuality,
        RiskUncertainty::MissingAssessment,
    );
    let mut ids = BTreeSet::<&str>::new();
    let mut conflict = false;
    for system in systems {
        if let Some(refs) = relevant.get(system.as_str()) {
            ids.extend(refs.iter().copied());
        }
        if let Some(sites) = exposed.get(system.as_str()) {
            for site in sites {
                let id = site.observation_id.as_deref().ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "evidence_observation",
                        "crypto use-site has no inventory observation",
                    )
                })?;
                let observation = observations.get(id).ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "evidence_observation",
                        "observation missing from validated inventory",
                    )
                })?;
                ids.extend(observation.evidence_ids.iter().map(String::as_str));
                if observation.conflict != ConflictState::Uncontested {
                    conflict = true;
                }
            }
        }
    }
    if !ids.is_empty() {
        factor.level = Some(RiskLevel::Low);
        factor.uncertainty = None;
    }
    for id in &ids {
        let item = evidence.get(id).ok_or_else(|| {
            problem(
                DiagnosticCode::InvalidReference,
                "risk_evidence",
                "risk graph evidence missing from inventory",
            )
        })?;
        if item.basis != EvidenceBasis::Direct {
            maximum(&mut factor, RiskLevel::High);
            uncertain(&mut factor, RiskUncertainty::WeakEvidence);
        }
    }
    if conflict {
        maximum(&mut factor, RiskLevel::High);
        uncertain(&mut factor, RiskUncertainty::ConflictingEvidence);
    }
    if incomplete {
        maximum(&mut factor, RiskLevel::High);
        uncertain(&mut factor, RiskUncertainty::IncompleteCoverage);
    }
    factor.inventory_evidence_ids = ids.into_iter().map(str::to_owned).collect();
    Ok(factor)
}

fn dependency_details<'a>(
    topology: &'a DependencyTopology,
    limits: &Limits,
) -> Result<BTreeMap<&'a str, (usize, BTreeSet<&'a str>)>, Diagnostic> {
    limits.check(ResourceKind::GraphEdges, topology.prerequisites().len())?;
    let mut details = BTreeMap::new();
    for arc in topology.prerequisites() {
        let entry = details
            .entry(arc.dependent_unit.as_str())
            .or_insert_with(|| (0_usize, BTreeSet::new()));
        entry.0 = limits.checked_add(ResourceKind::GraphEdges, entry.0, 1)?;
        entry.1.extend(arc.evidence_ids.iter().map(String::as_str));
    }
    Ok(details)
}

fn dependency_factor(
    cyclic: bool,
    dependencies: usize,
    incomplete: bool,
    evidence_ids: Vec<String>,
) -> RiskFactor {
    let level = if cyclic {
        RiskLevel::Severe
    } else if dependencies >= 3 {
        RiskLevel::High
    } else if dependencies > 0 {
        RiskLevel::Moderate
    } else {
        RiskLevel::Low
    };
    RiskFactor {
        kind: RiskFactorKind::DependencyComplexity,
        level: Some(level),
        uncertainty: incomplete.then_some(RiskUncertainty::IncompleteCoverage),
        inventory_evidence_ids: evidence_ids,
        assessment_references: Vec::new(),
    }
}

fn unknown(kind: RiskFactorKind, reason: RiskUncertainty) -> RiskFactor {
    RiskFactor {
        kind,
        level: None,
        uncertainty: Some(reason),
        inventory_evidence_ids: Vec::new(),
        assessment_references: Vec::new(),
    }
}

fn maximum(factor: &mut RiskFactor, risk: RiskLevel) {
    factor.level = Some(factor.level.map_or(risk, |before| before.max(risk)));
}

fn uncertain(factor: &mut RiskFactor, cause: RiskUncertainty) {
    factor.uncertainty = Some(factor.uncertainty.map_or(cause, |before| before.max(cause)));
}

fn valid_ref(id: &str, field: &'static str) -> Result<(), Diagnostic> {
    if id.is_empty() || id.len() > 256 || id.trim() != id || id.chars().any(char::is_control) {
        return Err(problem(
            DiagnosticCode::InvalidIdentifier,
            field,
            "risk source reference is empty, oversized or contains controls",
        ));
    }
    Ok(())
}

fn charge(limits: &Limits, bytes: &mut usize, value: &str) -> Result<(), Diagnostic> {
    *bytes = limits.checked_add(ResourceKind::ExportBytes, *bytes, value.len())?;
    Ok(())
}

fn problem(code: DiagnosticCode, subject: &'static str, reason: &'static str) -> Diagnostic {
    Diagnostic::new(code, subject, reason)
}
