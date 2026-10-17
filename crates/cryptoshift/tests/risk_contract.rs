//! Public consumer contract tests for risk factors and optional scoring.

use cryptoshift::{
    ClaimOrigin, CollectionCompleteness, CollectionRun, ConflictState, ContextAssessment,
    CryptoObservation, CryptoUseKind, DependencyAnalysis, DependencyTopology, Diagnostic,
    DiagnosticCode, EvidenceBasis, EvidenceGraph, EvidenceRecord, GraphEdge, GraphNode,
    GraphNodeKind, GraphRelation, IDENTITY_VERSION, InventorySnapshot, Limits,
    NORMALIZATION_VERSION, QuantumAssessment, QuantumPosture, RiskAnalysis, RiskFactor,
    RiskFactorKind, RiskFindingCode, RiskLevel, RiskReport, RiskUncertainty, SCORE_PROFILE_VERSION,
    ScoreProfile, ValidatedInventorySnapshot,
};

fn fixture(
    partial: bool,
    use_kind: CryptoUseKind,
    conflict: ConflictState,
    basis: EvidenceBasis,
) -> Result<
    (
        ValidatedInventorySnapshot,
        EvidenceGraph,
        DependencyTopology,
    ),
    Diagnostic,
> {
    let limits = Limits::default();
    let inventory = ValidatedInventorySnapshot::new(
        InventorySnapshot {
            identity_version: IDENTITY_VERSION,
            normalization_version: NORMALIZATION_VERSION,
            scope_id: "synthetic-scope".into(),
            runs: vec![CollectionRun {
                id: "run-1".into(),
                source_id: "collector-1".into(),
                scope_id: "synthetic-scope".into(),
                collected_at_unix_secs: 10,
                completeness: if partial {
                    CollectionCompleteness::Partial
                } else {
                    CollectionCompleteness::Complete
                },
            }],
            evidence: vec![EvidenceRecord {
                id: "ev-1".into(),
                run_id: "run-1".into(),
                source_id: "collector-1".into(),
                basis,
                confidence_bps: 7000,
                observed_at_unix_secs: 10,
            }],
            observations: vec![CryptoObservation {
                id: "obs-1".into(),
                asset_id: "app".into(),
                algorithm_id: "RSA-2048".into(),
                kind: use_kind,
                conflict,
                evidence_ids: vec!["ev-1".into()],
            }],
            absences: vec![],
        },
        &limits,
    )?;
    let graph = EvidenceGraph::new(
        &inventory,
        vec![
            GraphNode {
                id: "app".into(),
                kind: GraphNodeKind::System,
                evidence_ids: vec!["ev-1".into()],
                observation_id: None,
                observation_kind: None,
            },
            GraphNode {
                id: "use-site".into(),
                kind: GraphNodeKind::CryptoUse,
                evidence_ids: vec!["ev-1".into()],
                observation_id: Some("obs-1".into()),
                observation_kind: Some(use_kind),
            },
        ],
        vec![GraphEdge {
            from: "app".into(),
            to: "use-site".into(),
            relation: GraphRelation::ExposesUse,
            evidence_ids: vec!["ev-1".into()],
        }],
        &limits,
    )?;
    let topology = DependencyAnalysis::analyze(&graph, &limits)?;
    Ok((inventory, graph, topology))
}

fn complete_context(origin: ClaimOrigin) -> Vec<ContextAssessment> {
    RiskFactorKind::ALL
        .iter()
        .copied()
        .filter(|kind| kind.requires_context())
        .map(|factor| ContextAssessment {
            unit_id: "app".into(),
            factor,
            level: RiskLevel::Moderate,
            origin,
            source_reference: format!("assessment-{}", factor.as_str()),
        })
        .collect()
}

fn classification(origin: ClaimOrigin, posture: QuantumPosture) -> QuantumAssessment {
    QuantumAssessment {
        observation_id: "obs-1".into(),
        posture,
        origin,
        source_reference: "quantum-assessment-r1".into(),
    }
}

fn score_profile() -> Result<ScoreProfile, Diagnostic> {
    ScoreProfile::new("v1-equal".into(), SCORE_PROFILE_VERSION, [1000; 10])
}

fn assess(
    input: &(
        ValidatedInventorySnapshot,
        EvidenceGraph,
        DependencyTopology,
    ),
    profiles: &[QuantumAssessment],
    context: &[ContextAssessment],
    scoring: Option<&ScoreProfile>,
    limits: &Limits,
) -> Result<RiskReport, Diagnostic> {
    RiskAnalysis::analyze(
        &input.0, &input.1, &input.2, profiles, context, scoring, limits,
    )
}

fn factor(report: &RiskReport, kind: RiskFactorKind) -> &RiskFactor {
    &report.units[0].factors[kind.index()]
}

#[test]
fn absent_context_and_unclassified_algorithm_stay_unknown() -> Result<(), Diagnostic> {
    let data = fixture(
        false,
        CryptoUseKind::ActiveUse,
        ConflictState::Uncontested,
        EvidenceBasis::Direct,
    )?;
    let score = score_profile()?;
    let result = assess(&data, &[], &[], Some(&score), &Limits::default())?;
    assert_eq!(result.units.len(), 1);
    assert_eq!(result.units[0].factors.len(), 10);
    assert_eq!(result.units[0].score, None);
    assert_eq!(
        factor(&result, RiskFactorKind::QuantumExposure).uncertainty,
        Some(RiskUncertainty::MissingAssessment)
    );
    assert_eq!(factor(&result, RiskFactorKind::QuantumExposure).level, None);
    assert_eq!(
        factor(&result, RiskFactorKind::EvidenceQuality).level,
        Some(RiskLevel::Low)
    );
    assert_eq!(
        factor(&result, RiskFactorKind::DependencyComplexity).level,
        Some(RiskLevel::Low)
    );
    for kind in RiskFactorKind::ALL {
        if kind.requires_context() {
            assert_eq!(factor(&result, kind).level, None);
            assert_eq!(
                factor(&result, kind).uncertainty,
                Some(RiskUncertainty::MissingAssessment)
            );
        }
    }
    assert!(result.units[0].findings.iter().any(|finding| {
        finding.code == RiskFindingCode::UnresolvedFactor
            && finding.factor == RiskFactorKind::QuantumExposure
    }));
    Ok(())
}

#[test]
fn fully_attributed_inputs_yield_inspectable_versioned_score() -> Result<(), Diagnostic> {
    let data = fixture(
        false,
        CryptoUseKind::NegotiatedProtocol,
        ConflictState::Uncontested,
        EvidenceBasis::Direct,
    )?;
    let quantum = [classification(
        ClaimOrigin::AnalystAssessment,
        QuantumPosture::Susceptible,
    )];
    let mut context = complete_context(ClaimOrigin::AnalystAssessment);
    let profile = score_profile()?;
    let baseline = assess(
        &data,
        &quantum,
        &context,
        Some(&profile),
        &Limits::default(),
    )?;
    let unit = &baseline.units[0];
    assert_eq!(unit.score.as_ref().map(|s| s.pressure_bps), Some(3333));
    assert_eq!(baseline.score_profile, Some(profile.clone()));
    assert_eq!(
        factor(&baseline, RiskFactorKind::QuantumExposure).level,
        Some(RiskLevel::Severe)
    );
    assert_eq!(
        factor(&baseline, RiskFactorKind::QuantumExposure).inventory_evidence_ids,
        ["ev-1"]
    );
    assert_eq!(
        factor(&baseline, RiskFactorKind::QuantumExposure).assessment_references,
        ["quantum-assessment-r1"]
    );
    assert!(
        unit.findings
            .iter()
            .any(|finding| { finding.code == RiskFindingCode::SusceptibleUse })
    );
    context.reverse();
    let reordered = assess(
        &data,
        &quantum,
        &context,
        Some(&profile),
        &Limits::default(),
    )?;
    assert_eq!(baseline, reordered);
    let changed = ScoreProfile::new(
        "v1-weighted".into(),
        1,
        [1900, 900, 900, 900, 900, 900, 900, 900, 900, 900],
    )?;
    let weighted = assess(
        &data,
        &quantum,
        &context,
        Some(&changed),
        &Limits::default(),
    )?;
    assert_eq!(
        weighted.units[0].score.as_ref().map(|s| s.pressure_bps),
        Some(4000)
    );
    assert_eq!(weighted.units[0].factors, unit.factors);
    assert_eq!(weighted.units[0].findings, unit.findings);
    Ok(())
}

#[test]
fn configured_or_library_capability_never_becomes_active_use() -> Result<(), Diagnostic> {
    for kind in [
        CryptoUseKind::LibraryCapability,
        CryptoUseKind::ConfiguredProtocol,
    ] {
        let data = fixture(
            false,
            kind,
            ConflictState::Uncontested,
            EvidenceBasis::Direct,
        )?;
        let profiles = [classification(
            ClaimOrigin::AnalystAssessment,
            QuantumPosture::Susceptible,
        )];
        let context = complete_context(ClaimOrigin::AnalystAssessment);
        let report = assess(
            &data,
            &profiles,
            &context,
            Some(&score_profile()?),
            &Limits::default(),
        )?;
        assert_eq!(factor(&report, RiskFactorKind::QuantumExposure).level, None);
        assert_eq!(
            factor(&report, RiskFactorKind::QuantumExposure).uncertainty,
            Some(RiskUncertainty::UnconfirmedUse)
        );
        assert!(report.units[0].score.is_none());
        assert!(
            !report.units[0]
                .findings
                .iter()
                .any(|finding| { finding.code == RiskFindingCode::SusceptibleUse })
        );
    }
    Ok(())
}

#[test]
fn uncertainty_survives_known_severe_exposure() -> Result<(), Diagnostic> {
    let data = fixture(
        false,
        CryptoUseKind::ActiveUse,
        ConflictState::Conflicted,
        EvidenceBasis::Inferred,
    )?;
    let profile = [classification(
        ClaimOrigin::AnalystAssessment,
        QuantumPosture::Susceptible,
    )];
    let context = complete_context(ClaimOrigin::AnalystAssessment);
    let report = assess(
        &data,
        &profile,
        &context,
        Some(&score_profile()?),
        &Limits::default(),
    )?;
    let exposed = factor(&report, RiskFactorKind::QuantumExposure);
    assert_eq!(exposed.level, Some(RiskLevel::Severe));
    assert!(exposed.uncertainty.is_some());
    assert_eq!(report.units[0].score, None);
    assert_eq!(
        factor(&report, RiskFactorKind::EvidenceQuality).level,
        Some(RiskLevel::High)
    );
    assert!(
        factor(&report, RiskFactorKind::EvidenceQuality)
            .uncertainty
            .is_some()
    );
    Ok(())
}

#[test]
fn incomplete_collection_and_scenario_assumptions_never_score() -> Result<(), Diagnostic> {
    let data = fixture(
        true,
        CryptoUseKind::ActiveUse,
        ConflictState::Uncontested,
        EvidenceBasis::Direct,
    )?;
    let context = complete_context(ClaimOrigin::ScenarioAssumption);
    let profile = [classification(
        ClaimOrigin::ScenarioAssumption,
        QuantumPosture::CandidateResistant,
    )];
    let report = assess(
        &data,
        &profile,
        &context,
        Some(&score_profile()?),
        &Limits::default(),
    )?;
    assert_eq!(report.units[0].score, None);
    assert_eq!(
        factor(&report, RiskFactorKind::QuantumExposure).level,
        Some(RiskLevel::Moderate)
    );
    assert!(
        factor(&report, RiskFactorKind::QuantumExposure)
            .uncertainty
            .is_some()
    );
    assert_eq!(
        factor(&report, RiskFactorKind::EvidenceQuality).uncertainty,
        Some(RiskUncertainty::IncompleteCoverage)
    );
    assert_eq!(
        factor(&report, RiskFactorKind::DependencyComplexity).uncertainty,
        Some(RiskUncertainty::IncompleteCoverage)
    );
    assert!(
        report.units[0]
            .findings
            .iter()
            .any(|finding| { finding.code == RiskFindingCode::ScenarioDependent })
    );
    Ok(())
}

#[test]
fn missing_second_profile_cannot_be_masked_by_a_known_severe_use() -> Result<(), Diagnostic> {
    let (inventory, graph, _) = fixture(
        false,
        CryptoUseKind::ActiveUse,
        ConflictState::Uncontested,
        EvidenceBasis::Direct,
    )?;
    let mut input = inventory.snapshot().clone();
    input.observations.push(CryptoObservation {
        id: "obs-2".into(),
        asset_id: "app".into(),
        algorithm_id: "profile-not-classified".into(),
        kind: CryptoUseKind::ActiveUse,
        conflict: ConflictState::Uncontested,
        evidence_ids: vec!["ev-1".into()],
    });
    let snapshot = ValidatedInventorySnapshot::new(input, &Limits::default())?;
    let mut nodes = graph.nodes().to_vec();
    nodes.push(GraphNode {
        id: "use-second".into(),
        kind: GraphNodeKind::CryptoUse,
        evidence_ids: vec!["ev-1".into()],
        observation_id: Some("obs-2".into()),
        observation_kind: Some(CryptoUseKind::ActiveUse),
    });
    let mut edges = graph.edges().to_vec();
    edges.push(GraphEdge {
        from: "app".into(),
        to: "use-second".into(),
        relation: GraphRelation::ExposesUse,
        evidence_ids: vec!["ev-1".into()],
    });
    let bound = EvidenceGraph::new(&snapshot, nodes, edges, &Limits::default())?;
    let topology = DependencyAnalysis::analyze(&bound, &Limits::default())?;
    let input = (snapshot, bound, topology);
    let profile = [classification(
        ClaimOrigin::AnalystAssessment,
        QuantumPosture::Susceptible,
    )];
    let report = assess(
        &input,
        &profile,
        &complete_context(ClaimOrigin::AnalystAssessment),
        Some(&score_profile()?),
        &Limits::default(),
    )?;
    let exposure = factor(&report, RiskFactorKind::QuantumExposure);
    assert_eq!(exposure.level, Some(RiskLevel::Severe));
    assert_eq!(
        exposure.uncertainty,
        Some(RiskUncertainty::MissingAssessment)
    );
    assert!(report.units[0].score.is_none());
    Ok(())
}

#[test]
fn invalid_sources_duplicates_and_derived_factor_overrides_rejected() -> Result<(), Diagnostic> {
    let data = fixture(
        false,
        CryptoUseKind::ActiveUse,
        ConflictState::Uncontested,
        EvidenceBasis::Direct,
    )?;
    let p = classification(ClaimOrigin::AnalystAssessment, QuantumPosture::Susceptible);
    let check = |q: Vec<QuantumAssessment>, c: Vec<ContextAssessment>| {
        assess(&data, &q, &c, None, &Limits::default())
            .err()
            .map(|e| e.code)
    };
    assert_eq!(
        check(vec![p.clone(), p.clone()], vec![]),
        Some(DiagnosticCode::DuplicateRecord)
    );
    let mut missing = p.clone();
    missing.observation_id = "unknown".into();
    assert_eq!(
        check(vec![missing], vec![]),
        Some(DiagnosticCode::InvalidReference)
    );
    let mut bad_ref = p.clone();
    bad_ref.source_reference = " \n ".into();
    assert_eq!(
        check(vec![bad_ref], vec![]),
        Some(DiagnosticCode::InvalidIdentifier)
    );
    let mut claims = complete_context(ClaimOrigin::AnalystAssessment);
    claims.push(claims[0].clone());
    assert_eq!(
        check(vec![p.clone()], claims),
        Some(DiagnosticCode::DuplicateRecord)
    );
    let mut override_factor = complete_context(ClaimOrigin::AnalystAssessment);
    override_factor[0].factor = RiskFactorKind::QuantumExposure;
    assert_eq!(
        check(vec![p.clone()], override_factor),
        Some(DiagnosticCode::InvalidStateTransition)
    );
    let mut wrong_unit = complete_context(ClaimOrigin::AnalystAssessment);
    wrong_unit[0].unit_id = "other-tenant-unit".into();
    assert_eq!(
        check(vec![p], wrong_unit),
        Some(DiagnosticCode::InvalidReference)
    );
    Ok(())
}

#[test]
fn mismatched_source_digests_fail_closed() -> Result<(), Diagnostic> {
    let original = fixture(
        false,
        CryptoUseKind::ActiveUse,
        ConflictState::Uncontested,
        EvidenceBasis::Direct,
    )?;
    let different = fixture(
        true,
        CryptoUseKind::ActiveUse,
        ConflictState::Uncontested,
        EvidenceBasis::Direct,
    )?;
    let outcome = RiskAnalysis::analyze(
        &different.0,
        &original.1,
        &original.2,
        &[],
        &[],
        None,
        &Limits::default(),
    );
    assert_eq!(
        outcome.err().map(|e| e.code),
        Some(DiagnosticCode::IntegrityMismatch)
    );
    Ok(())
}

#[test]
fn invalid_profiles_and_tight_resource_budgets_fail_closed() -> Result<(), Diagnostic> {
    assert_eq!(
        ScoreProfile::new("invalid".into(), 99, [1000; 10])
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::UnsupportedSchemaVersion)
    );
    assert_eq!(
        ScoreProfile::new("invalid".into(), 1, [0; 10])
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::InvalidLimit)
    );
    assert_eq!(
        ScoreProfile::new("invalid".into(), 1, [2000; 10])
            .err()
            .map(|e| e.code),
        Some(DiagnosticCode::InvalidLimit)
    );
    let data = fixture(
        false,
        CryptoUseKind::ActiveUse,
        ConflictState::Uncontested,
        EvidenceBasis::Direct,
    )?;
    let contexts = complete_context(ClaimOrigin::AnalystAssessment);
    let profiles = [classification(
        ClaimOrigin::AnalystAssessment,
        QuantumPosture::Susceptible,
    )];
    let cases = [
        Limits {
            max_planner_candidates: 9,
            ..Limits::default()
        },
        Limits {
            max_evidence_records: 7,
            ..Limits::default()
        },
        Limits {
            max_diagnostics: 1,
            ..Limits::default()
        },
        Limits {
            max_export_bytes: 1,
            ..Limits::default()
        },
        Limits {
            max_graph_edges: 2,
            ..Limits::default()
        },
    ];
    for limits in cases {
        let result = assess(
            &data,
            &profiles,
            &contexts,
            Some(&score_profile()?),
            &limits,
        );
        assert_eq!(
            result.err().map(|e| e.code),
            Some(DiagnosticCode::ResourceLimitExceeded)
        );
    }
    Ok(())
}

#[test]
fn external_source_text_is_bounded_before_building_assessment_indexes()
-> Result<(), Diagnostic> {
    let data = fixture(
        false,
        CryptoUseKind::ActiveUse,
        ConflictState::Uncontested,
        EvidenceBasis::Direct,
    )?;
    let mut claims = complete_context(ClaimOrigin::AnalystAssessment);
    for claim in &mut claims {
        claim.source_reference = format!("reference-{}", "x".repeat(180));
    }
    let limits = Limits {
        max_input_bytes: 1024,
        ..Limits::default()
    };
    let outcome = assess(&data, &[], &claims, None, &limits);
    assert_eq!(
        outcome.err().map(|e| e.code),
        Some(DiagnosticCode::ResourceLimitExceeded)
    );
    Ok(())
}

