//! Versioned, explicitly attributed cryptographic-risk factor contracts.
//! No score or classification authorizes a migration or cryptographic use.

use crate::{Diagnostic, DiagnosticCode, SnapshotDigest};

/// Exact factor-vector schema; later changes require a new version.
pub const RISK_FACTOR_VERSION: u16 = 1;
/// Supported score-profile schema, not a policy or compliance standard.
pub const SCORE_PROFILE_VERSION: u16 = 1;

/// Risk-pressure dimensions in their stable version-1 positional order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RiskFactorKind {
    /// Exposure to explicitly classified quantum-susceptible use sites.
    QuantumExposure,
    /// Confidentiality protection horizon, externally assessed.
    ConfidentialityLifetime,
    /// Signature-verification protection horizon, externally assessed.
    SignatureLifetime,
    /// Consequence to service operations, externally assessed.
    OperationalCriticality,
    /// Source completeness, conflicts and basis quality.
    EvidenceQuality,
    /// Migration readiness assessment, never assumed.
    MigrationReadiness,
    /// Observed dependency/cycle complexity, not migration approval.
    DependencyComplexity,
    /// Externally assessed target deadline pressure.
    DeadlinePressure,
    /// Protocol and peer interoperability assessment.
    Interoperability,
    /// Deployment and rollback change-complexity assessment.
    ChangeComplexity,
}

impl RiskFactorKind {
    /// Canonical factor order for version 1 and score-weight alignment.
    pub const ALL: [Self; 10] = [
        Self::QuantumExposure,
        Self::ConfidentialityLifetime,
        Self::SignatureLifetime,
        Self::OperationalCriticality,
        Self::EvidenceQuality,
        Self::MigrationReadiness,
        Self::DependencyComplexity,
        Self::DeadlinePressure,
        Self::Interoperability,
        Self::ChangeComplexity,
    ];

    /// Stable ASCII factor name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QuantumExposure => "quantum_exposure",
            Self::ConfidentialityLifetime => "confidentiality_lifetime",
            Self::SignatureLifetime => "signature_lifetime",
            Self::OperationalCriticality => "operational_criticality",
            Self::EvidenceQuality => "evidence_quality",
            Self::MigrationReadiness => "migration_readiness",
            Self::DependencyComplexity => "dependency_complexity",
            Self::DeadlinePressure => "deadline_pressure",
            Self::Interoperability => "interoperability",
            Self::ChangeComplexity => "change_complexity",
        }
    }

    /// Position in the exact version-1 score profile.
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Whether a value must be explicitly attributed by an external caller.
    #[must_use]
    pub const fn requires_context(self) -> bool {
        !matches!(
            self,
            Self::QuantumExposure | Self::EvidenceQuality | Self::DependencyComplexity
        )
    }
}

/// Qualitative ordinal risk pressure; not an estimated probability.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RiskLevel {
    /// Lowest model-specific pressure, not proof of cryptographic safety.
    Low,
    /// Some additional migration/security attention indicated.
    Moderate,
    /// Elevated pressure.
    High,
    /// Severe reported or evidenced exposure.
    Severe,
}

impl RiskLevel {
    /// Ordinal for deterministic optional scoring, in 0..=3.
    #[must_use]
    pub const fn ordinal(self) -> u32 {
        self as u32
    }
}

/// Explicit reason a factor remains unresolved, even if elevated risk is known.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RiskUncertainty {
    /// Required contextual data or explicit classification is absent.
    MissingAssessment,
    /// The graph establishes no directly attributed crypto use.
    NoConfirmedUse,
    /// Configured or library capability cannot establish active use.
    UnconfirmedUse,
    /// Referenced evidence is inferred or has unknown collection basis.
    WeakEvidence,
    /// Source observations conflict or cannot be reconciled.
    ConflictingEvidence,
    /// A collector reported partial or failed scope coverage.
    IncompleteCoverage,
    /// Result depends on an explicitly declared scenario assumption.
    ScenarioAssumption,
}

/// Claim provenance is declared, not automatically authenticated.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ClaimOrigin {
    /// Externally assessed, independently sourced claim.
    AnalystAssessment,
    /// Modeling assumption with no claim of factual verification.
    ScenarioAssumption,
}

/// Classification of one observation by an external, attributed source.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum QuantumPosture {
    /// Source asserts exposure to a quantum-susceptible scheme.
    Susceptible,
    /// Source asserts an unverified post-quantum-resistant candidate.
    CandidateResistant,
    /// Source does not establish susceptibility.
    Unknown,
}

/// Explicit quantum classification tied to a validated inventory observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuantumAssessment {
    /// Stable observation ID present in validated inventory.
    pub observation_id: String,
    /// Assessed posture; no algorithm-name parsing or silent normalization.
    pub posture: QuantumPosture,
    /// External assessment versus scenario assumption.
    pub origin: ClaimOrigin,
    /// Opaque provenance reference to an external assessment record.
    pub source_reference: String,
}

/// Supplied context for one migration unit and one nondeducible factor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextAssessment {
    /// Exact SCC migration-unit ID in supplied topology.
    pub unit_id: String,
    /// Factor not derivable solely from inventory or graph structure.
    pub factor: RiskFactorKind,
    /// Explicit ordinal assessment, not raw calendar years or an inference.
    pub level: RiskLevel,
    /// Assessment or scenario assumption.
    pub origin: ClaimOrigin,
    /// Opaque, externally maintained provenance record ID.
    pub source_reference: String,
}

/// Auditable factor value with an unresolved caveat, when applicable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskFactor {
    /// Stable factor kind in version-1 vector order.
    pub kind: RiskFactorKind,
    /// Reported/derived pressure; None is unknown, never zero.
    pub level: Option<RiskLevel>,
    /// Additional uncertainty disables aggregate scoring.
    pub uncertainty: Option<RiskUncertainty>,
    /// Canonical union of underlying inventory evidence IDs.
    pub inventory_evidence_ids: Vec<String>,
    /// External context/profile references, not authenticated here.
    pub assessment_references: Vec<String>,
}

/// Stable, machine-readable explanatory finding.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RiskFindingCode {
    /// Missing, conflicting, partial or assumed factor evidence.
    UnresolvedFactor,
    /// Factor has High or Severe pressure with source references.
    ElevatedFactor,
    /// Quantum susceptibility asserted for a relevant use site.
    SusceptibleUse,
    /// Source declared an assumption, not established evidence.
    ScenarioDependent,
}

/// Finding refers back to full factor evidence instead of duplicating it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskFinding {
    /// Typed finding code.
    pub code: RiskFindingCode,
    /// Factor containing source references and uncertainty.
    pub factor: RiskFactorKind,
}

/// Configurable, fully inspectable weighting contract for optional scoring.
///
/// Caller is responsible for authenticating and managing policy/profile IDs;
/// this library enforces only supported schema and bounded arithmetic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScoreProfile {
    id: String,
    version: u16,
    weights_bps: [u16; 10],
}

impl ScoreProfile {
    /// Validate ten strictly positive weights adding to exactly 10,000 bps.
    pub fn new(
        id: String,
        version: u16,
        weights_bps: [u16; 10],
    ) -> Result<Self, Diagnostic> {
        if version != SCORE_PROFILE_VERSION {
            return Err(Diagnostic::new(
                DiagnosticCode::UnsupportedSchemaVersion,
                "score_profile_version",
                "score profile schema version is unsupported",
            ));
        }
        if id.is_empty()
            || id.len() > 256
            || id.trim() != id
            || id.chars().any(char::is_control)
        {
            return Err(Diagnostic::new(
                DiagnosticCode::InvalidIdentifier,
                "score_profile_id",
                "score profile identifier is invalid",
            ));
        }
        let mut sum = 0_u32;
        for weight in weights_bps {
            if weight == 0 || weight > 10_000 {
                return Err(Diagnostic::new(
                    DiagnosticCode::InvalidLimit,
                    "score_weight",
                    "each score factor must have a positive bounded weight",
                ));
            }
            sum = sum.checked_add(u32::from(weight)).ok_or_else(|| {
                Diagnostic::new(
                    DiagnosticCode::ArithmeticOverflow,
                    "score_weight",
                    "score weights overflow",
                )
            })?;
        }
        if sum != 10_000 {
            return Err(Diagnostic::new(
                DiagnosticCode::InvalidLimit,
                "score_weights",
                "all ten score weights must sum to exactly 10000 basis points",
            ));
        }
        Ok(Self {
            id,
            version,
            weights_bps,
        })
    }

    /// External profile ID, whose authenticity caller must establish.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Version of score-weight schema.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Inspectable weights in RiskFactorKind::ALL order.
    #[must_use]
    pub const fn weights_bps(&self) -> &[u16; 10] {
        &self.weights_bps
    }

    pub(crate) fn score(&self, factors: &[RiskFactor]) -> Option<u16> {
        if factors.len() != RiskFactorKind::ALL.len() {
            return None;
        }
        let mut numerator = 0_u32;
        for (index, factor) in factors.iter().enumerate() {
            if factor.kind != RiskFactorKind::ALL[index] || factor.uncertainty.is_some() {
                return None;
            }
            let risk = factor.level?;
            numerator += u32::from(self.weights_bps[index]) * risk.ordinal();
        }
        // Sum weights is exactly 10000; denominator is max ordinal 3.
        u16::try_from((numerator + 1) / 3).ok()
    }
}

/// Optional aggregate is secondary to full factor vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskScore {
    /// Heuristic pressure in 0..=10000 bps, not a probability.
    pub pressure_bps: u16,
    /// Explicit scoring profile ID.
    pub profile_id: String,
    /// Exact scoring profile schema version.
    pub profile_version: u16,
}

/// Evidence-first vector for one SCC unit, with exactly ten factors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitRiskVector {
    /// Original canonical SCC ID.
    pub unit_id: String,
    /// All ten typed factors, including every unknown or disputed factor.
    pub factors: Vec<RiskFactor>,
    /// Typed findings that reference corresponding factor.
    pub findings: Vec<RiskFinding>,
    /// None when profile absent or any factor unknown/uncertain.
    pub score: Option<RiskScore>,
}

/// Analysis anchored to a single validated source inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskReport {
    /// Factor schema version, not version of NIST policy.
    pub model_version: u16,
    /// Original canonical inventory content digest.
    pub source_digest: SnapshotDigest,
    /// Optional fully inspectable weight profile.
    pub score_profile: Option<ScoreProfile>,
    /// Canonically ordered SCC-level evidence-first vectors.
    pub units: Vec<UnitRiskVector>,
}
