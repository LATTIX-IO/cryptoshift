//! Independent Cryptoshift policy-result fixture, not a Cryptopolicy parser.
//!
//! Cryptopolicy's source evaluation produces permit/deny/indeterminate
//! assertions. This adapter retains their uncertainty; no source assertion
//! creates a target policy, authenticated approval, or operational readiness.

use std::collections::BTreeSet;

use crate::neutral_codec::{NeutralWriter, error, expected, identifier};
use crate::{
    Diagnostic, DiagnosticCode, KnownAlgorithm, Limits, ResourceKind, SnapshotDigest,
    TargetDisposition, TargetProfile,
};

/// Supported Cryptoshift-neutral policy-decision fixture revision.
pub const NEUTRAL_POLICY_VERSION: u16 = 1;

/// An outcome *claimed* by a separate policy evaluation engine.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum NeutralPolicyOutcome {
    /// A source reports permit. This is NEVER Cryptoshift change authorization.
    PermitClaimed = 1,
    /// A source reports deny. Fail closed regardless of external authentication.
    DenyClaimed = 2,
    /// No authoritative decision has been established.
    Indeterminate = 3,
}

/// Provenance triple; not an authenticated source signature or receipt.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NeutralPolicyEvidence {
    /// Original source namespace.
    pub source_id: String,
    /// Original source-local observation ID.
    pub evidence_id: String,
    /// Exact source record revision.
    pub source_revision: String,
}

/// One exact parameter-set policy evaluation from a source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeutralPolicyDecision {
    /// Exact recognized algorithm; aliases and unknown sets do not map.
    pub algorithm: KnownAlgorithm,
    /// Source-reported, explicitly nonauthoritative evaluation.
    pub outcome: NeutralPolicyOutcome,
    /// Opaque normalized reason code, never raw policy text.
    pub reason_code: String,
    /// Independently attributable input claims.
    pub evidence: Vec<NeutralPolicyEvidence>,
}

/// Untrusted typed result provided by an upstream-neutral fixture adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeutralPolicyInput {
    /// Exact v1 Cryptoshift-owned interchange schema.
    pub schema_version: u16,
    /// Policy-source namespace (not identity authentication).
    pub source_id: String,
    /// Exact source-policy identifier.
    pub policy_id: String,
    /// Exact source-policy revision string.
    pub policy_revision: String,
    /// Original source-evaluated policy content SHA-256.
    pub policy_digest: SnapshotDigest,
    /// Required target content identity, supplied independently.
    pub target_digest: SnapshotDigest,
    /// Exact tenant scope shared with the immutable target.
    pub scope_id: String,
    /// Caller-supplied UTC evaluation time; no ambient time.
    pub evaluated_at_unix_secs: i64,
    /// Source-declared expiry. No automatic renewal or grace period.
    pub expires_at_unix_secs: i64,
    /// Source decisions, including conflicts and indeterminate outcomes.
    pub decisions: Vec<NeutralPolicyDecision>,
}

/// The only effective gates available from *untrusted* policy evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeutralPolicyGate {
    /// A mandatory target prohibition or source denial prevents endorsement.
    Prohibited,
    /// May require external evidence; never "approved" or "safe".
    Unverified,
}

/// Immutable, versioned policy-result view; cannot authorize migration.
#[derive(Clone, Debug)]
pub struct NeutralPolicyReview {
    source_id: String,
    scope_id: String,
    target_digest: SnapshotDigest,
    policy_digest: SnapshotDigest,
    decisions: Vec<NeutralPolicyDecision>,
    canonical: Vec<u8>,
    digest: SnapshotDigest,
}

impl NeutralPolicyReview {
    /// Source provenance claim (not an authenticated publisher).
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }
    /// Scope/tenant, verified against immutable TargetProfile content.
    #[must_use]
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }
    /// Expected target revision content identity.
    #[must_use]
    pub const fn target_digest(&self) -> SnapshotDigest {
        self.target_digest
    }
    /// Claimed original source policy content identity.
    #[must_use]
    pub const fn policy_digest(&self) -> SnapshotDigest {
        self.policy_digest
    }
    /// Original source-attributed decisions sorted by recognized algorithm.
    #[must_use]
    pub fn decisions(&self) -> &[NeutralPolicyDecision] {
        &self.decisions
    }
    /// Canonical report digest, never an authoritative decision signature.
    #[must_use]
    pub const fn digest(&self) -> SnapshotDigest {
        self.digest
    }
    /// Bounded canonical v1 export, not a JSON policy decoder.
    pub fn export(&self, limits: &Limits) -> Result<Vec<u8>, Diagnostic> {
        limits.check(ResourceKind::ExportBytes, self.canonical.len())?;
        Ok(self.canonical.clone())
    }

    /// Return only Prohibited or Unverified, never Permit/Approved/Ready.
    ///
    /// The caller must independently authenticate and pin the target source.
    pub fn gate_for(
        &self,
        target: &TargetProfile,
        algorithm_id: &str,
    ) -> Result<NeutralPolicyGate, Diagnostic> {
        target.verify_expected_digest(self.target_digest)?;
        let algorithm = KnownAlgorithm::parse_exact(algorithm_id)?;
        let target_disposition = target.disposition(algorithm_id)?;
        if target_disposition == TargetDisposition::Forbidden
            || self
                .decisions
                .iter()
                .any(|d| d.algorithm == algorithm && d.outcome == NeutralPolicyOutcome::DenyClaimed)
        {
            Ok(NeutralPolicyGate::Prohibited)
        } else {
            Ok(NeutralPolicyGate::Unverified)
        }
    }

    /// Validate typed source/target consistency and bind a deterministic report.
    ///
    /// A source "permit" cannot weaken a Forbidden target, and a permit
    /// for an unlisted target constraint is never inferred.
    pub fn new(
        mut input: NeutralPolicyInput,
        target: &TargetProfile,
        limits: &Limits,
    ) -> Result<Self, Diagnostic> {
        limits.validate()?;
        if input.schema_version != NEUTRAL_POLICY_VERSION {
            return Err(error(
                DiagnosticCode::UnsupportedSchemaVersion,
                "neutral_policy_version",
                "neutral policy schema revision is unsupported",
            ));
        }
        for (value, subject) in [
            (&input.source_id, "neutral_policy_source"),
            (&input.policy_id, "neutral_policy_id"),
            (&input.policy_revision, "neutral_policy_revision"),
            (&input.scope_id, "neutral_policy_scope"),
        ] {
            identifier(value, subject)?;
        }
        if input.scope_id != target.content().scope_id {
            return Err(error(
                DiagnosticCode::InvalidReference,
                "neutral_policy_scope",
                "source policy result and target policy must share one tenant scope",
            ));
        }
        expected(
            target.digest(),
            input.target_digest,
            "neutral_policy_target",
        )?;
        if input.policy_digest == SnapshotDigest::from_bytes([0; 32]) {
            return Err(error(
                DiagnosticCode::MissingProvenance,
                "neutral_policy_digest",
                "source policy digest must identify a nonempty source revision",
            ));
        }
        if input.expires_at_unix_secs <= input.evaluated_at_unix_secs
            || target
                .content()
                .expires_at_unix_secs
                .is_some_and(|expiry| input.evaluated_at_unix_secs >= expiry)
        {
            return Err(error(
                DiagnosticCode::StaleCriticalProfile,
                "neutral_policy_freshness",
                "source policy or target expired at declared evaluation time",
            ));
        }
        limits.check(ResourceKind::ProfileReferences, input.decisions.len())?;
        let mut evidence_count = 0usize;
        let mut identity = BTreeSet::new();
        for decision in &mut input.decisions {
            identifier(&decision.reason_code, "neutral_policy_reason")?;
            if !identity.insert(decision.algorithm) {
                return Err(error(
                    DiagnosticCode::DuplicateRecord,
                    "neutral_policy_algorithm",
                    "source policy has multiple mutually ambiguous outcomes for one algorithm",
                ));
            }
            let target_state = target.disposition(decision.algorithm.id())?;
            if decision.outcome == NeutralPolicyOutcome::PermitClaimed
                && (target_state == TargetDisposition::Forbidden
                    || target_state == TargetDisposition::NotSpecified)
            {
                return Err(error(
                    DiagnosticCode::InvalidStateTransition,
                    "neutral_policy_conflict",
                    "source permit cannot override forbidden or undeclared target requirement",
                ));
            }
            if decision.evidence.is_empty()
                && decision.outcome != NeutralPolicyOutcome::Indeterminate
            {
                return Err(error(
                    DiagnosticCode::MissingProvenance,
                    "neutral_policy_evidence",
                    "claimed permit or deny requires source-qualified evidence",
                ));
            }
            evidence_count = limits.checked_add(
                ResourceKind::EvidenceRecords,
                evidence_count,
                decision.evidence.len(),
            )?;
            let mut refs = BTreeSet::new();
            for evidence in &decision.evidence {
                for (value, subject) in [
                    (&evidence.source_id, "neutral_policy_evidence_source"),
                    (&evidence.evidence_id, "neutral_policy_evidence_id"),
                    (
                        &evidence.source_revision,
                        "neutral_policy_evidence_revision",
                    ),
                ] {
                    identifier(value, subject)?;
                }
                if !refs.insert((
                    &evidence.source_id,
                    &evidence.evidence_id,
                    &evidence.source_revision,
                )) {
                    return Err(error(
                        DiagnosticCode::DuplicateRecord,
                        "neutral_policy_evidence",
                        "duplicate source/evidence/revision triple",
                    ));
                }
            }
            decision.evidence.sort();
        }
        input.decisions.sort_by_key(|d| d.algorithm);
        let mut writer = NeutralWriter::new(b"CSHIFT_NEUTRAL_POLICY_V1", limits)?;
        writer.u16(input.schema_version)?;
        writer.string(&input.source_id)?;
        writer.string(&input.policy_id)?;
        writer.string(&input.policy_revision)?;
        writer.digest(input.policy_digest)?;
        writer.digest(input.target_digest)?;
        writer.string(&input.scope_id)?;
        writer.i64(input.evaluated_at_unix_secs)?;
        writer.i64(input.expires_at_unix_secs)?;
        writer.count(input.decisions.len())?;
        for decision in &input.decisions {
            writer.string(decision.algorithm.id())?;
            writer.u8(decision.outcome as u8)?;
            writer.string(&decision.reason_code)?;
            writer.count(decision.evidence.len())?;
            for reference in &decision.evidence {
                writer.string(&reference.source_id)?;
                writer.string(&reference.evidence_id)?;
                writer.string(&reference.source_revision)?;
            }
        }
        let (canonical, digest) = writer.finish()?;
        Ok(Self {
            source_id: input.source_id,
            scope_id: input.scope_id,
            target_digest: input.target_digest,
            policy_digest: input.policy_digest,
            decisions: input.decisions,
            canonical,
            digest,
        })
    }

    /// Require an expected report digest from a separately trusted channel.
    ///
    /// A matching digest is still NOT proof of independent policy authority.
    pub fn import_pinned(
        input: NeutralPolicyInput,
        target: &TargetProfile,
        expected_policy_digest: SnapshotDigest,
        expected_report_digest: SnapshotDigest,
        limits: &Limits,
    ) -> Result<Self, Diagnostic> {
        expected(
            input.policy_digest,
            expected_policy_digest,
            "neutral_policy_source_digest",
        )?;
        let review = Self::new(input, target, limits)?;
        expected(
            review.digest,
            expected_report_digest,
            "neutral_policy_report_digest",
        )?;
        Ok(review)
    }
}
