//! Deterministic, evidence-preserving cryptographic inventory contract.
//! Claims in a snapshot are not proof of collector identity or cryptographic safety.

use crate::{Diagnostic, DiagnosticCode, Limits, ResourceKind, SchemaKind, VersionedEnvelope};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Only supported identity version.
pub const IDENTITY_VERSION: u16 = 1;
/// Only supported normalization contract.
pub const NORMALIZATION_VERSION: u16 = 1;

/// Meaning of a cryptographic observation, without inference between categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoUseKind {
    /// Observed cryptographic execution.
    ActiveUse,
    /// Algorithm supported by a library, not necessarily used.
    LibraryCapability,
    /// Protocol configured, not necessarily negotiated.
    ConfiguredProtocol,
    /// Negotiated protocol observed on the wire.
    NegotiatedProtocol,
    /// Not established.
    Unknown,
}

/// Whether a source directly observed a fact or inferred it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceBasis {
    /// Direct collection.
    Direct,
    /// Inferred collection.
    Inferred,
    /// Collection method unknown.
    Unknown,
}

/// Conflict state, independent of confidence and use classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictState {
    /// No conflict was reported; not proof of universal agreement.
    Uncontested,
    /// Evidence sources directly conflict.
    Conflicted,
    /// Source contradictions remain unresolved.
    Unresolved,
}

/// Completeness of an individual collection run and declared scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionCompleteness {
    /// Complete according to this source's coverage claim.
    Complete,
    /// Only some portions were inspected.
    Partial,
    /// Collection did not complete.
    Failed,
}

/// Confidence assigned to an asset absence; never inferred from a failed scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbsenceStatus {
    /// Tentative absence, never verified removal.
    Tentative,
    /// Source claims absence after complete scoped reinspection.
    Confirmed,
}

/// One attributable collection run within a snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionRun {
    /// Opaque run ID.
    pub id: String,
    /// Source ID; attribution is not cryptographic authentication.
    pub source_id: String,
    /// Scope ID, identical to enclosing snapshot scope.
    pub scope_id: String,
    /// Explicit Unix timestamp supplied by source.
    pub collected_at_unix_secs: i64,
    /// Source-declared coverage completeness.
    pub completeness: CollectionCompleteness,
}

/// Independently attributable observation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRecord {
    /// Opaque evidence ID.
    pub id: String,
    /// Run ID to which the evidence belongs.
    pub run_id: String,
    /// Source ID, which must equal the run's source.
    pub source_id: String,
    /// Direct, inferred or unknown basis.
    pub basis: EvidenceBasis,
    /// Inclusive confidence in basis points from zero to 10000.
    pub confidence_bps: u16,
    /// Explicit Unix collection timestamp.
    pub observed_at_unix_secs: i64,
}

/// Cryptographic observation retaining source references and use-site identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoObservation {
    /// Opaque stable observation ID.
    pub id: String,
    /// Asset or provisional asset ID.
    pub asset_id: String,
    /// Exact asserted algorithm or profile ID, not silently normalized.
    pub algorithm_id: String,
    /// Explicit capability/use/negotiated distinction.
    pub kind: CryptoUseKind,
    /// Explicit conflicting/uncertain status.
    pub conflict: ConflictState,
    /// One or more independent evidence IDs, sorted during validation.
    pub evidence_ids: Vec<String>,
}

/// A scoped source's claim of asset absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbsenceRecord {
    /// Run that made this claim.
    pub run_id: String,
    /// Previously known asset, not required in current observations.
    pub asset_id: String,
    /// Tentative or source-confirmed absence.
    pub status: AbsenceStatus,
}

/// Untrusted mutable input. Use validation before any downstream analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventorySnapshot {
    /// Schema-independent identity generation.
    pub identity_version: u16,
    /// Algorithm ID normalization generation.
    pub normalization_version: u16,
    /// Scope/tenant boundary.
    pub scope_id: String,
    /// Independently attributed collection runs.
    pub runs: Vec<CollectionRun>,
    /// Evidence from all collection sources.
    pub evidence: Vec<EvidenceRecord>,
    /// All observations, including contradictions and unknowns.
    pub observations: Vec<CryptoObservation>,
    /// Explicit tentative/confirmed absence assertions.
    pub absences: Vec<AbsenceRecord>,
}

/// SHA-256 digest of uniquely serialized snapshot bytes.
///
/// A digest authenticates neither the source nor the truth of any fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotDigest([u8; 32]);

impl SnapshotDigest {
    /// Construct expected digest from a separately trusted source.
    #[must_use]
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Raw 32-byte value.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Displayable SHA-256-prefixed hexadecimal identity.
    #[must_use]
    pub fn as_identifier(self) -> String {
        let mut result = String::from("sha256:");
        for byte in self.0 {
            use std::fmt::Write as _;
            let _ = write!(&mut result, "{byte:02x}");
        }
        result
    }

    pub(crate) fn hash(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut result = [0_u8; 32];
        result.copy_from_slice(&digest);
        Self(result)
    }
}

/// Immutable, fully referentially checked snapshot.
#[derive(Clone, Debug)]
pub struct ValidatedInventorySnapshot {
    snapshot: InventorySnapshot,
}

/// Versioned canonical bytes with their integrity identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryArtifact {
    /// Deterministic canonical representation, not an authenticated claim.
    pub bytes: Vec<u8>,
    /// Content digest bound to all serialized identity and coverage fields.
    pub digest: SnapshotDigest,
}

impl ValidatedInventorySnapshot {
    /// Validate bounds, IDs, sources, conflicts, and completeness; canonicalize order.
    pub fn new(mut snapshot: InventorySnapshot, limits: &Limits) -> Result<Self, Diagnostic> {
        validate(&snapshot, limits)?;
        snapshot.runs.sort_by(|a, b| a.id.cmp(&b.id));
        snapshot.evidence.sort_by(|a, b| a.id.cmp(&b.id));
        snapshot.observations.sort_by(|a, b| a.id.cmp(&b.id));
        snapshot
            .absences
            .sort_by(|a, b| (&a.run_id, &a.asset_id).cmp(&(&b.run_id, &b.asset_id)));
        for observation in &mut snapshot.observations {
            observation.evidence_ids.sort();
        }
        Ok(Self { snapshot })
    }

    /// Read-only access to validated, canonically sorted data.
    #[must_use]
    pub const fn snapshot(&self) -> &InventorySnapshot {
        &self.snapshot
    }

    /// Deterministically serialize a validated snapshot within export limits.
    pub fn export(&self, limits: &Limits) -> Result<InventoryArtifact, Diagnostic> {
        validate(&self.snapshot, limits)?;
        let bytes = crate::inventory_codec::encode(&self.snapshot, limits)?;
        let digest = SnapshotDigest::hash(&bytes);
        Ok(InventoryArtifact { bytes, digest })
    }

    /// Verify a trusted expected digest and decode the exact inventory schema.
    ///
    /// Callers must obtain expected digest through an independent trusted
    /// channel; equality with a digest supplied alongside input is not
    /// source authentication. No external networks or ambient clock are used.
    pub fn import_verified(
        envelope: &VersionedEnvelope<'_>,
        expected: SnapshotDigest,
        limits: &Limits,
        evaluation_time_unix_secs: i64,
    ) -> Result<Self, Diagnostic> {
        let admitted = envelope.preflight(limits, evaluation_time_unix_secs)?;
        if admitted.schema() != SchemaKind::InventorySnapshot {
            return Err(problem(
                DiagnosticCode::UnsupportedSchemaVersion,
                "snapshot_schema",
                "expected inventory snapshot envelope",
            ));
        }
        if SnapshotDigest::hash(admitted.unparsed_payload()) != expected {
            return Err(problem(
                DiagnosticCode::IntegrityMismatch,
                "snapshot_digest",
                "content differs from independent digest expectation",
            ));
        }
        let raw = admitted.unparsed_payload();
        let snapshot = crate::inventory_codec::decode(raw, limits)?;
        let checked = Self::new(snapshot, limits)?;
        let artifact = checked.export(limits)?;
        if artifact.bytes != raw {
            return Err(problem(
                DiagnosticCode::MalformedStructure,
                "canonical_bytes",
                "input is not uniquely canonically encoded",
            ));
        }
        Ok(checked)
    }
}

pub(crate) fn problem(
    code: DiagnosticCode,
    subject: &'static str,
    reason: &'static str,
) -> Diagnostic {
    Diagnostic::new(code, subject, reason)
}

fn bad_id(value: &str, subject: &'static str) -> Result<(), Diagnostic> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(problem(
            DiagnosticCode::InvalidIdentifier,
            subject,
            "ID must be nonempty and at most 256 bytes with no control characters",
        ));
    }
    Ok(())
}

fn validate(input: &InventorySnapshot, limits: &Limits) -> Result<(), Diagnostic> {
    limits.validate()?;
    if input.identity_version != IDENTITY_VERSION
        || input.normalization_version != NORMALIZATION_VERSION
    {
        return Err(problem(
            DiagnosticCode::UnsupportedIdentityVersion,
            "identity_version",
            "snapshot identity or normalization generation unsupported",
        ));
    }
    bad_id(&input.scope_id, "snapshot_scope")?;
    limits.check(ResourceKind::GraphNodes, input.observations.len())?;
    let n = limits.checked_add(
        ResourceKind::EvidenceRecords,
        input.runs.len(),
        input.evidence.len(),
    )?;
    limits.checked_add(ResourceKind::EvidenceRecords, n, input.absences.len())?;
    if input.runs.is_empty() {
        return Err(problem(
            DiagnosticCode::MissingProvenance,
            "collection_runs",
            "snapshot must contain at least one scoped source run",
        ));
    }
    let mut runs = BTreeMap::new();
    for run in &input.runs {
        bad_id(&run.id, "run_id")?;
        bad_id(&run.source_id, "run_source")?;
        bad_id(&run.scope_id, "run_scope")?;
        if run.scope_id != input.scope_id {
            return Err(problem(
                DiagnosticCode::InvalidReference,
                "run_scope",
                "collection run crosses snapshot scope",
            ));
        }
        if runs.insert(run.id.as_str(), run).is_some() {
            return Err(problem(
                DiagnosticCode::DuplicateRecord,
                "run_id",
                "duplicate run ID",
            ));
        }
    }

    let mut evidence = BTreeMap::new();
    for record in &input.evidence {
        bad_id(&record.id, "evidence_id")?;
        bad_id(&record.run_id, "evidence_run")?;
        bad_id(&record.source_id, "evidence_source")?;
        if record.confidence_bps > 10_000 {
            return Err(problem(
                DiagnosticCode::MalformedStructure,
                "confidence_bps",
                "confidence outside 0..10000",
            ));
        }
        if runs
            .get(record.run_id.as_str())
            .is_none_or(|run| run.source_id != record.source_id)
        {
            return Err(problem(
                DiagnosticCode::InvalidReference,
                "evidence_run",
                "evidence references an unknown or different-source run",
            ));
        }
        if evidence.insert(record.id.as_str(), record).is_some() {
            return Err(problem(
                DiagnosticCode::DuplicateRecord,
                "evidence_id",
                "duplicate evidence ID",
            ));
        }
    }

    let mut observations = BTreeSet::new();
    let mut edge_count = 0_usize;
    for observation in &input.observations {
        bad_id(&observation.id, "observation_id")?;
        bad_id(&observation.asset_id, "asset_id")?;
        bad_id(&observation.algorithm_id, "algorithm_id")?;
        if !observations.insert(observation.id.as_str()) {
            return Err(problem(
                DiagnosticCode::DuplicateRecord,
                "observation_id",
                "duplicate observation ID",
            ));
        }
        if observation.evidence_ids.is_empty() {
            return Err(problem(
                DiagnosticCode::MissingProvenance,
                "observation_evidence",
                "observation requires independent evidence",
            ));
        }
        edge_count = limits.checked_add(
            ResourceKind::GraphEdges,
            edge_count,
            observation.evidence_ids.len(),
        )?;
        let mut unique = BTreeSet::new();
        for id in &observation.evidence_ids {
            bad_id(id, "evidence_ref")?;
            if !unique.insert(id.as_str()) {
                return Err(problem(
                    DiagnosticCode::DuplicateRecord,
                    "observation_evidence",
                    "duplicate evidence reference",
                ));
            }
            if !evidence.contains_key(id.as_str()) {
                return Err(problem(
                    DiagnosticCode::InvalidReference,
                    "observation_evidence",
                    "unknown evidence reference",
                ));
            }
        }
    }

    let mut absence_ids = BTreeSet::new();
    for absence in &input.absences {
        bad_id(&absence.run_id, "absence_run")?;
        bad_id(&absence.asset_id, "absence_asset")?;
        if !absence_ids.insert((absence.run_id.as_str(), absence.asset_id.as_str())) {
            return Err(problem(
                DiagnosticCode::DuplicateRecord,
                "absence",
                "duplicate scoped absence",
            ));
        }
        let run = runs.get(absence.run_id.as_str()).ok_or_else(|| {
            problem(
                DiagnosticCode::InvalidReference,
                "absence_run",
                "absence references unknown run",
            )
        })?;
        if absence.status == AbsenceStatus::Confirmed
            && run.completeness != CollectionCompleteness::Complete
        {
            return Err(problem(
                DiagnosticCode::InvalidStateTransition,
                "confirmed_absence",
                "partial or failed collection cannot confirm removal",
            ));
        }
    }
    Ok(())
}
