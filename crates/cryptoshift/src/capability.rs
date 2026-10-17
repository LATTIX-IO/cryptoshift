//! Versioned, immutable, source-attributed cryptographic capability facts.
//!
//! A catalog records assertions and independently supplied validation claims.
//! It does not authenticate external evidence, prove deployment, negotiate
//! protocol extensions, approve algorithms, or authorize migration.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::{
    AlgorithmRole, Diagnostic, DiagnosticCode, KnownAlgorithm, Limits, ProfileProvenance,
    ResourceKind, SnapshotDigest, TargetDisposition, TargetProfile,
};

/// Exact supported capability-catalog schema revision.
pub const CAPABILITY_CATALOG_VERSION: u16 = 1;

/// Reported product/runtime capability state; never silently promoted.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CapabilityState {
    /// External evidence asserts this exact deployed runtime was verified.
    DeployedAndVerified,
    /// Available in a product offering; not proven installed or negotiated.
    Available,
    /// Experimental or preview support; not production readiness.
    Preview,
    /// Future vendor roadmap commitment; not available yet.
    Roadmap,
    /// Source explicitly reports no support for this exact tuple.
    Unsupported,
    /// Source cannot establish the state.
    Unknown,
}

/// Type of source information supporting a capability assertion.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CapabilityEvidenceBasis {
    /// Published product specification, not a runtime test.
    VendorDocumentation,
    /// Vendor declaration without independently verified deployment.
    VendorAssertion,
    /// An explicitly observed runtime verification record.
    RuntimeTest,
    /// Third-party attestation claiming validation of a specific runtime.
    RuntimeAttestation,
    /// Indirectly inferred information, which is never runtime verification.
    Inference,
}

/// Whether an external caller claims to have authenticated source evidence.
///
/// This field is **not verified here**; trust/key management belongs to the
/// caller. Even a VerifiedByHost value does not authenticate itself.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvidenceVerification {
    /// Source has not been independently authenticated.
    Unverified,
    /// Caller asserts evidence was independently authenticated off-line.
    VerifiedByHost,
}

/// Explicit and non-secret source reference for one capability claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityEvidence {
    /// Stable source/publisher ID; never assumed to identify a trusted party.
    pub source_id: String,
    /// Stable evidence record ID; the same document may support many facts.
    pub evidence_id: String,
    /// Source edition or exact review revision.
    pub source_revision: String,
    /// Provenance category, preserved without conflation.
    pub basis: CapabilityEvidenceBasis,
    /// Caller-reported source verification, not cryptographically checked.
    pub verification: EvidenceVerification,
    /// External verification receipt reference when checked by host.
    pub verification_reference: Option<String>,
    /// Claimed artifact hash, not a verified signature or source identity.
    pub artifact_digest: Option<SnapshotDigest>,
    /// Source observation instant, explicitly in UTC seconds.
    pub observed_at_unix_secs: i64,
    /// Optional validity limit; no global freshness default is fabricated.
    pub expires_at_unix_secs: Option<i64>,
}

/// One exact product/version/platform/runtime/algorithm capability assertion.
///
/// Independent assertions about the same tuple may disagree. They are
/// retained as separate records; the resolver reports Conflicting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRecord {
    /// Unique stable record identity within this catalog revision.
    pub record_id: String,
    /// Provider legal/technical identity.
    pub provider_id: String,
    /// Product identity under the provider.
    pub product_id: String,
    /// Exact build or product release revision.
    pub product_version: String,
    /// Exact platform/OS/runtime family or image name.
    pub platform_id: String,
    /// Target tenant/deployment scope, never implicitly global.
    pub scope_id: String,
    /// Exact deployed instance or image digest identity, if any.
    pub runtime_id: Option<String>,
    /// Exact recognized FIPS parameter set; no opaque aliases.
    pub algorithm: KnownAlgorithm,
    /// Explicit role, validated against the parameter set.
    pub role: AlgorithmRole,
    /// Claimed readiness state, never inferred from the algorithm name.
    pub state: CapabilityState,
    /// Source and verification claim with explicit expiry and provenance.
    pub evidence: CapabilityEvidence,
}

/// Untrusted draft; only CapabilityCatalog::new produces validated facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityCatalogDraft {
    /// Must equal CAPABILITY_CATALOG_VERSION.
    pub schema_version: u16,
    /// Globally meaningful catalog revision identity.
    pub catalog_id: String,
    /// Nonzero monotone revision *claimed* by the source.
    pub revision: u32,
    /// Exact scope/tenant boundary for every contained record.
    pub scope_id: String,
    /// Source identity and document revision, not authentication.
    pub provenance: ProfileProvenance,
    /// Individual source-attributed, potentially conflicting records.
    pub records: Vec<CapabilityRecord>,
}

/// Immutable canonical catalog, including all conflicting original claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityCatalog {
    content: CapabilityCatalogDraft,
    digest: SnapshotDigest,
}

/// Exact provider/product/runtime lookup. Every identity field is required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilitySelector<'a> {
    /// Tenant/target scope, must exactly match catalog and target.
    pub scope_id: &'a str,
    /// Exact provider ID.
    pub provider_id: &'a str,
    /// Exact product ID.
    pub product_id: &'a str,
    /// Exact product version/build.
    pub product_version: &'a str,
    /// Exact platform identifier.
    pub platform_id: &'a str,
    /// Exact deployed runtime ID or None for non-runtime-specific claims.
    pub runtime_id: Option<&'a str>,
    /// Exact catalog parameter-set identity.
    pub algorithm: KnownAlgorithm,
    /// Cryptographic role, validated independently of source assertions.
    pub role: AlgorithmRole,
}

/// Conservative raw-evidence aggregation without inferred readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityMatchState {
    /// No record matched the *entire* requested tuple.
    NoEvidence,
    /// Every current matching record asserts the same explicit state.
    Consistent(CapabilityState),
    /// Current source claims disagree; do not choose a winner.
    Conflicting,
    /// Any matching record is stale or dated in the future.
    Stale,
}

/// Read-only exact-match result. Never an authorization or compatibility proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityMatch {
    /// Original immutable catalog content digest.
    pub catalog_digest: SnapshotDigest,
    /// Independently validated desired target digest.
    pub target_digest: SnapshotDigest,
    /// Target requirement; Forbidden/NotSpecified are not permission.
    pub target_disposition: TargetDisposition,
    /// Unmodified status, conflict, staleness or absence of evidence.
    pub state: CapabilityMatchState,
    /// Sorted matched record IDs, including contradictions and stale claims.
    pub record_ids: Vec<String>,
    /// Sorted references to all matched original source evidence records.
    pub evidence_ids: Vec<String>,
}

impl CapabilityCatalog {
    /// Canonicalize, structurally validate and immutably pin a catalog.
    ///
    /// Evaluation time is explicit; expiring or verified-runtime claims must
    /// not be admitted without it. The caller must authenticate claims before
    /// trusting VerifiedByHost; this library only enforces structural rules.
    pub fn new(
        mut draft: CapabilityCatalogDraft,
        limits: &Limits,
        evaluation_time_unix_secs: Option<i64>,
    ) -> Result<Self, Diagnostic> {
        preflight(&draft, limits)?;
        if draft.schema_version != CAPABILITY_CATALOG_VERSION {
            return Err(error(
                DiagnosticCode::UnsupportedSchemaVersion,
                "capability_schema",
                "capability schema version is unsupported",
            ));
        }
        if draft.revision == 0 || draft.records.is_empty() {
            return Err(error(
                DiagnosticCode::InvalidStateTransition,
                "capability_revision",
                "capability revision and record set must be nonempty",
            ));
        }
        for value in [
            &draft.catalog_id,
            &draft.scope_id,
            &draft.provenance.issuer_id,
            &draft.provenance.document_id,
            &draft.provenance.revision,
        ] {
            valid_id(value, "capability_catalog_identity")?;
        }

        for record in &draft.records {
            validate_record(record, &draft.scope_id, evaluation_time_unix_secs)?;
        }
        draft.records.sort_by(|a, b| a.record_id.cmp(&b.record_id));
        if draft
            .records
            .windows(2)
            .any(|pair| pair[0].record_id == pair[1].record_id)
        {
            return Err(error(
                DiagnosticCode::DuplicateRecord,
                "capability_record",
                "duplicate capability record identity",
            ));
        }
        let bytes = encode(&draft, limits)?;
        let sum = Sha256::digest(bytes);
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&sum);
        Ok(Self {
            content: draft,
            digest: SnapshotDigest::from_bytes(digest),
        })
    }

    /// Entire canonical source-attributed catalog, immutably borrowed.
    #[must_use]
    pub const fn content(&self) -> &CapabilityCatalogDraft {
        &self.content
    }

    /// Deterministic SHA-256 identity; not an authentication signature.
    #[must_use]
    pub const fn digest(&self) -> SnapshotDigest {
        self.digest
    }

    /// Stable, domain-separated v1 bytes for independently pinned replay.
    ///
    /// This is an **export only**; do not treat it as an untrusted importer.
    pub fn export(&self, limits: &Limits) -> Result<Vec<u8>, Diagnostic> {
        preflight(&self.content, limits)?;
        encode(&self.content, limits)
    }

    /// Check against an independently trusted expected hash.
    pub fn verify_expected_digest(&self, expected: SnapshotDigest) -> Result<(), Diagnostic> {
        if self.digest == expected {
            Ok(())
        } else {
            Err(error(
                DiagnosticCode::IntegrityMismatch,
                "capability_digest",
                "capability catalog digest does not match expected identity",
            ))
        }
    }

    /// Evaluate only the exact scoped tuple against a desired target.
    ///
    /// Evaluation time is mandatory and rechecks freshness so a previously
    /// admitted claim can never silently remain ready after expiry.
    /// A vendor catalog fact never satisfies a runtime-specific lookup.
    pub fn match_target(
        &self,
        target: &TargetProfile,
        selector: CapabilitySelector<'_>,
        evaluation_time_unix_secs: i64,
        limits: &Limits,
    ) -> Result<CapabilityMatch, Diagnostic> {
        limits.validate()?;
        for field in [
            selector.scope_id,
            selector.provider_id,
            selector.product_id,
            selector.product_version,
            selector.platform_id,
        ] {
            valid_id(field, "capability_lookup")?;
        }
        if let Some(runtime) = selector.runtime_id {
            valid_id(runtime, "capability_runtime")?;
        }
        if selector.scope_id != self.content.scope_id
            || selector.scope_id != target.content().scope_id
        {
            return Err(error(
                DiagnosticCode::InvalidReference,
                "capability_scope",
                "target, selector and capability catalog scopes must match exactly",
            ));
        }
        if selector.role != selector.algorithm.role() {
            return Err(error(
                DiagnosticCode::InvalidStateTransition,
                "capability_lookup_role",
                "requested cryptographic role mismatches the exact parameter set",
            ));
        }
        let disposition = target.disposition(selector.algorithm.id())?;
        limits.check(ResourceKind::EvidenceRecords, self.content.records.len())?;
        let mut records = Vec::new();
        let mut evidence = BTreeSet::new();
        let mut statuses = BTreeSet::new();
        let mut stale = false;
        let mut bytes = 0_usize;
        for claim in &self.content.records {
            if claim.scope_id != selector.scope_id
                || claim.provider_id != selector.provider_id
                || claim.product_id != selector.product_id
                || claim.product_version != selector.product_version
                || claim.platform_id != selector.platform_id
                || claim.runtime_id.as_deref() != selector.runtime_id
                || claim.algorithm != selector.algorithm
                || claim.role != selector.role
            {
                continue;
            }
            charge(
                limits,
                ResourceKind::ExportBytes,
                &mut bytes,
                &claim.record_id,
            )?;
            charge(
                limits,
                ResourceKind::ExportBytes,
                &mut bytes,
                &claim.evidence.evidence_id,
            )?;
            records.push(claim.record_id.clone());
            evidence.insert(claim.evidence.evidence_id.as_str());
            statuses.insert(claim.state);
            stale |= evaluation_time_unix_secs < claim.evidence.observed_at_unix_secs
                || claim
                    .evidence
                    .expires_at_unix_secs
                    .is_some_and(|expiry| evaluation_time_unix_secs >= expiry);
        }
        let state = if records.is_empty() {
            CapabilityMatchState::NoEvidence
        } else if stale {
            CapabilityMatchState::Stale
        } else if statuses.len() != 1 {
            CapabilityMatchState::Conflicting
        } else if let Some(first) = statuses.first() {
            CapabilityMatchState::Consistent(*first)
        } else {
            CapabilityMatchState::NoEvidence
        };
        let mut evidence_ids = Vec::with_capacity(evidence.len());
        for id in evidence {
            // Only the unique references are emitted; conservative earlier
            // per-record charging ensures this allocation stays bounded.
            evidence_ids.push(id.to_owned());
        }
        Ok(CapabilityMatch {
            catalog_digest: self.digest,
            target_digest: target.digest(),
            target_disposition: disposition,
            state,
            record_ids: records,
            evidence_ids,
        })
    }
}

fn validate_record(
    record: &CapabilityRecord,
    scope_id: &str,
    evaluation_time: Option<i64>,
) -> Result<(), Diagnostic> {
    for value in [
        &record.record_id,
        &record.provider_id,
        &record.product_id,
        &record.product_version,
        &record.platform_id,
        &record.scope_id,
        &record.evidence.source_id,
        &record.evidence.evidence_id,
        &record.evidence.source_revision,
    ] {
        valid_id(value, "capability_record_identity")?;
    }
    if let Some(runtime) = &record.runtime_id {
        valid_id(runtime, "capability_runtime")?;
    }
    if let Some(verified) = &record.evidence.verification_reference {
        valid_id(verified, "capability_verification")?;
    }
    if record.scope_id != scope_id {
        return Err(error(
            DiagnosticCode::InvalidReference,
            "capability_scope",
            "a capability record cannot cross the catalog scope",
        ));
    }
    if record.role != record.algorithm.role() {
        return Err(error(
            DiagnosticCode::InvalidStateTransition,
            "capability_role",
            "capability role mismatches the pinned algorithm",
        ));
    }
    let ev = &record.evidence;
    if ev
        .expires_at_unix_secs
        .is_some_and(|expiry| expiry <= ev.observed_at_unix_secs)
    {
        return Err(error(
            DiagnosticCode::InvalidStateTransition,
            "capability_validity",
            "source expiry must be later than source observation time",
        ));
    }
    if ev.expires_at_unix_secs.is_some() || record.state == CapabilityState::DeployedAndVerified {
        let now = evaluation_time.ok_or_else(|| {
            error(
                DiagnosticCode::InvalidStateTransition,
                "capability_evaluation_time",
                "expiring or verified runtime evidence requires an explicit evaluation time",
            )
        })?;
        if now < ev.observed_at_unix_secs {
            return Err(error(
                DiagnosticCode::InvalidStateTransition,
                "capability_future_observation",
                "runtime observation cannot be accepted from the future",
            ));
        }
        if ev.expires_at_unix_secs.is_some_and(|expiry| now >= expiry) {
            return Err(error(
                DiagnosticCode::StaleCriticalProfile,
                "capability_expiry",
                "source evidence is stale at the explicit evaluation time",
            ));
        }
    } else if evaluation_time.is_some_and(|now| now < ev.observed_at_unix_secs) {
        return Err(error(
            DiagnosticCode::InvalidStateTransition,
            "capability_future_observation",
            "source observation cannot be from the future",
        ));
    }
    if ev.verification == EvidenceVerification::VerifiedByHost
        && (!matches!(
            ev.basis,
            CapabilityEvidenceBasis::RuntimeTest | CapabilityEvidenceBasis::RuntimeAttestation
        ) || ev.verification_reference.is_none()
            || ev.artifact_digest.is_none())
    {
        return Err(error(
            DiagnosticCode::MissingProvenance,
            "capability_verification",
            "host-verified claim requires runtime proof, verification reference and source digest",
        ));
    }
    if record.state == CapabilityState::DeployedAndVerified
        && (record.runtime_id.is_none()
            || !matches!(
                ev.basis,
                CapabilityEvidenceBasis::RuntimeTest | CapabilityEvidenceBasis::RuntimeAttestation
            )
            || ev.verification != EvidenceVerification::VerifiedByHost
            || ev.expires_at_unix_secs.is_none())
    {
        return Err(error(
            DiagnosticCode::MissingProvenance,
            "capability_deployment",
            "verified-deployment claim requires exact runtime identity and verified expiring proof",
        ));
    }
    Ok(())
}

fn preflight(draft: &CapabilityCatalogDraft, limits: &Limits) -> Result<(), Diagnostic> {
    limits.validate()?;
    limits.check(ResourceKind::EvidenceRecords, draft.records.len())?;
    limits.check(ResourceKind::ProfileReferences, draft.records.len())?;
    let mut bytes = 0_usize;
    for item in [
        &draft.catalog_id,
        &draft.scope_id,
        &draft.provenance.issuer_id,
        &draft.provenance.document_id,
        &draft.provenance.revision,
    ] {
        charge(limits, ResourceKind::InputBytes, &mut bytes, item)?;
    }
    for record in &draft.records {
        for field in [
            &record.record_id,
            &record.provider_id,
            &record.product_id,
            &record.product_version,
            &record.platform_id,
            &record.scope_id,
            &record.evidence.source_id,
            &record.evidence.evidence_id,
            &record.evidence.source_revision,
        ] {
            charge(limits, ResourceKind::InputBytes, &mut bytes, field)?;
        }
        if let Some(runtime) = &record.runtime_id {
            charge(limits, ResourceKind::InputBytes, &mut bytes, runtime)?;
        }
        if let Some(reference) = &record.evidence.verification_reference {
            charge(limits, ResourceKind::InputBytes, &mut bytes, reference)?;
        }
    }
    Ok(())
}

/// Non-secret opaque identifier grammar: no credentials/query tokens.
fn valid_id(value: &str, field: &'static str) -> Result<(), Diagnostic> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b':'))
    {
        return Err(error(
            DiagnosticCode::InvalidIdentifier,
            field,
            "capability identifiers must be nonsecret printable opaque references",
        ));
    }
    Ok(())
}

fn charge(
    limits: &Limits,
    resource: ResourceKind,
    count: &mut usize,
    value: &str,
) -> Result<(), Diagnostic> {
    *count = limits.checked_add(resource, *count, value.len())?;
    Ok(())
}

fn error(code: DiagnosticCode, field: &'static str, reason: &'static str) -> Diagnostic {
    Diagnostic::new(code, field, reason)
}

struct Writer<'a> {
    bytes: Vec<u8>,
    limits: &'a Limits,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), Diagnostic> {
        self.limits
            .checked_add(ResourceKind::ExportBytes, self.bytes.len(), bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn byte(&mut self, byte: u8) -> Result<(), Diagnostic> {
        self.put(&[byte])
    }
    fn u16(&mut self, value: u16) -> Result<(), Diagnostic> {
        self.put(&value.to_be_bytes())
    }
    fn u32(&mut self, value: u32) -> Result<(), Diagnostic> {
        self.put(&value.to_be_bytes())
    }
    fn i64(&mut self, value: i64) -> Result<(), Diagnostic> {
        self.put(&value.to_be_bytes())
    }
    fn string(&mut self, value: &str) -> Result<(), Diagnostic> {
        self.u32(u32::try_from(value.len()).map_err(|_| {
            error(
                DiagnosticCode::ArithmeticOverflow,
                "capability_size",
                "field length overflowed",
            )
        })?)?;
        self.put(value.as_bytes())
    }
    fn option_string(&mut self, value: Option<&str>) -> Result<(), Diagnostic> {
        if let Some(s) = value {
            self.byte(1)?;
            self.string(s)
        } else {
            self.byte(0)
        }
    }
    fn option_digest(&mut self, value: Option<SnapshotDigest>) -> Result<(), Diagnostic> {
        if let Some(d) = value {
            self.byte(1)?;
            self.put(&d.as_bytes())
        } else {
            self.byte(0)
        }
    }
    fn option_time(&mut self, value: Option<i64>) -> Result<(), Diagnostic> {
        if let Some(t) = value {
            self.byte(1)?;
            self.i64(t)
        } else {
            self.byte(0)
        }
    }
}

fn status_tag(value: CapabilityState) -> u8 {
    match value {
        CapabilityState::DeployedAndVerified => 1,
        CapabilityState::Available => 2,
        CapabilityState::Preview => 3,
        CapabilityState::Roadmap => 4,
        CapabilityState::Unsupported => 5,
        CapabilityState::Unknown => 6,
    }
}
fn basis_tag(value: CapabilityEvidenceBasis) -> u8 {
    match value {
        CapabilityEvidenceBasis::VendorDocumentation => 1,
        CapabilityEvidenceBasis::VendorAssertion => 2,
        CapabilityEvidenceBasis::RuntimeTest => 3,
        CapabilityEvidenceBasis::RuntimeAttestation => 4,
        CapabilityEvidenceBasis::Inference => 5,
    }
}
fn role_tag(value: AlgorithmRole) -> u8 {
    match value {
        AlgorithmRole::KeyEncapsulation => 1,
        AlgorithmRole::Signature => 2,
    }
}
fn verification_tag(value: EvidenceVerification) -> u8 {
    match value {
        EvidenceVerification::Unverified => 1,
        EvidenceVerification::VerifiedByHost => 2,
    }
}

fn encode(draft: &CapabilityCatalogDraft, limits: &Limits) -> Result<Vec<u8>, Diagnostic> {
    let mut w = Writer {
        bytes: Vec::new(),
        limits,
    };
    w.put(b"CSHIFT_CAPABILITY_V1\0")?;
    w.u16(draft.schema_version)?;
    w.string(&draft.catalog_id)?;
    w.u32(draft.revision)?;
    w.string(&draft.scope_id)?;
    w.string(&draft.provenance.issuer_id)?;
    w.string(&draft.provenance.document_id)?;
    w.string(&draft.provenance.revision)?;
    w.option_digest(draft.provenance.source_digest)?;
    w.u32(u32::try_from(draft.records.len()).map_err(|_| {
        error(
            DiagnosticCode::ArithmeticOverflow,
            "capability_count",
            "record count overflowed",
        )
    })?)?;
    for r in &draft.records {
        w.string(&r.record_id)?;
        w.string(&r.provider_id)?;
        w.string(&r.product_id)?;
        w.string(&r.product_version)?;
        w.string(&r.platform_id)?;
        w.string(&r.scope_id)?;
        w.option_string(r.runtime_id.as_deref())?;
        w.string(r.algorithm.id())?;
        w.byte(role_tag(r.role))?;
        w.byte(status_tag(r.state))?;
        w.string(&r.evidence.source_id)?;
        w.string(&r.evidence.evidence_id)?;
        w.string(&r.evidence.source_revision)?;
        w.byte(basis_tag(r.evidence.basis))?;
        w.byte(verification_tag(r.evidence.verification))?;
        w.option_string(r.evidence.verification_reference.as_deref())?;
        w.option_digest(r.evidence.artifact_digest)?;
        w.i64(r.evidence.observed_at_unix_secs)?;
        w.option_time(r.evidence.expires_at_unix_secs)?;
    }
    Ok(w.bytes)
}
