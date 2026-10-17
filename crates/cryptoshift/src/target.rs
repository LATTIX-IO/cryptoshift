//! Immutable, versioned target constraints with explicit provenance.
//!
//! This defines *desired* algorithm/profile constraints, not validated
//! provider capability, protocol negotiation, compliance or authorization.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::standards::{
    AlgorithmRole, KnownAlgorithm, STANDARDS_CATALOG_VERSION, SecurityCategory, StandardEdition,
};
use crate::{Diagnostic, DiagnosticCode, Limits, ResourceKind, SnapshotDigest};

/// Exact supported target-profile contract generation.
pub const TARGET_PROFILE_VERSION: u16 = 1;

/// Caller-attributed document revision; attribution is not authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileProvenance {
    /// Publisher/owner of the target constraints.
    pub issuer_id: String,
    /// Explicit policy/target specification document identity.
    pub document_id: String,
    /// Exact source revision string, never inferred from a timestamp.
    pub revision: String,
    /// Optional independently verifiable digest; not a signature.
    pub source_digest: Option<SnapshotDigest>,
}

/// Requested algorithm handling within one target scope.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConstraintDisposition {
    /// The named exact parameter set is required for the declared target.
    Required,
    /// The named exact parameter set is permitted by this target.
    Permitted,
    /// The exact parameter set is forbidden by the target.
    Forbidden,
}

/// One typed algorithm requirement for an exact parameter set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlgorithmConstraint {
    /// Recognized exact FIPS parameter set; aliases cannot enter the model.
    pub algorithm: KnownAlgorithm,
    /// Expected key-encapsulation or signature role.
    pub role: AlgorithmRole,
    /// Minimum NIST category for positive constraints, absent for Forbidden.
    pub minimum_category: Option<SecurityCategory>,
    /// Required, permitted or forbidden; no inferred default permission.
    pub disposition: ConstraintDisposition,
}

/// Hybrid constructions are optional, explicit and *not* validated here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HybridConstruction {
    /// Precisely identified second primitive, not an implied default.
    pub companion_algorithm_id: String,
    /// Specific combiner specification and edition (caller-supplied claim).
    pub combiner_reference: String,
}

/// Named and versioned protocol-level target requirement.
///
/// A matching algorithm/role does not prove the named protocol actually
/// supports the algorithm, a particular wire-format, or peer interoperability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolConstraint {
    /// Exact protocol identifier (e.g. one application-specific profile).
    pub protocol_id: String,
    /// Explicit protocol or extension revision, not an inferred latest value.
    pub revision: String,
    /// Intended cryptographic role at this protocol boundary.
    pub role: AlgorithmRole,
    /// Exact algorithm required or permitted by the target.
    pub algorithm: KnownAlgorithm,
    /// No hybrid is ever synthesized by the library.
    pub hybrid: Option<HybridConstruction>,
}

/// Exact certificate profile target; does not assert X.509 implementation
/// support, issuance, trust anchor availability, or algorithm validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateConstraint {
    /// Name of exact certificate/PKI profile.
    pub profile_id: String,
    /// Named profile revision or RFC edition.
    pub revision: String,
    /// Signature algorithm selected in this target.
    pub signature_algorithm: KnownAlgorithm,
    /// Reference to source defining certificate encoding/binding.
    pub specification_reference: String,
}

/// Separately sourced CNSA 2.0 constraint scope, strictly opt-in.
///
/// Only the general-purpose *asymmetric* subset is implemented in this
/// increment. No AES, SHA, LMS, XMSS, certificate, transition or timeline
/// compliance conclusion follows from successfully validating it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cnsa20Overlay {
    /// Explicitly selected NSA advisory revision.
    pub edition: StandardEdition,
    /// Independent reference documenting why this scope is subject to CNSA.
    pub applicability_reference: String,
}

/// Deadline declared by a separate authoritative source, never generated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitDeadline {
    /// Exact target stage or use-case to which the claim applies.
    pub applies_to: String,
    /// Explicit UTC deadline in seconds since Unix epoch.
    pub due_at_unix_secs: i64,
    /// Verifiable upstream policy source, not authenticated by this library.
    pub source_reference: String,
}

/// Mutable input prior to validation/canonicalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetProfileDraft {
    /// Must equal TARGET_PROFILE_VERSION.
    pub schema_version: u16,
    /// Stable target profile ID.
    pub profile_id: String,
    /// Mandatory nonzero target policy revision.
    pub revision: u32,
    /// Explicit scope/tenant/application boundary.
    pub scope_id: String,
    /// Separately owned, unverified provenance.
    pub provenance: ProfileProvenance,
    /// Exact pinned editions required to support the algorithm assertions.
    pub standards: Vec<StandardEdition>,
    /// Explicit positive or negative algorithm constraints.
    pub algorithms: Vec<AlgorithmConstraint>,
    /// Exact protocol+revision constraints, separate from FIPS approval.
    pub protocols: Vec<ProtocolConstraint>,
    /// Exact certificate+revision constraints, separate from FIPS approval.
    pub certificates: Vec<CertificateConstraint>,
    /// Optional independent CNSA 2.0 overlay; never enabled by default.
    pub cnsa20: Option<Cnsa20Overlay>,
    /// Optional explicit deadline. There is no assumed global date.
    pub deadline: Option<ExplicitDeadline>,
    /// Optional source-defined expiry for this revision.
    pub expires_at_unix_secs: Option<i64>,
}

/// Immutable canonical target representation and content identity.
///
/// Fields are private; callers can only construct through validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetProfile {
    content: TargetProfileDraft,
    digest: SnapshotDigest,
}

/// A typed three-state target lookup, not an authorization decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetDisposition {
    /// No declared requirement; unknown must not be treated as permitted.
    NotSpecified,
    /// Explicit target requires this exact algorithm.
    Required,
    /// Explicit target permits this exact algorithm.
    Permitted,
    /// Explicit target forbids this exact algorithm.
    Forbidden,
}

impl TargetProfile {
    /// Validate untrusted draft and canonicalize deterministic collection order.
    ///
    /// The evaluation time is explicitly provided by the caller. A missing
    /// time never implies freshness, and evaluation never reads a clock.
    pub fn new(
        mut draft: TargetProfileDraft,
        limits: &Limits,
        evaluation_time_unix_secs: Option<i64>,
    ) -> Result<Self, Diagnostic> {
        preflight(&draft, limits)?;
        if draft.schema_version != TARGET_PROFILE_VERSION {
            return Err(error(
                DiagnosticCode::UnsupportedSchemaVersion,
                "target_schema",
                "target profile contract revision is unsupported",
            ));
        }
        if draft.revision == 0 {
            return Err(error(
                DiagnosticCode::InvalidIdentifier,
                "target_revision",
                "target profile revision must be nonzero",
            ));
        }
        for value in [
            &draft.profile_id,
            &draft.scope_id,
            &draft.provenance.issuer_id,
            &draft.provenance.document_id,
            &draft.provenance.revision,
        ] {
            valid_id(value, "target_identity")?;
        }
        if let (Some(now), Some(expiry)) = (evaluation_time_unix_secs, draft.expires_at_unix_secs) {
            if now >= expiry {
                return Err(error(
                    DiagnosticCode::StaleCriticalProfile,
                    "target_expiry",
                    "target revision is expired at the explicit evaluation time",
                ));
            }
        }
        if draft.standards.is_empty() || draft.algorithms.is_empty() {
            return Err(error(
                DiagnosticCode::InvalidReference,
                "target_constraints",
                "profile requires explicit editions and algorithm constraints",
            ));
        }
        draft.standards.sort();
        if has_duplicate(&draft.standards) {
            return Err(duplicate("standards_edition"));
        }
        for constraint in &draft.algorithms {
            if constraint.role != constraint.algorithm.role() {
                return Err(error(
                    DiagnosticCode::InvalidStateTransition,
                    "algorithm_role",
                    "algorithm role conflicts with the recognized FIPS parameter set",
                ));
            }
            if !draft.standards.contains(&constraint.algorithm.standard()) {
                return Err(error(
                    DiagnosticCode::InvalidReference,
                    "algorithm_standard",
                    "source edition for algorithm is not declared in this profile",
                ));
            }
            match constraint.disposition {
                ConstraintDisposition::Forbidden if constraint.minimum_category.is_some() => {
                    return Err(error(
                        DiagnosticCode::InvalidStateTransition,
                        "forbidden_category",
                        "forbidden algorithm must not declare an enabling category",
                    ));
                }
                ConstraintDisposition::Required | ConstraintDisposition::Permitted => {
                    if !constraint
                        .minimum_category
                        .is_some_and(|category| category <= constraint.algorithm.category())
                    {
                        return Err(error(
                            DiagnosticCode::InvalidStateTransition,
                            "minimum_category",
                            "target minimum category is absent or exceeds selected parameter set",
                        ));
                    }
                }
                ConstraintDisposition::Forbidden => {}
            }
        }
        draft.algorithms.sort_by_key(|item| item.algorithm);
        if draft
            .algorithms
            .windows(2)
            .any(|pair| pair[0].algorithm == pair[1].algorithm)
        {
            return Err(duplicate("algorithm_constraint"));
        }
        for protocol in &draft.protocols {
            valid_id(&protocol.protocol_id, "protocol_id")?;
            valid_id(&protocol.revision, "protocol_revision")?;
            if protocol.role != protocol.algorithm.role() {
                return Err(error(
                    DiagnosticCode::InvalidStateTransition,
                    "protocol_role",
                    "selected parameter-set role contradicts protocol purpose",
                ));
            }
            require_positive(&draft.algorithms, protocol.algorithm, "protocol_algorithm")?;
            if let Some(hybrid) = &protocol.hybrid {
                valid_id(&hybrid.companion_algorithm_id, "hybrid_companion")?;
                valid_id(&hybrid.combiner_reference, "hybrid_combiner")?;
                if hybrid.companion_algorithm_id == protocol.algorithm.id() {
                    return Err(error(
                        DiagnosticCode::InvalidStateTransition,
                        "hybrid_companion",
                        "hybrid secondary primitive must not duplicate primary identity",
                    ));
                }
            }
        }
        draft.protocols.sort_by(|a, b| {
            (&a.protocol_id, &a.revision, a.role).cmp(&(&b.protocol_id, &b.revision, b.role))
        });
        if draft.protocols.windows(2).any(|items| {
            (&items[0].protocol_id, &items[0].revision, items[0].role)
                == (&items[1].protocol_id, &items[1].revision, items[1].role)
        }) {
            return Err(duplicate("protocol_profile"));
        }
        for cert in &draft.certificates {
            valid_id(&cert.profile_id, "certificate_id")?;
            valid_id(&cert.revision, "certificate_revision")?;
            valid_id(&cert.specification_reference, "certificate_reference")?;
            if cert.signature_algorithm.role() != AlgorithmRole::Signature {
                return Err(error(
                    DiagnosticCode::InvalidStateTransition,
                    "certificate_signature",
                    "certificate profile must name a digital signature algorithm",
                ));
            }
            require_positive(
                &draft.algorithms,
                cert.signature_algorithm,
                "certificate_signature",
            )?;
        }
        draft
            .certificates
            .sort_by(|a, b| (&a.profile_id, &a.revision).cmp(&(&b.profile_id, &b.revision)));
        if draft.certificates.windows(2).any(|items| {
            (&items[0].profile_id, &items[0].revision) == (&items[1].profile_id, &items[1].revision)
        }) {
            return Err(duplicate("certificate_profile"));
        }
        if let Some(overlay) = &draft.cnsa20 {
            if overlay.edition != StandardEdition::Cnsa20_2022v1
                || !draft.standards.contains(&overlay.edition)
            {
                return Err(error(
                    DiagnosticCode::UnsupportedSchemaVersion,
                    "cnsa_revision",
                    "unsupported or undeclared CNSA 2.0 advisory revision",
                ));
            }
            valid_id(&overlay.applicability_reference, "cnsa_applicability")?;
            if draft.algorithms.iter().any(|entry| {
                entry.disposition != ConstraintDisposition::Forbidden
                    && !entry.algorithm.cnsa20_general_purpose()
            }) {
                return Err(error(
                    DiagnosticCode::InvalidStateTransition,
                    "cnsa_algorithm",
                    "CNSA general-purpose asymmetric target selects a non-suite algorithm",
                ));
            }
            // An application-specific hybrid/protocol decision cannot be
            // inferred from an NSA general-purpose algorithm allowlist.
        }
        if draft.cnsa20.is_none() && draft.standards.contains(&StandardEdition::Cnsa20_2022v1) {
            return Err(error(
                DiagnosticCode::InvalidStateTransition,
                "cnsa_applicability",
                "a CNSA standard source without a scoped overlay is ambiguous",
            ));
        }
        if let Some(deadline) = &draft.deadline {
            valid_id(&deadline.applies_to, "deadline_scope")?;
            valid_id(&deadline.source_reference, "deadline_source")?;
        }

        let bytes = encode(&draft, limits)?;
        let sum = Sha256::digest(bytes);
        let mut value = [0_u8; 32];
        value.copy_from_slice(&sum);
        Ok(Self {
            content: draft,
            digest: SnapshotDigest::from_bytes(value),
        })
    }

    /// Canonical metadata and constraints, immutably borrowed.
    #[must_use]
    pub const fn content(&self) -> &TargetProfileDraft {
        &self.content
    }

    /// Deterministic, domain-separated SHA-256 content identity.
    ///
    /// This digest is *not* an authenticated publisher signature.
    #[must_use]
    pub const fn digest(&self) -> SnapshotDigest {
        self.digest
    }

    /// Export canonical, versioned binary bytes for exact historical replay.
    ///
    /// This output is not a wire-format import API; an importer must implement
    /// full framing/semantic validation and verify a trusted expected digest.
    pub fn export(&self, limits: &Limits) -> Result<Vec<u8>, Diagnostic> {
        preflight(&self.content, limits)?;
        encode(&self.content, limits)
    }

    /// Require exact match to a caller-supplied *independently trusted* digest.
    pub fn verify_expected_digest(&self, expected: SnapshotDigest) -> Result<(), Diagnostic> {
        if expected == self.digest {
            Ok(())
        } else {
            Err(error(
                DiagnosticCode::IntegrityMismatch,
                "target_digest",
                "validated target content does not match expected digest",
            ))
        }
    }

    /// Query exact known parameter set. Unlisted is *not* permitted.
    pub fn disposition(&self, algorithm_id: &str) -> Result<TargetDisposition, Diagnostic> {
        let known = KnownAlgorithm::parse_exact(algorithm_id)?;
        Ok(self
            .content
            .algorithms
            .binary_search_by_key(&known, |item| item.algorithm)
            .map_or(TargetDisposition::NotSpecified, |index| {
                match self.content.algorithms[index].disposition {
                    ConstraintDisposition::Required => TargetDisposition::Required,
                    ConstraintDisposition::Permitted => TargetDisposition::Permitted,
                    ConstraintDisposition::Forbidden => TargetDisposition::Forbidden,
                }
            }))
    }
}

fn preflight(draft: &TargetProfileDraft, limits: &Limits) -> Result<(), Diagnostic> {
    limits.validate()?;
    let mut count = limits.checked_add(
        ResourceKind::ProfileReferences,
        draft.standards.len(),
        draft.algorithms.len(),
    )?;
    count = limits.checked_add(
        ResourceKind::ProfileReferences,
        count,
        draft.protocols.len(),
    )?;
    count = limits.checked_add(
        ResourceKind::ProfileReferences,
        count,
        draft.certificates.len(),
    )?;
    if draft.cnsa20.is_some() {
        count = limits.checked_add(ResourceKind::ProfileReferences, count, 1)?;
    }
    if draft.deadline.is_some() {
        limits.checked_add(ResourceKind::ProfileReferences, count, 1)?;
    }
    let mut bytes = 0_usize;
    for s in [
        &draft.profile_id,
        &draft.scope_id,
        &draft.provenance.issuer_id,
        &draft.provenance.document_id,
        &draft.provenance.revision,
    ] {
        bytes = limits.checked_add(ResourceKind::InputBytes, bytes, s.len())?;
    }
    for p in &draft.protocols {
        for s in [&p.protocol_id, &p.revision] {
            bytes = limits.checked_add(ResourceKind::InputBytes, bytes, s.len())?;
        }
        if let Some(h) = &p.hybrid {
            for s in [&h.companion_algorithm_id, &h.combiner_reference] {
                bytes = limits.checked_add(ResourceKind::InputBytes, bytes, s.len())?;
            }
        }
    }
    for c in &draft.certificates {
        for s in [&c.profile_id, &c.revision, &c.specification_reference] {
            bytes = limits.checked_add(ResourceKind::InputBytes, bytes, s.len())?;
        }
    }
    if let Some(o) = &draft.cnsa20 {
        bytes = limits.checked_add(
            ResourceKind::InputBytes,
            bytes,
            o.applicability_reference.len(),
        )?;
    }
    if let Some(d) = &draft.deadline {
        for s in [&d.applies_to, &d.source_reference] {
            bytes = limits.checked_add(ResourceKind::InputBytes, bytes, s.len())?;
        }
    }
    Ok(())
}

fn valid_id(value: &str, subject: &'static str) -> Result<(), Diagnostic> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(error(
            DiagnosticCode::InvalidIdentifier,
            subject,
            "identifier must contain 1-256 printable ASCII bytes without whitespace",
        ));
    }
    Ok(())
}

fn require_positive(
    algorithms: &[AlgorithmConstraint],
    selected: KnownAlgorithm,
    subject: &'static str,
) -> Result<(), Diagnostic> {
    if algorithms.iter().any(|entry| {
        entry.algorithm == selected && entry.disposition != ConstraintDisposition::Forbidden
    }) {
        Ok(())
    } else {
        Err(error(
            DiagnosticCode::InvalidStateTransition,
            subject,
            "selected profile algorithm is absent or explicitly forbidden",
        ))
    }
}

fn duplicate(subject: &'static str) -> Diagnostic {
    error(
        DiagnosticCode::DuplicateRecord,
        subject,
        "duplicate or conflicting target requirement identity",
    )
}

fn has_duplicate<T: Ord>(values: &[T]) -> bool {
    values.windows(2).any(|items| items[0] == items[1])
}

fn error(code: DiagnosticCode, subject: &'static str, reason: &'static str) -> Diagnostic {
    Diagnostic::new(code, subject, reason)
}

/// Explicit binary writer: length-prefixes prevent ambiguous concatenations.
struct Writer<'a> {
    bytes: Vec<u8>,
    limits: &'a Limits,
}

impl Writer<'_> {
    fn put(&mut self, data: &[u8]) -> Result<(), Diagnostic> {
        let next =
            self.limits
                .checked_add(ResourceKind::ExportBytes, self.bytes.len(), data.len())?;
        self.bytes.reserve(next - self.bytes.len());
        self.bytes.extend_from_slice(data);
        Ok(())
    }

    fn byte(&mut self, value: u8) -> Result<(), Diagnostic> {
        self.put(&[value])
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

    fn str(&mut self, value: &str) -> Result<(), Diagnostic> {
        self.count(value.len())?;
        self.put(value.as_bytes())
    }

    fn count(&mut self, length: usize) -> Result<(), Diagnostic> {
        let value = u32::try_from(length).map_err(|_| {
            error(
                DiagnosticCode::ArithmeticOverflow,
                "target_encoding",
                "canonical length does not fit u32",
            )
        })?;
        self.u32(value)
    }

    fn digest(&mut self, value: SnapshotDigest) -> Result<(), Diagnostic> {
        self.put(&value.as_bytes())
    }
}

fn role_tag(role: AlgorithmRole) -> u8 {
    match role {
        AlgorithmRole::KeyEncapsulation => 1,
        AlgorithmRole::Signature => 2,
    }
}

fn disposition_tag(value: ConstraintDisposition) -> u8 {
    match value {
        ConstraintDisposition::Required => 1,
        ConstraintDisposition::Permitted => 2,
        ConstraintDisposition::Forbidden => 3,
    }
}

fn category_tag(value: Option<SecurityCategory>) -> u8 {
    match value {
        None => 0,
        Some(SecurityCategory::One) => 1,
        Some(SecurityCategory::Three) => 3,
        Some(SecurityCategory::Five) => 5,
    }
}

fn encode(draft: &TargetProfileDraft, limits: &Limits) -> Result<Vec<u8>, Diagnostic> {
    let mut w = Writer {
        bytes: Vec::new(),
        limits,
    };
    w.put(b"CSHIFT_TARGET_V1\0")?;
    w.u16(draft.schema_version)?;
    w.str(&draft.profile_id)?;
    w.u32(draft.revision)?;
    w.str(&draft.scope_id)?;
    w.str(&draft.provenance.issuer_id)?;
    w.str(&draft.provenance.document_id)?;
    w.str(&draft.provenance.revision)?;
    match draft.provenance.source_digest {
        Some(value) => {
            w.byte(1)?;
            w.digest(value)?;
        }
        None => w.byte(0)?,
    }
    w.count(draft.standards.len())?;
    for edition in &draft.standards {
        w.str(edition.id())?;
    }
    w.count(draft.algorithms.len())?;
    for item in &draft.algorithms {
        w.str(item.algorithm.id())?;
        w.byte(role_tag(item.role))?;
        w.byte(category_tag(item.minimum_category))?;
        w.byte(disposition_tag(item.disposition))?;
    }
    w.count(draft.protocols.len())?;
    for item in &draft.protocols {
        w.str(&item.protocol_id)?;
        w.str(&item.revision)?;
        w.byte(role_tag(item.role))?;
        w.str(item.algorithm.id())?;
        match &item.hybrid {
            Some(h) => {
                w.byte(1)?;
                w.str(&h.companion_algorithm_id)?;
                w.str(&h.combiner_reference)?;
            }
            None => w.byte(0)?,
        }
    }
    w.count(draft.certificates.len())?;
    for item in &draft.certificates {
        w.str(&item.profile_id)?;
        w.str(&item.revision)?;
        w.str(item.signature_algorithm.id())?;
        w.str(&item.specification_reference)?;
    }
    match &draft.cnsa20 {
        Some(overlay) => {
            w.byte(1)?;
            w.str(overlay.edition.id())?;
            w.str(&overlay.applicability_reference)?;
        }
        None => w.byte(0)?,
    }
    match &draft.deadline {
        Some(deadline) => {
            w.byte(1)?;
            w.str(&deadline.applies_to)?;
            w.i64(deadline.due_at_unix_secs)?;
            w.str(&deadline.source_reference)?;
        }
        None => w.byte(0)?,
    }
    match draft.expires_at_unix_secs {
        Some(expiry) => {
            w.byte(1)?;
            w.i64(expiry)?;
        }
        None => w.byte(0)?,
    }
    Ok(w.bytes)
}
