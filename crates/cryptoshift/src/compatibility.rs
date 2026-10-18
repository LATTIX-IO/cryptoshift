//! Offline peer/protocol/PKI compatibility evidence analysis (FOSS-438).
//!
//! This module admits source-attributed observations, not trusted handshakes.
//! No signature, trust-chain, revocation or channel authentication is performed.
//! Accordingly this version never emits an authoritative `Compatible` result.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    AlgorithmRole, CapabilityCatalog, CapabilityEvidenceRef, CapabilityMatch, CapabilityMatchState,
    CapabilitySelector, CapabilityState, Diagnostic, DiagnosticCode, EvidenceGraph, GraphNodeKind,
    KnownAlgorithm, Limits, ResourceKind, SnapshotDigest, TargetDisposition, TargetProfile,
};

/// Version of the immutable compatibility report and its canonical export.
pub const COMPATIBILITY_ANALYSIS_VERSION: u16 = 1;

/// Evidence-bound result. `Compatible` is reserved for a future trusted verifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CompatibilityStatus {
    /// Authenticated, protocol-specific interoperability (never produced in v1).
    Compatible = 1,
    /// A candidate with explicit outstanding validation prerequisites.
    Conditional = 2,
    /// A candidate for an explicitly profiled intermediate hybrid transition.
    Transitional = 3,
    /// A candidate contradicts an explicit target requirement or safe fallback rule.
    Incompatible = 4,
    /// Insufficient, stale, contradictory or untrusted facts prevent a conclusion.
    Unknown = 5,
}

/// Stable reason code for one attributed, non-secret compatibility finding.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CompatibilityCode {
    /// Target explicitly forbids the requested algorithm.
    AlgorithmForbidden = 1,
    /// Target has not established permission for the requested algorithm.
    TargetNotSpecified = 2,
    /// Named protocol, revision or role contradicts the target.
    ProtocolNotApproved = 3,
    /// Requested certificate profile/signature is not approved.
    CertificateNotApproved = 4,
    /// Requested hybrid construction is not explicitly approved.
    HybridNotApproved = 5,
    /// Any classical fallback is unapproved in the v1 target contract.
    DowngradeRejected = 6,
    /// Peer capability has no matching exact-runtime source records.
    CapabilityMissing = 7,
    /// Source records for one exact runtime disagree.
    CapabilityConflict = 8,
    /// At least one exact-runtime source record is stale.
    CapabilityStale = 9,
    /// A source claims no support or only preliminary/unknown readiness.
    CapabilityUnproven = 10,
    /// No independent source identifies the exact communication relationship.
    PeerLinkMissing = 11,
    /// Source asserts a different peer, tenant or protocol identity.
    EvidenceBindingMismatch = 12,
    /// Source observation is future-dated or expired.
    EvidenceStale = 13,
    /// Different independently sourced observations disagree.
    EvidenceConflict = 14,
    /// No selected peer negotiation has been supplied.
    NegotiationMissing = 15,
    /// Offered or selected algorithms contradict this candidate.
    NegotiationMismatch = 16,
    /// A source has not been authenticated against a trusted exchange.
    NegotiationUnauthenticated = 17,
    /// Selected certificate, chain or anchor differs from the candidate.
    PkiMismatch = 18,
    /// No source describes the necessary certificate and chain checks.
    PkiMissing = 19,
    /// Validity, revocation or signed validation proof is not established.
    PkiUnverified = 20,
    /// Hybrid wire and combiner binding is not demonstrated.
    HybridProofMissing = 21,
}

/// Location of a finding; the source IDs remain separately attributable.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CompatibilitySubject {
    /// Initiating product/runtime capability.
    Initiator = 1,
    /// Responding product/runtime capability.
    Responder = 2,
    /// The communication relationship connecting the two exact systems.
    PeerLink = 3,
    /// Protocol, extension and negotiated KEM/signature evidence.
    Protocol = 4,
    /// Certificate, trust-anchor, chain and revocation evidence.
    Pki = 5,
    /// Authoritative desired-state target (content identity, not a signature).
    Target = 6,
}

/// Typed outstanding gate; a finding is not an authorization to skip a gate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CompatibilityPrerequisite {
    /// Obtain an independently validated, scoped peer communication binding.
    VerifyPeerLink = 1,
    /// Obtain source-verified exact-runtime provider capability.
    VerifyInitiator = 2,
    /// Obtain source-verified exact-runtime provider capability.
    VerifyResponder = 3,
    /// Observe and authenticate the negotiated protocol and exact parameters.
    VerifyNegotiation = 4,
    /// Authenticate certificate, chain, anchor and validation-time evidence.
    VerifyPki = 5,
    /// Establish certificate revocation status using trusted evidence.
    VerifyRevocation = 6,
    /// Resolve contradictory or expired source claims.
    ReconcileEvidence = 7,
    /// Obtain an explicit target approval or a different candidate.
    ChangeTarget = 8,
    /// Demonstrate the named hybrid combiner and peer-specific wire binding.
    VerifyHybrid = 9,
}

/// Stable identity of an actual graph system and an exact deployed runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointIdentity {
    /// Graph node ID; the node must be a System.
    pub system_node_id: String,
    /// Capability provider ID.
    pub provider_id: String,
    /// Provider's exact product ID.
    pub product_id: String,
    /// Exact version/build, with no cross-version inheritance.
    pub product_version: String,
    /// Exact platform/image family.
    pub platform_id: String,
    /// Exact deployed runtime or image digest identity.
    pub runtime_id: String,
}

impl EndpointIdentity {
    fn selector<'a>(
        &'a self,
        scope_id: &'a str,
        algorithm: KnownAlgorithm,
        role: AlgorithmRole,
    ) -> CapabilitySelector<'a> {
        CapabilitySelector {
            scope_id,
            provider_id: &self.provider_id,
            product_id: &self.product_id,
            product_version: &self.product_version,
            platform_id: &self.platform_id,
            runtime_id: Some(&self.runtime_id),
            algorithm,
            role,
        }
    }
}

/// Exact proposed PKI identity; not a parsed or validated X.509 certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateSelection {
    /// Profile ID declared by the desired target.
    pub profile_id: String,
    /// Exact edition of the certificate profile.
    pub revision: String,
    /// Concrete leaf certificate identity, not certificate material.
    pub certificate_id: String,
    /// Exact chain identity (for example a separately generated fingerprint).
    pub chain_id: String,
    /// Exact required trust-anchor identity.
    pub trust_anchor_id: String,
    /// Requested signature parameter set.
    pub signature_algorithm: KnownAlgorithm,
}

/// Explicit, protocol-specific hybrid construction proposed by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HybridSelection {
    /// A second named primitive; aliases are not silently normalized.
    pub companion_algorithm_id: String,
    /// Versioned source/combiner reference matching the target precisely.
    pub combiner_reference: String,
}

/// Claimed source namespace and record identity, not authenticated provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilitySource {
    /// Independent publisher or observer namespace.
    pub source_id: String,
    /// Source-local evidence ID.
    pub evidence_id: String,
    /// Source's exact document or event revision.
    pub source_revision: String,
    /// Source-claimed observation timestamp.
    pub observed_at_unix_secs: i64,
    /// Explicit expiry; an absence of expiry does not imply freshness.
    pub expires_at_unix_secs: Option<i64>,
    /// Optional host-supplied verification receipt, never trusted by this crate.
    pub verification_reference: Option<String>,
    /// Optional claimed artifact SHA-256; not an authenticated signature.
    pub artifact_digest: Option<SnapshotDigest>,
}

impl CompatibilitySource {
    fn reference(&self) -> CapabilityEvidenceRef {
        CapabilityEvidenceRef {
            source_id: self.source_id.clone(),
            evidence_id: self.evidence_id.clone(),
            source_revision: self.source_revision.clone(),
        }
    }

    fn stale(&self, at: i64) -> bool {
        self.observed_at_unix_secs > at || self.expires_at_unix_secs.is_some_and(|end| at >= end)
    }
}

/// Evidence that the two distinct graph systems claim to communicate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerLinkObservation {
    /// Source attribution for this exact scoped relationship.
    pub source: CompatibilitySource,
    /// Exact declared tenant/scope.
    pub scope_id: String,
    /// Exact initiating graph System node.
    pub initiator_node_id: String,
    /// Exact responding graph System node.
    pub responder_node_id: String,
    /// Explicit protocol family/identifier.
    pub protocol_id: String,
    /// Explicit protocol revision.
    pub protocol_revision: String,
}

/// Caller-supplied negotiation observation; its authenticity is not validated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiationObservation {
    /// Independent evidence attribution.
    pub source: CompatibilitySource,
    /// Exact tenant/scope.
    pub scope_id: String,
    /// Initiating runtime which the observation claims to bind.
    pub initiator_runtime_id: String,
    /// Responding runtime which the observation claims to bind.
    pub responder_runtime_id: String,
    /// Protocol identity claimed by the observation.
    pub protocol_id: String,
    /// Protocol revision claimed by the observation.
    pub protocol_revision: String,
    /// Extension/wire-profile revision, not assumed from a FIPS parameter set.
    pub extension_revision: String,
    /// Initiator-advertised exact supported parameters.
    pub initiator_offers: Vec<KnownAlgorithm>,
    /// Responder-advertised exact supported parameters.
    pub responder_offers: Vec<KnownAlgorithm>,
    /// Algorithm claimed actually selected in the exchange.
    pub selected_algorithm: Option<KnownAlgorithm>,
    /// Signature algorithm claimed selected in the exchange.
    pub selected_signature: Option<KnownAlgorithm>,
    /// Exact hybrid companion claimed selected, when applicable.
    pub hybrid_companion_id: Option<String>,
    /// Exact combiner reference claimed used, when applicable.
    pub hybrid_combiner_reference: Option<String>,
    /// Whether the source asserts a classical downgrade took place.
    pub classical_fallback_used: bool,
}

/// Caller-supplied PKI and validation observation, not a chain verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PkiObservation {
    /// Independent evidence attribution.
    pub source: CompatibilitySource,
    /// Exact tenant/scope.
    pub scope_id: String,
    /// Claimed initiating runtime.
    pub initiator_runtime_id: String,
    /// Claimed responding runtime.
    pub responder_runtime_id: String,
    /// Named certificate profile.
    pub profile_id: String,
    /// Exact certificate profile revision.
    pub revision: String,
    /// Concrete certificate identity.
    pub certificate_id: String,
    /// Concrete certificate-chain identity.
    pub chain_id: String,
    /// Anchor which the host claims the chain terminates at.
    pub trust_anchor_id: String,
    /// Signature parameter set claimed validated.
    pub signature_algorithm: KnownAlgorithm,
    /// Claimed chain-validation result; never authenticated here.
    pub chain_valid: Option<bool>,
    /// Whether revocation evidence was claimed checked.
    pub revocation_checked: bool,
    /// Explicit time at which the source claimed validation.
    pub validation_at_unix_secs: i64,
}

/// Distinct peer-binding, negotiation and certificate evidence domains.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompatibilityObservation {
    /// A proposed communication relation; not inferred from graph DependsOn.
    PeerLink(PeerLinkObservation),
    /// An externally observed (but not internally authenticated) negotiation.
    Negotiation(NegotiationObservation),
    /// An externally observed (but not internally authenticated) PKI result.
    Pki(PkiObservation),
}

impl CompatibilityObservation {
    fn source(&self) -> &CompatibilitySource {
        match self {
            Self::PeerLink(item) => &item.source,
            Self::Negotiation(item) => &item.source,
            Self::Pki(item) => &item.source,
        }
    }
}

/// Untrusted candidate, with caller-pinned versions of all authoritative inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityRequest {
    /// Must equal COMPATIBILITY_ANALYSIS_VERSION.
    pub schema_version: u16,
    /// Exact tenant/scope binding for all inputs and observations.
    pub scope_id: String,
    /// Independently pinned graph digest.
    pub expected_graph_digest: SnapshotDigest,
    /// Independently pinned target digest.
    pub expected_target_digest: SnapshotDigest,
    /// Independently pinned initiator capability catalog digest.
    pub expected_initiator_catalog_digest: SnapshotDigest,
    /// Independently pinned responder capability catalog digest.
    pub expected_responder_catalog_digest: SnapshotDigest,
    /// Exact initiating graph node and runtime.
    pub initiator: EndpointIdentity,
    /// Exact responding graph node and runtime.
    pub responder: EndpointIdentity,
    /// Named candidate protocol.
    pub protocol_id: String,
    /// Named candidate protocol revision.
    pub protocol_revision: String,
    /// Explicit extension/wire-format revision (not supplied by FIPS).
    pub extension_revision: String,
    /// Exact candidate algorithm, not a marketing alias.
    pub algorithm: KnownAlgorithm,
    /// Explicit role; checked against the algorithm.
    pub role: AlgorithmRole,
    /// Optional selected certificate and chain identity.
    pub certificate: Option<CertificateSelection>,
    /// Optional explicitly named hybrid transition.
    pub hybrid: Option<HybridSelection>,
    /// Classical fallback requested or observed as part of this candidate.
    pub classical_fallback: bool,
    /// Source-attributed observations from independent namespaces.
    pub observations: Vec<CompatibilityObservation>,
}

/// Single typed finding and the source/evidence/revision triples attributable to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityFinding {
    /// Reason category.
    pub code: CompatibilityCode,
    /// Affected subject.
    pub subject: CompatibilitySubject,
    /// Sorted independently attributed sources; empty when the fact is absent.
    pub evidence_refs: Vec<CapabilityEvidenceRef>,
}

/// Full replay binding for an immutable compatibility analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatibilityBindings {
    /// Exact graph digest.
    pub graph_digest: SnapshotDigest,
    /// Underlying validated inventory digest.
    pub inventory_digest: SnapshotDigest,
    /// Exact target profile digest.
    pub target_digest: SnapshotDigest,
    /// Exact initiating capability catalog digest.
    pub initiator_catalog_digest: SnapshotDigest,
    /// Exact responding capability catalog digest.
    pub responder_catalog_digest: SnapshotDigest,
    /// Caller-supplied evaluation time.
    pub evaluated_at_unix_secs: i64,
}

/// Immutable, canonical, bounded compatibility result with unresolved proof gates.
#[derive(Clone, Debug)]
pub struct CompatibilityAnalysis {
    bindings: CompatibilityBindings,
    status: CompatibilityStatus,
    findings: Vec<CompatibilityFinding>,
    prerequisites: Vec<CompatibilityPrerequisite>,
    initiator_record_ids: Vec<String>,
    responder_record_ids: Vec<String>,
    evidence_refs: Vec<CapabilityEvidenceRef>,
    canonical: Vec<u8>,
    digest: SnapshotDigest,
}

impl CompatibilityAnalysis {
    /// Pinned graph, inventory, desired target and catalog versions.
    #[must_use]
    pub const fn bindings(&self) -> CompatibilityBindings {
        self.bindings
    }

    /// Conservative result, never a migration execution authorization.
    #[must_use]
    pub const fn status(&self) -> CompatibilityStatus {
        self.status
    }

    /// Sorted structured reasons and their source-attributed references.
    #[must_use]
    pub fn findings(&self) -> &[CompatibilityFinding] {
        &self.findings
    }

    /// Sorted unsatisfied requirements for an authoritative conclusion.
    #[must_use]
    pub fn prerequisites(&self) -> &[CompatibilityPrerequisite] {
        &self.prerequisites
    }

    /// Exact initiator capability record IDs, including contradictory sources.
    #[must_use]
    pub fn initiator_record_ids(&self) -> &[String] {
        &self.initiator_record_ids
    }

    /// Exact responder capability record IDs, including contradictory sources.
    #[must_use]
    pub fn responder_record_ids(&self) -> &[String] {
        &self.responder_record_ids
    }

    /// All distinct source/evidence/revision references, never source-ID-only.
    #[must_use]
    pub fn evidence_refs(&self) -> &[CapabilityEvidenceRef] {
        &self.evidence_refs
    }

    /// Immutable SHA-256 identity over all input claims and output decisions.
    #[must_use]
    pub const fn digest(&self) -> SnapshotDigest {
        self.digest
    }

    /// Versioned canonical binary evidence/report encoding; export, not import.
    pub fn export(&self, limits: &Limits) -> Result<Vec<u8>, Diagnostic> {
        limits.check(ResourceKind::ExportBytes, self.canonical.len())?;
        Ok(self.canonical.clone())
    }
}

/// Stateless, deterministic analyzer with no ambient time or network operations.
pub struct CompatibilityAnalyzer;

impl CompatibilityAnalyzer {
    /// Evaluate an exact two-runtime candidate against immutable sources.
    ///
    /// This version has no trusted cryptographic verifier. Even host-asserted
    /// "verified" records are treated as source claims, so Compatible is
    /// deliberately unreachable.
    pub fn analyze(
        request: &CompatibilityRequest,
        graph: &EvidenceGraph,
        target: &TargetProfile,
        initiator_catalog: &CapabilityCatalog,
        responder_catalog: &CapabilityCatalog,
        evaluated_at_unix_secs: i64,
        limits: &Limits,
    ) -> Result<CompatibilityAnalysis, Diagnostic> {
        admit(request, limits)?;
        let graph_digest = graph.fingerprint();
        if request.expected_graph_digest != graph_digest
            || request.expected_target_digest != target.digest()
            || request.expected_initiator_catalog_digest != initiator_catalog.digest()
            || request.expected_responder_catalog_digest != responder_catalog.digest()
        {
            return Err(err(
                DiagnosticCode::IntegrityMismatch,
                "compatibility_inputs",
                "input content identity mismatches a caller-pinned digest",
            ));
        }
        if request.scope_id != graph.source_scope_id()
            || request.scope_id != target.content().scope_id
            || request.scope_id != initiator_catalog.content().scope_id
            || request.scope_id != responder_catalog.content().scope_id
        {
            return Err(err(
                DiagnosticCode::InvalidReference,
                "compatibility_scope",
                "target, catalog and candidate scopes must match exactly",
            ));
        }
        if request.role != request.algorithm.role() {
            return Err(err(
                DiagnosticCode::InvalidStateTransition,
                "compatibility_role",
                "candidate algorithm and role must match exactly",
            ));
        }
        if request.initiator.system_node_id == request.responder.system_node_id
            || request.initiator.runtime_id == request.responder.runtime_id
        {
            return Err(err(
                DiagnosticCode::InvalidReference,
                "compatibility_peers",
                "initiator and responder must be distinct exact endpoints",
            ));
        }
        for endpoint in [&request.initiator, &request.responder] {
            if !graph.nodes().iter().any(|node| {
                node.id == endpoint.system_node_id && node.kind == GraphNodeKind::System
            }) {
                return Err(err(
                    DiagnosticCode::InvalidReference,
                    "compatibility_graph_node",
                    "peer endpoint must identify a System node in the exact graph",
                ));
            }
        }

        let left = initiator_catalog.match_target(
            target,
            request
                .initiator
                .selector(&request.scope_id, request.algorithm, request.role),
            evaluated_at_unix_secs,
            limits,
        )?;
        let right = responder_catalog.match_target(
            target,
            request
                .responder
                .selector(&request.scope_id, request.algorithm, request.role),
            evaluated_at_unix_secs,
            limits,
        )?;

        let bindings = CompatibilityBindings {
            graph_digest,
            inventory_digest: graph.source_digest(),
            target_digest: target.digest(),
            initiator_catalog_digest: initiator_catalog.digest(),
            responder_catalog_digest: responder_catalog.digest(),
            evaluated_at_unix_secs,
        };

        let mut findings: BTreeMap<
            (CompatibilitySubject, CompatibilityCode),
            BTreeSet<CapabilityEvidenceRef>,
        > = BTreeMap::new();
        let mut prerequisites = BTreeSet::new();
        let mut hard_block = false;
        let mut uncertainty = false;
        let mut source_refs = BTreeSet::new();

        for (which, matched) in [
            (CompatibilitySubject::Initiator, &left),
            (CompatibilitySubject::Responder, &right),
        ] {
            for reference in &matched.evidence_refs {
                source_refs.insert(reference.clone());
            }
            let gate = if which == CompatibilitySubject::Initiator {
                CompatibilityPrerequisite::VerifyInitiator
            } else {
                CompatibilityPrerequisite::VerifyResponder
            };
            prerequisites.insert(gate);
            match matched.state {
                CapabilityMatchState::Consistent(
                    CapabilityState::Available | CapabilityState::DeployedAndVerified,
                ) => {}
                CapabilityMatchState::NoEvidence => {
                    uncertainty = true;
                    add(
                        &mut findings,
                        which,
                        CompatibilityCode::CapabilityMissing,
                        &matched.evidence_refs,
                    );
                }
                CapabilityMatchState::Conflicting => {
                    uncertainty = true;
                    prerequisites.insert(CompatibilityPrerequisite::ReconcileEvidence);
                    add(
                        &mut findings,
                        which,
                        CompatibilityCode::CapabilityConflict,
                        &matched.evidence_refs,
                    );
                }
                CapabilityMatchState::Stale => {
                    uncertainty = true;
                    prerequisites.insert(CompatibilityPrerequisite::ReconcileEvidence);
                    add(
                        &mut findings,
                        which,
                        CompatibilityCode::CapabilityStale,
                        &matched.evidence_refs,
                    );
                }
                CapabilityMatchState::Consistent(_) => {
                    uncertainty = true;
                    add(
                        &mut findings,
                        which,
                        CompatibilityCode::CapabilityUnproven,
                        &matched.evidence_refs,
                    );
                }
            }
        }

        match target.disposition(request.algorithm.id())? {
            TargetDisposition::Forbidden => {
                hard_block = true;
                prerequisites.insert(CompatibilityPrerequisite::ChangeTarget);
                add(
                    &mut findings,
                    CompatibilitySubject::Target,
                    CompatibilityCode::AlgorithmForbidden,
                    &[],
                );
            }
            TargetDisposition::NotSpecified => {
                uncertainty = true;
                prerequisites.insert(CompatibilityPrerequisite::ChangeTarget);
                add(
                    &mut findings,
                    CompatibilitySubject::Target,
                    CompatibilityCode::TargetNotSpecified,
                    &[],
                );
            }
            TargetDisposition::Required | TargetDisposition::Permitted => {}
        }

        let protocol = target.content().protocols.iter().find(|item| {
            item.protocol_id == request.protocol_id
                && item.revision == request.protocol_revision
                && item.algorithm == request.algorithm
                && item.role == request.role
        });
        if protocol.is_none() {
            hard_block = true;
            prerequisites.insert(CompatibilityPrerequisite::ChangeTarget);
            add(
                &mut findings,
                CompatibilitySubject::Protocol,
                CompatibilityCode::ProtocolNotApproved,
                &[],
            );
        }

        let requested_hybrid = request
            .hybrid
            .as_ref()
            .map(|item| (&item.companion_algorithm_id, &item.combiner_reference));
        let approved_hybrid = protocol
            .and_then(|item| item.hybrid.as_ref())
            .map(|item| (&item.companion_algorithm_id, &item.combiner_reference));
        if requested_hybrid != approved_hybrid {
            hard_block = true;
            prerequisites.insert(CompatibilityPrerequisite::ChangeTarget);
            add(
                &mut findings,
                CompatibilitySubject::Protocol,
                CompatibilityCode::HybridNotApproved,
                &[],
            );
        }
        if request.classical_fallback {
            hard_block = true;
            add(
                &mut findings,
                CompatibilitySubject::Protocol,
                CompatibilityCode::DowngradeRejected,
                &[],
            );
        }

        if let Some(cert) = &request.certificate {
            if cert.signature_algorithm.role() != AlgorithmRole::Signature
                || !target.content().certificates.iter().any(|item| {
                    item.profile_id == cert.profile_id
                        && item.revision == cert.revision
                        && item.signature_algorithm == cert.signature_algorithm
                })
            {
                hard_block = true;
                prerequisites.insert(CompatibilityPrerequisite::ChangeTarget);
                add(
                    &mut findings,
                    CompatibilitySubject::Pki,
                    CompatibilityCode::CertificateNotApproved,
                    &[],
                );
            }
        } else if !target.content().certificates.is_empty() {
            uncertainty = true;
            prerequisites.insert(CompatibilityPrerequisite::VerifyPki);
            add(
                &mut findings,
                CompatibilitySubject::Pki,
                CompatibilityCode::PkiMissing,
                &[],
            );
        }

        let mut link_claims = BTreeSet::new();
        let mut negotiation_claims = BTreeSet::new();
        let mut pki_claims = BTreeSet::new();
        let mut has_link = false;
        let mut has_negotiation = false;
        let mut has_pki = false;
        let mut selected_hybrid = false;

        let mut observations: Vec<&CompatibilityObservation> =
            request.observations.iter().collect();
        observations.sort_by_key(|item| {
            let source = item.source();
            (
                &source.source_id,
                &source.evidence_id,
                &source.source_revision,
            )
        });
        for observation in &observations {
            let source = observation.source();
            let reference = source.reference();
            source_refs.insert(reference.clone());
            if source.stale(evaluated_at_unix_secs) {
                uncertainty = true;
                prerequisites.insert(CompatibilityPrerequisite::ReconcileEvidence);
                add(
                    &mut findings,
                    subject_of(observation),
                    CompatibilityCode::EvidenceStale,
                    &[reference],
                );
                continue;
            }

            let mut payload = Vec::new();
            encode_payload(&mut payload, observation);
            match observation {
                CompatibilityObservation::PeerLink(item) => {
                    if item.scope_id != request.scope_id
                        || item.initiator_node_id != request.initiator.system_node_id
                        || item.responder_node_id != request.responder.system_node_id
                        || item.protocol_id != request.protocol_id
                        || item.protocol_revision != request.protocol_revision
                    {
                        uncertainty = true;
                        add(
                            &mut findings,
                            CompatibilitySubject::PeerLink,
                            CompatibilityCode::EvidenceBindingMismatch,
                            &[reference],
                        );
                        continue;
                    }
                    has_link = true;
                    link_claims.insert(payload);
                }
                CompatibilityObservation::Negotiation(item) => {
                    if item.scope_id != request.scope_id
                        || item.initiator_runtime_id != request.initiator.runtime_id
                        || item.responder_runtime_id != request.responder.runtime_id
                        || item.protocol_id != request.protocol_id
                        || item.protocol_revision != request.protocol_revision
                        || item.extension_revision != request.extension_revision
                    {
                        uncertainty = true;
                        add(
                            &mut findings,
                            CompatibilitySubject::Protocol,
                            CompatibilityCode::EvidenceBindingMismatch,
                            &[reference],
                        );
                        continue;
                    }
                    has_negotiation = true;
                    negotiation_claims.insert(payload);
                    if item.selected_algorithm != Some(request.algorithm)
                        || !item.initiator_offers.contains(&request.algorithm)
                        || !item.responder_offers.contains(&request.algorithm)
                        || item.classical_fallback_used
                        || !valid_negotiated_signature(item, request)
                    {
                        uncertainty = true;
                        add(
                            &mut findings,
                            CompatibilitySubject::Protocol,
                            CompatibilityCode::NegotiationMismatch,
                            std::slice::from_ref(&reference),
                        );
                    }
                    if item.classical_fallback_used {
                        hard_block = true;
                        add(
                            &mut findings,
                            CompatibilitySubject::Protocol,
                            CompatibilityCode::DowngradeRejected,
                            std::slice::from_ref(&reference),
                        );
                    }
                    if let Some(hybrid) = &request.hybrid {
                        if item.hybrid_companion_id.as_deref()
                            == Some(hybrid.companion_algorithm_id.as_str())
                            && item.hybrid_combiner_reference.as_deref()
                                == Some(hybrid.combiner_reference.as_str())
                        {
                            selected_hybrid = true;
                        } else {
                            uncertainty = true;
                            prerequisites.insert(CompatibilityPrerequisite::VerifyHybrid);
                            add(
                                &mut findings,
                                CompatibilitySubject::Protocol,
                                CompatibilityCode::HybridProofMissing,
                                &[reference],
                            );
                        }
                    } else if item.hybrid_companion_id.is_some()
                        || item.hybrid_combiner_reference.is_some()
                    {
                        uncertainty = true;
                        add(
                            &mut findings,
                            CompatibilitySubject::Protocol,
                            CompatibilityCode::NegotiationMismatch,
                            &[reference],
                        );
                    }
                }
                CompatibilityObservation::Pki(item) => {
                    if item.scope_id != request.scope_id
                        || item.initiator_runtime_id != request.initiator.runtime_id
                        || item.responder_runtime_id != request.responder.runtime_id
                    {
                        uncertainty = true;
                        add(
                            &mut findings,
                            CompatibilitySubject::Pki,
                            CompatibilityCode::EvidenceBindingMismatch,
                            &[reference],
                        );
                        continue;
                    }
                    has_pki = true;
                    pki_claims.insert(payload);
                    if request.certificate.as_ref().is_none_or(|cert| {
                        item.profile_id != cert.profile_id
                            || item.revision != cert.revision
                            || item.certificate_id != cert.certificate_id
                            || item.chain_id != cert.chain_id
                            || item.trust_anchor_id != cert.trust_anchor_id
                            || item.signature_algorithm != cert.signature_algorithm
                    }) {
                        uncertainty = true;
                        add(
                            &mut findings,
                            CompatibilitySubject::Pki,
                            CompatibilityCode::PkiMismatch,
                            std::slice::from_ref(&reference),
                        );
                    }
                    if item.validation_at_unix_secs > evaluated_at_unix_secs
                        || item.chain_valid != Some(true)
                        || !item.revocation_checked
                    {
                        uncertainty = true;
                        prerequisites.insert(CompatibilityPrerequisite::VerifyRevocation);
                        add(
                            &mut findings,
                            CompatibilitySubject::Pki,
                            CompatibilityCode::PkiUnverified,
                            &[reference],
                        );
                    }
                }
            }
        }

        if !has_link {
            uncertainty = true;
            prerequisites.insert(CompatibilityPrerequisite::VerifyPeerLink);
            add(
                &mut findings,
                CompatibilitySubject::PeerLink,
                CompatibilityCode::PeerLinkMissing,
                &[],
            );
        } else {
            prerequisites.insert(CompatibilityPrerequisite::VerifyPeerLink);
        }
        if !has_negotiation {
            prerequisites.insert(CompatibilityPrerequisite::VerifyNegotiation);
            add(
                &mut findings,
                CompatibilitySubject::Protocol,
                CompatibilityCode::NegotiationMissing,
                &[],
            );
        } else {
            prerequisites.insert(CompatibilityPrerequisite::VerifyNegotiation);
            let sources: Vec<_> = observations
                .iter()
                .filter_map(|item| match item {
                    CompatibilityObservation::Negotiation(value) => Some(value.source.reference()),
                    _ => None,
                })
                .collect();
            add(
                &mut findings,
                CompatibilitySubject::Protocol,
                CompatibilityCode::NegotiationUnauthenticated,
                &sources,
            );
        }
        if request.certificate.is_some() {
            prerequisites.insert(CompatibilityPrerequisite::VerifyPki);
            if !has_pki {
                add(
                    &mut findings,
                    CompatibilitySubject::Pki,
                    CompatibilityCode::PkiMissing,
                    &[],
                );
            } else {
                let sources: Vec<_> = observations
                    .iter()
                    .filter_map(|item| match item {
                        CompatibilityObservation::Pki(value) => Some(value.source.reference()),
                        _ => None,
                    })
                    .collect();
                add(
                    &mut findings,
                    CompatibilitySubject::Pki,
                    CompatibilityCode::PkiUnverified,
                    &sources,
                );
            }
        }
        if request.hybrid.is_some() {
            prerequisites.insert(CompatibilityPrerequisite::VerifyHybrid);
            if !selected_hybrid {
                add(
                    &mut findings,
                    CompatibilitySubject::Protocol,
                    CompatibilityCode::HybridProofMissing,
                    &[],
                );
            }
        }

        for (subject, payloads) in [
            (CompatibilitySubject::PeerLink, &link_claims),
            (CompatibilitySubject::Protocol, &negotiation_claims),
            (CompatibilitySubject::Pki, &pki_claims),
        ] {
            if payloads.len() > 1 {
                uncertainty = true;
                prerequisites.insert(CompatibilityPrerequisite::ReconcileEvidence);
                let sources: Vec<_> = observations
                    .iter()
                    .filter(|item| subject_of(item) == subject)
                    .map(|item| item.source().reference())
                    .collect();
                add(
                    &mut findings,
                    subject,
                    CompatibilityCode::EvidenceConflict,
                    &sources,
                );
            }
        }

        let status = if hard_block {
            CompatibilityStatus::Incompatible
        } else if uncertainty {
            CompatibilityStatus::Unknown
        } else if request.hybrid.is_some() && selected_hybrid {
            CompatibilityStatus::Transitional
        } else {
            CompatibilityStatus::Conditional
        };

        let findings: Vec<_> = findings
            .into_iter()
            .map(|((subject, code), refs)| CompatibilityFinding {
                subject,
                code,
                evidence_refs: refs.into_iter().collect(),
            })
            .collect();
        let prerequisites: Vec<_> = prerequisites.into_iter().collect();
        let evidence_refs: Vec<_> = source_refs.into_iter().collect();
        let canonical = encode_report(
            request,
            &observations,
            bindings,
            status,
            &findings,
            &prerequisites,
            &left,
            &right,
            &evidence_refs,
            limits,
        )?;
        let digest = SnapshotDigest::hash(&canonical);
        Ok(CompatibilityAnalysis {
            bindings,
            status,
            findings,
            prerequisites,
            initiator_record_ids: left.record_ids,
            responder_record_ids: right.record_ids,
            evidence_refs,
            canonical,
            digest,
        })
    }
}

fn valid_negotiated_signature(
    item: &NegotiationObservation,
    request: &CompatibilityRequest,
) -> bool {
    match &request.certificate {
        Some(cert) => item.selected_signature == Some(cert.signature_algorithm),
        None => item.selected_signature.is_none(),
    }
}

fn subject_of(item: &CompatibilityObservation) -> CompatibilitySubject {
    match item {
        CompatibilityObservation::PeerLink(_) => CompatibilitySubject::PeerLink,
        CompatibilityObservation::Negotiation(_) => CompatibilitySubject::Protocol,
        CompatibilityObservation::Pki(_) => CompatibilitySubject::Pki,
    }
}

fn add(
    findings: &mut BTreeMap<
        (CompatibilitySubject, CompatibilityCode),
        BTreeSet<CapabilityEvidenceRef>,
    >,
    subject: CompatibilitySubject,
    code: CompatibilityCode,
    sources: &[CapabilityEvidenceRef],
) {
    findings
        .entry((subject, code))
        .or_default()
        .extend(sources.iter().cloned());
}

fn err(code: DiagnosticCode, subject: &'static str, reason: &'static str) -> Diagnostic {
    Diagnostic::new(code, subject, reason)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

fn admit(request: &CompatibilityRequest, limits: &Limits) -> Result<(), Diagnostic> {
    limits.validate()?;
    if request.schema_version != COMPATIBILITY_ANALYSIS_VERSION {
        return Err(err(
            DiagnosticCode::UnsupportedSchemaVersion,
            "compatibility_schema",
            "unsupported compatibility contract revision",
        ));
    }
    limits.check(ResourceKind::EvidenceRecords, request.observations.len())?;
    limits.checked_mul(
        ResourceKind::PlannerCandidates,
        request.observations.len(),
        3,
    )?;
    let mut bytes = 0_usize;
    let mut id = |value: &str| -> Result<(), Diagnostic> {
        if !valid_id(value) {
            return Err(err(
                DiagnosticCode::InvalidIdentifier,
                "compatibility_identifier",
                "invalid or sensitive candidate identifier",
            ));
        }
        bytes = limits.checked_add(ResourceKind::InputBytes, bytes, value.len())?;
        Ok(())
    };
    id(&request.scope_id)?;
    id(&request.protocol_id)?;
    id(&request.protocol_revision)?;
    id(&request.extension_revision)?;
    for peer in [&request.initiator, &request.responder] {
        for item in [
            &peer.system_node_id,
            &peer.provider_id,
            &peer.product_id,
            &peer.product_version,
            &peer.platform_id,
            &peer.runtime_id,
        ] {
            id(item)?;
        }
    }
    if let Some(cert) = &request.certificate {
        for item in [
            &cert.profile_id,
            &cert.revision,
            &cert.certificate_id,
            &cert.chain_id,
            &cert.trust_anchor_id,
        ] {
            id(item)?;
        }
    }
    if let Some(hybrid) = &request.hybrid {
        id(&hybrid.companion_algorithm_id)?;
        id(&hybrid.combiner_reference)?;
        if hybrid.companion_algorithm_id == request.algorithm.id() {
            return Err(err(
                DiagnosticCode::InvalidStateTransition,
                "hybrid_companion",
                "hybrid companion cannot repeat primary algorithm",
            ));
        }
    }
    let mut refs = BTreeSet::new();
    for observation in &request.observations {
        let source = observation.source();
        for item in [
            &source.source_id,
            &source.evidence_id,
            &source.source_revision,
        ] {
            id(item)?;
        }
        if let Some(reference) = &source.verification_reference {
            id(reference)?;
        }
        if !refs.insert((
            &source.source_id,
            &source.evidence_id,
            &source.source_revision,
        )) {
            return Err(err(
                DiagnosticCode::DuplicateRecord,
                "compatibility_source",
                "repeated evidence identity in one source namespace",
            ));
        }
        match observation {
            CompatibilityObservation::PeerLink(item) => {
                for value in [
                    &item.scope_id,
                    &item.initiator_node_id,
                    &item.responder_node_id,
                    &item.protocol_id,
                    &item.protocol_revision,
                ] {
                    id(value)?;
                }
            }
            CompatibilityObservation::Negotiation(item) => {
                for value in [
                    &item.scope_id,
                    &item.initiator_runtime_id,
                    &item.responder_runtime_id,
                    &item.protocol_id,
                    &item.protocol_revision,
                    &item.extension_revision,
                ] {
                    id(value)?;
                }
                limits.check(ResourceKind::ProfileReferences, item.initiator_offers.len())?;
                limits.check(ResourceKind::ProfileReferences, item.responder_offers.len())?;
                if item
                    .initiator_offers
                    .iter()
                    .any(|value| value.role() != request.role)
                    || item
                        .responder_offers
                        .iter()
                        .any(|value| value.role() != request.role)
                {
                    return Err(err(
                        DiagnosticCode::InvalidStateTransition,
                        "compatibility_offers",
                        "offered algorithm has a different cryptographic role",
                    ));
                }
                if let Some(value) = &item.hybrid_companion_id {
                    id(value)?;
                }
                if let Some(value) = &item.hybrid_combiner_reference {
                    id(value)?;
                }
            }
            CompatibilityObservation::Pki(item) => {
                for value in [
                    &item.scope_id,
                    &item.initiator_runtime_id,
                    &item.responder_runtime_id,
                    &item.profile_id,
                    &item.revision,
                    &item.certificate_id,
                    &item.chain_id,
                    &item.trust_anchor_id,
                ] {
                    id(value)?;
                }
                if item.signature_algorithm.role() != AlgorithmRole::Signature {
                    return Err(err(
                        DiagnosticCode::InvalidStateTransition,
                        "pki_signature",
                        "PKI signature algorithm is not a signature",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn str_field(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn bool_field(output: &mut Vec<u8>, value: bool) {
    output.push(u8::from(value));
}

fn optional_str(output: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(item) => {
            output.push(1);
            str_field(output, item);
        }
        None => output.push(0),
    }
}

fn optional_algorithm(output: &mut Vec<u8>, value: Option<KnownAlgorithm>) {
    optional_str(output, value.map(KnownAlgorithm::id));
}

fn optional_digest(output: &mut Vec<u8>, digest: Option<SnapshotDigest>) {
    match digest {
        Some(item) => {
            output.push(1);
            output.extend_from_slice(&item.as_bytes());
        }
        None => output.push(0),
    }
}

fn encode_payload(output: &mut Vec<u8>, item: &CompatibilityObservation) {
    match item {
        CompatibilityObservation::PeerLink(value) => {
            output.push(1);
            for part in [
                &value.scope_id,
                &value.initiator_node_id,
                &value.responder_node_id,
                &value.protocol_id,
                &value.protocol_revision,
            ] {
                str_field(output, part);
            }
        }
        CompatibilityObservation::Negotiation(value) => {
            output.push(2);
            for part in [
                &value.scope_id,
                &value.initiator_runtime_id,
                &value.responder_runtime_id,
                &value.protocol_id,
                &value.protocol_revision,
                &value.extension_revision,
            ] {
                str_field(output, part);
            }
            let mut left = value.initiator_offers.clone();
            let mut right = value.responder_offers.clone();
            left.sort();
            right.sort();
            for offers in [&left, &right] {
                output.extend_from_slice(&(offers.len() as u32).to_be_bytes());
                for algorithm in offers {
                    str_field(output, algorithm.id());
                }
            }
            optional_algorithm(output, value.selected_algorithm);
            optional_algorithm(output, value.selected_signature);
            optional_str(output, value.hybrid_companion_id.as_deref());
            optional_str(output, value.hybrid_combiner_reference.as_deref());
            bool_field(output, value.classical_fallback_used);
        }
        CompatibilityObservation::Pki(value) => {
            output.push(3);
            for part in [
                &value.scope_id,
                &value.initiator_runtime_id,
                &value.responder_runtime_id,
                &value.profile_id,
                &value.revision,
                &value.certificate_id,
                &value.chain_id,
                &value.trust_anchor_id,
            ] {
                str_field(output, part);
            }
            str_field(output, value.signature_algorithm.id());
            output.push(match value.chain_valid {
                None => 0,
                Some(false) => 1,
                Some(true) => 2,
            });
            bool_field(output, value.revocation_checked);
            output.extend_from_slice(&value.validation_at_unix_secs.to_be_bytes());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_report(
    request: &CompatibilityRequest,
    observations: &[&CompatibilityObservation],
    bindings: CompatibilityBindings,
    status: CompatibilityStatus,
    findings: &[CompatibilityFinding],
    prerequisites: &[CompatibilityPrerequisite],
    left: &CapabilityMatch,
    right: &CapabilityMatch,
    evidence_refs: &[CapabilityEvidenceRef],
    limits: &Limits,
) -> Result<Vec<u8>, Diagnostic> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"CSHIFT_COMPATIBILITY_V1");
    bytes.extend_from_slice(&COMPATIBILITY_ANALYSIS_VERSION.to_be_bytes());
    for digest in [
        bindings.inventory_digest,
        bindings.graph_digest,
        bindings.target_digest,
        bindings.initiator_catalog_digest,
        bindings.responder_catalog_digest,
    ] {
        bytes.extend_from_slice(&digest.as_bytes());
    }
    bytes.extend_from_slice(&bindings.evaluated_at_unix_secs.to_be_bytes());
    str_field(&mut bytes, &request.scope_id);
    for endpoint in [&request.initiator, &request.responder] {
        for item in [
            &endpoint.system_node_id,
            &endpoint.provider_id,
            &endpoint.product_id,
            &endpoint.product_version,
            &endpoint.platform_id,
            &endpoint.runtime_id,
        ] {
            str_field(&mut bytes, item);
        }
    }
    for item in [
        &request.protocol_id,
        &request.protocol_revision,
        &request.extension_revision,
    ] {
        str_field(&mut bytes, item);
    }
    str_field(&mut bytes, request.algorithm.id());
    bytes.push(match request.role {
        AlgorithmRole::KeyEncapsulation => 1,
        AlgorithmRole::Signature => 2,
    });
    bool_field(&mut bytes, request.classical_fallback);
    match &request.certificate {
        Some(cert) => {
            bytes.push(1);
            for item in [
                &cert.profile_id,
                &cert.revision,
                &cert.certificate_id,
                &cert.chain_id,
                &cert.trust_anchor_id,
            ] {
                str_field(&mut bytes, item);
            }
            str_field(&mut bytes, cert.signature_algorithm.id());
        }
        None => bytes.push(0),
    }
    match &request.hybrid {
        Some(hybrid) => {
            bytes.push(1);
            str_field(&mut bytes, &hybrid.companion_algorithm_id);
            str_field(&mut bytes, &hybrid.combiner_reference);
        }
        None => bytes.push(0),
    }
    for records in [&left.record_ids, &right.record_ids] {
        bytes.extend_from_slice(&(records.len() as u32).to_be_bytes());
        for item in records {
            str_field(&mut bytes, item);
        }
    }
    bytes.extend_from_slice(&(observations.len() as u32).to_be_bytes());
    for item in observations {
        let source = item.source();
        for part in [
            &source.source_id,
            &source.evidence_id,
            &source.source_revision,
        ] {
            str_field(&mut bytes, part);
        }
        bytes.extend_from_slice(&source.observed_at_unix_secs.to_be_bytes());
        match source.expires_at_unix_secs {
            Some(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&value.to_be_bytes());
            }
            None => bytes.push(0),
        }
        optional_str(&mut bytes, source.verification_reference.as_deref());
        optional_digest(&mut bytes, source.artifact_digest);
        encode_payload(&mut bytes, item);
    }
    bytes.push(status as u8);
    bytes.extend_from_slice(&(findings.len() as u32).to_be_bytes());
    for finding in findings {
        bytes.push(finding.subject as u8);
        bytes.push(finding.code as u8);
        bytes.extend_from_slice(&(finding.evidence_refs.len() as u32).to_be_bytes());
        for reference in &finding.evidence_refs {
            for part in [
                &reference.source_id,
                &reference.evidence_id,
                &reference.source_revision,
            ] {
                str_field(&mut bytes, part);
            }
        }
    }
    bytes.extend_from_slice(&(prerequisites.len() as u32).to_be_bytes());
    for item in prerequisites {
        bytes.push(*item as u8);
    }
    bytes.extend_from_slice(&(evidence_refs.len() as u32).to_be_bytes());
    for reference in evidence_refs {
        for part in [
            &reference.source_id,
            &reference.evidence_id,
            &reference.source_revision,
        ] {
            str_field(&mut bytes, part);
        }
    }
    limits.check(ResourceKind::ExportBytes, bytes.len())?;
    Ok(bytes)
}
