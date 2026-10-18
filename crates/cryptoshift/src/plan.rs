//! Immutable, replay-fenced migration-plan *drafts* (FOSS-444).
//!
//! Plan identity and source citations are not signatures. External exception
//! claims cannot waive blockers, and no API represents execution authority.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    BlockerCode, BlockerFinding, BlockerSeverity, CapabilityCatalog, DependencyTopology,
    Diagnostic, DiagnosticCode, Limits, ReadinessGateKind, RemediationAnalysis,
    RemediationEvidence, RemediationGate, RemediationOwner, ResourceKind,
    RiskFactorKind, ScoreProfile, SnapshotDigest, StandardEdition, TargetProfile,
    UnitReadiness, UnitReadinessStatus, WavePlanDraft, WavePlanner,
    STANDARDS_CATALOG_VERSION,
};

/// Version of the frozen, domain-separated plan and exception contract.
pub const MIGRATION_PLAN_VERSION: u16 = 1;

/// A declared capability catalog source; no proof of deployed functionality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanCatalogPin {
    /// Catalog publisher-assigned identity.
    pub catalog_id: String,
    /// Source-declared revision; not an authenticated monotonic counter.
    pub revision: u32,
    /// SHA-256 of the validated, immutable catalog body.
    pub digest: SnapshotDigest,
}

/// A fully specified optional risk scoring configuration, not a risk waiver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanScorePin {
    /// Caller-supplied score profile identity.
    pub profile_id: String,
    /// Exact schema revision of the scoring profile.
    pub version: u16,
    /// Digest of profile identity, schema and all ten exact weights.
    pub digest: SnapshotDigest,
}

/// Exact externally pinned upstream content identities and declared standards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanSourcePins {
    /// Tenant/scope identity; never inherited from another deployment.
    pub scope_id: String,
    /// Explicit caller-selected evaluation time; no system clock is read.
    pub evaluated_at_unix_secs: i64,
    /// Content-bound D2 wave draft.
    pub wave_digest: SnapshotDigest,
    /// Full-content D1 blocker and remediation report.
    pub remediation_digest: SnapshotDigest,
    /// FOSS-438/441 combined peer evidence hash.
    pub compatibility_set_digest: SnapshotDigest,
    /// Validated inventory content hash.
    pub inventory_digest: SnapshotDigest,
    /// Exact typed graph fingerprint.
    pub graph_digest: SnapshotDigest,
    /// SCC topology content hash.
    pub topology_digest: SnapshotDigest,
    /// Exact scoped target revision content hash.
    pub target_digest: SnapshotDigest,
    /// Full factor-vector risk content digest.
    pub risk_digest: SnapshotDigest,
    /// Exact standards catalog generation.
    pub standards_catalog_version: u16,
    /// Required standards (not independently authenticated).
    pub standards: Vec<StandardEdition>,
    /// Scoped capability source set, sorted by source identity.
    pub catalogs: Vec<PlanCatalogPin>,
    /// Digest over all capability catalog names, revisions, and bodies.
    pub catalog_set_digest: SnapshotDigest,
    /// Optional named, versioned score weighting scheme.
    pub scoring: Option<PlanScorePin>,
}

/// A source-claimed approval that is **never** verified by Cryptoshift.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedExceptionApproval {
    /// Claimed independent authority identity.
    pub issuer_id: String,
    /// Opaque external purported approval record; not a signature.
    pub receipt_reference: String,
    /// Exact revision of the claimed record.
    pub source_revision: String,
    /// Claimed observation time in UTC Unix seconds.
    pub observed_at_unix_secs: i64,
}

/// External request to document an exception; never a policy exception grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanExceptionRequest {
    /// Caller-issued record identity unique to one plan scope.
    pub request_id: String,
    /// Exact target tenant/scope.
    pub scope_id: String,
    /// A known, indivisible migration SCC.
    pub unit_id: String,
    /// Exact known target algorithm, protocol or certificate identifier.
    pub target_constraint_id: String,
    /// Owner-claim identity, not authenticated user principal.
    pub requester_source_id: String,
    /// Opaque source record; do not embed justification or secrets.
    pub justification_reference: String,
    /// Original requested time (explicit; no ambient clock).
    pub requested_at_unix_secs: i64,
    /// Exact external expiry; no inferred grace period.
    pub expires_at_unix_secs: i64,
    /// Claim only; no trusted signer, chain or authority validation exists.
    pub claimed_approval: Option<ClaimedExceptionApproval>,
}

/// No accepted/approved state exists without a real authority verifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PlanExceptionState {
    /// Pending independently authorized treatment and review.
    Requested = 1,
    /// A claimed receipt is present but explicitly unauthenticated.
    ClaimedApprovalUnverified = 2,
    /// Deadline passed; this never discharges an obligation.
    Expired = 3,
}

/// Immutable, canonical request record and derived nonauthoritative state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanExceptionRecord {
    /// Original supplied request, validated and sorted by request ID.
    pub request: PlanExceptionRequest,
    /// Derived from timestamp and caller claims without trust elevation.
    pub state: PlanExceptionState,
}

/// Namespaced evidence references, preserving original source distinctions.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PlanEvidenceRef {
    /// Exact D1 original provenance, never downgraded to bare local ID.
    Remediation(RemediationEvidence),
    /// Capability claim from source, evidence and revision.
    Capability {
        /// External claim publisher ID.
        source_id: String,
        /// Publisher-local evidence ID.
        evidence_id: String,
        /// Explicit evidence revision.
        source_revision: String,
    },
    /// Exception source record, not an endorsement.
    Exception {
        /// Claiming or requesting source identity.
        source_id: String,
        /// Original opaque source record.
        reference_id: String,
        /// Exact source revision, if independently stated.
        revision: String,
    },
}

/// Typed residual obligation; not a quantified probability of breach.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ResidualRiskKind {
    /// Required cryptographic/policy constraints remain unresolved.
    PolicyConstraint = 1,
    /// Quantum exposure or context risk is unresolved.
    QuantumOrContextRisk = 2,
    /// Peer negotiations or runtime interoperability need proof.
    PeerProtocol = 3,
    /// PKI chains, profiles, revocation or anchors need validation.
    PkiTrust = 4,
    /// Vendor/runtime capability is not independently authenticated.
    VendorCapability = 5,
    /// Unit ownership is missing or ambiguous.
    Ownership = 6,
    /// Upstream SCC needs independent acceptance.
    Dependency = 7,
    /// Source provenance, freshness or completeness requires review.
    EvidenceQuality = 8,
    /// Change-control authority is outstanding.
    ChangeApproval = 9,
    /// A reviewed maintenance window is outstanding.
    Maintenance = 10,
    /// Validated rollback/contingency approval is outstanding.
    Rollback = 11,
    /// Independently authenticated unit review is outstanding.
    UnitReview = 12,
    /// An explicit source-defined deadline requires handling.
    Deadline = 13,
    /// Unverified exception claim never dismisses underlying findings.
    ExceptionUnverified = 14,
    /// No scoped capability catalog was submitted.
    MissingCapabilityEvidence = 15,
}

/// One individually traceable residual risk/required action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidualRiskFacet {
    /// Source-bound stable record ID, rotating with upstream evidence.
    pub id: String,
    /// Scope-wide facets have no SCC; otherwise exact SCC unit ID.
    pub unit_id: Option<String>,
    /// Stable typed facet classification.
    pub kind: ResidualRiskKind,
    /// Exact original D1 blocker, if applicable.
    pub blocker_id: Option<String>,
    /// Exact original D1 action, if applicable.
    pub action_id: Option<String>,
    /// Exact directly dependent upstream SCC, if applicable.
    pub prerequisite_unit_id: Option<String>,
    /// Evidence original source namespaces and revisions.
    pub evidence: Vec<PlanEvidenceRef>,
    /// Exact unsatisfied external evidence/approval gates.
    pub validation_gates: Vec<RemediationGate>,
    /// External source-defined due date; never inferred.
    pub due_at_unix_secs: Option<i64>,
}

/// A plan *draft* state; none implies an approved or safe execution.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PlanAssessmentState {
    /// At least one hard-policy/contradiction blocker is present.
    Blocked = 1,
    /// Some essential source evidence or proof remains unresolved.
    Partial = 2,
    /// All modeled prerequisites lack an authenticated final approval.
    ExternalApprovalPending = 3,
    /// Evidence is modeled for external review only; NEVER authorization.
    CompleteEvidenceForReview = 4,
}

/// User-supplied expected content identities plus *untrusted* requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationPlanRequest {
    /// Stable schema revision; must match MIGRATION_PLAN_VERSION.
    pub schema_version: u16,
    /// Complete externally pinned source/plan versions.
    pub expected_pins: PlanSourcePins,
    /// Untrusted proposed exception requests, accepted neither here nor upstream.
    pub exceptions: Vec<PlanExceptionRequest>,
}

/// Immutable, auditable proposal; no authorization or execution API.
#[derive(Clone, Debug)]
pub struct MigrationPlanDraft {
    pins: PlanSourcePins,
    status: PlanAssessmentState,
    waves: Vec<crate::MigrationWave>,
    readiness: Vec<UnitReadiness>,
    blockers: Vec<String>,
    actions: Vec<String>,
    residual_risks: Vec<ResidualRiskFacet>,
    exceptions: Vec<PlanExceptionRecord>,
    canonical: Vec<u8>,
    digest: SnapshotDigest,
}

impl MigrationPlanDraft {
    /// Full upstream data provenance and version contract.
    #[must_use]
    pub fn pins(&self) -> &PlanSourcePins { &self.pins }
    /// Non-authoritative plan evidence completeness status.
    #[must_use]
    pub const fn status(&self) -> PlanAssessmentState { self.status }
    /// Immutable original D2 candidate waves, never an execution schedule.
    #[must_use]
    pub fn waves(&self) -> &[crate::MigrationWave] { &self.waves }
    /// Exact unmodified D2 per-unit review conditions.
    #[must_use]
    pub fn readiness(&self) -> &[UnitReadiness] { &self.readiness }
    /// Source-bound FOSS-441 blocker identity set.
    #[must_use]
    pub fn blocker_ids(&self) -> &[String] { &self.blockers }
    /// Source-bound FOSS-441 action identity set.
    #[must_use]
    pub fn action_ids(&self) -> &[String] { &self.actions }
    /// Source-attributed, unresolved evidence and operational obligations.
    #[must_use]
    pub fn residual_risks(&self) -> &[ResidualRiskFacet] { &self.residual_risks }
    /// Unverified exception proposals and claimed approvals, never grants.
    #[must_use]
    pub fn exceptions(&self) -> &[PlanExceptionRecord] { &self.exceptions }
    /// SHA-256 of frozen version-one canonical bytes.
    #[must_use]
    pub const fn digest(&self) -> SnapshotDigest { self.digest }
    /// Export only under an active output byte limit.
    pub fn export(&self, limits:&Limits) -> Result<Vec<u8>,Diagnostic> {
        limits.check(ResourceKind::ExportBytes,self.canonical.len())?;
        Ok(self.canonical.clone())
    }
}


#[path = "plan_codec.rs"]
mod codec;
use codec::Encoder;

/// Offline, bounded source-pinned plan builder. Does not authenticate approvals.
pub struct MigrationPlanner;

impl MigrationPlanner {
    /// Hash an exact scoring definition, including all factor weights.
    pub fn scoring_digest(score:&ScoreProfile,limits:&Limits)->Result<SnapshotDigest,Diagnostic>{
        let mut writer=Encoder::new(limits);
        writer.raw(b"CSHIFT_SCORING_PROFILE_D3_V1")?;
        writer.string(score.id())?;
        writer.u16(score.version())?;
        for weight in score.weights_bps(){writer.u16(*weight)?;}
        Ok(SnapshotDigest::hash(&writer.finish()))
    }

    /// Compute source pins for independent verification *before* building.
    ///
    /// A digest of untrusted inputs is only content identity; it is not a
    /// trusted source, authority signature, or permission to migrate.
    pub fn input_pins(
        topology:&DependencyTopology,
        remediation:&RemediationAnalysis,
        wave:&WavePlanDraft,
        target:&TargetProfile,
        capability_catalogs:&[&CapabilityCatalog],
        score:Option<&ScoreProfile>,
        limits:&Limits,
    )->Result<PlanSourcePins,Diagnostic>{
        limits.validate()?;
        limits.check(ResourceKind::ProfileReferences,capability_catalogs.len())?;
        let wb=WavePlanner::input_bindings(topology,remediation,target,limits)?;
        if wave.bindings()!=&wb{
            return Err(problem(DiagnosticCode::IntegrityMismatch,"plan_wave_binding",
                "wave draft and D1 must describe exactly the same source versions"));
        }
        let _ = wave.export(limits)?;
        let b=remediation.bindings();
        let now=b.evaluated_at_unix_secs;
        if target.content().expires_at_unix_secs.is_some_and(|expiry|now>=expiry){
            return Err(problem(DiagnosticCode::StaleCriticalProfile,"plan_target_expiry",
                "target profile is no longer current at pinned evaluation time"));
        }
        let mut catalogs=Vec::with_capacity(capability_catalogs.len());
        let mut seen=BTreeSet::new();
        let mut records=0_usize;
        for source in capability_catalogs{
            let data=source.content();
            if data.scope_id != target.content().scope_id {
                return Err(problem(DiagnosticCode::InvalidReference,"plan_catalog_scope",
                    "capability source cannot inherit facts across tenants"));
            }
            if !seen.insert(data.catalog_id.as_str()){
                return Err(problem(DiagnosticCode::DuplicateRecord,"plan_catalog_id",
                    "capability catalog IDs must be unique within a plan"));
            }
            records=limits.checked_add(ResourceKind::EvidenceRecords,records,data.records.len())?;
            for record in &data.records {
                if record.scope_id!=wb.scope_id {
                    return Err(problem(DiagnosticCode::InvalidReference,"plan_record_scope",
                        "capability record has mismatched deployment scope"));
                }
                if record.evidence.observed_at_unix_secs>now{
                    return Err(problem(DiagnosticCode::InvalidStateTransition,
                        "plan_capability_future","future observation cannot be used as present evidence"));
                }
                if record.evidence.expires_at_unix_secs.is_some_and(|expiry|now>=expiry) {
                    return Err(problem(DiagnosticCode::StaleCriticalProfile,
                        "plan_capability_expiry","an externally claimed capability observation expired"));
                }
            }
            catalogs.push(PlanCatalogPin{
                catalog_id:data.catalog_id.clone(),revision:data.revision,digest:source.digest(),
            });
        }
        catalogs.sort_by(|a,b|a.catalog_id.cmp(&b.catalog_id));
        let mut writer=Encoder::new(limits);
        writer.raw(b"CSHIFT_CATALOG_SET_D3_V1")?;
        writer.count(catalogs.len())?;
        for catalog in &catalogs{
            writer.string(&catalog.catalog_id)?;
            writer.u32(catalog.revision)?;
            writer.digest(catalog.digest)?;
        }
        let catalog_set_digest=SnapshotDigest::hash(&writer.finish());
        let scoring=score.map(|p| -> Result<PlanScorePin,Diagnostic> {
            Ok(PlanScorePin{
                profile_id:p.id().to_owned(),version:p.version(),
                digest:Self::scoring_digest(p,limits)?,
            })
        }).transpose()?;
        limits.check(ResourceKind::ProfileReferences,target.content().standards.len())?;
        Ok(PlanSourcePins{
            scope_id:wb.scope_id.clone(),
            evaluated_at_unix_secs:now,
            wave_digest:wave.digest(),
            remediation_digest:remediation.digest(),
            compatibility_set_digest:wb.compatibility_set_digest,
            inventory_digest:b.inventory_digest,
            graph_digest:b.graph_digest,
            topology_digest:b.topology_digest,
            target_digest:b.target_digest,
            risk_digest:b.risk_digest,
            standards_catalog_version:STANDARDS_CATALOG_VERSION,
            standards:target.content().standards.clone(),
            catalogs,catalog_set_digest,scoring,
        })
    }

    /// Build a complete, nonexecuting plan with all residual risks retained.
    ///
    /// No source pin, exception request or signed-looking receipt automatically
    /// discharges one D1/D2 gate or upgrades a unit to operational Ready.
    pub fn build(
        topology:&DependencyTopology,
        remediation:&RemediationAnalysis,
        wave:&WavePlanDraft,
        target:&TargetProfile,
        capability_catalogs:&[&CapabilityCatalog],
        score:Option<&ScoreProfile>,
        request:&MigrationPlanRequest,
        limits:&Limits,
    )->Result<MigrationPlanDraft,Diagnostic>{
        limits.validate()?;
        if request.schema_version!=MIGRATION_PLAN_VERSION{
            return Err(problem(DiagnosticCode::UnsupportedSchemaVersion,"migration_plan_version",
                "unsupported immutable MigrationPlan schema revision"));
        }
        limits.check(ResourceKind::ProfileReferences,request.exceptions.len())?;
        limits.check(ResourceKind::GraphNodes,wave.readiness().len())?;
        limits.check(ResourceKind::PlanWaves,wave.waves().len())?;
        limits.check(ResourceKind::PlanActions,remediation.actions().len())?;
        limits.check(ResourceKind::Diagnostics,remediation.blockers().len())?;
        let current=Self::input_pins(topology,remediation,wave,target,capability_catalogs,score,limits)?;
        if request.expected_pins!=current{
            return Err(problem(DiagnosticCode::IntegrityMismatch,"migration_plan_replay",
                "supplied plan pins do not match exact D1/D2/target/source versions"));
        }
        // Re-admit nested output sizes under this caller's active work budget,
        // including SCC members hidden by graph condensation.
        let mut member_count=0_usize;
        let mut work_count=0_usize;
        let mut evidence_count=0_usize;
        for item in wave.readiness(){
            member_count=limits.checked_add(ResourceKind::GraphNodes,member_count,item.system_ids.len())?;
            work_count=limits.checked_add(ResourceKind::PlannerCandidates,work_count,item.gates.len())?;
            for gate in &item.gates{
                evidence_count=limits.checked_add(ResourceKind::EvidenceRecords,evidence_count,gate.evidence.len())?;
            }
        }
        for cap in capability_catalogs{
            evidence_count=limits.checked_add(ResourceKind::EvidenceRecords,evidence_count,cap.content().records.len())?;
        }
        work_count=limits.checked_add(ResourceKind::PlannerCandidates,work_count,request.exceptions.len())?;
        work_count=limits.checked_add(ResourceKind::PlannerCandidates,work_count,remediation.actions().len())?;
        limits.check(ResourceKind::EvidenceRecords,evidence_count)?;
        limits.check(ResourceKind::PlanActions,work_count)?;

        let owners:BTreeMap<&str,&RemediationOwner>=remediation.actions().iter()
            .filter(|a|a.kind==crate::RemediationActionKind::ReviewUnitGate)
            .map(|a|(a.unit_id.as_str(),&a.owner)).collect();
        let known_units:BTreeSet<&str>=wave.readiness().iter().map(|r|r.unit_id.as_str()).collect();
        let now=current.evaluated_at_unix_secs;
        let known_constraints:BTreeSet<&str>=target.content().algorithms.iter()
            .map(|c|c.algorithm.id())
            .chain(target.content().protocols.iter().map(|c|c.protocol_id.as_str()))
            .chain(target.content().certificates.iter().map(|c|c.profile_id.as_str()))
            .collect();
        let mut seen_exceptions=BTreeSet::new();
        let mut input_bytes=0_usize;
        let mut exceptions=Vec::with_capacity(request.exceptions.len());
        for entry in &request.exceptions {
            for value in [
                &entry.request_id,&entry.scope_id,&entry.unit_id,
                &entry.target_constraint_id,&entry.requester_source_id,&entry.justification_reference
            ] {
                validate_reference(value)?;
                input_bytes=limits.checked_add(ResourceKind::InputBytes,input_bytes,value.len())?;
            }
            if entry.scope_id!=current.scope_id || !known_units.contains(entry.unit_id.as_str())
                || !known_constraints.contains(entry.target_constraint_id.as_str())
            {
                return Err(problem(DiagnosticCode::InvalidReference,"plan_exception_scope",
                    "exception request must name an existing tenant, SCC and target constraint"));
            }
            if !seen_exceptions.insert(entry.request_id.as_str()){
                return Err(problem(DiagnosticCode::DuplicateRecord,"plan_exception_id",
                    "exception record ID cannot repeat within a plan"));
            }
            match owners.get(entry.unit_id.as_str()){
                Some(RemediationOwner::Claimed(owner)) if owner==&entry.requester_source_id => {},
                _ => return Err(problem(DiagnosticCode::InvalidReference,"plan_exception_owner",
                    "exception requester must match a unique D1 owner claim")),
            }
            if entry.requested_at_unix_secs>now
                || entry.expires_at_unix_secs<=entry.requested_at_unix_secs
            {
                return Err(problem(DiagnosticCode::InvalidStateTransition,"plan_exception_time",
                    "exception request must have a valid source-defined time interval"));
            }
            if let Some(claim)=&entry.claimed_approval{
                for value in [&claim.issuer_id,&claim.receipt_reference,&claim.source_revision]{
                    validate_reference(value)?;
                    input_bytes=limits.checked_add(ResourceKind::InputBytes,input_bytes,value.len())?;
                }
                if claim.issuer_id==entry.requester_source_id
                    || claim.observed_at_unix_secs<entry.requested_at_unix_secs
                    || claim.observed_at_unix_secs>now
                {
                    return Err(problem(DiagnosticCode::InvalidStateTransition,"plan_exception_claim",
                        "exception claim must be separately sourced and temporally consistent"));
                }
            }
            let state=if now>=entry.expires_at_unix_secs{
                PlanExceptionState::Expired
            } else if entry.claimed_approval.is_some(){
                PlanExceptionState::ClaimedApprovalUnverified
            } else {
                PlanExceptionState::Requested
            };
            exceptions.push(PlanExceptionRecord{request:entry.clone(),state});
        }
        exceptions.sort_by(|a,b|a.request.request_id.cmp(&b.request.request_id));

        let blockers:BTreeMap<&str,&BlockerFinding>=remediation.blockers().iter()
            .map(|b|(b.id.as_str(),b)).collect();
        let mut facets=Vec::new();
        for unit in wave.readiness(){
            for gate in &unit.gates{
                let blocker=gate.blocker_id.as_deref()
                    .map(|id|blockers.get(id).copied().ok_or_else(||problem(
                        DiagnosticCode::InvalidReference,"plan_source_blocker",
                        "D2 references an absent D1 blocker"))).transpose()?;
                if blocker.is_some_and(|b|b.unit_id!=unit.unit_id){
                    return Err(problem(DiagnosticCode::InvalidReference,"plan_blocker_unit",
                        "D2 gate cannot borrow a blocker from another SCC"));
                }
                let kind=classify_gate(gate.kind,blocker);
                let refs:Vec<_>=gate.evidence.iter().cloned()
                    .map(PlanEvidenceRef::Remediation).collect();
                facets.push(ResidualRiskFacet{
                    id:String::new(),unit_id:Some(unit.unit_id.clone()),
                    kind,blocker_id:gate.blocker_id.clone(),
                    action_id:gate.action_id.clone(),
                    prerequisite_unit_id:gate.upstream_unit_id.clone(),
                    evidence:refs,validation_gates:gate.validations.clone(),
                    due_at_unix_secs:unit.due_at_unix_secs,
                });
            }
        }
        if capability_catalogs.is_empty(){
            facets.push(ResidualRiskFacet{
                id:String::new(),unit_id:None,kind:ResidualRiskKind::MissingCapabilityEvidence,
                blocker_id:None,action_id:None,prerequisite_unit_id:None,
                evidence:vec![],validation_gates:vec![RemediationGate::VerifyProvider],
                due_at_unix_secs:None,
            });
        }else{
            for catalog in capability_catalogs{
                for record in &catalog.content().records{
                    facets.push(ResidualRiskFacet{
                        id:String::new(),unit_id:None,kind:ResidualRiskKind::VendorCapability,
                        blocker_id:None,action_id:None,prerequisite_unit_id:None,
                        evidence:vec![PlanEvidenceRef::Capability{
                            source_id:record.evidence.source_id.clone(),
                            evidence_id:record.evidence.evidence_id.clone(),
                            source_revision:record.evidence.source_revision.clone(),
                        }],
                        validation_gates:vec![RemediationGate::VerifyProvider],
                        due_at_unix_secs:None,
                    });
                }
            }
        }
        for exception in &exceptions{
            let mut refs=vec![PlanEvidenceRef::Exception{
                source_id:exception.request.requester_source_id.clone(),
                reference_id:exception.request.justification_reference.clone(),
                revision:String::new(), // no source revision was provided
            }];
            if let Some(claim)=&exception.request.claimed_approval{
                refs.push(PlanEvidenceRef::Exception{
                    source_id:claim.issuer_id.clone(),
                    reference_id:claim.receipt_reference.clone(),
                    revision:claim.source_revision.clone(),
                });
            }
            facets.push(ResidualRiskFacet{
                id:String::new(),unit_id:Some(exception.request.unit_id.clone()),
                kind:ResidualRiskKind::ExceptionUnverified,
                blocker_id:None,action_id:None,prerequisite_unit_id:None,
                evidence:refs,
                validation_gates:vec![RemediationGate::ApprovePolicyAlternative],
                due_at_unix_secs:Some(exception.request.expires_at_unix_secs),
            });
        }
        limits.check(ResourceKind::Diagnostics,facets.len())?;
        limits.check(ResourceKind::PlanActions,facets.len())?;
        // Domain-separated per-facet identifiers bind all original revisions.
        for facet in &mut facets{
            facet.evidence.sort();
            facet.validation_gates.sort();
            let mut writer=Encoder::new(limits);
            writer.raw(b"CSHIFT_RESIDUAL_FACET_D3_V1")?;
            writer.digest(current.wave_digest)?;
            writer.digest(current.remediation_digest)?;
            writer.digest(current.compatibility_set_digest)?;
            writer.facet(facet)?;
            facet.id=SnapshotDigest::hash(&writer.finish()).as_identifier();
        }
        facets.sort_by(|a,b|(&a.unit_id,a.kind,&a.blocker_id,&a.action_id,
            &a.prerequisite_unit_id,&a.id)
            .cmp(&(&b.unit_id,b.kind,&b.blocker_id,&b.action_id,&b.prerequisite_unit_id,&b.id)));
        let status=if wave.readiness().iter().any(|u|u.status==UnitReadinessStatus::Blocked){
            PlanAssessmentState::Blocked
        }else if wave.readiness().iter().any(|u|u.status==UnitReadinessStatus::Unverified)
            || facets.iter().any(|f|matches!(f.kind,
                ResidualRiskKind::MissingCapabilityEvidence|ResidualRiskKind::VendorCapability
                |ResidualRiskKind::ExceptionUnverified))
        {
            PlanAssessmentState::Partial
        }else if wave.readiness().iter().any(|u|u.status==UnitReadinessStatus::AwaitingExternalApproval){
            PlanAssessmentState::ExternalApprovalPending
        }else{
            PlanAssessmentState::CompleteEvidenceForReview
        };
        let mut blocker_ids:Vec<String>=remediation.blockers().iter().map(|b|b.id.clone()).collect();
        blocker_ids.sort();
        let mut action_ids:Vec<String>=remediation.actions().iter().map(|a|a.id.clone()).collect();
        action_ids.sort();
        let mut writer=Encoder::new(limits);
        writer.raw(b"CSHIFT_MIGRATION_PLAN_V1")?;
        writer.u16(MIGRATION_PLAN_VERSION)?;
        writer.pins(&current)?;
        writer.u8(status as u8)?;
        writer.count(wave.waves().len())?;
        for stage in wave.waves(){writer.wave(stage)?;}
        writer.count(wave.readiness().len())?;
        for readiness in wave.readiness(){writer.readiness(readiness)?;}
        writer.strings(&blocker_ids)?;
        writer.strings(&action_ids)?;
        writer.count(facets.len())?;
        for facet in &facets{writer.facet(facet)?;}
        writer.count(exceptions.len())?;
        for entry in &exceptions{writer.exception(entry)?;}
        let canonical=writer.finish();
        let digest=SnapshotDigest::hash(&canonical);
        Ok(MigrationPlanDraft{
            pins:current,status,waves:wave.waves().to_vec(),
            readiness:wave.readiness().to_vec(),blockers:blocker_ids,actions:action_ids,
            residual_risks:facets,exceptions,canonical,digest,
        })
    }
}

fn validate_reference(value:&str)->Result<(),Diagnostic>{
    if value.is_empty() || value.len()>256 || value.trim()!=value
        || value.chars().any(char::is_control) {
        return Err(problem(DiagnosticCode::InvalidIdentifier,"plan_external_reference",
            "a bounded source identifier must be present without control characters"));
    }
    Ok(())
}

fn classify_gate(kind:ReadinessGateKind,blocker:Option<&BlockerFinding>)->ResidualRiskKind{
    if let Some(blocker)=blocker{
        if blocker.severity==BlockerSeverity::HardPolicy{
            return ResidualRiskKind::PolicyConstraint;
        }
        if blocker.required_gates.contains(&RemediationGate::ValidatePki){
            return ResidualRiskKind::PkiTrust;
        }
        if blocker.required_gates.contains(&RemediationGate::AuthenticatePeer)
            || blocker.required_gates.contains(&RemediationGate::VerifyHybrid){
            return ResidualRiskKind::PeerProtocol;
        }
        if blocker.required_gates.contains(&RemediationGate::VerifyProvider){
            return ResidualRiskKind::VendorCapability;
        }
        return match blocker.code{
            BlockerCode::OwnerMissing|BlockerCode::OwnerAmbiguous=>ResidualRiskKind::Ownership,
            BlockerCode::RiskUnresolved(RiskFactorKind::QuantumExposure)
            |BlockerCode::RiskElevated(RiskFactorKind::QuantumExposure)
            |BlockerCode::RiskUnresolved(_)|BlockerCode::RiskElevated(_)
                =>ResidualRiskKind::QuantumOrContextRisk,
            BlockerCode::DependencyGate=>ResidualRiskKind::Dependency,
            BlockerCode::DeadlinePassed=>ResidualRiskKind::Deadline,
            BlockerCode::PeerProofUnverified|BlockerCode::PeerCompatibilityMissing
            |BlockerCode::Compatibility(_)|BlockerCode::CompatibilityGate(_)
                =>ResidualRiskKind::EvidenceQuality,
        };
    }
    match kind {
        ReadinessGateKind::UnresolvedBlocker|ReadinessGateKind::ActionValidation
            =>ResidualRiskKind::EvidenceQuality,
        ReadinessGateKind::UpstreamUnitApproval=>ResidualRiskKind::Dependency,
        ReadinessGateKind::IndependentUnitReview=>ResidualRiskKind::UnitReview,
        ReadinessGateKind::ChangeApproval=>ResidualRiskKind::ChangeApproval,
        ReadinessGateKind::MaintenanceWindow=>ResidualRiskKind::Maintenance,
        ReadinessGateKind::RollbackPlan=>ResidualRiskKind::Rollback,
    }
}

fn problem(code:DiagnosticCode,subject:&'static str,reason:&'static str)->Diagnostic{
    Diagnostic::new(code,subject,reason)
}


/// Stable categories of meaningful differences between immutable plans.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PlanChangeKind {
    /// Tenant/scope changed; never consider plans interchangeable.
    Scope = 1,
    /// Inventory source revision changed.
    Inventory = 2,
    /// Typed graph revision changed.
    Graph = 3,
    /// SCC decomposition or prerequisite topology changed.
    Topology = 4,
    /// Full risk-factor content changed.
    Risk = 5,
    /// Desired target/policy revision changed.
    Target = 6,
    /// D1 remediation report revision changed.
    Remediation = 7,
    /// Peer protocol, PKI or vendor compatibility evidence set changed.
    CompatibilityEvidence = 8,
    /// Candidate D2 wave content changed.
    WavePlan = 9,
    /// Standards catalog edition or set changed.
    Standards = 10,
    /// Capability catalog identity/revision/evidence changed.
    Capabilities = 11,
    /// Optional scoring contract identity/weights changed.
    Scoring = 12,
    /// Overall nonauthoritative review state changed.
    Assessment = 13,
    /// Wave placements, capacity or prerequisites changed.
    WaveStructure = 14,
    /// Source-qualified per-unit review status or gates changed.
    UnitReadiness = 15,
    /// D1 blocker identities were added, removed or revised.
    Blockers = 16,
    /// D1 action identities were added, removed or revised.
    Actions = 17,
    /// One or more residual-risk facets changed.
    ResidualRisk = 18,
    /// Exception claim, scope, expiry or state changed.
    Exceptions = 19,
    /// Explicit analysis timestamp changed.
    EvaluationTime = 20,
}

/// Deterministic comparison of two immutable plan drafts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanDiff {
    /// Sorted typed change categories; empty means semantically identical.
    pub changes: Vec<PlanChangeKind>,
    /// Changed or missing SCC unit records, sorted and unique.
    pub changed_unit_ids: Vec<String>,
    /// Changed D1 blocker identity membership.
    pub changed_blocker_ids: Vec<String>,
    /// Changed D1 action identity membership.
    pub changed_action_ids: Vec<String>,
    /// Updated, removed or new exception request IDs.
    pub changed_exception_ids: Vec<String>,
    /// Source-fenced residual facet identities differing between plans.
    pub changed_residual_ids: Vec<String>,
}

impl MigrationPlanDraft {
    /// Compare typed semantic content instead of trusting opaque record IDs.
    ///
    /// A change in any input content digest is material even where no
    /// display-level unit state or label changed.
    pub fn semantic_diff(&self,next:&Self,limits:&Limits)->Result<PlanDiff,Diagnostic>{
        limits.validate()?;
        let budget=limits.checked_add(ResourceKind::PlannerCandidates,
            self.readiness.len(),next.readiness.len())?;
        let budget=limits.checked_add(ResourceKind::PlannerCandidates,
            budget,self.residual_risks.len())?;
        let budget=limits.checked_add(ResourceKind::PlannerCandidates,
            budget,next.residual_risks.len())?;
        limits.checked_add(ResourceKind::PlannerCandidates,budget,
            self.exceptions.len()+next.exceptions.len())?;
        let mut changes=BTreeSet::new();
        let a=&self.pins;
        let b=&next.pins;
        if a.scope_id!=b.scope_id {changes.insert(PlanChangeKind::Scope);}
        if a.evaluated_at_unix_secs!=b.evaluated_at_unix_secs{
            changes.insert(PlanChangeKind::EvaluationTime);
        }
        for (kind,left,right) in [
            (PlanChangeKind::Inventory,a.inventory_digest,b.inventory_digest),
            (PlanChangeKind::Graph,a.graph_digest,b.graph_digest),
            (PlanChangeKind::Topology,a.topology_digest,b.topology_digest),
            (PlanChangeKind::Risk,a.risk_digest,b.risk_digest),
            (PlanChangeKind::Target,a.target_digest,b.target_digest),
            (PlanChangeKind::Remediation,a.remediation_digest,b.remediation_digest),
            (PlanChangeKind::CompatibilityEvidence,
                a.compatibility_set_digest,b.compatibility_set_digest),
            (PlanChangeKind::WavePlan,a.wave_digest,b.wave_digest),
            (PlanChangeKind::Capabilities,a.catalog_set_digest,b.catalog_set_digest),
        ]{
            if left!=right{changes.insert(kind);}
        }
        if a.standards_catalog_version!=b.standards_catalog_version
            || a.standards!=b.standards{
            changes.insert(PlanChangeKind::Standards);
        }
        if a.catalogs!=b.catalogs{changes.insert(PlanChangeKind::Capabilities);}
        if a.scoring!=b.scoring{changes.insert(PlanChangeKind::Scoring);}
        if self.status!=next.status{changes.insert(PlanChangeKind::Assessment);}
        if self.waves!=next.waves{changes.insert(PlanChangeKind::WaveStructure);}

        let mut changed_units=Vec::new();
        let before_units:BTreeMap<&str,&UnitReadiness>=self.readiness.iter()
            .map(|u|(u.unit_id.as_str(),u)).collect();
        let after_units:BTreeMap<&str,&UnitReadiness>=next.readiness.iter()
            .map(|u|(u.unit_id.as_str(),u)).collect();
        let unit_keys:BTreeSet<&str>=before_units.keys().chain(after_units.keys()).copied().collect();
        for id in unit_keys{
            if before_units.get(id)!=after_units.get(id){changed_units.push(id.to_owned());}
        }
        if !changed_units.is_empty(){changes.insert(PlanChangeKind::UnitReadiness);}
        let blocker_ids=symmetric_ids(&self.blockers,&next.blockers);
        if !blocker_ids.is_empty(){changes.insert(PlanChangeKind::Blockers);}
        let action_ids=symmetric_ids(&self.actions,&next.actions);
        if !action_ids.is_empty(){changes.insert(PlanChangeKind::Actions);}
        let before_facets:BTreeSet<&str>=self.residual_risks.iter().map(|f|f.id.as_str()).collect();
        let after_facets:BTreeSet<&str>=next.residual_risks.iter().map(|f|f.id.as_str()).collect();
        let residual_ids:Vec<String>=before_facets.symmetric_difference(&after_facets)
            .map(|id|(*id).to_owned()).collect();
        if !residual_ids.is_empty(){changes.insert(PlanChangeKind::ResidualRisk);}
        let before_ex:BTreeMap<&str,&PlanExceptionRecord>=self.exceptions.iter()
            .map(|e|(e.request.request_id.as_str(),e)).collect();
        let after_ex:BTreeMap<&str,&PlanExceptionRecord>=next.exceptions.iter()
            .map(|e|(e.request.request_id.as_str(),e)).collect();
        let ex_ids:BTreeSet<&str>=before_ex.keys().chain(after_ex.keys()).copied().collect();
        let changed_exception_ids:Vec<String>=ex_ids.into_iter()
            .filter(|id|before_ex.get(id)!=after_ex.get(id))
            .map(str::to_owned).collect();
        if !changed_exception_ids.is_empty(){changes.insert(PlanChangeKind::Exceptions);}
        let total=changed_units.len()+blocker_ids.len()+action_ids.len()
            +residual_ids.len()+changed_exception_ids.len();
        limits.check(ResourceKind::Diagnostics,total)?;
        Ok(PlanDiff{
            changes:changes.into_iter().collect(),
            changed_unit_ids:changed_units,changed_blocker_ids:blocker_ids,
            changed_action_ids:action_ids,changed_exception_ids,
            changed_residual_ids:residual_ids,
        })
    }
}

fn symmetric_ids(a:&[String],b:&[String])->Vec<String>{
    let a:BTreeSet<&str>=a.iter().map(String::as_str).collect();
    let b:BTreeSet<&str>=b.iter().map(String::as_str).collect();
    a.symmetric_difference(&b).map(|id|(*id).to_owned()).collect()
}
