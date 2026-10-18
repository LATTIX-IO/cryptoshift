//! Bounded, tagged canonical D3 encoder. Never renders raw evidence payloads.

use super::*;

/// Fixed-width length-prefixed encoder with checked output budget.
pub(super) struct Encoder<'a> {
    limits: &'a Limits,
    bytes: Vec<u8>,
}

impl<'a> Encoder<'a> {
    pub(super) fn new(limits: &'a Limits) -> Self {
        Self {
            limits,
            bytes: Vec::new(),
        }
    }
    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }
    pub(super) fn raw(&mut self, bytes: &[u8]) -> Result<(), Diagnostic> {
        self.limits
            .checked_add(ResourceKind::ExportBytes, self.bytes.len(), bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub(super) fn u8(&mut self, value: u8) -> Result<(), Diagnostic> {
        self.raw(&[value])
    }
    pub(super) fn bool(&mut self, value: bool) -> Result<(), Diagnostic> {
        self.u8(u8::from(value))
    }
    pub(super) fn u16(&mut self, value: u16) -> Result<(), Diagnostic> {
        self.raw(&value.to_be_bytes())
    }
    pub(super) fn u32(&mut self, value: u32) -> Result<(), Diagnostic> {
        self.raw(&value.to_be_bytes())
    }
    pub(super) fn i64(&mut self, value: i64) -> Result<(), Diagnostic> {
        self.raw(&value.to_be_bytes())
    }
    pub(super) fn digest(&mut self, value: SnapshotDigest) -> Result<(), Diagnostic> {
        self.raw(&value.as_bytes())
    }
    pub(super) fn count(&mut self, value: usize) -> Result<(), Diagnostic> {
        self.u32(u32::try_from(value).map_err(|_| {
            problem(
                DiagnosticCode::ArithmeticOverflow,
                "migration_plan_count",
                "canonical collection length exceeds u32",
            )
        })?)
    }
    pub(super) fn string(&mut self, value: &str) -> Result<(), Diagnostic> {
        self.count(value.len())?;
        self.raw(value.as_bytes())
    }
    pub(super) fn strings(&mut self, values: &[String]) -> Result<(), Diagnostic> {
        self.count(values.len())?;
        for item in values {
            self.string(item)?;
        }
        Ok(())
    }
    pub(super) fn optional_string(&mut self, item: &Option<String>) -> Result<(), Diagnostic> {
        self.bool(item.is_some())?;
        if let Some(s) = item {
            self.string(s)?;
        }
        Ok(())
    }
    pub(super) fn optional_time(&mut self, item: Option<i64>) -> Result<(), Diagnostic> {
        self.bool(item.is_some())?;
        if let Some(t) = item {
            self.i64(t)?;
        }
        Ok(())
    }
    pub(super) fn pins(&mut self, value: &PlanSourcePins) -> Result<(), Diagnostic> {
        self.string(&value.scope_id)?;
        self.i64(value.evaluated_at_unix_secs)?;
        for digest in [
            value.wave_digest,
            value.remediation_digest,
            value.compatibility_set_digest,
            value.inventory_digest,
            value.graph_digest,
            value.topology_digest,
            value.target_digest,
            value.risk_digest,
            value.catalog_set_digest,
        ] {
            self.digest(digest)?;
        }
        self.u16(value.standards_catalog_version)?;
        self.count(value.standards.len())?;
        for edition in &value.standards {
            self.string(edition.id())?;
        }
        self.count(value.catalogs.len())?;
        for catalog in &value.catalogs {
            self.string(&catalog.catalog_id)?;
            self.u32(catalog.revision)?;
            self.digest(catalog.digest)?;
        }
        self.bool(value.scoring.is_some())?;
        if let Some(score) = &value.scoring {
            self.string(&score.profile_id)?;
            self.u16(score.version)?;
            self.digest(score.digest)?;
        }
        Ok(())
    }
    fn remediation_evidence(&mut self, value: &RemediationEvidence) -> Result<(), Diagnostic> {
        match value {
            RemediationEvidence::Inventory {
                source_id,
                run_id,
                evidence_id,
            } => {
                self.u8(1)?;
                for item in [source_id, run_id, evidence_id] {
                    self.string(item)?;
                }
            }
            RemediationEvidence::Compatibility {
                source_id,
                evidence_id,
                source_revision,
            } => {
                self.u8(2)?;
                for item in [source_id, evidence_id, source_revision] {
                    self.string(item)?;
                }
            }
            RemediationEvidence::RiskAssessment { reference_id } => {
                self.u8(3)?;
                self.string(reference_id)?;
            }
            RemediationEvidence::TargetDocument {
                issuer_id,
                document_id,
                source_revision,
            } => {
                self.u8(4)?;
                for item in [issuer_id, document_id, source_revision] {
                    self.string(item)?;
                }
            }
            RemediationEvidence::TargetDeadline { reference_id } => {
                self.u8(5)?;
                self.string(reference_id)?;
            }
        }
        Ok(())
    }
    fn plan_evidence(&mut self, value: &PlanEvidenceRef) -> Result<(), Diagnostic> {
        match value {
            PlanEvidenceRef::Remediation(e) => {
                self.u8(1)?;
                self.remediation_evidence(e)?;
            }
            PlanEvidenceRef::Capability {
                source_id,
                evidence_id,
                source_revision,
            } => {
                self.u8(2)?;
                for item in [source_id, evidence_id, source_revision] {
                    self.string(item)?;
                }
            }
            PlanEvidenceRef::Exception {
                source_id,
                reference_id,
                revision,
            } => {
                self.u8(3)?;
                for item in [source_id, reference_id, revision] {
                    self.string(item)?;
                }
            }
        }
        Ok(())
    }
    fn owner(&mut self, value: &RemediationOwner) -> Result<(), Diagnostic> {
        match value {
            RemediationOwner::Missing => self.u8(1)?,
            RemediationOwner::Claimed(id) => {
                self.u8(2)?;
                self.string(id)?;
            }
            RemediationOwner::Ambiguous(ids) => {
                self.u8(3)?;
                self.strings(ids)?;
            }
        }
        Ok(())
    }
    pub(super) fn wave(&mut self, value: &crate::MigrationWave) -> Result<(), Diagnostic> {
        self.count(value.number)?;
        self.strings(&value.unit_ids)?;
        self.count(value.occupied_system_slots)
    }
    pub(super) fn readiness(&mut self, value: &UnitReadiness) -> Result<(), Diagnostic> {
        self.string(&value.unit_id)?;
        self.strings(&value.system_ids)?;
        self.count(value.wave_number)?;
        self.u8(value.status as u8)?;
        self.strings(&value.prerequisite_unit_ids)?;
        self.strings(&value.blocker_ids)?;
        self.strings(&value.action_ids)?;
        self.owner(&value.owner)?;
        self.optional_time(value.due_at_unix_secs)?;
        self.count(value.gates.len())?;
        for gate in &value.gates {
            self.u8(gate.kind as u8)?;
            self.optional_string(&gate.blocker_id)?;
            self.optional_string(&gate.action_id)?;
            self.optional_string(&gate.upstream_unit_id)?;
            self.count(gate.evidence.len())?;
            for item in &gate.evidence {
                self.remediation_evidence(item)?;
            }
            self.count(gate.validations.len())?;
            for kind in &gate.validations {
                self.u8(*kind as u8)?;
            }
        }
        Ok(())
    }
    pub(super) fn facet(&mut self, value: &ResidualRiskFacet) -> Result<(), Diagnostic> {
        self.string(&value.id)?;
        self.optional_string(&value.unit_id)?;
        self.bool(value.subject.is_some())?;
        if let Some(subject) = &value.subject {
            match subject {
                PlanFacetSubject::Capability { catalog_id, record_id } => {
                    self.u8(1)?;
                    self.string(catalog_id)?;
                    self.string(record_id)?;
                }
                PlanFacetSubject::Exception { request_id, target_constraint_id } => {
                    self.u8(2)?;
                    self.string(request_id)?;
                    self.string(target_constraint_id)?;
                }
            }
        }
        self.u8(value.kind as u8)?;
        self.optional_string(&value.blocker_id)?;
        self.optional_string(&value.action_id)?;
        self.optional_string(&value.prerequisite_unit_id)?;
        self.count(value.evidence.len())?;
        for item in &value.evidence {
            self.plan_evidence(item)?;
        }
        self.count(value.validation_gates.len())?;
        for gate in &value.validation_gates {
            self.u8(*gate as u8)?;
        }
        self.optional_time(value.due_at_unix_secs)
    }
    pub(super) fn exception(&mut self, value: &PlanExceptionRecord) -> Result<(), Diagnostic> {
        let r = &value.request;
        self.string(&r.request_id)?;
        self.string(&r.scope_id)?;
        self.string(&r.unit_id)?;
        self.string(&r.target_constraint_id)?;
        self.string(&r.requester_source_id)?;
        self.string(&r.justification_reference)?;
        self.i64(r.requested_at_unix_secs)?;
        self.i64(r.expires_at_unix_secs)?;
        self.bool(r.claimed_approval.is_some())?;
        if let Some(claim) = &r.claimed_approval {
            self.string(&claim.issuer_id)?;
            self.string(&claim.receipt_reference)?;
            self.string(&claim.source_revision)?;
            self.i64(claim.observed_at_unix_secs)?;
        }
        self.u8(value.state as u8)
    }
}
