//! Unique, bounded, explicitly versioned binary encoding for inventory snapshots.
//! This is a Cryptoshift-local contract until Cryptomap shift v1 is standardized.

use crate::inventory::{
    AbsenceRecord, AbsenceStatus, CollectionCompleteness, CollectionRun, ConflictState,
    CryptoObservation, CryptoUseKind, EvidenceBasis, EvidenceRecord, InventorySnapshot, problem,
};
use crate::{Diagnostic, DiagnosticCode, Limits, ParseBudget, ResourceKind};

const MAGIC: &[u8; 8] = b"CSHIFT01";

struct Writer {
    data: Vec<u8>,
    limits: Limits,
}

impl Writer {
    fn new(limits: Limits) -> Self {
        Self {
            data: Vec::new(),
            limits,
        }
    }

    fn put(&mut self, value: &[u8]) -> Result<(), Diagnostic> {
        self.limits
            .checked_add(ResourceKind::ExportBytes, self.data.len(), value.len())?;
        self.data.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), Diagnostic> {
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

    fn size(&mut self, value: usize) -> Result<(), Diagnostic> {
        let as_u32 = u32::try_from(value).map_err(|_| {
            problem(
                DiagnosticCode::ArithmeticOverflow,
                "inventory_count",
                "canonical field count cannot fit u32",
            )
        })?;
        self.u32(as_u32)
    }

    fn string(&mut self, value: &str) -> Result<(), Diagnostic> {
        let len = u16::try_from(value.len()).map_err(|_| {
            problem(
                DiagnosticCode::ResourceLimitExceeded,
                "inventory_string",
                "canonical identifier exceeds u16 byte limit",
            )
        })?;
        self.u16(len)?;
        self.put(value.as_bytes())
    }
}

pub(crate) fn encode(input: &InventorySnapshot, limits: &Limits) -> Result<Vec<u8>, Diagnostic> {
    limits.validate()?;
    let mut w = Writer::new(*limits);
    w.put(MAGIC)?;
    w.u16(1)?;
    w.u16(0)?;
    w.u16(input.identity_version)?;
    w.u16(input.normalization_version)?;
    w.string(&input.scope_id)?;
    w.size(input.runs.len())?;
    for run in &input.runs {
        w.string(&run.id)?;
        w.string(&run.source_id)?;
        w.string(&run.scope_id)?;
        w.i64(run.collected_at_unix_secs)?;
        w.u8(match run.completeness {
            CollectionCompleteness::Complete => 0,
            CollectionCompleteness::Partial => 1,
            CollectionCompleteness::Failed => 2,
        })?;
    }
    w.size(input.evidence.len())?;
    for e in &input.evidence {
        w.string(&e.id)?;
        w.string(&e.run_id)?;
        w.string(&e.source_id)?;
        w.u8(match e.basis {
            EvidenceBasis::Direct => 0,
            EvidenceBasis::Inferred => 1,
            EvidenceBasis::Unknown => 2,
        })?;
        w.u16(e.confidence_bps)?;
        w.i64(e.observed_at_unix_secs)?;
    }
    w.size(input.observations.len())?;
    for o in &input.observations {
        w.string(&o.id)?;
        w.string(&o.asset_id)?;
        w.string(&o.algorithm_id)?;
        w.u8(match o.kind {
            CryptoUseKind::ActiveUse => 0,
            CryptoUseKind::LibraryCapability => 1,
            CryptoUseKind::ConfiguredProtocol => 2,
            CryptoUseKind::NegotiatedProtocol => 3,
            CryptoUseKind::Unknown => 4,
        })?;
        w.u8(match o.conflict {
            ConflictState::Uncontested => 0,
            ConflictState::Conflicted => 1,
            ConflictState::Unresolved => 2,
        })?;
        w.size(o.evidence_ids.len())?;
        for id in &o.evidence_ids {
            w.string(id)?;
        }
    }
    w.size(input.absences.len())?;
    for absence in &input.absences {
        w.string(&absence.run_id)?;
        w.string(&absence.asset_id)?;
        w.u8(match absence.status {
            AbsenceStatus::Tentative => 0,
            AbsenceStatus::Confirmed => 1,
        })?;
    }
    Ok(w.data)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
    limits: &'a Limits,
    budget: ParseBudget,
    edge_references: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], limits: &'a Limits) -> Result<Self, Diagnostic> {
        limits.check(ResourceKind::InputBytes, bytes.len())?;
        Ok(Self {
            bytes,
            offset: 0,
            limits,
            budget: ParseBudget::new(*limits)?,
            edge_references: 0,
        })
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], Diagnostic> {
        let end = self.offset.checked_add(count).ok_or_else(malformed)?;
        let result = self.bytes.get(self.offset..end).ok_or_else(malformed)?;
        self.offset = end;
        Ok(result)
    }

    fn u8(&mut self) -> Result<u8, Diagnostic> {
        self.budget.record(2, 1)?;
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Diagnostic> {
        self.budget.record(2, 1)?;
        let mut bytes = [0_u8; 2];
        bytes.copy_from_slice(self.take(2)?);
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, Diagnostic> {
        self.budget.record(2, 1)?;
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_be_bytes(bytes))
    }

    fn i64(&mut self) -> Result<i64, Diagnostic> {
        self.budget.record(2, 1)?;
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(i64::from_be_bytes(bytes))
    }

    fn count(&mut self, resource: ResourceKind) -> Result<usize, Diagnostic> {
        let count = usize::try_from(self.u32()?).map_err(|_| malformed())?;
        self.limits.check(resource, count)?;
        self.budget.record(1, count)?;
        Ok(count)
    }

    fn string(&mut self) -> Result<String, Diagnostic> {
        let size = usize::from(self.u16()?);
        if size > 256 {
            return Err(problem(
                DiagnosticCode::ResourceLimitExceeded,
                "inventory_string",
                "identifier exceeds 256-byte bounded contract",
            ));
        }
        self.budget.record(2, 1)?;
        let slice = self.take(size)?;
        let str_value = std::str::from_utf8(slice).map_err(|_| malformed())?;
        Ok(str_value.to_owned())
    }

    fn edge_count(&mut self) -> Result<usize, Diagnostic> {
        let count = self.count(ResourceKind::GraphEdges)?;
        self.edge_references =
            self.limits
                .checked_add(ResourceKind::GraphEdges, self.edge_references, count)?;
        Ok(count)
    }

    fn complete(&self) -> Result<(), Diagnostic> {
        if self.offset != self.bytes.len() {
            return Err(malformed());
        }
        Ok(())
    }
}

fn malformed() -> Diagnostic {
    problem(
        DiagnosticCode::MalformedStructure,
        "inventory_bytes",
        "truncated, invalid, or unknown canonical inventory field",
    )
}

pub(crate) fn decode(bytes: &[u8], limits: &Limits) -> Result<InventorySnapshot, Diagnostic> {
    let mut r = Reader::new(bytes, limits)?;
    if r.take(MAGIC.len())? != MAGIC {
        return Err(malformed());
    }
    if r.u16()? != 1 || r.u16()? != 0 {
        return Err(problem(
            DiagnosticCode::UnsupportedSchemaVersion,
            "inventory_wire",
            "unsupported inventory wire format version",
        ));
    }
    let identity_version = r.u16()?;
    let normalization_version = r.u16()?;
    let scope_id = r.string()?;

    let mut runs = Vec::new();
    for _ in 0..r.count(ResourceKind::EvidenceRecords)? {
        let id = r.string()?;
        let source_id = r.string()?;
        let scope_id = r.string()?;
        let collected_at_unix_secs = r.i64()?;
        let completeness = match r.u8()? {
            0 => CollectionCompleteness::Complete,
            1 => CollectionCompleteness::Partial,
            2 => CollectionCompleteness::Failed,
            _ => return Err(malformed()),
        };
        runs.push(CollectionRun {
            id,
            source_id,
            scope_id,
            collected_at_unix_secs,
            completeness,
        });
    }

    let mut evidence = Vec::new();
    for _ in 0..r.count(ResourceKind::EvidenceRecords)? {
        let id = r.string()?;
        let run_id = r.string()?;
        let source_id = r.string()?;
        let basis = match r.u8()? {
            0 => EvidenceBasis::Direct,
            1 => EvidenceBasis::Inferred,
            2 => EvidenceBasis::Unknown,
            _ => return Err(malformed()),
        };
        let confidence_bps = r.u16()?;
        let observed_at_unix_secs = r.i64()?;
        evidence.push(EvidenceRecord {
            id,
            run_id,
            source_id,
            basis,
            confidence_bps,
            observed_at_unix_secs,
        });
    }

    let mut observations = Vec::new();
    for _ in 0..r.count(ResourceKind::GraphNodes)? {
        let id = r.string()?;
        let asset_id = r.string()?;
        let algorithm_id = r.string()?;
        let kind = match r.u8()? {
            0 => CryptoUseKind::ActiveUse,
            1 => CryptoUseKind::LibraryCapability,
            2 => CryptoUseKind::ConfiguredProtocol,
            3 => CryptoUseKind::NegotiatedProtocol,
            4 => CryptoUseKind::Unknown,
            _ => return Err(malformed()),
        };
        let conflict = match r.u8()? {
            0 => ConflictState::Uncontested,
            1 => ConflictState::Conflicted,
            2 => ConflictState::Unresolved,
            _ => return Err(malformed()),
        };
        let mut evidence_ids = Vec::new();
        for _ in 0..r.edge_count()? {
            evidence_ids.push(r.string()?);
        }
        observations.push(CryptoObservation {
            id,
            asset_id,
            algorithm_id,
            kind,
            conflict,
            evidence_ids,
        });
    }

    let mut absences = Vec::new();
    for _ in 0..r.count(ResourceKind::EvidenceRecords)? {
        let run_id = r.string()?;
        let asset_id = r.string()?;
        let status = match r.u8()? {
            0 => AbsenceStatus::Tentative,
            1 => AbsenceStatus::Confirmed,
            _ => return Err(malformed()),
        };
        absences.push(AbsenceRecord {
            run_id,
            asset_id,
            status,
        });
    }
    r.complete()?;
    Ok(InventorySnapshot {
        identity_version,
        normalization_version,
        scope_id,
        runs,
        evidence,
        observations,
        absences,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cumulative_edge_budget_rejects_second_list_before_allocation() -> Result<(), Diagnostic> {
        let limits = Limits {
            max_graph_edges: 2,
            ..Limits::default()
        };
        let bytes = [0_u8, 0, 0, 2, 0, 0, 0, 2];
        let mut reader = Reader::new(&bytes, &limits)?;
        assert_eq!(reader.edge_count()?, 2);
        assert_eq!(
            reader.edge_count().err().map(|e| e.code),
            Some(DiagnosticCode::ResourceLimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn scalar_parse_tokens_charge_budget_before_reading() -> Result<(), Diagnostic> {
        let limits = Limits {
            max_parse_tokens: 1,
            ..Limits::default()
        };
        let mut reader = Reader::new(&[7_u8, 8], &limits)?;
        assert_eq!(reader.u8()?, 7);
        assert_eq!(
            reader.u8().err().map(|e| e.code),
            Some(DiagnosticCode::ResourceLimitExceeded)
        );
        Ok(())
    }
}
