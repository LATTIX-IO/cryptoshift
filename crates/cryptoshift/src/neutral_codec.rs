//! Deterministic, checked framing shared by fixture-based neutral adapters.
//!
//! Bytes and digests are content identities, not producer signatures.

use sha2::{Digest, Sha256};

use crate::{Diagnostic, DiagnosticCode, Limits, ResourceKind, SnapshotDigest};

pub(crate) struct NeutralWriter<'a> {
    bytes: Vec<u8>,
    limits: &'a Limits,
}

impl<'a> NeutralWriter<'a> {
    pub(crate) fn new(tag: &[u8], limits: &'a Limits) -> Result<Self, Diagnostic> {
        limits.validate()?;
        let mut writer = Self {
            bytes: Vec::new(),
            limits,
        };
        writer.raw(tag)?;
        Ok(writer)
    }

    pub(crate) fn raw(&mut self, data: &[u8]) -> Result<(), Diagnostic> {
        self.limits
            .checked_add(ResourceKind::ExportBytes, self.bytes.len(), data.len())?;
        self.bytes.extend_from_slice(data);
        Ok(())
    }

    pub(crate) fn u8(&mut self, value: u8) -> Result<(), Diagnostic> {
        self.raw(&[value])
    }

    pub(crate) fn u16(&mut self, value: u16) -> Result<(), Diagnostic> {
        self.raw(&value.to_be_bytes())
    }

    pub(crate) fn u32(&mut self, value: u32) -> Result<(), Diagnostic> {
        self.raw(&value.to_be_bytes())
    }

    pub(crate) fn i64(&mut self, value: i64) -> Result<(), Diagnostic> {
        self.raw(&value.to_be_bytes())
    }

    pub(crate) fn count(&mut self, value: usize) -> Result<(), Diagnostic> {
        let encoded = u32::try_from(value).map_err(|_| {
            error(
                DiagnosticCode::ArithmeticOverflow,
                "neutral_count",
                "canonical collection length exceeds u32",
            )
        })?;
        self.u32(encoded)
    }

    pub(crate) fn string(&mut self, value: &str) -> Result<(), Diagnostic> {
        self.count(value.len())?;
        self.raw(value.as_bytes())
    }

    pub(crate) fn digest(&mut self, digest: SnapshotDigest) -> Result<(), Diagnostic> {
        self.raw(&digest.as_bytes())
    }

    pub(crate) fn strings(&mut self, values: &[String]) -> Result<(), Diagnostic> {
        self.count(values.len())?;
        for value in values {
            self.string(value)?;
        }
        Ok(())
    }

    /// All serialized bytes must also fit the caller's active import budget.
    pub(crate) fn finish(self) -> Result<(Vec<u8>, SnapshotDigest), Diagnostic> {
        self.limits
            .check(ResourceKind::InputBytes, self.bytes.len())?;
        let sum = Sha256::digest(&self.bytes);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&sum);
        Ok((self.bytes, SnapshotDigest::from_bytes(bytes)))
    }
}

pub(crate) fn identifier(value: &str, field: &'static str) -> Result<(), Diagnostic> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(error(
            DiagnosticCode::InvalidIdentifier,
            field,
            "neutral source identifier must be bounded and canonical",
        ));
    }
    Ok(())
}

pub(crate) fn error(
    code: DiagnosticCode,
    field: &'static str,
    reason: &'static str,
) -> Diagnostic {
    Diagnostic::new(code, field, reason)
}

pub(crate) fn expected(
    actual: SnapshotDigest,
    pinned: SnapshotDigest,
    field: &'static str,
) -> Result<(), Diagnostic> {
    if actual != pinned {
        Err(error(
            DiagnosticCode::IntegrityMismatch,
            field,
            "content differs from the independently pinned source version",
        ))
    } else {
        Ok(())
    }
}
