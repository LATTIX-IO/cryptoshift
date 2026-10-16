//! Versioned, bounded admission contract for untrusted external documents.
//!
//! This module validates the outer metadata and byte size only. The payload
//! remains unparsed; a later format adapter must parse it with matching limits
//! and verify its typed schema before using any domain facts.

use crate::diagnostic::{Diagnostic, DiagnosticCode};
use crate::limits::{Limits, ResourceKind};

/// Supported families of external or produced documents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SchemaKind {
    /// A cryptographic inventory snapshot supplied by discovery tooling.
    InventorySnapshot,
    /// Hard target constraints originating in organizational policy.
    TargetProfile,
    /// A versioned catalogue of externally sourced standards profiles.
    StandardsProfile,
    /// Product, library, and provider capability claims.
    CapabilityCatalog,
    /// A generated migration plan (must additionally satisfy plan validation).
    MigrationPlan,
}

impl SchemaKind {
    /// Non-sensitive identifier for metrics and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InventorySnapshot => "inventory_snapshot",
            Self::TargetProfile => "target_profile",
            Self::StandardsProfile => "standards_profile",
            Self::CapabilityCatalog => "capability_catalog",
            Self::MigrationPlan => "migration_plan",
        }
    }
}

/// Schema-version pair, distinct from cryptographic-standard revision numbers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaVersion {
    /// Breaking contract generation.
    pub major: u16,
    /// Compatible-in-principle, but not automatically accepted, contract revision.
    pub minor: u16,
}

impl SchemaVersion {
    /// The exact foundational outer-envelope contract supported in this increment.
    pub const V1_0: Self = Self { major: 1, minor: 0 };

    /// Test this revision against the explicitly implemented envelope contract.
    ///
    /// Until field-level compatibility rules exist, even a higher minor version
    /// is rejected. This avoids silently reinterpreting new critical fields.
    pub fn require_supported(self, kind: SchemaKind) -> Result<(), Diagnostic> {
        if self == Self::V1_0 {
            Ok(())
        } else {
            Err(Diagnostic::new(
                DiagnosticCode::UnsupportedSchemaVersion,
                kind.as_str(),
                "outer schema revision is not supported; explicit migration required",
            ))
        }
    }
}

/// Reference to a **critical** standards, capability, or target profile.
///
/// A string naming its source is provenance metadata, not a signature,
/// freshness attestation, or proof of deployed capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CriticalProfileReference<'a> {
    /// Stable profile reference, never echoed in diagnostics.
    pub id: &'a str,
    /// Profile family to which the reference belongs.
    pub kind: SchemaKind,
    /// Exact outer schema revision claimed by the profile.
    pub version: SchemaVersion,
    /// Nonempty source attribution; independently unverified.
    pub source_id: &'a str,
    /// Optional profile expiry as UTC seconds since the Unix epoch.
    pub expires_at_unix_secs: Option<i64>,
}

/// Untrusted document envelope supplied by an external format adapter.
///
/// Its header fields are **claims** and its payload is **not** parsed or
/// authenticated by this type. Call [`Self::preflight`] before any parser.
#[derive(Clone, Copy, Debug)]
pub struct VersionedEnvelope<'a> {
    /// Claimed payload family.
    pub schema: SchemaKind,
    /// Claimed outer schema revision.
    pub version: SchemaVersion,
    /// Raw bytes of an unparsed serialized payload.
    pub payload: &'a [u8],
    /// Required nonempty source attribution (not authenticity proof).
    pub source_id: &'a str,
    /// Required external profiles whose compatibility must not be assumed.
    pub critical_profiles: &'a [CriticalProfileReference<'a>],
}

/// Bounded envelope **metadata**, not a semantically validated domain document.
#[derive(Clone, Copy, Debug)]
pub struct PreflightedEnvelope<'a> {
    schema: SchemaKind,
    version: SchemaVersion,
    bytes: &'a [u8],
}

impl PreflightedEnvelope<'_> {
    /// Claimed schema family after metadata admission.
    #[must_use]
    pub const fn schema(&self) -> SchemaKind {
        self.schema
    }

    /// Claimed schema version after metadata admission.
    #[must_use]
    pub const fn version(&self) -> SchemaVersion {
        self.version
    }

    /// The still-unparsed bytes; these remain untrusted after this check.
    #[must_use]
    pub const fn unparsed_payload(&self) -> &[u8] {
        self.bytes
    }

    /// Bound JSON-style `{}` / `[]` nesting without parsing complete JSON.
    ///
    /// This only checks UTF-8, matching delimiters outside strings, and
    /// an explicit depth limit. Full JSON syntax and schema validation remain
    /// mandatory in the subsequent adapter; passing this is NOT validation.
    pub fn preflight_json_nesting(&self, limits: &Limits) -> Result<(), Diagnostic> {
        limits.check(ResourceKind::InputBytes, self.bytes.len())?;
        if core::str::from_utf8(self.bytes).is_err() {
            return Err(structure_error());
        }
        let mut delimiters = [0_u8; 128];
        let mut depth = 0_usize;
        let mut in_string = false;
        let mut escaped = false;
        for byte in self.bytes {
            if in_string {
                if escaped {
                    escaped = false;
                } else if *byte == b'\\' {
                    escaped = true;
                } else if *byte == b'"' {
                    in_string = false;
                }
                continue;
            }
            match *byte {
                b'"' => in_string = true,
                b'{' | b'[' => {
                    depth = limits.checked_add(ResourceKind::ParseDepth, depth, 1)?;
                    delimiters[depth - 1] = *byte;
                }
                b'}' | b']' => {
                    if depth == 0
                        || (delimiters[depth - 1] == b'{' && *byte != b'}')
                        || (delimiters[depth - 1] == b'[' && *byte != b']')
                    {
                        return Err(structure_error());
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        if in_string || depth != 0 {
            return Err(structure_error());
        }
        Ok(())
    }
}

impl<'a> VersionedEnvelope<'a> {
    /// Reject malformed metadata, unsupported profile versions, stale profile
    /// references, and oversized raw documents before payload deserialization.
    ///
    /// `evaluation_time_unix_secs` is explicit; this function reads no clock.
    /// Passing preflight does not validate the serialized payload, profiles'
    /// contents, their signatures, or a target policy decision.
    pub fn preflight(
        &self,
        limits: &Limits,
        evaluation_time_unix_secs: i64,
    ) -> Result<PreflightedEnvelope<'a>, Diagnostic> {
        limits.validate()?;
        limits.check(ResourceKind::InputBytes, self.payload.len())?;
        limits.check(
            ResourceKind::ProfileReferences,
            self.critical_profiles.len(),
        )?;
        if self.payload.is_empty() {
            return Err(Diagnostic::new(
                DiagnosticCode::EmptyPayload,
                "payload",
                "a nonempty serialized document is required",
            ));
        }
        self.version.require_supported(self.schema)?;
        validate_identifier(self.source_id, "source_id", true)?;
        for profile in self.critical_profiles {
            validate_identifier(profile.id, "profile_id", false)?;
            validate_identifier(profile.source_id, "profile_source_id", true)?;
            profile.version.require_supported(profile.kind)?;
            if profile
                .expires_at_unix_secs
                .is_some_and(|expires| evaluation_time_unix_secs >= expires)
            {
                return Err(Diagnostic::new(
                    DiagnosticCode::StaleCriticalProfile,
                    profile.kind.as_str(),
                    "critical profile is expired at the explicit evaluation time",
                ));
            }
        }
        Ok(PreflightedEnvelope {
            schema: self.schema,
            version: self.version,
            bytes: self.payload,
        })
    }
}

fn structure_error() -> Diagnostic {
    Diagnostic::new(
        DiagnosticCode::MalformedStructure,
        "payload_structure",
        "unbalanced JSON-like delimiters, unterminated string, or invalid UTF-8",
    )
}

fn validate_identifier(
    input: &str,
    field: &'static str,
    source_attribution: bool,
) -> Result<(), Diagnostic> {
    if input.trim().is_empty() {
        return Err(Diagnostic::new(
            if source_attribution {
                DiagnosticCode::MissingProvenance
            } else {
                DiagnosticCode::InvalidIdentifier
            },
            field,
            "a nonempty identifier is required",
        ));
    }
    if input.len() > 256 || input.chars().any(char::is_control) {
        return Err(Diagnostic::new(
            DiagnosticCode::InvalidIdentifier,
            field,
            "identifier must be at most 256 UTF-8 bytes and contain no control characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture<'a>(
        payload: &'a [u8],
        profiles: &'a [CriticalProfileReference<'a>],
    ) -> VersionedEnvelope<'a> {
        VersionedEnvelope {
            schema: SchemaKind::InventorySnapshot,
            version: SchemaVersion::V1_0,
            payload,
            source_id: "test-runner",
            critical_profiles: profiles,
        }
    }

    #[test]
    fn supported_header_does_not_claim_payload_is_parsed() {
        let document = fixture(b"{\"unverified\":true}", &[]);
        let admitted = document.preflight(&Limits::default(), 10);
        assert!(admitted.is_ok());
        if let Ok(value) = admitted {
            assert_eq!(value.schema(), SchemaKind::InventorySnapshot);
            assert_eq!(value.version(), SchemaVersion::V1_0);
            assert_eq!(value.unparsed_payload(), b"{\"unverified\":true}");
        }
    }

    #[test]
    fn unsupported_minor_and_major_versions_fail_closed() {
        let mut document = fixture(b"{}", &[]);
        for version in [
            SchemaVersion { major: 1, minor: 1 },
            SchemaVersion { major: 2, minor: 0 },
            SchemaVersion { major: 0, minor: 0 },
        ] {
            document.version = version;
            assert!(matches!(
                document.preflight(&Limits::default(), 0),
                Err(Diagnostic {
                    code: DiagnosticCode::UnsupportedSchemaVersion,
                    ..
                })
            ));
        }
    }

    #[test]
    fn empty_oversize_and_missing_source_fail_closed() {
        let limits = Limits {
            max_input_bytes: 2,
            ..Limits::default()
        };
        let mut document = fixture(b"", &[]);
        assert!(matches!(
            document.preflight(&limits, 0),
            Err(Diagnostic {
                code: DiagnosticCode::EmptyPayload,
                ..
            })
        ));
        document.payload = b"123";
        assert!(matches!(
            document.preflight(&limits, 0),
            Err(Diagnostic {
                code: DiagnosticCode::ResourceLimitExceeded,
                ..
            })
        ));
        document.payload = b"{}";
        document.source_id = "  ";
        assert!(matches!(
            document.preflight(&limits, 0),
            Err(Diagnostic {
                code: DiagnosticCode::MissingProvenance,
                ..
            })
        ));
    }

    #[test]
    fn invalid_identifier_does_not_echo_source() {
        let mut document = fixture(b"{}", &[]);
        document.source_id = "private-secret\n";
        let outcome = document.preflight(&Limits::default(), 0);
        assert!(matches!(
            outcome,
            Err(Diagnostic {
                code: DiagnosticCode::InvalidIdentifier,
                ..
            })
        ));
        if let Err(error) = outcome {
            assert!(!error.to_string().contains("private-secret"));
        }
    }

    #[test]
    fn critical_profiles_require_valid_version_and_freshness() {
        let initial = CriticalProfileReference {
            id: "example-standard",
            kind: SchemaKind::StandardsProfile,
            version: SchemaVersion::V1_0,
            source_id: "standards-test-fixture",
            expires_at_unix_secs: Some(100),
        };
        let input = [initial];
        let document = fixture(b"{}", &input);
        assert!(document.preflight(&Limits::default(), 99).is_ok());
        assert!(matches!(
            document.preflight(&Limits::default(), 100),
            Err(Diagnostic {
                code: DiagnosticCode::StaleCriticalProfile,
                ..
            })
        ));
        let bad = [CriticalProfileReference {
            version: SchemaVersion { major: 9, minor: 0 },
            ..initial
        }];
        assert!(matches!(
            fixture(b"{}", &bad).preflight(&Limits::default(), 1),
            Err(Diagnostic {
                code: DiagnosticCode::UnsupportedSchemaVersion,
                ..
            })
        ));
    }

    #[test]
    fn bounded_json_scanner_respects_strings_and_escape_sequences() {
        let input = fixture(br#"{"value":"quoted \" ] }", "list":[{"ok":true}]}"#, &[]);
        let accepted = input.preflight(&Limits::default(), 1);
        assert!(accepted.is_ok());
        if let Ok(preflight) = accepted {
            assert!(preflight.preflight_json_nesting(&Limits::default()).is_ok());
        }
    }

    #[test]
    fn bounded_json_scanner_rejects_mismatches_deep_nesting_and_utf8() {
        for bytes in [
            b"{]".as_slice(),
            b"{\"x\": [}".as_slice(),
            b"{\"x\"".as_slice(),
            b"\"unfinished".as_slice(),
            &[255_u8],
        ] {
            let input = fixture(bytes, &[]);
            let admitted = input.preflight(&Limits::default(), 0);
            assert!(admitted.is_ok());
            if let Ok(header) = admitted {
                assert!(matches!(
                    header.preflight_json_nesting(&Limits::default()),
                    Err(Diagnostic {
                        code: DiagnosticCode::MalformedStructure,
                        ..
                    })
                ));
            }
        }
        let input = fixture(b"[[[]]]", &[]);
        let limits = Limits {
            max_parse_depth: 2,
            ..Limits::default()
        };
        if let Ok(admitted) = input.preflight(&limits, 0) {
            assert!(matches!(
                admitted.preflight_json_nesting(&limits),
                Err(Diagnostic {
                    code: DiagnosticCode::ResourceLimitExceeded,
                    ..
                })
            ));
        }
    }

    #[test]
    fn excessive_critical_references_fail_before_traversal() {
        let refs = [CriticalProfileReference {
            id: "one",
            kind: SchemaKind::TargetProfile,
            version: SchemaVersion::V1_0,
            source_id: "test",
            expires_at_unix_secs: None,
        }; 2];
        let limits = Limits {
            max_profile_references: 1,
            ..Limits::default()
        };
        assert!(matches!(
            fixture(b"{}", &refs).preflight(&limits, 0),
            Err(Diagnostic {
                code: DiagnosticCode::ResourceLimitExceeded,
                ..
            })
        ));
    }
}
