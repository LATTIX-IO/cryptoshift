//! Stable, typed diagnostics for untrusted migration-planning inputs.
//!
//! Diagnostic messages describe fixed contract violations. They never echo
//! imported inventory, policy text, identifiers, or credential-bearing payloads.

use core::fmt;

/// Machine-readable failure class for early trust-boundary validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiagnosticCode {
    /// A configured resource limit is zero or exceeds its maximum ceiling.
    InvalidLimit,
    /// A configured resource limit has been exceeded.
    ResourceLimitExceeded,
    /// Size or counter arithmetic overflowed.
    ArithmeticOverflow,
    /// A future or incompatible critical schema revision was supplied.
    UnsupportedSchemaVersion,
    /// An input carries no nonempty source attribution.
    MissingProvenance,
    /// A profile identifier or source attribution is malformed.
    InvalidIdentifier,
    /// A required critical profile has expired for the explicit evaluation time.
    StaleCriticalProfile,
    /// A bounded structural scan found malformed container nesting or bytes.
    MalformedStructure,
    /// An input body was empty when content was required.
    EmptyPayload,
}

impl DiagnosticCode {
    /// A stable ASCII identifier suitable for logging and integration tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLimit => "CSHIFT_INVALID_LIMIT",
            Self::ResourceLimitExceeded => "CSHIFT_RESOURCE_LIMIT_EXCEEDED",
            Self::ArithmeticOverflow => "CSHIFT_ARITHMETIC_OVERFLOW",
            Self::UnsupportedSchemaVersion => "CSHIFT_UNSUPPORTED_SCHEMA_VERSION",
            Self::MissingProvenance => "CSHIFT_MISSING_PROVENANCE",
            Self::InvalidIdentifier => "CSHIFT_INVALID_IDENTIFIER",
            Self::StaleCriticalProfile => "CSHIFT_STALE_CRITICAL_PROFILE",
            Self::MalformedStructure => "CSHIFT_MALFORMED_STRUCTURE",
            Self::EmptyPayload => "CSHIFT_EMPTY_PAYLOAD",
        }
    }
}

/// A deterministic diagnostic with no copy of untrusted source content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    /// Machine-readable category; use this instead of parsing a message.
    pub code: DiagnosticCode,
    /// Static, documented logical field or resource name.
    pub subject: &'static str,
    /// Static explanation of the failure; contains no input strings.
    pub reason: &'static str,
    /// Numeric value encountered, when relevant.
    pub observed: Option<usize>,
    /// Maximum allowed value, when relevant.
    pub maximum: Option<usize>,
}

impl Diagnostic {
    pub(crate) const fn new(
        code: DiagnosticCode,
        subject: &'static str,
        reason: &'static str,
    ) -> Self {
        Self {
            code,
            subject,
            reason,
            observed: None,
            maximum: None,
        }
    }

    pub(crate) const fn with_numbers(
        code: DiagnosticCode,
        subject: &'static str,
        reason: &'static str,
        observed: usize,
        maximum: usize,
    ) -> Self {
        Self {
            code,
            subject,
            reason,
            observed: Some(observed),
            maximum: Some(maximum),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}): {}",
            self.code.as_str(),
            self.subject,
            self.reason
        )?;
        if let (Some(observed), Some(maximum)) = (self.observed, self.maximum) {
            write!(f, " [observed={observed}, max={maximum}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for Diagnostic {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_code_is_stable_and_does_not_echo_source_text() {
        let d = Diagnostic::with_numbers(
            DiagnosticCode::ResourceLimitExceeded,
            "input_bytes",
            "input exceeds configured limit",
            10,
            9,
        );
        assert_eq!(d.code.as_str(), "CSHIFT_RESOURCE_LIMIT_EXCEEDED");
        assert_eq!(
            d.to_string(),
            "CSHIFT_RESOURCE_LIMIT_EXCEEDED (input_bytes): input exceeds configured limit [observed=10, max=9]"
        );
        assert!(!d.to_string().contains("secret"));
    }
}
