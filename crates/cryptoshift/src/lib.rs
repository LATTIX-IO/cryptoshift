//! Deterministic cryptographic-migration planning contracts.
//!
//! This early, unpublished increment only defines *trust-boundary preflight*:
//! bounded resource admission, exact outer schema versions, and safe diagnostics.
//! It does **not** parse external formats, validate crypto inventory semantics,
//! implement policy evaluation, or generate migration plans. Format adapters in
//! later increments must validate payload structure and provenance themselves.
//!
//! # Example
//!
//! ```
//! use cryptoshift::{Limits, SchemaKind, SchemaVersion, VersionedEnvelope};
//!
//! let input = VersionedEnvelope {
//!     schema: SchemaKind::InventorySnapshot,
//!     version: SchemaVersion::V1_0,
//!     payload: b"{}",
//!     source_id: "example-fixture",
//!     critical_profiles: &[],
//! };
//! let admitted = input.preflight(&Limits::default(), 0)?;
//! assert_eq!(admitted.unparsed_payload(), b"{}");
//! # Ok::<(), cryptoshift::Diagnostic>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod diagnostic;
mod envelope;
mod limits;

pub use diagnostic::{Diagnostic, DiagnosticCode};
pub use envelope::{
    CriticalProfileReference, PreflightedEnvelope, SchemaKind, SchemaVersion, VersionedEnvelope,
};
pub use limits::{Limits, ParseBudget, ResourceKind};
