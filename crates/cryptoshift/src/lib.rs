//! Deterministic cryptographic-migration planning contracts.
//!
//! This early, unpublished library includes trust-boundary preflight plus a
//! validated, canonical binary inventory snapshot contract. Its snapshots retain
//! evidence and collection incompleteness; they are not authenticated observations.
//! This crate does not yet evaluate policies or generate migration plans.
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
mod graph;
mod inventory;
mod inventory_codec;
mod limits;
mod topology;

pub use diagnostic::{Diagnostic, DiagnosticCode};
pub use envelope::{
    CriticalProfileReference, PreflightedEnvelope, SchemaKind, SchemaVersion, VersionedEnvelope,
};
pub use limits::{Limits, ParseBudget, ResourceKind};

pub use inventory::{
    AbsenceRecord, AbsenceStatus, CollectionCompleteness, CollectionRun, ConflictState,
    CryptoObservation, CryptoUseKind, EvidenceBasis, EvidenceRecord, IDENTITY_VERSION,
    InventoryArtifact, InventorySnapshot, NORMALIZATION_VERSION, SnapshotDigest,
    ValidatedInventorySnapshot,
};

pub use graph::{EvidenceGraph, GraphEdge, GraphNode, GraphNodeKind, GraphRelation};

pub use topology::{DependencyAnalysis, DependencyTopology, DirectFanout, MigrationUnit, PrerequisiteArc};
