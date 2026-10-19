//! Cryptoshift-owned, neutral and *synthetic-fixture* inventory handoff.
//!
//! Cryptomap FOSS-316/340-344 do not yet provide a finalized shared wire
//! contract. This module does not claim native Cryptomap compatibility.
//! Source and content identifiers are not authenticated attestations.

use std::collections::{BTreeMap, BTreeSet};

use crate::neutral_codec::{NeutralWriter, error, expected, identifier};
use crate::{
    AbsenceStatus, CollectionCompleteness, ConflictState, CryptoObservation, Diagnostic,
    DiagnosticCode, EvidenceGraph, GraphEdge, GraphNode, IDENTITY_VERSION, Limits,
    NORMALIZATION_VERSION, ResourceKind, SchemaKind, SchemaVersion, SnapshotDigest,
    ValidatedInventorySnapshot, VersionedEnvelope,
};

/// Exact supported Cryptoshift-neutral inventory handoff revision.
pub const NEUTRAL_INVENTORY_VERSION: u16 = 1;
/// Exact supported Cryptoshift-neutral evidence-backed delta revision.
pub const NEUTRAL_CHANGE_VERSION: u16 = 1;

/// Pre-existing source claims, canonical inventory bytes and typed graph facts.
///
/// This is a **Rust fixture DTO**, not Cryptomap's unimplemented interchange
/// format. Raw inventory bytes use Cryptoshift's existing CSHIFT01 v1 codec.
#[derive(Clone, Debug)]
pub struct NeutralInventoryInput<'a> {
    /// Exact Cryptoshift-neutral handoff schema generation.
    pub schema_version: u16,
    /// Claimed producer namespace, not a signature.
    pub producer_id: &'a str,
    /// Exact immutable source revision identifier, not a sequence guarantee.
    pub producer_revision: &'a str,
    /// Required tenant/application scope.
    pub scope_id: &'a str,
    /// Raw inventory in an existing v1 envelope.
    pub inventory: VersionedEnvelope<'a>,
    /// Typed graph nodes that may only reference this inventory's evidence.
    pub nodes: &'a [GraphNode],
    /// Directed typed relationships, not implied protocol negotiation.
    pub edges: &'a [GraphEdge],
}

/// Pinned content hashes acquired through a separate trusted channel.
///
/// Generating these from the same untrusted input is NOT source validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NeutralInventoryPins {
    /// Validated v1 CSHIFT01 inventory digest.
    pub inventory_digest: SnapshotDigest,
    /// Exact evidence graph content fingerprint.
    pub graph_digest: SnapshotDigest,
    /// Source/tenant/version-bound composite fixture digest.
    pub handoff_digest: SnapshotDigest,
}

/// Immutable validated projection into the existing inventory and graph APIs.
#[derive(Clone, Debug)]
pub struct NeutralInventoryProjection {
    source_id: String,
    source_revision: String,
    scope_id: String,
    inventory: ValidatedInventorySnapshot,
    graph: EvidenceGraph,
    canonical: Vec<u8>,
    pins: NeutralInventoryPins,
}

impl NeutralInventoryProjection {
    /// Original unverified producer identity.
    #[must_use]
    pub fn producer_id(&self) -> &str {
        &self.source_id
    }
    /// Source-reported revision, which consumers must authenticate separately.
    #[must_use]
    pub fn producer_revision(&self) -> &str {
        &self.source_revision
    }
    /// Exact tenant scope.
    #[must_use]
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }
    /// Existing fully validated inventory, preserving all evidence categories.
    #[must_use]
    pub fn inventory(&self) -> &ValidatedInventorySnapshot {
        &self.inventory
    }
    /// Existing referentially closed graph, with no inferred peer relationships.
    #[must_use]
    pub fn graph(&self) -> &EvidenceGraph {
        &self.graph
    }
    /// Digests of original inventory, graph, and source-qualified handoff.
    #[must_use]
    pub const fn pins(&self) -> NeutralInventoryPins {
        self.pins
    }
    /// Deterministic metadata export, explicitly NOT a standalone graph decoder.
    pub fn export(&self, limits: &Limits) -> Result<Vec<u8>, Diagnostic> {
        limits.check(ResourceKind::ExportBytes, self.canonical.len())?;
        Ok(self.canonical.clone())
    }
}

/// Stateless adapter into existing public inventory and graph contracts.
pub struct NeutralInventoryAdapter;

impl NeutralInventoryAdapter {
    /// Validate the fixture and compute *untrusted* source-derived content pins.
    ///
    /// Callers should independently compare these pins to trusted metadata.
    /// This is useful when producing an offline fixture, not for authentication.
    pub fn project(
        input: &NeutralInventoryInput<'_>,
        expected_inventory_digest: SnapshotDigest,
        limits: &Limits,
        evaluated_at_unix_secs: i64,
    ) -> Result<NeutralInventoryProjection, Diagnostic> {
        limits.validate()?;
        if input.schema_version != NEUTRAL_INVENTORY_VERSION {
            return Err(error(
                DiagnosticCode::UnsupportedSchemaVersion,
                "neutral_inventory_version",
                "neutral inventory schema revision is not supported",
            ));
        }
        for (value, name) in [
            (input.producer_id, "neutral_producer"),
            (input.producer_revision, "neutral_source_revision"),
            (input.scope_id, "neutral_scope"),
        ] {
            identifier(value, name)?;
        }
        if input.inventory.schema != SchemaKind::InventorySnapshot
            || input.inventory.version != SchemaVersion::V1_0
            || input.inventory.source_id != input.producer_id
        {
            return Err(error(
                DiagnosticCode::InvalidReference,
                "neutral_inventory_envelope",
                "producer or inventory envelope must match exact v1 handoff",
            ));
        }
        limits.check(ResourceKind::InputBytes, input.inventory.payload.len())?;
        limits.check(ResourceKind::GraphNodes, input.nodes.len())?;
        limits.check(ResourceKind::GraphEdges, input.edges.len())?;
        // The import verifies the *expected digest* and canonical v1 payload
        // prior to any graph or policy construction.
        let inventory = ValidatedInventorySnapshot::import_verified(
            &input.inventory,
            expected_inventory_digest,
            limits,
            evaluated_at_unix_secs,
        )?;
        let body = inventory.snapshot();
        if body.scope_id != input.scope_id
            || body.identity_version != IDENTITY_VERSION
            || body.normalization_version != NORMALIZATION_VERSION
        {
            return Err(error(
                DiagnosticCode::UnsupportedIdentityVersion,
                "neutral_snapshot_identity",
                "scope/identity/normalization must match exact v1",
            ));
        }
        for run in &body.runs {
            if run.collected_at_unix_secs > evaluated_at_unix_secs {
                return Err(error(
                    DiagnosticCode::InvalidStateTransition,
                    "neutral_future_run",
                    "future collection run cannot justify current evidence",
                ));
            }
        }
        for evidence in &body.evidence {
            if evidence.observed_at_unix_secs > evaluated_at_unix_secs {
                return Err(error(
                    DiagnosticCode::InvalidStateTransition,
                    "neutral_future_evidence",
                    "future observation cannot justify current evidence",
                ));
            }
        }
        // A claimed negotiated protocol must cite at least one *directly*
        // collected source observation, not only inferred/configured evidence.
        // Even direct evidence remains an unauthenticated source claim here.
        let direct_evidence: BTreeSet<&str> = body
            .evidence
            .iter()
            .filter(|e| e.basis == crate::EvidenceBasis::Direct)
            .map(|e| e.id.as_str())
            .collect();
        for observation in &body.observations {
            if observation.kind == crate::CryptoUseKind::NegotiatedProtocol
                && !observation
                    .evidence_ids
                    .iter()
                    .any(|id| direct_evidence.contains(id.as_str()))
            {
                return Err(error(
                    DiagnosticCode::InvalidStateTransition,
                    "neutral_negotiation_evidence",
                    "claimed wire negotiation must cite direct observation evidence",
                ));
            }
        }
        // Reject oversized borrowed graph fields *before* cloning them.
        // Node/edge counts alone cannot bound an individual node's reference
        // list or an attacker-controlled identifier's allocation size.
        let mut reference_count = 0_usize;
        let mut input_bytes = limits.checked_add(
            ResourceKind::InputBytes,
            input.inventory.payload.len(),
            input.producer_id.len(),
        )?;
        for value in [input.producer_revision, input.scope_id] {
            input_bytes = limits.checked_add(ResourceKind::InputBytes, input_bytes, value.len())?;
        }
        for node in input.nodes {
            identifier(&node.id, "neutral_graph_node")?;
            input_bytes =
                limits.checked_add(ResourceKind::InputBytes, input_bytes, node.id.len())?;
            if let Some(observation_id) = &node.observation_id {
                identifier(observation_id, "neutral_graph_observation")?;
                input_bytes = limits.checked_add(
                    ResourceKind::InputBytes,
                    input_bytes,
                    observation_id.len(),
                )?;
            }
            reference_count = limits.checked_add(
                ResourceKind::GraphEdges,
                reference_count,
                node.evidence_ids.len(),
            )?;
            for id in &node.evidence_ids {
                identifier(id, "neutral_node_evidence")?;
                input_bytes =
                    limits.checked_add(ResourceKind::InputBytes, input_bytes, id.len())?;
            }
        }
        for edge in input.edges {
            for value in [&edge.from, &edge.to] {
                identifier(value, "neutral_graph_edge")?;
                input_bytes =
                    limits.checked_add(ResourceKind::InputBytes, input_bytes, value.len())?;
            }
            reference_count = limits.checked_add(
                ResourceKind::GraphEdges,
                reference_count,
                edge.evidence_ids.len(),
            )?;
            for id in &edge.evidence_ids {
                identifier(id, "neutral_edge_evidence")?;
                input_bytes =
                    limits.checked_add(ResourceKind::InputBytes, input_bytes, id.len())?;
            }
        }
        let graph = EvidenceGraph::new(
            &inventory,
            input.nodes.to_vec(),
            input.edges.to_vec(),
            limits,
        )?;
        let graph_digest = graph.fingerprint();
        let mut writer = NeutralWriter::new(b"CSHIFT_NEUTRAL_INV_V1", limits)?;
        writer.u16(input.schema_version)?;
        writer.string(input.producer_id)?;
        writer.string(input.producer_revision)?;
        writer.string(input.scope_id)?;
        writer.u16(body.identity_version)?;
        writer.u16(body.normalization_version)?;
        writer.digest(expected_inventory_digest)?;
        writer.digest(graph_digest)?;
        let (canonical, handoff_digest) = writer.finish()?;
        Ok(NeutralInventoryProjection {
            source_id: input.producer_id.to_owned(),
            source_revision: input.producer_revision.to_owned(),
            scope_id: input.scope_id.to_owned(),
            inventory,
            graph,
            canonical,
            pins: NeutralInventoryPins {
                inventory_digest: expected_inventory_digest,
                graph_digest,
                handoff_digest,
            },
        })
    }

    /// Admit an externally supplied source version ONLY when all pins match.
    pub fn import_pinned(
        input: &NeutralInventoryInput<'_>,
        pinned: NeutralInventoryPins,
        limits: &Limits,
        evaluated_at_unix_secs: i64,
    ) -> Result<NeutralInventoryProjection, Diagnostic> {
        let projected = Self::project(
            input,
            pinned.inventory_digest,
            limits,
            evaluated_at_unix_secs,
        )?;
        expected(
            projected.pins.graph_digest,
            pinned.graph_digest,
            "neutral_graph_digest",
        )?;
        expected(
            projected.pins.handoff_digest,
            pinned.handoff_digest,
            "neutral_handoff_digest",
        )?;
        Ok(projected)
    }
}

/// A source-described change; not a cryptographic proof of a collector.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum NeutralChangeKind {
    /// Observation ID did not exist in the previous inventory.
    ObservationAdded = 1,
    /// Existing observation ID changed its fully attributed payload.
    ObservationModified = 2,
    /// Current observation explicitly contains conflicting evidence.
    ObservationConflicted = 3,
    /// Current collector has incomplete or unconfirmed asset absence.
    TentativeAbsent = 4,
    /// Complete scoped reinspection explicitly claimed asset absent.
    ConfirmedAbsent = 5,
}

/// Full audit trail for a claimed inventory transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeutralChangeClaim {
    /// Exact asset involved.
    pub asset_id: String,
    /// Exact typed transition.
    pub kind: NeutralChangeKind,
    /// Required for observation events, absent for absence events.
    pub observation_id: Option<String>,
    /// Exact current collection run claiming the transition.
    pub run_id: String,
    /// Exact source evidence IDs from that current run.
    pub evidence_ids: Vec<String>,
}

/// Only source-qualified, pinned delta facts; never a rollout instruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeutralChangeSetInput {
    /// Exact neutral delta contract version.
    pub schema_version: u16,
    /// Tenant scope shared by both input projections.
    pub scope_id: String,
    /// Claimed producer ID common to both versions.
    pub producer_id: String,
    /// Source revision must match the current projected inventory.
    pub producer_revision: String,
    /// Old source version content identity supplied independently.
    pub expected_before: SnapshotDigest,
    /// Current source version content identity supplied independently.
    pub expected_after: SnapshotDigest,
    /// Explicit reported transitions; the library never invents absences.
    pub changes: Vec<NeutralChangeClaim>,
}

/// Immutable, audited delta with a bounded deterministic export.
#[derive(Clone, Debug)]
pub struct NeutralChangeSet {
    before: SnapshotDigest,
    after: SnapshotDigest,
    changes: Vec<NeutralChangeClaim>,
    canonical: Vec<u8>,
    digest: SnapshotDigest,
}

impl NeutralChangeSet {
    /// Exact previous fixture identity.
    #[must_use]
    pub const fn before_digest(&self) -> SnapshotDigest {
        self.before
    }
    /// Exact next fixture identity.
    #[must_use]
    pub const fn after_digest(&self) -> SnapshotDigest {
        self.after
    }
    /// Source-qualified typed changes, sorted canonically.
    #[must_use]
    pub fn changes(&self) -> &[NeutralChangeClaim] {
        &self.changes
    }
    /// Complete canonical content digest (not provenance authentication).
    #[must_use]
    pub const fn digest(&self) -> SnapshotDigest {
        self.digest
    }
    /// Bounded, stable v1 binary export for consumers and regression fixtures.
    pub fn export(&self, limits: &Limits) -> Result<Vec<u8>, Diagnostic> {
        limits.check(ResourceKind::ExportBytes, self.canonical.len())?;
        Ok(self.canonical.clone())
    }

    /// Validate a declared source ChangeSet against both complete source projections.
    ///
    /// Confirmed removal requires a prior observed asset plus a current
    /// **complete** run's exact confirmed absence, with no current sighting.
    /// This never promotes a partial rescan into an authoritative deletion.
    pub fn new(
        before: &NeutralInventoryProjection,
        after: &NeutralInventoryProjection,
        mut input: NeutralChangeSetInput,
        limits: &Limits,
    ) -> Result<Self, Diagnostic> {
        limits.validate()?;
        if input.schema_version != NEUTRAL_CHANGE_VERSION {
            return Err(error(
                DiagnosticCode::UnsupportedSchemaVersion,
                "neutral_changes_version",
                "unsupported neutral ChangeSet schema",
            ));
        }
        if before.scope_id != after.scope_id
            || before.scope_id != input.scope_id
            || before.source_id != after.source_id
            || before.source_id != input.producer_id
            || after.source_revision != input.producer_revision
            || before.source_revision == after.source_revision
        {
            return Err(error(
                DiagnosticCode::InvalidReference,
                "neutral_delta_scope",
                "delta must join two distinct source revisions in one producer/tenant",
            ));
        }
        expected(
            before.pins.handoff_digest,
            input.expected_before,
            "neutral_change_before",
        )?;
        expected(
            after.pins.handoff_digest,
            input.expected_after,
            "neutral_change_after",
        )?;
        limits.check(ResourceKind::EvidenceRecords, input.changes.len())?;
        let old = before.inventory.snapshot();
        let next = after.inventory.snapshot();
        let old_observations: BTreeMap<&str, &CryptoObservation> = old
            .observations
            .iter()
            .map(|o| (o.id.as_str(), o))
            .collect();
        let next_observations: BTreeMap<&str, &CryptoObservation> = next
            .observations
            .iter()
            .map(|o| (o.id.as_str(), o))
            .collect();
        let runs: BTreeMap<&str, &crate::CollectionRun> =
            next.runs.iter().map(|r| (r.id.as_str(), r)).collect();
        let evidence: BTreeMap<&str, &crate::EvidenceRecord> =
            next.evidence.iter().map(|e| (e.id.as_str(), e)).collect();
        // Index once: per-claim linear absence and asset scans otherwise form
        // a CPU denial of service for large but otherwise valid source inputs.
        // Status tags avoid imposing an Ord implementation on public AbsenceStatus.
        let absences: BTreeSet<(&str, &str, u8)> = next
            .absences
            .iter()
            .map(|absence| {
                (
                    absence.asset_id.as_str(),
                    absence.run_id.as_str(),
                    if absence.status == AbsenceStatus::Confirmed {
                        2
                    } else {
                        1
                    },
                )
            })
            .collect();
        let old_assets: BTreeSet<&str> = old
            .observations
            .iter()
            .map(|observation| observation.asset_id.as_str())
            .collect();
        let next_assets: BTreeSet<&str> = next
            .observations
            .iter()
            .map(|observation| observation.asset_id.as_str())
            .collect();
        // Fail duplicate claims before expensive provenance and transition
        // validation; use borrowed keys so no attacker-controlled IDs are
        // cloned merely to establish uniqueness.
        {
            let mut claims = BTreeSet::new();
            for claim in &input.changes {
                identifier(&claim.asset_id, "neutral_change_asset")?;
                identifier(&claim.run_id, "neutral_change_run")?;
                if let Some(id) = claim.observation_id.as_deref() {
                    identifier(id, "neutral_change_observation")?;
                }
                if !claims.insert((
                    claim.asset_id.as_str(),
                    claim.kind,
                    claim.observation_id.as_deref(),
                    claim.run_id.as_str(),
                )) {
                    return Err(error(
                        DiagnosticCode::DuplicateRecord,
                        "neutral_change_id",
                        "repeated source-defined transition identity",
                    ));
                }
            }
        }
        let mut references = 0usize;
        for claim in &mut input.changes {
            references = limits.checked_add(
                ResourceKind::GraphEdges,
                references,
                claim.evidence_ids.len(),
            )?;
            identifier(&claim.asset_id, "neutral_change_asset")?;
            identifier(&claim.run_id, "neutral_change_run")?;
            if let Some(id) = claim.observation_id.as_deref() {
                identifier(id, "neutral_change_observation")?;
            }
            let run = runs.get(claim.run_id.as_str()).ok_or_else(|| {
                error(
                    DiagnosticCode::InvalidReference,
                    "neutral_change_run",
                    "change refers to absent current run",
                )
            })?;
            if claim.evidence_ids.is_empty() {
                return Err(error(
                    DiagnosticCode::MissingProvenance,
                    "neutral_change_evidence",
                    "transition must retain at least one current source evidence reference",
                ));
            }
            let mut unique = BTreeSet::new();
            for id in &claim.evidence_ids {
                identifier(id, "neutral_change_evidence")?;
                if !unique.insert(id.as_str()) {
                    return Err(error(
                        DiagnosticCode::DuplicateRecord,
                        "neutral_change_evidence",
                        "duplicate evidence attribution",
                    ));
                }
                if evidence.get(id.as_str()).is_none_or(|e| e.run_id != run.id) {
                    return Err(error(
                        DiagnosticCode::InvalidReference,
                        "neutral_change_evidence",
                        "change evidence is not from declared current collection run",
                    ));
                }
            }
            claim.evidence_ids.sort();
            let observation = claim
                .observation_id
                .as_deref()
                .and_then(|id| next_observations.get(id));
            let valid = match claim.kind {
                NeutralChangeKind::ObservationAdded => observation.is_some_and(|o| {
                    o.asset_id == claim.asset_id
                        && !old_observations.contains_key(o.id.as_str())
                        && claim
                            .evidence_ids
                            .iter()
                            .all(|id| o.evidence_ids.binary_search(id).is_ok())
                }),
                NeutralChangeKind::ObservationModified => observation.is_some_and(|o| {
                    o.asset_id == claim.asset_id
                        && old_observations
                            .get(o.id.as_str())
                            .is_some_and(|prior| *prior != *o)
                        && claim
                            .evidence_ids
                            .iter()
                            .all(|id| o.evidence_ids.binary_search(id).is_ok())
                }),
                NeutralChangeKind::ObservationConflicted => observation.is_some_and(|o| {
                    o.asset_id == claim.asset_id
                        && o.conflict != ConflictState::Uncontested
                        && claim
                            .evidence_ids
                            .iter()
                            .all(|id| o.evidence_ids.binary_search(id).is_ok())
                }),
                NeutralChangeKind::TentativeAbsent | NeutralChangeKind::ConfirmedAbsent => {
                    if claim.observation_id.is_some() {
                        false
                    } else {
                        let status = if claim.kind == NeutralChangeKind::ConfirmedAbsent {
                            AbsenceStatus::Confirmed
                        } else {
                            AbsenceStatus::Tentative
                        };
                        absences.contains(&(
                            claim.asset_id.as_str(),
                            run.id.as_str(),
                            if status == AbsenceStatus::Confirmed {
                                2
                            } else {
                                1
                            },
                        )) && (status != AbsenceStatus::Confirmed
                            || (run.completeness == CollectionCompleteness::Complete
                                && old_assets.contains(claim.asset_id.as_str())
                                && !next_assets.contains(claim.asset_id.as_str())))
                    }
                }
            };
            if !valid {
                return Err(error(
                    DiagnosticCode::InvalidStateTransition,
                    "neutral_change_claim",
                    "declared transition is not supported by both scoped snapshots",
                ));
            }
        }
        input.changes.sort_by(|a, b| {
            (&a.asset_id, a.kind, &a.observation_id, &a.run_id).cmp(&(
                &b.asset_id,
                b.kind,
                &b.observation_id,
                &b.run_id,
            ))
        });
        if input.changes.windows(2).any(|w| {
            (
                &w[0].asset_id,
                w[0].kind,
                &w[0].observation_id,
                &w[0].run_id,
            ) == (
                &w[1].asset_id,
                w[1].kind,
                &w[1].observation_id,
                &w[1].run_id,
            )
        }) {
            return Err(error(
                DiagnosticCode::DuplicateRecord,
                "neutral_change_id",
                "repeated source-defined transition identity",
            ));
        }
        let mut writer = NeutralWriter::new(b"CSHIFT_NEUTRAL_CHANGE_V1", limits)?;
        writer.u16(input.schema_version)?;
        writer.string(&input.scope_id)?;
        writer.string(&input.producer_id)?;
        writer.string(&input.producer_revision)?;
        writer.digest(input.expected_before)?;
        writer.digest(input.expected_after)?;
        writer.count(input.changes.len())?;
        for claim in &input.changes {
            writer.string(&claim.asset_id)?;
            writer.u8(claim.kind as u8)?;
            writer.u8(u8::from(claim.observation_id.is_some()))?;
            if let Some(id) = &claim.observation_id {
                writer.string(id)?;
            }
            writer.string(&claim.run_id)?;
            writer.strings(&claim.evidence_ids)?;
        }
        let (canonical, digest) = writer.finish()?;
        Ok(Self {
            before: input.expected_before,
            after: input.expected_after,
            changes: input.changes,
            canonical,
            digest,
        })
    }
}
