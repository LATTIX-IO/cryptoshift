//! Typed, deterministic, source-evidence-bound cryptographic dependency graph.
//! This validates only topology and evidence, not quantum risk or safe migration.

use std::collections::{BTreeMap, BTreeSet};

use crate::inventory::{CryptoUseKind, SnapshotDigest, ValidatedInventorySnapshot};
use crate::{Diagnostic, DiagnosticCode, Limits, ResourceKind};

/// Explicit family of migration graph nodes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GraphNodeKind {
    /// An application, system or service.
    System,
    /// A concrete cryptographic use-site, tied to one inventory observation.
    CryptoUse,
    /// A software cryptographic library, whether or not actively used.
    Library,
    /// A certificate.
    Certificate,
    /// A configured PKI trust anchor.
    TrustAnchor,
    /// A cryptographic key reference, never key material.
    Key,
    /// A hardware security module.
    Hsm,
    /// A data asset.
    Data,
    /// An accountable administrative owner.
    Owner,
    /// A vendor or external product provider.
    Vendor,
}

/// Allowed directional relationship families.
///
/// Declaring a relation is not evidence that cryptography was actually
/// negotiated, that a key is safe, or that a future migration is possible.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GraphRelation {
    /// System -> CryptoUse: system exposes an observed/configured use-site.
    ExposesUse,
    /// System -> Library: system has a dependency on a library.
    LoadsLibrary,
    /// Library -> CryptoUse: library implements an observed use-site.
    ImplementsUse,
    /// System -> Certificate: system uses a certificate.
    UsesCertificate,
    /// Certificate -> TrustAnchor: certificate chains to a trust anchor.
    IssuedBy,
    /// System -> Hsm: evidence of configured or observed hardware use.
    UsesHsm,
    /// Hsm -> Key: key material is held by hardware.
    HoldsKey,
    /// Key -> Data: key protects data.
    ProtectsData,
    /// System, Data, Key, Certificate or Hsm -> Owner: responsibility.
    OwnedBy,
    /// System, Library or Hsm -> Vendor: upstream supply dependency.
    SuppliedBy,
    /// System -> System: directional operational dependency (cycles allowed).
    DependsOn,
}

impl GraphRelation {
    fn permits(self, from: GraphNodeKind, to: GraphNodeKind) -> bool {
        use GraphNodeKind as N;
        match self {
            Self::ExposesUse => from == N::System && to == N::CryptoUse,
            Self::LoadsLibrary => from == N::System && to == N::Library,
            Self::ImplementsUse => from == N::Library && to == N::CryptoUse,
            Self::UsesCertificate => from == N::System && to == N::Certificate,
            Self::IssuedBy => from == N::Certificate && to == N::TrustAnchor,
            Self::UsesHsm => from == N::System && to == N::Hsm,
            Self::HoldsKey => from == N::Hsm && to == N::Key,
            Self::ProtectsData => from == N::Key && to == N::Data,
            Self::OwnedBy => {
                matches!(from, N::System | N::Data | N::Key | N::Certificate | N::Hsm)
                    && to == N::Owner
            }
            Self::SuppliedBy => matches!(from, N::System | N::Library | N::Hsm) && to == N::Vendor,
            Self::DependsOn => from == N::System && to == N::System,
        }
    }
}

/// A stable node with evidence from a validated, scoped inventory snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphNode {
    /// Stable opaque ID unique across graph node families.
    pub id: String,
    /// Declared family.
    pub kind: GraphNodeKind,
    /// Source evidence references; duplicates are rejected.
    pub evidence_ids: Vec<String>,
    /// Mandatory for a CryptoUse node, prohibited for every other kind.
    pub observation_id: Option<String>,
    /// Exact observation classification; CryptoUse requires a match, others None.
    pub observation_kind: Option<CryptoUseKind>,
}

/// Directed typed edge with independently traceable evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphEdge {
    /// Stable source node ID.
    pub from: String,
    /// Stable destination node ID.
    pub to: String,
    /// Typed, directional relationship.
    pub relation: GraphRelation,
    /// Evidence references, all drawn from the same validated inventory.
    pub evidence_ids: Vec<String>,
}

/// Immutable, deterministic graph over one snapshot, without migration decisions.
#[derive(Clone, Debug)]
pub struct EvidenceGraph {
    source_digest: SnapshotDigest,
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
}

impl EvidenceGraph {
    /// Build a bounded directed graph with strict referential closure.
    ///
    /// All node/edge claims must link to known, scoped inventory evidence.
    /// CryptoUse nodes must map one-to-one onto inventory observations and
    /// may cite only evidence associated with that exact observation.
    /// Nodes and edges are canonically sorted without collapsing conflicts.
    pub fn new(
        snapshot: &ValidatedInventorySnapshot,
        mut nodes: Vec<GraphNode>,
        mut edges: Vec<GraphEdge>,
        limits: &Limits,
    ) -> Result<Self, Diagnostic> {
        limits.validate()?;
        limits.check(ResourceKind::GraphNodes, nodes.len())?;
        limits.check(ResourceKind::GraphEdges, edges.len())?;
        let source_digest = snapshot.export(limits)?.digest;
        let inventory = snapshot.snapshot();

        let evidence: BTreeSet<&str> = inventory
            .evidence
            .iter()
            .map(|item| item.id.as_str())
            .collect();
        let observations: BTreeMap<&str, &crate::CryptoObservation> = inventory
            .observations
            .iter()
            .map(|item| (item.id.as_str(), item))
            .collect();

        let mut identities = BTreeMap::new();
        let mut observation_bindings = BTreeSet::new();
        let mut references = 0_usize;

        for node in &mut nodes {
            identifier(&node.id, "graph_node")?;
            if identities.insert(node.id.clone(), node.kind).is_some() {
                return Err(problem(
                    DiagnosticCode::DuplicateRecord,
                    "graph_node",
                    "graph node ID cannot be repeated across families",
                ));
            }
            if node.evidence_ids.is_empty() {
                return Err(problem(
                    DiagnosticCode::MissingProvenance,
                    "graph_node",
                    "graph node requires source evidence",
                ));
            }
            references = limits.checked_add(
                ResourceKind::GraphEdges,
                references,
                node.evidence_ids.len(),
            )?;
            validate_evidence(&mut node.evidence_ids, &evidence)?;
            if node.kind == GraphNodeKind::CryptoUse {
                let binding = node.observation_id.as_deref().ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "graph_observation",
                        "crypto use node must map to an inventory observation",
                    )
                })?;
                identifier(binding, "graph_observation")?;
                let observed = observations.get(binding).ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "graph_observation",
                        "crypto use node references an unknown observation",
                    )
                })?;
                if node.observation_kind != Some(observed.kind) {
                    return Err(problem(
                        DiagnosticCode::InvalidStateTransition,
                        "graph_observation_kind",
                        "graph use-site classification must match its inventory observation",
                    ));
                }
                if !observation_bindings.insert(binding.to_owned()) {
                    return Err(problem(
                        DiagnosticCode::DuplicateRecord,
                        "graph_observation",
                        "two crypto use nodes cannot alias one observed use-site",
                    ));
                }
                if node
                    .evidence_ids
                    .iter()
                    .any(|id| observed.evidence_ids.binary_search(id).is_err())
                {
                    return Err(problem(
                        DiagnosticCode::InvalidReference,
                        "graph_observation",
                        "crypto use node may cite only evidence for its observation",
                    ));
                }
            } else if node.observation_id.is_some() || node.observation_kind.is_some() {
                return Err(problem(
                    DiagnosticCode::InvalidReference,
                    "graph_observation",
                    "only a crypto use node may bind to an observation",
                ));
            }
        }

        let mut edge_keys = BTreeSet::new();
        for edge in &mut edges {
            identifier(&edge.from, "graph_edge_from")?;
            identifier(&edge.to, "graph_edge_to")?;
            let source = identities.get(&edge.from).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "graph_edge_from",
                    "edge source node must exist",
                )
            })?;
            let target = identities.get(&edge.to).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "graph_edge_to",
                    "edge target node must exist",
                )
            })?;
            if !edge.relation.permits(*source, *target) {
                return Err(problem(
                    DiagnosticCode::InvalidStateTransition,
                    "graph_relation",
                    "edge direction or node-kind relationship is not supported",
                ));
            }
            if !edge_keys.insert((edge.from.clone(), edge.to.clone(), edge.relation)) {
                return Err(problem(
                    DiagnosticCode::DuplicateRecord,
                    "graph_edge",
                    "duplicate typed directed relationship",
                ));
            }
            if edge.evidence_ids.is_empty() {
                return Err(problem(
                    DiagnosticCode::MissingProvenance,
                    "graph_edge",
                    "graph relation requires attributable evidence",
                ));
            }
            references = limits.checked_add(
                ResourceKind::GraphEdges,
                references,
                edge.evidence_ids.len(),
            )?;
            validate_evidence(&mut edge.evidence_ids, &evidence)?;
        }
        nodes.sort_by(|left, right| left.id.cmp(&right.id));
        edges.sort_by(|left, right| {
            (&left.from, &left.to, left.relation).cmp(&(&right.from, &right.to, right.relation))
        });
        Ok(Self {
            source_digest,
            nodes,
            edges,
        })
    }

    /// Exact digest of the canonical inventory used as evidence authority.
    #[must_use]
    pub const fn source_digest(&self) -> SnapshotDigest {
        self.source_digest
    }

    /// Canonical nodes, sorted by stable opaque ID.
    #[must_use]
    pub fn nodes(&self) -> &[GraphNode] {
        &self.nodes
    }

    /// Canonical directed edges, sorted by source, target and relation.
    #[must_use]
    pub fn edges(&self) -> &[GraphEdge] {
        &self.edges
    }
}

fn identifier(id: &str, subject: &'static str) -> Result<(), Diagnostic> {
    if id.trim().is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
        return Err(problem(
            DiagnosticCode::InvalidIdentifier,
            subject,
            "graph ID must be nonempty, bounded and free from controls",
        ));
    }
    Ok(())
}

fn problem(code: DiagnosticCode, subject: &'static str, reason: &'static str) -> Diagnostic {
    Diagnostic::new(code, subject, reason)
}

fn validate_evidence(ids: &mut [String], known: &BTreeSet<&str>) -> Result<(), Diagnostic> {
    let mut seen = BTreeSet::new();
    for id in ids.iter() {
        identifier(id, "graph_evidence")?;
        if !seen.insert(id.as_str()) {
            return Err(problem(
                DiagnosticCode::DuplicateRecord,
                "graph_evidence",
                "duplicate evidence ID in one record",
            ));
        }
        if !known.contains(id.as_str()) {
            return Err(problem(
                DiagnosticCode::InvalidReference,
                "graph_evidence",
                "graph references evidence missing from the inventory",
            ));
        }
    }
    ids.sort();
    Ok(())
}
