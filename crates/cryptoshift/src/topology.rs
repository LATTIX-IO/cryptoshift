//! Iterative, bounded topology analysis for the validated evidence graph.
//!
//! Only `System -> System` `DependsOn` edges become prerequisites.
//! The output records structural facts and source evidence, **not** a safe or
//! approved migration plan, risk score, or authenticated collector assertion.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Diagnostic, DiagnosticCode, EvidenceGraph, GraphNodeKind, GraphRelation, Limits, ResourceKind,
    SnapshotDigest,
};

/// An indivisible planning candidate: a strongly connected group of systems.
///
/// The stable ID is the lexicographically smallest system ID in this group.
/// `cyclic` flags a group with multiple members or an explicit self-loop.
/// No property of this type asserts migration readiness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationUnit {
    /// Stable canonical unit ID, equal to its first member's graph ID.
    pub id: String,
    /// Original system node IDs in lexicographic order.
    pub system_ids: Vec<String>,
    /// True for a nontrivial cycle or explicit system self-dependency.
    pub cyclic: bool,
    /// Unique evidence IDs associated with intra-unit dependency edges.
    pub internal_dependency_evidence_ids: Vec<String>,
}

/// One typed condensation-DAG relationship.
///
/// `dependent_unit` **depends on** `prerequisite_unit`. The prerequisite
/// must therefore appear earlier in dependency-first order. Multiple graph
/// edges between two units are aggregated with evidence deduplicated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrerequisiteArc {
    /// Unit that depends on another unit.
    pub dependent_unit: String,
    /// Unit that must precede the dependent unit.
    pub prerequisite_unit: String,
    /// Canonically sorted, attributable source evidence IDs.
    pub evidence_ids: Vec<String>,
}

/// Direct, nontransitive structural fan-in for one graph node.
///
/// Counts include typed graph relations other than `DependsOn` only.
/// Different relations from the same source contribute separate direct edges,
/// but the source counts only once. No criticality/safety is inferred.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectFanout {
    /// Target graph node ID, not a new normalized identity.
    pub target_node_id: String,
    /// Exact node family from the validated graph.
    pub target_kind: GraphNodeKind,
    /// Number of direct incoming non-prerequisite graph edges.
    pub incoming_edge_count: usize,
    /// Number of distinct direct predecessor node IDs.
    pub distinct_source_count: usize,
    /// Unique evidence references of these incoming structural edges.
    pub evidence_ids: Vec<String>,
}

/// Direct non-prerequisite outgoing fanout for one graph node.
///
/// A source with multiple edges (for example one HSM with multiple keys)
/// is reported independently of incoming shared-consumer counts. Edges
/// may carry inferred evidence and are not proof of active use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectOutgoingFanout {
    /// Source node ID from the validated graph.
    pub source_node_id: String,
    /// Exact source node kind.
    pub source_kind: GraphNodeKind,
    /// Number of direct non-prerequisite outgoing edges.
    pub outgoing_edge_count: usize,
    /// Number of unique direct target nodes.
    pub distinct_target_count: usize,
    /// Sorted source evidence IDs from these outgoing edges.
    pub evidence_ids: Vec<String>,
}

/// Canonical, read-only dependency and infrastructure topology.
///
/// SCC analysis includes every `System` node, even an isolated system.
/// An edge `A DependsOn B` is stored as `A -> B` but scheduled `B, A`.
/// Other relation kinds remain independent direct structural fan-in.
/// Neither cycle collapsing nor ordering implies operational authorization.
#[derive(Clone, Debug)]
pub struct DependencyTopology {
    source_digest: SnapshotDigest,
    graph_fingerprint: SnapshotDigest,
    units: Vec<MigrationUnit>,
    prerequisites: Vec<PrerequisiteArc>,
    dependency_first_order: Vec<String>,
    direct_fanout: Vec<DirectFanout>,
    direct_outgoing_fanout: Vec<DirectOutgoingFanout>,
}

/// Stateless, deterministic dependency analyzer.
pub struct DependencyAnalysis;

impl DependencyAnalysis {
    /// Analyze a graph without recursion, external reads, or mutation.
    ///
    /// Uses iterative Kosaraju SCCs, sorted condensation edges and Kahn's
    /// dependency-first traversal. All outputs are constrained by `Limits`;
    /// partial results are never returned on budget exhaustion.
    pub fn analyze(
        graph: &EvidenceGraph,
        limits: &Limits,
    ) -> Result<DependencyTopology, Diagnostic> {
        limits.validate()?;
        limits.check(ResourceKind::GraphNodes, graph.nodes().len())?;
        limits.check(ResourceKind::GraphEdges, graph.edges().len())?;
        // A validated graph can have been admitted under *looser* limits.
        // Recheck the aggregate attached evidence references before copying
        // any evidence into analysis-owned indexes or outputs.
        let mut evidence_references = 0_usize;
        for node in graph.nodes() {
            evidence_references = limits.checked_add(
                ResourceKind::GraphEdges,
                evidence_references,
                node.evidence_ids.len(),
            )?;
        }
        for edge in graph.edges() {
            evidence_references = limits.checked_add(
                ResourceKind::GraphEdges,
                evidence_references,
                edge.evidence_ids.len(),
            )?;
        }

        // A small caller work budget must fail before BTreeMaps, adjacency
        // vectors, or traversal stacks are allocated.
        let system_count = graph
            .nodes()
            .iter()
            .filter(|node| node.kind == GraphNodeKind::System)
            .count();
        let dependency_count = graph
            .edges()
            .iter()
            .filter(|edge| edge.relation == GraphRelation::DependsOn)
            .count();
        limits.checked_add(
            ResourceKind::PlannerCandidates,
            system_count,
            dependency_count,
        )?;
        // Bound the worst-case output text before source evidence aggregation.
        preflight_output(graph, limits)?;

        // The source graph is validated and canonically sorted by FOSS-420.
        let systems: Vec<&str> = graph
            .nodes()
            .iter()
            .filter(|node| node.kind == GraphNodeKind::System)
            .map(|node| node.id.as_str())
            .collect();
        let index: BTreeMap<&str, usize> = systems
            .iter()
            .enumerate()
            .map(|(position, name)| (*name, position))
            .collect();
        let mut forward = vec![Vec::<usize>::new(); systems.len()];
        let mut reverse = vec![Vec::<usize>::new(); systems.len()];
        for edge in graph.edges() {
            if edge.relation != GraphRelation::DependsOn {
                continue;
            }
            let &from = index.get(edge.from.as_str()).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "dependency_system",
                    "prerequisite endpoint is not a known system",
                )
            })?;
            let &to = index.get(edge.to.as_str()).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "prerequisite_system",
                    "prerequisite endpoint is not a known system",
                )
            })?;
            forward[from].push(to);
            reverse[to].push(from);
        }

        // Iterative postorder DFS: no attacker-controlled call-stack depth.
        let mut visited = vec![false; systems.len()];
        let mut finishing = Vec::with_capacity(systems.len());
        for root in 0..systems.len() {
            if visited[root] {
                continue;
            }
            visited[root] = true;
            let mut stack = vec![(root, 0_usize)];
            while let Some((node, next)) = stack.pop() {
                if next < forward[node].len() {
                    stack.push((node, next + 1));
                    let adjacent = forward[node][next];
                    if !visited[adjacent] {
                        visited[adjacent] = true;
                        stack.push((adjacent, 0));
                    }
                } else {
                    finishing.push(node);
                }
            }
        }

        // Reverse-graph DFS produces each SCC once, including singletons.
        let mut assigned = vec![false; systems.len()];
        let mut components: Vec<Vec<usize>> = Vec::new();
        for &root in finishing.iter().rev() {
            if assigned[root] {
                continue;
            }
            assigned[root] = true;
            let mut stack = vec![root];
            let mut members = Vec::new();
            while let Some(node) = stack.pop() {
                members.push(node);
                for &adjacent in &reverse[node] {
                    if !assigned[adjacent] {
                        assigned[adjacent] = true;
                        stack.push(adjacent);
                    }
                }
            }
            members.sort_unstable();
            components.push(members);
        }
        // System indices already reflect canonical graph IDs.
        components.sort_by_key(|members| members[0]);
        let mut membership = vec![0_usize; systems.len()];
        let mut units = Vec::with_capacity(components.len());
        for (unit_idx, members) in components.iter().enumerate() {
            for &system_idx in members {
                membership[system_idx] = unit_idx;
            }
            let names: Vec<String> = members.iter().map(|&id| systems[id].to_owned()).collect();
            units.push(MigrationUnit {
                id: names[0].clone(),
                system_ids: names,
                cyclic: members.len() > 1,
                internal_dependency_evidence_ids: Vec::new(),
            });
        }

        let mut internal: Vec<BTreeSet<&str>> = vec![BTreeSet::new(); units.len()];
        let mut arcs: BTreeMap<(usize, usize), BTreeSet<&str>> = BTreeMap::new();
        let kind: BTreeMap<&str, GraphNodeKind> = graph
            .nodes()
            .iter()
            .map(|node| (node.id.as_str(), node.kind))
            .collect();
        let mut incoming: BTreeMap<&str, Incoming<'_>> = BTreeMap::new();
        let mut outgoing: BTreeMap<&str, Outgoing<'_>> = BTreeMap::new();

        for edge in graph.edges() {
            if edge.relation == GraphRelation::DependsOn {
                let &from = index.get(edge.from.as_str()).ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "dependency_system",
                        "unknown dependency system",
                    )
                })?;
                let &to = index.get(edge.to.as_str()).ok_or_else(|| {
                    problem(
                        DiagnosticCode::InvalidReference,
                        "prerequisite_system",
                        "unknown prerequisite system",
                    )
                })?;
                let dependent = membership[from];
                let prerequisite = membership[to];
                if dependent == prerequisite {
                    if from == to {
                        units[dependent].cyclic = true;
                    }
                    internal[dependent].extend(edge.evidence_ids.iter().map(String::as_str));
                } else {
                    arcs.entry((dependent, prerequisite))
                        .or_default()
                        .extend(edge.evidence_ids.iter().map(String::as_str));
                }
            } else {
                let state = incoming.entry(edge.to.as_str()).or_default();
                state.edge_count =
                    limits.checked_add(ResourceKind::GraphEdges, state.edge_count, 1)?;
                state.sources.insert(edge.from.as_str());
                state
                    .evidence
                    .extend(edge.evidence_ids.iter().map(String::as_str));

                let outbound = outgoing.entry(edge.from.as_str()).or_default();
                outbound.edge_count =
                    limits.checked_add(ResourceKind::GraphEdges, outbound.edge_count, 1)?;
                outbound.targets.insert(edge.to.as_str());
                outbound
                    .evidence
                    .extend(edge.evidence_ids.iter().map(String::as_str));
            }
        }

        let mut output_bytes = 0_usize;
        for (unit, sources) in units.iter_mut().zip(internal) {
            charge(limits, &mut output_bytes, &unit.id)?;
            for name in &unit.system_ids {
                charge(limits, &mut output_bytes, name)?;
            }
            for id in sources {
                charge(limits, &mut output_bytes, id)?;
                unit.internal_dependency_evidence_ids.push(id.to_owned());
            }
        }

        let mut prerequisites = Vec::with_capacity(arcs.len());
        let mut unmet = vec![0_usize; units.len()];
        let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); units.len()];
        for ((dependent, prerequisite), references) in arcs {
            unmet[dependent] = limits.checked_add(ResourceKind::GraphEdges, unmet[dependent], 1)?;
            dependents[prerequisite].push(dependent);
            let id = &units[dependent].id;
            let required = &units[prerequisite].id;
            charge(limits, &mut output_bytes, id)?;
            charge(limits, &mut output_bytes, required)?;
            let mut evidence_ids = Vec::with_capacity(references.len());
            for item in references {
                charge(limits, &mut output_bytes, item)?;
                evidence_ids.push(item.to_owned());
            }
            prerequisites.push(PrerequisiteArc {
                dependent_unit: id.clone(),
                prerequisite_unit: required.clone(),
                evidence_ids,
            });
        }
        // Canonical public edge order is ID-based, not allocation-order-based.
        prerequisites.sort_by(|left, right| {
            (&left.dependent_unit, &left.prerequisite_unit)
                .cmp(&(&right.dependent_unit, &right.prerequisite_unit))
        });

        // A depends on B means B must precede A; invert edges for Kahn.
        let mut ready: BTreeSet<usize> = unmet
            .iter()
            .enumerate()
            .filter(|(_, count)| **count == 0)
            .map(|(position, _)| position)
            .collect();
        let mut dependency_first_order = Vec::with_capacity(units.len());
        while let Some(unit) = ready.pop_first() {
            charge(limits, &mut output_bytes, &units[unit].id)?;
            dependency_first_order.push(units[unit].id.clone());
            for &dependent in &dependents[unit] {
                unmet[dependent] -= 1;
                if unmet[dependent] == 0 {
                    ready.insert(dependent);
                }
            }
        }
        if dependency_first_order.len() != units.len() {
            return Err(problem(
                DiagnosticCode::InvalidStateTransition,
                "condensation_dag",
                "collapsed dependency graph unexpectedly contains a cycle",
            ));
        }

        let mut direct_fanout = Vec::with_capacity(incoming.len());
        for (target, data) in incoming {
            let target_kind = *kind.get(target).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "structural_target",
                    "direct structural reference has no target node",
                )
            })?;
            charge(limits, &mut output_bytes, target)?;
            let mut evidence_ids = Vec::with_capacity(data.evidence.len());
            for item in data.evidence {
                charge(limits, &mut output_bytes, item)?;
                evidence_ids.push(item.to_owned());
            }
            direct_fanout.push(DirectFanout {
                target_node_id: target.to_owned(),
                target_kind,
                incoming_edge_count: data.edge_count,
                distinct_source_count: data.sources.len(),
                evidence_ids,
            });
        }
        let mut direct_outgoing_fanout = Vec::with_capacity(outgoing.len());
        for (source, data) in outgoing {
            let source_kind = *kind.get(source).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "structural_source",
                    "direct structural reference has no source node",
                )
            })?;
            charge(limits, &mut output_bytes, source)?;
            let mut evidence_ids = Vec::with_capacity(data.evidence.len());
            for item in data.evidence {
                charge(limits, &mut output_bytes, item)?;
                evidence_ids.push(item.to_owned());
            }
            direct_outgoing_fanout.push(DirectOutgoingFanout {
                source_node_id: source.to_owned(),
                source_kind,
                outgoing_edge_count: data.edge_count,
                distinct_target_count: data.targets.len(),
                evidence_ids,
            });
        }
        Ok(DependencyTopology {
            source_digest: graph.source_digest(),
            graph_fingerprint: graph.fingerprint(),
            units,
            prerequisites,
            dependency_first_order,
            direct_fanout,
            direct_outgoing_fanout,
        })
    }
}

#[derive(Default)]
struct Incoming<'a> {
    edge_count: usize,
    sources: BTreeSet<&'a str>,
    evidence: BTreeSet<&'a str>,
}

#[derive(Default)]
struct Outgoing<'a> {
    edge_count: usize,
    targets: BTreeSet<&'a str>,
    evidence: BTreeSet<&'a str>,
}

fn charge(limits: &Limits, total: &mut usize, value: &str) -> Result<(), Diagnostic> {
    *total = limits.checked_add(ResourceKind::ExportBytes, *total, value.len())?;
    Ok(())
}

// Conservative upper bound for all emitted string content. It may reject
// graphs whose deduplicated output would fit, but never admits a large
// evidence aggregation merely because a prior validator had looser limits.
fn preflight_output(graph: &EvidenceGraph, limits: &Limits) -> Result<(), Diagnostic> {
    let mut bytes = 0_usize;
    let mut max_system_id = 0_usize;
    for node in graph.nodes() {
        if node.kind == GraphNodeKind::System {
            max_system_id = max_system_id.max(node.id.len());
            let triplicate = limits.checked_mul(ResourceKind::ExportBytes, node.id.len(), 3)?;
            bytes = limits.checked_add(ResourceKind::ExportBytes, bytes, triplicate)?;
        }
    }
    let arc_names = limits.checked_mul(ResourceKind::ExportBytes, max_system_id, 2)?;
    for edge in graph.edges() {
        if edge.relation == GraphRelation::DependsOn {
            bytes = limits.checked_add(ResourceKind::ExportBytes, bytes, arc_names)?;
        } else {
            charge(limits, &mut bytes, &edge.from)?;
            charge(limits, &mut bytes, &edge.to)?;
        }
        for evidence in &edge.evidence_ids {
            charge(limits, &mut bytes, evidence)?;
            if edge.relation != GraphRelation::DependsOn {
                // An edge contributes to both incoming and outgoing views.
                charge(limits, &mut bytes, evidence)?;
            }
        }
    }
    Ok(())
}

fn problem(code: DiagnosticCode, subject: &'static str, reason: &'static str) -> Diagnostic {
    Diagnostic::new(code, subject, reason)
}

impl DependencyTopology {
    /// Digest of the immutable inventory from which the source graph was built.
    #[must_use]
    pub const fn source_digest(&self) -> SnapshotDigest {
        self.source_digest
    }

    /// Exact canonical typed graph fingerprint used to construct this topology.
    ///
    /// Distinguishes different edge/node sets over an identical inventory.
    /// The fingerprint is a content identity, not a source signature.
    #[must_use]
    pub const fn graph_fingerprint(&self) -> SnapshotDigest {
        self.graph_fingerprint
    }

    /// Canonically sorted SCC-based system units, including isolated systems.
    #[must_use]
    pub fn units(&self) -> &[MigrationUnit] {
        &self.units
    }

    /// Sorted, evidence-bound dependent-to-prerequisite condensation edges.
    #[must_use]
    pub fn prerequisites(&self) -> &[PrerequisiteArc] {
        &self.prerequisites
    }

    /// Unit IDs in dependency-first order with lexical tie-breaking.
    #[must_use]
    pub fn dependency_first_order(&self) -> &[String] {
        &self.dependency_first_order
    }

    /// Direct non-prerequisite incoming references; never transitive counts.
    #[must_use]
    pub fn direct_fanout(&self) -> &[DirectFanout] {
        &self.direct_fanout
    }

    /// Direct non-prerequisite outgoing edges and unique structural targets.
    #[must_use]
    pub fn direct_outgoing_fanout(&self) -> &[DirectOutgoingFanout] {
        &self.direct_outgoing_fanout
    }

    /// Iteratively collect all **transitive** prerequisite units of one unit.
    ///
    /// Returns the prerequisite subset in global dependency-first order;
    /// does not include the queried unit and does not expand cycles inside an
    /// SCC. Traversal is independently checked against the caller's limits.
    pub fn prerequisite_chain(
        &self,
        unit_id: &str,
        limits: &Limits,
    ) -> Result<Vec<String>, Diagnostic> {
        limits.validate()?;
        limits.check(ResourceKind::GraphNodes, self.units.len())?;
        limits.check(ResourceKind::GraphEdges, self.prerequisites.len())?;
        limits.checked_add(
            ResourceKind::PlannerCandidates,
            self.units.len(),
            self.prerequisites.len(),
        )?;
        let index: BTreeMap<&str, usize> = self
            .units
            .iter()
            .enumerate()
            .map(|(idx, unit)| (unit.id.as_str(), idx))
            .collect();
        let root = *index.get(unit_id).ok_or_else(|| {
            problem(
                DiagnosticCode::InvalidReference,
                "migration_unit",
                "prerequisite query references an unknown unit",
            )
        })?;
        let mut links = vec![Vec::<usize>::new(); self.units.len()];
        for edge in &self.prerequisites {
            let dependent = *index.get(edge.dependent_unit.as_str()).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "dependent_unit",
                    "stored prerequisite references unknown dependent",
                )
            })?;
            let prior = *index.get(edge.prerequisite_unit.as_str()).ok_or_else(|| {
                problem(
                    DiagnosticCode::InvalidReference,
                    "prerequisite_unit",
                    "stored prerequisite references unknown prerequisite",
                )
            })?;
            links[dependent].push(prior);
        }
        let mut seen = vec![false; self.units.len()];
        seen[root] = true;
        let mut stack = vec![root];
        let mut examined = 0_usize;
        while let Some(node) = stack.pop() {
            examined = limits.checked_add(ResourceKind::PlannerCandidates, examined, 1)?;
            for &prior in &links[node] {
                if !seen[prior] {
                    seen[prior] = true;
                    stack.push(prior);
                }
            }
        }
        let mut bytes = 0_usize;
        let mut result = Vec::new();
        for id in &self.dependency_first_order {
            let idx = index[id.as_str()];
            if idx != root && seen[idx] {
                charge(limits, &mut bytes, id)?;
                result.push(id.clone());
            }
        }
        Ok(result)
    }
}
