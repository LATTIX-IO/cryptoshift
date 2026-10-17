# FOSS-422 — Bounded prerequisite topology and SCC migration units

Status: unpublished Rust developer contract; no migration execution, no security
policy decisions, no PQC readiness claims.

## Operational goal and trust boundary

Consume **only** a `ValidatedInventorySnapshot` and the corresponding
`EvidenceGraph` from FOSS-418/FOSS-420. `DependencyAnalysis::analyze` is a
stateless, offline graph transformation over already validated facts. It never
queries a live infrastructure service, dereferences URLs, reads private key
material, invokes a cryptographic migration, or infers a cryptographic
algorithm is safe. The content digest identifies the exact source snapshot;
it does not authenticate a collector or establish truth of the reported facts.

The graph must already preserve source attribution, observation-vs-capability,
source conflicts, unknown observations, and collection completeness. Analysis
cannot silently promote `LibraryCapability`, `ConfiguredProtocol`,
`Inferred`, or `Unknown` into negotiated/active crypto or remediation.

## Input and graph relationship semantics

Only edges whose `GraphRelation == DependsOn` participate in the directed
prerequisite graph. These are validated System -> System edges, where

    A --DependsOn--> B  means  B precedes A

This orientation is intentionally different from a scheduling edge. The
`PrerequisiteArc` public API retains `dependent_unit -> prerequisite_unit`
with sorted, attributable edge evidence. The public
`dependency_first_order()` reverses the scheduling orientation and returns
the prerequisite before the dependent, with lexical tie-breaking among
currently ready units.

System -> Library, System -> Certificate, System -> Hsm, Certificate ->
TrustAnchor, Hsm -> Key, Key -> Data, ownership, vendor, and crypto-use
relations are **structural**, not implicit migration prerequisites.

A narrowly scoped additive FOSS-422 graph relation `UsesHsm` allows a
System -> Hsm statement *with source evidence*. This supports reporting two
systems with direct claims to the same HSM; it cannot prove actual hardware
usage or whether key migration is safe.

## SCC and migration-unit contract

The implementation builds forward/reverse adjacency indexes once and runs
**iterative Kosaraju**, not recursive Tarjan/DFS. Its work is O(V+E) for SCC
traversals, plus deterministic sorting and ordered map/set operations.
Adjacency is limited to system dependencies; all system nodes, including
isolated ones, get exactly one SCC. Every strongly connected component
becomes one `MigrationUnit`, with:
- stable `id` equal to the lexicographically smallest original system ID;
- original member system IDs, sorted and unique;
- `cyclic=true` for multiple members **or** an explicit self-loop;
- deduplicated evidence IDs from *within* the SCC, including self-loops.

Cycles are retained as indivisible **planning candidates**, never dropped
or presented as approved cutover decisions. Distinct SCCs collapse to a
condensation DAG; multiple edges between two SCCs aggregate evidence.
Ordering is deterministic using a lexicographically keyed ready set.
The public `prerequisite_chain(unit_id, limits)` computes transitive
prerequisites on demand with an explicit nonrecursive traversal, yielding a
dependency-first subset of units and omitting the queried unit. No O(V^2)
all-pairs reachability materialization is performed.

## Direct fanout / shared infrastructure

`direct_fanout()` reports one row per target receiving at least one
**non-DependsOn** incoming edge. `incoming_edge_count` counts direct typed
edges (different relations count separately); `distinct_source_count`
deduplicates direct source node IDs. `evidence_ids` are a canonical union
of evidence references from those edges. A node is "directly shared" in this
limited structural sense when `distinct_source_count >= 2`. This is **not**
a recursive reachability or operational criticality score.

`direct_outgoing_fanout()` separately reports **source-side** structural
high fanout: total outgoing non-prerequisite edges, number of distinct
direct targets, and evidence references. For example, one HSM with two
`HoldsKey` relations has outgoing count two, while two systems with explicit
`UsesHsm` relations produce an incoming distinct-source count of two at
that same HSM. Neither condition proves the other; all source-attributed
observations are retained without transitive inference.

Dependency arcs and direct structural fanout are intentionally separate
projections. Callers must not infer PKI interoperability, shared blast
radius, PQC eligibility, migration readiness, or a risk score from counts.

## Bounds and rejection behavior

- `max_graph_nodes` and `max_graph_edges` constrain the accepted graph at
  analysis time even when the graph was previously created with looser limits.
  The graph's **total attached node/edge evidence references** are also
  rechecked against `max_graph_edges` independently of the edge count, so a
  caller cannot bypass stricter limits by reusing a loosely admitted graph.
- `max_planner_candidates` bounds `System` count plus the number of direct
  System -> System dependency edges before adjacency construction. Default
  20,000 admits a 10,000-node/9,999-edge path.
- `max_export_bytes` bounds the **total UTF-8 bytes of emitted IDs and
  evidence references** in units, arcs, order and fanout. This is a
  **pre-admission upper bound**, checked before adjacency indexes and
  evidence sets are allocated. It conservatively charges system IDs up to
  three times, potential condensation-arc unit IDs at the longest system-ID
  length, and non-prerequisite edge evidence twice for separate incoming and
  outgoing views. It can reject a graph whose heavily deduplicated result
  would fit. This is not an encoded wire protocol or exact allocator
  accounting; object/container allocations remain bounded by graph
  cardinalities.
- Checked arithmetic rejects overflow; any failure returns a typed
  `Diagnostic` and no partial topology. `prerequisite_chain` applies its
  own caller-supplied node/edge/work/output budgets.
- No global all-pairs transitive closure or arbitrary expansion of inferred
  dependencies. DAG cycles after SCC collapse are treated as invalid state.

Note: rebuilding a validated `EvidenceGraph` from raw user strings is **not**
this module's responsibility. Use the source FOSS-418/420 validators first.

## Test-to-requirement evidence

| Requirement | Integration test |
| --- | --- |
| A depends on B depends on C: C, B, A, canonical reorder | chain_has_prerequisites_first_and_is_order_invariant |
| Diamond with unique transitive closure and ready-set tie-break | diamond_chain_has_unique_dependency_first_order |
| Three-node cycle, self-loop, second cycle and singleton | nontrivial_cycles_self_loops_and_isolated_systems_preserved |
| Direct shared library, trust anchor and HSM plus HSM multi-key outgoing high fanout | structural_shared_infrastructure_is_direct_not_transitive |
| Configured vs negotiated/active must not be promoted | structural_crypto_use_retains_original_configured_classification |
| Tight node, edge, work and output limits | bounded_analysis_and_chain_fail_closed |
| Iterative 10k-node path under default limits | ten_thousand_systems_analyze_iteratively_without_stack_overflow |

All tests use public Rust types and synthetic, provenance-attributed, offline
fixtures. They do not need a Cryptomap collector, a cloud deployment, or a
running encryption system.

## Manual, inspectable verification

From repository root:

```bash
python3 scripts/release_safety.py --with-cargo
python3 -m unittest discover -s scripts -p "test_release_safety.py" -v
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo run --example dependency_analysis --locked
```

Example expected salient lines:

    dependency first: ["database", "api", "frontend"]
    frontend prerequisites: ["database", "api"]
    cycles: 0
    No policy decision, readiness assessment, or infrastructure change.

In protected GitHub CI, **both** `Rust checks` and
`Supply chain and SemVer` must succeed on the exact PR head and on
the merged `main`. The latter executes RustSec, cargo-deny and SemVer.
`publish = false`, read-only CI, and manual release-PR-only controls
remain unchanged.

## Known limitations and next increment boundaries

- No temporal cross-snapshot dependency changes, tenant joins, or verification
  of a collector's identity. Incomplete inventory may hide dependencies.
- Direct fanout does not compute transitive blast radius or ownership policy.
- A cyclic unit may require human resolution; its grouping is not a plan.
- The graph does not assert a target PQC algorithm, transition window, data
  classification, customer outage budget, rollback guarantee, or approval.
- FOSS-427 owns deterministic, explainable factor-vector security scoring;
  FOSS-442 owns bounded wave scheduling and rollback/approval gates.
- Cryptomap FOSS-316 / adapter FOSS-446 still own cross-project inventory
  translation and conformance; the internal binary DTO is not that adapter.
