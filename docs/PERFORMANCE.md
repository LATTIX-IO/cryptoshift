# FOSS-453 — Reproducible offline scaling evidence

This benchmark is a **synthetic test of computational scaling**, not cryptographic assurance, peer authentication, a performance SLO or a migration execution tool. Fixture digests are content identities and **not signatures**.

## Profiles and constraints

| Profile | Graph systems | Source evidence records | Expected SCC units | Dependency construction |
|---|---:|---:|---:|---|
| small | 8 | 1 | 2 | Four-system SCCs and an inter-SCC dependency chain |
| standard | 24 | 1 | 6 | Same generator, six units |
| large | 64 | 1 | 16 | Same generator, sixteen units |

A single synthetic **partial** collection run asserts the one evidence identity attached to every system and dependency edge. No observation or peer negotiation is authenticated; the compatibility report must remain `Unknown`. Target constraints request ML-KEM-1024 on an explicitly named synthetic protocol. Both vendor catalogs contain only **unverified documentation claims**. Unknown coverage remains unverified; no branch can authorize execution, suppress residual risk, or treat vendor advertising as runtime proof.

The generator creates canonical five-digit node identities and directed `DependsOn` edges; each consecutive group of four nodes contains a cycle, while neighboring groups form an acyclic chain. The SCC topology must contain exactly `systems / 4` units. Graphs created in ascending and reversed insertion order must generate **identical** inventory, graph, risk, topology, compatibility, remediation, wave and final plan content digests. A second check repeats the complete pipeline and requires digest equality. The negative gate re-admits the graph with `max_graph_nodes = systems - 1` and requires `ResourceLimitExceeded` rather than truncation, panic, or incomplete output.

The timed phases are: inventory+typed graph creation, iterative dependency/SCC analysis, evidence-bound risk analysis (priority evidence), offline peer compatibility, remediation blocker analysis, capacity-bounded advisory wave planning, and immutable digest-bound plan assembly. Risk is not a made-up single security score: unverified factors cannot be upgraded to certainty. The benchmark produces no control-plane writes.

## Reproduce

From the repository root:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo bench -p cryptoshift --bench phase_scaling -- --smoke
cargo bench -p cryptoshift --bench phase_scaling
rustc --version
cargo --version
```

The `--smoke` mode executes each profile in original and reversed input order and checks deterministic semantic identities, SCC counts, fail-closed resource exhaustion, unproven negotiation and nonauthoritative plan status. It prints one `scaling:v1` identity line plus phase timings per size. Normal mode repeats the same verified pipeline ten times and prints average elapsed milliseconds. **Timing is diagnostic data only:** CI must never gate correctness on runner speed. The CI gate checks stable semantic output markers and completed fixed-size smoke work.

For a locally collected performance baseline, record the **exact** commit, OS/kernel, CPU architecture and model, memory, power mode, Rust compiler/toolchain, Cargo version, release profile, command line, number of repetitions, warm/cold cache, elapsed wall-clock samples (p50/p95 if enough repetitions), and all reported plan/phase digests. Cross-host timings are not directly comparable without that metadata. Do not commit unstable timings as immutable golden acceptance thresholds.

## Frozen semantic baseline

The source-controlled `tests/perf/v1/identity.golden` is pinned to the exact reviewed output of [Linux CI #39661071220](https://github.com/LATTIX-IO/cryptoshift/actions/runs/39661071220) at commit `769d4b81c8564ed58df6cf56a8dd7466b6c872d3`. It contains precisely one canonical identity record per scale with graph, risk, compatibility, remediation, wave and immutable plan digests. All CI and manually invoked benchmark runs compare every identity record byte-for-byte to this baseline, and also verify input-order permutation equality. Durations are deliberately excluded from the golden. Any drift requires source evidence, explicit review and a separate qualified update; self-rewriting a golden during a test is prohibited. `tests/perf/**` uses LF-pinned Git attributes for Windows parity.

## Test-to-requirement mapping

| Requirement | Evidence |
|---|---|
| Reproducible bounded small/standard/large fixtures | `benches/phase_scaling.rs` generator; three-size fixture table |
| Graph and iterative SCC scalability | `graph` and `topology` phase timers; exact `systems / 4` unit assertion |
| Compatibility, risk/priority and waves | `compatibility`, `risk`, `remediation`, `waves` phase timers |
| Whole immutable plan semantics | Plan digest and stage digest identity replay |
| Semantics unchanged under source ordering | Ascending vs reversed graph input order for each profile |
| Hostile smaller-budget consumer | Graph re-admission rejects with `ResourceLimitExceeded` |
| CI not dependent on timing noise | Deterministic `scaling:v1 PASS` result; no maximum-time assertion |
| Rust 1.85 and platform acceptance | Full workspace tests on MSRV; Windows matrix available after FOSS-448 integration |

## Limitations and release contract

These synthetic shapes do not measure real enterprise asset diversity, adversarial edge-density beyond the defined generator, actual PQC cryptography, real Cryptomap/Cryptopolicy wire transfers, native provider integrations, online scanning, approval verification, or service deployments. The benchmark does not demonstrate asymptotic complexity bounds in general; it supplies repeatable evidence within explicit, resource-bounded shapes. Public publishing stays disabled pending FOSS-456 and corrected protection ruleset FOSS-509.
