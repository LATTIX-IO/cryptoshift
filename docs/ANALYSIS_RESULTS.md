# FOSS-450 — Atomic analysis and redacted diagnostics (v1)

Cryptoshift now exposes an **offline, all-or-nothing** analysis entry point. It produces one immutable `MigrationPlanDraft` only after topology, risk, remediation, advisory waves, plan building and active export-budget checks have all succeeded. The orchestrator never executes, authorizes or approves migration changes.

## Contract

`AnalysisRunner::analyze(&AnalysisRequest, &Limits) -> AnalysisResult` owns temporary phase products until the final pinned draft is validated. Consumers must provide **independently obtained expected inventory, graph and target digests**. Computing them from the same untrusted input as a fixture is useful only for regression, never publisher authentication. This contract does not decode native Cryptomap/Cryptopolicy transport and does not verify external policy, protocol handshakes, PKI, exception approval or vendor capability.

`AnalysisResult::outcome()` is one of:

| Outcome | Meaning |
| --- | --- |
| `Complete` | All modeled evidence is complete **for independent review**, with no residual-risk facets; never authorization |
| `Warnings` | Complete evidence-for-review state but disclosed unresolved residual risks |
| `Partial` | Missing source evidence or independent approval; not deployable |
| `Infeasible` | A hard policy/contradiction blocks the draft; not deployable |
| `Failed` | Validation or computation rejected the request; **no plan is returned** |

A `Failed` result has `plan() == None`, `metrics() == None`, an immutable source-safe `Diagnostic` at `failure()`, and one `ValidationFailed` finding with the stage that failed. No intermediate topology, risk result, candidate waves or plan is exposed. Successful results contain one immutable plan and at most one deterministic status finding. The `findings()` codes are static identifiers; text and log output never copy user-provided source values.

`AnalysisRequest` does not infer external trust. Every required digest must come from the host's independently verified channel; the library's SHA-256 identifiers only bind content. The caller supplies an explicit UTC evaluation instant. Existing phase validators recheck scope, schema, freshness, compatibility and all resource limits.

## Safe, optional observability

Set `include_metrics: true` to obtain `AnalysisMetrics`, a deterministic aggregate count-only record of observations, graph nodes/edges, migration units, risk vectors, blockers, waves and residual risks. This is **not** tracing, event data, timings or per-tenant logging. Metrics are absent on a failed run and on all requests where the flag is false. Do not transmit counts outside an approved telemetry boundary without host-side authorization.

## Independent consumer and adversarial acceptance

The detached package-path Cargo consumer in `acceptance/neutral-consumer` uses this public API with a synthetic fixture, checks stable plan identity across repeated analyses, verifies the flag-controlled metrics, and substitutes a forged graph digest to show the run rejects the input **with no committed plan or metrics**. Its self-generated expected hashes are explicitly not independently authenticated.

Run from the repository root:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo run --frozen --manifest-path acceptance/neutral-consumer/Cargo.toml
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
```

The publication guard `publish = false` remains mandatory. FOSS-453 measures large-case performance; FOSS-454 completes public API/packaged-client adoption; FOSS-456 owns SBOM, provenance and explicit release authorization.
