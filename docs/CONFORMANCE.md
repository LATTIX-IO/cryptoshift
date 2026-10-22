# FOSS-448 — Gate E2 synthetic enterprise conformance

This test-only v1 corpus exercises Cryptoshift's existing **public Rust API**, not a native Cryptomap or Cryptopolicy interchange. The source artifacts are synthetic and **not authenticated**. Hashes are content identities, never trust anchors. No sockets, live certificate checks, production tenants, secrets, or migration execution occur.

## Versioned corpus and provenance

`tests/conformance/v1/scenarios.tsv` is a deliberately strict seven-column versioned source fixture. Each scenario fixes a tenant (`synthetic-enterprise`), a producer (`synthetic-collector`), revision `r1`, and UTC Unix evaluation time `1800000000`. The Rust acceptance runner rejects unknown schema versions, record counts, or enum strings. Synthetic content records carry source-local evidence, collection completeness and observation classification. The frozen `full_pipeline.golden` is an output **regression** pin, not an independently authenticated source digest.

| Scenario | Sources | Expected security outcome |
|---|---|---|
| transport | configured ML-KEM-1024 and separately source-claimed negotiated use | configured does not authenticate negotiated peer exchange; Unknown/Conditional only |
| pki | legacy RSA inventory, X.509 certificate/trust anchor graph links | graph chain is not certificate validation or revocation |
| codesign | ML-DSA-87 signing use-site | algorithm recognition cannot authenticate an image or firmware signature |
| kms | classical RSA inventory, HSM / key / data asset dependency graph | vendor HSM claims are not deployed runtime proof |
| vendor | inferred library-capability from partial collection | partial coverage cannot authorize removals; product advertised support is not readiness |

The graph also includes an edge-gateway/cloud-kms dependency cycle. E2 must preserve the SCC as one indivisible migration candidate and propagate opaque evidence IDs, blockers, unverified readiness and residual risk through wave and immutable plan drafts. Policy `PermitClaimed` must remain `Unverified`; explicit target prohibition must remain `Prohibited`.

## Replay

Run from the workspace root:

```sh
cargo test --locked -p cryptoshift --test conformance_v1
cargo test --locked -p cryptoshift --test conformance_v1 -- seeded_permutations
cargo run --frozen --manifest-path acceptance/neutral-consumer/Cargo.toml
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
```

The frozen manifest includes source SHA-256 plus inventory, graph, handoff, risk, topology, target, policy, vendor catalogs, compatibility, remediation, wave and final plan hashes, with typed states/counts. If it changes, compare each changed pin and source fact, then review and deliberately update the golden with independent acceptance. Do not regenerate expected content inside tests.

## Requirement-to-test traceability

| Invariant | Test |
|---|---|
| Enterprise transport/PKI/signing/HSM/vendor → neutral source → graph → SCC → risk → target → compatibility → remediation → waves → plan | `complete_enterprise_pipeline_matches_reviewed_full_phase_golden` |
| Equivalent source record insertion order, reproducible Rust outputs | `seeded_permutations_preserve_full_phase_canonical_bytes` |
| Changed source fact rotates inventory/graph/plan and reports typed semantic change | `source_mutation_rotates_pins_and_produces_typed_semantic_diff` |
| Import, graph, parser, planning and output budgets | `bounded_planning_and_source_export_reject_smaller_consumer_budgets`, `deterministic_bounded_parser_mutations_never_treat_framing_as_schema_validation` |
| Forged target pin, unsupported downgrade/hybrid, wrong tenant, unproven negotiation | `invalid_and_untrusted_evidence_does_not_upgrade_authority` |
| Truncated source, unreviewed major/minor, expired profile, policy forgery | `schema_digest_expiry_and_policy_claim_tampering_fail_closed` |
| Existing absence/provenance/profile replay hardening | `neutral_inventory_contract`, `neutral_policy_contract` |

## Limitations

The E2 test suite does not validate real wire-level Cryptomap/Cryptopolicy JSON, verify producer signatures, authenticate revocation/handshake assertions, implement a cryptographic signature verifier, execute migrations, benchmark large-scale performance or authorize releases. Those are separate contracts or Gate F work. Limits default to a 4 MiB input, 50,000 nodes, 250,000 edges, 20,000 planner candidates and 16 MiB output; this corpus forces smaller budgets to verify safe rejection. Publishing remains `false`.
