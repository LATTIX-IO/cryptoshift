# Cryptoshift threat model — foundational admission boundary

Status: foundational SDD for FOSS-416; **not** a statement that a production
migration planner or secure serialization adapter already exists.

## Assets and security objectives

- The integrity of an organization's source inventory, asserted cryptographic
  capabilities, standards versions, and mandatory target-state policy.
- The authenticity, freshness, and traceability of the evidence used to make
  recommendations (a source ID alone is not an authenticity assertion).
- Deterministic migration findings, blockers, and safe readiness gates.
- Processing capacity: external inputs must not exhaust CPU, memory, or output
  budgets or crash a long-running analysis host.
- Confidentiality: errors and operational metrics must not contain supplied
  inventory secrets, credentials, or data assets.

Cryptoshift is an offline analyzer. It must not discover assets over the network,
execute migrations, produce cryptographic operations, override cryptopolicy, or
write to production environments.

## Trust boundaries and attacker-controlled surfaces

| Boundary | Untrusted material | Threat | Foundation control |
| --- | --- | --- | --- |
| Cryptomap or alternate import | Raw inventory bytes, claimed source, topology | Oversized, deceptive, incomplete or duplicate observations | Byte limit, explicit provenance, schema-version preflight; domain validation deferred to FOSS-418 |
| Cryptopolicy target handoff | Claimed target/profile metadata | Downgrade by unknown revision or implicit relaxation of a hard requirement | Exact-version rejection; policy semantics deferred to planner increments |
| Standards/vendor capability catalog | Version, freshness, provider and product claims | Roadmap claim represented as verified runtime support, stale critical profile | Explicit critical version and expiry checks; no assertion of capability authenticity |
| Graph and planner internals | Node/edge counts, dependencies, candidate paths | Graph explosion, cycles, integer overflow, memory pressure | Shared configurable limits with hard ceilings and checked arithmetic; graph analysis deferred |
| Results, logs and exports | Diagnostic text and future remediation plans | Sensitive evidence exposure and fabricated plan readiness | Diagnostics use static phrases and numeric counts only; export verification deferred |
| GitHub Actions/release | Workflow dispatch and workspace manifests | Premature crates.io release | FOSS-414 publication guard (separate stacked dependency) |

## Threat scenarios and explicit mitigations

1. **Oversize document:** Check raw byte size before calling a parser.
   Oversized values reject with `CSHIFT_RESOURCE_LIMIT_EXCEEDED`.
2. **Nested structured document:** JSON-like adapters can preflight balanced
   brackets and quoted-string nesting without unbounded recursion. A parser
   must separately charge `ParseBudget` for *every* value and container before
   allocation, then perform full syntax and schema validation.
3. **Integer overflow or counter wrap:** All cumulative counters use checked
   addition/multiplication. Overflow rejects with `CSHIFT_ARITHMETIC_OVERFLOW`.
4. **Invalid limit configuration:** Zero or above-ceiling limits reject before
   processing, preventing an importer's unbounded or disabled controls.
5. **Unknown/unsupported critical schema:** An outer version other than v1.0
   rejects; even future minor versions are not silently treated as compatible.
6. **Expired profile:** Critical referenced profile expiry is evaluated using
   the caller-supplied Unix timestamp, never system time or implicit defaults.
   Expiry at or before the evaluation instant rejects.
7. **Missing attribution or malformed identifier:** Reject blank, control-
   containing, or oversized identifiers. A well-formed attribution does **not**
   mean a signed or trustworthy observation.
8. **Error-message leakage:** Diagnostic constructors use static domain and
   reason text plus numeric counters; imported content is not interpolated.

## Trust decisions and non-goals

- `preflight` only checks outer metadata and serialized byte counts. Its return
  type is deliberately `PreflightedEnvelope`, **not** `ValidatedInventory`.
- `preflight_json_nesting` is only a bounded *structure scanner*, not a JSON
  parser. It may accept syntactically invalid JSON and must not be used to
  authorize any data, policy decision, or migration action.
- Unknown cryptographic algorithms, product profiles, key capabilities, and
  unverified signatures cannot be asserted safe based on this increment.
- Source metadata is not a cryptographic signature, trusted attestation, or
  identity proof. Signature verification and trust-anchor configuration belong
  in later adapters and deployment integration.
- A plan must ultimately bind immutable inventory, target, scoring, standards,
  capability, and planner versions; FOSS-416 does **not** create such plans.
- No telemetry feature is implemented. Future metrics must be aggregate-only
  and use typed diagnostic codes rather than imported payload text.

## Residual risks / required follow-up

- **FOSS-418:** Validate actual inventory payload schemas, observations,
  evidence semantics, immutable snapshots/digests, redacted export and change
  completeness; round-trip fixture contracts with Cryptomap.
- **FOSS-430/436/438:** Author authoritative target and capability catalogs,
  actual revision compatibility, protocol-specific transitions and provenance.
- **FOSS-441/442/444:** Enforce immutable hard policy, evidence-backed gates,
  deterministic plan identity, blocked/unknown state and residual risk.
- **FOSS-448:** Fuzz real input parsers and graph/planner caps, run cross-project
  conformance suites and hostile fixture regression.
- **FOSS-450/456:** Stable diagnostics, structured observability, sustained
  benchmarks, managed release approvals and provenance.

## Security test traceability

| Attack/invariant | Test location |
| --- | --- |
| Invalid and above-ceiling resource budgets | `limits::tests::zero_and_above_ceiling_are_invalid` |
| Overflow on counts | `limits::tests::overflow_is_not_a_zero_or_saturated_count` |
| Deep nesting and token limits | `limits::tests::parser_budget_rejects_nesting_and_does_not_advance_after_failure` |
| Deterministic budget under adversarial counts | `limits::tests::limits_reject_attack_like_count_sequence` |
| Unknown major/minor revision | `envelope::tests::unsupported_minor_and_major_versions_fail_closed` |
| Oversize, empty, unattributed document | `envelope::tests::empty_oversize_and_missing_source_fail_closed` |
| Confidential error context | `envelope::tests::invalid_identifier_does_not_echo_source` |
| Expired and unsupported critical profile | `envelope::tests::critical_profiles_require_valid_version_and_freshness` |
| External public-Rust client | `tests/preflight_consumer.rs` |

Each future format adapter must independently demonstrate payload-level parsing,
input-type correctness, negative fixtures and version interoperability before
being described as a validated source.
