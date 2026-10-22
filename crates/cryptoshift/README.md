# cryptoshift

The `cryptoshift` crate is part of the Lattix open-source ecosystem. Its public API is an offline, non-executing cryptographic migration planner.

This crate currently provides development-only Rust contracts for inventory,
immutable graphs, explainable risk, approved target and capability profiles,
evidence-bound peer, protocol and PKI compatibility, and non-executing blocker
and remediation analysis, bounded nonauthorizing SCC wave drafts, immutable migration plan proposals
with source-pinned residual risk and unverified exception claims, and independent neutral
inventory/ChangeSet/policy-result fixture contracts.
It produces advisory migration plan drafts but does **not** authenticate external
cryptographic proofs, upstream native wire formats, exception approvals,
or authorize infrastructure changes. It remains unpublished with `publish = false`; the first public release requires separately approved release work (FOSS-456). Public `Complete` and `Warnings` outcomes are reserved and not emitted by the v1 runner while capability evidence is unverified.

The [API reference and getting started guide](https://github.com/LATTIX-IO/cryptoshift/blob/main/docs/GETTING_STARTED.md) describes the end-to-end example and separately packaged Cargo consumer. The example is read-only and never authorizes migration.

Repository: https://github.com/LATTIX-IO/cryptoshift

## License

Licensed under either Apache-2.0 or MIT, at your option.
