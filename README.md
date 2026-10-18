# cryptoshift

Cryptographic migration planning and post-quantum transition tooling.

Maintained by Lattix Technologies Corp.

Project website: https://lattix.io

## Status

This project is an **unpublished development workspace** with versioned Rust
contracts for inventory, cryptographic dependency topology, risk, target
profiles, product capabilities, conservative peer compatibility, and advisory
source-attributed SCC remediation actions.
It does **not yet generate a full MigrationPlan** or authenticate protocol/PKI
proofs. No public crates.io release is authorized.

## Crates

- cryptoshift — offline evidence-bound analysis library (unpublished)

## Acceptance examples

    cargo run -p cryptoshift --example capability_catalog --locked
    cargo run -p cryptoshift --example peer_compatibility --locked
    cargo run -p cryptoshift --example remediation_actions --locked

See the [peer compatibility contract](docs/PEER_COMPATIBILITY.md) and [remediation action contract](docs/REMEDIATION_ACTIONS.md) for evidence and authorization limitations.

## Development

    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-features --locked

## Release safety

All workspace crate manifests explicitly declare `publish = false`. Release-plz
is **manual, release-PR preparation only**, with an explicit confirmation input
and only from `main`. Neither the workflow nor normal pushes publish packages
or receive crates.io publishing credentials.

Run the safety and negative regression checks using Python 3.11+ and Rust:

    python3 scripts/release_safety.py --with-cargo
    python3 -m unittest discover -s scripts -p "test_release_safety.py" -v
    cargo package --locked --list -p cryptoshift

The package listing is a non-publishing inspection, not a publication test.

Before a future release, FOSS-456 must define controlled publishing with
appropriate environment approvals, validate package ownership on crates.io,
complete API and documentation, MSRV and clean-room consumer verification,
security scans, SBOM and provenance, and deliberately change both the manifest
and release guard in a reviewed release PR. No release is authorized by FOSS-414.

Repository-local configuration checks do not substitute for administrative
branch protections or protected GitHub environments.

## License

Licensed under Apache-2.0 or MIT, at your option.
