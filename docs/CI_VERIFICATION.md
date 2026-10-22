# CI verification architecture (FOSS-471)

Five checks must independently succeed for complete protected-main release qualification: **Rust checks**, **Rust 1.85 MSRV**, **Supply chain and SemVer**, **Windows Rust stable conformance**, and **Windows Rust 1.85.0 conformance**. Every required status must be registered in the active main ruleset, with strict up-to-date policy. The current incomplete live ruleset is tracked as FOSS-509 and must be corrected before registry publication. A single green Rust check is never a complete release authorization.

## Independent jobs

- **Rust checks**: release-safety guard, 28 negative/positive configuration regressions, nonpublishing Cargo package inspection, format, compilation, Clippy (`-D warnings`), tests and warning-free rustdoc.
- **Supply chain and SemVer**: version-verified RustSec audit, dependency licensing/source policy via cargo-deny, and API compatibility via cargo-semver-checks. This job runs concurrently, not as an optional step following Rust checks.
- Workflow is read-only by default. Checkout does not persist credentials. There are no publishing credentials and no crates.io publish path. `publish = false` remains mandatory until separately reviewed release work.

## Tool version and cache contract

`cargo-audit=0.22.2`, `cargo-deny=0.20.2` and `cargo-semver-checks=0.51.0` are installed via `cargo install --locked --version` if a verified cache is unavailable. The cache is keyed by the Rust host/compiler and an explicit pinned-version segment (`audit-0.22.2-deny-0.20.2-semver-0.51.0`) so changes to tooling versions invalidate it.

The cached `~/.cargo/bin` entries are checked by executing each tool's `--version` before use. Caches are saved ONLY on a trusted push to protected `main` (`save-if`), never on a pull request, preventing PR branches from seeding the trusted shared tool cache. A PR can restore cache from `main`. The pinned cache action is not dynamically resolved. Without a cache, the job builds all three pinned tools from sources and then executes all audit commands.

The existing Rust workspace cache is separately scoped to its build job and is also saved only from `main`.

FOSS-454 adds source-package acceptance under stable and Rust 1.85. Its checker verifies the actual `.crate` archive and builds a synthetic developer example using a temporary clean-room Cargo project outside the workspace. It uses `--offline` and `--frozen`, checks a fixed semantic golden, and never publishes.

These are compilation caches, not independently signed binary supply-chain attestations. To increase assurance later, replace them with a provenance-attested binary distribution plus verified digest. Current safety relies on protected-main writers, exact tool-version checks and pinned installer inputs.

## Validate from repository root

```bash
python3 scripts/release_safety.py --with-cargo
python3 -m unittest discover -s scripts -p "test_release_safety.py" -v
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
cargo audit
cargo deny check
cargo semver-checks check-release --workspace --all-features
```

Expected: all exit zero; two CI jobs succeed. Negative regressions must fail if either job/mandatory step is disabled, made nonfatal, or replaced with an echo command; weakening the publication guard or allowing PR cache writes must also fail.

## Observability and acceptance

Baseline single-job Rust CI on `main`: [run #38969570693](https://github.com/LATTIX-IO/cryptoshift/actions/runs/38969570693). Final exact-head prior release: [run #38970105468](https://github.com/LATTIX-IO/cryptoshift/actions/runs/38970105468). These installed cargo tools serially on every clean runner and delayed audit execution.

Record both **cold** (empty cache) and **warm** (`main` cache available) job start/end times from GitHub's job page after this PR runs. There is no benchmark claim until both have actually executed. Fail closed if cache unavailable; do not make elapsed time a release gate.

**Administration**: GitHub branch rules are not configured by this PR. Require `Rust checks` and `Supply chain and SemVer` in repo settings, and keep review-thread resolution, signed commits and protected `main` where available.
