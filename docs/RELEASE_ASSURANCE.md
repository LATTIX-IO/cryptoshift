# Cryptoshift Release Assurance

The initial FOSS-456 increment establishes an independently reviewable, provenance-attested **release candidate**, not a public release. The crate and repository remain unpublished. No existing GitHub workflow holds a crates.io credential or performs a registry upload, and `publish = false` remains mandatory.

## Release Boundary

A candidate and a published crate are different authorization states. The manual [release candidate workflow](../.github/workflows/release-candidate.yml) may construct an archive, build an SPDX software bill of materials (SBOM), record source content identities, generate unsigned local provenance metadata, and request a **separate GitHub-signed artifact attestation**. This does not authorize a versioned tag, GitHub Release, registry mutation, cryptographic migration, or production use.

## Non-Negotiable Preconditions

The manual workflow accepts an explicit full 40-character protected-main commit, an exact Cargo workspace version and a boolean confirmation. It must:

1. Run only on the original `LATTIX-IO/cryptoshift` repository's `refs/heads/main`, via `workflow_dispatch`. It cannot start on a push, pull request or scheduled job.
2. Verify the actual Git checkout matches the caller-provided commit and Cargo manifest version. Reject short SHAs and mismatched versions.
3. Fetch active main ruleset `24680955`; require explicit branch target `refs/heads/main`, no excluded branch patterns, and an **explicitly visible empty** bypass-actor list (missing metadata blocks qualification). Require strict, independent `Rust checks`, `Rust 1.85 MSRV`, `Supply chain and SemVer`, `Windows Rust stable conformance` and `Windows Rust 1.85.0 conformance`, along with signed commits, linear history, no force-push/deletion, squash-only merges and resolved review threads.
4. Enumerate **all** GitHub Actions check-runs for the exact commit (bounded paginated API response), selecting the latest job by increasing check-run **ID**, not completion timestamp. Require each of the five contexts to be from the official Actions app, bound to the exact commit and repository, and completed successfully. Truncated/missing API data or a newer failed, queued or in-progress run fails closed; an older green run cannot override it.
5. Verify the `publish = false` crate guard remains in place. The workflow contains no registry credentials or publishing action.
6. Execute the FOSS-454 actual-archive offline consumer, then construct a bounded and content-addressed candidate from the generated `.crate`.

The current active ruleset lacks several required checks (FOSS-509), so the release-candidate workflow must **reject** attempted execution until authorized GitHub repository administration corrects it.

## Artifacts and Provenance

An eligible manual run creates these files in `dist/release-candidate/`:

| Artifact | Meaning |
| --- | --- |
| `cryptoshift-<version>.crate` | Source package built from exactly the verified Cargo workspace. |
| `sbom.spdx.json` | SPDX 2.3 package inventory based on Cargo.lock with original registry checksums. Known crates.io registry identifiers map to valid archive download URLs (unrecognized sources are `NOASSERTION`); license fields remain `NOASSERTION` until independently supported by package metadata and `cargo deny`. This is not a license certification. |
| `provenance-unsigned.json` | Unsigned in-toto Statement/SLSA v1-shaped metadata containing pinned source and file SHA-256 material descriptors under `buildDefinition.resolvedDependencies` (not an invalid `materials` field). **Unsigned** metadata is not a source attestation or signed provenance. |
| `CHANGELOG.md` | Reviewed, exact-version draft release notes. |

The **unprivileged candidate job** packages the crate, verifies the protected source and all five checks, then uploads evidence with a pinned artifact action and finite retention. It has `contents:read` and `checks:read` only: **no OIDC or attestation write privilege is present while executing package/dependency build scripts**. A separately isolated **attestation job** depends on successful candidate qualification, downloads the exact candidate with a pinned action, verifies the original job's SHA-256 against the downloaded crate and unsigned provenance subject, and only then invokes pinned `actions/attest-build-provenance` with scoped OIDC and attestation permissions. The attestation job does not check out or execute repository build code.

The SHA-256 identifies bytes; it is not a signature. Validate the GitHub attestation separately and verify the artifact digest locally before trusting the candidate. The workflow's pinned GitHub Actions check-runs and attestation still do not certify external Cryptomap/Cryptopolicy wire compatibility, runtime peer negotiation, PKI authority or safe execution.

## Reproduce and Test

```sh
python3 scripts/release_safety.py --with-cargo
python3 -m unittest scripts.test_release_candidate -v
python3 -m unittest scripts.test_package_consumer_check -v
python3 scripts/package_consumer_check.py
```

The complete five-job exact-head CI remains mandatory; the last command runs an external Cargo client offline, twice, against a real packaged archive. The release-candidate generator is deliberately not invoked from ordinary pull-request CI with registry or signing permissions.

For an authorized main-branch candidate, enter `expected_commit`, `version`, and `confirm_candidate=true` under Actions > Cryptoshift release candidate evidence. The workflow refuses to start a candidate when the branch/ruleset/check-state gate is not satisfied. After success, use the GitHub CLI to independently verify the uploaded subject attestation against `LATTIX-IO/cryptoshift` and the exact commit.

## Publication Hold and Handoff

Candidate preparation does not constitute authorization to publish. Before an actual first crates.io release, separately complete:

- Independent approval of the release version and release notes, the owned registry namespace, API compatibility and any known v1 limitations.
- Verified MSRV, Linux/Windows conformance and fresh-package consumer acceptance at the same exact source commit, dependency security and license scans, and human-reviewed SPDX and provenance artifacts.
- Correct FOSS-509 repository rules, an administratively protected publishing environment, scoped one-use registry credentials, and approval by the authorized release owner.
- A **new reviewed, deliberately authorized publishing change** that removes the literal `publish = false` guard only after the above controls are active. Review the effects on `scripts/release_safety.py` rather than suppressing its checks.
- Independent post-publication verification of the crates.io artifact, version/tag identity and GitHub Release evidence.

Until then, **no registry publish, no release tag, and no public artifact claim** is permitted. Separate local actions and protected environment administration remain release prerequisites, not implicit completed work.
