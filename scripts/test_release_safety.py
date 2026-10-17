"""Release safety config regression tests."""
from pathlib import Path
import tempfile
import unittest
from release_safety import check_repository

class ReleaseSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.put("Cargo.toml", '[workspace]\nmembers = ["crates/cryptoshift"]\n')
        self.put("crates/cryptoshift/Cargo.toml", '[package]\nname = "cryptoshift"\nversion = "0.1.0"\npublish = false\n')
        for workflow in (".github/workflows/ci.yml", ".github/workflows/release-plz.yml"):
            self.put(workflow, (Path(__file__).resolve().parents[1] / workflow).read_text(encoding="utf-8"))

    def put(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def mutate(self, path, source, replacement):
        target = self.root / path
        content = target.read_text()
        self.assertIn(source, content)
        self.put(path, content.replace(source, replacement))

    def reject(self, marker):
        result = check_repository(self.root)
        self.assertTrue(any(marker in problem for problem in result), result)

    def test_safe(self):
        """Regression scenario: safe."""
        self.assertEqual(check_repository(self.root), [])

    def test_publish_allowlist(self):
        """Regression scenario: publish allowlist."""
        self.mutate("crates/cryptoshift/Cargo.toml", "publish = false", 'publish = ["crates-io"]')
        self.reject("publish = false")

    def test_missing_publish(self):
        """Regression scenario: missing publish."""
        self.mutate("crates/cryptoshift/Cargo.toml", "publish = false", "")
        self.reject("publish = false")

    def test_new_member(self):
        """Regression scenario: new member."""
        self.mutate("Cargo.toml", '["crates/cryptoshift"]', '["crates/cryptoshift", "crates/extra"]')
        self.put("crates/extra/Cargo.toml", '[package]\nname = "extra"\nversion = "0.1.0"\n')
        self.reject("crates/extra/Cargo.toml")

    def test_push_trigger(self):
        """Regression scenario: push trigger."""
        self.mutate(".github/workflows/release-plz.yml", "on:\n  workflow_dispatch:", "on:\n  push:\n    branches: [main]\n  workflow_dispatch:")
        self.reject("only trigger")

    def test_release_job(self):
        """Regression scenario: release job."""
        p = ".github/workflows/release-plz.yml"
        self.put(p, (self.root / p).read_text() + "  release-plz-release:\n    runs-on: ubuntu-latest\n")
        self.reject("only prepare release PRs")

    def test_release_command(self):
        """Regression scenario: release command."""
        self.mutate(".github/workflows/release-plz.yml", "command: release-pr", "command: release")
        self.reject("publishing command")

    def test_cargo_publish(self):
        """Regression scenario: cargo publish."""
        self.put(".github/workflows/unsafe.yml", "jobs:\n  bad:\n    steps:\n      - run: cargo publish --token fake\n")
        self.reject("publishing command")

    def test_registry_credentials(self):
        """Regression scenario: registry credentials."""
        p = ".github/workflows/release-plz.yml"
        self.put(p, (self.root / p).read_text() + "# CARGO_REGISTRY_TOKEN\n")
        self.reject("registry publishing token")

    def test_manual_confirmation(self):
        """Regression scenario: manual confirmation."""
        self.mutate(".github/workflows/release-plz.yml", "inputs.prepare_release_pr", "true")
        self.reject("require confirmation")

    def test_ci_guard(self):
        """Regression scenario: ci guard."""
        self.mutate(".github/workflows/ci.yml", "python3 scripts/release_safety.py --with-cargo", "echo skipped")
        self.reject("CI must enforce")

    def test_release_action_requires_verified_v05142_commit(self):
        """A floating or unreviewed pinned release-plz action is prohibited."""
        self.mutate(".github/workflows/release-plz.yml", "release-plz/action@8921286633dfa0c4020f7f30bd1c14fe19cbb10e", "release-plz/action@0000000000000000000000000000000000000000")
        self.reject("Release-plz action must use the reviewed pinned SHA")

    def test_release_action_does_not_accept_floating_tags(self):
        """A version-looking tag is not an immutable execution commitment."""
        self.mutate(".github/workflows/release-plz.yml", "release-plz/action@8921286633dfa0c4020f7f30bd1c14fe19cbb10e", "release-plz/action@v0.5.142")
        self.reject("Release-plz action must use the reviewed pinned SHA")

    def test_release_action_separation(self):
        """Regression scenario: release action separation."""
        self.put(".github/workflows/unsafe.yml", "jobs:\n  bad:\n    steps:\n      - uses: release-plz/action@abcdef\n")
        self.reject("outside the guarded workflow")


    def test_or_condition_bypass(self):
        """Never substitute OR for the independent release confirmation."""
        self.mutate(".github/workflows/release-plz.yml", " && inputs.prepare_release_pr }}", " || inputs.prepare_release_pr }}")
        self.reject("require confirmation")

    def test_wrong_branch_condition(self):
        """Reject manually confirmed runs on branches other than main."""
        self.mutate(".github/workflows/release-plz.yml", "refs/heads/main", "refs/heads/other")
        self.reject("require confirmation")

    def test_wrong_owner_condition(self):
        """A release proposal must require the original organization."""
        self.mutate(".github/workflows/release-plz.yml", "repository_owner == 'LATTIX-IO'", "repository_owner != 'LATTIX-IO'")
        self.reject("require confirmation")

    def test_disabled_guard_step(self):
        """A present but conditionally skipped safety step is not enough."""
        self.mutate(".github/workflows/ci.yml", "- name: Reject unsafe release settings\n        run:", "- name: Reject unsafe release settings\n        if: false\n        run:")
        self.reject("CI must enforce")

    def test_disabled_guard_job(self):
        """A job-level condition cannot disable mandatory release checks."""
        self.mutate(".github/workflows/ci.yml", "  rust-checks:\n    name:", "  rust-checks:\n    if: false\n    name:")
        self.reject("CI must enforce")

    def test_guard_continue_on_error(self):
        """CI cannot ignore publication-guard failures."""
        self.mutate(".github/workflows/ci.yml", "- name: Reject unsafe release settings\n        run:", "- name: Reject unsafe release settings\n        continue-on-error: true\n        run:")
        self.reject("CI must enforce")

    def test_quoted_test_command_is_not_executable(self):
        """Merely printing the unit test command does not execute it."""
        self.mutate(".github/workflows/ci.yml", 'run: python3 -m unittest discover -s scripts -p "test_release_safety.py" -v', 'run: echo python3 -m unittest discover -s scripts -p "test_release_safety.py" -v')
        self.reject("CI must execute release safety regression tests")

    def test_disabled_regression_test_step(self):
        """Negative regression tests must be part of the executed CI job."""
        self.mutate(".github/workflows/ci.yml", "- name: Release safety regression tests\n        run:", "- name: Release safety regression tests\n        if: false\n        run:")
        self.reject("CI must execute release safety regression tests")

    def test_missing_supply_chain_job(self):
        """Removing independent supply-chain verification must fail closed."""
        self.mutate(".github/workflows/ci.yml", "  supply-chain:", "  removed-supply-chain:")
        self.reject("Supply-chain CI must execute RustSec audit")

    def test_disabled_supply_chain_job(self):
        """Skipping the entire audit job is not an acceptable optimization."""
        self.mutate(".github/workflows/ci.yml", "  supply-chain:\n    name:", "  supply-chain:\n    if: false\n    name:")
        self.reject("Supply-chain CI must execute RustSec audit")

    def test_disabled_rustsec_step(self):
        """Presence of an audit command alone is insufficient."""
        self.mutate(".github/workflows/ci.yml", "- name: RustSec audit\n        run:", "- name: RustSec audit\n        if: false\n        run:")
        self.reject("Supply-chain CI must execute RustSec audit")

    def test_disabled_deny_step(self):
        """Dependency policy cannot be silenced."""
        self.mutate(".github/workflows/ci.yml", "- name: Dependency policy\n        run:", "- name: Dependency policy\n        continue-on-error: true\n        run:")
        self.reject("Supply-chain CI must execute Dependency policy")

    def test_skipped_semver_step(self):
        """SemVer checks are independently required."""
        self.mutate(".github/workflows/ci.yml", "run: cargo semver-checks check-release --workspace --all-features", "run: echo skipped")
        self.reject("Supply-chain CI must execute SemVer compatibility")

    def test_untrusted_pull_request_cache_write(self):
        """Untrusted pull requests cannot populate the main audit tool cache."""
        expected = "save-if: $" + "{{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
        self.mutate(".github/workflows/ci.yml", expected, "save-if: true")
        self.reject("Supply-chain cache must only be writable")

    def test_cache_key_must_include_pinned_versions(self):
        """A cache from older audit tooling cannot silently substitute."""
        self.mutate(".github/workflows/ci.yml", "audit-0.22.2-deny-0.20.2-semver-0.51.0", "audit-floating")
        self.reject("Audit tool versions must have")

    def test_audit_cache_action_must_remain_pinned(self):
        """The audit job cannot use a floating action revision."""
        ci = (self.root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        needle = "uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6"
        self.assertEqual(ci.count(needle), 2)
        self.put(".github/workflows/ci.yml", ci.replace(needle, "uses: Swatinem/rust-cache@v2"))
        self.reject("Audit tool cache must use the pinned trusted action")

    def test_old_cache_action_pin_rejected(self):
        """Previously reviewed SHA is not automatically trusted after bump."""
        self.mutate(".github/workflows/ci.yml", "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6", "Swatinem/rust-cache@258712b0b7b1ddf8bddc9fc3b0faca682b2736c3")
        self.reject("Audit tool cache must use the pinned trusted action")

    def test_upstream_master_is_not_the_verified_release(self):
        """Reject the bot's untagged moving-master SHA."""
        self.mutate(".github/workflows/ci.yml", "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6", "Swatinem/rust-cache@f0d9c3887740aee45f6153b24b3a6b815192ec16")
        self.reject("Audit tool cache must use the pinned trusted action")

    def test_rust_build_cache_must_match_audit_cache_pin(self):
        """An independently swapped build-cache action is not trusted."""
        path = ".github/workflows/ci.yml"
        ci = (self.root / path).read_text(encoding="utf-8")
        sha = "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6"
        self.assertEqual(ci.count(sha), 2)
        self.put(path, ci.replace(sha, "Swatinem/rust-cache@258712b0b7b1ddf8bddc9fc3b0faca682b2736c3", 1))
        self.reject("Rust build cache must use the pinned trusted action")

    def test_rust_build_cache_write_is_main_only(self):
        """PR cache writing cannot be unlocked while audit cache stays fenced."""
        path = ".github/workflows/ci.yml"
        ci = (self.root / path).read_text(encoding="utf-8")
        expected = "save-if: $" + "{{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
        self.assertEqual(ci.count(expected), 2)
        self.put(path, ci.replace(expected, "save-if: true", 1))
        self.reject("Rust build cache must only be writable")

    def test_cache_policy_not_satisfied_by_unrelated_step(self):
        """Only inputs of the pinned cache action can authorize cache writes."""
        path = ".github/workflows/ci.yml"
        ci = (self.root / path).read_text(encoding="utf-8")
        expected = "save-if: $" + "{{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
        pos = ci.index("  supply-chain:")
        before, supply = ci[:pos], ci[pos:]
        self.assertIn(expected, supply)
        supply = supply.replace(expected, "save-if: true", 1)
        supply += "\n      - name: Ignored decoy\n        with:\n          " + expected + "\n"
        self.put(path, before + supply)
        self.reject("Supply-chain cache must only be writable")

    def test_job_level_permission_escalation(self):
        """A write token on the auditing job violates the read-only policy."""
        self.mutate(
            ".github/workflows/ci.yml",
            "  supply-chain:\n    name:",
            "  supply-chain:\n    permissions: write-all\n    name:",
        )
        self.reject("CI requires read-only workflow permissions")

    def test_top_level_write_all_permission(self):
        """A misleading contents: read elsewhere cannot replace the top-level policy."""
        self.mutate(
            ".github/workflows/ci.yml",
            "permissions:\n  contents: read\n",
            "permissions: write-all\n",
        )
        self.reject("CI requires read-only workflow permissions")

