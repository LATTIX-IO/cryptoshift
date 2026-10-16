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

