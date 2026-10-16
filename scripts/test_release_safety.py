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
        self.put(".github/workflows/ci.yml", 'name: CI\non:\n  pull_request:\n\njobs:\n  checks:\n    steps:\n      - name: Guard\n        run: python3 scripts/release_safety.py --with-cargo\n      - name: Tests\n        run: python3 -m unittest discover -s scripts -p "test_release_safety.py" -v\n')
        self.put(".github/workflows/release-plz.yml", """on:
  workflow_dispatch:
    inputs:
      prepare_release_pr:
        type: boolean
permissions:
  contents: read
jobs:
  release-plz-pr:
    if: PLACEHOLDER
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10
        with:
          persist-credentials: false
      - uses: release-plz/action@d529f731ae3e89610ada96eda34e5c6ba3b12214
        with:
          command: release-pr
""".replace("PLACEHOLDER", "github.ref == 'refs/heads/main' && inputs.prepare_release_pr"))

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
        self.assertEqual(check_repository(self.root), [])

    def test_publish_allowlist(self):
        self.mutate("crates/cryptoshift/Cargo.toml", "publish = false", 'publish = ["crates-io"]')
        self.reject("publish = false")

    def test_missing_publish(self):
        self.mutate("crates/cryptoshift/Cargo.toml", "publish = false", "")
        self.reject("publish = false")

    def test_new_member(self):
        self.mutate("Cargo.toml", '["crates/cryptoshift"]', '["crates/cryptoshift", "crates/extra"]')
        self.put("crates/extra/Cargo.toml", '[package]\nname = "extra"\nversion = "0.1.0"\n')
        self.reject("crates/extra/Cargo.toml")

    def test_push_trigger(self):
        self.mutate(".github/workflows/release-plz.yml", "on:\n  workflow_dispatch:", "on:\n  push:\n    branches: [main]\n  workflow_dispatch:")
        self.reject("only trigger")

    def test_release_job(self):
        p = ".github/workflows/release-plz.yml"
        self.put(p, (self.root / p).read_text() + "  release-plz-release:\n    runs-on: ubuntu-latest\n")
        self.reject("only prepare release PRs")

    def test_release_command(self):
        self.mutate(".github/workflows/release-plz.yml", "command: release-pr", "command: release")
        self.reject("publishing command")

    def test_cargo_publish(self):
        self.put(".github/workflows/unsafe.yml", "jobs:\n  bad:\n    steps:\n      - run: cargo publish --token fake\n")
        self.reject("publishing command")

    def test_registry_credentials(self):
        p = ".github/workflows/release-plz.yml"
        self.put(p, (self.root / p).read_text() + "# CARGO_REGISTRY_TOKEN\n")
        self.reject("registry publishing token")

    def test_manual_confirmation(self):
        self.mutate(".github/workflows/release-plz.yml", "inputs.prepare_release_pr", "true")
        self.reject("require confirmation")

    def test_ci_guard(self):
        self.mutate(".github/workflows/ci.yml", "python3 scripts/release_safety.py --with-cargo", "echo skipped")
        self.reject("CI must enforce")

    def test_release_action_separation(self):
        self.put(".github/workflows/unsafe.yml", "jobs:\n  bad:\n    steps:\n      - uses: release-plz/action@abcdef\n")
        self.reject("outside the guarded workflow")
