"""Negative release-candidate governance and provenance configuration tests."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest

from release_candidate import (
    REQUIRED,
    check_run_errors,
    ruleset_errors,
    sbom,
    provenance_statement,
    workflow_errors,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release-candidate.yml"
TEST_COMMIT = "a" * 40


def valid_ruleset() -> dict:
    return {
        "enforcement": "active",
        "target": "branch",
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "bypass_actors": [],
        "rules": [
            {"type": name}
            for name in ("deletion", "non_fast_forward", "required_linear_history", "required_signatures")
        ] + [
            {
                "type": "pull_request",
                "parameters": {
                    "required_review_thread_resolution": True,
                    "allowed_merge_methods": ["squash"],
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [{"context": name} for name in sorted(REQUIRED)],
                },
            },
        ],
    }


def valid_checkruns() -> dict:
    return {
        "total_count": len(REQUIRED),
        "check_runs": [
            {
                "id": 1000 + index,
                "head_sha": TEST_COMMIT,
                "name": name,
                "app": {"slug": "github-actions"},
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-10-21T10:00:00Z",
                "completed_at": "2026-10-21T10:01:00Z",
                "details_url": "https://github.com/LATTIX-IO/cryptoshift/actions/runs/123",
            }
            for index, name in enumerate(sorted(REQUIRED))
        ]
    }


class CandidateGateTests(unittest.TestCase):
    def test_valid_protections(self) -> None:
        self.assertEqual(ruleset_errors(valid_ruleset()), [])
        self.assertEqual(check_run_errors(valid_checkruns(), TEST_COMMIT), [])

    def test_each_missing_required_status_fails(self) -> None:
        for missing in REQUIRED:
            with self.subTest(missing=missing):
                rules = valid_ruleset()
                entries = rules["rules"][-1]["parameters"]["required_status_checks"]
                rules["rules"][-1]["parameters"]["required_status_checks"] = [
                    item for item in entries if item["context"] != missing
                ]
                self.assertTrue(ruleset_errors(rules))
                checkruns = valid_checkruns()
                checkruns["check_runs"] = [
                    item for item in checkruns["check_runs"] if item["name"] != missing
                ]
                self.assertTrue(check_run_errors(checkruns, TEST_COMMIT))

    def test_non_strict_or_unsigned_main_rejected(self) -> None:
        rules = valid_ruleset()
        rules["rules"][-1]["parameters"]["strict_required_status_checks_policy"] = False
        self.assertTrue(ruleset_errors(rules))
        rules = valid_ruleset()
        rules["rules"] = [x for x in rules["rules"] if x["type"] != "required_signatures"]
        self.assertTrue(ruleset_errors(rules))

    def test_explicit_bypass_actors_rejected(self) -> None:
        rules = valid_ruleset()
        rules["bypass_actors"] = [{"actor_id": 42, "actor_type": "Team", "bypass_mode": "always"}]
        self.assertTrue(ruleset_errors(rules))

    def test_review_bypass_and_other_merge_method_rejected(self) -> None:
        rules = valid_ruleset()
        review = next(x for x in rules["rules"] if x["type"] == "pull_request")
        review["parameters"]["required_review_thread_resolution"] = False
        self.assertTrue(ruleset_errors(rules))
        review["parameters"]["required_review_thread_resolution"] = True
        review["parameters"]["allowed_merge_methods"] = ["merge", "squash"]
        self.assertTrue(ruleset_errors(rules))

    def test_forged_or_stale_check_cannot_override_last_failure(self) -> None:
        payload = valid_checkruns()
        # Older success finishes after the newer failed run. Created ID
        # wins, even though the older completion timestamp is later.
        original = payload["check_runs"][0]
        original["completed_at"] = "2026-10-21T10:30:00Z"
        payload["check_runs"].append({
            **deepcopy(original),
            "id": 9000,
            "conclusion": "failure",
            "completed_at": "2026-10-21T10:05:00Z",
        })
        payload["total_count"] += 1
        self.assertTrue(check_run_errors(payload, TEST_COMMIT))
        payload["check_runs"][-1]["status"] = "queued"
        payload["check_runs"][-1]["conclusion"] = None
        payload["check_runs"][-1]["started_at"] = None
        payload["check_runs"][-1]["completed_at"] = None
        self.assertTrue(check_run_errors(payload, TEST_COMMIT))
        payload["check_runs"][-1]["app"] = {"slug": "untrusted-bot"}
        self.assertEqual(check_run_errors(payload, TEST_COMMIT), [])

    def test_main_ruleset_scope_and_bypass_visibility_are_mandatory(self) -> None:
        for corrupt in (
            lambda r: r.pop("target"),
            lambda r: r.update(target="tag"),
            lambda r: r.pop("conditions"),
            lambda r: r["conditions"]["ref_name"].update(include=["refs/heads/release"]),
            lambda r: r["conditions"]["ref_name"].update(include=["~DEFAULT_BRANCH"]),
            lambda r: r["conditions"]["ref_name"].update(exclude=["refs/heads/main"]),
            lambda r: r.pop("bypass_actors"),
            lambda r: r.update(bypass_actors=None),
        ):
            rules = valid_ruleset()
            corrupt(rules)
            self.assertTrue(ruleset_errors(rules))

    def test_checks_require_untruncated_exact_head_official_run_ids(self) -> None:
        for corrupt in (
            lambda x: x.update(total_count=99),
            lambda x: x["check_runs"][0].pop("id"),
            lambda x: x["check_runs"][0].update(head_sha="b" * 40),
            lambda x: x["check_runs"][0].update(
                details_url="https://attacker.invalid/actions/runs/123/job/987",
            ),
        ):
            payload = valid_checkruns()
            corrupt(payload)
            self.assertTrue(check_run_errors(payload, TEST_COMMIT))

    def test_signed_predicate_schema_is_not_claimed_by_unsigned_metadata(self) -> None:
        digests = {
            "Cargo.lock": "b" * 64,
            "tests/conformance/v1/full_pipeline.golden": "c" * 64,
            "tests/perf/v1/identity.golden": "d" * 64,
            "tests/acceptance/packaged-consumer.golden": "e" * 64,
        }
        statement = provenance_statement(
            "0.1.0", TEST_COMMIT, "cryptoshift-0.1.0.crate",
            "f" * 64, digests, "synthetic-run",
        )
        self.assertEqual(
            set(statement), {"_type", "subject", "predicateType", "predicate"},
        )
        predicate = statement["predicate"]
        self.assertNotIn("materials", predicate)
        self.assertEqual(
            statement["predicateType"], "https://slsa.dev/provenance/v1",
        )
        deps = predicate["buildDefinition"]["resolvedDependencies"]
        self.assertEqual(len(deps), len(digests) + 1)
        self.assertEqual(deps[0]["digest"]["gitCommit"], TEST_COMMIT)
        for path, digest in digests.items():
            self.assertIn({
                "uri": f"git+https://github.com/LATTIX-IO/cryptoshift@{TEST_COMMIT}#{path}",
                "digest": {"sha256": digest},
            }, deps)
        with self.assertRaises(ValueError):
            provenance_statement("0.1.0", TEST_COMMIT, "crate", "f" * 64,
                                 {"Cargo.lock": "malformed"}, "synthetic-run")

    def test_workflow_is_manual_pinned_and_nonpublishing(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(workflow_errors(text), [])
        mutations = [
            ("  workflow_dispatch:", "  push:\n    branches: [main]\n  workflow_dispatch:"),
            ("inputs.confirm_candidate", "true"),
            ("&& inputs.confirm_candidate", "|| inputs.confirm_candidate"),
            ("github.repository_owner == 'LATTIX-IO'", "github.repository_owner != 'LATTIX-IO'"),
            ("persist-credentials: false", "persist-credentials: true"),
            ("attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a", "attest-build-provenance@v3"),
            ("    steps:", "    continue-on-error: true\n    steps:"),
        ]
        for original, replacement in mutations:
            with self.subTest(original=original):
                self.assertIn(original, text)
                self.assertTrue(workflow_errors(text.replace(original, replacement)))

    def test_spdx_is_deterministic_and_checksum_bound(self) -> None:
        contents = (
            b'version = 4\n'
            b'[[package]]\nname = "cryptoshift"\nversion = "0.1.0"\n'
            b'[[package]]\nname = "sha2"\nversion = "0.10.9"\n'
            b'checksum = "' + (b"e" * 64) + b'"\n'
        )
        result = sbom(contents, "0.1.0", "a" * 40, "2026-10-21T13:00:00+00:00", "b" * 64)
        self.assertEqual(result["spdxVersion"], "SPDX-2.3")
        self.assertEqual(result["packages"][0]["checksums"][0]["checksumValue"], "b" * 64)
        self.assertEqual(result, sbom(contents, "0.1.0", "a" * 40, "2026-10-21T13:00:00+00:00", "b" * 64))
        with self.assertRaises(ValueError):
            sbom(contents.replace(b"e" * 64, b"unsafe"), "0.1.0", "a" * 40, "2026-10-21T13:00:00+00:00", "b" * 64)


if __name__ == "__main__":
    unittest.main()
