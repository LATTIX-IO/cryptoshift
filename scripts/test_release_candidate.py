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
    workflow_errors,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release-candidate.yml"


def valid_ruleset() -> dict:
    return {
        "enforcement": "active",
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
        "check_runs": [
            {
                "name": name,
                "app": {"slug": "github-actions"},
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-10-21T10:00:00Z",
                "completed_at": "2026-10-21T10:01:00Z",
                "details_url": "https://github.com/LATTIX-IO/cryptoshift/actions/runs/123",
            }
            for name in sorted(REQUIRED)
        ]
    }


class CandidateGateTests(unittest.TestCase):
    def test_valid_protections(self) -> None:
        self.assertEqual(ruleset_errors(valid_ruleset()), [])
        self.assertEqual(check_run_errors(valid_checkruns()), [])

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
                self.assertTrue(check_run_errors(checkruns))

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
        payload["check_runs"].append({
            **deepcopy(payload["check_runs"][0]),
            "conclusion": "failure",
            "completed_at": "2026-10-21T10:05:00Z",
        })
        self.assertTrue(check_run_errors(payload))
        payload["check_runs"][-1]["app"] = {"slug": "untrusted-bot"}
        self.assertEqual(check_run_errors(payload), [])

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
