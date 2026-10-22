#!/usr/bin/env python3
"""Create a nonpublishing, content-bound release-candidate evidence package.

This command does not sign provenance or authorize crates.io publication.
The manual GitHub workflow adds a signed GitHub artifact attestation separately.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tomllib
from urllib.request import Request, urlopen

from release_safety import section_keys, job_lines, named_step, executable_step

ROOT = Path(__file__).resolve().parents[1]
REPO = "LATTIX-IO/cryptoshift"
RULESET_ID = 24680955
REQUIRED = frozenset((
    "Rust checks",
    "Rust 1.85 MSRV",
    "Supply chain and SemVer",
    "Windows Rust stable conformance",
    "Windows Rust 1.85.0 conformance",
))
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")


def canonical(data: dict) -> bytes:
    """Stable UTF-8 JSON with no host-dependent whitespace."""
    return (json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ruleset_errors(ruleset: dict) -> list[str]:
    """Reject absent or non-strict independently mandatory CI contexts."""
    controls = [rule for rule in ruleset.get("rules", []) if rule.get("type") == "required_status_checks"]
    if ruleset.get("enforcement") != "active" or len(controls) != 1:
        return ["missing active required-status-check rule"]
    errors = []
    # The API may omit bypass actors for read-only credentials. Missing is
    # unverifiable, not equivalent to an empty/bypass-free authorization list.
    actors = ruleset.get("bypass_actors")
    if not isinstance(actors, list):
        errors.append("bypass actor visibility unavailable; require independently verified admin-readable ruleset")
    elif actors:
        errors.append("main protection contains bypass actors; eliminate exception before release")
    if ruleset.get("target") != "branch":
        errors.append("required governance ruleset must target branches")
    conditions = ruleset.get("conditions")
    ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
    includes = ref_name.get("include") if isinstance(ref_name, dict) else None
    excludes = ref_name.get("exclude") if isinstance(ref_name, dict) else None
    if not isinstance(includes, list) or "refs/heads/main" not in includes:
        errors.append("required governance ruleset does not explicitly protect refs/heads/main")
    if not isinstance(excludes, list) or excludes:
        errors.append("required governance ruleset has unknown or nonempty branch exclusions")
    params = controls[0].get("parameters", {})
    contexts = [x.get("context") for x in params.get("required_status_checks", [])]
    if params.get("strict_required_status_checks_policy") is not True:
        errors.append("required checks must be strict")
    if len(contexts) != len(set(contexts)):
        errors.append("duplicate required check contexts")
    types = {rule.get("type") for rule in ruleset.get("rules", [])}
    mandatory_types = {"deletion", "non_fast_forward", "required_linear_history",
                       "required_signatures", "pull_request"}
    if not mandatory_types.issubset(types):
        errors.append("missing source-protection or review rules")
    reviews = [rule for rule in ruleset.get("rules", []) if rule.get("type") == "pull_request"]
    if len(reviews) != 1 or reviews[0].get("parameters", {}).get("required_review_thread_resolution") is not True:
        errors.append("required PR review-thread resolution is absent")
    if len(reviews) != 1 or reviews[0].get("parameters", {}).get("allowed_merge_methods") != ["squash"]:
        errors.append("main must allow only squash merge")
    missing = sorted(REQUIRED.difference(contexts))
    if missing:
        errors.append("missing required checks: " + ", ".join(missing))
    return errors


def check_run_errors(payload: dict, expected_commit: str) -> list[str]:
    """Require the newest GitHub Actions check ID for every exact-head context.

    GitHub's check-run IDs increase with creation. Completed timestamps are
    *not* ordering identities: an older slow success can finish after a
    newer failed or queued run. Missing/truncated responses fail closed.
    """
    checks = payload.get("check_runs")
    if not isinstance(checks, list) or payload.get("total_count") != len(checks):
        return ["incomplete or unverified exact-commit check-run enumeration"]
    found = {}
    errors = []
    for run in checks:
        name = run.get("name")
        if name not in REQUIRED:
            continue
        app = run.get("app")
        if not isinstance(app, dict) or app.get("slug") != "github-actions":
            continue
        run_id = run.get("id")
        if type(run_id) is not int or run_id <= 0:
            errors.append("missing official check-run creation identity: " + name)
            continue
        if run.get("head_sha") != expected_commit:
            errors.append("official check-run does not match exact source commit: " + name)
            continue
        details = str(run.get("details_url", ""))
        if not re.fullmatch(
            r"https://github[.]com/LATTIX-IO/cryptoshift/actions/runs/[0-9]+/job/[0-9]+",
            details,
        ):
            errors.append("official check-run has an untrusted origin: " + name)
            continue
        if name not in found or run_id > found[name][0]:
            found[name] = (run_id, run.get("status"), run.get("conclusion"))
    for name in sorted(REQUIRED):
        if name not in found:
            errors.append("missing exact-commit GitHub Actions check: " + name)
        elif found[name][1:] != ("completed", "success"):
            errors.append("newest GitHub Actions check not green: " + name)
    return errors

def read_live_checks(commit: str) -> dict:
    """Enumerate all exact-source check runs with a finite fail-closed bound."""
    base = f"https://api.github.com/repos/{REPO}/commits/{commit}/check-runs"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "cryptoshift-release-candidate"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    checks = []
    total = None
    for page in range(1, 11):
        url = f"{base}?per_page=100&page={page}"
        with urlopen(Request(url, headers=headers), timeout=15) as response:
            payload = json.load(response)
        count = payload.get("total_count")
        part = payload.get("check_runs")
        if type(count) is not int or count < 0 or not isinstance(part, list):
            raise ValueError("unverifiable GitHub check-run enumeration")
        if total is None:
            total = count
            if total > 1000:
                raise ValueError("check-run enumeration exceeds bounded release-gate scope")
        if count != total or not part and len(checks) < total:
            raise ValueError("GitHub check-run enumeration changed or is incomplete")
        checks.extend(part)
        if len(checks) == total:
            return {"total_count": total, "check_runs": checks}
        if len(checks) > total:
            raise ValueError("GitHub check-run enumeration contains duplicate pages")
    raise ValueError("GitHub check-run enumeration was truncated")

def read_live_ruleset() -> dict:
    """Read the active GitHub governance rule; no app-admin mutation is possible."""
    url = f"https://api.github.com/repos/{REPO}/rulesets/{RULESET_ID}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "cryptoshift-release-candidate"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    with urlopen(Request(url, headers=headers), timeout=15) as response:
        return json.load(response)


def workflow_errors(workflow: str) -> list[str]:
    """Check the reviewed, nonpublishing manual workflow shape."""
    errors = []
    if section_keys(workflow, "on") != ["workflow_dispatch"]:
        errors.append("candidate workflow must have only workflow_dispatch")
    if section_keys(workflow, "jobs") != ["candidate", "attest"]:
        errors.append("candidate workflow requires separate package and attestation jobs")
    expected_if = (
        "if: $" + "{{ github.repository_owner == 'LATTIX-IO' && "
        "github.ref == 'refs/heads/main' && inputs.confirm_candidate }}"
    )
    job = job_lines(workflow, "candidate")
    attestation_job = job_lines(workflow, "attest")
    conditions = [line.strip() for line in job if line.startswith("    if:")]
    attest_conditions = [line.strip() for line in attestation_job if line.startswith("    if:")]
    if conditions != [expected_if] or attest_conditions != [expected_if]:
        errors.append("both release jobs require exact owner/main/confirmation conjunction")
    if not executable_step(job, "Package and test detached consumer", "python3 scripts/package_consumer_check.py"):
        errors.append("candidate workflow must execute the packaged consumer")
    if "    needs: candidate" not in attestation_job:
        errors.append("attestation must depend on successful candidate qualification")
    if "      id-token: write" in job or "      attestations: write" in job:
        errors.append("untrusted package build job must not have attestation/OIDC permissions")
    if "      checks: read" not in job or "      contents: read" not in job:
        errors.append("candidate build job requires scoped read-only permissions")
    if "      id-token: write" not in attestation_job or "      attestations: write" not in attestation_job:
        errors.append("attestation job requires scoped OIDC and attestations permissions")
    if "      contents: read" not in attestation_job:
        errors.append("attestation job must have minimal contents:read")
    if "actions/attest-build-provenance@" in "\n".join(job):
        errors.append("candidate build must not execute attestation action")
    if "python3 scripts/" in "\n".join(attestation_job) or "cargo " in "\n".join(attestation_job):
        errors.append("privileged attestation job must not execute repository build code")
    download = named_step(attestation_job, "Download qualified candidate evidence")
    if "uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093" not in "\n".join(download):
        errors.append("attestation must download an artifact with the reviewed immutable action pin")
    if "      crate_sha256: ${{ steps.record-crate-digest.outputs.sha256 }}" not in workflow:
        errors.append("candidate must pass an exact package digest to isolated attestation")
    verify = named_step(attestation_job, "Verify exact qualified crate subject")
    if not verify or "sha256sum --check --status" not in "\n".join(verify) or "provenance-unsigned.json" not in "\n".join(verify):
        errors.append("attestation must re-verify archived crate digest and source claim")
    if "actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a" not in "\n".join(
        named_step(attestation_job, "Attest exact built crate provenance")
    ):
        errors.append("signed attestation step must be isolated and pinned")
    for required in (
        "github.repository_owner == 'LATTIX-IO'",
        "github.ref == 'refs/heads/main'",
        "inputs.confirm_candidate",
        "persist-credentials: false",
        "contents: read",
        "checks: read",
        "id-token: write",
        "attestations: write",
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a",
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "python3 scripts/package_consumer_check.py",
        "python3 scripts/release_candidate.py",
        "--require-branch-gates",
    ):
        if required not in workflow:
            errors.append("candidate workflow missing: " + required)
    if "continue-on-error:" in workflow:
        errors.append("candidate workflow cannot ignore failures")
    if re.search(r"\bcargo\s+publish\b", workflow):
        errors.append("candidate workflow must not publish")
    return errors


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, text=True, capture_output=True, check=True).stdout.strip()


def validated_inputs(expected_commit: str, expected_version: str, require_rules: bool) -> tuple[str, str]:
    if not SHA.fullmatch(expected_commit):
        raise ValueError("expected commit must be a full immutable 40-character SHA")
    if not VERSION.fullmatch(expected_version):
        raise ValueError("invalid explicit semantic version")
    if git("rev-parse", "HEAD") != expected_commit:
        raise ValueError("input commit differs from checked-out source")
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    manifest = tomllib.loads((ROOT / "crates" / "cryptoshift" / "Cargo.toml").read_text(encoding="utf-8"))
    version = workspace["workspace"]["package"]["version"]
    if version != expected_version or manifest["package"].get("publish") is not False:
        raise ValueError("wrong package version or unsafe publish flag")
    if require_rules:
        workflow = (ROOT / ".github" / "workflows" / "release-candidate.yml").read_text(encoding="utf-8")
        errors = workflow_errors(workflow)
        if errors:
            raise ValueError("; ".join(errors))
        if os.environ.get("GITHUB_REPOSITORY") != REPO or os.environ.get("GITHUB_REF") != "refs/heads/main":
            raise ValueError("candidate evidence can run only on owner-controlled main")
        errors = ruleset_errors(read_live_ruleset())
        errors.extend(check_run_errors(read_live_checks(expected_commit), expected_commit))
        if errors:
            raise ValueError("; ".join(errors))
    return version, git("show", "-s", "--format=%cI", "HEAD")


def download_location(package: dict) -> str:
    """Use only valid SPDX download URLs or recognized VCS references."""
    source = package.get("source")
    if source in (
        "registry+https://github.com/rust-lang/crates.io-index",
        "sparse+https://index.crates.io/",
    ):
        name = package["name"]
        version = package["version"]
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", name) or not VERSION.fullmatch(version):
            raise ValueError("invalid Cargo registry package identity")
        return f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
    if isinstance(source, str) and source.startswith("git+https://") and not any(
        char.isspace() for char in source
    ):
        return source
    return "NOASSERTION"


def sbom(lockfile: bytes, version: str, commit: str, timestamp: str, archive_sha: str) -> dict:
    """SPDX 2.3 manifest from exact Cargo.lock entries, with explicit unknown licenses."""
    lock = tomllib.loads(lockfile.decode("utf-8"))
    packages = []
    for index, package in enumerate(sorted(lock["package"], key=lambda x: (x["name"], x["version"]))):
        ref = f"SPDXRef-Package-{index}"
        entry = {
            "SPDXID": ref,
            "name": package["name"],
            "versionInfo": package["version"],
            "downloadLocation": download_location(package),
            "filesAnalyzed": False,
            "licenseDeclared": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        checksum = package.get("checksum")
        if checksum:
            if not re.fullmatch(r"[0-9a-f]{64}", checksum):
                raise ValueError("invalid registry checksum in Cargo.lock")
            entry["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
        elif package["name"] == "cryptoshift" and package["version"] == version:
            entry["checksums"] = [{"algorithm": "SHA256", "checksumValue": archive_sha}]
        packages.append(entry)
    date = datetime.fromisoformat(timestamp).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"cryptoshift-{version}-locked-source",
        "documentNamespace": f"https://lattix.io/foss/cryptoshift/spdx/{commit}/{version}",
        "creationInfo": {"created": date, "creators": ["Tool: cryptoshift-release-candidate-v1"]},
        "packages": packages,
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": p["SPDXID"]}
            for p in packages if p["name"] == "cryptoshift" and p["versionInfo"] == version
        ],
    }



def provenance_statement(
    version: str, commit: str, package_name: str, archive_sha: str,
    material_digests: dict[str, str], invocation_id: str,
) -> dict:
    """Unsigned SLSA v1 shape: source and file inputs are resolvedDependencies."""
    dependencies = [
        {"uri": f"git+https://github.com/{REPO}",
         "digest": {"gitCommit": commit}},
    ]
    for path, digest in sorted(material_digests.items()):
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid content hash in release candidate materials")
        dependencies.append({
            "uri": f"git+https://github.com/{REPO}@{commit}#{path}",
            "digest": {"sha256": digest},
        })
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": package_name, "digest": {"sha256": archive_sha}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": f"https://github.com/{REPO}/.github/workflows/release-candidate.yml",
                "externalParameters": {"version": version, "commit": commit},
                "resolvedDependencies": dependencies,
            },
            "runDetails": {
                "builder": {"id": "cryptoshift-manual-candidate-v1"},
                "metadata": {"invocationId": invocation_id},
            },
        },
    }


def build(expected_commit: str, expected_version: str, output: Path, require_rules: bool) -> None:
    version, timestamp = validated_inputs(expected_commit, expected_version, require_rules)
    if f"## [{version}]" not in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"):
        raise ValueError("missing explicit versioned release notes")
    package = ROOT / "target" / "package" / f"cryptoshift-{version}.crate"
    raw = package.read_bytes()
    if not raw or len(raw) > 25_000_000:
        raise ValueError("missing or unbounded source archive")
    archive_sha = sha(raw)
    lockfile = (ROOT / "Cargo.lock").read_bytes()
    manifest = sbom(lockfile, version, expected_commit, timestamp, archive_sha)
    materials = {}
    for file in ("Cargo.lock", "tests/conformance/v1/full_pipeline.golden",
                 "tests/perf/v1/identity.golden", "tests/acceptance/packaged-consumer.golden"):
        materials[file] = sha((ROOT / file).read_bytes())
    predicate = provenance_statement(
        version, expected_commit, package.name, archive_sha, materials,
        os.environ.get("GITHUB_RUN_ID", "local"),
    )
    output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(package, output / package.name)
    (output / "sbom.spdx.json").write_bytes(canonical(manifest))
    (output / "provenance-unsigned.json").write_bytes(canonical(predicate))
    (output / "CHANGELOG.md").write_bytes((ROOT / "CHANGELOG.md").read_bytes())
    print("candidate_package_sha256=" + archive_sha)
    print("candidate_sbom_sha256=" + sha(canonical(manifest)))
    print("candidate_provenance_unsigned_sha256=" + sha(canonical(predicate)))
    print("candidate-only: PASS; registry publishing remains disabled")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--require-branch-gates", action="store_true")
    args = parser.parse_args()
    build(args.expected_commit, args.expected_version, args.output_dir, args.require_branch_gates)


if __name__ == "__main__":
    main()
