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
    params = controls[0].get("parameters", {})
    contexts = [x.get("context") for x in params.get("required_status_checks", [])]
    errors = []
    if params.get("strict_required_status_checks_policy") is not True:
        errors.append("required checks must be strict")
    if len(contexts) != len(set(contexts)):
        errors.append("duplicate required check contexts")
    missing = sorted(REQUIRED.difference(contexts))
    if missing:
        errors.append("missing required checks: " + ", ".join(missing))
    return errors


def read_live_ruleset() -> dict:
    """Read the active GitHub governance rule; no app-admin mutation is possible."""
    url = f"https://api.github.com/repos/{REPO}/rulesets/{RULESET_ID}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "cryptoshift-release-candidate"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    with urlopen(Request(url, headers=headers), timeout=15) as response:
        return json.load(response)


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
        if os.environ.get("GITHUB_REPOSITORY") != REPO or os.environ.get("GITHUB_REF") != "refs/heads/main":
            raise ValueError("candidate evidence can run only on owner-controlled main")
        errors = ruleset_errors(read_live_ruleset())
        if errors:
            raise ValueError("; ".join(errors))
    return version, git("show", "-s", "--format=%cI", "HEAD")


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
            "downloadLocation": package.get("source", "NOASSERTION"),
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


def build(expected_commit: str, expected_version: str, output: Path, require_rules: bool) -> None:
    version, timestamp = validated_inputs(expected_commit, expected_version, require_rules)
    if not (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").find(f"## [{version}]") >= 0:
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
        materials[file] = "sha256:" + sha((ROOT / file).read_bytes())
    predicate = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": package.name, "digest": {"sha256": archive_sha}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/LATTIX-IO/cryptoshift/.github/workflows/release-candidate.yml",
                "externalParameters": {"version": version, "commit": expected_commit},
                "resolvedDependencies": [
                    {"uri": "git+https://github.com/LATTIX-IO/cryptoshift", "digest": {"gitCommit": expected_commit}}
                ],
            },
            "runDetails": {
                "builder": {"id": "cryptoshift-manual-candidate-v1"},
                "metadata": {"invocationId": os.environ.get("GITHUB_RUN_ID", "local")},
            },
            "materials": materials,
        },
        "unsigned": True,
        "warning": "Local metadata is NOT signed or independently authenticated. GitHub attestation is a distinct workflow step.",
    }
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
