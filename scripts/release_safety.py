#!/usr/bin/env python3
"""Fail CI if the unreleased Cryptoshift workspace can publish from Actions.

No external Python dependencies. This is a repository-specific, fail-closed
configuration guard, not a substitute for GitHub environment/branch protection.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ".github/workflows/release-plz.yml"
CI_WORKFLOW = ".github/workflows/ci.yml"
REGISTRY_SECRETS = re.compile(r"\b(?:CARGO_REGISTRY_TOKEN|CRATES_IO_TOKEN|CARGO_PUBLISH_TOKEN)\b")
CARGO_PUBLISH = re.compile(r"\bcargo\s+(?:\+\S+\s+)?publish\b")
RELEASE_COMMAND = re.compile(r"(?m)^\s*command:\s*release\s*(?:#.*)?$")


def section_keys(workflow: str, section: str) -> list[str]:
    """Read top-level YAML mapping keys at two-space indentation only."""
    lines = workflow.splitlines()
    try:
        first = lines.index(f"{section}:")
    except ValueError:
        return []

    keys = []
    for line in lines[first + 1 :]:
        if line and not line[0].isspace() and not line.startswith("#"):
            break
        key = re.fullmatch(r"  ([a-zA-Z_][\w-]*):(?:\s*#.*)?", line)
        if key:
            keys.append(key.group(1))
    return keys


def check_repository(root: Path, *, verify_cargo_metadata: bool = False) -> list[str]:
    """Return all detected unsafe release settings; empty means the gate passes."""
    issues: list[str] = []
    try:
        workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
        members = workspace["workspace"]["members"]
        if not isinstance(members, list) or not members:
            return ["Workspace must define nonempty explicit members"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [f"Cannot validate workspace Cargo.toml: {exc}"]

    for member in members:
        if not isinstance(member, str) or not member or "*" in member or ".." in Path(member).parts or Path(member).is_absolute():
            issues.append(f"Unsupported workspace member path: {member!r}")
            continue
        manifest = root / member / "Cargo.toml"
        try:
            package = tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]
            if package.get("publish") is not False:
                issues.append(f"{manifest.relative_to(root)} must have literal publish = false")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            issues.append(f"Cannot validate {manifest.relative_to(root)}: {exc}")

    workflow_dir = root / ".github" / "workflows"
    workflows = sorted(set(workflow_dir.glob("*.yml")) | set(workflow_dir.glob("*.yaml")))
    if not workflows:
        issues.append("No GitHub Actions workflows found")
    for workflow in workflows:
        contents = workflow.read_text(encoding="utf-8")
        relative = workflow.relative_to(root)
        if CARGO_PUBLISH.search(contents) or RELEASE_COMMAND.search(contents):
            issues.append(f"{relative} contains a publishing command")
        if REGISTRY_SECRETS.search(contents):
            issues.append(f"{relative} exposes a registry publishing token to Actions")
        if workflow.name != "release-plz.yml" and "release-plz/action@" in contents:
            issues.append(f"{relative} invokes release-plz outside the guarded workflow")

    try:
        release = (root / RELEASE_WORKFLOW).read_text(encoding="utf-8")
        if section_keys(release, "on") != ["workflow_dispatch"]:
            issues.append("Release workflow must have workflow_dispatch as its only trigger")
        if section_keys(release, "jobs") != ["release-plz-pr"]:
            issues.append("Release workflow must only prepare release PRs; no release job")
        if not re.search(r"(?m)^\s*command:\s*release-pr\s*$", release):
            issues.append("Manual release-pr command must be preserved")
        if not re.search(r"release-plz/action@[a-f0-9]{40}\b", release):
            issues.append("Release-plz action must be pinned to a commit SHA")
        if "inputs.prepare_release_pr" not in release or "refs/heads/main" not in release:
            issues.append("Manual release-PR preparation must require confirmation on main")
        if "persist-credentials: false" not in release:
            issues.append("Checkout must not persist credentials in the release workflow")
        if not re.search(r"(?m)^permissions:\s*\n  contents: read\s*$", release):
            issues.append("Release workflow must have read-only top-level permissions")
    except OSError as exc:
        issues.append(f"Missing release workflow: {exc}")

    try:
        ci = (root / CI_WORKFLOW).read_text(encoding="utf-8")
        if not re.search(r"(?m)^\s*run: python3 scripts/release_safety\.py --with-cargo\s*$", ci):
            issues.append("CI must enforce the release safety guard with Cargo metadata")
        if "unittest discover -s scripts -p" not in ci:
            issues.append("CI must execute release safety regression tests")
    except OSError as exc:
        issues.append(f"Missing CI workflow: {exc}")

    if verify_cargo_metadata:
        try:
            proc = subprocess.run(
                ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode:
                issues.append(f"cargo metadata failed: {proc.stderr.strip()[:400]}")
            else:
                metadata = json.loads(proc.stdout)
                workspace_ids = set(metadata["workspace_members"])
                packages = [pkg for pkg in metadata["packages"] if pkg["id"] in workspace_ids]
                if not packages:
                    issues.append("Cargo metadata returned no workspace packages")
                for pkg in packages:
                    if pkg.get("publish") != []:
                        issues.append(f"Cargo metadata allows publication for {pkg['name']}")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            issues.append(f"Cannot validate Cargo metadata: {exc}")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-cargo", action="store_true", help="Also validate cargo metadata --locked")
    args = parser.parse_args()
    issues = check_repository(ROOT, verify_cargo_metadata=args.with_cargo)
    if issues:
        for issue in issues:
            print(f"FAIL: {issue}", file=sys.stderr)
        return 1
    print("PASS: all workspace packages are non-publishable; release workflow only prepares PRs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
