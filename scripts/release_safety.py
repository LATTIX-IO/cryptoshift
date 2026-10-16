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



EXPECTED_RELEASE_IF = (
    "if: $" + "{{ github.repository_owner == 'LATTIX-IO' && "
    "github.ref == 'refs/heads/main' && inputs.prepare_release_pr }}"
)


def job_lines(workflow: str, name: str) -> list[str]:
    """Return exactly one two-space YAML job body, otherwise fail closed."""
    lines = workflow.splitlines()
    headers = [i for i, line in enumerate(lines) if re.fullmatch(r"  [a-zA-Z_][\w-]*:\s*", line)]
    matching = [i for i in headers if lines[i].strip() == f"{name}:"]
    if len(matching) != 1 or not re.search(r"(?m)^jobs:\s*$", workflow):
        return []
    start = matching[0]
    end = next((i for i in headers if i > start), len(lines))
    return lines[start + 1 : end]


def named_step(job: list[str], name: str) -> list[str]:
    """Extract one named step without accidentally accepting comments as code."""
    starts = [i for i, line in enumerate(job) if line.startswith("      - ")]
    matching = [i for i in starts if job[i].strip() == f"- name: {name}"]
    if len(matching) != 1:
        return []
    start = matching[0]
    end = next((i for i in starts if i > start), len(job))
    return job[start + 1 : end]


def executable_step(job: list[str], name: str, run_command: str) -> bool:
    """Demand a concrete unconditioned, non-ignored command in its own step."""
    step = named_step(job, name)
    return bool(step) and [line.strip() for line in step if re.match(r"^        run:", line)] == [f"run: {run_command}"] and not any(
        re.match(r"^        (?:if|continue-on-error):", line) for line in step
    )




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
        release_job = job_lines(release, "release-plz-pr")
        conditions = [line.strip() for line in release_job if line.startswith("    if:")]
        if conditions != [EXPECTED_RELEASE_IF]:
            issues.append("Manual release-PR preparation must require confirmation on main")
        if "persist-credentials: false" not in release:
            issues.append("Checkout must not persist credentials in the release workflow")
        if not re.search(r"(?m)^permissions:\s*\n  contents: read\s*$", release):
            issues.append("Release workflow must have read-only top-level permissions")
    except OSError as exc:
        issues.append(f"Missing release workflow: {exc}")

    try:
        ci = (root / CI_WORKFLOW).read_text(encoding="utf-8")
        checks = job_lines(ci, "rust-checks")
        disabled_job = not checks or any(
            re.match(r"^    (?:if|continue-on-error):", line) for line in checks
        )
        if disabled_job or not executable_step(checks, "Reject unsafe release settings", "python3 scripts/release_safety.py --with-cargo"):
            issues.append("CI must enforce the release safety guard with Cargo metadata")
        if disabled_job or not executable_step(checks, "Release safety regression tests", 'python3 -m unittest discover -s scripts -p "test_release_safety.py" -v'):
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
