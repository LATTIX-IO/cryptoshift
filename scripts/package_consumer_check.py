#!/usr/bin/env python3
"""Verify the unpublished package as a detached, offline Cargo consumer.

This script does NOT publish, authenticate source claims or grant migration approval.
It runs after the workspace dependencies have been cached by CI.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "acceptance" / "packaged-consumer.golden"
EXPECTED_TAGS = (
    "migration plan state: ",
    "readiness: ",
    "atomic analysis state: ",
    "forged graph pin: ",
    "This is not an authorization to execute, migrate, or approve changes.",
)


def safe_path(member: tarfile.TarInfo, prefix: str) -> bool:
    """A crate member must be a regular file/directory below its own prefix."""
    p = PurePosixPath(member.name)
    return (
        not p.is_absolute()
        and len(p.parts) >= 2
        and p.parts[0] == prefix
        and all(part not in ("", ".", "..") for part in p.parts)
        and (member.isfile() or member.isdir())
        and not member.issym()
        and not member.islnk()
        and not member.isdev()
    )


def projection(output: str) -> str:
    """Extract the exact stable public-facing lines, excluding local timing."""
    return "\n".join(
        line for line in output.splitlines()
        if line.startswith(EXPECTED_TAGS)
    ) + "\n"


def controlled_target(root: Path, inherited: dict[str, str]) -> tuple[dict[str, str], Path]:
    """Override any inherited build.target-dir with a fresh canonical target path."""
    configured = dict(inherited)
    target = (root / "target").resolve()
    configured["CARGO_TARGET_DIR"] = str(target)
    return configured, target


def execute(command: list[str], *, env: dict[str, str]) -> str:
    print("verify-package:", " ".join(command), flush=True)
    done = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
    if done.returncode:
        raise RuntimeError(
            f"exit={done.returncode} for {command[0]}: {done.stderr[-3000:]}"
        )
    return done.stdout


def verify(toolchain: str | None) -> None:
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    version = workspace["workspace"]["package"]["version"]
    stem = f"cryptoshift-{version}"
    command = ["cargo", *([f"+{toolchain}"] if toolchain else [])]
    env = os.environ.copy()
    env["CARGO_NET_OFFLINE"] = "true"
    # Cargo config and CARGO_TARGET_DIR may redirect output. Fix the target
    # explicitly and reject a stale package from a prior run.
    env, target_dir = controlled_target(ROOT, env)
    package = target_dir / "package" / f"{stem}.crate"
    if package.exists():
        package.unlink()
    execute([*command, "package", "-p", "cryptoshift", "--offline", "--locked"], env=env)
    raw = package.read_bytes()
    if len(raw) > 25_000_000:
        raise RuntimeError("unexpected package size")
    digest = hashlib.sha256(raw).hexdigest()
    with tempfile.TemporaryDirectory(prefix="cryptoshift-cleanroom-") as temporary:
        location = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > 2500:
                raise RuntimeError("empty or oversized package file inventory")
            for member in members:
                if not safe_path(member, stem) or member.size > 15_000_000:
                    raise RuntimeError("package contains unsafe member")
                if member.isfile():
                    output_path = location.joinpath(*PurePosixPath(member.name).parts)
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    handle = archive.extractfile(member)
                    if handle is None:
                        raise RuntimeError("unreadable package member")
                    with handle, output_path.open("wb") as writer:
                        content = handle.read(15_000_001)
                        if len(content) != member.size:
                            raise RuntimeError("invalid package member size")
                        writer.write(content)
        root = location / stem
        manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["package"]
        if manifest.get("name") != "cryptoshift" or manifest.get("version") != version:
            raise RuntimeError("unexpected crate identity")
        if manifest.get("rust-version") != "1.85":
            raise RuntimeError("missing declared minimum toolchain")
        if manifest.get("publish") is not False:
            raise RuntimeError("package publish guard was lost")
        if not (root / "src" / "lib.rs").is_file() or not (root / "README.md").is_file():
            raise RuntimeError("public package is missing the library or README")

        consumer = location / "consumer"
        (consumer / "src").mkdir(parents=True)
        (consumer / "Cargo.toml").write_text(
            '[package]\nname = "cryptoshift-cleanroom"\nversion = "0.0.0"\nedition = "2024"\n'
            'rust-version = "1.85"\n[workspace]\n[dependencies]\n'
            f'cryptoshift = {{ path = "../{stem}", version = "={version}" }}\n',
            encoding="utf-8",
        )
        (consumer / "src" / "main.rs").write_bytes(
            (ROOT / "crates" / "cryptoshift" / "examples" / "migration_plan.rs").read_bytes()
        )
        manifest_arg = str(consumer / "Cargo.toml")
        execute([*command, "generate-lockfile", "--offline", "--manifest-path", manifest_arg], env=env)
        first = execute([*command, "run", "--frozen", "--manifest-path", manifest_arg, "--quiet"], env=env)
        second = execute([*command, "run", "--frozen", "--manifest-path", manifest_arg, "--quiet"], env=env)
        if first != second:
            raise RuntimeError("detached consumer nondeterministic public output")
        if projection(first) != GOLDEN.read_text(encoding="utf-8"):
            raise RuntimeError("detached consumer semantic golden changed")
        if not re.search(r"migration plan digest: sha256:[0-9a-f]{64}\b", first):
            raise RuntimeError("missing canonical SHA-256 plan digest")
        print(f"package_identity=sha256:{digest}")
        print(f"consumer_output=sha256:{hashlib.sha256(first.encode()).hexdigest()}")
        print("FOSS-454 packaged clean-room consumer: PASS (no publication)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", choices=("1.85.0",), default=None)
    args = parser.parse_args()
    verify(args.toolchain)


if __name__ == "__main__":
    main()
