"""Offline public-package security regressions without running Cargo."""
from __future__ import annotations

import tarfile
import unittest

from scripts.package_consumer_check import controlled_target, safe_path, projection


class PackageConsumerChecks(unittest.TestCase):
    def member(self, path: str, member_type: bytes = tarfile.REGTYPE) -> tarfile.TarInfo:
        record = tarfile.TarInfo(path)
        record.type = member_type
        return record

    def test_cargo_target_override_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            inherited = {"CARGO_TARGET_DIR": "/some/foreign/cache", "CARGO_NET_OFFLINE": "true"}
            environment, location = controlled_target(root, inherited)
            self.assertEqual(location, (root / "target").resolve())
            self.assertEqual(environment["CARGO_TARGET_DIR"], str(location))
            self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
            self.assertEqual(inherited["CARGO_TARGET_DIR"], "/some/foreign/cache")

    def test_allow_exact_package_root_file_only(self) -> None:
        self.assertTrue(safe_path(self.member("cryptoshift-0.1.0/src/lib.rs"), "cryptoshift-0.1.0"))
        self.assertFalse(safe_path(self.member("other-0.1.0/src/lib.rs"), "cryptoshift-0.1.0"))

    def test_reject_absolute_traversal_and_symlink(self) -> None:
        for name in (
            "../cryptoshift-0.1.0/src/lib.rs",
            "cryptoshift-0.1.0/../../outside",
            "/tmp/cryptoshift-0.1.0/src/lib.rs",
            "cryptoshift-0.1.0",
        ):
            with self.subTest(name=name):
                self.assertFalse(safe_path(self.member(name), "cryptoshift-0.1.0"))
        self.assertFalse(safe_path(self.member("cryptoshift-0.1.0/link", tarfile.SYMTYPE), "cryptoshift-0.1.0"))
        self.assertFalse(safe_path(self.member("cryptoshift-0.1.0/hardlink", tarfile.LNKTYPE), "cryptoshift-0.1.0"))

    def test_semantic_projection_is_stable_and_bounded(self) -> None:
        output = (
            "run-time: 1719ms\n"
            "migration plan state: Partial\n"
            "readiness: Unverified\n"
            "atomic analysis state: Partial\n"
            "forged graph pin: Failed\n"
            "This is not an authorization to execute, migrate, or approve changes.\n"
        )
        expected = "\n".join(line for line in output.splitlines()[1:]) + "\n"
        self.assertEqual(projection(output), expected)
        self.assertNotIn("run-time", projection(output))


if __name__ == "__main__":
    unittest.main()
