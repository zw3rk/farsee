# SPDX-License-Identifier: Apache-2.0
"""Tests for the fail-closed release-platform policy."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_release_platform", ROOT / "tools/check_release_platform.py"
)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class ReleasePlatformTests(unittest.TestCase):
    def test_declared_darwin_platforms_are_accepted(self) -> None:
        manifest = {
            "release_platforms": ["aarch64-darwin", "x86_64-darwin"]
        }
        for system in manifest["release_platforms"]:
            with self.subTest(system=system):
                self.assertEqual(AUDIT.audit_manifest(manifest, system), [])

    def test_linux_platform_is_rejected(self) -> None:
        manifest = {
            "release_platforms": ["aarch64-darwin", "x86_64-darwin"]
        }
        self.assertEqual(
            AUDIT.audit_manifest(manifest, "x86_64-linux"),
            ["release artifacts are not approved for x86_64-linux"],
        )

    def test_platform_list_is_required_and_canonical(self) -> None:
        for value in (
            None,
            [],
            ["aarch64-darwin", "aarch64-darwin"],
            ["Darwin-arm64"],
            ["aarch64-darwin", 7],
        ):
            with self.subTest(value=value):
                errors = AUDIT.audit_manifest(
                    {"release_platforms": value}, "aarch64-darwin"
                )
                self.assertTrue(errors)

    def test_host_system_uses_nix_names(self) -> None:
        self.assertEqual(AUDIT.host_system("Darwin", "arm64"), "aarch64-darwin")
        self.assertEqual(AUDIT.host_system("Linux", "AMD64"), "x86_64-linux")
        self.assertEqual(AUDIT.host_system("Linux", "aarch64"), "aarch64-linux")


if __name__ == "__main__":
    unittest.main()
