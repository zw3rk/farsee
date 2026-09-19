# SPDX-License-Identifier: Apache-2.0
"""Tests for the complete Nix package closure policy."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "nix_closure_audit", ROOT / "tools" / "nix_closure_audit.py"
)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


class NixClosureAuditTests(unittest.TestCase):
    def manifest(self) -> dict:
        return {
            "allowed_licenses": ["Apache-2.0"],
            "forbidden_runtime_patterns": ["ffmpeg", "libusb"],
            "dependencies": [
                {
                    "name": "FreeRDP",
                    "license": "Apache-2.0",
                    "store_patterns": ["farsee-freerdp-minimal-3.15.0"],
                },
                {
                    "name": "OpenSSL",
                    "license": "Apache-2.0",
                    "store_patterns": ["openssl-3.4.3"],
                },
            ],
        }

    def test_forbidden_transitive_component_is_rejected(self) -> None:
        paths = [
            "/nix/store/aaaa-farsee-1.0",
            "/nix/store/bbbb-ffmpeg-7.1.1",
        ]
        errors = AUDIT.audit_paths(paths, self.manifest(), paths[0])
        self.assertTrue(any("forbidden" in error and paths[1] in error
                            for error in errors))

    def test_minimal_declared_closure_is_accepted(self) -> None:
        paths = [
            "/nix/store/aaaa-farsee-1.0",
            "/nix/store/bbbb-farsee-freerdp-minimal-3.15.0",
            "/nix/store/cccc-openssl-3.4.3",
        ]
        self.assertEqual(AUDIT.audit_paths(paths, self.manifest(), paths[0]), [])

    def test_undeclared_transitive_component_is_rejected(self) -> None:
        root = "/nix/store/aaaa-farsee-1.0"
        undeclared = "/nix/store/dddd-unexpected-runtime-2.0"
        errors = AUDIT.audit_paths([root, undeclared], self.manifest(), root)
        self.assertEqual(errors, [f"undeclared Nix closure path: {undeclared}"])

    def test_declared_component_with_disallowed_license_is_rejected(self) -> None:
        manifest = self.manifest()
        manifest["dependencies"].append(
            {
                "name": "bad-runtime",
                "license": "LGPL-2.1-only",
                "store_patterns": ["bad-runtime-1.0"],
            }
        )
        root = "/nix/store/aaaa-farsee-1.0"
        bad = "/nix/store/eeee-bad-runtime-1.0"
        errors = AUDIT.audit_paths([root, bad], manifest, root)
        self.assertEqual(
            errors,
            ["Nix closure path has no allowed-license declaration: " + bad],
        )


if __name__ == "__main__":
    unittest.main()
