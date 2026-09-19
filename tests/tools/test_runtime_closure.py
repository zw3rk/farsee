# SPDX-License-Identifier: Apache-2.0
"""Tests for cross-platform dynamic-library closure discovery."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "runtime_closure", ROOT / "tools" / "runtime_closure.py"
)
assert SPEC is not None and SPEC.loader is not None
RUNTIME_CLOSURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNTIME_CLOSURE)


class RuntimeClosureTests(unittest.TestCase):
    def test_otool_parser_returns_absolute_dependencies(self) -> None:
        text = """/tmp/farsee:
\t/nix/store/aaaa-zlib-1.3.1/lib/libz.dylib (compatibility version 1.0.0)
\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)
"""
        paths, errors = RUNTIME_CLOSURE.parse_otool(text)
        self.assertEqual(
            paths,
            [
                "/nix/store/aaaa-zlib-1.3.1/lib/libz.dylib",
                "/usr/lib/libSystem.B.dylib",
            ],
        )
        self.assertEqual(errors, [])

    def test_otool_parser_rejects_unresolved_loader_path(self) -> None:
        text = """/tmp/farsee:
\t@rpath/libbad.dylib (compatibility version 1.0.0)
"""
        _, errors = RUNTIME_CLOSURE.parse_otool(text)
        self.assertTrue(any("unresolved" in error for error in errors))

    def test_ldd_parser_returns_paths_and_rejects_not_found(self) -> None:
        text = """libz.so.1 => /nix/store/aaaa-zlib/lib/libz.so.1 (0x1)
libbad.so => not found
/nix/store/bbbb-glibc/lib/ld-linux-x86-64.so.2 (0x2)
"""
        paths, errors = RUNTIME_CLOSURE.parse_ldd(text)
        self.assertEqual(
            paths,
            [
                "/nix/store/aaaa-zlib/lib/libz.so.1",
                "/nix/store/bbbb-glibc/lib/ld-linux-x86-64.so.2",
            ],
        )
        self.assertTrue(any("not found" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
