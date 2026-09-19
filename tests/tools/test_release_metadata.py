# SPDX-License-Identifier: Apache-2.0
"""Tests for deterministic package release metadata."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "gen_release_metadata", ROOT / "tools" / "gen_release_metadata.py"
)
assert SPEC is not None and SPEC.loader is not None
METADATA = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = METADATA
SPEC.loader.exec_module(METADATA)


class ReleaseMetadataTests(unittest.TestCase):
    def test_metadata_contains_stable_release_identity(self) -> None:
        self.assertEqual(
            METADATA.metadata("1.2.3-rc1", "linux-x86_64", "abc123", 42),
            {
                "name": "farsee",
                "platform": "linux-x86_64",
                "schema": 1,
                "source_date_epoch": 42,
                "source_revision": "abc123",
                "version": "1.2.3-rc1",
            },
        )

    def test_metadata_rejects_unsafe_or_unstable_fields(self) -> None:
        with self.assertRaises(ValueError):
            METADATA.metadata("1.2.3 rc1", "linux-x86_64", "abc123", 42)
        with self.assertRaises(ValueError):
            METADATA.metadata("1.2.3", "linux-x86_64", "abc123", -1)


if __name__ == "__main__":
    unittest.main()
