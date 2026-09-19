# SPDX-License-Identifier: Apache-2.0
"""Regression tests for deterministic release-note extraction."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "tools" / "gen_release_notes.py"


class ReleaseNotesTests(unittest.TestCase):
    def run_generator(self, changelog: str, version: str) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "CHANGELOG.md"
            output = root / "notes.md"
            source.write_text(changelog, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(GENERATOR), str(source), str(output),
                 "--version", version],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            notes = output.read_text(encoding="utf-8") if output.exists() else ""
            return result.returncode, notes, result.stderr

    def test_exact_version_section_becomes_release_notes(self) -> None:
        changelog = """# Changelog

## [Unreleased]

Pending.

## [1.2.3]

Released behavior.

## [1.2.2]

Older behavior.
"""
        status, notes, stderr = self.run_generator(changelog, "1.2.3")
        self.assertEqual(status, 0, stderr)
        self.assertIn("# farsee 1.2.3 release notes", notes)
        self.assertIn("Released behavior.", notes)
        self.assertNotIn("Pending.", notes)
        self.assertNotIn("Older behavior.", notes)

    def test_missing_or_duplicate_version_section_is_rejected(self) -> None:
        for changelog in (
            "# Changelog\n\n## [Unreleased]\n\nPending.\n",
            "# Changelog\n\n## [1.2.3]\n\nA.\n\n## [1.2.3]\n\nB.\n",
        ):
            with self.subTest(changelog=changelog):
                status, notes, _stderr = self.run_generator(changelog, "1.2.3")
                self.assertNotEqual(status, 0)
                self.assertEqual(notes, "")

    def test_release_artifacts_include_versioned_notes_in_checksums(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        recipe = makefile.split("release-artifacts:", 1)[1].split(
            "\n\n", 1
        )[0]
        self.assertIn("gen_release_notes.py", recipe)
        self.assertIn("RELEASE_NOTES", recipe)
        self.assertIn("$(notdir $(RELEASE_NOTES))", recipe)


if __name__ == "__main__":
    unittest.main()
