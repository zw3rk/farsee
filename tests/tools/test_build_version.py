# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the generated build-version contract."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "tools" / "gen_version_header.py"


class BuildVersionTests(unittest.TestCase):
    def generate(self, version: str) -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "farsee_build_version.h"
            result = subprocess.run(
                [sys.executable, str(GENERATOR), str(output),
                 "--version", version],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            content = output.read_text(encoding="utf-8") if output.exists() else ""
            return result, content

    def test_semver_is_rendered_as_c_constants(self) -> None:
        result, content = self.generate("12.34.56-rc.2+build.9")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("#define FARSEE_VERSION_MAJOR 12", content)
        self.assertIn("#define FARSEE_VERSION_MINOR 34", content)
        self.assertIn("#define FARSEE_VERSION_PATCH 56", content)
        self.assertIn(
            '#define FARSEE_VERSION_SUFFIX "-rc.2+build.9"', content
        )
        self.assertIn(
            '#define FARSEE_VERSION_STRING "12.34.56-rc.2+build.9"', content
        )

    def test_non_semver_and_c_injection_are_rejected(self) -> None:
        for version in (
            "1.2", "01.2.3", "1.02.3", "1.2.03", "1.2.3-",
            '1.2.3\"-DOVERRIDE=1', "1.2.3/path", "v1.2.3",
        ):
            with self.subTest(version=version):
                result, content = self.generate(version)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(content, "")

    def test_build_and_release_workflow_propagate_one_version(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("GEN_VERSION_H", makefile)
        self.assertIn("gen_version_header.py", makefile)
        self.assertIn("-include $(GEN_VERSION_H)", makefile)
        self.assertNotIn("--version '$(VERSION)'", makefile)

        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        self.assertIn('make release-cli VERSION="$version"', flake)

        workflow = (
            ROOT / ".github" / "workflows" / "release.yml"
        ).read_text(encoding="utf-8")
        self.assertIn('VERSION="$VERSION" release-check', workflow)
        self.assertIn('VERSION="$VERSION" release-artifacts', workflow)


if __name__ == "__main__":
    unittest.main()
