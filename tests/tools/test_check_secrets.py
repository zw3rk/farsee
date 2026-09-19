# SPDX-License-Identifier: Apache-2.0
"""Self-tests for the current-tree and history secret gate."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "check_secrets.py"


class SecretGateTests(unittest.TestCase):
    def setUp(self) -> None:
        gitleaks = shutil.which("gitleaks")
        if gitleaks is None:
            self.skipTest("gitleaks is unavailable")
        self.gitleaks = gitleaks
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self._git("init", "--initial-branch", "master")
        self._git("config", "user.name", "Gate Test")
        self._git("config", "user.email", "gate@example.invalid")
        self._write(".gitleaksignore", "# Exact reviewed fingerprints only.\n")
        self._write("clean.txt", "public fixture\n")
        self._git("add", ".gitleaksignore", "clean.txt")
        self._git("commit", "-m", "Create clean fixture")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            check=True,
            capture_output=True,
            text=True,
        )

    def _write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    @staticmethod
    def _synthetic_finding() -> str:
        return "AK" + "IA" + "A1B2C3D4E5F6G7H8"

    def _run_gate(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--root",
                str(self.root),
                "--gitleaks",
                self.gitleaks,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def _finding_fingerprint(self) -> str:
        report = self.root / "finding.json"
        result = subprocess.run(
            [
                self.gitleaks,
                "git",
                str(self.root),
                "--no-banner",
                "--redact",
                "--exit-code",
                "0",
                "--gitleaks-ignore-path",
                "/dev/null",
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--log-opts=--all",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        findings = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(len(findings), 1)
        report.unlink()
        return str(findings[0]["Fingerprint"])

    def test_clean_repository_passes(self) -> None:
        result = self._run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_exact_reachable_history_fingerprint_passes(self) -> None:
        self._write("reviewed.txt", self._synthetic_finding() + "\n")
        self._git("add", "reviewed.txt")
        self._git("commit", "-m", "Add reviewed fixture")
        fingerprint = self._finding_fingerprint()
        self._write(".gitleaksignore", fingerprint + "\n")
        self._git("add", ".gitleaksignore")
        self._git("commit", "-m", "Review fixture")

        result = self._run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_global_fingerprint_is_rejected(self) -> None:
        self._write(".gitleaksignore", "reviewed.txt:github-pat:1\n")
        self._git("add", ".gitleaksignore")
        result = self._run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid fingerprint", result.stderr)

    def test_committed_finding_is_rejected(self) -> None:
        self._write("committed.txt", self._synthetic_finding() + "\n")
        self._git("add", "committed.txt")
        self._git("commit", "-m", "Add committed finding")
        self.assertNotEqual(self._run_gate().returncode, 0)

    def test_staged_finding_is_rejected(self) -> None:
        self._write("staged.txt", self._synthetic_finding() + "\n")
        self._git("add", "staged.txt")
        self.assertNotEqual(self._run_gate().returncode, 0)

    def test_unstaged_finding_is_rejected(self) -> None:
        self._write("changed.txt", "public fixture\n")
        self._git("add", "changed.txt")
        self._git("commit", "-m", "Add tracked fixture")
        self._write("changed.txt", self._synthetic_finding() + "\n")
        self.assertNotEqual(self._run_gate().returncode, 0)

    def test_untracked_finding_is_rejected(self) -> None:
        self._write("untracked.txt", self._synthetic_finding() + "\n")
        self.assertNotEqual(self._run_gate().returncode, 0)


if __name__ == "__main__":
    unittest.main()
