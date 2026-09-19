# SPDX-License-Identifier: Apache-2.0
"""Self-tests for the all-refs Git history vocabulary gate."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location(
    "history_trace_scan", TOOLS / "history_trace_scan.py"
)
assert SPEC is not None and SPEC.loader is not None
SCAN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SCAN
SPEC.loader.exec_module(SCAN)

HASH_RULE = SCAN.Rule(
    "synthetic_hash",
    "synthetic_hash",
    None,
    (SCAN.TokenHash(2, hashlib.sha256(b"synthetic marker").digest()),),
)
REGEX_RULE = SCAN.Rule(
    "synthetic_regex",
    "synthetic_regex",
    re.compile(r"\bfixture-[0-9]+\b", re.ASCII),
)
NESTED_RULE = SCAN.Rule(
    "synthetic_nested",
    "synthetic_nested",
    re.compile(r"\b[0-9]+ value\b", re.ASCII),
)
TEXT_ONLY_RULE = SCAN.Rule(
    "synthetic_text_only",
    "synthetic_text_only",
    re.compile(r"(?<![A-Za-z0-9])e" + "17" + r"(?![A-Za-z0-9])",
               re.ASCII | re.IGNORECASE),
    (),
    True,
)
RULES = [HASH_RULE, REGEX_RULE, NESTED_RULE]


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True,
                   stdout=subprocess.DEVNULL)


def commit(root: Path, message: str) -> None:
    git(
        root,
        "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "-c", "commit.gpgSign=false",
        "commit", "-am", message,
    )


class HistoryTraceTests(unittest.TestCase):
    def init_repo(self, root: Path) -> None:
        git(root, "init", "-q", "-b", "master")
        (root / "safe.txt").write_text("ordinary public text\n", encoding="utf-8")
        git(root, "add", "safe.txt")
        commit(root, "Initial public source")

    def test_clean_history_passes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.init_repo(root)
            self.assertEqual(SCAN.scan_history(root, RULES), [])

    def test_retained_ref_message_path_and_blob_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.init_repo(root)
            git(root, "checkout", "-qb", "retained")
            path = root / "synthetic-marker.txt"
            path.write_text("fixture-42 value\n", encoding="utf-8")
            git(root, "add", path.name)
            commit(root, "fixture-43")
            git(root, "-c", "tag.gpgSign=false", "tag", "fixture-7")
            git(root, "checkout", "-q", "master")

            findings = SCAN.scan_history(root, RULES)
            categories = {finding.category for finding in findings}
            self.assertEqual(
                categories,
                {"synthetic_hash", "synthetic_regex", "synthetic_nested"},
            )
            self.assertTrue(any("history-commit:" in item.location
                                for item in findings))
            self.assertTrue(any("history-blob:" in item.location
                                for item in findings))
            self.assertTrue(any("history-path:" in item.location
                                for item in findings))

    def test_combined_matcher_is_bounded_and_preserves_nested_rules(self) -> None:
        matcher = SCAN.HistoryMatcher(RULES)
        payload = b"ordinary\x00bytes\n" * 131072 + b"fixture-42 value synthetic-marker"
        started = time.monotonic()
        findings = matcher.scan(payload, "fixture", binary=True)
        elapsed = time.monotonic() - started
        categories = {finding.category for finding in findings}
        self.assertEqual(
            categories,
            {"synthetic_hash", "synthetic_regex", "synthetic_nested"},
        )
        self.assertLess(elapsed, 5.0)

    def test_combined_matcher_matches_individual_nested_rule_results(self) -> None:
        payload = b"prefix fixture-42 value synthetic-marker suffix"
        matcher = SCAN.HistoryMatcher(RULES)
        combined = matcher.scan(payload, "fixture")
        individual = SCAN.scan_blob(payload, "fixture", RULES)
        self.assertEqual(sorted(combined), sorted(individual))

    def test_hash_hit_survives_nonmatching_active_regex_rule(self) -> None:
        payload = b"prefix synthetic-marker suffix"
        matcher = SCAN.HistoryMatcher([HASH_RULE, REGEX_RULE])
        self.assertEqual(
            matcher.scan(payload, "fixture"),
            SCAN.scan_blob(payload, "fixture", [HASH_RULE]),
        )

    def test_text_only_history_rule_scans_text_and_skips_nul_blob(self) -> None:
        matcher = SCAN.HistoryMatcher([TEXT_ONLY_RULE])
        phase = bytes.fromhex("7072656669782045313720737566666978")
        textual = matcher.scan(phase, "history-blob:text", binary=True)
        binary = matcher.scan(b"\0" + phase + b"\0", "history-blob:binary",
                              binary=True)
        self.assertTrue(textual)
        self.assertTrue(all(":byte:" in item.location for item in textual))
        self.assertEqual(binary, [])
        self.assertEqual(
            sorted(textual),
            sorted(SCAN.scan_blob(
                phase, "history-blob:text", [TEXT_ONLY_RULE], binary=True,
            )),
        )

    def test_text_only_history_rule_uses_blob_content_classification(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.init_repo(root)
            text = root / "text.txt"
            binary = root / "binary.bin"
            phase = bytes.fromhex("7072656669782045313720737566666978")
            text.write_bytes(phase + b"\n")
            binary.write_bytes(b"\0" + phase + b"\0")
            git(root, "add", text.name, binary.name)
            commit(root, "Add text and binary fixtures")

            findings = SCAN.scan_history(root, [TEXT_ONLY_RULE])
            blob_findings = [item for item in findings
                             if item.location.startswith("history-blob:")]
            self.assertEqual(len(blob_findings), 1)
            self.assertIn(":text.txt:byte:", blob_findings[0].location)

    def test_make_gate_has_a_wall_clock_limit(self) -> None:
        result = subprocess.run(
            ["make", "-n", "history-trace-check"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("timeout 120", result.stdout)


if __name__ == "__main__":
    unittest.main()
