# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the Linux ThreadSanitizer acceptance dimension."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def make_recipe(makefile: str, target: str) -> str:
    match = re.search(
        rf"^{re.escape(target)}:[^\n]*\n(?P<body>(?:\t.*\n)+)",
        makefile,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"missing Make target: {target}")
    return match.group("body")


class TsanPolicyTests(unittest.TestCase):
    def test_tsan_build_mode_instruments_compile_and_link(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertRegex(
            makefile,
            r"(?m)^TSAN_FLAGS\s*:=.*-fsanitize=thread",
        )
        mode = makefile.split("else ifeq ($(BUILD),tsan)", 1)
        self.assertEqual(len(mode), 2, "BUILD=tsan mode is missing")
        mode_body = mode[1].split("else ifeq", 1)[0].split("else\n", 1)[0]
        self.assertIn("BUILD_CFLAGS := $(TSAN_FLAGS)", mode_body)
        self.assertIn("BUILD_LDFLAGS := $(TSAN_FLAGS)", mode_body)

    def test_tsan_target_runs_only_the_deterministic_linux_regression(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertRegex(
            makefile,
            r"(?m)^TSAN_GATE_DIR\s*\?=\s*\$\(BUILD_DIR\)/tsan-gate$",
        )
        recipe = make_recipe(makefile, "tsan-check")
        for required in (
            '"$(UNAME_S)" = "Darwin"',
            "skipped on macOS; Linux CI is authoritative",
            '"$(UNAME_S)" != "Linux"',
            "unsupported platform",
            "exit 2",
            "BUILD_DIR=$(TSAN_GATE_DIR)",
            "BUILD=tsan",
            "CC=clang",
            "FARSEE_WITH_RDP=0",
            "clean build",
            "$(TSAN_GATE_DIR)/tsan/bin/farsee_tests",
            "--filter farsee_slot_two_publishers__reserve_distinct_storage",
            "TSAN_OPTIONS",
            "halt_on_error=1",
            "exitcode=66",
        ):
            self.assertIn(required, recipe)

        ci_recipe = make_recipe(makefile, "ci")
        self.assertIn("tsan-check", ci_recipe)

    def test_ci_has_a_pinned_linux_tsan_job(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        match = re.search(
            r"(?ms)^  linux-tsan:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
            workflow,
        )
        self.assertIsNotNone(match, "missing dedicated Linux TSAN CI job")
        assert match is not None
        job = match.group("body")
        self.assertIn("runs-on: ubuntu-24.04", job)
        self.assertIn(
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            job,
        )
        self.assertIn(
            "DeterminateSystems/nix-installer-action@"
            "da36cb69b1c3247ad7a1f931ebfd954a1105ef14",
            job,
        )
        self.assertIn("nix develop --command make", job)
        self.assertIn("BUILD_DIR=${{ runner.temp }}/farsee-tsan", job)
        self.assertIn("tsan-check", job)


if __name__ == "__main__":
    unittest.main()
