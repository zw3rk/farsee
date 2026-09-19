# SPDX-License-Identifier: Apache-2.0
"""Build-mode policy tests for private RFB capture diagnostics."""

from __future__ import annotations

import re
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFINE = "-DFARSEE_ENABLE_CAPTURE_DIAGNOSTICS=1"
RELEASE_DEFINE = "-DFARSEE_RELEASE_BUILD=1"


def make_database(mode: str, *overrides: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="farsee-capture-make-") as raw:
        return subprocess.run(
            [
                "make",
                "-pn",
                f"BUILD={mode}",
                f"BUILD_DIR={raw}",
                *overrides,
                "help",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )


def make_value(mode: str, name: str, *overrides: str) -> str:
    result = make_database(mode, *overrides)
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    match = re.search(
        rf"(?m)^{re.escape(name)}[ \t]*(?::|\+|\?)?=[ \t]*(.*)$",
        result.stdout,
    )
    if match is None:
        raise AssertionError(f"missing Make variable {name} for BUILD={mode}")
    return match.group(1)


class CaptureDiagnosticBuildPolicyTests(unittest.TestCase):
    def test_release_macro_override_fails_compilation(self) -> None:
        compiler = os.environ.get("CC", "cc")
        result = subprocess.run(
            [
                compiler,
                "-std=c11",
                RELEASE_DEFINE,
                DEFINE,
                "-I",
                str(ROOT / "include"),
                "-x",
                "c",
                "-fsyntax-only",
                "-",
            ],
            input='#include "farsee/rfb_capture_control.h"\n',
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot be enabled in release builds", result.stderr)

    def test_positive_define_is_build_mode_scoped(self) -> None:
        for mode in ("dev", "asan-ubsan", "coverage", "fuzz"):
            for rdp in (False, True):
                with self.subTest(mode=mode, rdp=rdp):
                    overrides = (f"FARSEE_WITH_RDP={int(rdp)}",)
                    self.assertEqual(
                        make_value(mode, "CAPTURE_DIAGNOSTIC_DEFS", *overrides),
                        DEFINE,
                    )
                    self.assertIn(
                        DEFINE, make_value(mode, "CFLAGS", *overrides).split()
                    )

        for rdp in (False, True):
            with self.subTest(mode="release", rdp=rdp):
                overrides = (f"FARSEE_WITH_RDP={int(rdp)}",)
                self.assertEqual(
                    make_value("release", "CAPTURE_DIAGNOSTIC_DEFS", *overrides),
                    "",
                )
                self.assertNotIn(
                    DEFINE,
                    make_value("release", "CFLAGS", *overrides).split(),
                )

    def test_release_cannot_override_capture_policy_variables(self) -> None:
        for variable, value in (
            ("CAPTURE_DIAGNOSTIC_DEFS", DEFINE),
            ("CAPTURE_DIAGNOSTICS_BUILD", "1"),
        ):
            with self.subTest(variable=variable):
                result = make_database("release", f"{variable}={value}")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"{variable} cannot be overridden", result.stderr)

    def test_release_injected_compiler_flags_are_caught_by_header_guard(self) -> None:
        for variable in ("BUILD_CFLAGS", "CFLAGS"):
            with self.subTest(variable=variable):
                flags = make_value(
                    "release", "CFLAGS", f"{variable}=-O2 {DEFINE}"
                ).split()
                self.assertIn(DEFINE, flags)
                self.assertIn(RELEASE_DEFINE, flags)

    def test_release_cannot_inject_diagnostic_product_sources(self) -> None:
        injected = str(ROOT / "src/rfb/rfb_capture_control.c")
        self.assertEqual(
            make_value(
                "release",
                "PRODUCT_RFB_DIAGNOSTIC_SRCS",
                f"PRODUCT_RFB_DIAGNOSTIC_SRCS={injected}",
            ),
            "",
        )


if __name__ == "__main__":
    unittest.main()
