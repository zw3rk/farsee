# SPDX-License-Identifier: Apache-2.0
"""Build-mode policy tests for developer-only FreeRDP/WinPR WLog controls."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFINE = "-DFARSEE_ENABLE_WLOG_DIAGNOSTICS=1"
RELEASE_DEFINE = "-DFARSEE_RELEASE_BUILD=1"


def make_database(mode: str, *overrides: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="farsee-wlog-make-") as raw:
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


class WLogBuildPolicyTests(unittest.TestCase):
    def test_release_macro_override_fails_compilation(self) -> None:
        compiler = os.environ.get("CC", "cc")
        for header in (
            "farsee/cli_args.h",
            "protocol/rdp/rdp_freerdp_facade.h",
        ):
            with self.subTest(header=header):
                result = subprocess.run(
                    [
                        compiler,
                        "-std=c11",
                        RELEASE_DEFINE,
                        DEFINE,
                        "-I",
                        str(ROOT / "include"),
                        "-I",
                        str(ROOT / "src"),
                        "-x",
                        "c",
                        "-fsyntax-only",
                        "-",
                    ],
                    input=f'#include "{header}"\n',
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "cannot be enabled in release builds", result.stderr
                )

    def test_positive_define_is_present_only_in_developer_build_modes(self) -> None:
        for mode in ("dev", "asan-ubsan", "coverage", "fuzz"):
            with self.subTest(mode=mode):
                self.assertEqual(
                    make_value(
                        mode, "WLOG_DIAGNOSTIC_DEFS", "FARSEE_WITH_RDP=1"
                    ),
                    DEFINE,
                )
                self.assertIn(
                    DEFINE,
                    make_value(
                        mode, "CFLAGS", "FARSEE_WITH_RDP=1"
                    ).split(),
                )
                self.assertIn(
                    DEFINE,
                    make_value(
                        mode, "SA_CFLAGS", "FARSEE_WITH_RDP=1"
                    ).split(),
                )

        self.assertEqual(make_value("release", "WLOG_DIAGNOSTIC_DEFS"), "")
        self.assertNotIn(DEFINE, make_value("release", "CFLAGS").split())
        self.assertNotIn(DEFINE, make_value("release", "SA_CFLAGS").split())
        self.assertEqual(
            make_value("release", "RELEASE_POLICY_DEFS"), RELEASE_DEFINE
        )
        self.assertEqual(make_value("dev", "RELEASE_POLICY_DEFS"), "")
        self.assertEqual(make_value("asan-ubsan", "RELEASE_POLICY_DEFS"), "")
        self.assertEqual(make_value("coverage", "RELEASE_POLICY_DEFS"), "")
        self.assertEqual(make_value("fuzz", "RELEASE_POLICY_DEFS"), "")

        for mode in ("dev", "asan-ubsan", "coverage", "fuzz", "release"):
            with self.subTest(mode=mode, rdp="disabled"):
                self.assertEqual(
                    make_value(
                        mode,
                        "WLOG_DIAGNOSTIC_DEFS",
                        "FARSEE_WITH_RDP=0",
                    ),
                    "",
                )
                self.assertNotIn(
                    DEFINE,
                    make_value(
                        mode, "CFLAGS", "FARSEE_WITH_RDP=0"
                    ).split(),
                )

    def test_release_command_line_flag_overrides_cannot_enable_wlog(self) -> None:
        for variable in ("BUILD_CFLAGS", "CFLAGS"):
            with self.subTest(variable=variable):
                flags = make_value(
                    "release", "CFLAGS", f"{variable}=-O2 {DEFINE}"
                ).split()
                self.assertIn(DEFINE, flags)
                self.assertIn(RELEASE_DEFINE, flags)
                self.assertLess(flags.index(DEFINE), flags.index(RELEASE_DEFINE))

        for variable, value in (
            ("WLOG_DIAGNOSTIC_DEFS", DEFINE),
            ("RELEASE_POLICY_DEFS", ""),
        ):
            with self.subTest(variable=variable):
                result = make_database("release", f"{variable}={value}")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"{variable} cannot be overridden", result.stderr)


if __name__ == "__main__":
    unittest.main()
