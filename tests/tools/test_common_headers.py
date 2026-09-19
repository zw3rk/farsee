# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the common public-header boundary."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_common_headers", ROOT / "tools" / "check_common_headers.py"
)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


def run_checker(include_dir: Path) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        result = CHECKER.main(["check_common_headers.py", str(include_dir)])
    return result, stdout.getvalue(), stderr.getvalue()


class CommonHeaderBoundaryTests(unittest.TestCase):
    def test_protocol_type_in_common_header_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            include = Path(raw) / "include"
            common = include / "farsee" / "farsee_bad.h"
            common.parent.mkdir(parents=True)
            common.write_text("typedef struct rfb_state rfb_state;\n",
                              encoding="utf-8")
            result, _, stderr = run_checker(include)
            self.assertEqual(result, 1)
            self.assertIn("forbidden token 'rfb_'", stderr)

    def test_protocol_word_in_comment_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            include = Path(raw) / "include"
            common = include / "farsee" / "farsee_clean.h"
            common.parent.mkdir(parents=True)
            common.write_text(
                "// An RFB producer can use this neutral value.\n"
                "typedef unsigned farsee_value;\n",
                encoding="utf-8",
            )
            result, stdout, stderr = run_checker(include)
            self.assertEqual(result, 0, stderr)
            self.assertIn("1 header(s) clean", stdout)

    def test_repository_common_headers_are_clean(self) -> None:
        result, _, stderr = run_checker(ROOT / "include")
        self.assertEqual(result, 0, stderr)


if __name__ == "__main__":
    unittest.main()
