# SPDX-License-Identifier: Apache-2.0
"""The generated registry must not combine all tests into one C unit."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class SplitRegistryTests(unittest.TestCase):
    def test_generated_header_contains_no_test_source_includes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            env = dict(os.environ, FARSEE_WITH_RDP="1")
            subprocess.run(
                [
                    "python3",
                    str(ROOT / "tools" / "gen_test_registry.py"),
                    str(ROOT / "tests"),
                    td,
                ],
                check=True,
                env=env,
                stdout=subprocess.DEVNULL,
            )
            header = (Path(td) / "test_includes.generated.h").read_text(
                encoding="utf-8"
            )
            registry = (Path(td) / "registry.generated.c").read_text(
                encoding="utf-8"
            )
            self.assertNotIn('#include "tests/unit/', header)
            self.assertIn("extern const rfb_test_entry", registry)


if __name__ == "__main__":
    unittest.main()
