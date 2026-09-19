# SPDX-License-Identifier: Apache-2.0
"""Keep remediated production files within the project size guideline."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

# Add a file when its ownership split is complete. Legacy oversized files stay
# visible in ARC.7 without making unrelated work fail before their remediation.
REMEDIATED_MAX_LINES = {
    "src/app/live_shell.c": 1_000,
    "src/app/rdp_live.c": 1_000,
    "src/app/rfb_live.c": 1_000,
    "src/protocol/rdp/rdp_callbacks.c": 1_000,
    "src/rfb/rfb_capture_scheduler.c": 1_000,
    "src/rfb/rfb_capture_scheduler_lifecycle.c": 1_000,
    "src/rfb/rfb_session.c": 1_000,
    "src/rfb/rfb_session_capture.c": 1_000,
    "src/rfb/rfb_session_connect.c": 1_000,
    "src/rfb/rfb_session_frame.c": 1_000,
    "src/rfb/rfb_session_input.c": 1_000,
    "src/rfb/rfb_session_wire.c": 1_000,
}


class ProductionFileSizeTests(unittest.TestCase):
    def test_remediated_files_stay_within_guideline(self) -> None:
        for relative, limit in REMEDIATED_MAX_LINES.items():
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                line_count = len(text.splitlines())
                self.assertLessEqual(
                    line_count,
                    limit,
                    f"{relative} has {line_count} lines; limit is {limit}",
                )


if __name__ == "__main__":
    unittest.main()
