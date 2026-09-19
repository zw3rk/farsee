# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the bounded macOS interoperability runner."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tools" / "macos_acceptance.sh"


class MacosAcceptanceTests(unittest.TestCase):
    def make_fake(self, temp: Path, *, record_marker: bool = True) -> Path:
        fake = temp / "farsee-fake"
        marker = (
            'echo "farsee: Apple AES-CBC record layer active '
            '(0x044f rekey; AES-CBC records on wire)." >&2\n'
            if record_marker
            else ""
        )
        fake.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env bash
                # SPDX-License-Identifier: Apache-2.0
                set -u
                fd=""
                saw_user=0
                saw_type36=0
                saw_records=0
                saw_null=0
                saw_view_only=0
                saw_share=0
                while [ "$#" -gt 0 ]; do
                  case "$1" in
                    --password-fd)
                      fd="${{2:-}}"; shift 2 ;;
                    --user)
                      [ "${{2:-}}" = test-user ] || exit 2
                      saw_user=1; shift 2 ;;
                    --apple-security=36)
                      saw_type36=1; shift ;;
                    --apple-postauth=records)
                      saw_records=1; shift ;;
                    --apple-attach=share)
                      saw_share=1; shift ;;
                    --presenter)
                      [ "${{2:-}}" = null ] || exit 2
                      saw_null=1; shift 2 ;;
                    --view-only)
                      saw_view_only=1; shift ;;
                    --auth|--connect-timeout)
                      shift 2 ;;
                    *) shift ;;
                  esac
                done
                [[ "$fd" =~ ^[0-9]+$ ]] || exit 2
                IFS= read -r -u "$fd" password || true
                [ "$password" = test-password ] || exit 2
                [ "$saw_user$saw_type36$saw_records$saw_null$saw_view_only$saw_share" = 111111 ] || exit 2
                {marker}sleep 10
                """
            ),
            encoding="utf-8",
        )
        fake.chmod(0o755)
        return fake

    def run_with_password(
        self, fake: Path, *, host: str = "authorized.example.invalid"
    ) -> subprocess.CompletedProcess[str]:
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b"test-password\n")
            os.close(write_fd)
            write_fd = -1
            env = os.environ.copy()
            env.update(
                FARSEE_BIN=str(fake),
                FARSEE_USER="test-user",
                FARSEE_PASSWORD_FD=str(read_fd),
                FARSEE_APPLE_SECURITY="36",
                FARSEE_ACCEPTANCE_DURATION="1",
            )
            return subprocess.run(
                [str(RUNNER), host],
                cwd=ROOT,
                env=env,
                pass_fds=(read_fd,),
                capture_output=True,
                text=True,
                timeout=10,
            )
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)

    def test_forced_type36_record_session_passes_after_bounded_run(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = self.run_with_password(self.make_fake(Path(raw)))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("RESULT: PASS", result.stdout)
            self.assertIn("APPLE_SECURITY: 36", result.stdout)
            self.assertIn("RECORD_LAYER: active", result.stdout)
            self.assertNotIn("test-password", result.stdout + result.stderr)
            self.assertNotIn("authorized.example.invalid", result.stdout)

    def test_missing_record_session_marker_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fake = self.make_fake(Path(raw), record_marker=False)
            result = self.run_with_password(fake)
            self.assertEqual(result.returncode, 1)
            self.assertIn("RESULT: FAIL", result.stdout)
            self.assertIn("record layer did not become active", result.stderr)

    def test_absent_host_reports_needs_hardware(self) -> None:
        env = os.environ.copy()
        env["FARSEE_BIN"] = "/bin/true"
        result = subprocess.run(
            [str(RUNNER)], cwd=ROOT, env=env,
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 3)
        self.assertIn("NEEDS_HARDWARE", result.stderr)

    def test_invalid_password_fd_is_rejected_before_connection(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fake = Path(raw) / "farsee-fake"
            fake.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
            fake.chmod(0o755)
            env = os.environ.copy()
            env.update(
                FARSEE_BIN=str(fake),
                FARSEE_USER="test-user",
                FARSEE_PASSWORD_FD="not-an-fd",
            )
            result = subprocess.run(
                [str(RUNNER), "authorized.example.invalid"], cwd=ROOT, env=env,
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("FARSEE_PASSWORD_FD", result.stderr)


if __name__ == "__main__":
    unittest.main()
