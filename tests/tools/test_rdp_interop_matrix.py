# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the executable RDP interoperability matrix."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "tools" / "rdp_interop_matrix.sh"


class RdpInteropMatrixTests(unittest.TestCase):
    def make_fake(self, temp: Path) -> Path:
        fake = temp / "farsee-fake"
        fake.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                # SPDX-License-Identifier: Apache-2.0
                set -u
                fd=""
                while [ "$#" -gt 0 ]; do
                  case "$1" in
                    --password-fd)
                      fd="${2:-}"
                      [[ "$fd" =~ ^[0-9]+$ ]] || exit 2
                      shift 2
                      ;;
                    --desktop-w|--desktop-h)
                      [[ "${2:-}" =~ ^[0-9]+$ ]] || exit 2
                      shift 2
                      ;;
                    --presenter)
                      [ "${2:-}" = null ] || exit 2
                      shift 2
                      ;;
                    --cert)
                      [ "${2:-}" = pin ] || exit 2
                      shift 2
                      ;;
                    --clipboard)
                      [[ "${2:-}" = on || "${2:-}" = off ]] || exit 2
                      shift 2
                      ;;
                    --view-only)
                      shift
                      ;;
                    --desktop-size)
                      exit 2
                      ;;
                    *)
                      shift
                      ;;
                  esac
                done
                [ -n "$fd" ] || exit 2
                IFS= read -r -u "$fd" password || true
                if [ "${RDP_TEST_ECHO_PASSWORD:-0}" = 1 ]; then
                  printf 'diagnostic=%s\n' "$password" >&2
                fi
                [ "${RDP_TEST_CHANGED_CERT:-0}" = 1 ] && exit 4
                [ "$password" = wrong-password ] && exit 4
                [ "$password" = "${RDP_TEST_EXPECTED_PASSWORD:-test-password}" ] || exit 2
                exit 0
                """
            ),
            encoding="utf-8",
        )
        fake.chmod(0o755)
        return fake

    def test_xrdp_matrix_uses_valid_cli_and_integer_password_fd(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            fake = self.make_fake(temp)
            out = temp / "evidence"
            env = os.environ.copy()
            env.update(
                FARSEE_BIN=str(fake),
                RDP_XRDP_HOST="tester@example.invalid",
                RDP_XRDP_PW="test-password",
            )
            result = subprocess.run(
                [str(MATRIX), str(out)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            records = sorted(out.glob("*.txt"))
            self.assertEqual(len(records), 3)
            for record in records:
                self.assertIn("RESULT: PASS", record.read_text(encoding="utf-8"))

    def test_changed_certificate_is_a_separate_post_rotation_phase(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            fake = self.make_fake(temp)
            out = temp / "evidence"
            env = os.environ.copy()
            env.update(
                FARSEE_BIN=str(fake),
                RDP_MATRIX_PHASE="changed-cert",
                RDP_WIN_TOFU_HOST="tester@example.invalid",
                RDP_WIN_PW="test-password",
                RDP_TEST_CHANGED_CERT="1",
            )
            result = subprocess.run(
                [str(MATRIX), str(out)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            records = sorted(out.glob("*.txt"))
            self.assertEqual(
                [record.name for record in records],
                ["win-changed-cert-reject.txt"],
            )
            self.assertIn(
                "RESULT: PASS", records[0].read_text(encoding="utf-8")
            )

    def test_evidence_redaction_treats_password_as_literal_text(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            fake = self.make_fake(temp)
            out = temp / "evidence"
            password = r"test/[&].*\\password"
            env = os.environ.copy()
            env.update(
                FARSEE_BIN=str(fake),
                RDP_XRDP_HOST="tester@example.invalid",
                RDP_XRDP_PW=password,
                RDP_TEST_EXPECTED_PASSWORD=password,
                RDP_TEST_ECHO_PASSWORD="1",
            )
            result = subprocess.run(
                [str(MATRIX), str(out)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            contents = [
                record.read_text(encoding="utf-8")
                for record in out.glob("*.txt")
            ]
            self.assertTrue(contents)
            self.assertFalse(any(password in content for content in contents))
            self.assertTrue(
                any("diagnostic=<REDACTED>" in content for content in contents)
            )


if __name__ == "__main__":
    unittest.main()
