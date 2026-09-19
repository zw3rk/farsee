# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the bounded macOS interoperability runner."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tools" / "macos_acceptance.sh"
TEST_REVISION = subprocess.run(
    ["git", "rev-parse", "HEAD"],
    cwd=ROOT,
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
TEST_VERSION = "0.1.0-dev"
APPROVED_SIGNING_SHA1 = json.loads(
    (ROOT / "release" / "approval.json").read_text(encoding="utf-8")
)["signing_identity_approval"]["evidence"].removeprefix("sha1:")


class MacosAcceptanceTests(unittest.TestCase):
    def make_signing_tools(
        self, temp: Path, *, fingerprint: str = APPROVED_SIGNING_SHA1,
        valid_signature: bool = True,
    ) -> Path:
        tool_dir = temp / "tools"
        tool_dir.mkdir()
        codesign = tool_dir / "codesign"
        verify_status = 0 if valid_signature else 1
        codesign.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env bash
                set -u
                case " $* " in
                  *" --verify "*) exit {verify_status} ;;
                  *" --verbose=4 "*)
                    echo 'Identifier=com.zw3rk.farsee' >&2
                    echo 'Authority=Developer ID Application: Test' >&2
                    echo 'TeamIdentifier=TESTTEAM01' >&2
                    exit 0 ;;
                esac
                for arg in "$@"; do
                  case "$arg" in
                    --extract-certificates=*)
                      prefix="${{arg#--extract-certificates=}}"
                      : > "${{prefix}}0"
                      exit 0 ;;
                  esac
                done
                exit 2
                """
            ),
            encoding="utf-8",
        )
        codesign.chmod(0o755)
        openssl = tool_dir / "openssl"
        openssl.write_text(
            "#!/bin/sh\necho 'sha1 Fingerprint=" + fingerprint + "'\n",
            encoding="utf-8",
        )
        openssl.chmod(0o755)
        return tool_dir

    def make_fake(
        self, temp: Path, *, record_marker: bool = True,
        wire_record_marker: bool = False,
        name: str = "farsee-fake",
    ) -> Path:
        fake = temp / name
        if wire_record_marker:
            marker = 'echo "farsee: Apple AES-CBC records active" >&2\n'
        elif record_marker:
            marker = (
                'echo "farsee: Apple AES-CBC record layer active '
                '(0x044f rekey; AES-CBC records on wire)." >&2\n'
            )
        else:
            marker = ""
        fake.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env bash
                # SPDX-License-Identifier: Apache-2.0
                set -u
                if [ "${{1:-}}" = --version ]; then
                  echo "farsee {TEST_VERSION} git={TEST_REVISION} built=test"
                  exit 0
                fi
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
        self, fake: Path, *, host: str = "authorized.example.invalid",
        release_signing_tools: Path | None = None,
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
            if release_signing_tools is None:
                env.update(
                    FARSEE_ACCEPTANCE_EXPECTED_REVISION=TEST_REVISION,
                    FARSEE_ACCEPTANCE_EXPECTED_VERSION=TEST_VERSION,
                    FARSEE_ACCEPTANCE_TEST_ONLY="yes",
                )
            else:
                env["PATH"] = str(release_signing_tools) + os.pathsep + env["PATH"]
                env.pop("FARSEE_ACCEPTANCE_TEST_ONLY", None)
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
            fake = self.make_fake(Path(raw))
            result = self.run_with_password(fake)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("RESULT: TEST_ONLY_PASS", result.stdout)
            self.assertNotIn("RESULT: PASS", result.stdout)
            self.assertIn("APPLE_SECURITY: 36", result.stdout)
            self.assertIn("RECORD_LAYER: active", result.stdout)
            self.assertIn(f"CANDIDATE_VERSION: {TEST_VERSION}", result.stdout)
            self.assertIn(f"CANDIDATE_REVISION: {TEST_REVISION}", result.stdout)
            self.assertIn(
                "CANDIDATE_SHA256: " + hashlib.sha256(fake.read_bytes()).hexdigest(),
                result.stdout,
            )
            self.assertIn("CODESIGN: not-required", result.stdout)
            self.assertNotIn("test-password", result.stdout + result.stderr)
            self.assertNotIn("authorized.example.invalid", result.stdout)

    def test_release_evidence_requires_the_approved_signature(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            fake = self.make_fake(temp)
            tools = self.make_signing_tools(temp)
            result = self.run_with_password(fake, release_signing_tools=tools)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("EVIDENCE_CLASS: release-candidate", result.stdout)
            self.assertIn("CODESIGN: verified", result.stdout)
            self.assertIn("RESULT: PASS", result.stdout)
            self.assertNotIn("TEST_ONLY_PASS", result.stdout)

    def test_release_evidence_rejects_an_unapproved_signature(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            fake = self.make_fake(temp)
            tools = self.make_signing_tools(temp, fingerprint="0" * 40)
            result = self.run_with_password(fake, release_signing_tools=tools)
            self.assertEqual(result.returncode, 2)
            self.assertIn("signing identity is not approved", result.stderr)
            self.assertNotIn("RESULT: PASS", result.stdout)

    def test_release_evidence_rejects_an_invalid_signature(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            fake = self.make_fake(temp)
            tools = self.make_signing_tools(temp, valid_signature=False)
            result = self.run_with_password(fake, release_signing_tools=tools)
            self.assertEqual(result.returncode, 2)
            self.assertIn("code signature is invalid", result.stderr)
            self.assertNotIn("RESULT: PASS", result.stdout)

    def test_missing_record_session_marker_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fake = self.make_fake(Path(raw), record_marker=False)
            result = self.run_with_password(fake)
            self.assertEqual(result.returncode, 1)
            self.assertIn("RESULT: FAIL", result.stdout)
            self.assertIn("record layer did not become active", result.stderr)

    def test_wire_record_activation_marker_passes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fake = self.make_fake(
                Path(raw), record_marker=False, wire_record_marker=True
            )
            result = self.run_with_password(fake)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("RECORD_LAYER: active", result.stdout)

    def test_make_target_can_select_a_presigned_candidate(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn(
            "MACOS_ACCEPTANCE_BIN ?= $(BUILD_DIR)/release/bin/farsee",
            makefile,
        )
        recipe = makefile.split("macos-acceptance:", 1)[1].split("\n\n", 1)[0]
        command_lines = [line for line in recipe.splitlines() if line.startswith("\t")]
        self.assertNotIn("$(MACOS_ACCEPTANCE_BIN)", "\n".join(command_lines))

    def test_make_target_does_not_parse_candidate_path_as_shell(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            fake = self.make_fake(
                temp,
                name="farsee';printf-SHELL-INJECTION;'",
            )
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, b"test-password\n")
                os.close(write_fd)
                write_fd = -1
                env = os.environ.copy()
                env.update(
                    FARSEE_USER="test-user",
                    FARSEE_PASSWORD_FD=str(read_fd),
                    FARSEE_APPLE_SECURITY="36",
                    FARSEE_ACCEPTANCE_DURATION="1",
                    FARSEE_ACCEPTANCE_EXPECTED_REVISION=TEST_REVISION,
                    FARSEE_ACCEPTANCE_EXPECTED_VERSION=TEST_VERSION,
                )
                result = subprocess.run(
                    [
                        "make", "--silent", "macos-acceptance",
                        "MAKE=/usr/bin/true",
                        f"MACOS_ACCEPTANCE_BIN={fake}",
                        "MACOS_ACCEPTANCE_HOST=authorized.example.invalid",
                        "MACOS_ACCEPTANCE_TEST_ONLY=yes",
                    ],
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
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("SHELL-INJECTION", result.stdout + result.stderr)
            self.assertIn("RESULT: TEST_ONLY_PASS", result.stdout)
            self.assertNotIn("RESULT: PASS", result.stdout)

    def test_candidate_revision_mismatch_fails_before_connection(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fake = self.make_fake(Path(raw))
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
                    FARSEE_ACCEPTANCE_EXPECTED_REVISION="000000000000",
                    FARSEE_ACCEPTANCE_EXPECTED_VERSION=TEST_VERSION,
                    FARSEE_ACCEPTANCE_TEST_ONLY="yes",
                )
                result = subprocess.run(
                    [str(RUNNER), "authorized.example.invalid"],
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
            self.assertEqual(result.returncode, 2)
            self.assertIn("revision does not match", result.stderr)

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
                FARSEE_ACCEPTANCE_EXPECTED_REVISION=TEST_REVISION,
                FARSEE_ACCEPTANCE_EXPECTED_VERSION=TEST_VERSION,
                FARSEE_ACCEPTANCE_TEST_ONLY="yes",
            )
            result = subprocess.run(
                [str(RUNNER), "authorized.example.invalid"], cwd=ROOT, env=env,
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("FARSEE_PASSWORD_FD", result.stderr)


if __name__ == "__main__":
    unittest.main()
