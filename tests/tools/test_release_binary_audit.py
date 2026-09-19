# SPDX-License-Identifier: Apache-2.0
"""Tests for release binary lab/debug residue checks."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
import json


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "release_binary_audit", ROOT / "tools" / "release_binary_audit.py"
)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)
POLICY = json.loads((ROOT / "release" / "binary-policy.json").read_text(
    encoding="utf-8"
))


class ReleaseBinaryAuditTests(unittest.TestCase):
    def test_forbidden_symbol_is_rejected(self) -> None:
        policy = {"forbidden_symbol_patterns": ["^fake_apple_"]}
        errors = AUDIT.audit_outputs(policy, "0000 T fake_apple_start\n", "")
        self.assertTrue(any("fake_apple_start" in error for error in errors))

    def test_forbidden_debug_string_is_rejected(self) -> None:
        policy = {"forbidden_string_patterns": ["FARSEE_DUMP_SECRET"]}
        errors = AUDIT.audit_outputs(policy, "0000 T farsee_main\n", "FARSEE_DUMP_SECRET\n")
        self.assertTrue(any("FARSEE_DUMP_SECRET" in error for error in errors))

    def test_apple_product_symbol_is_allowed(self) -> None:
        policy = {
            "forbidden_symbol_patterns": ["^fake_apple_"],
            "forbidden_string_patterns": ["FARSEE_DUMP_SECRET"],
        }
        errors = AUDIT.audit_outputs(
            policy,
            "0000 T apple_mvs_stream_decode_next\n",
            "APPLE_SECURITY_TYPE_33\n",
        )
        self.assertEqual(errors, [])

    def test_shipped_policy_rejects_test_seams_on_elf_and_darwin(self) -> None:
        for symbol in (
            "rfb_session_test_publish_frame",
            "_rfb_session_test_publish_frame",
        ):
            with self.subTest(symbol=symbol):
                errors = AUDIT.audit_outputs(
                    POLICY,
                    f"0000000000000000 T {symbol}\n",
                    "",
                )
                self.assertTrue(any(symbol in error for error in errors))

    def test_shipped_policy_allows_undefined_and_neutral_product_symbols(self) -> None:
        errors = AUDIT.audit_outputs(
            POLICY,
            "                 U rfb_session_test_publish_frame\n"
            "0000000000000000 T rfb_session_process_input\n",
            "",
        )
        self.assertEqual(errors, [])

    def test_shipped_policy_rejects_removed_dump_surface(self) -> None:
        symbols = (
            "rfb_presenter_dump_init",
            "rfb_presenter_dump_ops",
            "rfb_capture_frame_write",
            "rfb_secret_write_file_0600",
        )
        strings = (
            "--dump-frame",
            "--presenter dump",
            "--presenter=dump",
            "--presenter auto|kitty|dump|null",
            "dump",
            "FARSEE_APPLE_DUMP_DIR",
            "FARSEE_DUMP_FRAME",
        )
        for symbol in symbols:
            with self.subTest(symbol=symbol):
                errors = AUDIT.audit_outputs(
                    POLICY, f"0000000000000000 T {symbol}\n", ""
                )
                self.assertIn(f"forbidden release symbol: {symbol}", errors)
        for value in strings:
            with self.subTest(value=value):
                errors = AUDIT.audit_outputs(POLICY, "", value + "\n")
                self.assertIn(f"forbidden release string: {value}", errors)

    def test_shipped_policy_rejects_plaintext_evidence_surface(self) -> None:
        symbols = (
            "rfb_capture_evidence_fd_valid",
            "rfb_capture_evidence_fds_distinct",
            "rfb_capture_evidence_write",
            "rfb_capture_setup_evidence_write",
            "session_queue_capture_setup",
            "session_queue_capture_setup_with_writer",
        )
        for symbol in symbols:
            with self.subTest(symbol=symbol):
                errors = AUDIT.audit_outputs(
                    POLICY, f"0000000000000000 T {symbol}\n", ""
                )
                self.assertIn(f"forbidden release symbol: {symbol}", errors)

    def test_shipped_policy_rejects_capture_diagnostic_interfaces(self) -> None:
        symbols = (
            "rfb_capture_control_encode",
            "rfb_capture_control_decode",
            "rfb_capture_control_endpoint_valid",
            "rfb_capture_control_drain_ack",
            "rfb_capture_schedule_v2_parse",
            "rfb_capture_metadata_v1_decode",
        )
        for prefix in ("", "_"):
            for symbol in symbols:
                exported = prefix + symbol
                with self.subTest(symbol=exported):
                    errors = AUDIT.audit_outputs(
                        POLICY, f"0000000000000000 T {exported}\n", ""
                    )
                    self.assertIn(
                        f"forbidden release symbol: {exported}", errors
                    )

    def test_shipped_policy_rejects_cpu_probe_surface(self) -> None:
        symbols = tuple(
            prefix + stem
            for stem in (
                "farsee_cpu_probe_begin",
                "farsee_cpu_probe_present_skip",
            )
            for prefix in ("", "_")
        )
        strings = (
            "FARSEE_CPU_PROBE",
            "farsee.cpu_probe",
        )
        for symbol in symbols:
            with self.subTest(symbol=symbol):
                errors = AUDIT.audit_outputs(
                    POLICY, f"0000000000000000 T {symbol}\n", ""
                )
                self.assertIn(f"forbidden release symbol: {symbol}", errors)
        for value in strings:
            with self.subTest(value=value):
                errors = AUDIT.audit_outputs(POLICY, "", value + "\n")
                self.assertIn(f"forbidden release string: {value}", errors)

    def test_shipped_policy_rejects_shared_log_scratch(self) -> None:
        for symbol in (
            "rfb_log_escape_remote_tmp",
            "_rfb_log_escape_remote_tmp",
        ):
            with self.subTest(symbol=symbol):
                errors = AUDIT.audit_outputs(
                    POLICY, f"0000000000000000 T {symbol}\n", ""
                )
                self.assertIn(f"forbidden release symbol: {symbol}", errors)

    def test_test_runner_is_outside_the_release_binary_target(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        recipe = makefile.split("check-release-binary:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("$(RELEASE_BINARY)", recipe)
        self.assertNotIn("$(TEST_BINARY)", recipe)


if __name__ == "__main__":
    unittest.main()
