# SPDX-License-Identifier: Apache-2.0
"""Self-tests for the Apple behavior gate."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO / "tools" / "apple_preservation_gate.py"
SPEC = importlib.util.spec_from_file_location("apple_preservation_gate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)
MANIFEST = REPO / "tools" / "apple_preservation_manifest.json"


class ApplePreservationGateTests(unittest.TestCase):
    def test_comment_only_edit_preserves_semantic_digest(self) -> None:
        before = b'int f(void) { /* sample rationale */ return 0; }\n'
        after = b'// stable contract\nint f(void) { return 0; }\n'
        self.assertEqual(GATE.c_semantic_digest(before),
                         GATE.c_semantic_digest(after))

    def test_code_or_literal_edit_changes_semantic_digest(self) -> None:
        before = b'const char *s = "//data"; int n = 1;\n'
        changed_code = b'const char *s = "//data"; int n = 2;\n'
        changed_literal = b'const char *s = "/*data*/"; int n = 1;\n'
        self.assertNotEqual(GATE.c_semantic_digest(before),
                            GATE.c_semantic_digest(changed_code))
        self.assertNotEqual(GATE.c_semantic_digest(before),
                            GATE.c_semantic_digest(changed_literal))

    def test_preprocessor_line_boundary_changes_semantic_digest(self) -> None:
        separate = b"#define FEATURE 1\nint feature(void) { return FEATURE; }\n"
        joined = b"#define FEATURE 1 int feature(void) { return FEATURE; }\n"
        self.assertNotEqual(
            GATE.c_semantic_digest(separate), GATE.c_semantic_digest(joined)
        )

    def test_line_splicing_before_comment_removal_changes_semantic_digest(self) -> None:
        continued_comment = (
            b"#define FEATURE 1 // rationale \\\n"
            b"int feature(void) { return FEATURE; }\n"
        )
        terminated_comment = (
            b"#define FEATURE 1 // rationale\n"
            b"int feature(void) { return FEATURE; }\n"
        )
        self.assertNotEqual(
            GATE.c_semantic_digest(continued_comment),
            GATE.c_semantic_digest(terminated_comment),
        )

    def test_macro_name_parenthesis_adjacency_changes_semantic_digest(self) -> None:
        function_like = b"#define VALUE(x) ((x) + 1)\n"
        object_like = b"#define VALUE (x) ((x) + 1)\n"
        self.assertNotEqual(
            GATE.c_semantic_digest(function_like),
            GATE.c_semantic_digest(object_like),
        )

    def test_include_header_whitespace_changes_semantic_digest(self) -> None:
        compact = b"#include <farsee/apple_auth.h>\n"
        spaced = b"#include < farsee/apple_auth.h >\n"
        self.assertNotEqual(
            GATE.c_semantic_digest(compact), GATE.c_semantic_digest(spaced)
        )

    def test_preprocessor_comment_text_does_not_change_semantic_digest(self) -> None:
        before = b"#define VALUE 1 /* public rationale */\n"
        after = b"#define VALUE 1 /* updated contract explanation */\n"
        self.assertEqual(
            GATE.c_semantic_digest(before), GATE.c_semantic_digest(after)
        )

    def test_protected_semantics_accept_comments_and_reject_code_or_literals(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "protected.c"
            original = b'const char *value = "wire"; int count = 1;\n'
            path.write_bytes(original)
            expected = {"protected.c": GATE.c_semantic_digest(original)}
            self.assertEqual(GATE.protected_semantic_errors(root, expected), [])

            path.write_bytes(
                b'// public contract\nconst char *value = "wire"; int count = 1;\n'
            )
            self.assertEqual(GATE.protected_semantic_errors(root, expected), [])

            path.write_bytes(b'const char *value = "wire"; int count = 2;\n')
            self.assertEqual(
                GATE.protected_semantic_errors(root, expected),
                ["semantic source change: protected.c"],
            )

            path.write_bytes(b'const char *value = "record"; int count = 1;\n')
            self.assertEqual(
                GATE.protected_semantic_errors(root, expected),
                ["semantic source change: protected.c"],
            )

    def test_test_inventory_ignores_comments_and_accepts_multiline_macro(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "cases.c"
            path.write_text(
                "// RFB_TEST(fake, ignored)\n"
                "RFB_TEST(\n  suite_name,\n  contract_name\n) {}\n",
                encoding="utf-8",
            )
            self.assertEqual(
                GATE.test_inventory(root, ["cases.c"]),
                ["suite_name::contract_name"],
            )

    def test_runner_inventory_omits_rdp_sources_when_rdp_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "tests" / "unit" / "rdp").mkdir(parents=True)
            (root / "tests" / "unit" / "apple.c").write_text(
                "RFB_TEST(apple, retained) {}\n", encoding="utf-8"
            )
            (root / "tests" / "unit" / "rdp" / "optional.c").write_text(
                "RFB_TEST(rdp, optional) {}\n", encoding="utf-8"
            )
            paths = [
                "tests/unit/apple.c",
                "tests/unit/rdp/optional.c",
            ]
            self.assertEqual(
                GATE.runner_test_inventory(root, paths, rdp_enabled=False),
                ["apple::retained"],
            )
            self.assertEqual(
                GATE.runner_test_inventory(root, paths, rdp_enabled=True),
                ["apple::retained", "rdp::optional"],
            )

    def test_fixture_digest_covers_paths_and_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "a").write_bytes(b"one")
            before = GATE.fixture_tree_digest(root)
            (root / "a").write_bytes(b"two")
            self.assertNotEqual(before, GATE.fixture_tree_digest(root))
            (root / "b").write_bytes(b"two")
            self.assertNotEqual(before, GATE.fixture_tree_digest(root))

    def test_symbol_parser_normalizes_platform_prefix(self) -> None:
        symbols = GATE.parse_nm_output(
            "_apple_record_open\n00000000 T apple_srp_compute_m2\n"
        )
        self.assertEqual(symbols, {"apple_record_open", "apple_srp_compute_m2"})

    def test_repository_manifest_matches_current_test_and_fixture_inventory(self) -> None:
        manifest = GATE.load_manifest(MANIFEST)
        protected = set(manifest["protected_sources"])
        protected.update(manifest["focused_test_sources"])
        self.assertEqual(set(manifest["protected_semantics_sha256"]), protected)
        self.assertEqual(
            GATE.protected_semantic_errors(
                REPO, manifest["protected_semantics_sha256"]
            ),
            [],
        )
        inventory = GATE.test_inventory(REPO, manifest["focused_test_sources"])
        self.assertEqual(len(inventory), manifest["test_inventory_count"])
        self.assertEqual(GATE.inventory_digest(inventory),
                         manifest["test_inventory_sha256"])
        for relative, expected in manifest["fixture_roots"].items():
            self.assertEqual(GATE.fixture_tree_digest(REPO / relative), expected)


if __name__ == "__main__":
    unittest.main()
