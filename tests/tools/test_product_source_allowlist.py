# SPDX-License-Identifier: Apache-2.0
"""The product link must use a closed source allowlist."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"


def make_paths(variable: str, rdp: bool, build: str = "dev") -> set[Path]:
    result = subprocess.run(
        ["make", "-pn", f"FARSEE_WITH_RDP={int(rdp)}", f"BUILD={build}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    # `make -pn` may report that the default help target is not remade; its
    # database remains authoritative for these immediate variables.
    prefix = f"{variable} := "
    for line in result.stdout.splitlines():
        if line.startswith(prefix):
            return {Path(item).resolve() for item in line[len(prefix):].split()}
    raise AssertionError(f"{variable} is absent from the Make database")


def product_sources(rdp: bool, build: str = "dev") -> set[Path]:
    return make_paths("PRODUCT_LIB_SRCS", rdp, build)


class ProductSourceAllowlistTests(unittest.TestCase):
    def test_allowlist_uses_no_discovery_or_subtractive_expression(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        section = text.split("# BEGIN PRODUCT SOURCE ALLOWLIST", 1)[1].split(
            "# END PRODUCT SOURCE ALLOWLIST", 1
        )[0]
        for forbidden in ("$(wildcard", "$(filter-out", "$(shell", "find "):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, section)

    def test_every_allowlisted_source_exists_and_scaffold_is_excluded(self) -> None:
        sources = product_sources(rdp=True)
        self.assertTrue(sources)
        self.assertTrue(all(path.is_file() for path in sources))
        forbidden = {
            ROOT / "src/farsee/farsee_engine.c",
            ROOT / "src/farsee/farsee_reactor.c",
            ROOT / "src/rfb/apple_session.c",
            ROOT / "src/protocol/rdp/rdp_worker.c",
        }
        self.assertTrue(sources.isdisjoint({path.resolve() for path in forbidden}))

    def test_allowlist_preserves_the_reviewed_live_link_boundary(self) -> None:
        for rdp in (False, True):
            with self.subTest(rdp=rdp):
                expected = make_paths("LIB_SRCS", rdp) - make_paths(
                    "SCAFFOLD_SRCS", rdp
                )
                self.assertEqual(product_sources(rdp), expected)

    def test_apple_product_sources_are_listed_explicitly(self) -> None:
        sources = product_sources(rdp=False)
        expected = {
            path.resolve()
            for path in (ROOT / "src/rfb").glob("apple_*.c")
            if path.name != "apple_session.c"
        }
        expected.update(
            {
                (ROOT / "src/rfb/encoding_apple_0450.c").resolve(),
                (ROOT / "src/rfb/encoding_apple_mvs.c").resolve(),
                (ROOT / "src/crypto/apple_crypto.c").resolve(),
            }
        )
        self.assertTrue(expected)
        self.assertEqual(expected - sources, set())

    def test_shared_credential_prompt_is_in_the_product(self) -> None:
        expected = (ROOT / "src/app/credential_prompt.c").resolve()
        self.assertIn(expected, product_sources(rdp=False))
        self.assertIn(expected, product_sources(rdp=True))

    def test_apple_auth_fake_is_a_bounded_test_adapter(self) -> None:
        public_header = (ROOT / "include/farsee/apple_auth.h").read_text(
            encoding="utf-8"
        )
        product_source = (ROOT / "src/rfb/apple_auth.c").read_text(
            encoding="utf-8"
        )
        adapter_header = ROOT / "tests/fakes/apple_auth_fake.h"
        adapter_source = ROOT / "tests/fakes/apple_auth_fake.c"

        self.assertNotIn("apple_auth_fake", public_header)
        self.assertNotIn("apple_auth_fake", product_source)
        self.assertTrue(adapter_header.is_file())
        self.assertTrue(adapter_source.is_file())
        self.assertNotIn(adapter_source.resolve(), product_sources(rdp=False))
        self.assertNotIn(adapter_source.resolve(), product_sources(rdp=True))

    def test_fake_apple_server_is_a_bounded_test_adapter(self) -> None:
        public_header = ROOT / "include/farsee/fake_apple_server.h"
        product_source = ROOT / "src/rfb/fake_apple_server.c"
        adapter_header = ROOT / "tests/fakes/fake_apple_server.h"
        adapter_source = ROOT / "tests/fakes/fake_apple_server.c"

        self.assertFalse(public_header.exists())
        self.assertFalse(product_source.exists())
        self.assertTrue(adapter_header.is_file())
        self.assertTrue(adapter_source.is_file())
        self.assertIn(
            adapter_source.resolve(), make_paths("TEST_FAKES_SRCS", True)
        )
        self.assertNotIn(adapter_source.resolve(), product_sources(rdp=False))
        self.assertNotIn(adapter_source.resolve(), product_sources(rdp=True))

    def test_apple_product_symbol_inventory_excludes_test_adapters(self) -> None:
        symbols = {
            line.strip()
            for line in (
                ROOT / "tools/apple_preservation_symbols.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
        self.assertNotIn("apple_auth_fake_ctx", symbols)
        self.assertNotIn("apple_auth_fake_init", symbols)
        self.assertFalse(any(symbol.startswith("fake_apple_") for symbol in symbols))

    def test_rdp_sources_are_enabled_only_by_the_feature(self) -> None:
        with_rdp = product_sources(rdp=True)
        without_rdp = product_sources(rdp=False)
        self.assertFalse(any("/protocol/rdp/" in str(path) for path in without_rdp))
        self.assertTrue(any("/protocol/rdp/" in str(path) for path in with_rdp))

    def test_capture_artifact_and_control_are_diagnostic_product_sources(self) -> None:
        diagnostic = {
            (ROOT / "src/rfb/rfb_capture_artifact.c").resolve(),
            (ROOT / "src/rfb/rfb_capture_control.c").resolve(),
        }
        for build in ("dev", "asan-ubsan", "coverage", "fuzz"):
            with self.subTest(build=build):
                self.assertLessEqual(diagnostic, product_sources(True, build))
        for rdp in (False, True):
            with self.subTest(release_rdp=rdp):
                self.assertTrue(
                    diagnostic.isdisjoint(product_sources(rdp, "release"))
                )
        self.assertLessEqual(diagnostic, product_sources(False, "dev"))
        for rdp in (False, True):
            with self.subTest(test_library_rdp=rdp):
                self.assertLessEqual(diagnostic, make_paths("LIB_SRCS", rdp))

        release_test_objects = make_paths("TEST_LIB_OBJS", True, "release")
        for source in (
            "rfb_session_capture.o",
            "rfb_session_connect.o",
        ):
            with self.subTest(release_test_object=source):
                self.assertTrue(
                    any(
                        str(path).endswith(f"/test-lib/rfb/{source}")
                        for path in release_test_objects
                    )
                )
                self.assertFalse(
                    any(
                        str(path).endswith(f"/obj/rfb/{source}")
                        for path in release_test_objects
                    )
                )

    def test_product_environment_reads_are_closed_and_non_wire(self) -> None:
        allowed = {
            (ROOT / "src/rfb/apple_type33_connect.c").resolve(): {"HOME"},
            (ROOT / "src/app/rdp_live.c").resolve(): {"HOME"},
        }
        observed: dict[Path, set[str]] = {}
        pattern = re.compile(r'\bgetenv\s*\(\s*"([^"]+)"\s*\)')
        for path in product_sources(rdp=True):
            text = path.read_text(encoding="utf-8")
            matches = set(pattern.findall(text))
            self.assertEqual(len(re.findall(r"\bgetenv\s*\(", text)),
                             len(pattern.findall(text)), path)
            for forbidden_api in ("secure_getenv", "setenv", "unsetenv", "putenv"):
                self.assertNotRegex(text, rf"\b{forbidden_api}\s*\(", path)
            if matches:
                observed[path] = matches
        self.assertEqual(observed, allowed)


if __name__ == "__main__":
    unittest.main()
