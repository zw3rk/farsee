# SPDX-License-Identifier: Apache-2.0
"""Enforce clearing of OpenSSL BIGNUM owners used by SRP arithmetic."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / "src" / "crypto" / "apple_crypto.c"
FUNCTIONS = {
    "rfb_crypto_modexp": {"bn_base", "bn_exp", "bn_mod", "bn_result"},
    "rfb_crypto_modmul": {"bn_a", "bn_b", "bn_mod", "bn_result"},
    "rfb_crypto_modadd": {"bn_a", "bn_b", "bn_mod", "bn_result"},
    "rfb_crypto_modsub": {"bn_a", "bn_b", "bn_mod", "bn_result"},
}


def function_body(source: str, name: str) -> str:
    start = source.index(f"bool {name}(")
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening : index + 1]
    raise AssertionError(f"unterminated function: {name}")


class BignumCleanupTests(unittest.TestCase):
    def test_modular_arithmetic_clears_every_owned_bignum(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        for name, expected_owners in FUNCTIONS.items():
            with self.subTest(function=name):
                body = function_body(source, name)
                owners = set(re.findall(
                    r"\bBIGNUM\s+\*([A-Za-z_][A-Za-z0-9_]*)\s*=", body
                ))
                self.assertEqual(owners, expected_owners)
                self.assertNotIn("BN_free(", body)
                for owner in sorted(owners):
                    self.assertEqual(body.count(f"BN_clear_free({owner});"), 1)
                self.assertEqual(body.count("BN_CTX_free(bn_ctx);"), 1)
                first_owner = min(body.index(f"BIGNUM *{owner}")
                                  for owner in owners)
                self.assertEqual(body[first_owner:].count("return "), 1)


if __name__ == "__main__":
    unittest.main()
