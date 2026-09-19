#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Common-header dependency boundary check (gate F1).

The Farsee common public headers (``include/farsee/farsee_*.h``) MUST NOT
expose protocol- or platform-specific types. Specifically no symbol from
this list may appear *in code* (a comment mentioning a name for
documentation is allowed, since it is not a type dependency):

    rfb_  freerdp  winpr  spice  ahpss
    openssl  commonCrypto  Security/  CoreCrypto
    pthread  <sys/  windows.h  winsock  dispatch.h
    kitty

The scan strips C/C++ comments before matching, so prose references in
comments do not trip it. A real ``#include <pthread.h>`` or
``rfb_framebuffer`` type usage does.

Exits non-zero with a diagnostic if any forbidden token is found in code.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# Tokens that, if they appear in CODE (not comments), indicate a forbidden
# type/include has leaked through the common boundary.
FORBIDDEN = [
    "rfb_", "freerdp", "winpr", "spice", "ahpss",
    "openssl", "commonCrypto", "Security/", "CoreCrypto",
    "pthread", "<sys/", "windows.h", "winsock", "dispatch.h",
    "kitty",
]

# Strip C block comments, line comments, and string/char literals so that
# only identifiers and preprocessor tokens remain for matching.
_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE = re.compile(r"//[^\n]*")
_STR = re.compile(r'"(\\.|[^"\\])*"')


def strip_to_code(text: str) -> str:
    text = _BLOCK.sub(" ", text)
    text = _LINE.sub(" ", text)
    text = _STR.sub(" ", text)
    return text


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_common_headers.py <include-dir>", file=sys.stderr)
        return 2
    inc = Path(argv[1])
    if not inc.is_dir():
        print(f"not a directory: {inc}", file=sys.stderr)
        return 2
    headers = sorted(inc.glob("farsee/farsee_*.h"))
    if not headers:
        print("no common headers found", file=sys.stderr)
        return 1
    failures = 0
    for h in headers:
        code = strip_to_code(h.read_text(encoding="utf-8", errors="replace"))
        for tok in FORBIDDEN:
            if tok in code:
                print(f"{h}: forbidden token '{tok}' in common header code",
                      file=sys.stderr)
                failures += 1
    if failures:
        print(f"\n{failures} common header boundary violation(s).",
              file=sys.stderr)
        return 1
    print(f"common header boundary check: {len(headers)} header(s) clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
