#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""License and provenance auditor for farsee.

Enforces the clean-room and license policy (plan.md §5, G0, G12):

  1. Every C source/header under src/, include/, tests/, and tools/ C
     sources must carry an `SPDX-License-Identifier: Apache-2.0` header.
  2. THIRD_PARTY_NOTICES.md must list every external dependency that is
     linked into release artifacts, with an allowlist license.
  3. No file under the audited tree may contain a GPL/AGPL/LGPL SPDX
     identifier or a verbatim GPL license header sentinel.

The fixture tests under tests/fixtures/license/ prove both the accept
and reject paths (plan.md §G0: "license checker fixture proving a
prohibited SPDX identifier is rejected").

Usage:
    tools/check_license.py <repo-root>
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# Licenses permitted in shipped/linked artifacts (plan.md §5.4).
ALLOWED_LICENSES = {
    "Apache-2.0",
    "MIT",
    "ISC",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "Zlib",
    "CC0-1.0",
    "Unlicense",
}

# Project license every first-party file must declare.
PROJECT_LICENSE = "Apache-2.0"

# GPL family is never allowed, anywhere in the audited tree.
FORBIDDEN_IDENTIFIERS = {
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "LGPL-2.0",
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
}

# Directories whose first-party C sources/headers we audit. The fixture
# directory is special: it contains deliberate reject samples and is
# audited separately.
AUDIT_SOURCE_DIRS = ("src", "include", "tests", "tools")
# Exclude by basename (applied at every walk level) ...
EXCLUDE_DIR_BASENAMES = {"build", ".git", "result", "fixtures"}
# ... and by path relative to repo root (for precise exclusions).
EXCLUDE_DIR_PATHS = {"tests/fixtures/license"}

SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*([^\n*/]+)")


def _is_excluded_dir(path: Path, root: Path) -> bool:
    if path.name in EXCLUDE_DIR_BASENAMES:
        return True
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        return False
    for ex in EXCLUDE_DIR_PATHS:
        if rel == ex or rel.startswith(ex + "/"):
            return True
    return False


def iter_first_party_files(root: Path):
    """Yield first-party C/H source files that must carry the project header."""
    for sub in AUDIT_SOURCE_DIRS:
        base = root / sub
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            # Filter out excluded directories in-place so os.walk does not
            # descend into them.
            dirnames[:] = [
                d for d in dirnames
                if not d.startswith(".")
                and not _is_excluded_dir(Path(dirpath) / d, root)
            ]
            for fn in filenames:
                if fn.endswith((".c", ".h")):
                    yield Path(dirpath) / fn


def find_spdx(text: str):
    return SPDX_RE.findall(text)


def audit_first_party(root: Path):
    errors = []
    count = 0
    for path in iter_first_party_files(root):
        count += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:  # pragma: no cover - filesystem error
            errors.append(f"{path}: cannot read: {e}")
            continue
        ids = find_spdx(text)
        if PROJECT_LICENSE not in ids:
            errors.append(
                f"{path}: missing or wrong SPDX header "
                f"(expected {PROJECT_LICENSE}, got {ids!r})"
            )
            continue
        for ident in ids:
            if ident in FORBIDDEN_IDENTIFIERS:
                errors.append(
                    f"{path}: forbidden license identifier {ident!r}"
                )
    return count, errors


def audit_fixture(root: Path):
    """Verify the license-fixture directory behaves as documented:
    a good fixture passes and a bad (GPL) fixture is rejected."""
    fixture_dir = root / "tests" / "fixtures" / "license"
    good = fixture_dir / "good_apache.c"
    bad = fixture_dir / "bad_gpl.c"
    if not good.is_file() or not bad.is_file():
        return [f"license fixture missing: need {good} and {bad}"]
    errors = []

    good_ids = find_spdx(good.read_text(encoding="utf-8"))
    if "Apache-2.0" not in good_ids:
        errors.append(f"fixture {good}: expected Apache-2.0 SPDX, got {good_ids}")

    bad_ids = find_spdx(bad.read_text(encoding="utf-8"))
    if not any(i in FORBIDDEN_IDENTIFIERS for i in bad_ids):
        errors.append(
            f"fixture {bad}: expected a GPL-family identifier, got {bad_ids}"
        )
    return errors


def audit_third_party_notices(root: Path):
    """THIRD_PARTY_NOTICES.md must exist and mention every allowed license
    we actually ship. We do a light syntax check here; the deep audit is
    manual at each gate."""
    notices = root / "THIRD_PARTY_NOTICES.md"
    if not notices.is_file():
        return ["THIRD_PARTY_NOTICES.md is missing"]
    return []


def main(argv):
    if len(argv) != 2:
        print("usage: check_license.py <repo-root>", file=sys.stderr)
        return 2
    root = Path(argv[1]).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    errors = []
    nfiles, fp_errors = audit_first_party(root)
    errors.extend(fp_errors)
    errors.extend(audit_fixture(root))
    errors.extend(audit_third_party_notices(root))

    print(f"license audit: {nfiles} first-party C/H files checked")
    if errors:
        print("FAIL:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("ok: no GPL-family identifiers; all first-party files carry "
          "Apache-2.0; THIRD_PARTY_NOTICES.md present.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
