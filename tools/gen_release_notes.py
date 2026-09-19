#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Extract one exact changelog section as deterministic release notes."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re

from gen_version_header import parse_version


HEADING = re.compile(r"^## \[([^]\r\n]+)\][^\r\n]*$", re.MULTILINE)


def extract(changelog: str, version: str) -> str:
    parse_version(version)
    matches = [match for match in HEADING.finditer(changelog)
               if match.group(1) == version]
    if len(matches) != 1:
        raise ValueError(
            f"expected one changelog section for {version}, found {len(matches)}"
        )
    match = matches[0]
    next_heading = HEADING.search(changelog, match.end())
    end = next_heading.start() if next_heading is not None else len(changelog)
    body = changelog[match.end():end].strip()
    if not body:
        raise ValueError(f"empty changelog section for {version}")
    return (
        "<!-- SPDX-License-Identifier: Apache-2.0 -->\n\n"
        f"# farsee {version} release notes\n\n{body}\n"
    )


def write_if_changed(path: Path, content: str) -> None:
    try:
        if path.read_text(encoding="utf-8") == content:
            return
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("changelog", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--version")
    args = parser.parse_args()
    version = args.version or os.environ.get("FARSEE_GUARD_VERSION")
    if version is None:
        parser.error("--version or FARSEE_GUARD_VERSION is required")
    try:
        notes = extract(
            args.changelog.read_text(encoding="utf-8"), version
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    write_if_changed(args.output, notes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
