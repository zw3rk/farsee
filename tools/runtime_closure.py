#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Resolve the complete dynamic-library closure of one release binary.

The output is one canonical absolute path per line. The license gate consumes
that file through FARSEE_RUNTIME_CLOSURE. Resolution fails closed on loader
tokens and missing libraries because an incomplete inventory is not an audit.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def parse_otool(text: str):
    paths = []
    errors = []
    for raw in text.splitlines()[1:]:
        line = raw.strip()
        if not line:
            continue
        path = line.split(" (", 1)[0]
        if path.startswith("@"):
            errors.append(f"unresolved Mach-O loader path: {path}")
        elif os.path.isabs(path):
            paths.append(path)
        else:
            errors.append(f"unrecognized otool dependency: {line}")
    return paths, errors


def parse_ldd(text: str):
    paths = []
    errors = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("linux-vdso"):
            continue
        if "=>" in line:
            name, resolved = line.split("=>", 1)
            resolved = resolved.strip()
            if resolved.startswith("not found"):
                errors.append(f"dynamic library not found: {name.strip()}")
                continue
            path = resolved.split(" ", 1)[0]
        else:
            path = line.split(" ", 1)[0]
        if os.path.isabs(path):
            paths.append(path)
        else:
            errors.append(f"unrecognized ldd dependency: {line}")
    return paths, errors


def dependencies(path: Path):
    if sys.platform == "darwin":
        command = ["otool", "-L", str(path)]
        parser = parse_otool
    elif sys.platform.startswith("linux"):
        command = ["ldd", str(path)]
        parser = parse_ldd
    else:
        return [], [f"unsupported runtime-closure platform: {sys.platform}"]
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        return [], [f"{' '.join(command)} failed ({result.returncode}): {detail}"]
    return parser(result.stdout)


def collect(binary: Path):
    pending = [binary.resolve()]
    inspected = set()
    closure = set()
    errors = []
    while pending:
        current = pending.pop()
        key = str(current)
        if key in inspected:
            continue
        inspected.add(key)
        paths, current_errors = dependencies(current)
        errors.extend(current_errors)
        for raw in paths:
            path = Path(raw)
            closure.add(raw)
            if raw.startswith("/nix/store/") and raw not in inspected:
                if not path.is_file():
                    errors.append(f"runtime dependency is not a file: {raw}")
                else:
                    pending.append(path)
    return sorted(closure), errors


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    if not args.binary.is_file():
        parser.error(f"binary does not exist: {args.binary}")
    paths, errors = collect(args.binary)
    if errors:
        for error in errors:
            print(f"runtime-closure: {error}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(f"{path}\n" for path in paths), encoding="utf-8")
    print(f"runtime-closure: {len(paths)} libraries -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
