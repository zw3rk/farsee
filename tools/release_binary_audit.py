#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reject lab-only symbols and debug controls from a release binary."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


def audit_outputs(policy, nm_text: str, strings_text: str):
    errors = []
    symbol_patterns = [
        re.compile(pattern) for pattern in policy.get("forbidden_symbol_patterns", [])
    ]
    string_patterns = [
        re.compile(pattern) for pattern in policy.get("forbidden_string_patterns", [])
    ]
    symbols = []
    for line in nm_text.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        symbol_type = fields[-2]
        if len(symbol_type) != 1 or symbol_type.upper() == "U":
            continue
        symbols.append(fields[-1])
    for symbol in symbols:
        if any(pattern.search(symbol) for pattern in symbol_patterns):
            errors.append(f"forbidden release symbol: {symbol}")
    for line in strings_text.splitlines():
        if any(pattern.search(line) for pattern in string_patterns):
            errors.append(f"forbidden release string: {line}")
    return sorted(set(errors))


def run(command):
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")
    return result.stdout


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("policy", type=Path)
    args = parser.parse_args(argv)
    if not args.binary.is_file():
        parser.error(f"binary does not exist: {args.binary}")
    try:
        policy = json.loads(args.policy.read_text(encoding="utf-8"))
        if policy.get("schema") != 1:
            raise ValueError("schema must be 1")
        errors = audit_outputs(
            policy,
            run(["nm", "-g", str(args.binary)]),
            run(["strings", "-a", str(args.binary)]),
        )
    except (OSError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
        print(f"release-binary: {exc}")
        return 1
    if errors:
        for error in errors:
            print(f"release-binary: {error}")
        return 1
    print("ok: release binary contains no lab-only symbols or debug controls")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
