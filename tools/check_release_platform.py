#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Enforce the machine-readable release-platform allowlist."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import re
import sys
from typing import Optional, Sequence


SYSTEM_RE = re.compile(r"^[a-z0-9_]+-(?:darwin|linux)$")


def host_system(os_name: str | None = None, machine: str | None = None) -> str:
    os_value = (os_name or platform.system()).lower()
    machine_value = (machine or platform.machine()).lower()
    architecture = {
        "amd64": "x86_64",
        "arm64": "aarch64",
    }.get(machine_value, machine_value)
    return f"{architecture}-{os_value}"


def validate_manifest(manifest: object) -> list[str]:
    if not isinstance(manifest, dict):
        return ["dependency manifest must be an object"]
    systems = manifest.get("release_platforms")
    if not isinstance(systems, list) or not systems:
        return ["release_platforms must be a non-empty list"]
    if not all(
        isinstance(system, str) and SYSTEM_RE.fullmatch(system)
        for system in systems
    ):
        return ["release_platforms must contain canonical Nix system names"]
    if systems != sorted(set(systems)):
        return ["release_platforms must be unique and sorted"]
    return []


def audit_manifest(manifest: object, system: str) -> list[str]:
    errors = validate_manifest(manifest)
    if errors:
        return errors
    assert isinstance(manifest, dict)
    if system not in manifest["release_platforms"]:
        errors.append(f"release artifacts are not approved for {system}")
    return errors


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check whether this host may produce farsee release artifacts."
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--system", help="Nix system name (tests only)")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if not args.quiet:
            print(f"release platform policy: {exc}", file=sys.stderr)
        return 2
    system = args.system or host_system()
    validation_errors = validate_manifest(manifest)
    if validation_errors:
        if not args.quiet:
            for error in validation_errors:
                print(f"release platform policy: {error}", file=sys.stderr)
        return 2
    errors = audit_manifest(manifest, system)
    if errors:
        if not args.quiet:
            for error in errors:
                print(f"release platform policy: {error}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"release platform policy: PASS ({system})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
