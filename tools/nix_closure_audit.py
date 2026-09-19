#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate every path in a Nix package closure against release policy."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess


def audit_paths(paths: list[str], manifest: dict, package_path: str) -> list[str]:
    """Return fail-closed policy errors for the complete closure."""
    forbidden = [
        pattern.lower() for pattern in manifest["forbidden_runtime_patterns"]
    ]
    allowed_licenses = set(manifest["allowed_licenses"])
    dependencies = manifest["dependencies"]
    errors = set()
    for path in paths:
        if path == package_path:
            continue
        lowered = path.lower()
        if any(pattern in lowered for pattern in forbidden):
            errors.add(f"forbidden Nix closure path: {path}")
            continue
        matches = [
            dependency for dependency in dependencies
            if any(
                pattern in path
                for pattern in dependency.get("store_patterns", [])
            )
        ]
        if not matches:
            errors.add(f"undeclared Nix closure path: {path}")
        elif not any(
            dependency.get("license") in allowed_licenses
            for dependency in matches
        ):
            errors.add(
                f"Nix closure path has no allowed-license declaration: {path}"
            )
    return sorted(errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        if manifest.get("schema") != 1:
            raise ValueError("manifest schema must be 1")
        for key in ("allowed_licenses", "dependencies",
                    "forbidden_runtime_patterns"):
            if not isinstance(manifest.get(key), list):
                raise ValueError(f"{key} must be a list")
        if not all(
            isinstance(value, str) and value
            for value in manifest["allowed_licenses"]
        ):
            raise ValueError("allowed_licenses must be strings")
        if not all(
            isinstance(value, str) and value
            for value in manifest["forbidden_runtime_patterns"]
        ):
            raise ValueError("forbidden_runtime_patterns must be strings")
        for dependency in manifest["dependencies"]:
            if not isinstance(dependency, dict):
                raise ValueError("dependency entries must be objects")
            patterns = dependency.get("store_patterns")
            if (
                dependency.get("license") not in manifest["allowed_licenses"]
                or not isinstance(patterns, list)
                or not patterns
                or not all(isinstance(value, str) and value for value in patterns)
            ):
                raise ValueError(
                    "dependencies need an allowed license and store patterns"
                )
        package_path = str(args.package.resolve(strict=True))
        result = subprocess.run(
            ["nix-store", "-qR", package_path],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"nix-store -qR failed: {detail}")
        paths = sorted({line.strip() for line in result.stdout.splitlines()
                        if line.strip()})
        errors = audit_paths(paths, manifest, package_path)
    except (OSError, KeyError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
        print(f"Nix closure audit error: {exc}")
        return 2
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("".join(f"{path}\n" for path in paths), encoding="utf-8")
    if errors:
        for error in errors:
            print(error)
        return 1
    print(f"ok: all {len(paths)} Nix closure paths have allowed declarations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
