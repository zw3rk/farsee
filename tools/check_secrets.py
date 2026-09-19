#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Scan committed, staged, unstaged, and untracked repository content."""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Optional, Sequence


_FINGERPRINT = re.compile(
    r"^(?P<commit>[0-9a-f]{40}):(?P<path>[^:\r\n]+):"
    r"(?P<rule>[A-Za-z0-9][A-Za-z0-9_.-]*):(?P<line>[1-9][0-9]*)$"
)


def _git(root: Path, *args: str, text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=text,
    )


def _valid_relative_path(raw: str) -> bool:
    path = PurePosixPath(raw)
    return (
        raw != "" and
        not path.is_absolute() and
        all(part not in ("", ".", "..") for part in path.parts)
    )


def validate_ignore_text(root: Path, text: str, label: str,
                         reachable: set[str]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _FINGERPRINT.fullmatch(line)
        if match is None:
            errors.append(f"{label}:{number}: invalid fingerprint")
            continue
        if line in seen:
            errors.append(f"{label}:{number}: duplicate fingerprint")
            continue
        seen.add(line)
        commit = match.group("commit")
        relative = match.group("path")
        if commit not in reachable:
            errors.append(f"{label}:{number}: unreachable fingerprint commit")
            continue
        if not _valid_relative_path(relative):
            errors.append(f"{label}:{number}: invalid fingerprint path")
            continue
        present = _git(root, "cat-file", "-e", f"{commit}:{relative}")
        if present.returncode != 0:
            errors.append(f"{label}:{number}: fingerprint path is absent at commit")
    return errors


def _load_ignore_versions(root: Path) -> tuple[Path, str, str]:
    ignore = root / ".gitleaksignore"
    if ignore.is_symlink() or not ignore.is_file():
        raise ValueError(".gitleaksignore must be a tracked regular file")
    worktree = ignore.read_text(encoding="utf-8")
    staged = _git(root, "show", ":.gitleaksignore")
    if staged.returncode != 0:
        raise ValueError(".gitleaksignore is absent from the staged index")
    return ignore, worktree, staged.stdout


def _run_gitleaks(root: Path, executable: str, ignore: Path,
                   mode: str, *extra: str) -> int:
    command = [
        executable,
        mode,
        str(root) if mode == "git" else extra[0],
        "--redact",
        "--no-banner",
        "--gitleaks-ignore-path",
        str(ignore),
    ]
    if mode == "git":
        command.extend(extra)
    result = subprocess.run(command, check=False, cwd=root)
    return result.returncode


def _untracked_paths(root: Path) -> list[Path]:
    result = _git(
        root, "ls-files", "--others", "--exclude-standard", "-z", text=False
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"cannot enumerate untracked content: {detail}")
    paths: list[Path] = []
    for encoded in result.stdout.split(b"\0"):
        if not encoded:
            continue
        relative = os.fsdecode(encoded)
        if not _valid_relative_path(relative):
            raise ValueError(f"invalid untracked path: {relative!r}")
        path = root / relative
        if path.is_symlink():
            raise ValueError(f"untracked symlink requires review: {relative}")
        if not path.is_file():
            raise ValueError(f"untracked path is not a regular file: {relative}")
        paths.append(path)
    return paths


def run(root: Path, executable: str) -> int:
    root = root.resolve()
    if not (root / ".git").exists():
        print("secret gate: root is not a Git worktree", file=sys.stderr)
        return 2
    reachable_result = _git(root, "rev-list", "--all")
    if reachable_result.returncode != 0:
        print("secret gate: cannot enumerate reachable commits", file=sys.stderr)
        return 2
    reachable = set(reachable_result.stdout.splitlines())
    try:
        ignore, worktree_ignore, staged_ignore = _load_ignore_versions(root)
        errors = validate_ignore_text(
            root, worktree_ignore, ".gitleaksignore", reachable
        )
        errors.extend(validate_ignore_text(
            root, staged_ignore, "index:.gitleaksignore", reachable
        ))
        untracked = _untracked_paths(root)
    except (OSError, UnicodeDecodeError, ValueError, RuntimeError) as exc:
        print(f"secret gate: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"secret gate: {error}", file=sys.stderr)
        return 2

    scans = (
        ("reachable history", ("git", "--log-opts=--all")),
        ("staged content", ("git", "--staged")),
        ("unstaged content", ("git", "--pre-commit")),
    )
    for label, (mode, *extra) in scans:
        status = _run_gitleaks(root, executable, ignore, mode, *extra)
        if status != 0:
            print(f"secret gate: {label} scan failed", file=sys.stderr)
            return 1 if status == 1 else 2
    for path in untracked:
        status = _run_gitleaks(root, executable, ignore, "dir", str(path))
        if status != 0:
            relative = path.relative_to(root)
            print(f"secret gate: untracked scan failed: {relative}",
                  file=sys.stderr)
            return 1 if status == 1 else 2
    print("secret gate: PASS")
    return 0


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan current content and reachable Git history for secrets."
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--gitleaks", default="gitleaks")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    return run(args.root, args.gitleaks)


if __name__ == "__main__":
    raise SystemExit(main())
