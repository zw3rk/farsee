#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Require every external approval before release signing or upload."""

from __future__ import annotations

import argparse
from datetime import date
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Optional, Sequence


APPROVAL_FIELDS = (
    "owner_release_approval",
    "apple_provenance_approval",
    "independent_review_approval",
    "signing_identity_approval",
)
EXPECTED_FIELDS = {
    "schema",
    "status",
    "candidate_revision",
    "candidate_version",
    *APPROVAL_FIELDS,
}
DECISION_FIELDS = {"approved", "approver", "approved_on", "evidence"}
REVISION = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")
APPROVAL_RECORD_PATH = "release/approval.json"


def _audit_decision(name: str, value: object) -> list[str]:
    if not isinstance(value, dict) or set(value) != DECISION_FIELDS:
        return [f"approval record {name} decision fields are not exact"]
    approved = value.get("approved")
    if type(approved) is not bool:
        return [f"approval record {name} approved value is not boolean"]
    metadata = (
        value.get("approver"),
        value.get("approved_on"),
        value.get("evidence"),
    )
    if not approved:
        errors = [f"approval record {name} is not approved"]
        if any(item is not None for item in metadata):
            errors.append(
                f"approval record {name} has metadata without approval"
            )
        return errors

    errors: list[str] = []
    for label, item in zip(
        ("approver", "approved_on", "evidence"), metadata, strict=True
    ):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"approval record {name} {label} is missing")
    approved_on = value.get("approved_on")
    if isinstance(approved_on, str) and approved_on:
        try:
            date.fromisoformat(approved_on)
        except ValueError:
            errors.append(
                f"approval record {name} approved_on is not an ISO date"
            )
    return errors


def audit(record: object, *, expected_version: Optional[str] = None) -> list[str]:
    if not isinstance(record, dict):
        return ["approval record must be an object"]
    errors: list[str] = []
    if set(record) != EXPECTED_FIELDS:
        errors.append("approval record fields are not exact")
    if record.get("schema") != 2:
        errors.append("approval record schema must be 2")
    if record.get("status") != "approved":
        errors.append("approval record status is not approved")
    revision = record.get("candidate_revision")
    if not isinstance(revision, str) or REVISION.fullmatch(revision) is None:
        errors.append("approval record candidate_revision is not a full Git SHA")
    version = record.get("candidate_version")
    if not isinstance(version, str) or VERSION.fullmatch(version) is None:
        errors.append("approval record candidate_version is invalid")
    elif expected_version is not None and version != expected_version:
        errors.append(
            "approval record candidate_version does not match the requested version"
        )
    for field in APPROVAL_FIELDS:
        errors.extend(_audit_decision(field, record.get(field)))
    return errors


def audit_candidate_paths(paths: Sequence[str]) -> list[str]:
    unexpected = sorted({path for path in paths if path != APPROVAL_RECORD_PATH})
    return [
        "candidate source changed after approval boundary: " + ", ".join(unexpected)
    ] if unexpected else []


def _git(repo_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def audit_candidate_source(repo_root: Path, revision: str) -> list[str]:
    resolved = _git(repo_root, "rev-parse", "--verify", f"{revision}^{{commit}}")
    if resolved.returncode != 0 or resolved.stdout.strip() != revision:
        return ["approval candidate revision is not an exact reachable commit"]
    ancestor = _git(repo_root, "merge-base", "--is-ancestor", revision, "HEAD")
    if ancestor.returncode != 0:
        return ["approval candidate revision is not an ancestor of HEAD"]
    changed = _git(repo_root, "diff", "--name-only", revision, "--", ".")
    if changed.returncode != 0:
        return ["could not compare the approval candidate to the worktree"]
    untracked = _git(
        repo_root, "ls-files", "--others", "--exclude-standard"
    )
    if untracked.returncode != 0:
        return ["could not enumerate untracked candidate files"]
    paths = [
        path
        for output in (changed.stdout, untracked.stdout)
        for path in output.splitlines()
        if path
    ]
    return audit_candidate_paths(paths)


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify the farsee release approval record."
    )
    parser.add_argument("record", type=Path)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--version", required=True)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        record = json.loads(args.record.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"release approval gate: {exc}", file=sys.stderr)
        return 2
    errors = audit(record, expected_version=args.version)
    if isinstance(record, dict):
        revision = record.get("candidate_revision")
        if isinstance(revision, str) and REVISION.fullmatch(revision):
            errors.extend(audit_candidate_source(args.repo_root, revision))
    if errors:
        for error in errors:
            print(f"release approval gate: {error}", file=sys.stderr)
        print("release approval gate: BLOCKED", file=sys.stderr)
        return 1
    print("release approval gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
