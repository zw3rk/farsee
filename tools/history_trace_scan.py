#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Scan every locally reachable Git ref, message, path, tag, and blob."""

from __future__ import annotations

import argparse
import base64
import bisect
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Iterable, Optional, Sequence

from forbidden_trace_scan import (
    Finding,
    Rule,
    TokenHash,
    is_textual_blob,
    load_manifest,
    scan_blob,
)


def load_history_prefilters(
    path: Path, rules: Sequence[Rule]
) -> dict[str, tuple[bytes, ...]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    by_id = {item.get("id"): item for item in raw.get("rules", [])}
    result: dict[str, tuple[bytes, ...]] = {}
    for rule in rules:
        encoded = by_id.get(rule.rule_id, {}).get("history_prefilter_any_b64")
        if encoded is None:
            continue
        if not isinstance(encoded, list) or not encoded:
            raise ValueError(f"invalid history prefilter for {rule.rule_id}")
        needles = []
        for value in encoded:
            if not isinstance(value, str) or not value:
                raise ValueError(f"invalid history prefilter for {rule.rule_id}")
            try:
                needle = base64.b64decode(value, validate=True).lower()
            except ValueError as exc:
                raise ValueError(
                    f"invalid encoded history prefilter for {rule.rule_id}"
                ) from exc
            if not needle:
                raise ValueError(f"empty history prefilter for {rule.rule_id}")
            needles.append(needle)
        result[rule.rule_id] = tuple(needles)
    return result


class HistoryMatcher:
    """Match all vocabulary rules in one pass, including nested matches."""

    def __init__(
        self,
        rules: Sequence[Rule],
        prefilters: Optional[dict[str, tuple[bytes, ...]]] = None,
    ) -> None:
        self.all_rules = list(rules)
        self.rules = [rule for rule in rules if rule.pattern is not None]
        self.hashed_rules = [rule for rule in rules if rule.token_hashes]
        self.by_group: dict[str, Rule] = {}
        self.group_by_id: dict[str, str] = {}
        for index, rule in enumerate(self.rules):
            group = f"rule_{index}"
            self.by_group[group] = rule
            self.group_by_id[rule.rule_id] = group
        if not self.rules and not self.hashed_rules:
            raise ValueError("history matcher requires at least one rule")
        self.prefilters = prefilters or {}
        self.patterns: dict[tuple[str, ...], re.Pattern[str]] = {}

    def _active_rules(self, data: bytes) -> list[Rule]:
        active = [
            rule for rule in self.rules
            if not rule.text_only or is_textual_blob(data)
        ]
        if not self.prefilters:
            return active
        lowered = data.lower()
        return [
            rule for rule in active
            if rule.rule_id not in self.prefilters or any(
                needle in lowered
                for needle in self.prefilters.get(rule.rule_id, ())
            )
        ]

    def _pattern(self, active: Sequence[Rule]) -> re.Pattern[str]:
        key = tuple(rule.rule_id for rule in active)
        cached = self.patterns.get(key)
        if cached is not None:
            return cached
        alternatives = []
        for rule in active:
            expression = rule.pattern.pattern
            if rule.pattern.flags & re.IGNORECASE:
                expression = f"(?i:{expression})"
            group = self.group_by_id[rule.rule_id]
            alternatives.append(f"(?P<{group}>{expression})")
        compiled = re.compile("|".join(alternatives), re.ASCII)
        self.patterns[key] = compiled
        return compiled

    def scan(self, data: bytes, label: str, *, binary: bool = False) -> list[Finding]:
        findings = scan_blob(data, label, self.hashed_rules, binary=binary)
        active = self._active_rules(data)
        if not active:
            return findings
        pattern = self._pattern(active)
        text = data.decode("latin-1")
        matches: list[tuple[int, Rule]] = []
        position = 0
        while position <= len(text):
            match = pattern.search(text, position)
            if match is None:
                break
            group = match.lastgroup
            if group is None:
                raise RuntimeError("combined history rule has no matching group")
            matches.append((match.start(), self.by_group[group]))
            # Advance one byte from the start, not the end. This preserves a
            # rule that begins inside another rule's match (for example, a
            # model marker nested in an attribution trailer).
            position = match.start() + 1
        if not matches:
            return findings
        newlines = (
            [] if binary else
            [index for index, char in enumerate(text) if char == "\n"]
        )
        for start, rule in matches:
            if binary:
                location = f"{label}:byte:{start}"
            else:
                line = bisect.bisect_left(newlines, start) + 1
                prior = newlines[line - 2] if line > 1 else -1
                location = f"{label}:{line}:{start - prior}"
            findings.append(Finding(location, rule.category, rule.rule_id))
        return findings


def _git(root: Path, args: Sequence[str], *, input_data: bytes = b"") -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        input=input_data,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def reachable_objects(root: Path) -> tuple[list[tuple[str, str]], set[str]]:
    """Return unique reachable object IDs and every historical diff path."""
    raw_objects = _git(root, ["rev-list", "--objects", "--all"])
    objects: list[tuple[str, str]] = []
    object_paths: set[str] = set()
    for raw in raw_objects.splitlines():
        oid_raw, separator, path_raw = raw.partition(b" ")
        oid = oid_raw.decode("ascii")
        path = path_raw.decode("utf-8", "surrogateescape") if separator else ""
        objects.append((oid, path))
        if path:
            object_paths.add(path)

    # rev-list assigns one representative name to an object. Diff path output
    # retains other names used by renames and identical blobs.
    raw_paths = _git(
        root,
        ["log", "--all", "--format=", "--name-only", "-z", "--no-renames"],
    )
    for raw in raw_paths.split(b"\0"):
        if raw:
            object_paths.add(raw.decode("utf-8", "surrogateescape"))
    return objects, object_paths


def object_contents(
    root: Path, objects: Iterable[tuple[str, str]]
) -> Iterable[tuple[str, str, str, bytes]]:
    """Yield reachable object content through one bounded batch stream."""
    reachable = {oid: path for oid, path in objects}
    # Feeding the exact rev-list through a temporary request stream avoids two
    # bad alternatives: a pipe can deadlock while Python is reading the object
    # output, and --batch-all-objects spends time reading unreachable retained
    # objects that are outside this all-ref gate's contract.
    with tempfile.TemporaryFile() as requests:
        for oid in reachable:
            requests.write(oid.encode("ascii") + b"\n")
        requests.seek(0)
        process = subprocess.Popen(
            ["git", "-C", str(root), "cat-file", "--batch"],
            stdin=requests,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdout is not None
        try:
            for expected_oid in reachable:
                header = process.stdout.readline().rstrip(b"\n")
                fields = header.split()
                if len(fields) != 3:
                    raise RuntimeError(
                        "git cat-file returned an invalid header: "
                        + header.decode("utf-8", "replace")
                    )
                oid = fields[0].decode("ascii")
                if oid != expected_oid:
                    raise RuntimeError(
                        f"git cat-file returned {oid}, expected {expected_oid}"
                    )
                object_type = fields[1].decode("ascii")
                size = int(fields[2])
                data = process.stdout.read(size)
                terminator = process.stdout.read(1)
                if len(data) != size or terminator != b"\n":
                    raise RuntimeError(f"git cat-file truncated object {oid}")
                path = reachable.get(oid)
                if path is None:
                    raise RuntimeError(f"git cat-file returned unrequested object {oid}")
                yield oid, object_type, path, data
        finally:
            stderr = process.stderr.read() if process.stderr is not None else b""
            returncode = process.wait()
            process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            if returncode != 0:
                detail = stderr.decode("utf-8", "replace").strip()
                raise RuntimeError(f"git cat-file --batch failed: {detail}")


def scan_history(
    root: Path,
    rules: Sequence[Rule],
    prefilters: Optional[dict[str, tuple[bytes, ...]]] = None,
) -> list[Finding]:
    findings: list[Finding] = []
    matcher = HistoryMatcher(rules, prefilters)
    objects, paths = reachable_objects(root)

    refs = _git(root, ["for-each-ref", "--format=%(refname)"])
    findings.extend(scan_blob(refs, "history:refs", rules))
    for path in sorted(paths):
        findings.extend(
            scan_blob(
                path.encode("utf-8", "surrogateescape"),
                f"history-path:{path}",
                rules,
            )
        )

    for oid, object_type, path, data in object_contents(root, objects):
        if object_type not in {"blob", "commit", "tag"}:
            continue
        suffix = f":{path}" if path else ""
        label = f"history-{object_type}:{oid}{suffix}"
        findings.extend(
            matcher.scan(data, label, binary=(object_type == "blob"))
        )
    return sorted(set(findings))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check all locally reachable Git history against the vocabulary manifest."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    root = args.root.resolve()
    manifest = args.manifest or root / "tools" / "forbidden_trace_manifest.json"
    try:
        rules, _retained = load_manifest(manifest)
        prefilters = load_history_prefilters(manifest, rules)
        findings = scan_history(root, rules, prefilters)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"history trace gate error: {exc}", file=sys.stderr)
        return 2
    for finding in findings:
        print(
            f"{finding.location}: {finding.category} ({finding.rule_id})",
            file=sys.stderr,
        )
    if findings:
        print(
            f"history trace gate: FAIL ({len(findings)} finding(s))",
            file=sys.stderr,
        )
        return 1
    print("history trace gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
