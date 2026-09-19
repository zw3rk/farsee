#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""License and provenance auditor for farsee.

Enforces the source and dependency license policy (plan.md §5, G0, G12):

  1. Every first-party source or script under src/, include/, tests/, and
     tools/ must carry an `SPDX-License-Identifier: Apache-2.0` header.
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

import json
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

# Directories whose first-party sources/scripts we audit. The fixture
# directory is special: it contains deliberate reject samples and is
# audited separately.
AUDIT_SOURCE_DIRS = ("src", "include", "tests", "tools")
# Exclude by basename (applied at every walk level) ...
EXCLUDE_DIR_BASENAMES = {"build", ".git", "result", "fixtures"}
# ... and by path relative to repo root (for precise exclusions).
EXCLUDE_DIR_PATHS = {"tests/fixtures/license"}

SPDX_RE = re.compile(
    r"SPDX-License-Identifier:\s*([A-Za-z0-9][A-Za-z0-9.-]*)"
)
ADR_PATH_RE = re.compile(r"\bdocs/adr/[A-Za-z0-9._/-]+\.md\b")
FIRST_PARTY_SUFFIXES = {".c", ".cmd", ".h", ".ini", ".py", ".sh", ".xml"}
ROOT_SOURCE_FILES = {"Makefile", "flake.nix"}


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
    """Yield first-party source/script files requiring the project header."""
    for name in sorted(ROOT_SOURCE_FILES):
        path = root / name
        if path.is_file():
            yield path
    workflow_dir = root / ".github" / "workflows"
    if workflow_dir.is_dir():
        for path in sorted(workflow_dir.iterdir()):
            if path.is_file() and path.suffix in {".yml", ".yaml"}:
                yield path
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
                path = Path(dirpath) / fn
                if path.suffix in FIRST_PARTY_SUFFIXES:
                    yield path


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


def audit_dependency_manifest_data(manifest, notice_text):
    """Validate dependency policy and notice coverage from parsed data."""
    errors = []
    if manifest.get("schema") != 1:
        errors.append("dependency manifest: schema must be 1")
    allowed = set(manifest.get("allowed_licenses", []))
    if allowed != ALLOWED_LICENSES:
        errors.append(
            "dependency manifest: allowed_licenses must exactly match policy"
        )
    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        return errors + ["dependency manifest: dependencies must be non-empty"]
    seen = set()
    for index, dep in enumerate(dependencies):
        label = f"dependency manifest entry {index}"
        if not isinstance(dep, dict):
            errors.append(f"{label}: must be an object")
            continue
        name = dep.get("name")
        if not isinstance(name, str) or not name:
            errors.append(f"{label}: missing name")
            continue
        label = f"dependency {name!r}"
        if name in seen:
            errors.append(f"{label}: duplicate name")
        seen.add(name)
        version = dep.get("version")
        if not isinstance(version, str) or not version:
            errors.append(f"{label}: missing version")
        license_id = dep.get("license")
        if license_id not in ALLOWED_LICENSES:
            errors.append(f"{label}: license {license_id!r} is not allowed")
        patterns = dep.get("store_patterns")
        if not isinstance(patterns, list) or not patterns or not all(
            isinstance(pattern, str) and pattern for pattern in patterns
        ):
            errors.append(f"{label}: store_patterns must be non-empty strings")
        marker = dep.get("notice")
        if not isinstance(marker, str) or not marker:
            errors.append(f"{label}: missing notice marker")
        elif isinstance(version, str) and version not in marker:
            errors.append(f"{label}: notice marker does not include version")
        elif marker not in notice_text:
            errors.append(f"{label}: notice marker {marker!r} not found")
    forbidden = manifest.get("forbidden_runtime_patterns", [])
    if not isinstance(forbidden, list) or not all(
        isinstance(pattern, str) and pattern for pattern in forbidden
    ):
        errors.append(
            "dependency manifest: forbidden_runtime_patterns must be strings"
        )
    if "system_library_prefixes" in manifest:
        errors.append(
            "dependency manifest: system_library_prefixes is too broad; "
            "declare exact system_libraries paths"
        )
    system_libraries = manifest.get("system_libraries")
    if not isinstance(system_libraries, list) or not system_libraries:
        errors.append(
            "dependency manifest: system_libraries must be a non-empty list"
        )
    else:
        seen_system_paths = set()
        for index, item in enumerate(system_libraries):
            label = f"system library entry {index}"
            if not isinstance(item, dict):
                errors.append(f"{label}: must be an object")
                continue
            name = item.get("name")
            license_name = item.get("license")
            paths = item.get("paths")
            marker = item.get("notice")
            if not isinstance(name, str) or not name:
                errors.append(f"{label}: missing name")
            if not isinstance(license_name, str) or not license_name:
                errors.append(f"{label}: missing license")
            if not isinstance(paths, list) or not paths:
                errors.append(f"{label}: paths must be non-empty")
            else:
                for path in paths:
                    if (not isinstance(path, str) or not path.startswith("/")
                            or path.endswith("/")):
                        errors.append(f"{label}: invalid exact path {path!r}")
                    elif path in seen_system_paths:
                        errors.append(f"{label}: duplicate path {path}")
                    else:
                        seen_system_paths.add(path)
            if not isinstance(marker, str) or not marker:
                errors.append(f"{label}: missing notice marker")
            elif marker not in notice_text:
                errors.append(f"{label}: notice marker {marker!r} not found")
    return errors


def audit_notice_links(root: Path, notice_text: str):
    """Reject stale local ADR references in the shipped notice file."""
    errors = []
    for relative in sorted(set(ADR_PATH_RE.findall(notice_text))):
        if not (root / relative).is_file():
            errors.append(f"THIRD_PARTY_NOTICES.md: missing ADR target {relative}")
    return errors


def audit_runtime_paths_data(manifest, runtime_paths):
    """Validate resolved runtime paths against the dependency manifest."""
    errors = []
    forbidden = tuple(manifest.get("forbidden_runtime_patterns", []))
    declared_system_paths = {
        path
        for item in manifest.get("system_libraries", [])
        if isinstance(item, dict)
        for path in item.get("paths", [])
        if isinstance(path, str)
    }
    dependencies = manifest.get("dependencies", [])
    for path in sorted(set(runtime_paths)):
        if path in declared_system_paths:
            continue
        if not path.startswith("/nix/store/"):
            errors.append(f"undeclared system runtime dependency: {path}")
            continue
        if any(pattern in path for pattern in forbidden):
            errors.append(f"forbidden runtime dependency: {path}")
            continue
        matches = [
            dep for dep in dependencies
            if any(pattern in path for pattern in dep.get("store_patterns", []))
        ]
        if not matches:
            errors.append(f"undeclared runtime dependency: {path}")
        elif not any(dep.get("license") in ALLOWED_LICENSES for dep in matches):
            errors.append(f"runtime dependency has disallowed license: {path}")
    return errors


def load_dependency_manifest(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8")), []
    except (OSError, json.JSONDecodeError) as exc:
        return {}, [f"dependency manifest {path}: {exc}"]


def audit_third_party_notices(root: Path):
    """Validate notices and the machine-readable runtime dependency policy."""
    notices = root / "THIRD_PARTY_NOTICES.md"
    if not notices.is_file():
        return ["THIRD_PARTY_NOTICES.md is missing"]
    manifest_path = root / "release" / "dependencies.json"
    manifest, errors = load_dependency_manifest(manifest_path)
    if errors:
        return errors
    try:
        notice_text = notices.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"{notices}: cannot read: {exc}"]
    errors.extend(audit_dependency_manifest_data(manifest, notice_text))
    errors.extend(audit_notice_links(root, notice_text))
    closure_file = os.environ.get("FARSEE_RUNTIME_CLOSURE")
    if closure_file:
        try:
            paths = Path(closure_file).read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            errors.append(f"runtime closure {closure_file}: {exc}")
        else:
            errors.extend(audit_runtime_paths_data(manifest, paths))
    return errors


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

    print(f"license audit: {nfiles} first-party source/script files checked")
    if errors:
        print("FAIL:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("ok: first-party SPDX, dependency policy, notices, and optional "
          "runtime closure are valid")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
