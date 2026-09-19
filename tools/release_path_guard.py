#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate and prepare exact release staging paths without shell expansion."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
from typing import Mapping, Optional, Sequence


TOKEN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")


@dataclass(frozen=True)
class ReleasePaths:
    build_dir: Path
    stage: Path
    artifact_dir: Path
    archive: Path
    version: str
    platform: str


def _safe_path(raw: str, label: str) -> Path:
    if not raw or "'" in raw or any(ord(char) < 32 for char in raw):
        raise ValueError(f"{label} contains unsafe characters")
    path = Path(raw)
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    if ".." in path.parts:
        raise ValueError(f"{label} must not contain '..'")
    return path


def from_environment(environment: Mapping[str, str]) -> ReleasePaths:
    required = {
        "build_dir": "FARSEE_GUARD_BUILD_DIR",
        "stage": "FARSEE_GUARD_RELEASE_STAGE",
        "artifact_dir": "FARSEE_GUARD_ARTIFACT_DIR",
        "archive": "FARSEE_GUARD_ARCHIVE",
        "version": "FARSEE_GUARD_VERSION",
        "platform": "FARSEE_GUARD_PLATFORM",
    }
    values = {}
    for field, name in required.items():
        value = environment.get(name)
        if value is None:
            raise ValueError(f"missing environment variable {name}")
        values[field] = value
    return ReleasePaths(
        build_dir=_safe_path(values["build_dir"], "BUILD_DIR"),
        stage=_safe_path(values["stage"], "RELEASE_STAGE"),
        artifact_dir=_safe_path(
            values["artifact_dir"], "RELEASE_ARTIFACT_DIR"
        ),
        archive=_safe_path(values["archive"], "RELEASE_ARCHIVE"),
        version=values["version"],
        platform=values["platform"],
    )


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return child != parent
    except ValueError:
        return False


def validate(paths: ReleasePaths) -> None:
    if not TOKEN.fullmatch(paths.version):
        raise ValueError("VERSION is not a portable release token")
    if not TOKEN.fullmatch(paths.platform):
        raise ValueError("RELEASE_PLATFORM is not a portable release token")
    build = paths.build_dir.resolve(strict=False)
    if build in {Path("/"), Path.home().resolve()}:
        raise ValueError("BUILD_DIR is too broad for release preparation")

    resolved = {
        "RELEASE_STAGE": paths.stage.resolve(strict=False),
        "RELEASE_ARTIFACT_DIR": paths.artifact_dir.resolve(strict=False),
        "RELEASE_ARCHIVE": paths.archive.resolve(strict=False),
    }
    for label, value in resolved.items():
        if not _inside(value, build):
            raise ValueError(f"{label} must be strictly inside BUILD_DIR")
    if paths.stage.name != f"farsee-{paths.version}":
        raise ValueError("RELEASE_STAGE basename does not match VERSION")
    if paths.archive.name != (
        f"farsee-{paths.version}-{paths.platform}.tar.gz"
    ):
        raise ValueError("RELEASE_ARCHIVE basename does not match release metadata")
    if not _inside(resolved["RELEASE_ARCHIVE"], resolved["RELEASE_ARTIFACT_DIR"]):
        raise ValueError("RELEASE_ARCHIVE must be inside RELEASE_ARTIFACT_DIR")
    stage = resolved["RELEASE_STAGE"]
    artifacts = resolved["RELEASE_ARTIFACT_DIR"]
    if _inside(stage, artifacts) or _inside(artifacts, stage) or stage == artifacts:
        raise ValueError("release stage and artifact directories must be disjoint")

    for target in (paths.stage, paths.artifact_dir):
        current = target
        while current != paths.build_dir:
            if current.is_symlink():
                raise ValueError(f"release path traverses symbolic link: {current}")
            if current.parent == current:
                raise ValueError("release path does not reach BUILD_DIR")
            current = current.parent


def prepare(paths: ReleasePaths, kind: str) -> Path:
    validate(paths)
    target = paths.stage if kind == "stage" else paths.artifact_dir
    if target.exists():
        if target.is_symlink() or not target.is_dir():
            raise ValueError(f"refusing non-directory release target: {target}")
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=False)
    target.chmod(0o755)
    return target


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", choices=("stage", "artifacts"), required=True)
    args = parser.parse_args(argv)
    try:
        target = prepare(from_environment(os.environ), args.prepare)
    except (OSError, ValueError) as exc:
        print(f"release path guard: {exc}")
        return 2
    print(f"release path guard: prepared {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
