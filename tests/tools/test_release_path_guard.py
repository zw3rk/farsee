# SPDX-License-Identifier: Apache-2.0
"""Regression tests for destructive release-path preparation."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "release_path_guard", ROOT / "tools" / "release_path_guard.py"
)
assert SPEC is not None and SPEC.loader is not None
GUARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GUARD
SPEC.loader.exec_module(GUARD)


class ReleasePathGuardTests(unittest.TestCase):
    def paths(self, build: Path, *, version: str = "1.2.3"):
        artifacts = build / "release-artifacts"
        platform = "darwin-arm64"
        return GUARD.ReleasePaths(
            build_dir=build,
            stage=build / "release-stage" / f"farsee-{version}",
            artifact_dir=artifacts,
            archive=artifacts / f"farsee-{version}-{platform}.tar.gz",
            version=version,
            platform=platform,
        )

    def test_safe_stage_is_cleared_and_recreated(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            build = Path(raw) / "build"
            stage = self.paths(build).stage
            stage.mkdir(parents=True)
            (stage / "stale").write_text("old", encoding="utf-8")
            self.assertEqual(GUARD.prepare(self.paths(build), "stage"), stage)
            self.assertTrue(stage.is_dir())
            self.assertFalse((stage / "stale").exists())

    def test_prepared_directory_mode_does_not_depend_on_umask(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            build = Path(raw) / "build"
            prior = os.umask(0o077)
            try:
                stage = GUARD.prepare(self.paths(build), "stage")
            finally:
                os.umask(prior)
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o755)

    def test_traversal_version_is_rejected_without_deleting_target(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            build = Path(raw) / "build"
            protected = Path(raw) / "protected"
            protected.mkdir()
            paths = self.paths(build, version="../../protected")
            with self.assertRaisesRegex(ValueError, "VERSION"):
                GUARD.prepare(paths, "stage")
            self.assertTrue(protected.is_dir())

    def test_overlong_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            build = Path(raw) / "build"
            paths = self.paths(build, version="v" * 65)
            with self.assertRaisesRegex(ValueError, "VERSION"):
                GUARD.validate(paths)

    def test_build_root_itself_is_never_a_target(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            build = Path(raw) / "build"
            paths = self.paths(build)
            paths = GUARD.ReleasePaths(
                build, build, paths.artifact_dir, paths.archive,
                paths.version, paths.platform,
            )
            with self.assertRaisesRegex(ValueError, "RELEASE_STAGE"):
                GUARD.validate(paths)

    def test_symlink_target_is_refused_and_destination_survives(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            build = base / "build"
            destination = build / "real-stage"
            destination.mkdir(parents=True)
            sentinel = destination / "keep"
            sentinel.write_text("safe", encoding="utf-8")
            paths = self.paths(build)
            paths.stage.parent.mkdir(parents=True)
            paths.stage.symlink_to(destination, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                GUARD.prepare(paths, "stage")
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "safe")

    def test_stage_and_artifact_directories_must_be_disjoint(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            build = Path(raw) / "build"
            paths = self.paths(build)
            nested = paths.stage / "artifacts"
            paths = GUARD.ReleasePaths(
                build, paths.stage, nested,
                nested / f"farsee-{paths.version}-{paths.platform}.tar.gz",
                paths.version, paths.platform,
            )
            with self.assertRaisesRegex(ValueError, "disjoint"):
                GUARD.validate(paths)


if __name__ == "__main__":
    unittest.main()
