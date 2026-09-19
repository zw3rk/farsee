# SPDX-License-Identifier: Apache-2.0
"""Regression tests for final release-artifact identity verification."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDITOR = ROOT / "tools" / "check_release_artifacts.py"
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location("check_release_artifacts", AUDITOR)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def package(
    name: str, spdx_id: str, license_id: str, purpose: str,
    version: str | None = None, comment: str | None = None,
) -> dict:
    value = {
        "name": name,
        "SPDXID": spdx_id,
        "supplier": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": license_id,
        "licenseDeclared": license_id,
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": purpose,
    }
    if version is not None:
        value["versionInfo"] = version
    if comment is not None:
        value["comment"] = comment
    return value


class ReleaseArtifactAuditTests(unittest.TestCase):
    @staticmethod
    def rebuild_archive(
        environment: dict[str, str], *, extra: bool = False,
        duplicate: bool = False, binary_mode: int = 0o755,
    ) -> None:
        stage = Path(environment["FARSEE_GUARD_RELEASE_STAGE"])
        archive = Path(environment["FARSEE_GUARD_ARCHIVE"])
        epoch = int(environment["FARSEE_AUDIT_SOURCE_DATE_EPOCH"])

        def canonical(info: tarfile.TarInfo) -> tarfile.TarInfo:
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = epoch
            if info.isdir():
                info.mode = 0o755
            elif info.name.endswith("/bin/farsee"):
                info.mode = binary_mode
            else:
                info.mode = 0o644
            return info

        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(stage, arcname=stage.name, filter=canonical)
            if extra:
                info = tarfile.TarInfo(f"{stage.name}/unreviewed.txt")
                content = b"unreviewed\n"
                info.size = len(content)
                canonical(info)
                import io
                bundle.addfile(info, io.BytesIO(content))
            if duplicate:
                source = stage / "share" / "doc" / "farsee" / "LICENSE"
                bundle.add(
                    source,
                    arcname=f"{stage.name}/share/doc/farsee/LICENSE",
                    filter=canonical,
                )

    @staticmethod
    def refresh_checksums(environment: dict[str, str]) -> None:
        artifacts = Path(environment["FARSEE_GUARD_ARTIFACT_DIR"])
        version = environment["FARSEE_GUARD_VERSION"]
        platform = environment["FARSEE_GUARD_PLATFORM"]
        paths = (
            Path(environment["FARSEE_GUARD_ARCHIVE"]),
            artifacts / f"farsee-{version}-{platform}.spdx.json",
            artifacts / f"farsee-{version}-release-notes.md",
        )
        (artifacts / "SHA256SUMS").write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                for path in paths
            ),
            encoding="utf-8",
        )

    def fixture(self, root: Path) -> dict[str, str]:
        version = "1.2.3-rc1"
        platform = "darwin-arm64"
        revision = "abc123"
        epoch = 42
        build = root / "build"
        stage = build / "release-stage" / f"farsee-{version}"
        docs = stage / "share" / "doc" / "farsee"
        binary = stage / "bin" / "farsee"
        artifacts = build / "release-artifacts"
        approved = root / "approved"
        archive = artifacts / f"farsee-{version}-{platform}.tar.gz"
        sbom = artifacts / f"farsee-{version}-{platform}.spdx.json"
        notes = artifacts / f"farsee-{version}-release-notes.md"
        docs.mkdir(parents=True)
        binary.parent.mkdir(parents=True)
        binary.write_text(
            "#!/bin/sh\necho 'farsee 1.2.3-rc1 git=abc123 built=42'\n",
            encoding="utf-8",
        )
        binary.chmod(0o755)
        for name in ("LICENSE", "NOTICE"):
            (docs / name).write_text(f"{name}\n", encoding="utf-8")
        (docs / "THIRD_PARTY_NOTICES.md").write_text(
            "### libexample 4.5.6\n\n### Darwin runtime\n",
            encoding="utf-8",
        )
        manifest = {
            "schema": 1,
            "allowed_licenses": [
                "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "CC0-1.0",
                "ISC", "MIT", "Unlicense", "Zlib",
            ],
            "dependencies": [{
                "name": "libexample",
                "version": "4.5.6",
                "license": "MIT",
                "store_patterns": ["libexample-4.5.6"],
                "notice": "### libexample 4.5.6",
            }],
            "forbidden_runtime_patterns": ["forbidden"],
            "system_libraries": [{
                "name": "Darwin runtime",
                "license": "Apple system library",
                "paths": ["/usr/lib/libSystem.B.dylib"],
                "notice": "### Darwin runtime",
            }],
        }
        (docs / "dependencies.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        (docs / "runtime-closure.txt").write_text(
            "/nix/store/aaaa-libexample-4.5.6/lib/libexample.dylib\n"
            "/usr/lib/libSystem.B.dylib\n",
            encoding="utf-8",
        )
        (docs / "release-metadata.json").write_text(
            json.dumps({
                "name": "farsee",
                "platform": platform,
                "schema": 1,
                "source_date_epoch": epoch,
                "source_revision": revision,
                "version": version,
            }),
            encoding="utf-8",
        )
        artifacts.mkdir(parents=True)
        root_id = "SPDXRef-Package-farsee"
        dependency_id = "SPDXRef-Dependency-libexample"
        system_id = "SPDXRef-System-Darwin-runtime"
        sbom_value = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "farsee-1.2.3-rc1-darwin-arm64",
            "creationInfo": {
                "creators": [
                    "Organization: Anchore, Inc",
                    "Tool: farsee-release-sbom",
                    "Tool: syft-1.24.0",
                ],
                "created": "1970-01-01T00:00:42Z",
                "licenseListVersion": "3.25",
            },
            "packages": [
                package(
                    "Darwin runtime", system_id, "NOASSERTION", "LIBRARY",
                    comment=(
                        "Host system library linked by farsee but not "
                        "redistributed; see THIRD_PARTY_NOTICES.md."
                    ),
                ),
                package("farsee", root_id, "Apache-2.0", "APPLICATION", version),
                package("libexample", dependency_id, "MIT", "LIBRARY", "4.5.6"),
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relatedSpdxElement": root_id,
                    "relationshipType": "DESCRIBES",
                },
                {
                    "spdxElementId": root_id,
                    "relatedSpdxElement": dependency_id,
                    "relationshipType": "DEPENDS_ON",
                },
                {
                    "spdxElementId": root_id,
                    "relatedSpdxElement": system_id,
                    "relationshipType": "DEPENDS_ON",
                },
            ],
            "hasExtractedLicensingInfos": [],
        }
        identity = AUDIT.artifact_identity(
            hashlib.sha256(binary.read_bytes()).hexdigest(), sbom_value
        )
        sbom_value["documentNamespace"] = (
            "https://github.com/zw3rk/farsee/releases/spdx/"
            f"farsee-1.2.3-rc1-darwin-arm64-abc123-{identity}"
        )
        sbom.write_text(
            json.dumps(sbom_value, sort_keys=True), encoding="utf-8"
        )
        notes.write_text(
            "<!-- SPDX-License-Identifier: Apache-2.0 -->\n\n"
            "# farsee 1.2.3-rc1 release notes\n\nFixed.\n",
            encoding="utf-8",
        )
        approved.mkdir()
        (approved / "release").mkdir()
        (approved / "CHANGELOG.md").write_text(
            "# Changelog\n\n"
            "## [1.2.3-rc1] - 1970-01-01\n\n"
            "Fixed.\n\n"
            "## [1.2.2] - 1969-12-31\n\n"
            "Older.\n",
            encoding="utf-8",
        )
        for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
            (approved / name).write_bytes((docs / name).read_bytes())
        (approved / "release" / "dependencies.json").write_bytes(
            (docs / "dependencies.json").read_bytes()
        )
        environment = {
            "FARSEE_GUARD_BUILD_DIR": str(build),
            "FARSEE_GUARD_RELEASE_STAGE": str(stage),
            "FARSEE_GUARD_ARTIFACT_DIR": str(artifacts),
            "FARSEE_GUARD_ARCHIVE": str(archive),
            "FARSEE_GUARD_VERSION": version,
            "FARSEE_GUARD_PLATFORM": platform,
            "FARSEE_SOURCE_REV": revision,
            "SOURCE_DATE_EPOCH": str(epoch),
            "FARSEE_AUDIT_SOURCE_REV": revision,
            "FARSEE_AUDIT_SOURCE_DATE_EPOCH": str(epoch),
            "_FARSEE_TEST_SOURCE_ROOT": str(approved),
            "_FARSEE_TEST_RUNTIME_CLOSURE": json.dumps([
                "/nix/store/aaaa-libexample-4.5.6/lib/libexample.dylib",
                "/usr/lib/libSystem.B.dylib",
            ]),
        }
        self.rebuild_archive(environment)
        self.refresh_checksums(environment)
        return environment

    def run_audit(self, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        audit_environment = {
            key: value for key, value in environment.items()
            if not key.startswith("_FARSEE_TEST_")
        }
        actual_closure = json.loads(
            environment["_FARSEE_TEST_RUNTIME_CLOSURE"]
        )
        with mock.patch.dict(os.environ, audit_environment, clear=False):
            errors = AUDIT.audit(
                runtime_collector=lambda _binary: (actual_closure, []),
                source_root=Path(environment["_FARSEE_TEST_SOURCE_ROOT"]),
            )
        if errors:
            stderr = "".join(
                f"release artifact audit: {error}\n" for error in errors
            )
            return subprocess.CompletedProcess(
                [sys.executable, str(AUDITOR)], 1, "", stderr
            )
        return subprocess.CompletedProcess(
            [sys.executable, str(AUDITOR)], 0,
            "release artifact audit: PASS\n", "",
        )

    def test_complete_consistent_artifact_set_passes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = self.run_audit(self.fixture(Path(raw)))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("release artifact audit: PASS", result.stdout)

    def test_tampered_release_notes_body_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            environment = self.fixture(Path(raw))
            notes = (
                Path(environment["FARSEE_GUARD_ARTIFACT_DIR"])
                / "farsee-1.2.3-rc1-release-notes.md"
            )
            notes.write_text(
                "<!-- SPDX-License-Identifier: Apache-2.0 -->\n\n"
                "# farsee 1.2.3-rc1 release notes\n\nTampered.\n",
                encoding="utf-8",
            )
            self.refresh_checksums(environment)
            result = self.run_audit(environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("release notes differ", result.stderr)

    def test_noncanonical_checksum_order_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            environment = self.fixture(Path(raw))
            checksums = (
                Path(environment["FARSEE_GUARD_ARTIFACT_DIR"])
                / "SHA256SUMS"
            )
            lines = checksums.read_text(encoding="utf-8").splitlines()
            checksums.write_text(
                "\n".join(reversed(lines)) + "\n", encoding="utf-8"
            )
            result = self.run_audit(environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("checksum filenames are not in canonical order", result.stderr)

    def test_metadata_version_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            environment = self.fixture(Path(raw))
            metadata = (
                Path(environment["FARSEE_GUARD_RELEASE_STAGE"])
                / "share" / "doc" / "farsee" / "release-metadata.json"
            )
            value = json.loads(metadata.read_text(encoding="utf-8"))
            value["version"] = "1.2.4"
            metadata.write_text(json.dumps(value), encoding="utf-8")
            result = self.run_audit(environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("metadata version", result.stderr)

    def test_nondeterministic_sbom_identity_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            environment = self.fixture(Path(raw))
            sbom = (
                Path(environment["FARSEE_GUARD_ARTIFACT_DIR"])
                / "farsee-1.2.3-rc1-darwin-arm64.spdx.json"
            )
            value = json.loads(sbom.read_text(encoding="utf-8"))
            value["documentNamespace"] = (
                "file:///" + "Users/example/private/build"
            )
            value["creationInfo"]["created"] = "2030-01-01T00:00:00Z"
            sbom.write_text(json.dumps(value), encoding="utf-8")
            self.refresh_checksums(environment)
            result = self.run_audit(environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("documentNamespace", result.stderr)
            self.assertIn("creationInfo.created", result.stderr)

    def test_missing_or_extra_sbom_package_fails(self) -> None:
        for mutation, expected in (
            ("missing", "missing packages"),
            ("extra", "unexpected packages"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                environment = self.fixture(Path(raw))
                sbom = (
                    Path(environment["FARSEE_GUARD_ARTIFACT_DIR"])
                    / "farsee-1.2.3-rc1-darwin-arm64.spdx.json"
                )
                value = json.loads(sbom.read_text(encoding="utf-8"))
                if mutation == "missing":
                    value["packages"] = [
                        item for item in value["packages"]
                        if item["name"] != "libexample"
                    ]
                else:
                    value["packages"].append(package(
                        "undeclared", "SPDXRef-Dependency-undeclared",
                        "MIT", "LIBRARY", "9.9",
                    ))
                sbom.write_text(json.dumps(value), encoding="utf-8")
                self.refresh_checksums(environment)
                result = self.run_audit(environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_sbom_license_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            environment = self.fixture(Path(raw))
            sbom = (
                Path(environment["FARSEE_GUARD_ARTIFACT_DIR"])
                / "farsee-1.2.3-rc1-darwin-arm64.spdx.json"
            )
            value = json.loads(sbom.read_text(encoding="utf-8"))
            dependency = next(
                item for item in value["packages"]
                if item["name"] == "libexample"
            )
            dependency["licenseDeclared"] = "GPL-3.0-only"
            sbom.write_text(json.dumps(value), encoding="utf-8")
            self.refresh_checksums(environment)
            result = self.run_audit(environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("licenseDeclared", result.stderr)

    def test_self_consistent_disallowed_manifest_license_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            environment = self.fixture(Path(raw))
            docs = (
                Path(environment["FARSEE_GUARD_RELEASE_STAGE"])
                / "share" / "doc" / "farsee"
            )
            manifest_path = docs / "dependencies.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["dependencies"][0]["license"] = "GPL-3.0-only"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            sbom = (
                Path(environment["FARSEE_GUARD_ARTIFACT_DIR"])
                / "farsee-1.2.3-rc1-darwin-arm64.spdx.json"
            )
            value = json.loads(sbom.read_text(encoding="utf-8"))
            dependency = next(
                item for item in value["packages"]
                if item["name"] == "libexample"
            )
            dependency["licenseDeclared"] = "GPL-3.0-only"
            dependency["licenseConcluded"] = "GPL-3.0-only"
            sbom.write_text(json.dumps(value), encoding="utf-8")
            self.refresh_checksums(environment)
            result = self.run_audit(environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("GPL-3.0-only", result.stderr)

    def test_unused_approved_manifest_dependency_is_not_required_in_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            environment = self.fixture(Path(raw))
            docs = (
                Path(environment["FARSEE_GUARD_RELEASE_STAGE"])
                / "share" / "doc" / "farsee"
            )
            manifest_path = docs / "dependencies.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["dependencies"].append({
                "name": "unused",
                "version": "7.8.9",
                "license": "MIT",
                "store_patterns": ["unused-7.8.9"],
                "notice": "### unused 7.8.9",
            })
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with (docs / "THIRD_PARTY_NOTICES.md").open(
                "a", encoding="utf-8"
            ) as stream:
                stream.write("\n### unused 7.8.9\n")
            approved = Path(environment["_FARSEE_TEST_SOURCE_ROOT"])
            (approved / "release" / "dependencies.json").write_bytes(
                manifest_path.read_bytes()
            )
            (approved / "THIRD_PARTY_NOTICES.md").write_bytes(
                (docs / "THIRD_PARTY_NOTICES.md").read_bytes()
            )
            self.rebuild_archive(environment)
            self.refresh_checksums(environment)
            result = self.run_audit(environment)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_mandatory_package_field_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            environment = self.fixture(Path(raw))
            sbom = (
                Path(environment["FARSEE_GUARD_ARTIFACT_DIR"])
                / "farsee-1.2.3-rc1-darwin-arm64.spdx.json"
            )
            value = json.loads(sbom.read_text(encoding="utf-8"))
            del value["packages"][0]["downloadLocation"]
            sbom.write_text(json.dumps(value), encoding="utf-8")
            self.refresh_checksums(environment)
            result = self.run_audit(environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("downloadLocation", result.stderr)

    def test_noncanonical_runtime_closure_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            environment = self.fixture(Path(raw))
            closure = (
                Path(environment["FARSEE_GUARD_RELEASE_STAGE"])
                / "share" / "doc" / "farsee" / "runtime-closure.txt"
            )
            lines = closure.read_text(encoding="utf-8").splitlines()
            closure.write_text(
                "".join(f"{line}\n" for line in reversed(lines)),
                encoding="utf-8",
            )
            self.rebuild_archive(environment)
            self.refresh_checksums(environment)
            result = self.run_audit(environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("canonical absolute, sorted, and unique", result.stderr)

    def test_forged_runtime_closure_cannot_omit_linked_library(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            environment = self.fixture(Path(raw))
            stage = Path(environment["FARSEE_GUARD_RELEASE_STAGE"])
            closure = stage / "share" / "doc" / "farsee" / "runtime-closure.txt"
            closure.write_text("/usr/lib/libSystem.B.dylib\n", encoding="utf-8")
            sbom = (
                Path(environment["FARSEE_GUARD_ARTIFACT_DIR"])
                / "farsee-1.2.3-rc1-darwin-arm64.spdx.json"
            )
            value = json.loads(sbom.read_text(encoding="utf-8"))
            value["packages"] = [
                item for item in value["packages"]
                if item["name"] != "libexample"
            ]
            value["relationships"] = [
                item for item in value["relationships"]
                if item["relatedSpdxElement"] != "SPDXRef-Dependency-libexample"
            ]
            sbom.write_text(json.dumps(value), encoding="utf-8")
            self.rebuild_archive(environment)
            self.refresh_checksums(environment)
            result = self.run_audit(environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match the packaged binary", result.stderr)

    def test_staged_policy_file_must_match_reviewed_source(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            environment = self.fixture(Path(raw))
            notice = (
                Path(environment["FARSEE_GUARD_RELEASE_STAGE"])
                / "share" / "doc" / "farsee" / "NOTICE"
            )
            notice.write_text("different but self-consistent\n", encoding="utf-8")
            self.rebuild_archive(environment)
            self.refresh_checksums(environment)
            result = self.run_audit(environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("differs from reviewed source", result.stderr)

    def test_archive_extra_or_duplicate_member_fails(self) -> None:
        for mutation, expected in (
            ("extra", "unexpected archive member"),
            ("duplicate", "duplicate archive member"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                environment = self.fixture(Path(raw))
                self.rebuild_archive(
                    environment,
                    extra=mutation == "extra",
                    duplicate=mutation == "duplicate",
                )
                self.refresh_checksums(environment)
                result = self.run_audit(environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_archive_nonexecutable_binary_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            environment = self.fixture(Path(raw))
            self.rebuild_archive(environment, binary_mode=0o644)
            self.refresh_checksums(environment)
            result = self.run_audit(environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("archive member mode", result.stderr)


if __name__ == "__main__":
    unittest.main()
