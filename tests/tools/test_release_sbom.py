# SPDX-License-Identifier: Apache-2.0
"""Tests for deterministic release-SBOM normalization."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "release_sbom", ROOT / "tools" / "release_sbom.py"
)
assert SPEC is not None and SPEC.loader is not None
SBOM = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SBOM
SPEC.loader.exec_module(SBOM)


def syft_document(namespace: str, created: str) -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "farsee",
        "documentNamespace": namespace,
        "creationInfo": {
            "licenseListVersion": "3.25",
            "creators": [
                "Organization: Anchore, Inc",
                "Tool: syft-1.24.0",
            ],
            "created": created,
        },
        "packages": [
            {
                "name": "farsee",
                "SPDXID": "SPDXRef-DocumentRoot-Directory-farsee",
                "versionInfo": "1.2.3-rc1",
                "supplier": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "primaryPackagePurpose": "FILE",
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-DocumentRoot-Directory-farsee",
                "relationshipType": "DESCRIBES",
            }
        ],
    }


def dependency_manifest() -> dict:
    return {
        "schema": 1,
        "dependencies": [
            {
                "name": "libexample",
                "version": "4.5.6",
                "license": "MIT",
                "store_patterns": ["libexample-4.5.6"],
            },
            {
                "name": "zlib",
                "version": "1.3.1",
                "license": "Zlib",
                "store_patterns": ["zlib-1.3.1"],
            },
        ],
        "system_libraries": [
            {
                "name": "Darwin runtime",
                "license": "Apple system library",
                "paths": ["/usr/lib/libSystem.B.dylib"],
            }
        ],
    }


class ReleaseSbomTests(unittest.TestCase):
    def normalize(
        self, document: dict | None = None, manifest: dict | None = None,
        runtime_paths: list[str] | None = None,
    ):
        return SBOM.normalize(
            document or syft_document(
                "file:///" + "Users/build", "2026-09-02T00:00:00Z"
            ),
            manifest or dependency_manifest(),
            runtime_paths or [
                "/nix/store/aaaa-libexample-4.5.6/lib/libexample.dylib",
                "/nix/store/bbbb-zlib-1.3.1/lib/libz.dylib",
                "/usr/lib/libSystem.B.dylib",
            ],
            version="1.2.3-rc1",
            platform="darwin-arm64",
            revision="abc123",
            epoch=42,
            binary_digest="0" * 64,
        )

    def test_normalization_is_deterministic_and_reconciles_manifest(self) -> None:
        first = self.normalize()
        second = self.normalize(
            syft_document(
                "file:///" + "private/tmp/other", "2030-01-01T00:00:00Z"
            )
        )
        self.assertEqual(first, second)
        self.assertEqual(first["name"], "farsee-1.2.3-rc1-darwin-arm64")
        self.assertTrue(first["documentNamespace"].startswith(
            "https://github.com/zw3rk/farsee/releases/spdx/"
            "farsee-1.2.3-rc1-darwin-arm64-abc123-"
        ))
        self.assertEqual(first["creationInfo"]["created"], "1970-01-01T00:00:42Z")
        packages = {item["name"]: item for item in first["packages"]}
        self.assertEqual(set(packages), {
            "farsee", "libexample", "zlib", "Darwin runtime",
        })
        self.assertEqual(packages["farsee"]["licenseDeclared"], "Apache-2.0")
        self.assertEqual(packages["libexample"]["versionInfo"], "4.5.6")
        self.assertEqual(packages["libexample"]["licenseDeclared"], "MIT")
        self.assertEqual(
            packages["Darwin runtime"]["licenseDeclared"],
            "NOASSERTION",
        )
        self.assertIn(
            "not redistributed", packages["Darwin runtime"]["comment"]
        )
        self.assertEqual(first["hasExtractedLicensingInfos"], [])

    def test_syft_discovered_extra_package_is_rejected(self) -> None:
        document = syft_document("unused", "unused")
        document["packages"].append({"name": "undeclared", "SPDXID": "SPDXRef-X"})
        with self.assertRaisesRegex(ValueError, "unexpected package"):
            self.normalize(document)

    def test_duplicate_manifest_package_name_is_rejected(self) -> None:
        manifest = dependency_manifest()
        manifest["dependencies"].append({
            "name": "zlib", "version": "2", "license": "Zlib",
            "store_patterns": ["zlib-2"],
        })
        with self.assertRaisesRegex(ValueError, "duplicate package name"):
            self.normalize(manifest=manifest)

    def test_unused_and_other_platform_manifest_entries_are_omitted(self) -> None:
        manifest = dependency_manifest()
        manifest["system_libraries"].append({
            "name": "Linux runtime",
            "license": "Linux system library",
            "paths": ["/lib/libc.so.6"],
        })
        value = self.normalize(
            manifest=manifest,
            runtime_paths=[
                "/nix/store/bbbb-zlib-1.3.1/lib/libz.dylib",
                "/usr/lib/libSystem.B.dylib",
            ],
        )
        self.assertEqual(
            {item["name"] for item in value["packages"]},
            {"farsee", "zlib", "Darwin runtime"},
        )

    def test_unmatched_or_ambiguous_runtime_path_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "0 manifest matches"):
            self.normalize(runtime_paths=["/nix/store/aaaa-unknown/lib/libx.dylib"])
        manifest = dependency_manifest()
        manifest["dependencies"][1]["store_patterns"] = ["libexample"]
        with self.assertRaisesRegex(ValueError, "2 manifest matches"):
            self.normalize(
                manifest=manifest,
                runtime_paths=[
                    "/nix/store/aaaa-libexample-4.5.6/lib/libexample.dylib"
                ],
            )

    def test_manifest_spdx_identifier_collision_is_rejected(self) -> None:
        manifest = dependency_manifest()
        manifest["dependencies"] = [
            {
                "name": "lib example", "version": "1", "license": "MIT",
                "store_patterns": ["lib-example-one"],
            },
            {
                "name": "lib-example", "version": "2", "license": "MIT",
                "store_patterns": ["lib-example-two"],
            },
        ]
        with self.assertRaisesRegex(ValueError, "duplicate SPDX"):
            self.normalize(
                manifest=manifest,
                runtime_paths=["/nix/store/aaaa-lib-example-one/lib/x"],
            )

    def test_rewrite_bytes_are_identical_for_unstable_syft_fields(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            sbom_path = root / "farsee.spdx.json"
            manifest_path = root / "dependencies.json"
            closure_path = root / "runtime-closure.txt"
            binary_path = root / "farsee"
            binary_path.write_bytes(b"test release binary\n")
            manifest_path.write_text(
                json.dumps(dependency_manifest()), encoding="utf-8"
            )
            closure_path.write_text(
                "/nix/store/aaaa-libexample-4.5.6/lib/libexample.dylib\n"
                "/nix/store/bbbb-zlib-1.3.1/lib/libz.dylib\n"
                "/usr/lib/libSystem.B.dylib\n",
                encoding="utf-8",
            )
            outputs = []
            for namespace, created in (
                ("file:///" + "Users/build", "2026-09-02T00:00:00Z"),
                ("file:///" + "private/tmp/build", "2030-01-01T00:00:00Z"),
            ):
                sbom_path.write_text(
                    json.dumps(syft_document(namespace, created)),
                    encoding="utf-8",
                )
                SBOM.rewrite(
                    sbom_path, manifest_path, closure_path, binary_path,
                    version="1.2.3-rc1", platform="darwin-arm64",
                    revision="abc123", epoch=42,
                )
                outputs.append(sbom_path.read_bytes())
            self.assertEqual(outputs[0], outputs[1])
            self.assertTrue(outputs[0].endswith(b"\n"))

    def test_invalid_identity_or_epoch_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid version"):
            SBOM.normalize(
                syft_document("unused", "unused"), dependency_manifest(),
                ["/usr/lib/libSystem.B.dylib"],
                version="1.2.3 bad", platform="darwin-arm64",
                revision="abc123", epoch=42,
                binary_digest="0" * 64,
            )
        with self.assertRaisesRegex(ValueError, "epoch"):
            SBOM.normalize(
                syft_document("unused", "unused"), dependency_manifest(),
                ["/usr/lib/libSystem.B.dylib"],
                version="1.2.3", platform="darwin-arm64",
                revision="abc123", epoch=-1,
                binary_digest="0" * 64,
            )

    def test_binary_or_package_variant_has_a_distinct_namespace(self) -> None:
        rdp = self.normalize()
        no_rdp = self.normalize(runtime_paths=[
            "/nix/store/bbbb-zlib-1.3.1/lib/libz.dylib",
            "/usr/lib/libSystem.B.dylib",
        ])
        rebuilt = SBOM.normalize(
            syft_document("unused", "unused"), dependency_manifest(),
            [
                "/nix/store/aaaa-libexample-4.5.6/lib/libexample.dylib",
                "/nix/store/bbbb-zlib-1.3.1/lib/libz.dylib",
                "/usr/lib/libSystem.B.dylib",
            ],
            version="1.2.3-rc1", platform="darwin-arm64",
            revision="abc123", epoch=42,
            binary_digest="f" * 64,
        )
        self.assertNotEqual(rdp["documentNamespace"], no_rdp["documentNamespace"])
        self.assertNotEqual(rdp["documentNamespace"], rebuilt["documentNamespace"])

    def test_epoch_change_has_a_distinct_namespace(self) -> None:
        first = self.normalize()
        second = SBOM.normalize(
            syft_document("unused", "unused"), dependency_manifest(),
            [
                "/nix/store/aaaa-libexample-4.5.6/lib/libexample.dylib",
                "/nix/store/bbbb-zlib-1.3.1/lib/libz.dylib",
                "/usr/lib/libSystem.B.dylib",
            ],
            version="1.2.3-rc1", platform="darwin-arm64",
            revision="abc123", epoch=43, binary_digest="0" * 64,
        )
        self.assertNotEqual(first["documentNamespace"], second["documentNamespace"])


if __name__ == "__main__":
    unittest.main()
