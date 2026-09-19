#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify one staged package and its release artifacts as one identity."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
from typing import Callable

from check_license import audit_dependency_manifest_data, audit_runtime_paths_data
from gen_release_notes import extract as extract_release_notes
from release_path_guard import from_environment, validate
from runtime_closure import collect as collect_runtime_closure


SHA256_LINE = re.compile(r"^([0-9a-f]{64})  ([^/\r\n]+)$")
DOCUMENTS = (
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "dependencies.json",
    "release-metadata.json",
    "runtime-closure.txt",
)
SPDX_ID_PART = re.compile(r"[^0-9A-Za-z.-]+")
DOCUMENT_ID = "SPDXRef-DOCUMENT"
ROOT_ID = "SPDXRef-Package-farsee"
REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DOCUMENTS = {
    "LICENSE": Path("LICENSE"),
    "NOTICE": Path("NOTICE"),
    "THIRD_PARTY_NOTICES.md": Path("THIRD_PARTY_NOTICES.md"),
    "dependencies.json": Path("release/dependencies.json"),
}


def read_json(path: Path, label: str, errors: list[str]):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{label}: {exc}")
        return {}


def spdx_id(kind: str, value: str) -> str:
    part = SPDX_ID_PART.sub("-", value).strip("-.")
    return f"SPDXRef-{kind}-{part}"


def artifact_identity(binary_digest: str, document: dict) -> str:
    material = json.dumps(
        {"binary_sha256": binary_digest, "document": document},
        ensure_ascii=True, separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def expected_namespace(
    version: str, platform: str, revision: str, identity: str,
) -> str:
    from urllib.parse import quote
    suffix = "-".join(
        quote(value, safe="-._") for value in (version, platform, revision)
    )
    return (
        "https://github.com/zw3rk/farsee/releases/spdx/"
        f"farsee-{suffix}-{identity}"
    )


def expected_creation_time(epoch: int) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def audit_spdx(
    spdx: object, manifest: object, *, version: str, platform: str,
    revision: str, epoch: int, runtime_paths: list[str], binary_digest: str,
    forbidden_paths: tuple[str, ...],
) -> list[str]:
    errors: list[str] = []
    if not isinstance(spdx, dict):
        return ["SPDX SBOM must be a JSON object"]
    if not isinstance(manifest, dict):
        return ["dependency manifest must be a JSON object"]
    expected_document_keys = {
        "SPDXID", "creationInfo", "dataLicense", "documentNamespace",
        "hasExtractedLicensingInfos", "name", "packages", "relationships",
        "spdxVersion",
    }
    if set(spdx) != expected_document_keys:
        errors.append("SPDX SBOM document fields are not canonical")
    expected_document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": DOCUMENT_ID,
        "name": f"farsee-{version}-{platform}",
    }
    for key, expected in expected_document.items():
        if spdx.get(key) != expected:
            errors.append(
                f"SPDX SBOM {key} is {spdx.get(key)!r}, expected {expected!r}"
            )
    identity_document = dict(spdx)
    identity_document.pop("documentNamespace", None)
    identity = artifact_identity(binary_digest, identity_document)
    namespace = expected_namespace(version, platform, revision, identity)
    if spdx.get("documentNamespace") != namespace:
        errors.append(
            "SPDX SBOM documentNamespace is "
            f"{spdx.get('documentNamespace')!r}, expected {namespace!r}"
        )

    creation = spdx.get("creationInfo")
    if not isinstance(creation, dict):
        errors.append("SPDX SBOM creationInfo must be an object")
    else:
        if set(creation) != {"created", "creators", "licenseListVersion"}:
            errors.append("SPDX SBOM creationInfo fields are not canonical")
        expected_created = expected_creation_time(epoch)
        if creation.get("created") != expected_created:
            errors.append(
                "SPDX SBOM creationInfo.created is "
                f"{creation.get('created')!r}, expected {expected_created!r}"
            )
        creators = creation.get("creators")
        creator_set = set(creators) if isinstance(creators, list) else set()
        syft = {
            value for value in creator_set
            if isinstance(value, str) and value.startswith("Tool: syft-")
        }
        required = {
            "Organization: Anchore, Inc",
            "Tool: farsee-release-sbom",
        }
        if (not isinstance(creators, list) or
                not all(isinstance(value, str) for value in creators) or
                creators != sorted(creator_set) or len(syft) != 1 or
                creator_set != required | syft):
            errors.append("SPDX SBOM creators are not the canonical Syft tool set")
        license_list = creation.get("licenseListVersion")
        if not isinstance(license_list, str) or not license_list:
            errors.append("SPDX SBOM lacks a licenseListVersion")

    dependencies = manifest.get("dependencies")
    systems = manifest.get("system_libraries")
    if not isinstance(dependencies, list) or not isinstance(systems, list):
        return errors + ["dependency manifest package lists are invalid"]
    dependency_items: list[dict] = []
    system_items: list[dict] = []
    manifest_names = {"farsee"}
    manifest_ids = {ROOT_ID}
    for item in dependencies:
        if not isinstance(item, dict):
            errors.append("dependency manifest contains a non-object dependency")
            continue
        name = item.get("name")
        version_info = item.get("version")
        license_id = item.get("license")
        patterns = item.get("store_patterns")
        if not all(isinstance(value, str) and value
                   for value in (name, version_info, license_id)):
            errors.append("dependency manifest contains an incomplete dependency")
            continue
        if (not isinstance(patterns, list) or not patterns or
                not all(isinstance(value, str) and value for value in patterns)):
            errors.append(f"dependency manifest has invalid patterns: {name}")
            continue
        package_id = spdx_id("Dependency", name)
        if name in manifest_names:
            errors.append(f"dependency manifest contains duplicate package: {name}")
            continue
        if package_id in manifest_ids:
            errors.append(f"dependency manifest has colliding SPDXID: {package_id}")
            continue
        manifest_names.add(name)
        manifest_ids.add(package_id)
        dependency_items.append(item)
    for item in systems:
        if not isinstance(item, dict):
            errors.append("dependency manifest contains a non-object system library")
            continue
        name = item.get("name")
        license_name = item.get("license")
        exact_paths = item.get("paths")
        if not all(isinstance(value, str) and value
                   for value in (name, license_name)):
            errors.append("dependency manifest contains an incomplete system library")
            continue
        if (not isinstance(exact_paths, list) or not exact_paths or
                not all(isinstance(value, str) and value for value in exact_paths)):
            errors.append(f"dependency manifest has invalid system paths: {name}")
            continue
        package_id = spdx_id("System", name)
        if name in manifest_names:
            errors.append(f"dependency manifest contains duplicate package: {name}")
            continue
        if package_id in manifest_ids:
            errors.append(f"dependency manifest has colliding SPDXID: {package_id}")
            continue
        manifest_names.add(name)
        manifest_ids.add(package_id)
        system_items.append(item)

    selected_dependencies: set[str] = set()
    selected_systems: set[str] = set()
    for runtime_path in runtime_paths:
        dependency_matches = [
            item for item in dependency_items
            if any(pattern in runtime_path for pattern in item["store_patterns"])
        ]
        system_matches = [
            item for item in system_items if runtime_path in item["paths"]
        ]
        if len(dependency_matches) + len(system_matches) != 1:
            errors.append(
                "runtime closure path does not have one manifest package: "
                f"{runtime_path}"
            )
            continue
        if dependency_matches:
            selected_dependencies.add(dependency_matches[0]["name"])
        else:
            selected_systems.add(system_matches[0]["name"])

    expected_packages: dict[str, tuple[str, object, str, str]] = {
        "farsee": (ROOT_ID, version, "Apache-2.0", "APPLICATION")
    }
    for item in dependency_items:
        if item["name"] in selected_dependencies:
            expected_packages[item["name"]] = (
                spdx_id("Dependency", item["name"]), item["version"],
                item["license"], "LIBRARY",
            )
    expected_extracted: dict[str, str] = {}
    for item in system_items:
        if item["name"] in selected_systems:
            expected_packages[item["name"]] = (
                spdx_id("System", item["name"]), None,
                "NOASSERTION", "LIBRARY"
            )

    raw_packages = spdx.get("packages")
    actual_packages: dict[str, dict] = {}
    if not isinstance(raw_packages, list):
        errors.append("SPDX SBOM packages must be a list")
        raw_packages = []
    package_order = [
        item.get("name") for item in raw_packages if isinstance(item, dict)
    ]
    if package_order != sorted(
        package_order,
        key=lambda value: (value.casefold(), value) if isinstance(value, str)
        else ("", ""),
    ):
        errors.append("SPDX SBOM packages are not in canonical order")
    for item in raw_packages:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            errors.append("SPDX SBOM contains an invalid package")
            continue
        name = item["name"]
        if name in actual_packages:
            errors.append(f"SPDX SBOM contains duplicate package name: {name}")
        actual_packages[name] = item
    actual_ids = [
        item.get("SPDXID") for item in actual_packages.values()
    ]
    if (not all(isinstance(value, str) and re.fullmatch(
            r"SPDXRef-[0-9A-Za-z.-]+", value
    ) for value in actual_ids) or len(actual_ids) != len(set(actual_ids))):
        errors.append("SPDX SBOM package SPDXIDs are invalid or duplicate")
    missing = sorted(set(expected_packages) - set(actual_packages))
    unexpected = sorted(set(actual_packages) - set(expected_packages))
    if missing:
        errors.append(f"SPDX SBOM missing packages: {missing!r}")
    if unexpected:
        errors.append(f"SPDX SBOM unexpected packages: {unexpected!r}")
    for name in sorted(set(expected_packages) & set(actual_packages)):
        expected_id, expected_version, license_id, purpose = expected_packages[name]
        item = actual_packages[name]
        expected_fields = {
            "name": name,
            "SPDXID": expected_id,
            "licenseDeclared": license_id,
            "licenseConcluded": license_id,
            "primaryPackagePurpose": purpose,
            "filesAnalyzed": False,
            "supplier": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        if expected_version is None:
            if "versionInfo" in item:
                errors.append(
                    f"SPDX package {name!r} versionInfo must be absent"
                )
            expected_fields["comment"] = (
                "Host system library linked by farsee but not redistributed; "
                "see THIRD_PARTY_NOTICES.md."
            )
        else:
            expected_fields["versionInfo"] = expected_version
        if set(item) != set(expected_fields):
            missing_fields = sorted(set(expected_fields) - set(item))
            extra_fields = sorted(set(item) - set(expected_fields))
            errors.append(
                f"SPDX package {name!r} fields are not canonical; "
                f"missing {missing_fields!r}, extra {extra_fields!r}"
            )
        for key, expected in expected_fields.items():
            actual = item.get(key)
            if actual != expected:
                errors.append(
                    f"SPDX package {name!r} {key} is {actual!r}, "
                    f"expected {expected!r}"
                )

    raw_extracted = spdx.get("hasExtractedLicensingInfos")
    actual_extracted: dict[str, dict] = {}
    if not isinstance(raw_extracted, list):
        errors.append("SPDX SBOM extracted licensing info must be a list")
        raw_extracted = []
    extracted_order = [
        item.get("licenseId") for item in raw_extracted if isinstance(item, dict)
    ]
    if extracted_order != sorted(extracted_order):
        errors.append("SPDX SBOM extracted licensing info is not canonical")
    for item in raw_extracted:
        if not isinstance(item, dict) or not isinstance(item.get("licenseId"), str):
            errors.append("SPDX SBOM contains invalid extracted licensing info")
            continue
        if set(item) != {"extractedText", "licenseId", "name"}:
            errors.append("SPDX SBOM extracted license fields are not canonical")
        if item["licenseId"] in actual_extracted:
            errors.append(
                "SPDX SBOM contains duplicate extracted licensing info: "
                f"{item['licenseId']}"
            )
        actual_extracted[item["licenseId"]] = item
    if set(actual_extracted) != set(expected_extracted):
        errors.append("SPDX SBOM system-license references do not match the manifest")
    for license_id, license_name in expected_extracted.items():
        item = actual_extracted.get(license_id, {})
        if (item.get("name") != license_name or
                item.get("extractedText") != license_name):
            errors.append(f"SPDX SBOM extracted license differs: {license_id}")

    raw_relationships = spdx.get("relationships")
    actual_relationships = set()
    relationship_order = []
    if not isinstance(raw_relationships, list):
        errors.append("SPDX SBOM relationships must be a list")
        raw_relationships = []
    for item in raw_relationships:
        if not isinstance(item, dict):
            errors.append("SPDX SBOM contains an invalid relationship")
            continue
        if set(item) != {
            "relatedSpdxElement", "relationshipType", "spdxElementId"
        }:
            errors.append("SPDX SBOM relationship fields are not canonical")
        relationship = (
            item.get("spdxElementId"), item.get("relationshipType"),
            item.get("relatedSpdxElement"),
        )
        relationship_order.append(relationship)
        actual_relationships.add(relationship)
    if (len(actual_relationships) != len(relationship_order) or
            relationship_order != sorted(relationship_order)):
        errors.append("SPDX SBOM relationships are not canonical and unique")
    expected_relationships = {
        (DOCUMENT_ID, "DESCRIBES", ROOT_ID),
        *(
            (ROOT_ID, "DEPENDS_ON", fields[0])
            for name, fields in expected_packages.items() if name != "farsee"
        ),
    }
    if actual_relationships != expected_relationships:
        errors.append("SPDX SBOM relationships do not match the dependency manifest")

    serialized = json.dumps(spdx, sort_keys=True)
    if any(path and path in serialized for path in forbidden_paths):
        errors.append("SPDX SBOM contains an absolute build path")
    if "file://" in serialized:
        errors.append("SPDX SBOM contains a local file URI")
    return errors


def audit(
    *,
    runtime_collector: Callable[[Path], tuple[list[str], list[str]]] =
        collect_runtime_closure,
    source_root: Path = REPO_ROOT,
) -> list[str]:
    errors: list[str] = []
    try:
        paths = from_environment(os.environ)
        validate(paths)
    except (OSError, ValueError) as exc:
        return [f"release paths: {exc}"]
    try:
        epoch_raw = os.environ.get("FARSEE_AUDIT_SOURCE_DATE_EPOCH")
        if epoch_raw is None:
            epoch_raw = os.environ["SOURCE_DATE_EPOCH"]
        revision = os.environ.get("FARSEE_AUDIT_SOURCE_REV")
        if revision is None:
            revision = os.environ["FARSEE_SOURCE_REV"]
        epoch = int(epoch_raw)
    except (KeyError, ValueError) as exc:
        return [f"release identity environment: {exc}"]

    binary = paths.stage / "bin" / "farsee"
    document_dir = paths.stage / "share" / "doc" / "farsee"
    required_stage = [binary, *(document_dir / name for name in DOCUMENTS)]
    for path in required_stage:
        if not path.is_file() or path.stat().st_size == 0:
            errors.append(f"missing or empty staged file: {path}")

    for name, relative in SOURCE_DOCUMENTS.items():
        staged = document_dir / name
        source = source_root / relative
        try:
            staged_bytes = staged.read_bytes()
            source_bytes = source.read_bytes()
        except OSError as exc:
            errors.append(f"reviewed source document {relative}: {exc}")
        else:
            if staged_bytes != source_bytes:
                errors.append(
                    f"staged {name} differs from reviewed source {relative}"
                )

    if binary.is_file():
        try:
            result = subprocess.run(
                [str(binary), "--version"], check=False,
                capture_output=True, text=True, timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"staged binary version: {exc}")
        else:
            fields = result.stdout.splitlines()[0].split() if result.stdout else []
            actual = fields[1] if result.returncode == 0 and len(fields) >= 2 else None
            if actual != paths.version:
                errors.append(
                    f"binary version is {actual!r}, expected {paths.version!r}"
                )

    metadata_path = document_dir / "release-metadata.json"
    metadata = read_json(metadata_path, "release metadata", errors)
    manifest_path = document_dir / "dependencies.json"
    manifest = read_json(manifest_path, "dependency manifest", errors)
    notice_path = document_dir / "THIRD_PARTY_NOTICES.md"
    try:
        notice_text = notice_path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"third-party notices: {exc}")
        notice_text = ""
    if isinstance(manifest, dict):
        errors.extend(
            f"staged dependency policy: {error}"
            for error in audit_dependency_manifest_data(manifest, notice_text)
        )
    expected_metadata = {
        "name": "farsee",
        "platform": paths.platform,
        "schema": 1,
        "source_date_epoch": epoch,
        "source_revision": revision,
        "version": paths.version,
    }
    for key, expected in expected_metadata.items():
        if metadata.get(key) != expected:
            errors.append(
                f"metadata {key} is {metadata.get(key)!r}, expected {expected!r}"
            )

    artifact_dir = paths.artifact_dir
    sbom = artifact_dir / f"farsee-{paths.version}-{paths.platform}.spdx.json"
    notes = artifact_dir / f"farsee-{paths.version}-release-notes.md"
    checksums = artifact_dir / "SHA256SUMS"
    spdx = read_json(sbom, "SPDX SBOM", errors)

    closure_path = document_dir / "runtime-closure.txt"
    closure_paths: list[str] = []
    try:
        closure_text = closure_path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"runtime closure: {exc}")
    else:
        closure_paths = closure_text.splitlines()
        if (not closure_paths or
                not all(Path(path).is_absolute() for path in closure_paths) or
                closure_paths != sorted(set(closure_paths))):
            errors.append(
                "runtime closure must be canonical absolute, sorted, and unique"
            )
        elif isinstance(manifest, dict):
            errors.extend(
                f"runtime closure: {error}"
                for error in audit_runtime_paths_data(manifest, closure_paths)
            )
    if binary.is_file():
        try:
            actual_closure, closure_errors = runtime_collector(binary)
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"packaged binary runtime closure: {exc}")
        else:
            errors.extend(
                f"packaged binary runtime closure: {error}"
                for error in closure_errors
            )
            if not closure_errors and actual_closure != closure_paths:
                errors.append(
                    "staged runtime closure does not match the packaged binary"
                )
    try:
        binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    except OSError as exc:
        errors.append(f"release binary digest: {exc}")
        binary_digest = "0" * 64
    errors.extend(audit_spdx(
        spdx, manifest, version=paths.version, platform=paths.platform,
        revision=revision, epoch=epoch, runtime_paths=closure_paths,
        binary_digest=binary_digest,
        forbidden_paths=(str(paths.build_dir), str(paths.stage)),
    ))
    try:
        notes_text = notes.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"release notes: {exc}")
    else:
        try:
            expected_notes = extract_release_notes(
                (source_root / "CHANGELOG.md").read_text(encoding="utf-8"),
                paths.version,
            )
        except (OSError, ValueError) as exc:
            errors.append(f"reviewed release notes source: {exc}")
        else:
            if notes_text != expected_notes:
                errors.append(
                    "release notes differ from the reviewed changelog section"
                )

    checksummed = (paths.archive, sbom, notes)
    expected_order = [path.name for path in checksummed]
    expected_names = set(expected_order)
    actual_hashes: dict[str, str] = {}
    actual_order: list[str] = []
    try:
        for line in checksums.read_text(encoding="utf-8").splitlines():
            match = SHA256_LINE.fullmatch(line)
            if match is None or match.group(2) in actual_hashes:
                errors.append(f"invalid checksum line: {line!r}")
                continue
            actual_hashes[match.group(2)] = match.group(1)
            actual_order.append(match.group(2))
    except OSError as exc:
        errors.append(f"checksums: {exc}")
    if actual_order != expected_order:
        errors.append(
            "checksum filenames are not in canonical order: "
            f"{actual_order!r}, expected {expected_order!r}"
        )
    if set(actual_hashes) != expected_names:
        errors.append(
            f"checksum filenames are {sorted(actual_hashes)!r}, "
            f"expected {sorted(expected_names)!r}"
        )
    for path in checksummed:
        if not path.is_file():
            errors.append(f"missing artifact: {path}")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_hashes.get(path.name) != digest:
            errors.append(f"checksum mismatch: {path.name}")

    if paths.archive.is_file():
        try:
            with tarfile.open(paths.archive, "r:gz") as bundle:
                root = paths.stage.name
                expected_members = {
                    root: ("directory", 0o755),
                    f"{root}/bin": ("directory", 0o755),
                    f"{root}/bin/farsee": ("file", 0o755),
                    f"{root}/share": ("directory", 0o755),
                    f"{root}/share/doc": ("directory", 0o755),
                    f"{root}/share/doc/farsee": ("directory", 0o755),
                    **{
                        f"{root}/share/doc/farsee/{name}": ("file", 0o644)
                        for name in DOCUMENTS
                    },
                }
                members = {}
                for member in bundle.getmembers():
                    name = member.name.rstrip("/")
                    pure = PurePosixPath(name)
                    if pure.is_absolute() or ".." in pure.parts:
                        errors.append(f"unsafe archive member: {name}")
                    if name in members:
                        errors.append(f"duplicate archive member: {name}")
                        continue
                    members[name] = member
                    kind = (
                        "directory" if member.isdir()
                        else "file" if member.isfile()
                        else "unsupported"
                    )
                    expected = expected_members.get(name)
                    if expected is None:
                        errors.append(f"unexpected archive member: {name}")
                    else:
                        expected_kind, expected_mode = expected
                        if kind != expected_kind:
                            errors.append(
                                f"archive member has type {kind}, expected "
                                f"{expected_kind}: {name}"
                            )
                        if member.mode & 0o7777 != expected_mode:
                            errors.append(
                                f"archive member mode is "
                                f"{member.mode & 0o7777:04o}, expected "
                                f"{expected_mode:04o}: {name}"
                            )
                        if member.mtime != epoch:
                            errors.append(
                                f"archive member mtime is {member.mtime}, "
                                f"expected {epoch}: {name}"
                            )
                        if (member.uid != 0 or member.gid != 0 or
                                member.uname or member.gname):
                            errors.append(
                                f"archive member ownership is not canonical: {name}"
                            )
                for name in sorted(set(expected_members) - set(members)):
                    errors.append(f"archive is missing member: {name}")
                for staged in required_stage:
                    relative = staged.relative_to(paths.stage).as_posix()
                    name = f"{root}/{relative}"
                    member = members.get(name)
                    if member is None or not member.isfile():
                        errors.append(f"archive is missing regular file: {name}")
                        continue
                    stream = bundle.extractfile(member)
                    content = stream.read() if stream is not None else b""
                    if content != staged.read_bytes():
                        errors.append(f"archive content differs from stage: {name}")
        except (OSError, tarfile.TarError) as exc:
            errors.append(f"release archive: {exc}")
    return errors


def main() -> int:
    errors = audit()
    if errors:
        for error in errors:
            print(f"release artifact audit: {error}", file=sys.stderr)
        return 1
    print("release artifact audit: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
