#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Normalize Syft SPDX JSON into deterministic release metadata."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Mapping, Optional, Sequence
from urllib.parse import quote


TOKEN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")
SPDX_ID_PART = re.compile(r"[^0-9A-Za-z.-]+")
DOCUMENT_ID = "SPDXRef-DOCUMENT"
ROOT_ID = "SPDXRef-Package-farsee"
DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _identity_token(label: str, value: str) -> str:
    if not TOKEN.fullmatch(value):
        raise ValueError(f"invalid {label}: {value!r}")
    return value


def _spdx_id(kind: str, value: str) -> str:
    part = SPDX_ID_PART.sub("-", value).strip("-.")
    if not part:
        raise ValueError(f"cannot form an SPDX identifier for {value!r}")
    return f"SPDXRef-{kind}-{part}"


def document_namespace(
    version: str, platform: str, revision: str, artifact_digest: str,
) -> str:
    values = (
        _identity_token("version", version),
        _identity_token("platform", platform),
        _identity_token("revision", revision),
    )
    if not DIGEST.fullmatch(artifact_digest):
        raise ValueError("artifact digest must be a lowercase SHA-256 value")
    suffix = "-".join(quote(value, safe="-._") for value in values)
    return (
        "https://github.com/zw3rk/farsee/releases/spdx/"
        f"farsee-{suffix}-{artifact_digest}"
    )


def artifact_identity(
    binary_digest: str, document: Mapping[str, object],
) -> str:
    """Bind the SPDX namespace to the binary and canonical document content."""
    if not DIGEST.fullmatch(binary_digest):
        raise ValueError("binary digest must be a lowercase SHA-256 value")
    material = json.dumps(
        {"binary_sha256": binary_digest, "document": document},
        ensure_ascii=True, separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def creation_time(epoch: int) -> str:
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise ValueError("source date epoch must be a non-negative integer")
    try:
        value = datetime.fromtimestamp(epoch, timezone.utc)
    except (OSError, OverflowError, ValueError) as exc:
        raise ValueError(f"source date epoch is out of range: {epoch}") from exc
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _package(
    name: str, spdx_id: str, license_id: str, purpose: str,
    version: Optional[str] = None, comment: Optional[str] = None,
) -> dict:
    value = {
        "SPDXID": spdx_id,
        "copyrightText": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": license_id,
        "licenseDeclared": license_id,
        "name": name,
        "primaryPackagePurpose": purpose,
        "supplier": "NOASSERTION",
    }
    if version is not None:
        value["versionInfo"] = version
    if comment is not None:
        value["comment"] = comment
    return value


def _manifest_packages(
    manifest: Mapping[str, object], runtime_paths: Sequence[str],
) -> tuple[list[dict], list[dict]]:
    if manifest.get("schema") != 1:
        raise ValueError("dependency manifest schema must be 1")
    dependencies = manifest.get("dependencies")
    systems = manifest.get("system_libraries")
    if not isinstance(dependencies, list) or not dependencies:
        raise ValueError("dependency manifest needs dependencies")
    if not isinstance(systems, list) or not systems:
        raise ValueError("dependency manifest needs system_libraries")

    names = {"farsee"}
    identifiers = {ROOT_ID}
    dependency_items: list[dict] = []
    system_items: list[dict] = []
    for index, item in enumerate(dependencies):
        if not isinstance(item, dict):
            raise ValueError(f"dependency entry {index} must be an object")
        name = item.get("name")
        version = item.get("version")
        license_id = item.get("license")
        if not all(isinstance(value, str) and value
                   for value in (name, version, license_id)):
            raise ValueError(f"dependency entry {index} is incomplete")
        patterns = item.get("store_patterns")
        if (not isinstance(patterns, list) or not patterns or
                not all(isinstance(value, str) and value for value in patterns)):
            raise ValueError(f"dependency entry {index} needs store patterns")
        if name in names:
            raise ValueError(f"duplicate package name: {name}")
        spdx_id = _spdx_id("Dependency", name)
        if spdx_id in identifiers:
            raise ValueError(f"duplicate SPDX package identifier: {spdx_id}")
        names.add(name)
        identifiers.add(spdx_id)
        dependency_items.append(item)

    for index, item in enumerate(systems):
        if not isinstance(item, dict):
            raise ValueError(f"system library entry {index} must be an object")
        name = item.get("name")
        license_name = item.get("license")
        paths = item.get("paths")
        if not all(isinstance(value, str) and value
                   for value in (name, license_name)):
            raise ValueError(f"system library entry {index} is incomplete")
        if not isinstance(paths, list) or not paths:
            raise ValueError(f"system library entry {index} needs exact paths")
        if not all(isinstance(value, str) and value for value in paths):
            raise ValueError(f"system library entry {index} has an invalid path")
        if name in names:
            raise ValueError(f"duplicate package name: {name}")
        spdx_id = _spdx_id("System", name)
        if spdx_id in identifiers:
            raise ValueError(f"duplicate SPDX package identifier: {spdx_id}")
        names.add(name)
        identifiers.add(spdx_id)
        system_items.append(item)

    if (not runtime_paths or not all(
            isinstance(value, str) and value.startswith("/")
            for value in runtime_paths
    )):
        raise ValueError("runtime closure needs absolute paths")
    if list(runtime_paths) != sorted(set(runtime_paths)):
        raise ValueError("runtime closure paths must be canonical and unique")

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
        matches = [*dependency_matches, *system_matches]
        if len(matches) != 1:
            raise ValueError(
                f"runtime path has {len(matches)} manifest matches: {runtime_path}"
            )
        match = matches[0]
        if dependency_matches:
            selected_dependencies.add(match["name"])
        else:
            selected_systems.add(match["name"])

    dependency_packages = [
        _package(
            item["name"], _spdx_id("Dependency", item["name"]),
            item["license"], "LIBRARY", item["version"],
        )
        for item in dependency_items if item["name"] in selected_dependencies
    ]
    system_packages = [
        _package(
            item["name"], _spdx_id("System", item["name"]),
            "NOASSERTION", "LIBRARY", comment=(
                "Host system library linked by farsee but not redistributed; "
                "see THIRD_PARTY_NOTICES.md."
            ),
        )
        for item in system_items if item["name"] in selected_systems
    ]
    return dependency_packages, system_packages


def normalize(
    document: Mapping[str, object], manifest: Mapping[str, object],
    runtime_paths: Sequence[str], *,
    version: str, platform: str, revision: str, epoch: int,
    binary_digest: str,
) -> dict:
    """Return one canonical SPDX document or reject incomplete Syft data."""
    _identity_token("version", version)
    _identity_token("platform", platform)
    _identity_token("revision", revision)
    created = creation_time(epoch)
    if document.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("Syft output must use SPDX-2.3")
    if document.get("dataLicense") != "CC0-1.0":
        raise ValueError("Syft output must use the CC0-1.0 SPDX data license")
    if document.get("SPDXID") != DOCUMENT_ID:
        raise ValueError("Syft output has an unexpected document SPDXID")
    if document.get("name") != "farsee":
        raise ValueError("Syft source name must be farsee")

    source_packages = document.get("packages")
    if not isinstance(source_packages, list) or len(source_packages) != 1:
        raise ValueError("Syft output contains an unexpected package inventory")
    source = source_packages[0]
    if not isinstance(source, dict) or source.get("name") != "farsee":
        raise ValueError("Syft output contains an unexpected package")
    if source.get("versionInfo") != version:
        raise ValueError("Syft source version does not match the release version")

    creation = document.get("creationInfo")
    if not isinstance(creation, dict):
        raise ValueError("Syft output lacks creationInfo")
    creators = creation.get("creators")
    if (not isinstance(creators, list) or
            not all(isinstance(value, str) and value for value in creators) or
            not any(value.startswith("Tool: syft-") for value in creators)):
        raise ValueError("Syft output lacks its tool creator")
    license_list = creation.get("licenseListVersion")
    if not isinstance(license_list, str) or not license_list:
        raise ValueError("Syft output lacks its SPDX license-list version")

    dependencies, systems = _manifest_packages(manifest, runtime_paths)
    packages = [
        _package("farsee", ROOT_ID, "Apache-2.0", "APPLICATION", version),
        *dependencies,
        *systems,
    ]
    packages.sort(key=lambda item: (item["name"].casefold(), item["name"]))

    relationships = [{
        "relatedSpdxElement": ROOT_ID,
        "relationshipType": "DESCRIBES",
        "spdxElementId": DOCUMENT_ID,
    }]
    relationships.extend({
        "relatedSpdxElement": item["SPDXID"],
        "relationshipType": "DEPENDS_ON",
        "spdxElementId": ROOT_ID,
    } for item in (*dependencies, *systems))
    relationships.sort(key=lambda item: (
        item["spdxElementId"], item["relationshipType"],
        item["relatedSpdxElement"],
    ))

    normalized = {
        "SPDXID": DOCUMENT_ID,
        "creationInfo": {
            "created": created,
            "creators": sorted(set(creators) | {"Tool: farsee-release-sbom"}),
            "licenseListVersion": license_list,
        },
        "dataLicense": "CC0-1.0",
        "hasExtractedLicensingInfos": [],
        "name": f"farsee-{version}-{platform}",
        "packages": packages,
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }
    identity = artifact_identity(binary_digest, normalized)
    normalized["documentNamespace"] = document_namespace(
        version, platform, revision, identity
    )
    return normalized


def _load_json(path: Path, label: str) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def rewrite(
    sbom_path: Path, manifest_path: Path, runtime_closure_path: Path,
    binary_path: Path, *, version: str, platform: str, revision: str, epoch: int,
) -> None:
    document = _load_json(sbom_path, "Syft SPDX document")
    manifest = _load_json(manifest_path, "dependency manifest")
    if runtime_closure_path.is_symlink() or not runtime_closure_path.is_file():
        raise ValueError(
            f"runtime closure must be a regular file: {runtime_closure_path}"
        )
    try:
        runtime_paths = runtime_closure_path.read_text(
            encoding="utf-8"
        ).splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot read runtime closure: {exc}") from exc
    if binary_path.is_symlink() or not binary_path.is_file():
        raise ValueError(f"release binary must be a regular file: {binary_path}")
    try:
        binary_digest = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ValueError(f"cannot read release binary: {exc}") from exc
    value = normalize(
        document, manifest, runtime_paths, version=version, platform=platform,
        revision=revision, epoch=epoch, binary_digest=binary_digest,
    )
    content = json.dumps(value, indent=2, sort_keys=True) + "\n"
    temporary: Optional[Path] = None
    try:
        descriptor, raw = tempfile.mkstemp(
            prefix=f".{sbom_path.name}.", dir=sbom_path.parent
        )
        temporary = Path(raw)
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, sbom_path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sbom", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--runtime-closure", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--version")
    parser.add_argument("--platform")
    parser.add_argument("--revision")
    parser.add_argument("--epoch", type=int)
    args = parser.parse_args(argv)
    version = args.version or os.environ.get("FARSEE_GUARD_VERSION")
    platform = args.platform or os.environ.get("FARSEE_GUARD_PLATFORM")
    revision = args.revision or os.environ.get("FARSEE_AUDIT_SOURCE_REV")
    epoch = args.epoch
    if epoch is None:
        raw = os.environ.get("FARSEE_AUDIT_SOURCE_DATE_EPOCH")
        try:
            epoch = int(raw) if raw is not None else None
        except ValueError:
            parser.error("FARSEE_AUDIT_SOURCE_DATE_EPOCH must be an integer")
    if version is None or platform is None or revision is None or epoch is None:
        parser.error("version, platform, revision, and epoch are required")
    try:
        rewrite(
            args.sbom, args.manifest, args.runtime_closure, args.binary,
            version=version, platform=platform,
            revision=revision, epoch=epoch,
        )
    except (OSError, ValueError) as exc:
        print(f"release SBOM: {exc}", file=sys.stderr)
        return 1
    print(f"release SBOM: normalized {args.sbom}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
