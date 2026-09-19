#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write deterministic project release metadata as canonical JSON."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re


TOKEN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")


def metadata(version: str, platform: str, revision: str, epoch: int) -> dict:
    for label, value in (
        ("version", version),
        ("platform", platform),
        ("revision", revision),
    ):
        if not TOKEN.fullmatch(value):
            raise ValueError(f"invalid {label}: {value!r}")
    if epoch < 0:
        raise ValueError("source date epoch must be non-negative")
    return {
        "name": "farsee",
        "platform": platform,
        "schema": 1,
        "source_date_epoch": epoch,
        "source_revision": revision,
        "version": version,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--platform", required=True)
    parser.add_argument("--revision")
    parser.add_argument("--epoch", type=int)
    args = parser.parse_args()
    version = args.version or os.environ.get("FARSEE_GUARD_VERSION")
    revision = args.revision or os.environ.get("FARSEE_AUDIT_SOURCE_REV")
    epoch = args.epoch
    if epoch is None:
        raw_epoch = os.environ.get("FARSEE_AUDIT_SOURCE_DATE_EPOCH")
        try:
            epoch = int(raw_epoch) if raw_epoch is not None else None
        except ValueError:
            parser.error("FARSEE_AUDIT_SOURCE_DATE_EPOCH must be an integer")
    if version is None or revision is None or epoch is None:
        parser.error("version, revision, and epoch release identity are required")
    try:
        value = metadata(version, args.platform, revision, epoch)
    except ValueError as exc:
        parser.error(str(exc))
    content = json.dumps(value, indent=2, sort_keys=True) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
