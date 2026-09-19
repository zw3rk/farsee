#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Build two complete release artifact sets and compare their bytes.

set -eu

ROOT="${1:?usage: check_reproducible.sh ROOT BUILD_DIR}"
BASE="${2:?usage: check_reproducible.sh ROOT BUILD_DIR}"
REV="${FARSEE_SOURCE_REV:-$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || printf unknown)}"
EPOCH="${SOURCE_DATE_EPOCH:-1}"
VERSION="${FARSEE_GUARD_VERSION:-0.1.0-dev}"
PLATFORM="${FARSEE_GUARD_PLATFORM:-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)}"
RDP="${FARSEE_WITH_RDP:-1}"
BUILD_TIMEOUT="${FARSEE_REPRO_BUILD_TIMEOUT_SECONDS:-600}"
A="$BASE/repro-a"
B="$BASE/repro-b"

case "$BUILD_TIMEOUT" in
    *[!0-9]*|'')
        echo "invalid FARSEE_REPRO_BUILD_TIMEOUT_SECONDS: $BUILD_TIMEOUT" >&2
        exit 2
        ;;
esac

build_artifacts() {
    candidate="$1"
    timeout "$BUILD_TIMEOUT" make -C "$ROOT" BUILD_DIR="$candidate" clean
    timeout "$BUILD_TIMEOUT" make -C "$ROOT" \
        BUILD_DIR="$candidate" BUILD=release CC=clang \
        VERSION="$VERSION" RELEASE_PLATFORM="$PLATFORM" \
        FARSEE_WITH_RDP="$RDP" FARSEE_SOURCE_REV="$REV" \
        SOURCE_DATE_EPOCH="$EPOCH" release-artifacts
}

build_artifacts "$A"
build_artifacts "$B"

cmp "$A/release/bin/farsee" "$B/release/bin/farsee"
for artifact in \
    "farsee-$VERSION-$PLATFORM.tar.gz" \
    "farsee-$VERSION-$PLATFORM.spdx.json" \
    "farsee-$VERSION-release-notes.md" \
    SHA256SUMS
do
    cmp "$A/release-artifacts/$artifact" "$B/release-artifacts/$artifact"
done
echo "ok: release binary and artifact set are byte-for-byte reproducible"
