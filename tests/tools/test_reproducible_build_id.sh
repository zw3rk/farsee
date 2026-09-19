#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Stable source identity must not depend on the current clock or an in-tree .git.

set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/farsee-build-id.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

make -C "$ROOT" BUILD_DIR="$tmp/a" BUILD=dev FARSEE_SOURCE_REV=0123456789ab \
    SOURCE_DATE_EPOCH=1700000000 gen-build-id >/dev/null
first="$tmp/a/dev/obj/generated/build_id.h"
cp "$first" "$tmp/first.h"
sleep 1
make -C "$ROOT" BUILD_DIR="$tmp/a" BUILD=dev FARSEE_SOURCE_REV=0123456789ab \
    SOURCE_DATE_EPOCH=1700000000 gen-build-id >/dev/null
cmp "$tmp/first.h" "$first"
grep -q 'FARSEE_GIT_REV "0123456789ab"' "$first"
grep -q 'FARSEE_BUILD_TIME "source-date-epoch:1700000000"' "$first"

echo "ok: reproducible build identity selftest"
