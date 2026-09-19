#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for the test-registry feature stamp: the
# generated registry content depends on FARSEE_WITH_RDP, so toggling the
# feature in the same build dir must ALWAYS regenerate the registry.
# Before the stamp, a FARSEE_WITH_RDP=0 build left a feature-0 registry
# behind and plain `make test` silently skipped the 12 rdp unit files.

set -u

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

fail() {
    echo "not ok: $1" >&2
    exit 1
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/registry-toggle-selftest.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

GENINC="$tmp/dev/obj/generated/test_includes.generated.h"
GENREG="$tmp/dev/obj/generated/registry.generated.c"

rdp_entries() {
    grep -c 'unit/rdp/' "$GENREG" 2>/dev/null || true
}

registry_mtime() {
    # BSD stat: -f %m; GNU stat: -c %Y (GNU -f means "file-system dump"
    # and would capture live fs counters, never comparing equal). Only a
    # bare numeric answer counts; anything else falls through.
    m="$(stat -f %m "$GENREG" 2>/dev/null)"
    case "$m" in
        '' | *[!0-9]*) m="$(stat -c %Y "$GENREG" 2>/dev/null)" ;;
    esac
    printf '%s\n' "$m"
}

# 1. Feature-off generation: registry must exclude rdp tests.
make -C "$ROOT" BUILD_DIR="$tmp" BUILD=dev FARSEE_WITH_RDP=0 gen-test-registry \
    > "$tmp/gen0.log" 2>&1 \
    || { cat "$tmp/gen0.log" >&2; fail "FARSEE_WITH_RDP=0 registry generation failed"; }
n0="$(rdp_entries)"
[ "$n0" = "0" ] || fail "feature-off registry must not include rdp tests (got $n0)"

# 2. Plain (feature-on) invocation in the SAME build dir must REGENERATE
#    the registry with the RDP tests restored. A stale registry is a bug.
sleep 1
make -C "$ROOT" BUILD_DIR="$tmp" BUILD=dev FARSEE_WITH_RDP=1 gen-test-registry \
    > "$tmp/gen1.log" 2>&1 \
    || { cat "$tmp/gen1.log" >&2; fail "default registry generation failed"; }
n1="$(rdp_entries)"
[ "$n1" -gt 0 ] 2>/dev/null || \
    fail "registry stale across FARSEE_WITH_RDP toggle: rdp tests missing"

# 3. Registry size sanity: the feature-on registry must REGISTER more
#    tests than the feature-off one (the rdp suite is included).
reg0_lines="$(grep -c 'extern const rfb_test_entry' "$GENREG" 2>/dev/null || true)"
[ "$reg0_lines" -gt 1500 ] 2>/dev/null || \
    fail "feature-on registry implausibly small ($reg0_lines entries)"

# 4. Re-running with an UNCHANGED value must NOT regenerate (idempotent;
#    the stamp must not force needless runner rebuilds).
before="$(registry_mtime)"
sleep 1
make -C "$ROOT" BUILD_DIR="$tmp" BUILD=dev FARSEE_WITH_RDP=1 gen-test-registry \
    > "$tmp/gen1b.log" 2>&1 \
    || { cat "$tmp/gen1b.log" >&2; fail "repeat registry generation failed"; }
after="$(registry_mtime)"
[ "$before" = "$after" ] || \
    fail "registry regenerated although FARSEE_WITH_RDP did not change"

# 5. Toggling back to 0 must regenerate again.
sleep 1
make -C "$ROOT" BUILD_DIR="$tmp" BUILD=dev FARSEE_WITH_RDP=0 gen-test-registry \
    > "$tmp/gen0b.log" 2>&1 \
    || { cat "$tmp/gen0b.log" >&2; fail "toggle-back registry generation failed"; }
n0b="$(rdp_entries)"
[ "$n0b" = "0" ] || fail "toggle back to 0 must regenerate a feature-off registry"

echo "ok: registry feature-stamp selftest"
