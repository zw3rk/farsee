#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for compiler header dependency tracking:
# objects must be compiled with -MMD -MP and the emitted .d files must
# be included by make, so touching a widely-included header rebuilds its
# dependents. Without dependency tracking, editing a
# header left dependent objects stale across incremental builds.

set -u

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

fail() {
    echo "not ok: $1" >&2
    exit 1
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/dep-tracking-selftest.XXXXXX")"
cleanup() {
    # Restore the header's exact mtime (snapshot taken via cp -p).
    if [ -f "$mtref" ]; then
        touch -r "$mtref" "$HDR" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

OBJ="$tmp/dev/obj/rfb/rfb_session.o"
HDR="$ROOT/include/farsee/rfb_session.h"
mtref="$tmp/hdr.mtime.ref"

# 1. Compile one object that includes the public session header. The
#    compile rule must also emit a .d fragment (-MMD -MP).
make -C "$ROOT" BUILD_DIR="$tmp" BUILD=dev "$tmp/dev/obj/rfb/rfb_session.o" \
    > "$tmp/build.log" 2>&1 \
    || { cat "$tmp/build.log" >&2; fail "object build failed"; }
[ -f "$OBJ" ] || fail "expected object was not built"
[ -f "${OBJ%.o}.d" ] || fail "compiler dependency file missing (no -MMD)"
grep -q 'rfb_session\.h' "${OBJ%.o}.d" \
    || fail "dep file does not record rfb_session.h"

# 2. Touch the header, then a dry-run must schedule a recompile of the
#    dependent object. (mtime is restored afterwards — content never
#    changes.)
cp -p "$HDR" "$mtref" || fail "cannot snapshot header mtime"
# Some filesystems and Make versions compare only whole-second mtimes. Ensure
# the touched header is strictly newer than the object on those platforms.
sleep 1
touch "$HDR"
out="$(make -C "$ROOT" BUILD_DIR="$tmp" BUILD=dev "$OBJ" -n 2>&1)"
touch -r "$mtref" "$HDR"
case "$out" in
    *"-c -o"*) ;;
    *) echo "$out" >&2; fail "dependent object not rebuilt after header touch" ;;
esac

# 3. With nothing changed, a dry-run must NOT recompile (the dep change
#    must not break incremental builds).
out2="$(make -C "$ROOT" BUILD_DIR="$tmp" BUILD=dev "$OBJ" -n 2>&1)"
case "$out2" in
    *"-c -o"*) echo "$out2" >&2
               fail "object rebuilt although nothing changed (non-idempotent)" ;;
    *) ;;
esac

echo "ok: header dependency tracking selftest"
