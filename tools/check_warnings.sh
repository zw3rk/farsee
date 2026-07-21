#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# G0 configure self-test: prove the build treats warnings as errors
# (plan.md §15.2). A program with a deliberate, well-defined warning
# (unused parameter under -Wextra) must FAIL to compile.
set -u

CC="${CC:-clang}"
TMPDIR_WORK=$(mktemp -d 2>/dev/null || mktemp -d -t farsee_warn)
trap 'rm -rf "$TMPDIR_WORK"' EXIT
SRC="$TMPDIR_WORK/warn.c"
OBJ="$TMPDIR_WORK/warn.o"

cat >"$SRC" <<'EOF'
static int f(int x, int y) {  /* y is deliberately unused */
    return x;
}
int main(void) { return f(1, 2); }
EOF

if "$CC" -std=c11 -pedantic -Wall -Wextra -Werror -c -o "$OBJ" "$SRC" 2>/dev/null; then
    echo "FAIL: $CC compiled an unused-parameter program under -Wextra -Werror." >&2
    echo "      Warnings must fail the build (plan.md §15.2)." >&2
    exit 1
fi

echo "ok: -Wextra -Werror flags a deliberate warning ($CC)."
exit 0
