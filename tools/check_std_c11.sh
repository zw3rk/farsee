#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# G0 configure self-test: prove the build enforces the Curated C11 subset
# with no GNU extensions (AGENTS.md "C programming guidelines";
# plan.md §15.1). A program that uses a non-C11 (GCC-specific) construct
# must FAIL to compile under the project's standard flags.
#
# Specifically, taking the address of a label with the `&&label` GCC
# extension (computed goto) is a GNU-only construct and is rejected under
# -std=c11 -pedantic.
set -u

CC="${CC:-clang}"
TMPDIR_WORK=$(mktemp -d 2>/dev/null || mktemp -d -t farsee_c11)
trap 'rm -rf "$TMPDIR_WORK"' EXIT
SRC="$TMPDIR_WORK/ext.c"
OBJ="$TMPDIR_WORK/ext.o"

cat >"$SRC" <<'EOF'
/* Computed goto: GCC-only extension, not valid ISO C11. */
static int f(int which) {
    static void *tbl[] = { &&a, &&b };
    goto *tbl[which];
a:
    return 1;
b:
    return 2;
}
int main(void) { return f(0); }
EOF

if "$CC" -std=c11 -pedantic -Wall -Wextra -Werror -c -o "$OBJ" "$SRC" 2>/dev/null; then
    echo "FAIL: $CC accepted a GNU computed-goto under -std=c11 -pedantic -Werror." >&2
    echo "      The project must keep C extensions disabled (plan.md §15.1)." >&2
    exit 1
fi

echo "ok: -std=c11 -pedantic rejects a GNU-only construct ($CC)."
exit 0
