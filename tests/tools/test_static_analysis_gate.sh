#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Negative self-test for the static-analysis gate: the
# gate must fail when the analyzer itself errors out, including a broken SDK
# path, a missing compiler, or `clang: error:` output. Analyzer exit status is
# authoritative even when output is filtered.
#
# SA_FILES limits the gate to one file so the self-test stays fast.

set -u

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

fail() {
    echo "not ok: $1" >&2
    exit 1
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/static-gate-selftest.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

# Fake analyzer mimicking a broken-SDK clang: writes `clang: error:` to stderr
# and exits with status 1.
fakebin="$tmp/bin"
mkdir -p "$fakebin"
cat > "$fakebin/clang" <<'EOF'
#!/bin/sh
echo "clang: error: no such file or directory: '/broken/sdk/usr/include'" >&2
exit 1
EOF
chmod +x "$fakebin/clang"

# 1. Broken analyzer must fail the gate even though the only output
#    line starts with "clang:".
if make -C "$ROOT" ANALYZER_CC="$fakebin/clang" SA_FILES="src/core/bytes.c" \
        check-static-analysis > "$tmp/neg.log" 2>&1; then
    cat "$tmp/neg.log" >&2
    fail "static-analysis gate must fail on analyzer error"
fi

# 2. Benign-only output must still pass: emit nothing but the documented
#    `unused-command-line-argument` warning and exit 0.
cat > "$fakebin/clang" <<'EOF'
#!/bin/sh
echo "clang: warning: argument unused during compilation: '-isysroot /x' [-Wunused-command-line-argument]" >&2
exit 0
EOF
chmod +x "$fakebin/clang"
if ! make -C "$ROOT" ANALYZER_CC="$fakebin/clang" SA_FILES="src/core/bytes.c" \
        check-static-analysis > "$tmp/benign.log" 2>&1; then
    cat "$tmp/benign.log" >&2
    fail "gate must ignore the documented unused-command-line-argument warning"
fi

# 3. A clean single-file analysis must pass.
if ! make -C "$ROOT" SA_FILES="src/core/bytes.c" check-static-analysis \
        > "$tmp/pos.log" 2>&1; then
    cat "$tmp/pos.log" >&2
    fail "gate must pass a clean real analysis"
fi

echo "ok: static-analysis gate selftest"
