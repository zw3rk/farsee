#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for tools/fuzz_smoke.sh.
#
# It verifies that a zero-exit target passes, a signal-like or plain nonzero
# target fails, and an empty target directory fails. Output redirection must
# not mask target failure.
#
# The FUZZ_BIN/FUZZ_CORPUS_ROOT/FUZZ_LOG_DIR/FUZZ_ARTIFACT_ROOT knobs avoid
# real fuzz binaries.

set -u

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SCRIPT="$ROOT/tools/fuzz_smoke.sh"

fail() {
    echo "not ok: $1" >&2
    exit 1
}

[ -x "$SCRIPT" ] || fail "tools/fuzz_smoke.sh missing or not executable"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/fuzz-smoke-selftest.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

# Healthy fake target: consumes libFuzzer args, exits 0.
mkdir -p "$tmp/ok-bin"
cat > "$tmp/ok-bin/fuzz_fake_ok" <<'EOF'
#!/bin/sh
if [ -n "${FUZZ_FAKE_ARGS_OUT:-}" ]; then
    printf '%s\n' "$@" > "$FUZZ_FAKE_ARGS_OUT"
fi
exit 0
EOF
chmod +x "$tmp/ok-bin/fuzz_fake_ok"

# Representative deadly-signal fake: write a libFuzzer-style message, then
# terminate with SIGABRT.
mkdir -p "$tmp/crash-bin"
cat > "$tmp/crash-bin/fuzz_fake_crash" <<'EOF'
#!/bin/sh
echo "==1234== ERROR: libFuzzer: deadly signal" >&2
kill -ABRT $$
EOF
chmod +x "$tmp/crash-bin/fuzz_fake_crash"

# Failing fake target: plain non-zero exit (libFuzzer error path).
mkdir -p "$tmp/fail-bin"
cat > "$tmp/fail-bin/fuzz_fake_exit77" <<'EOF'
#!/bin/sh
echo "ERROR: the fuzzing engine exited with an error" >&2
exit 77
EOF
chmod +x "$tmp/fail-bin/fuzz_fake_exit77"

# 1. Healthy-only run must pass the gate.
if ! FUZZ_BIN="$tmp/ok-bin" FUZZ_CORPUS_ROOT="$tmp/corpus" \
     FUZZ_LOG_DIR="$tmp/logs" FUZZ_ARTIFACT_ROOT="$tmp/artifacts" \
     FUZZ_FAKE_ARGS_OUT="$tmp/ok.args" FUZZ_DURATION=1 \
     "$SCRIPT" > "$tmp/ok.log" 2>&1; then
    cat "$tmp/ok.log" >&2
    fail "healthy corpus run must exit 0"
fi
[ -d "$tmp/artifacts/fuzz_fake_ok" ] ||
    fail "healthy run must create a per-target artifact directory"
grep -Fqx -- \
    "-artifact_prefix=$tmp/artifacts/fuzz_fake_ok/" "$tmp/ok.args" ||
    fail "healthy run must direct libFuzzer artifacts to retained storage"

# 2. A deadly-signal target must fail the gate.
if FUZZ_BIN="$tmp/crash-bin" FUZZ_CORPUS_ROOT="$tmp/corpus" \
     FUZZ_LOG_DIR="$tmp/logs" FUZZ_DURATION=1 \
     "$SCRIPT" > "$tmp/crash.log" 2>&1; then
    cat "$tmp/crash.log" >&2
    fail "crashing target (deadly signal) must fail the gate"
fi

# 3. A plain non-zero target must FAIL the gate too.
if FUZZ_BIN="$tmp/fail-bin" FUZZ_CORPUS_ROOT="$tmp/corpus" \
     FUZZ_LOG_DIR="$tmp/logs" FUZZ_DURATION=1 \
     "$SCRIPT" > "$tmp/fail.log" 2>&1; then
    cat "$tmp/fail.log" >&2
    fail "non-zero-exit target must fail the gate"
fi

# 4. An empty FUZZ_BIN (no built targets) must fail, not pass without testing.
#    The shell glob matches nothing, so no target runs.
mkdir -p "$tmp/empty-bin"
if FUZZ_BIN="$tmp/empty-bin" FUZZ_CORPUS_ROOT="$tmp/corpus" \
     FUZZ_LOG_DIR="$tmp/logs" FUZZ_DURATION=1 \
     "$SCRIPT" > "$tmp/empty.log" 2>&1; then
    cat "$tmp/empty.log" >&2
    fail "empty fuzz-bin must fail the gate, not pass vacuously"
fi

echo "ok: fuzz_smoke gate selftest"
