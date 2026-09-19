#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Run every fuzz target briefly against its corpus (plan.md §G12
# per-change fuzz smoke). Each target is executed with its output
# captured to a log file; the gate FAILS on any target that exits
# non-zero (crash, sanitizer abort, libFuzzer error).
#
# Overridable knobs (also used by the tests/tools/test_fuzz_smoke.sh
# negative self-test):
#   FUZZ_BIN          directory holding the fuzz binaries
#   FUZZ_CORPUS_ROOT  root of the per-target corpus directories
#   FUZZ_LOG_DIR      where per-target run logs are written
#   FUZZ_ARTIFACT_ROOT where libFuzzer crash and timeout artifacts are retained
#   FUZZ_DURATION     seconds per target (G12 sets this higher)
#   FUZZ_MAX_LEN      max input length per target
set -u

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
FUZZ_BIN="${FUZZ_BIN:-$ROOT/build/fuzz/bin}"
CORPUS_ROOT="${FUZZ_CORPUS_ROOT:-$ROOT/tests/fuzz/corpus}"
LOG_DIR="${FUZZ_LOG_DIR:-$ROOT/build/fuzz/logs}"
ARTIFACT_ROOT="${FUZZ_ARTIFACT_ROOT:-$LOG_DIR/artifacts}"
DURATION="${FUZZ_DURATION:-5}"   # seconds per target, G12 sets this higher

if [ ! -d "$FUZZ_BIN" ]; then
    echo "fuzz-smoke: no fuzz binaries (expected at $FUZZ_BIN)." >&2
    echo "fuzz-smoke: build them first: make BUILD=fuzz fuzz" >&2
    exit 2
fi

mkdir -p "$LOG_DIR"

status=0
ran=0
for target in "$FUZZ_BIN"/*; do
    # Only run regular executable files (skip .dSYM dirs on macOS, etc.).
    [ -f "$target" ] || continue
    [ -x "$target" ] || continue
    name="$(basename "$target")"
    corpus="$CORPUS_ROOT/$name"
    log="$LOG_DIR/$name.log"
    artifacts="$ARTIFACT_ROOT/$name"
    echo "==> $name (max ${DURATION}s)"
    mkdir -p "$corpus" "$artifacts"
    # Run the target with output redirected to a log file so the exit
    # status we capture is the target's. POSIX sh has no pipefail, so a
    # pipeline can hide a target failure.
    # -max_total_time caps wall clock; -max_len is per-target and set by
    # the target's own LLVMFuzzerTestOneInput contract.
    "$target" -max_total_time="$DURATION" \
        -artifact_prefix="$artifacts/" "$corpus" \
        -max_len="${FUZZ_MAX_LEN:-4096}" > "$log" 2>&1
    rc=$?
    ran=$((ran + 1))
    tail -3 "$log"
    if [ "$rc" -ne 0 ]; then
        echo "FAIL: $name (exit $rc; full log: $log)"
        status=1
    fi
done

# An empty or binary-less FUZZ_BIN would loop zero times and exit 0. Treat
# zero executed targets as a gate failure.
if [ "$ran" -eq 0 ]; then
    echo "FAIL: no fuzz targets found in $FUZZ_BIN (expected built targets)" >&2
    status=1
fi

exit $status
