#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Run every fuzz target briefly against its corpus (plan.md §G12
# per-change fuzz smoke). The actual targets land starting in G1
# (fuzz_bytes_and_buffer); until then this script is a no-op scaffold
# that exists so `make fuzz-smoke` is callable from G0's CI target.
set -u

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
FUZZ_BIN="$ROOT/build/fuzz/bin"
DURATION="${FUZZ_DURATION:-5}"   # seconds per target, G12 sets this higher

if [ ! -d "$FUZZ_BIN" ]; then
    echo "fuzz-smoke: no fuzz binaries yet (expected at $FUZZ_BIN)."
    echo "fuzz-smoke: targets land starting in G1. Skipping."
    exit 0
fi

status=0
for target in "$FUZZ_BIN"/*; do
    # Only run regular executable files (skip .dSYM dirs on macOS, etc.).
    [ -f "$target" ] || continue
    [ -x "$target" ] || continue
    name="$(basename "$target")"
    corpus="$ROOT/tests/fuzz/corpus/$name"
    echo "==> $name (max ${DURATION}s)"
    mkdir -p "$corpus"
    # -max_total_time caps wall clock; -max_len is per-target and set by
    # the target's own LLVMFuzzerTestOneInput contract.
    "$target" -max_total_time="$DURATION" "$corpus" \
        -max_len="${FUZZ_MAX_LEN:-4096}" \
        2>&1 | tail -3 || {
            echo "FAIL: $name"
            status=1
        }
done

exit $status
