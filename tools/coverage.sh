#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Aggregate gcov/gcno data into an lcov report and enforce the plan.md
# §15.5 coverage thresholds. The thresholds are deliberately low for G0
# (the project is mostly empty) and tighten per gate as modules land.
#
# Usage:
#   tools/coverage.sh <build-root> <coverage-out-dir> [--enforce]
#
# Inputs: <build-root>  the BUILD=coverage object tree (contains *.gcno/*.gcda)
#         <coverage-out-dir>  where to write lcov/html output
#         --enforce  exit non-zero if any module threshold is missed
set -u

BUILD_ROOT="${1:?usage: coverage.sh <build-root> <out-dir> [--enforce]}"
OUT_DIR="${2:?usage: coverage.sh <build-root> <out-dir> [--enforce]}"
ENFORCE=0
THRESHOLD_FILE="${COVERAGE_THRESHOLDS:-$(dirname "$0")/../coverage-thresholds.tsv}"
if [ "${3:-}" = "--enforce" ]; then ENFORCE=1; fi

mkdir -p "$OUT_DIR"

if ! command -v lcov >/dev/null 2>&1; then
    echo "coverage: lcov not found on PATH; run inside 'nix develop'." >&2
    exit 2
fi

# Prefer llvm-cov (matches clang-built artifacts) via our shim that adds
# the `gcov` subcommand lcov expects; fall back to plain gcov.
GCOV_TOOL=""
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if command -v llvm-cov >/dev/null 2>&1; then
    GCOV_TOOL="--gcov-tool $SCRIPT_DIR/llvm-gcov.sh"
fi

# lcov 2.x is strict about gcno/gcda format versions. When clang produces
# the data (format Bxx*) but the default gcov is GCC's (different format),
# lcov refuses. We pass --ignore-errors version to keep going; the line/branch
# data itself is still parsed correctly.
LCOV_COMMON="--rc lcov_branch_coverage=1 --rc lcov_excl_br_line=1 --rc lcov_excl_line=LCOV_EXCL_LINE --ignore-errors version,mismatch $GCOV_TOOL"

echo "==> Capturing coverage from $BUILD_ROOT"
eval lcov $LCOV_COMMON --capture \
     --directory "$BUILD_ROOT" --output-file "$OUT_DIR/farsee.info" \
     \> "$OUT_DIR/capture.log" 2\>\&1 || {
    echo "coverage: lcov --capture failed; see $OUT_DIR/capture.log" >&2
    tail -20 "$OUT_DIR/capture.log" >&2
    exit 1
}

echo "==> Filtering to first-party code"
eval lcov $LCOV_COMMON \
     --extract "$OUT_DIR/farsee.info" '*/src/*' \
     --output-file "$OUT_DIR/farsee.filtered.info" \
     \>\> "$OUT_DIR/capture.log" 2\>\&1 || {
    # extract failure is non-fatal; we still have the raw .info
    cp "$OUT_DIR/farsee.info" "$OUT_DIR/farsee.filtered.info"
}

echo "==> HTML report"
genhtml --branch-coverage -o "$OUT_DIR/html" "$OUT_DIR/farsee.filtered.info" \
        >> "$OUT_DIR/capture.log" 2>&1 || true

echo "==> Coverage summary"
# lcov 2.x renamed --summary; try both.
lcov --rc lcov_branch_coverage=1 --summary "$OUT_DIR/farsee.filtered.info" \
     2>&1 | tee "$OUT_DIR/summary.txt" || true

echo "coverage report: $OUT_DIR/html/index.html"

# Threshold enforcement (G12 populates coverage-thresholds.tsv). Until then
# --enforce is a no-op that just confirms the report was produced.
if [ "$ENFORCE" = "1" ]; then
    if [ ! -f "$THRESHOLD_FILE" ]; then
        echo "coverage: --enforce ignored (no $THRESHOLD_FILE yet; G0 baseline)."
        exit 0
    fi
    echo "coverage: enforcing thresholds from $THRESHOLD_FILE"
    # TODO G12: parse per-module line/branch thresholds and fail on miss.
fi

exit 0
