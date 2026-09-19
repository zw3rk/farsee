#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Aggregate gcov/gcno data into an lcov report and enforce the
# tools/coverage-thresholds.tsv ratchet (plan.md §15.5).
#
# Usage:
#   tools/coverage.sh <build-root> <coverage-out-dir> \
#       --sources <product-source-list> [--enforce]
#   tools/coverage.sh --check-thresholds <info-file> <thresholds.tsv>
#   tools/coverage.sh --check-total <info-file> <line-pct> <branch-pct>
#
# Inputs: <build-root>  the BUILD=coverage object tree (contains *.gcno/*.gcda)
#         <coverage-out-dir>  where to write lcov/html output
#         --sources  newline-separated absolute product .c paths
#         --enforce  exit non-zero if any module threshold is missed
#         --check-thresholds  run ONLY the enforcement pass against an
#           existing lcov .info file (used by the tests/tools shell
#           self-tests and when re-seeding the ratchet).
#
# Threshold TSV format (TAB-separated; '#'-prefixed lines are comments):
#   <module>	<min_line_pct>	<min_branch_pct>
# The module is the first path component under src/ (e.g. `core`,
# `rfb`); `*` is the catch-all row applied to any module without an
# exact row. Enforcement fails closed:
#   - missing thresholds file                    -> exit 1
#   - malformed / duplicate rows                 -> exit non-zero
#   - module with no matching row (and no `*`)   -> exit 1
#   - any module below either floor              -> exit 1
#   - row naming a module with no measured files -> exit 1
set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
THRESHOLD_FILE="${COVERAGE_THRESHOLDS:-$SCRIPT_DIR/coverage-thresholds.tsv}"

check_total() {
    ct_info="$1"
    ct_line="$2"
    ct_branch="$3"
    [ -f "$ct_info" ] || {
        echo "coverage: aggregate info missing: $ct_info" >&2
        return 1
    }
    case "$ct_line:$ct_branch" in
        *[!0-9:]* | :* | *:) echo "coverage: aggregate floors must be integers" >&2; return 2 ;;
    esac
    [ "$ct_line" -le 100 ] && [ "$ct_branch" -le 100 ] || {
        echo "coverage: aggregate floors must be 0..100" >&2
        return 2
    }
    awk -F: -v want_line="$ct_line" -v want_branch="$ct_branch" '
        $1 == "LF" { lf += $2 }
        $1 == "LH" { lh += $2 }
        $1 == "BRF" { bf += $2 }
        $1 == "BRH" { bh += $2 }
        END {
            if (lf <= 0 || bf <= 0) {
                print "coverage: aggregate line/branch data missing" > "/dev/stderr"
                exit 1
            }
            lp = int((100 * lh) / lf)
            bp = int((100 * bh) / bf)
            printf("coverage: aggregate lines %d%% (floor %d%%), branches %d%% (floor %d%%)\n",
                   lp, want_line, bp, want_branch)
            if (lp < want_line || bp < want_branch) exit 1
        }
    ' "$ct_info"
}

# ---------------------------------------------------------------------------
# Threshold enforcement: aggregate the lcov .info per src/ module and
# compare against the TSV floors. Prints the measured table on stdout,
# failures on stderr. Returns non-zero on any miss.
# ---------------------------------------------------------------------------
enforce_thresholds() {
    et_info="$1"
    et_tsv="$2"
    if [ ! -f "$et_info" ]; then
        echo "coverage: no lcov data at $et_info" >&2
        return 1
    fi
    if [ ! -f "$et_tsv" ]; then
        echo "coverage: thresholds file missing: $et_tsv" >&2
        echo "coverage: enforcement fails closed without it" \
             "(seed tools/coverage-thresholds.tsv from a measured run)" >&2
        return 1
    fi
    awk -v tsv="$et_tsv" -v info="$et_info" '
        FILENAME == tsv {
            line = $0
            sub(/\r$/, "", line)
            if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) next
            n = split(line, f, "\t")
            if (n != 3) {
                printf("coverage: malformed threshold row " \
                       "(want module<TAB>line<TAB>branch): %s\n", line) > "/dev/stderr"
                bad = 1
                next
            }
            mod = f[1]
            if (mod in tline) {
                printf("coverage: duplicate threshold row for module %s\n", \
                       mod) > "/dev/stderr"
                bad = 1
            }
            tline[mod] = f[2] + 0
            tbr[mod] = f[3] + 0
            next
        }
        /^SF:/ {
            path = substr($0, 4)
            mod = ""
            if (path ~ /\/src\//) {
                sub(/^.*\/src\//, "", path)
                i = index(path, "/")
                mod = (i > 0) ? substr(path, 1, i - 1) : path
            }
            cur = mod
            next
        }
        /^(LF|LH|BRF|BRH):/ {
            split($0, kv, ":")
            if (cur == "") next
            if (kv[1] == "LF") lf[cur] += kv[2]
            else if (kv[1] == "LH") lh[cur] += kv[2]
            else if (kv[1] == "BRF") brf[cur] += kv[2]
            else if (kv[1] == "BRH") brh[cur] += kv[2]
            next
        }
        END {
            if (bad) exit 2
            status = 0
            measured = 0
            for (m in lf) {
                measured = 1
                lp = (lf[m] > 0) ? int(lh[m] * 100 / lf[m]) : 100
                bp = (brf[m] > 0) ? int(brh[m] * 100 / brf[m]) : 100
                row = ""
                if (m in tline) row = m
                else if (("*") in tline) row = "*"
                if (row == "") {
                    printf("coverage: %-12s lines %d%%  branches %d%%  (no threshold row)\n",
                           m, lp, bp)
                    printf("coverage: FAIL: module %s has no threshold row and no catch-all\n",
                           m) > "/dev/stderr"
                    status = 1
                    continue
                }
                printf("coverage: %-12s lines %d%% (floor %d%%)  branches %d%% (floor %d%%)\n",
                       m, lp, tline[row], bp, tbr[row])
                if (lp < tline[row] || bp < tbr[row]) {
                    printf("coverage: FAIL: module %s below floor " \
                           "(lines %d%% vs %d%%, branches %d%% vs %d%%)\n",
                           m, lp, tline[row], bp, tbr[row]) > "/dev/stderr"
                    status = 1
                }
            }
            for (m in tline) {
                if (m != "*" && !(m in lf)) {
                    printf("coverage: FAIL: threshold row for module %s " \
                           "but no measured files\n", m) > "/dev/stderr"
                    status = 1
                }
            }
            if (!measured) {
                printf("coverage: FAIL: no first-party (src/) coverage data in %s\n",
                       info) > "/dev/stderr"
                status = 1
            }
            exit status
        }
    ' "$et_tsv" "$et_info"
    return $?
}

# ---------------------------------------------------------------------------
# Mode dispatch: enforcement-only mode (no lcov/gcov needed).
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--check-thresholds" ]; then
    if [ $# -ne 3 ]; then
        echo "usage: coverage.sh --check-thresholds <info-file> <thresholds.tsv>" >&2
        exit 2
    fi
    enforce_thresholds "$2" "$3"
    exit $?
fi
if [ "${1:-}" = "--check-total" ]; then
    if [ $# -ne 4 ]; then
        echo "usage: coverage.sh --check-total <info-file> <line-pct> <branch-pct>" >&2
        exit 2
    fi
    check_total "$2" "$3" "$4"
    exit $?
fi

BUILD_ROOT="${1:?usage: coverage.sh <build-root> <out-dir> --sources <list> [--enforce]}"
OUT_DIR="${2:?usage: coverage.sh <build-root> <out-dir> --sources <list> [--enforce]}"
shift 2
ENFORCE=0
SOURCE_LIST=""
while [ $# -gt 0 ]; do
    case "$1" in
        --enforce)
            ENFORCE=1
            shift
            ;;
        --sources)
            [ $# -ge 2 ] || {
                echo "coverage: --sources needs a path" >&2
                exit 2
            }
            SOURCE_LIST="$2"
            shift 2
            ;;
        *)
            echo "coverage: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

[ -n "$SOURCE_LIST" ] && [ -f "$SOURCE_LIST" ] || {
    echo "coverage: product source list is required" >&2
    exit 2
}

SOURCE_PATTERNS=$(awk -v prefix="$PROJECT_ROOT/src/" '
    /[[:space:]]/ || $0 !~ /\.c$/ || index($0, prefix) != 1 {
        printf("coverage: invalid product source path: %s\n", $0) > "/dev/stderr"
        bad = 1
        next
    }
    seen[$0]++ {
        printf("coverage: duplicate product source path: %s\n", $0) > "/dev/stderr"
        bad = 1
        next
    }
    { print }
    END {
        if (length(seen) == 0) {
            print "coverage: product source list is empty" > "/dev/stderr"
            bad = 1
        }
        exit bad
    }
' "$SOURCE_LIST") || exit 2
for source in $SOURCE_PATTERNS; do
    [ -f "$source" ] || {
        echo "coverage: product source is missing: $source" >&2
        exit 2
    }
done

# Fail closed when enforcing without a thresholds file.
if [ "$ENFORCE" = "1" ] && [ ! -f "$THRESHOLD_FILE" ]; then
    echo "coverage: thresholds file missing: $THRESHOLD_FILE" >&2
    echo "coverage: --enforce fails closed without it" \
         "(seed tools/coverage-thresholds.tsv from a measured run)" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

if ! command -v lcov >/dev/null 2>&1; then
    echo "coverage: lcov not found on PATH; run inside 'nix develop'." >&2
    exit 2
fi

# Prefer llvm-cov (matches clang-built artifacts) via our shim that adds
# the `gcov` subcommand lcov expects; fall back to plain gcov.
GCOV_TOOL_PATH=""
if command -v llvm-cov >/dev/null 2>&1; then
    GCOV_TOOL_PATH="$SCRIPT_DIR/llvm-gcov.sh"
fi

# lcov 2.x is strict about gcno/gcda format versions. Prefer llvm-cov for
# Clang data; keep the existing version/mismatch tolerance for the fallback
# capture path. Any consistency warning is a gate failure, including a new
# warning that lcov would otherwise tolerate below its default message limit.
run_lcov() {
    if [ -n "$GCOV_TOOL_PATH" ]; then
        lcov --rc branch_coverage=1 \
            --rc lcov_excl_br_line=LCOV_EXCL_BR_LINE \
            --rc lcov_excl_line=LCOV_EXCL_LINE \
            --ignore-errors version,mismatch \
            --expect-message-count 'inconsistent:%C==0' \
            --gcov-tool "$GCOV_TOOL_PATH" "$@"
    else
        lcov --rc branch_coverage=1 \
            --rc lcov_excl_br_line=LCOV_EXCL_BR_LINE \
            --rc lcov_excl_line=LCOV_EXCL_LINE \
            --ignore-errors version,mismatch \
            --expect-message-count 'inconsistent:%C==0' "$@"
    fi
}

echo "==> Capturing zero-hit coverage from $BUILD_ROOT"
run_lcov --capture --initial \
    --base-directory "$PROJECT_ROOT" \
    --directory "$BUILD_ROOT" --output-file "$OUT_DIR/farsee.initial.info" \
    > "$OUT_DIR/capture.log" 2>&1 || {
    echo "coverage: lcov initial capture failed; see $OUT_DIR/capture.log" >&2
    tail -20 "$OUT_DIR/capture.log" >&2
    exit 1
}

echo "==> Capturing exercised coverage"
run_lcov --capture \
    --base-directory "$PROJECT_ROOT" \
    --directory "$BUILD_ROOT" --output-file "$OUT_DIR/farsee.runtime.info" \
    >> "$OUT_DIR/capture.log" 2>&1 || {
    echo "coverage: lcov runtime capture failed; see $OUT_DIR/capture.log" >&2
    tail -20 "$OUT_DIR/capture.log" >&2
    exit 1
}

echo "==> Merging zero-hit and exercised coverage"
run_lcov --add-tracefile "$OUT_DIR/farsee.initial.info" \
    --add-tracefile "$OUT_DIR/farsee.runtime.info" \
    --output-file "$OUT_DIR/farsee.info" \
    >> "$OUT_DIR/capture.log" 2>&1 || {
    echo "coverage: lcov merge failed; see $OUT_DIR/capture.log" >&2
    tail -20 "$OUT_DIR/capture.log" >&2
    exit 1
}

echo "==> Filtering to the closed product source list"
run_lcov --extract "$OUT_DIR/farsee.info" $SOURCE_PATTERNS \
    --output-file "$OUT_DIR/farsee.filtered.info" \
    >> "$OUT_DIR/capture.log" 2>&1 || {
    echo "coverage: first-party extraction failed; see $OUT_DIR/capture.log" >&2
    tail -20 "$OUT_DIR/capture.log" >&2
    exit 1
}

awk '
    FNR == NR {
        expected[$0] = 1
        next
    }
    /^SF:/ {
        path = substr($0, 4)
        measured[path]++
        if (!(path in expected)) {
            printf("coverage: unexpected source record: %s\n", path) > "/dev/stderr"
            bad = 1
        }
        if (measured[path] > 1) {
            printf("coverage: duplicate source record: %s\n", path) > "/dev/stderr"
            bad = 1
        }
    }
    END {
        for (path in expected) {
            if (!(path in measured)) {
                printf("coverage: missing product source record: %s\n", path) > "/dev/stderr"
                bad = 1
            }
        }
        exit bad
    }
' "$SOURCE_LIST" "$OUT_DIR/farsee.filtered.info" || {
    echo "coverage: filtered source inventory does not match the product" >&2
    exit 1
}

echo "==> HTML report"
genhtml --branch-coverage \
        --expect-message-count 'inconsistent:%C==0' \
        -o "$OUT_DIR/html" "$OUT_DIR/farsee.filtered.info" \
        >> "$OUT_DIR/capture.log" 2>&1 || {
    echo "coverage: HTML generation failed; see $OUT_DIR/capture.log" >&2
    tail -20 "$OUT_DIR/capture.log" >&2
    exit 1
}

echo "==> Coverage summary"
if ! run_lcov --summary "$OUT_DIR/farsee.filtered.info" \
        > "$OUT_DIR/summary.txt" 2>&1; then
    echo "coverage: summary failed; see $OUT_DIR/summary.txt" >&2
    tail -20 "$OUT_DIR/summary.txt" >&2
    exit 1
fi
cat "$OUT_DIR/summary.txt"

echo "coverage report: $OUT_DIR/html/index.html"

# Threshold enforcement: per-module ratchet from
# tools/coverage-thresholds.tsv; fails closed on any miss.
if [ "$ENFORCE" = "1" ]; then
    echo "coverage: enforcing thresholds from $THRESHOLD_FILE"
    enforce_thresholds "$OUT_DIR/farsee.filtered.info" "$THRESHOLD_FILE" || exit 1
    echo "coverage: all module thresholds met"
fi

exit 0
