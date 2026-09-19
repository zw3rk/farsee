#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Unit self-test for coverage threshold enforcement: tools/coverage.sh
# --check-thresholds must
#   - exit 1 when the thresholds file is missing (fail closed),
#   - exit 1 when any floor is unreachable for the measured data,
#   - exit 0 when every module measures at or above its floor.
# It also pins the fail-closed semantics for modules without a
# threshold row and for malformed rows.

set -u

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SCRIPT="$ROOT/tools/coverage.sh"

fail() {
    echo "not ok: $1" >&2
    exit 1
}

[ -f "$SCRIPT" ] || fail "tools/coverage.sh missing"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/coverage-enforce-selftest.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

# Minimal lcov .info: module "core" -> lines 1/2 = 50%, branches 1/2 = 50%.
info="$tmp/farsee.filtered.info"
cat > "$info" <<'EOF'
TN:
SF:/repo/src/core/a.c
DA:1,1
DA:2,0
LF:2
LH:1
BRDA:1,0,0,1
BRDA:1,0,1,0
BRF:2
BRH:1
end_of_record
EOF

check() {
    # check <tsv-path-or-missing> ; returns the script's exit status
    tsv="$1"
    if [ "$tsv" = "MISSING" ]; then
        "$SCRIPT" --check-thresholds "$info" "$tmp/does-not-exist.tsv" \
            > "$tmp/out.log" 2>&1
    else
        "$SCRIPT" --check-thresholds "$info" "$tsv" > "$tmp/out.log" 2>&1
    fi
}

# 1. Missing thresholds file -> exit 1 (fail closed).
check MISSING
[ $? -ne 0 ] || { cat "$tmp/out.log" >&2; fail "missing thresholds file must exit non-zero"; }

# 2. Unreachable floor -> exit 1.
printf '*\t100\t100\n' > "$tmp/unreachable.tsv"
check "$tmp/unreachable.tsv"
[ $? -ne 0 ] || { cat "$tmp/out.log" >&2; fail "unreachable floor must exit non-zero"; }

# 3. Measured exactly at the floor -> exit 0.
printf '# module\tmin_line_pct\tmin_branch_pct\n*\t50\t50\n' > "$tmp/at-floor.tsv"
check "$tmp/at-floor.tsv"
[ $? -eq 0 ] || { cat "$tmp/out.log" >&2; fail "measured-at-floor must pass"; }

# 4. Measured above the floor -> exit 0.
printf '*\t49\t40\n' > "$tmp/above.tsv"
check "$tmp/above.tsv"
[ $? -eq 0 ] || { cat "$tmp/out.log" >&2; fail "measured-above-floor must pass"; }

# 5. Exact module row applies (and beats a stricter catch-all).
printf 'core\t50\t50\n*\t100\t100\n' > "$tmp/module-row.tsv"
check "$tmp/module-row.tsv"
[ $? -eq 0 ] || { cat "$tmp/out.log" >&2; fail "exact module row must take precedence over the catch-all"; }

# 6. A module with NO matching row and no catch-all -> exit 1.
printf 'other\t0\t0\n' > "$tmp/no-match.tsv"
check "$tmp/no-match.tsv"
[ $? -ne 0 ] || { cat "$tmp/out.log" >&2; fail "module without threshold row must fail (no catch-all)"; }

# 7. Malformed row -> exit non-zero.
printf 'core\t50\n' > "$tmp/malformed.tsv"
check "$tmp/malformed.tsv"
[ $? -ne 0 ] || { cat "$tmp/out.log" >&2; fail "malformed threshold row must fail"; }

# 8. Row naming a module with no measured files -> exit 1 (silent
#    module loss guard).
printf 'core\t50\t50\nghost\t0\t0\n' > "$tmp/ghost.tsv"
check "$tmp/ghost.tsv"
[ $? -ne 0 ] || { cat "$tmp/out.log" >&2; fail "threshold row without measured files must fail"; }

# 9. Missing info file -> exit 1.
if "$SCRIPT" --check-thresholds "$tmp/no-such.info" "$tmp/at-floor.tsv" \
        > "$tmp/out.log" 2>&1; then
    cat "$tmp/out.log" >&2
    fail "missing info file must exit non-zero"
fi

# 10. Release-wide aggregate thresholds are separate from module ratchets.
if "$SCRIPT" --check-total "$info" 85 80 > "$tmp/out.log" 2>&1; then
    cat "$tmp/out.log" >&2
    fail "50/50 aggregate must fail the 85/80 release policy"
fi
if ! "$SCRIPT" --check-total "$info" 50 50 > "$tmp/out.log" 2>&1; then
    cat "$tmp/out.log" >&2
    fail "aggregate exactly at 50/50 must pass"
fi

# 11. Capture resolves compiler-recorded relative source paths from the
# repository root. A fake lcov records one argument per line and emits the
# minimal files needed for the report path to complete.
fake_bin="$tmp/bin"
mkdir -p "$fake_bin" "$tmp/build-root"
cat > "$fake_bin/lcov" <<'EOF'
#!/bin/sh
set -eu
{
    printf 'LCOV_BEGIN\n'
    printf '%s\n' "$@"
    printf 'LCOV_END\n'
} >> "$COVERAGE_TOOL_ARGS"
mode=
input=
output=
previous=
for argument do
    case "$previous" in
        input) input="$argument" ;;
        output) output="$argument" ;;
    esac
    previous=
    case "$argument" in
        --capture) mode=capture ;;
        --extract) mode=extract; previous=input ;;
        --add-tracefile) mode=add; previous=input ;;
        --output-file) previous=output ;;
        --summary) mode=summary ;;
    esac
done
case "$mode" in
    capture)
        printf 'TN:\nSF:%s\nDA:1,1\nLF:1\nLH:1\nend_of_record\n' \
            "$COVERAGE_FAKE_SOURCE" \
            > "$output"
        ;;
    extract)
        [ "${COVERAGE_LCOV_FAIL_EXTRACT:-0}" -eq 0 ] || exit 1
        cp "$input" "$output"
        ;;
    add) cp "$input" "$output" ;;
    summary) [ "${COVERAGE_LCOV_FAIL_SUMMARY:-0}" -eq 0 ] || exit 1 ;;
    *) exit 2 ;;
esac
EOF
cat > "$fake_bin/genhtml" <<'EOF'
#!/bin/sh
{
    printf 'GENHTML_BEGIN\n'
    printf '%s\n' "$@"
    printf 'GENHTML_END\n'
} >> "$COVERAGE_TOOL_ARGS"
[ "${COVERAGE_GENHTML_FAIL:-0}" -eq 0 ]
EOF
chmod +x "$fake_bin/lcov" "$fake_bin/genhtml"
capture_args="$tmp/tool-args.log"
source_list="$tmp/product-sources.txt"
printf '%s\n' "$ROOT/src/core/allocator.c" > "$source_list"
if ! COVERAGE_FAKE_SOURCE="$ROOT/src/core/allocator.c" \
        COVERAGE_TOOL_ARGS="$capture_args" PATH="$fake_bin:$PATH" \
        "$SCRIPT" "$tmp/build-root" "$tmp/report" \
        --sources "$source_list" \
        > "$tmp/out.log" 2>&1; then
    cat "$tmp/out.log" >&2
    fail "mock coverage capture must complete"
fi
if ! awk -v root="$ROOT" '
    $0 == "--base-directory" { getline; if ($0 == root) found = 1 }
    END { exit(found ? 0 : 1) }
' "$capture_args"; then
    cat "$capture_args" >&2
    fail "capture must resolve relative sources from the repository root"
fi
if ! awk '
    /^(LCOV|GENHTML)_BEGIN$/ {
        if (active) bad = 1
        active = 1
        tool = substr($0, 1, index($0, "_") - 1)
        consistency = branch = compat = unsafe = 0
        next
    }
    /^(LCOV|GENHTML)_END$/ {
        if (!active) bad = 1
        if (consistency != 1 || unsafe != 0) bad = 1
        if (tool == "LCOV" && (branch != 1 || compat != 1)) bad = 1
        calls[tool]++
        active = 0
        next
    }
    active && $0 == "inconsistent:%C==0" { consistency++ }
    active && $0 == "branch_coverage=1" { branch++ }
    active && $0 == "version,mismatch" { compat++ }
    active && $0 == "version,mismatch,inconsistent" { unsafe++ }
    END {
        if (active || calls["LCOV"] != 5 || calls["GENHTML"] != 1) bad = 1
        exit bad
    }
' "$capture_args"; then
    cat "$capture_args" >&2
    fail "every lcov/report phase must reject consistency warnings"
fi
if ! grep -Fqx 'lcov_excl_br_line=LCOV_EXCL_BR_LINE' "$capture_args"; then
    cat "$capture_args" >&2
    fail "capture must honor source branch-exclusion markers"
fi
if ! grep -Fqx -- '--initial' "$capture_args"; then
    cat "$capture_args" >&2
    fail "capture must include zero-hit product objects"
fi

# 12. A failed first-party extraction must fail closed. Copying the raw report
# would include tests and third-party headers in the release percentage.
rm -rf "$tmp/report"
: > "$capture_args"
if COVERAGE_LCOV_FAIL_EXTRACT=1 \
        COVERAGE_FAKE_SOURCE="$ROOT/src/core/allocator.c" \
        COVERAGE_TOOL_ARGS="$capture_args" PATH="$fake_bin:$PATH" \
        "$SCRIPT" "$tmp/build-root" "$tmp/report" \
        --sources "$source_list" \
        > "$tmp/out.log" 2>&1; then
    cat "$tmp/out.log" >&2
    fail "failed first-party extraction must fail the coverage report"
fi

# 13. The filtered report must match the closed product source list exactly.
# A scaffold or unknown source record cannot enter the release metric.
rm -rf "$tmp/report"
: > "$capture_args"
if COVERAGE_FAKE_SOURCE="$ROOT/src/core/buffer.c" \
        COVERAGE_TOOL_ARGS="$capture_args" PATH="$fake_bin:$PATH" \
        "$SCRIPT" "$tmp/build-root" "$tmp/report" \
        --sources "$source_list" \
        > "$tmp/out.log" 2>&1; then
    cat "$tmp/out.log" >&2
    fail "coverage report with an unknown product source must fail"
fi

# 14. Report rendering is part of the coverage artifact and fails closed.
rm -rf "$tmp/report"
: > "$capture_args"
if COVERAGE_GENHTML_FAIL=1 \
        COVERAGE_FAKE_SOURCE="$ROOT/src/core/allocator.c" \
        COVERAGE_TOOL_ARGS="$capture_args" PATH="$fake_bin:$PATH" \
        "$SCRIPT" "$tmp/build-root" "$tmp/report" \
        --sources "$source_list" \
        > "$tmp/out.log" 2>&1; then
    cat "$tmp/out.log" >&2
    fail "failed HTML generation must fail the coverage report"
fi

# 15. A failed summary cannot be hidden behind a successful renderer.
rm -rf "$tmp/report"
: > "$capture_args"
if COVERAGE_LCOV_FAIL_SUMMARY=1 \
        COVERAGE_FAKE_SOURCE="$ROOT/src/core/allocator.c" \
        COVERAGE_TOOL_ARGS="$capture_args" PATH="$fake_bin:$PATH" \
        "$SCRIPT" "$tmp/build-root" "$tmp/report" \
        --sources "$source_list" \
        > "$tmp/out.log" 2>&1; then
    cat "$tmp/out.log" >&2
    fail "failed summary must fail the coverage report"
fi

# 16. Build and output paths are data, even when they contain shell syntax.
weird_build="$tmp/build root;not-a-command"
weird_report="$tmp/report root;not-a-command"
mkdir -p "$weird_build"
rm -rf "$weird_report"
: > "$capture_args"
if ! COVERAGE_FAKE_SOURCE="$ROOT/src/core/allocator.c" \
        COVERAGE_TOOL_ARGS="$capture_args" PATH="$fake_bin:$PATH" \
        "$SCRIPT" "$weird_build" "$weird_report" \
        --sources "$source_list" \
        > "$tmp/out.log" 2>&1; then
    cat "$tmp/out.log" >&2
    fail "coverage paths with spaces and shell syntax must stay literal"
fi
[ -f "$weird_report/farsee.filtered.info" ] ||
    fail "literal output path must contain the filtered report"

echo "ok: coverage threshold enforcement selftest"
