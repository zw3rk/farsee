#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run a bounded Apple RFB interoperability check against authorized hardware.
# This verifies authentication, protected-record activation, and stable session
# entry. Visual fidelity and input checks remain manual parts of G11/G26.
#
# Usage:
#   FARSEE_USER=account FARSEE_PASSWORD_FD=3 \
#     tools/macos_acceptance.sh mac.example 3<password-file
#
# The runner does not print the host, account, password, child output, or file
# descriptor. It emits a small result record that is safe to redirect into an
# evidence file after local review.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FARSEE_BIN="${FARSEE_BIN:-$ROOT/build/release/bin/farsee}"
HOST="${1:-}"
PORT="${FARSEE_PORT:-5900}"
USER_NAME="${FARSEE_USER:-}"
PASSWORD_FD="${FARSEE_PASSWORD_FD:-}"
SECURITY="${FARSEE_APPLE_SECURITY:-36}"
ATTACH="${FARSEE_APPLE_ATTACH:-share}"
DURATION="${FARSEE_ACCEPTANCE_DURATION:-15}"
CONNECT_TIMEOUT="${FARSEE_CONNECT_TIMEOUT:-10000}"

needs_hardware() {
    echo "macos_acceptance: NEEDS_HARDWARE" >&2
    echo "Provide an authorized host, FARSEE_USER, and FARSEE_PASSWORD_FD." >&2
    echo "The password descriptor must contain the macOS account password." >&2
    exit 3
}

if [ -z "$HOST" ]; then
    needs_hardware
fi
if [ ! -x "$FARSEE_BIN" ]; then
    echo "macos_acceptance: FARSEE_BIN is not executable" >&2
    echo "Build it with: nix develop --command make release" >&2
    exit 2
fi
if [ -z "$USER_NAME" ]; then
    echo "macos_acceptance: FARSEE_USER is required" >&2
    exit 2
fi
case "$PASSWORD_FD" in
    ''|*[!0-9]*)
        echo "macos_acceptance: FARSEE_PASSWORD_FD must be a non-negative integer" >&2
        exit 2
        ;;
esac
case "$PORT" in
    ''|*[!0-9]*)
        echo "macos_acceptance: FARSEE_PORT must be an integer" >&2
        exit 2
        ;;
esac
case "$SECURITY" in
    auto|36) ;;
    *)
        echo "macos_acceptance: FARSEE_APPLE_SECURITY must be auto or 36" >&2
        exit 2
        ;;
esac
case "$ATTACH" in
    share|login) ;;
    *)
        echo "macos_acceptance: FARSEE_APPLE_ATTACH must be share or login" >&2
        exit 2
        ;;
esac
case "$DURATION" in
    ''|*[!0-9]*)
        echo "macos_acceptance: FARSEE_ACCEPTANCE_DURATION must be 1..300" >&2
        exit 2
        ;;
esac
if [ "$DURATION" -lt 1 ] || [ "$DURATION" -gt 300 ]; then
    echo "macos_acceptance: FARSEE_ACCEPTANCE_DURATION must be 1..300" >&2
    exit 2
fi
case "$CONNECT_TIMEOUT" in
    ''|*[!0-9]*)
        echo "macos_acceptance: FARSEE_CONNECT_TIMEOUT must be an integer" >&2
        exit 2
        ;;
esac
if ! command -v timeout >/dev/null 2>&1; then
    echo "macos_acceptance: timeout is unavailable; enter the Nix shell" >&2
    exit 2
fi

LOG="$(mktemp "${TMPDIR:-/tmp}/farsee-macos-acceptance.XXXXXX")" || exit 2
cleanup() {
    rm -f -- "$LOG"
}
trap cleanup EXIT HUP INT TERM

set +e
timeout --signal=INT --kill-after=5 "${DURATION}s" \
    "$FARSEE_BIN" "vnc://$HOST:$PORT" \
    --auth apple \
    --user "$USER_NAME" \
    --password-fd "$PASSWORD_FD" \
    --apple-security="$SECURITY" \
    --apple-attach="$ATTACH" \
    --apple-postauth=records \
    --presenter null \
    --view-only \
    --connect-timeout "$CONNECT_TIMEOUT" \
    >"$LOG" 2>&1
status=$?
set -e

record_active=0
if grep -Fq "Apple AES-CBC record layer active" "$LOG" ||
        grep -Fxq "farsee: Apple AES-CBC records active" "$LOG"; then
    record_active=1
fi

printf 'GATE: macOS Apple RFB interoperability\n'
printf 'APPLE_SECURITY: %s\n' "$SECURITY"
printf 'APPLE_ATTACH: %s\n' "$ATTACH"
printf 'POSTAUTH: records\n'
printf 'PRESENTER: null\n'
printf 'VIEW_ONLY: yes\n'

if [ "$record_active" -eq 1 ]; then
    record_status=active
else
    record_status=inactive
fi

case "$status" in
    0|124|130) ;;
    *)
        printf 'RECORD_LAYER: %s\n' "$record_status"
        printf 'RESULT: FAIL\n'
        echo "macos_acceptance: client failed before the bounded run completed (exit $status)" >&2
        exit 1
        ;;
esac

if [ "$record_active" -ne 1 ]; then
    printf 'RECORD_LAYER: inactive\n'
    printf 'RESULT: FAIL\n'
    echo "macos_acceptance: protected record layer did not become active" >&2
    exit 1
fi

printf 'RECORD_LAYER: active\n'
printf 'RESULT: PASS\n'
printf 'MANUAL_FIDELITY: pending\n'
printf 'MANUAL_INPUT: pending\n'
