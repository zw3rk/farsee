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
HOST="${FARSEE_ACCEPTANCE_HOST:-${1:-}}"
PORT="${FARSEE_PORT:-5900}"
USER_NAME="${FARSEE_USER:-}"
PASSWORD_FD="${FARSEE_PASSWORD_FD:-}"
SECURITY="${FARSEE_APPLE_SECURITY:-36}"
ATTACH="${FARSEE_APPLE_ATTACH:-share}"
DURATION="${FARSEE_ACCEPTANCE_DURATION:-15}"
CONNECT_TIMEOUT="${FARSEE_CONNECT_TIMEOUT:-10000}"
EXPECTED_VERSION="${FARSEE_ACCEPTANCE_EXPECTED_VERSION:-}"
EXPECTED_REVISION="${FARSEE_ACCEPTANCE_EXPECTED_REVISION:-}"
TEST_ONLY="${FARSEE_ACCEPTANCE_TEST_ONLY:-no}"

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
case "$TEST_ONLY" in
    yes|no) ;;
    *)
        echo "macos_acceptance: FARSEE_ACCEPTANCE_TEST_ONLY must be yes or no" >&2
        exit 2
        ;;
esac
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
if [ "$TEST_ONLY" = yes ]; then
    if [ -z "$EXPECTED_VERSION" ] || [ -z "$EXPECTED_REVISION" ]; then
        echo "macos_acceptance: test-only expected version and revision are required" >&2
        exit 2
    fi
else
    EXPECTED_VERSION="$(
        sed -n 's/^VERSION[[:space:]]*?=[[:space:]]*//p' "$ROOT/Makefile" |
            sed -n '1p'
    )"
    EXPECTED_REVISION="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null)"
    if [ -z "$EXPECTED_VERSION" ] ||
            [[ ! "$EXPECTED_REVISION" =~ ^[0-9a-f]{40}$ ]]; then
        echo "macos_acceptance: repository candidate boundary is unavailable" >&2
        exit 2
    fi
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/farsee-macos-acceptance.XXXXXX")" || exit 2
LOG="$WORK_DIR/client.log"
cleanup() {
    rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

version_line="$("$FARSEE_BIN" --version 2>/dev/null | sed -n '1p')"
if [[ ! "$version_line" =~ ^farsee[[:space:]]+([^[:space:]]+)[[:space:]]+git=([^[:space:]]+)[[:space:]]+built= ]]; then
    echo "macos_acceptance: candidate has no valid version identity" >&2
    exit 2
fi
CANDIDATE_VERSION="${BASH_REMATCH[1]}"
CANDIDATE_REVISION="${BASH_REMATCH[2]}"
if [ "$CANDIDATE_VERSION" != "$EXPECTED_VERSION" ]; then
    echo "macos_acceptance: candidate version does not match the expected version" >&2
    exit 2
fi
if [ "$CANDIDATE_REVISION" != "$EXPECTED_REVISION" ]; then
    echo "macos_acceptance: candidate revision does not match the expected revision" >&2
    exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    echo "macos_acceptance: sha256sum is unavailable; enter the Nix shell" >&2
    exit 2
fi
CANDIDATE_SHA256="$(sha256sum "$FARSEE_BIN" | awk '{print $1}')"
if [[ ! "$CANDIDATE_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "macos_acceptance: failed to identify the candidate digest" >&2
    exit 2
fi

CODESIGN_STATUS=not-required
CODESIGN_SHA1=none
CODESIGN_IDENTIFIER=none
CODESIGN_TEAM_ID=none
CODESIGN_AUTHORITY=none
if [ "$TEST_ONLY" = no ]; then
    for command_name in codesign openssl python3; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "macos_acceptance: $command_name is required for signed-candidate verification" >&2
            exit 2
        fi
    done
    if ! codesign --verify --strict --verbose=2 "$FARSEE_BIN" >/dev/null 2>&1; then
        echo "macos_acceptance: candidate code signature is invalid" >&2
        exit 2
    fi
    signing_details="$(codesign -d --verbose=4 "$FARSEE_BIN" 2>&1)"
    CODESIGN_IDENTIFIER="$(printf '%s\n' "$signing_details" | sed -n 's/^Identifier=//p' | sed -n '1p')"
    CODESIGN_TEAM_ID="$(printf '%s\n' "$signing_details" | sed -n 's/^TeamIdentifier=//p' | sed -n '1p')"
    CODESIGN_AUTHORITY="$(printf '%s\n' "$signing_details" | sed -n 's/^Authority=//p' | sed -n '1p')"
    if [ -z "$CODESIGN_IDENTIFIER" ] || [ -z "$CODESIGN_TEAM_ID" ] ||
            [ -z "$CODESIGN_AUTHORITY" ]; then
        echo "macos_acceptance: candidate signature identity is incomplete" >&2
        exit 2
    fi
    if ! codesign -d --extract-certificates="$WORK_DIR/cert-" \
            "$FARSEE_BIN" >/dev/null 2>&1 || [ ! -f "$WORK_DIR/cert-0" ]; then
        echo "macos_acceptance: cannot extract the candidate signing certificate" >&2
        exit 2
    fi
    CODESIGN_SHA1="$(
        openssl x509 -inform DER -in "$WORK_DIR/cert-0" -noout \
            -fingerprint -sha1 2>/dev/null |
            sed -n 's/^[^=]*=//p' | tr -d ':' | tr '[:lower:]' '[:upper:]'
    )"
    EXPECTED_SIGNING_SHA1="$(
        python3 - "$ROOT/release/approval.json" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    approval = json.load(stream)["signing_identity_approval"]
evidence = approval.get("evidence") or ""
if approval.get("approved") is not True or not re.fullmatch(
        r"sha1:[0-9A-Fa-f]{40}", evidence):
    raise SystemExit(1)
print(evidence.removeprefix("sha1:").upper())
PY
    )" || {
        echo "macos_acceptance: approved signing identity is unavailable" >&2
        exit 2
    }
    if [ "$CODESIGN_SHA1" != "$EXPECTED_SIGNING_SHA1" ]; then
        echo "macos_acceptance: candidate signing identity is not approved" >&2
        exit 2
    fi
    CODESIGN_STATUS=verified
fi

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
printf 'CANDIDATE_VERSION: %s\n' "$CANDIDATE_VERSION"
printf 'CANDIDATE_REVISION: %s\n' "$CANDIDATE_REVISION"
printf 'CANDIDATE_SHA256: %s\n' "$CANDIDATE_SHA256"
printf 'CODESIGN: %s\n' "$CODESIGN_STATUS"
printf 'CODESIGN_SHA1: %s\n' "$CODESIGN_SHA1"
printf 'CODESIGN_IDENTIFIER: %s\n' "$CODESIGN_IDENTIFIER"
printf 'CODESIGN_TEAM_ID: %s\n' "$CODESIGN_TEAM_ID"
printf 'CODESIGN_AUTHORITY: %s\n' "$CODESIGN_AUTHORITY"
if [ "$TEST_ONLY" = yes ]; then
    printf 'EVIDENCE_CLASS: test-only\n'
else
    printf 'EVIDENCE_CLASS: release-candidate\n'
fi
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
if [ "$TEST_ONLY" = yes ]; then
    printf 'RESULT: TEST_ONLY_PASS\n'
else
    printf 'RESULT: PASS\n'
fi
printf 'MANUAL_FIDELITY: pending\n'
printf 'MANUAL_INPUT: pending\n'
