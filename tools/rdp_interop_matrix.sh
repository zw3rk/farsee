#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RDP §15.19 interop matrix runner (R6).
#
# Runs farsee against a provisioned RDP endpoint and records the interop
# evidence required by R6 interop matrix (docs/gates/R06-interop-qemu-lab.md) /
# §15.20. With an authorized provisioned Windows host (RDP+TLS+NLA) and/or an
# xrdp host with test credentials, this script executes the matrix and writes
# the results.
#
# Usage:
#   RDP_WIN_CA_HOST=user@windows-ca.example \
#   RDP_WIN_TOFU_HOST=user@windows-selfsigned.example RDP_WIN_PW=... \
#   RDP_XRDP_HOST=user@xrdp.example RDP_XRDP_PW=... \
#   nix develop --command make rdp-interop
# After the TOFU endpoint certificate is rotated, preserve HOME and run:
#   RDP_INTEROP_PHASE=changed-cert RDP_WIN_TOFU_HOST=... RDP_WIN_PW=... \
#   nix develop --command make rdp-interop RDP_INTEROP_PHASE=changed-cert
#
# Credentials are read from the ENVIRONMENT (never CLI args / logs), per
# §7.3 / §10.2. The script never echoes secrets; it records only the matrix
# outcomes (pass/fail + sanitized diagnostics).
#
# PREREQUISITE: an authorized endpoint must be provisioned (operator action).
# See docs/gates/R06-interop-qemu-lab.md for why this is blocked in
# environments without one. This script fails fast and honestly until then.

set -u
OUT="${1:-docs/gates/interop-evidence}"
PYTHON="${PYTHON:-python3}"
mkdir -p "$OUT"
matrix_failed=0
cases_run=0

# farsee must be built with RDP enabled.
FARSEE_BIN="${FARSEE_BIN:-build/dev/bin/farsee}"
if [ ! -x "$FARSEE_BIN" ]; then
  echo "FAIL: $FARSEE_BIN not found. Build with: nix develop --command make FARSEE_WITH_RDP=1 build" >&2
  exit 2
fi

# §15.19 matrix cases. Each is a label + an farsee invocation; the script
# captures exit status + sanitized output (secrets redacted) to $OUT.
record() {
  local label="$1"; shift
  local expected_rc="$1"; shift
  local f="$OUT/${label}.txt"
  cases_run=$((cases_run + 1))
  echo "=== $label ===" | tee "$f"
  "$@" >>"$f" 2>&1
  local rc=$?
  if [ "$rc" -eq "$expected_rc" ]; then
    echo "RESULT: PASS" | tee -a "$f"
  else
    echo "RESULT: FAIL (exit $rc; expected $expected_rc)" | tee -a "$f"
    matrix_failed=1
  fi
  # Redact any credential that may have leaked into output (defense in depth).
  for var in RDP_WIN_PW RDP_XRDP_PW; do
    val="${!var:-}"
    if [ -n "$val" ]; then
      # Replace the exact credential bytes. Do not interpret regex or
      # replacement metacharacters from an operator-supplied password.
      redact_literal "$val" "$f" || {
        echo "FAIL: could not redact evidence file" >&2
        matrix_failed=1
      }
    fi
  done
  echo "---"
}

run_with_password() {
  local password="$1"; shift
  "$@" --password-fd 3 3< <(printf '%s' "$password")
}

redact_literal() {
  local value="$1"
  local path="$2"
  REDACT_VALUE="$value" "$PYTHON" - "$path" <<'PY'
import os
from pathlib import Path
import sys

path = Path(sys.argv[1])
secret = os.environ["REDACT_VALUE"]
content = path.read_text(encoding="utf-8", errors="replace")
path.write_text(content.replace(secret, "<REDACTED>"), encoding="utf-8")
PY
}

phase="${RDP_MATRIX_PHASE:-baseline}"
win_ca_host="${RDP_WIN_CA_HOST:-${RDP_WIN_HOST:-}}"
win_tofu_host="${RDP_WIN_TOFU_HOST:-}"
xrdp_host="${RDP_XRDP_HOST:-}"

if [ "$phase" != baseline ] && [ "$phase" != changed-cert ]; then
  echo "FAIL: RDP_MATRIX_PHASE must be baseline or changed-cert" >&2
  exit 2
fi

if [ -z "$win_ca_host" ] && [ -z "$win_tofu_host" ] && [ -z "$xrdp_host" ]; then
  cat >&2 <<EOF
NEEDS_HARDWARE: no RDP endpoint provisioned.
Set RDP_WIN_CA_HOST=user@windows-ca.example and/or
RDP_WIN_TOFU_HOST=user@windows-selfsigned.example (Windows, TLS+NLA), and/or
RDP_XRDP_HOST=user@xrdp.example (xrdp), with RDP_*_PW credentials in the
environment, then re-run. See docs/gates/R06-interop-qemu-lab.md.
EOF
  exit 3
fi

# --- Windows endpoint (two configurations expected for §15.19) -------------
if [ "$phase" = baseline ] && [ -n "$win_ca_host" ]; then
  # CA-valid certificate, correct credentials.
  record "win-ca-valid-correct-creds" 0 run_with_password \
    "${RDP_WIN_PW:-}" "$FARSEE_BIN" rdp://"$win_ca_host" \
    --presenter null --view-only
  # Incorrect credentials -> auth rejection, no weaker-method fallback.
  record "win-incorrect-creds-reject" 4 run_with_password \
    "wrong-password" "$FARSEE_BIN" rdp://"$win_ca_host" \
    --presenter null --view-only
  # Resize.
  record "win-resize" 0 run_with_password \
    "${RDP_WIN_PW:-}" "$FARSEE_BIN" rdp://"$win_ca_host" \
    --presenter null --view-only --desktop-w 1024 --desktop-h 768
  # Clipboard on / off.
  record "win-clipboard-on" 0 run_with_password \
    "${RDP_WIN_PW:-}" "$FARSEE_BIN" rdp://"$win_ca_host" \
    --presenter null --clipboard on
  record "win-clipboard-off" 0 run_with_password \
    "${RDP_WIN_PW:-}" "$FARSEE_BIN" rdp://"$win_ca_host" \
    --presenter null --clipboard off
fi

if [ "$phase" = baseline ] && [ -n "$win_tofu_host" ]; then
  # Establish the pin. Preserve HOME for the post-rotation phase.
  record "win-selfsigned-first-use" 0 run_with_password \
    "${RDP_WIN_PW:-}" "$FARSEE_BIN" rdp://"$win_tofu_host" \
    --cert pin --presenter null --view-only
fi

if [ "$phase" = changed-cert ]; then
  if [ -z "$win_tofu_host" ]; then
    echo "FAIL: changed-cert phase needs RDP_WIN_TOFU_HOST" >&2
    exit 2
  fi
  # The operator must rotate the certificate after the baseline phase. The
  # same target string and HOME make this a real pin-mismatch check.
  record "win-changed-cert-reject" 4 run_with_password \
    "${RDP_WIN_PW:-}" "$FARSEE_BIN" rdp://"$win_tofu_host" \
    --cert pin --presenter null --view-only
fi

# --- xrdp endpoint ---------------------------------------------------------
if [ "$phase" = baseline ] && [ -n "$xrdp_host" ]; then
  record "xrdp-correct-creds" 0 run_with_password \
    "${RDP_XRDP_PW:-}" "$FARSEE_BIN" rdp://"$xrdp_host" \
    --presenter null --view-only
  record "xrdp-incorrect-creds-reject" 4 run_with_password \
    "wrong-password" "$FARSEE_BIN" rdp://"$xrdp_host" \
    --presenter null --view-only
  record "xrdp-resize" 0 run_with_password \
    "${RDP_XRDP_PW:-}" "$FARSEE_BIN" rdp://"$xrdp_host" \
    --presenter null --view-only --desktop-w 1024 --desktop-h 768
fi

# --- Summary ---------------------------------------------------------------
echo ""
echo "Interop matrix evidence written to $OUT/"
echo "Record PASS_INTEROP in docs/gates/R06-interop-qemu-lab.md only after"
echo "every required case passes against independent endpoints."
if [ "$cases_run" -eq 0 ]; then
  echo "FAIL: no cases apply to phase $phase" >&2
  exit 2
fi
exit "$matrix_failed"
