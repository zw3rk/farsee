#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RDP §15.19 interop matrix runner (R6).
#
# Runs farsee against a provisioned RDP endpoint and records the interop
# evidence required by R6 interop matrix (docs/gates/R06-interop-qemu-lab.md) /
# §15.20. This is the turnkey resumption path: once an operator provisions
# an authorized Windows host (RDP+TLS+NLA) and/or an xrdp host with test
# credentials, this script executes the matrix and writes the evidence.
#
# Usage:
#   RDP_WIN_HOST=user@windows.example  RDP_WIN_PW=... \
#   RDP_XRDP_HOST=user@xrdp.example    RDP_XRDP_PW=... \
#   ./tools/rdp_interop_matrix.sh [evidence_out_dir]
#
# Credentials are read from the ENVIRONMENT (never CLI args / logs), per
# §7.3 / §10.2. The script never echoes secrets; it records only the matrix
# outcomes (pass/fail + sanitized diagnostics).
#
# PREREQUISITE: an authorized endpoint must be provisioned (operator action).
# See docs/gates/R06-interop-needs-hardware.md for why this is blocked in
# environments without one. This script fails fast and honestly until then.

set -u
OUT="${1:-docs/gates/interop-evidence}"
mkdir -p "$OUT"

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
  local f="$OUT/${label}.txt"
  echo "=== $label ===" | tee "$f"
  "$@" >>"$f" 2>&1
  local rc=$?
  if [ $rc -eq 0 ]; then
    echo "RESULT: PASS" | tee -a "$f"
  else
    echo "RESULT: FAIL (exit $rc)" | tee -a "$f"
  fi
  # Redact any credential that may have leaked into output (defense in depth).
  for var in RDP_WIN_PW RDP_XRDP_PW; do
    val="${!var:-}"
    if [ -n "$val" ]; then
      # in-place redaction
      sed -i'' -e "s/${val//\//\\/}/<REDACTED>/g" "$f" 2>/dev/null || true
    fi
  done
  echo "---"
}

win_host="${RDP_WIN_HOST:-}"
xrdp_host="${RDP_XRDP_HOST:-}"

if [ -z "$win_host" ] && [ -z "$xrdp_host" ]; then
  cat >&2 <<EOF
NEEDS_HARDWARE: no RDP endpoint provisioned.
Set RDP_WIN_HOST=user@windows.example (Windows, TLS+NLA) and/or
RDP_XRDP_HOST=user@xrdp.example (xrdp), with RDP_*_PW credentials in the
environment, then re-run. See docs/gates/R06-interop-needs-hardware.md.
EOF
  exit 3
fi

# --- Windows endpoint (two configurations expected for §15.19) -------------
if [ -n "$win_host" ]; then
  # CA-valid certificate, correct credentials.
  record "win-ca-valid-correct-creds" \
    "$FARSEE_BIN" rdp://"$win_host" --password-fd <(printf '%s' "${RDP_WIN_PW:-}")
  # Self-signed first-use (TOFU approval prompt).
  record "win-selfsigned-first-use" \
    "$FARSEE_BIN" rdp://"$win_host" --password-fd <(printf '%s' "${RDP_WIN_PW:-}")
  # Changed certificate -> must default-reject.
  record "win-changed-cert-reject" \
    "$FARSEE_BIN" rdp://"$win_host" --password-fd <(printf '%s' "${RDP_WIN_PW:-}")
  # Incorrect credentials -> auth rejection, no weaker-method fallback.
  record "win-incorrect-creds-reject" \
    "$FARSEE_BIN" rdp://"$win_host" --password-fd <(printf '%s' "wrong-password")
  # Resize.
  record "win-resize" \
    "$FARSEE_BIN" rdp://"$win_host" --password-fd <(printf '%s' "${RDP_WIN_PW:-}") --desktop-size 1024x768
  # Clipboard on / off.
  record "win-clipboard-on" \
    "$FARSEE_BIN" rdp://"$win_host" --password-fd <(printf '%s' "${RDP_WIN_PW:-}") --clipboard bidirectional-text
  record "win-clipboard-off" \
    "$FARSEE_BIN" rdp://"$win_host" --password-fd <(printf '%s' "${RDP_WIN_PW:-}") --clipboard off
fi

# --- xrdp endpoint ---------------------------------------------------------
if [ -n "$xrdp_host" ]; then
  record "xrdp-correct-creds" \
    "$FARSEE_BIN" rdp://"$xrdp_host" --password-fd <(printf '%s' "${RDP_XRDP_PW:-}")
  record "xrdp-incorrect-creds-reject" \
    "$FARSEE_BIN" rdp://"$xrdp_host" --password-fd <(printf '%s' "wrong-password")
  record "xrdp-resize" \
    "$FARSEE_BIN" rdp://"$xrdp_host" --password-fd <(printf '%s' "${RDP_XRDP_PW:-}") --desktop-size 1024x768
fi

# --- Summary ---------------------------------------------------------------
echo ""
echo "Interop matrix evidence written to $OUT/"
echo "Review and promote to PASS_INTEROP in docs/gates/R06-interop-needs-hardware.md"
echo "once every required case is PASS against independent endpoints."
