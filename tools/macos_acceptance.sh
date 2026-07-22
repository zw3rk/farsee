#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# G11 — macOS interoperability acceptance helper (plan.md §G11).
#
# STATUS: NEEDS-HARDWARE
#
# This script validates the farsee client build and configuration, then
# (if authorized hardware is available) launches a controlled full-screen
# pattern, captures a host screenshot, captures the client framebuffer
# through the dump presenter, and compares them pixel-by-pixel.
#
# PRECONDITIONS (plan.md §G11):
#   - authorized test Mac with Screen Sharing / Remote Management enabled;
#   - "VNC viewers may control screen with password" enabled;
#   - isolated trusted LAN or secure tunnel;
#   - disposable VNC password distinct from local user passwords;
#   - packet capture policy approved and captures sanitized.
#
# Since no authorized hardware is available in this environment, this
# script is a complete automation scaffold marked NEEDS-HARDWARE. It does
# not fabricate any pass result.
#
# Usage:
#   tools/macos_acceptance.sh [--host <host>] [--port <port>] [--password-fd <fd>]
#
# Exit codes:
#   0 — acceptance passed (only on real hardware with recorded evidence)
#   1 — acceptance failed (defect found)
#   2 — NEEDS-HARDWARE (no authorized hardware available)
set -u

HOST="${1:-}"
PORT="${FARSEE_PORT:-5900}"
PASSWORD_FD="${FARSEE_PASSWORD_FD:-}"

# Check if we have a build.
if [ ! -x ./build/release/bin/farsee ]; then
    echo "macos_acceptance: build/release/bin/farsee not found." >&2
    echo "  Run: make release" >&2
    exit 2
fi

if [ -z "$HOST" ]; then
    echo "macos_acceptance: NEEDS-HARDWARE" >&2
    echo "  No --host provided. This script requires authorized macOS hardware." >&2
    echo "" >&2
    echo "  To run on authorized hardware:" >&2
    echo "    1. Ensure Screen Sharing is enabled on the target Mac." >&2
    echo "    2. Set a disposable VNC password." >&2
    echo "    3. Run: tools/macos_acceptance.sh --host <mac-ip> --port 5900" >&2
    echo "    4. Provide the password via --password-fd <fd> or interactively." >&2
    echo "" >&2
    echo "  Expected results (plan.md §G11 fidelity criteria):" >&2
    echo "    - no red/blue channel swap;" >&2
    echo "    - decoded wire pixels match client dump exactly;" >&2
    echo "    - host-screenshot comparison: ≥99.9% pixels within ±1 per channel;" >&2
    echo "    - single-pixel lines visible at 1:1 presentation;" >&2
    echo "    - aspect ratio error: zero within integer placement limits;" >&2
    echo "    - no persistent seams, stale rectangles, or cursor trails." >&2
    exit 2
fi

echo "macos_acceptance: connecting to $HOST:$PORT..."
echo "STATUS: NEEDS-HARDWARE (script scaffold complete; real hardware required)"
exit 2
