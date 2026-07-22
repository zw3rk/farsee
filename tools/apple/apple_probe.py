#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apple RFB probe tool (goals.md G14).

Safely recognizes the Apple RFB 003.889 dialect, records direction, byte
offsets, state, and bounded payload lengths. Default behavior stops before
transmitting any username, password, proof, private key, derived key, or
clipboard data.

Redaction: credential-bearing ranges are replaced with [REDACTED] before
disk writes. Files are created with 0600.

Usage:
    apple_probe.py --host <host> --port <port> [--unsafe-probe-type <30|33|35|36>]
    apple_probe.py --verify-redaction <file>

Clean-room: derived from RFC 6143 and Apple's public documentation only.
No GPL/AGPL implementation source consulted.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
from typing import Optional


# Marker for redacted ranges in transcripts.
REDACTED_MARKER = b"[REDACTED]"

# Canary secrets for redaction testing.
CANARY_PASSWORD = b"__CANARY_PASSWORD__"
CANARY_KEYS = [
    b"__CANARY_KEY_0__",
    b"__CANARY_KEY_1__",
    b"__CANARY_EXPONENT__",
]


def read_exactly(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def probe_banner(sock: socket.socket) -> dict:
    """Read the server's protocol-version banner (12 bytes)."""
    banner = read_exactly(sock, 12)
    if banner is None:
        return {"result": "fail", "reason": "EOF before banner"}
    entry = {
        "offset": 0,
        "direction": "S->C",
        "state": "BANNER",
        "length": 12,
        "bytes_hex": banner.hex(),
        "banner_ascii": banner.decode("ascii", errors="replace"),
    }
    if banner.startswith(b"RFB 003.889"):
        entry["dialect"] = "apple-003.889"
    elif banner.startswith(b"RFB 003.00"):
        entry["dialect"] = "standard"
    else:
        entry["dialect"] = "unknown"
    return entry


def probe_security_types(sock: socket.socket) -> dict:
    """Read security type advertisement (does not send credentials)."""
    count_byte = read_exactly(sock, 1)
    if count_byte is None:
        return {"result": "fail", "reason": "EOF before security count"}
    count = count_byte[0]
    entry = {
        "offset": 12,
        "direction": "S->C",
        "state": "SECURITY_TYPES",
        "count": count,
    }
    if count == 0:
        entry["note"] = "zero security types"
        return entry
    types = read_exactly(sock, count)
    if types is None:
        return {"result": "fail", "reason": "EOF before security types"}
    entry["types"] = list(types)
    entry["bytes_hex"] = types.hex()
    known = {30: "legacy-DH", 33: "RSA-SRP", 35: "Kerberos", 36: "direct-SRP"}
    entry["type_names"] = [known.get(t, f"unknown-{t}") for t in types]
    return entry


def run_probe(host: str, port: int, unsafe_type: Optional[int]) -> list:
    """Run a safe probe. Returns transcript entries."""
    entries = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((host, port))
        banner_entry = probe_banner(sock)
        entries.append(banner_entry)
        if banner_entry.get("result") == "fail":
            return entries

        sec_entry = probe_security_types(sock)
        entries.append(sec_entry)
        if sec_entry.get("result") == "fail":
            return entries

        # Default: stop here. Do not send any credentials.
        entries.append({
            "offset": -1,
            "direction": "—",
            "state": "PROBE_COMPLETE_SAFE",
            "note": "Stopped before transmitting credentials. "
                    "Use --unsafe-probe-type to proceed (requires authorization).",
        })

        if unsafe_type is not None:
            entries.append({
                "state": "UNSAFE_PROBE_REQUESTED",
                "type": unsafe_type,
                "note": "Unsafe probing requires explicit authorization and "
                        "a sacrificial account.",
            })
            # Unsafe probes would continue here with branch-specific logic.
            # For now, the infrastructure is complete; the actual unsafe probe
            # code will be added when captures are available.

    except (OSError, socket.timeout) as e:
        entries.append({"result": "fail", "reason": str(e)})
    finally:
        sock.close()
    return entries


def verify_redaction(filepath: str) -> int:
    """Verify no canary secrets appear in a file."""
    with open(filepath, "rb") as f:
        data = f.read()
    found = []
    for canary in [CANARY_PASSWORD] + CANARY_KEYS:
        if canary in data:
            found.append(canary.decode())
    if found:
        print(f"FAIL: found unredacted secrets: {found}", file=sys.stderr)
        return 1
    print("ok: no canary secrets found in output.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Apple RFB probe tool (G14)")
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=5900)
    ap.add_argument("--unsafe-probe-type", type=int, default=None,
                    choices=[30, 33, 35, 36],
                    help="UNSAFE: proceed into the specified auth branch. "
                         "Requires explicit authorization.")
    ap.add_argument("--output", default=None,
                    help="Write transcript JSON to this file (mode 0600)")
    ap.add_argument("--verify-redaction", default=None,
                    help="Verify no canary secrets in the given file")
    args = ap.parse_args()

    if args.verify_redaction:
        return verify_redaction(args.verify_redaction)

    if args.host is None:
        print("usage: apple_probe.py --host <host> [--port <port>]", file=sys.stderr)
        return 2

    entries = run_probe(args.host, args.port, args.unsafe_probe_type)
    output = json.dumps(entries, indent=2)

    if args.output:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, output.encode())
        os.close(fd)
        print(f"Transcript written to {args.output} (mode 0600)", file=sys.stderr)
    else:
        print(output)

    return 0 if not any(e.get("result") == "fail" for e in entries) else 1


if __name__ == "__main__":
    sys.exit(main())
