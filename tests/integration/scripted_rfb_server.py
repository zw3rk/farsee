#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Scripted RFB server for integration testing (plan.md §G2, §14.4).

Uses only the Python standard library. Implements just enough of the RFB
server side to drive the client through the handshake so the integration
tests can validate the client's exact bytes. This is a test double, not a
production server; it intentionally supports only the paths the tests need.

Clean-room: derived from RFC 6143 (the public standard), not from any
other RFB server implementation. No GPL/AGPL source consulted.

Usage:
    scripted_rfb_server.py --port <p> --scenario <name> [--bind <addr>]

Scenarios:
    vnc38-success      3.8, offer VNC auth, accept the response.
    none38-success     3.8, offer None, accept.
    vnc38-wrong-pw     3.8, offer VNC auth, reject the response with a reason.
    zero-types         3.8, refuse with a reason string.
    banner-unknown     Send an unknown vendor banner; client must disconnect.

The script prints a one-line JSON transcript on exit:
    {"result": "ok"|"fail", "reason": "...", "client_bytes": "<hex>"}
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import traceback
from typing import Optional


BANNER_38 = b"RFB 003.008\n"
BANNER_33 = b"RFB 003.003\n"
BANNER_37 = b"RFB 003.007\n"


def read_exactly(conn: socket.socket, n: int) -> Optional[bytes]:
    """Read exactly n bytes or return None on EOF."""
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def serve_vnc38_success(conn: socket.socket) -> dict:
    conn.sendall(BANNER_38)
    # Expect the client's banner.
    cb = read_exactly(conn, 12)
    if cb is None:
        return {"result": "fail", "reason": "client closed before banner"}
    if not cb.startswith(b"RFB 003.008"):
        return {"result": "fail", "reason": f"bad client banner {cb!r}",
                "client_bytes": cb.hex()}
    # Offer VNC auth (type 2).
    conn.sendall(bytes([1, 2]))
    # Expect the selection byte.
    sel = read_exactly(conn, 1)
    if sel != bytes([2]):
        return {"result": "fail", "reason": f"bad selection {sel!r}",
                "client_bytes": (cb + (sel or b"")).hex()}
    # Send the challenge.
    challenge = bytes(range(16))
    conn.sendall(challenge)
    # Read the response.
    resp = read_exactly(conn, 16)
    if resp is None or len(resp) != 16:
        return {"result": "fail", "reason": "short response"}
    # We don't verify the response cryptographically here; the unit KAT
    # covers that. Accept any 16-byte response.
    conn.sendall(bytes([0, 0, 0, 0]))  # OK
    return {"result": "ok", "client_bytes": (cb + sel + resp).hex()}


def serve_none38_success(conn: socket.socket) -> dict:
    conn.sendall(BANNER_38)
    cb = read_exactly(conn, 12)
    if cb is None or not cb.startswith(b"RFB 003.008"):
        return {"result": "fail", "reason": "bad banner"}
    conn.sendall(bytes([1, 1]))  # offer None
    sel = read_exactly(conn, 1)
    if sel != bytes([1]):
        return {"result": "fail", "reason": "bad selection", "client_bytes": (cb+(sel or b"")).hex()}
    conn.sendall(bytes([0, 0, 0, 0]))  # OK
    return {"result": "ok", "client_bytes": (cb + sel).hex()}


def serve_vnc38_wrong_pw(conn: socket.socket) -> dict:
    conn.sendall(BANNER_38)
    cb = read_exactly(conn, 12)
    if cb is None:
        return {"result": "fail", "reason": "eof"}
    conn.sendall(bytes([1, 2]))
    sel = read_exactly(conn, 1)
    if sel != bytes([2]):
        return {"result": "fail", "reason": "bad selection"}
    conn.sendall(bytes(range(16)))  # challenge
    resp = read_exactly(conn, 16)
    if resp is None:
        return {"result": "fail", "reason": "short response"}
    reason = b"wrong password"
    conn.sendall(bytes([0, 0, 0, 1]))  # failed
    conn.sendall(bytes([0, 0, 0, len(reason)]) + reason)
    return {"result": "ok", "reason_sent": reason.decode("ascii", "replace"),
            "client_bytes": (cb + sel + resp).hex()}


def serve_zero_types(conn: socket.socket) -> dict:
    conn.sendall(BANNER_38)
    cb = read_exactly(conn, 12)
    if cb is None:
        return {"result": "fail", "reason": "eof"}
    reason = b"server refusing"
    conn.sendall(bytes([0]))  # zero types
    conn.sendall(bytes([0, 0, 0, len(reason)]) + reason)
    return {"result": "ok", "reason_sent": reason.decode("ascii", "replace"),
            "client_bytes": cb.hex()}


def serve_banner_unknown(conn: socket.socket) -> dict:
    # Unknown vendor banner; a well-behaved client disconnects cleanly.
    conn.sendall(b"RFB 003.889\n")
    # The client should not echo; read nothing further. Give it a moment.
    conn.settimeout(2.0)
    try:
        extra = conn.recv(64)
    except socket.timeout:
        extra = b""
    return {"result": "ok", "client_bytes": extra.hex()}


def serve_vnc38_init(conn: socket.socket) -> dict:
    """Full handshake through ServerInit (G5 lifecycle path)."""
    conn.sendall(BANNER_38)
    cb = read_exactly(conn, 12)
    if cb is None:
        return {"result": "fail", "reason": "client closed before banner"}
    conn.sendall(bytes([1, 2]))  # offer VNC auth
    sel = read_exactly(conn, 1)
    if sel != bytes([2]):
        return {"result": "fail", "reason": f"bad selection {sel!r}",
                "client_bytes": (cb + (sel or b"")).hex()}
    conn.sendall(bytes(range(16)))  # challenge
    resp = read_exactly(conn, 16)
    if resp is None:
        return {"result": "fail", "reason": "short response"}
    conn.sendall(bytes([0, 0, 0, 0]))  # OK
    # Read ClientInit (1 byte shared flag).
    ci = read_exactly(conn, 1)
    if ci is None:
        return {"result": "fail", "reason": "no ClientInit"}
    # Send ServerInit: 16x16, canonical 32bpp, name "farsee-test".
    si = bytearray()
    si += bytes([0, 16, 0, 16])  # width, height
    si += bytes([32, 24, 0, 1])  # bpp, depth, big-endian, true-color
    si += bytes([0, 255, 0, 255, 0, 255])  # red/green/blue max
    si += bytes([16, 8, 0])  # red/green/blue shift
    si += bytes([0, 0, 0])  # padding
    name = b"farsee-test"
    si += len(name).to_bytes(4, "big")
    si += name
    conn.sendall(bytes(si))
    return {"result": "ok", "client_bytes": (cb + sel + resp + ci).hex()}


SCENARIOS = {
    "vnc38-success": serve_vnc38_success,
    "none38-success": serve_none38_success,
    "vnc38-wrong-pw": serve_vnc38_wrong_pw,
    "zero-types": serve_zero_types,
    "banner-unknown": serve_banner_unknown,
    "vnc38-init": serve_vnc38_init,
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(1)
    # Signal readiness so the test harness can connect.
    print(json.dumps({"listen": True, "port": args.port}), flush=True)

    conn, _ = srv.accept()
    conn.settimeout(10.0)
    try:
        result = SCENARIOS[args.scenario](conn)
    except Exception as e:  # pragma: no cover - defensive
        result = {"result": "fail", "reason": f"exception: {e}",
                  "trace": traceback.format_exc()[-400:]}
    conn.close()
    srv.close()
    print(json.dumps(result), flush=True)
    return 0 if result.get("result") == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
