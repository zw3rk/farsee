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
import struct
import sys
import time
import traceback
from typing import Optional
import zlib


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


CAPTURE_INITIAL_FBUR = bytes.fromhex("03000000000000100010")
CAPTURE_TARGET_FBUR = bytes.fromhex("03000000000000080008")
CAPTURE_MUTATION_TARGET_FBUR = bytes.fromhex("03010000000000100010")
CAPTURE_SINGLETON_BODY = bytes.fromhex("00030500000843686d")


def capture_none38_server_init(conn: socket.socket) -> Optional[str]:
    """Drive a classic 3.8 None-auth session through 16x16 ServerInit."""
    conn.sendall(BANNER_38)
    client_banner = read_exactly(conn, 12)
    if client_banner != BANNER_38:
        return "bad client banner"
    conn.sendall(bytes([1, 1]))
    if read_exactly(conn, 1) != bytes([1]):
        return "bad None selection"
    conn.sendall(bytes([0, 0, 0, 0]))
    if read_exactly(conn, 1) != bytes([1]):
        return "bad ClientInit shared flag"

    pixel_format = bytes.fromhex("2018000100ff00ff00ff100800000000")
    name = b"farsee-capture-test"
    server_init = (
        bytes.fromhex("00100010")
        + pixel_format
        + len(name).to_bytes(4, "big")
        + name
    )
    conn.sendall(server_init)
    return None


def capture_read_setup(conn: socket.socket, zrle_control: bool = False) -> Optional[str]:
    expected_pixel_format = bytes.fromhex(
        "000000002018000100ff00ff00ff100800000000"
    )
    expected_encodings = bytes.fromhex(
        "0200000300000010ffffff21ffffff11"
        if zrle_control else
        "02000005000000100000000100000000ffffff11ffffff21"
    )
    set_pixel_format = read_exactly(conn, len(expected_pixel_format))
    if set_pixel_format != expected_pixel_format:
        return "bad SetPixelFormat"
    set_encodings = read_exactly(conn, len(expected_encodings))
    if set_encodings != expected_encodings:
        return "bad SetEncodings"
    initial_request = read_exactly(conn, len(CAPTURE_INITIAL_FBUR))
    if initial_request != CAPTURE_INITIAL_FBUR:
        return "bad mandatory initial FBUR"
    return None


def serve_capture_zrle_control(conn: socket.socket) -> dict:
    reason = capture_none38_server_init(conn)
    if reason is not None:
        return {"result": "fail", "reason": reason}
    reason = capture_read_setup(conn, zrle_control=True)
    if reason is not None:
        return {"result": "fail", "reason": reason}
    compressor = zlib.compressobj()
    expanded = bytes((1, 0x33, 0x22, 0x11))
    compressed = compressor.compress(expanded) + compressor.flush(zlib.Z_SYNC_FLUSH)
    rectangle = (
        struct.pack(">HHHHi", 0, 0, 16, 16, 16)
        + struct.pack(">I", len(compressed)) + compressed
    )
    response = b"\x00\x00\x00\x01" + rectangle
    for byte in response:
        conn.sendall(bytes((byte,)))
    return {
        "result": "ok",
        "initial_quarantined": True,
        "control_fullscreen_nonincremental": True,
        "fragmented": True,
        "extra_client_bytes": capture_collect_extra(conn, 0.2),
    }


def capture_rect(x: int, y: int, width: int, height: int,
                 body: bytes = CAPTURE_SINGLETON_BODY) -> bytes:
    header = (
        x.to_bytes(2, "big")
        + y.to_bytes(2, "big")
        + width.to_bytes(2, "big")
        + height.to_bytes(2, "big")
        + (0x03F3).to_bytes(4, "big")
    )
    return header + len(body).to_bytes(4, "big") + body


def capture_collect_extra(conn: socket.socket, timeout: float = 2.0) -> int:
    """Count bytes after the sole target request until EOF or the bound."""
    conn.settimeout(timeout)
    extra = 0
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            extra += len(chunk)
    except (socket.timeout, ConnectionResetError):
        # A timeout is itself bounded; the runner also bounds the driver.
        pass
    return extra


def serve_capture(conn: socket.socket, scenario: str) -> dict:
    reason = capture_none38_server_init(conn)
    if reason is not None:
        return {"result": "fail", "reason": reason}
    reason = capture_read_setup(conn)
    if reason is not None:
        return {"result": "fail", "reason": reason}

    mutation_scenario = scenario.startswith("capture-mutation-")
    if not mutation_scenario:
        # The target request is forbidden until the mandatory initial response
        # completes and a quiet poll establishes the response boundary.
        conn.settimeout(0.05)
        try:
            premature = conn.recv(64)
        except socket.timeout:
            premature = b""
        if premature:
            return {"result": "fail", "reason": "target before initial FBU",
                    "premature_bytes": len(premature)}
        conn.settimeout(10.0)

    initial = bytes.fromhex("00000000")  # FBU with zero rectangles.
    if scenario == "capture-initial-desktop-size":
        desktop_size = (
            bytes.fromhex("00000001")
            + bytes.fromhex("0000000000180010ffffff21")
        )
        conn.sendall(desktop_size)
        return {"result": "ok", "initial_quarantined": True,
                "extra_client_bytes": capture_collect_extra(conn)}
    if scenario == "capture-unsolicited":
        conn.sendall(initial + initial)
        return {"result": "ok", "initial_quarantined": True,
                "extra_client_bytes": capture_collect_extra(conn)}
    conn.sendall(initial)

    if scenario in {
        "capture-mutation-early-ack",
        "capture-mutation-wrong-binding",
        "capture-mutation-duplicate-ack",
        "capture-mutation-wrong-nonce",
        "capture-mutation-wrong-transition",
        "capture-mutation-wrong-version",
        "capture-mutation-no-ack-timeout",
        "capture-mutation-control-eof",
        "capture-mutation-ready-backpressure",
    }:
        extra = capture_collect_extra(conn)
        return {"result": "ok", "initial_quarantined": True,
                "target_absent": extra == 0, "extra_client_bytes": extra}

    if scenario == "capture-mutation-hold-unsolicited-fbu":
        # The initial continuous-quiet interval is 30 ms. Leave a wide margin
        # so READY is emitted, then inject a second zero-rectangle FBU while
        # the protocol thread is still waiting for the mutation ACK.
        time.sleep(0.1)
        try:
            conn.sendall(initial)
        except (BrokenPipeError, ConnectionResetError):
            pass
        extra = capture_collect_extra(conn)
        return {"result": "ok", "initial_quarantined": True,
                "target_absent": extra == 0, "extra_client_bytes": extra}

    expected_target = (CAPTURE_MUTATION_TARGET_FBUR
                       if mutation_scenario else CAPTURE_TARGET_FBUR)
    target_request = read_exactly(conn, len(expected_target))
    if target_request != expected_target:
        return {"result": "fail", "reason": "bad targeted FBUR",
                "target_bytes": 0 if target_request is None
                                else len(target_request)}

    if scenario == "capture-eof":
        return {"result": "ok", "initial_quarantined": True,
                "target_exact": True,
                "extra_client_bytes": capture_collect_extra(conn, 0.05)}
    if scenario == "capture-timeout":
        return {"result": "ok", "initial_quarantined": True,
                "target_exact": True,
                "extra_client_bytes": capture_collect_extra(conn)}
    if scenario == "capture-multiple-rects":
        conn.sendall(bytes.fromhex("00000002"))
        return {"result": "ok", "initial_quarantined": True,
                "target_exact": True,
                "extra_client_bytes": capture_collect_extra(conn)}

    body = CAPTURE_SINGLETON_BODY
    x = 0
    if scenario == "capture-geometry-mismatch":
        x = 8
    elif scenario == "capture-invalid-quality":
        body = bytes([0, 7, 5]) + CAPTURE_SINGLETON_BODY[3:]

    response = bytes.fromhex("00000001") + capture_rect(x, 0, 8, 8, body)
    if scenario == "capture-post-target-unsolicited":
        conn.sendall(response)
        time.sleep(0.01)
        conn.sendall(initial)
        return {"result": "ok", "initial_quarantined": True,
                "target_exact": True,
                "extra_client_bytes": capture_collect_extra(conn)}
    if scenario in {"capture-success", "capture-mutation-success"}:
        # Leave the final body byte outstanding long enough for the client to
        # observe incomplete input. Then attach Bell directly after it: a
        # successful DONE state proves the following message stayed aligned.
        for byte in response[:-1]:
            conn.sendall(bytes([byte]))
            time.sleep(0.002)
        conn.sendall(response[-1:] + bytes([2]))
        return {"result": "ok", "initial_quarantined": True,
                "target_exact": True, "fragmented": True,
                "bell_after": True,
                "target_fullscreen_incremental": mutation_scenario,
                "extra_client_bytes": capture_collect_extra(conn)}

    conn.sendall(response)
    return {"result": "ok", "initial_quarantined": True,
            "target_exact": True,
            "extra_client_bytes": capture_collect_extra(conn)}


def serve_capture_success(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-success")


def serve_capture_geometry_mismatch(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-geometry-mismatch")


def serve_capture_multiple_rects(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-multiple-rects")


def serve_capture_unsolicited(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-unsolicited")


def serve_capture_invalid_quality(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-invalid-quality")


def serve_capture_timeout(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-timeout")


def serve_capture_eof(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-eof")


def serve_capture_post_target_unsolicited(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-post-target-unsolicited")


def serve_capture_initial_desktop_size(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-initial-desktop-size")


def serve_capture_mutation_success(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-mutation-success")


def serve_capture_mutation_early_ack(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-mutation-early-ack")


def serve_capture_mutation_wrong_binding(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-mutation-wrong-binding")


def serve_capture_mutation_duplicate_ack(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-mutation-duplicate-ack")


def serve_capture_mutation_wrong_nonce(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-mutation-wrong-nonce")


def serve_capture_mutation_wrong_transition(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-mutation-wrong-transition")


def serve_capture_mutation_wrong_version(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-mutation-wrong-version")


def serve_capture_mutation_no_ack_timeout(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-mutation-no-ack-timeout")


def serve_capture_mutation_control_eof(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-mutation-control-eof")


def serve_capture_mutation_ready_backpressure(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-mutation-ready-backpressure")


def serve_capture_mutation_hold_unsolicited_fbu(conn: socket.socket) -> dict:
    return serve_capture(conn, "capture-mutation-hold-unsolicited-fbu")


SCENARIOS = {
    "vnc38-success": serve_vnc38_success,
    "none38-success": serve_none38_success,
    "vnc38-wrong-pw": serve_vnc38_wrong_pw,
    "zero-types": serve_zero_types,
    "banner-unknown": serve_banner_unknown,
    "vnc38-init": serve_vnc38_init,
    "capture-success": serve_capture_success,
    "capture-zrle-control": serve_capture_zrle_control,
    "capture-geometry-mismatch": serve_capture_geometry_mismatch,
    "capture-multiple-rects": serve_capture_multiple_rects,
    "capture-unsolicited": serve_capture_unsolicited,
    "capture-invalid-quality": serve_capture_invalid_quality,
    "capture-timeout": serve_capture_timeout,
    "capture-eof": serve_capture_eof,
    "capture-post-target-unsolicited": serve_capture_post_target_unsolicited,
    "capture-initial-desktop-size": serve_capture_initial_desktop_size,
    "capture-mutation-success": serve_capture_mutation_success,
    "capture-mutation-early-ack": serve_capture_mutation_early_ack,
    "capture-mutation-wrong-binding": serve_capture_mutation_wrong_binding,
    "capture-mutation-duplicate-ack": serve_capture_mutation_duplicate_ack,
    "capture-mutation-wrong-nonce": serve_capture_mutation_wrong_nonce,
    "capture-mutation-wrong-transition": (
        serve_capture_mutation_wrong_transition
    ),
    "capture-mutation-wrong-version": serve_capture_mutation_wrong_version,
    "capture-mutation-no-ack-timeout": (
        serve_capture_mutation_no_ack_timeout
    ),
    "capture-mutation-control-eof": serve_capture_mutation_control_eof,
    "capture-mutation-ready-backpressure": (
        serve_capture_mutation_ready_backpressure
    ),
    "capture-mutation-hold-unsolicited-fbu": (
        serve_capture_mutation_hold_unsolicited_fbu
    ),
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
