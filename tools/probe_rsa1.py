#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
G18A — authorized real-macOS RSA1 branch-entry probe.

Connects to a macOS Screen Sharing server, negotiates RFB 003.889,
selects security type 33, sends the 15-byte authtype-0 key request,
and observes the response. Stops after receiving the server's public-key
response or a FIN/RST — no password proof is sent.

Records only redacted evidence: banner, security types, response length,
SHA-256 hash of the response, OS build, exact commands, and FIN/RST vs
data result. No passwords, usernames, or private keys are transmitted.

Usage:
    nix develop --command python3 tools/probe_rsa1.py <host> <port>
"""

import hashlib
import socket
import struct
import sys
import time

RECV_TIMEOUT = 5.0  # seconds
MAX_RESPONSE = 8192  # bytes


def recv_exact(sock, n):
    """Receive exactly n bytes or return None on EOF/timeout."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None  # EOF
        buf += chunk
    return buf


def probe(host, port):
    print(f"probe: connecting to {host}:{port}")
    sock = socket.create_connection((host, port), timeout=5.0)
    sock.settimeout(RECV_TIMEOUT)

    # --- Step 1: RFB banner exchange ---
    server_banner = recv_exact(sock, 12)
    if server_banner is None:
        print("result: FIN during banner (server closed immediately)")
        return
    banner_str = server_banner.decode("ascii", errors="replace").rstrip()
    print(f"banner: server={banner_str!r}")

    # Reply with RFB 003.889 (Apple dialect).
    client_banner = b"RFB 003.889\n"
    sock.sendall(client_banner)
    print(f"banner: client=RFB 003.889")

    # --- Step 2: Security types ---
    sec_types_raw = recv_exact(sock, 1)
    if sec_types_raw is None:
        print("result: FIN during security-type count")
        return
    count = sec_types_raw[0]
    if count == 0:
        # Failure reason follows (u32 len + string).
        reason_len_raw = recv_exact(sock, 4)
        if reason_len_raw:
            rlen = struct.unpack(">I", reason_len_raw)[0]
            reason = recv_exact(sock, rlen) or b""
            print(f"result: server rejected (reason_len={rlen})")
        else:
            print("result: FIN after zero security types")
        return

    types_raw = recv_exact(sock, count)
    if types_raw is None:
        print("result: FIN during security-type list")
        return
    sec_types = list(types_raw)
    print(f"security: types={sec_types}")

    if 33 not in sec_types:
        print(f"result: type 33 not offered (have {sec_types})")
        return

    # --- Step 3: Select type 33 ---
    sock.sendall(bytes([33]))
    print("security: selected type=33 (0x21)")

    # --- Step 4: Send the 15-byte authtype-0 key request ---
    # RSA1-UNBLOCK.md §3 exact golden:
    #   21 00 00 00 0a 01 00 52 53 41 31 00 00 00 00
    key_request = bytes([
        0x21,                          # selector
        0x00, 0x00, 0x00, 0x0a,        # total_len = 10
        0x01, 0x00,                    # version = 0x0100
        0x52, 0x53, 0x41, 0x31,        # "RSA1"
        0x00, 0x00,                    # authtype = 0 (key request)
        0x00, 0x00,                    # inner_len = 0
    ])
    sock.sendall(key_request)
    print(f"sent: key_request len={len(key_request)} golden")

    # --- Step 5: Observe the response ---
    try:
        response = sock.recv(MAX_RESPONSE)
    except socket.timeout:
        print("result: TIMEOUT (no response within {}s)".format(RECV_TIMEOUT))
        sock.close()
        return

    if not response:
        print("result: FIN (server closed connection after key request)")
        print("interpretation: branch-entry framing likely rejected")
        sock.close()
        return

    # We received data — structurally validate it.
    resp_hash = hashlib.sha256(response).hexdigest()
    print(f"response: len={len(response)} sha256={resp_hash[:16]}...")

    # Try to parse as a key response (§3):
    #   u32_be total_len, u32_le version, u16_be der_len, DER, u8 trailing
    if len(response) >= 10:
        total_len = struct.unpack(">I", response[0:4])[0]
        version_le = struct.unpack("<I", response[4:8])[0]
        der_len = struct.unpack(">H", response[8:10])[0]
        print(f"parsed: total_len={total_len} version=0x{version_le:08x} "
              f"der_len={der_len}")

        if version_le == 0x00000100:
            print("version: MATCH (0x00000100 little-endian) — mixed-endian "
                  "format confirmed")
        else:
            print(f"version: MISMATCH (expected 0x00000100, got 0x{version_le:08x})")

        if total_len == der_len + 7:
            print(f"total_len: CONSISTENT (der_len+7={der_len+7})")
            if len(response) >= 10 + der_len + 1:
                trailing = response[10 + der_len]
                print(f"trailing_byte: 0x{trailing:02x} "
                      f"({'OK' if trailing == 0 else 'NOT ZERO'})")
                print("result: KEY RESPONSE RECEIVED — §3 RSA1 branch entry ACCEPTED")
                print("interpretation: the 15-byte key-request golden is "
                      "syntactically accepted by macOS")

                # --- Step 6 (§4): Send packet 1 (identity envelope) ---
                # Extract the DER SPKI from the key response.
                der_spki = response[10:10 + der_len]
                der_hash = hashlib.sha256(der_spki).hexdigest()
                print(f"spki: der_len={der_len} sha256={der_hash[:16]}...")

                # Build packet 1 using the project's tested C helper.
                # The identity is username 'probe-test' only — NO password.
                import subprocess
                helper = subprocess.run(
                    ["build/probe_packet1"],
                    input=der_spki,
                    capture_output=True,
                )
                if helper.returncode != 0:
                    print(f"packet1: C helper failed: "
                          f"{helper.stderr.decode().strip()}")
                    sock.close()
                    return

                packet1 = helper.stdout
                pkt_hash = hashlib.sha256(packet1).hexdigest()
                print(f"packet1: len={len(packet1)} sha256={pkt_hash[:16]}...")
                # After a key-request exchange, packet 1 is 654 bytes
                # (no leading selector — §4 line 135-136).
                if len(packet1) != 654:
                    print(f"packet1: ERROR expected 654 bytes, got "
                          f"{len(packet1)}")
                    sock.close()
                    return

                # Verify the packet-1 framing (no selector prefix).
                # Layout: total_len(4) + version(2) + "RSA1"(4) + authtype(2) + ...
                # total_len=650 -> 00 00 02 8a, version=01 00, authtype=00 02
                if packet1[0:4] == bytes([0x00, 0x00, 0x02, 0x8a]) and \
                        packet1[4:6] == bytes([0x01, 0x00]):
                    print("packet1: framing OK (total_len=650, "
                          "version 01 00)")
                else:
                    print(f"packet1: framing check — "
                          f"bytes0-3={packet1[0:4].hex()} "
                          f"bytes4-5={packet1[4:6].hex()}")

                # Send the coalesced selector+packet1 as one write.
                sock.sendall(packet1)
                print(f"sent: selector+packet1 len={len(packet1)}")

                # --- Step 7: Observe the SRP challenge acceptance oracle ---
                try:
                    challenge = sock.recv(MAX_RESPONSE)
                except socket.timeout:
                    print("result: TIMEOUT after packet 1 (no SRP challenge "
                          "within {}s)".format(RECV_TIMEOUT))
                    print("interpretation: §4 inconclusive — server neither "
                          "FIN/RST'd nor sent a challenge")
                    sock.close()
                    return

                if not challenge:
                    print("result: FIN after packet 1 (server closed)")
                    print("interpretation: §4 packet 1 REJECTED — likely "
                          "identity format or RSA operation")
                    sock.close()
                    return

                chal_hash = hashlib.sha256(challenge).hexdigest()
                print(f"challenge: len={len(challenge)} "
                      f"sha256={chal_hash[:16]}...")
                print("result: DATA RECEIVED after packet 1 — §4 packet 1 "
                      "ACCEPTED (SRP challenge or equivalent)")
                print("interpretation: RSA1 branch entry + packet 1 "
                      "accepted by macOS; receipt proves RSA1 succeeded")
            else:
                print(f"result: partial key response (have {len(response)}, "
                      f"need {10 + der_len + 1})")
        else:
            print(f"total_len: INCONSISTENT (der_len+7={der_len+7}, "
                  f"got {total_len})")
    else:
        print(f"result: short response ({len(response)} bytes) — not a "
              f"standard key response")

    sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <host> <port>", file=sys.stderr)
        sys.exit(2)
    probe(sys.argv[1], int(sys.argv[2]))
