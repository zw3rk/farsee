#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Capture the SRP challenge from the VM for structure analysis.
Saves ONLY the challenge bytes (no credentials, no SPKI, no ciphertext).
"""
import hashlib
import socket
import struct
import subprocess
import sys
import time

RECV_TIMEOUT = 10.0

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def capture(host, port):
    print(f"capture: connecting to {host}:{port}")
    sock = socket.create_connection((host, port), timeout=5.0)
    sock.settimeout(RECV_TIMEOUT)

    # Banner exchange
    server_banner = recv_exact(sock, 12)
    banner_str = server_banner.decode("ascii", errors="replace").rstrip()
    print(f"banner: server={banner_str!r}")
    sock.sendall(b"RFB 003.889\n")

    # Security types
    count = recv_exact(sock, 1)[0]
    types_raw = recv_exact(sock, count)
    sec_types = list(types_raw)
    print(f"security: types={sec_types}")

    # Select type 33
    sock.sendall(bytes([33]))

    # Send key request (§3 golden)
    key_request = bytes([
        0x21, 0x00, 0x00, 0x00, 0x0a, 0x01, 0x00,
        0x52, 0x53, 0x41, 0x31, 0x00, 0x00, 0x00, 0x00,
    ])
    sock.sendall(key_request)
    print(f"sent: key_request")

    # Read key response
    key_resp = sock.recv(8192)
    print(f"key_response: len={len(key_resp)}")

    # Parse key response to get SPKI
    total_len = struct.unpack(">I", key_resp[0:4])[0]
    version_le = struct.unpack("<I", key_resp[4:8])[0]
    der_len = struct.unpack(">H", key_resp[8:10])[0]
    spki = key_resp[10:10+der_len]
    print(f"spki: der_len={der_len} (not saved)")

    # Build identity plaintext for "admin"
    username = b"admin"
    payload_len = len(username) + 7
    import io
    pt = struct.pack(">I", payload_len)
    pt += struct.pack(">I", len(username))
    pt += username
    pt += struct.pack(">H", 0)  # empty string
    pt += struct.pack("B", 0)   # empty opaque
    print(f"identity: {len(pt)} bytes for username 'admin'")

    # Encrypt with the C helper
    proc = subprocess.run(
        ["build/probe_packet1"],
        input=spki,
        capture_output=True,
    )
    if proc.returncode != 0:
        print(f"encrypt failed: {proc.stderr.decode()}")
        sock.close()
        return

    packet1 = proc.stdout
    print(f"packet1: len={len(packet1)}")

    # Send packet 1 (654 bytes, no selector prefix)
    sock.sendall(packet1)

    # Read the SRP challenge
    time.sleep(2)
    challenge = b""
    sock.settimeout(5)
    try:
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            challenge += chunk
    except socket.timeout:
        pass

    print(f"challenge: len={len(challenge)}")

    if len(challenge) > 0:
        # Save raw challenge for analysis (NO credentials in this file)
        with open("/tmp/srp_challenge.bin", "wb") as f:
            f.write(challenge)
        print(f"saved to /tmp/srp_challenge.bin")

        # Print first 64 bytes hex for structure analysis
        print(f"first 64 bytes hex:")
        for i in range(0, min(64, len(challenge)), 16):
            hex_str = " ".join(f"{challenge[j]:02x}" for j in range(i, min(i+16, len(challenge))))
            print(f"  {i:4d}: {hex_str}")

        # Try to parse outer structure
        if len(challenge) >= 13:
            outer_len = struct.unpack(">I", challenge[0:4])[0]
            print(f"\nouter u32_be: {outer_len} (0x{outer_len:08x})")
            # Try various interpretations
            if len(challenge) >= 5:
                step = challenge[4]
                print(f"byte[4] (step?): {step}")
            if len(challenge) >= 9:
                inner1 = struct.unpack(">I", challenge[5:9])[0]
                print(f"bytes[5:9] u32_be: {inner1} (0x{inner1:08x})")
            if len(challenge) >= 13:
                inner2 = struct.unpack(">I", challenge[9:13])[0]
                print(f"bytes[9:13] u32_be: {inner2} (0x{inner2:08x})")

    sock.close()

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.64.3"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5900
    capture(host, port)
