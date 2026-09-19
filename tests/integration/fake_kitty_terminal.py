#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fake Kitty terminal for PTY integration testing (plan.md §G7).

Receives Kitty graphics protocol commands (APC ESC _ G ... ESC \\) over a
pseudo-terminal, decodes the base64 payload, and reconstructs the original
image bytes. This proves the direct-transfer presenter emits valid Kitty
graphics commands that a compliant terminal can decode.

Clean-room: derived from the public Kitty graphics protocol specification
(https://sw.kovidgoyal.net/kitty/graphics-protocol/). No Kitty source code
consulted.

Usage:
    fake_kitty_terminal.py --pty-fd <fd> [--expect-bytes <n>]

Reads from the PTY fd, assembles APC chunks, base64-decodes the payload,
and writes the reconstructed raw image bytes to stdout. The test harness
compares them against the known source bytes.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pty-fd", type=int, required=True)
    ap.add_argument("--expect-bytes", type=int, default=0,
                    help="expected raw image byte count; exit 1 on mismatch")
    ap.add_argument("--max-bytes", type=int, default=4 * 1024 * 1024)
    args = ap.parse_args()

    # Read from the PTY until we have a complete Kitty graphics sequence
    # (or EOF). APC = ESC _ ... ESC \.
    buf = bytearray()
    total_read = 0
    while total_read < args.max_bytes:
        try:
            chunk = os.read(args.pty_fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf.extend(chunk)
        total_read += len(chunk)
        # Check if we have at least one complete APC sequence.
        if b"\x1b\\" in buf and b"\x1b_G" in buf:
            break  # got at least one complete command

    # Find all APC _ G sequences and concatenate their payloads.
    # Each is: ESC _ G <fields> ; <base64> ESC \
    # The base64 payload is after the last ';' in the control section.
    raw_total = bytearray()
    i = 0
    while i < len(buf):
        # Find ESC _ G
        start = buf.find(b"\x1b_G", i)
        if start < 0:
            break
        # Find the ESC \ terminator
        end = buf.find(b"\x1b\\", start)
        if end < 0:
            break
        body = buf[start + 3:end]  # skip ESC _ G
        # Isolate the base64 payload. The Kitty format is:
        #   key1=val1,key2=val2,...,m=0<base64-payload>
        # The payload is everything after the last control-field value.
        # Control fields match: [a-zA-Z]+= followed by the value up to the
        # next comma. The payload is the trailing run of base64 chars.
        # Strategy: strip known control fields, then base64-decode the rest.
        # The control fields are comma-separated; after removing all
        # key=value,tokens, what remains is the payload.
        # Simplest reliable approach: the payload starts right after the
        # last `m=0` or `m=1` (which is always the final control field
        # before the payload in our encoder).
        decoded = b''
        is_shm = b't=s' in body
        for marker in (b'm=0', b'm=1'):
            pos = body.rfind(marker)
            if pos >= 0:
                candidate = body[pos + len(marker):]
                candidate = re.sub(rb'[^A-Za-z0-9+/=]', b'', candidate)
                if len(candidate) > 0:
                    try:
                        decoded = base64.b64decode(candidate)
                    except Exception:
                        decoded = b''
                    break
        if not decoded:
            # Fallback: try decoding the whole body after removing control chars.
            candidate = re.sub(rb'[^A-Za-z0-9+/=]', b'', body)
            try:
                decoded = base64.b64decode(candidate)
            except Exception:
                decoded = b''
        if is_shm and decoded:
            # For t=s (SHM transfer), the decoded payload is the shm object
            # name. POSIX shm lives in a kernel namespace, so use shm_open
            # (via ctypes) rather than a filesystem open.
            try:
                shm_name = decoded.decode('ascii')
                import ctypes
                import ctypes.util
                import mmap

                libname = ctypes.util.find_library("c")
                if libname is None:
                    # Portable fallbacks: Linux libc.so.6, macOS libc.dylib.
                    for cand in ("libc.so.6", "libc.dylib", "libc.so"):
                        try:
                            libc = ctypes.CDLL(cand)
                            break
                        except OSError:
                            libc = None
                    if libc is None:
                        raise OSError("cannot load libc for shm_open")
                else:
                    libc = ctypes.CDLL(libname)

                # Linux: shm_open may live in librt on older glibc; try c first.
                if not hasattr(libc, "shm_open"):
                    rt = ctypes.util.find_library("rt")
                    if rt is not None:
                        libc = ctypes.CDLL(rt)

                libc.shm_open.argtypes = [
                    ctypes.c_char_p, ctypes.c_int, ctypes.c_uint
                ]
                libc.shm_open.restype = ctypes.c_int
                O_RDONLY = 0
                fd = libc.shm_open(shm_name.encode("ascii"), O_RDONLY, 0)
                if fd < 0:
                    sys.stderr.write(f"shm_open failed for {shm_name}\n")
                else:
                    # mmap the object (portable; read() is unreliable on
                    # some platforms for shm fds).
                    size = os.fstat(fd).st_size
                    if size > 0:
                        mm = mmap.mmap(fd, size, access=mmap.ACCESS_READ)
                        shm_data = mm[:]
                        mm.close()
                        raw_total.extend(shm_data)
                    os.close(fd)
            except Exception as e:
                sys.stderr.write(f"SHM read error: {e}\n")
        else:
            raw_total.extend(decoded)
        i = end + 2

    # SHM objects are often page-rounded; tests care about the payload prefix.
    if args.expect_bytes > 0 and len(raw_total) > args.expect_bytes:
        raw_total = raw_total[: args.expect_bytes]

    # Write reconstructed raw bytes to stdout.
    os.write(1, raw_total)

    if args.expect_bytes > 0 and len(raw_total) != args.expect_bytes:
        sys.stderr.write(
            f"FAIL: expected {args.expect_bytes} raw bytes, got {len(raw_total)}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
