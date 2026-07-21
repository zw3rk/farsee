#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""G5 lifecycle integration orchestrator.

Drives the lifecycle_integration C binary (handshake + ServerInit over the
POSIX nonblocking adapter) against the scripted server's vnc38-init
scenario, and checks the driver reports the expected framebuffer geometry.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time


def find_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run_scenario(driver: str, server_py: str, scenario: str,
                 driver_args: list[str], password: str,
                 expect_ok: bool, expect_geom: tuple[int, int] | None) -> tuple[bool, str]:
    port = find_free_port()
    srv = subprocess.Popen(
        [sys.executable, server_py, "--port", str(port),
         "--scenario", scenario],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    try:
        time.sleep(0.3)
        if srv.poll() is not None:
            out, err = srv.communicate(timeout=2)
            return False, f"server exited early: {err.strip()}"
        drv = subprocess.run(
            [driver, str(port), password] + driver_args,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15,
        )
        try:
            result = json.loads(drv.stdout.strip().splitlines()[-1])
        except Exception as e:
            return False, f"driver bad JSON: {drv.stdout!r} ({e})"
        ok = (result.get("result") == "ok") == expect_ok
        if ok and expect_geom is not None:
            w = result.get("width"); h = result.get("height")
            if (w, h) != expect_geom:
                ok = False
                result["geom_note"] = f"expected {expect_geom}, got ({w},{h})"
        return ok, json.dumps(result)
    finally:
        srv.wait(timeout=5)


SCENARIOS = [
    # (server scenario, driver args, password, expect_ok, expect_geom)
    # Only vnc38-init drives all the way through ServerInit; the other
    # scenarios exercise specific failure/early-exit paths.
    ("vnc38-init", [], "password", True, (16, 16)),
    ("vnc38-wrong-pw", [], "wrongpw1", False, None),
    ("banner-unknown", [], "x", False, None),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", required=True)
    ap.add_argument("--server", required=True)
    args = ap.parse_args()
    all_ok = True
    for scenario, drv_args, password, expect_ok, geom in SCENARIOS:
        ok, detail = run_scenario(args.driver, args.server, scenario,
                                  drv_args, password, expect_ok, geom)
        status = "PASS" if ok else "FAIL"
        print(f"  {status}  lifecycle::{scenario}  {detail}")
        if not ok:
            all_ok = False
    print()
    print("LIFECYCLE  " + ("all passed" if all_ok else "FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
