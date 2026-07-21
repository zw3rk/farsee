#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Orchestrate the C handshake driver against the scripted RFB server.

Launches the scripted server on an ephemeral port, then runs the C driver
pointed at it, and checks the driver's JSON result against the scenario's
expectation. Each scenario is a tuple:
    (server_scenario, driver_args, expected_driver_result)

plan.md §G2: "Scripted loopback server validates exact bytes from client
for each supported protocol version and security path."
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from typing import List, Tuple


def find_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for_server(proc: subprocess.Popen, port: int, timeout: float = 5.0) -> bool:
    """Wait until the server prints its ready line or the port accepts."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                # The accept() in the server is single-shot; connecting here
                # would consume it. Instead just poll the port via bind.
                pass
        except OSError:
            time.sleep(0.05)
            continue
        # Port appears open; but we don't want to consume the accept. Trust
        # the server's ready line if present.
        return True
    return False


def run_scenario(driver: str, server_py: str,
                 scenario: str, driver_args: List[str],
                 expect_ok: bool, password: str = "password") -> Tuple[bool, str]:
    port = find_free_port()
    srv = subprocess.Popen(
        [sys.executable, server_py, "--port", str(port),
         "--scenario", scenario],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    try:
        # Give the server a moment to bind + listen.
        time.sleep(0.3)
        if srv.poll() is not None:
            out, err = srv.communicate(timeout=2)
            return False, f"server exited early: {err.strip()}"

        # Run the driver.
        drv = subprocess.run(
            [driver, str(port), password] + driver_args,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10,
        )
        drv_out = drv.stdout.strip()
        try:
            result = json.loads(drv_out.splitlines()[-1])
        except Exception as e:
            return False, f"driver produced bad JSON: {drv_out!r} ({e})"

        ok = (result.get("result") == "ok") == expect_ok
        detail = json.dumps(result)
        return ok, detail
    finally:
        srv.wait(timeout=5)


SCENARIOS = [
    # (server scenario, driver args, expect driver ok?)
    ("vnc38-success", [], True),
    ("none38-success", ["--allow-none"], True),
    ("vnc38-wrong-pw", [], False),   # driver should report auth failure
    ("zero-types", [], False),       # driver should fail
    ("banner-unknown", [], False),   # driver should reject unknown banner
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", required=True)
    ap.add_argument("--server", required=True)
    args = ap.parse_args()

    all_ok = True
    for scenario, drv_args, expect_ok in SCENARIOS:
        ok, detail = run_scenario(args.driver, args.server, scenario, drv_args, expect_ok)
        status = "PASS" if ok else "FAIL"
        print(f"  {status}  integration::{scenario}  {detail}")
        if not ok:
            all_ok = False

    print()
    print("INTEGRATION  " + ("all passed" if all_ok else "FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
