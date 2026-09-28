#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the capture-only rfb_session scheduler over loopback TCP."""

from __future__ import annotations

import argparse
import errno
import json
import os
import select
import socket
import struct
import subprocess
import sys
import time
from typing import Any


CONTROL_NONCE = 0x1020304050607080
CONTROL_TRANSITION = 0x01020304
CONTROL_BINDING = bytes(range(1, 33))
CONTROL_WIRE_SIZE = 52


def find_free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


SCENARIOS: list[dict[str, Any]] = [
    {
        "name": "capture-zrle-control",
        "zrle_control": True,
        "timeout_ms": 500,
        "error": 0,
        "state": 8,
        "failure": 0,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
        "classification": 4,
    },
    {
        "name": "capture-zrle-control-connected",
        "server_name": "capture-zrle-control",
        "connected": True,
        "zrle_control": True,
        "timeout_ms": 500,
        "error": 0,
        "state": 8,
        "failure": 0,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
        "classification": 4,
    },
    {
        "name": "capture-success",
        "direct_capture": True,
        "target_expected": True,
        "timeout_ms": 500,
        "error": 0,
        "state": 8,
        "failure": 0,
        "callbacks": 2,
        "targeted": 1,
    },
    {
        "name": "capture-geometry-mismatch",
        "timeout_ms": 500,
        "error": 6,
        "state": 9,
        "failure": 3,
        "callbacks": 1,
        "targeted": 0,
    },
    {
        "name": "capture-multiple-rects",
        "timeout_ms": 500,
        "error": 6,
        "state": 9,
        "failure": 2,
        "callbacks": 1,
        "targeted": 0,
    },
    {
        "name": "capture-unsolicited",
        "timeout_ms": 500,
        "error": 6,
        "state": 9,
        "failure": 1,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
    },
    {
        "name": "capture-invalid-quality",
        "timeout_ms": 500,
        "error": 6,
        "state": 9,
        "failure": 5,
        "callbacks": 1,
        "targeted": 0,
    },
    {
        "name": "capture-timeout",
        "timeout_ms": 120,
        "error": 11,
        "state": 9,
        "failure": 6,
        "callbacks": 1,
        "targeted": 0,
    },
    {
        "name": "capture-eof",
        "timeout_ms": 500,
        "error": 4,
        "state": 9,
        "failure": 7,
        "callbacks": 1,
        "targeted": 0,
    },
    {
        "name": "capture-post-target-unsolicited",
        "timeout_ms": 500,
        "error": 6,
        "state": 9,
        "failure": 1,
        "callbacks": 1,
        "targeted": 0,
    },
    {
        "name": "capture-initial-desktop-size",
        "timeout_ms": 500,
        "error": 6,
        "state": 9,
        "failure": 3,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
    },
    {
        "name": "capture-mutation-success",
        "mutation": True,
        "target_expected": True,
        "timeout_ms": 500,
        "error": 0,
        "state": 8,
        "failure": 0,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
        "classification": 2,
    },
    {
        "name": "capture-mutation-success-connected",
        "server_name": "capture-mutation-success",
        "connected": True,
        "mutation": True,
        "target_expected": True,
        "timeout_ms": 500,
        "error": 0,
        "state": 8,
        "failure": 0,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
        "classification": 2,
    },
    {
        "name": "capture-mutation-early-ack",
        "mutation": True,
        "timeout_ms": 500,
        "error": 6,
        "state": 9,
        "failure": 9,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
        "classification": 3,
    },
    {
        "name": "capture-mutation-wrong-binding",
        "mutation": True,
        "timeout_ms": 500,
        "error": 6,
        "state": 9,
        "failure": 9,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
        "classification": 3,
    },
    {
        "name": "capture-mutation-duplicate-ack",
        "mutation": True,
        "timeout_ms": 500,
        "error": 6,
        "state": 9,
        "failure": 9,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
        "classification": 3,
    },
    {
        "name": "capture-mutation-wrong-nonce",
        "mutation": True,
        "timeout_ms": 500,
        "error": 6,
        "state": 9,
        "failure": 9,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
        "classification": 3,
    },
    {
        "name": "capture-mutation-wrong-transition",
        "mutation": True,
        "timeout_ms": 500,
        "error": 6,
        "state": 9,
        "failure": 9,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
        "classification": 3,
    },
    {
        "name": "capture-mutation-wrong-version",
        "mutation": True,
        "timeout_ms": 500,
        "error": 6,
        "state": 9,
        "failure": 9,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
        "classification": 3,
    },
    {
        "name": "capture-mutation-no-ack-timeout",
        "mutation": True,
        "timeout_ms": 120,
        "error": 11,
        "state": 9,
        "failure": 6,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
        "classification": 3,
        "ack_expected": False,
    },
    {
        "name": "capture-mutation-control-zero-datagram",
        "mutation": True,
        "timeout_ms": 500,
        "error": 5,
        "state": 9,
        "failure": 9,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
        "classification": 3,
        "ack_expected": False,
    },
    {
        "name": "capture-mutation-ready-backpressure",
        "mutation": True,
        "timeout_ms": 500,
        "error": 5,
        "accepted_errors": [5, 6],
        "state": 9,
        "failure": 9,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
        "classification": 3,
        "ready_expected": False,
        "ack_expected": False,
    },
    {
        "name": "capture-mutation-hold-unsolicited-fbu",
        "mutation": True,
        "timeout_ms": 500,
        "error": 6,
        "state": 9,
        "failure": 1,
        "callbacks": 0,
        "initial": 0,
        "targeted": 0,
        "classification": 3,
        "ack_expected": False,
    },
]


def last_json_line(text: str) -> dict[str, Any]:
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise ValueError("no JSON output")
    return json.loads(lines[-1])


def result_matches(spec: dict[str, Any], driver: dict[str, Any],
                   server: dict[str, Any],
                   control: dict[str, Any]) -> tuple[bool, str]:
    expected = {
        "connect_error": 0,
        "error": spec["error"],
        "state": spec["state"],
        "failure": spec["failure"],
        "callbacks": spec["callbacks"],
        "initial": spec.get("initial", 1),
        "targeted": spec["targeted"],
    }
    mismatches = [
        f"driver {key}: expected {value!r}, got {driver.get(key)!r}"
        for key, value in expected.items()
        if driver.get(key) != value
    ]
    accepted_errors = spec.get("accepted_errors")
    if accepted_errors is not None:
        mismatches = [
            mismatch for mismatch in mismatches
            if not mismatch.startswith("driver error:")
        ]
        if driver.get("error") not in accepted_errors:
            mismatches.append(
                f"driver error: expected one of {accepted_errors!r}, "
                f"got {driver.get('error')!r}"
            )
    if driver.get("result") != "ok":
        mismatches.append("driver did not report a completed observation")
    if server.get("result") != "ok":
        mismatches.append(f"server failed: {server.get('reason')!r}")
    if not server.get("initial_quarantined"):
        mismatches.append("mandatory initial FBU was not quarantined")
    if server.get("extra_client_bytes") != 0:
        mismatches.append(
            "unexpected client bytes after target "
            f"({server.get('extra_client_bytes')!r}); input must stay silent"
        )

    if spec.get("mutation"):
        mutation_expected = {
            "final_present": True,
            "final_terminal": True,
            "final_classification": spec["classification"],
        }
        mismatches.extend(
            f"driver {key}: expected {value!r}, got {driver.get(key)!r}"
            for key, value in mutation_expected.items()
            if driver.get(key) != value
        )
        ready_expected = spec.get(
            "ready_expected",
            spec["name"] != "capture-mutation-early-ack",
        )
        if control.get("ready_decoded") != ready_expected:
            mismatches.append(
                "control READY decode did not match expected timing"
            )
        ack_expected = spec.get("ack_expected", True)
        if control.get("ack_sent") != ack_expected:
            mismatches.append("control ACK timing did not match expectation")
        if (spec["name"] == "capture-mutation-ready-backpressure" and
                not control.get("backpressure_prefilled")):
            mismatches.append("control READY send queue was not pre-filled")
        if spec.get("target_expected"):
            if not server.get("target_fullscreen_incremental"):
                mismatches.append(
                    "server did not see the exact full-screen incremental FBUR"
                )
            if not driver.get("final_fbu_complete"):
                mismatches.append("successful final did not close its FBU")
            if not driver.get("final_quiet_complete"):
                mismatches.append("successful final did not close quiet")
        elif not server.get("target_absent"):
            mismatches.append("control failure emitted a targeted FBUR")

    if spec.get("zrle_control"):
        control_expected = {
            "final_present": True,
            "final_terminal": True,
            "final_classification": spec["classification"],
            "final_fbu_complete": True,
            "final_quiet_complete": True,
            "frame_width": 16,
            "frame_height": 16,
            "frame_first_rgba": [0x11, 0x22, 0x33, 0xFF],
            "frame_bytes": 16 * 16 * 4,
            "frame_all_expected": True,
        }
        mismatches.extend(
            f"driver {key}: expected {value!r}, got {driver.get(key)!r}"
            for key, value in control_expected.items()
            if driver.get(key) != value
        )
        if not server.get("control_fullscreen_nonincremental"):
            mismatches.append("ZRLE control request was not exact")
        if not server.get("fragmented"):
            mismatches.append("ZRLE control response was not fragmented")

    if (spec.get("connected") and
            driver.get("borrowed_fd_open") is not True):
        mismatches.append("session destroy closed the borrowed connected fd")

    if spec.get("target_expected"):
        success_expected = {
            "direct": True,
            "requested_id": 17,
            "actual_x": 0,
            "actual_y": 0,
            "actual_width": 8,
            "actual_height": 8,
            "actual_encoding": 0x03F3,
            "records": 1,
            "first_run": 1,
        }
        if spec.get("direct_capture"):
            mismatches.extend(
                f"driver {key}: expected {value!r}, got {driver.get(key)!r}"
                for key, value in success_expected.items()
                if driver.get(key) != value
            )
        if not server.get("target_exact"):
            mismatches.append("targeted request bytes were not exact")
        if not server.get("fragmented"):
            mismatches.append("response was not sent fragmented")
        if not server.get("bell_after"):
            mismatches.append("following Bell was not sent")

    detail = "; ".join(mismatches) if mismatches else json.dumps(driver)
    return not mismatches, detail


def encode_ack(nonce: int, transition: int, binding: bytes) -> bytes:
    return struct.pack(">4sHBBQI32s", b"MVSC", 1, 0, 2,
                       nonce, transition, binding)


def receive_ready(control: socket.socket) -> tuple[int, int]:
    readable, _, _ = select.select([control], [], [], 2.0)
    if not readable:
        raise TimeoutError("READY datagram timeout")
    wire = control.recv(CONTROL_WIRE_SIZE + 1)
    if len(wire) != CONTROL_WIRE_SIZE:
        raise ValueError("READY datagram has wrong size")
    magic, version, reserved, kind, nonce, transition, binding = (
        struct.unpack(">4sHBBQI32s", wire)
    )
    if (magic != b"MVSC" or version != 1 or reserved != 0 or kind != 1 or
            nonce == 0 or transition == 0 or binding != bytes(32)):
        raise ValueError("READY datagram failed structural validation")
    if nonce != CONTROL_NONCE or transition != CONTROL_TRANSITION:
        raise ValueError("READY datagram failed campaign binding")
    return nonce, transition


def run_scenario(driver: str, server_py: str,
                 spec: dict[str, Any]) -> tuple[bool, str]:
    port = find_free_port()
    driver_control: socket.socket | None = None
    orchestrator_control: socket.socket | None = None
    connected_socket: socket.socket | None = None
    driver_process: subprocess.Popen[str] | None = None
    server = subprocess.Popen(
        [sys.executable, server_py, "--port", str(port),
         "--scenario", spec.get("server_name", spec["name"])],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    try:
        time.sleep(0.15)
        if server.poll() is not None:
            stdout, stderr = server.communicate(timeout=1)
            return False, f"server exited early: {stdout!r} {stderr!r}"
        assert server.stdout is not None
        ready = json.loads(server.stdout.readline())
        if not ready.get("listen"):
            return False, f"server did not report ready: {ready!r}"

        control_result = {"ready_decoded": False, "ack_sent": False}
        if spec.get("connected"):
            connected_socket = socket.socket(socket.AF_INET,
                                             socket.SOCK_STREAM)
            connected_socket.connect(("127.0.0.1", port))
            driver_args = [driver, "--connected-fd",
                           str(connected_socket.fileno()),
                           str(spec["timeout_ms"])]
        else:
            driver_args = [driver, str(port), str(spec["timeout_ms"])]
        if spec.get("zrle_control"):
            driver_args.append("zrle-control")
        if spec.get("mutation"):
            driver_control, orchestrator_control = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_DGRAM
            )
            driver_control.setblocking(False)
            orchestrator_control.setblocking(False)
            driver_args.append(str(driver_control.fileno()))
            if spec["name"] == "capture-mutation-early-ack":
                orchestrator_control.send(
                    encode_ack(CONTROL_NONCE, CONTROL_TRANSITION,
                               CONTROL_BINDING)
                )
                control_result["ack_sent"] = True
            elif spec["name"] == "capture-mutation-ready-backpressure":
                driver_control.setsockopt(socket.SOL_SOCKET,
                                          socket.SO_SNDBUF, 1024)
                filled = 0
                while filled < 1024:
                    try:
                        driver_control.send(bytes(CONTROL_WIRE_SIZE))
                        filled += 1
                    except OSError as error:
                        if error.errno in {
                            errno.EAGAIN, errno.EWOULDBLOCK, errno.ENOBUFS
                        }:
                            break
                        raise
                if filled == 0 or filled == 1024:
                    raise ValueError("could not bound READY send backpressure")
                readable, _, _ = select.select([driver_control], [], [], 0)
                if readable:
                    raise ValueError("backpressure created driver inbound data")
                control_result["backpressure_prefilled"] = True
            driver_process = subprocess.Popen(
                driver_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                pass_fds=((connected_socket.fileno(), driver_control.fileno())
                          if connected_socket is not None else
                          (driver_control.fileno(),)),
            )
            driver_control.close()
            driver_control = None
            ready_required = spec.get(
                "ready_expected",
                spec["name"] != "capture-mutation-early-ack",
            )
            if ready_required:
                nonce, transition = receive_ready(orchestrator_control)
                control_result["ready_decoded"] = True
                if spec["name"] == "capture-mutation-control-zero-datagram":
                    # SOCK_DGRAM peer close is not observable on every POSIX
                    # platform. An empty datagram portably exercises the
                    # control channel's zero-length/closed-input path.
                    orchestrator_control.send(b"")
                    orchestrator_control.close()
                    orchestrator_control = None
                elif spec.get("ack_expected", True):
                    binding = CONTROL_BINDING
                    if spec["name"] == "capture-mutation-wrong-binding":
                        binding = (bytes([CONTROL_BINDING[0] ^ 1])
                                   + CONTROL_BINDING[1:])
                    if spec["name"] == "capture-mutation-wrong-nonce":
                        nonce ^= 1
                    if spec["name"] == "capture-mutation-wrong-transition":
                        transition += 1
                    ack = encode_ack(nonce, transition, binding)
                    if spec["name"] == "capture-mutation-wrong-version":
                        malformed = bytearray(ack)
                        malformed[5] = 2
                        ack = bytes(malformed)
                    orchestrator_control.send(ack)
                    control_result["ack_sent"] = True
                    if spec["name"] == "capture-mutation-duplicate-ack":
                        orchestrator_control.send(ack)
            driver_stdout, driver_stderr = driver_process.communicate(timeout=5)
            driver_returncode = driver_process.returncode
        else:
            completed = subprocess.run(
                driver_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                pass_fds=((connected_socket.fileno(),)
                          if connected_socket is not None else ()),
            )
            driver_stdout = completed.stdout
            driver_stderr = completed.stderr
            driver_returncode = completed.returncode
        if driver_returncode != 0:
            return False, (
                f"driver exit {driver_returncode}: "
                f"stdout={driver_stdout!r} stderr={driver_stderr!r}"
            )
        driver_result = last_json_line(driver_stdout)
        server_stdout, server_stderr = server.communicate(timeout=3)
        if server.returncode != 0:
            return False, (
                f"server exit {server.returncode}: "
                f"stdout={server_stdout!r} stderr={server_stderr!r}"
            )
        server_result = last_json_line(server_stdout)
        return result_matches(spec, driver_result, server_result,
                              control_result)
    except (json.JSONDecodeError, ValueError, TimeoutError) as error:
        return False, f"bad JSON: {error}"
    except subprocess.TimeoutExpired as error:
        return False, f"bounded process timeout: {error}"
    finally:
        if driver_process is not None and driver_process.poll() is None:
            driver_process.terminate()
            try:
                driver_process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                driver_process.kill()
                driver_process.wait(timeout=1)
        if driver_control is not None:
            driver_control.close()
        if orchestrator_control is not None:
            orchestrator_control.close()
        if connected_socket is not None:
            connected_socket.close()
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=1)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver", required=True)
    parser.add_argument("--server", required=True)
    args = parser.parse_args()

    all_ok = True
    for scenario in SCENARIOS:
        ok, detail = run_scenario(args.driver, args.server, scenario)
        print(f"  {'PASS' if ok else 'FAIL'}  "
              f"capture::{scenario['name']}  {detail}")
        all_ok = all_ok and ok
    print()
    print("CAPTURE  " + ("all passed" if all_ok else "FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
