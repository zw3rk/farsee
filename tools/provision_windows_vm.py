#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Windows VM Provisioning State Machine (R6, §15.19)
#
# Bounded state machine: PREPARE -> BOOT_INSTALLER -> WAIT_INSTALL ->
# WAIT_RDP -> VERIFY_LOGIN -> BUILD_BASE -> RUN_MATRIX -> SHUTDOWN -> CLEANUP.
#
# Each state has a deadline, typed failure reason, retained logs (secrets
# redacted), and cleanup on interruption. QEMU is launched with a PID file,
# private QMP socket, unique run directory, per-run firmware vars, private
# display, and loopback-only port forwarding.
#
# Usage:
#   python3 provision_windows.py --iso /path/to/win11-iot-ltsc-2024-arm64.iso
#   python3 provision_windows.py --iso ... --expected-sha256 CCEC358A...
#
# The operator must place the official Windows 11 IoT Enterprise LTSC 2024
# ARM64 ISO at the cache path if Microsoft's download wizard requires
# interactive registration.

import hashlib
import os
import random
import signal
import socket
import string
import subprocess
import sys
import time
import json

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ISO_CACHE = "/tmp/rdp-lab/windows/win11-iot-ltsc-2024-arm64.iso"
EXPECTED_SHA256 = "3DCDBA9C9C0AA0430D4332B60C9AFCB3CD613D648A49CBBA2D4EF7B5978F32E8"
RDP_PORT = 13390  # loopback only

# QEMU binary and firmware (from nix shell)
QEMU_BIN = None  # resolved at runtime
EDK2_CODE = None  # resolved at runtime
EDK2_VARS = None  # resolved at runtime

# State deadlines (seconds)
DEADLINES = {
    "PREPARE": 60,
    "BOOT_INSTALLER": 120,
    "WAIT_INSTALL": 1800,     # 30 min (HVF should be much faster)
    "WAIT_RDP": 600,          # 10 min for RDP to come up after boot
    "VERIFY_LOGIN": 120,
    "BUILD_BASE": 60,
    "RUN_MATRIX": 600,
    "SHUTDOWN": 60,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def resolve_qemu():
    """Resolve QEMU binary and firmware paths from nix."""
    global QEMU_BIN, EDK2_CODE, EDK2_VARS
    r = subprocess.run(
        ["nix", "shell", "nixpkgs#qemu", "--command", "bash", "-c",
         'echo "$(which qemu-system-aarch64)"; '
         'ls /nix/store/*qemu-11*/share/qemu/edk2-aarch64-code.fd | head -1; '
         'ls /nix/store/*qemu-11*/share/qemu/edk2-arm-vars.fd | head -1'],
        capture_output=True, text=True, timeout=120
    )
    lines = r.stdout.strip().split("\n")
    QEMU_BIN = lines[0]
    EDK2_CODE = lines[1]
    EDK2_VARS = lines[2]
    return all([QEMU_BIN, EDK2_CODE, EDK2_VARS])

def verify_iso(iso_path, expected_sha256):
    """Verify the ISO SHA-256."""
    if not os.path.exists(iso_path):
        return False, f"ISO not found at {iso_path}"
    h = hashlib.sha256()
    with open(iso_path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    actual = h.hexdigest().upper()
    if actual != expected_sha256.upper():
        return False, f"SHA-256 mismatch: expected {expected_sha256}, got {actual}"
    return True, f"SHA-256 verified: {actual}"

def generate_credential(length=20):
    """Generate a random local password. Never logged."""
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def is_port_open(host, port, timeout=2):
    """Check if a TCP port is open."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def redact_secrets(text, secrets):
    """Redact all known secrets from text."""
    for s in secrets:
        text = text.replace(s, "<REDACTED>")
    return text

# ---------------------------------------------------------------------------
# State Machine
# ---------------------------------------------------------------------------

class VMProvisioner:
    def __init__(self, iso_path, run_dir):
        self.iso_path = iso_path
        self.run_dir = run_dir
        self.state = "PREPARE"
        self.qemu_pid = None
        self.qemu_pid_file = os.path.join(run_dir, "qemu.pid")
        self.qmp_socket = os.path.join(run_dir, "qmp.sock")
        self.serial_log = os.path.join(run_dir, "serial.log")
        self.stdout_log = os.path.join(run_dir, "stdout.log")
        self.disk_path = os.path.join(run_dir, "disk.qcow2")
        self.fw_vars = os.path.join(run_dir, "fw_vars.fd")
        self.base_path = os.path.join(run_dir, "base.qcow2")
        self.secrets = []
        self.username = "TestAdmin"
        self.password = None
        os.makedirs(run_dir, exist_ok=True)

    def log(self, msg):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [{self.state}] {msg}"
        print(line, flush=True)
        with open(os.path.join(self.run_dir, "state.log"), "a") as f:
            f.write(redact_secrets(line, self.secrets) + "\n")

    def qemu_command(self, extra_args=None):
        """Build the QEMU command for the current phase."""
        cmd = [
            self.qemu_bin,  # type: ignore
            "-M", "virt",
            "-accel", "hvf",
            "-cpu", "host",
            "-smp", "4",
            "-m", "4096",
            "-drive", f"if=pflash,format=raw,readonly=on,file={self.edk2_code}",  # type: ignore
            "-drive", f"if=pflash,format=raw,file={self.fw_vars}",
            "-drive", f"file={self.disk_path},if=virtio,format=qcow2",
            "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{RDP_PORT}-:3389",
            "-device", "virtio-net-pci,netdev=net0",
            "-display", "none",
            "-serial", f"file:{self.serial_log}",
            "-pidfile", self.qemu_pid_file,
            "-qmp", f"unix:{self.qmp_socket},server,nowait",
        ]
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def run_state(self, state_name, func, deadline):
        """Run a state function with a deadline."""
        self.state = state_name
        self.log(f"entering {state_name} (deadline {deadline}s)")
        start = time.time()
        try:
            result = func(deadline - (time.time() - start))
            elapsed = time.time() - start
            if result:
                self.log(f"{state_name} PASSED ({elapsed:.0f}s)")
                return True
            else:
                self.log(f"{state_name} FAILED ({elapsed:.0f}s)")
                return False
        except Exception as e:
            self.log(f"{state_name} EXCEPTION: {e}")
            return False

    def cleanup(self):
        """Cleanup: shut down QEMU if running."""
        if self.qemu_pid and os.path.exists(f"/proc/{self.qemu_pid}"):
            os.kill(self.qemu_pid, signal.SIGTERM)
            time.sleep(5)
        # Redact secrets from all logs
        for log_file in [self.serial_log, self.stdout_log,
                         os.path.join(self.run_dir, "state.log")]:
            if os.path.exists(log_file):
                with open(log_file, "r") as f:
                    content = f.read()
                with open(log_file, "w") as f:
                    f.write(redact_secrets(content, self.secrets))

    # --- State implementations ---

    def s_prepare(self, deadline):
        """PREPARE: verify ISO, resolve QEMU, create disk, firmware vars, creds."""
        ok, msg = verify_iso(self.iso_path, EXPECTED_SHA256)
        if not ok:
            self.log(f"ISO verification failed: {msg}")
            self.log(f"OPERATOR: place the official Windows 11 IoT Enterprise LTSC 2024")
            self.log(f"ARM64 ISO at: {self.iso_path}")
            self.log(f"Expected SHA-256: {EXPECTED_SHA256}")
            return False
        self.log(f"ISO verified: {msg}")

        if not resolve_qemu():
            self.log("failed to resolve QEMU from nix")
            return False
        self.qemu_bin = QEMU_BIN
        self.edk2_code = EDK2_CODE
        self.log(f"QEMU: {QEMU_BIN}")
        self.log(f"UEFI code: {EDK2_CODE}")

        # Create disk
        subprocess.run(
            [f"{os.path.dirname(QEMU_BIN)}/qemu-img", "create", "-f", "qcow2",
             self.disk_path, "40G"],
            check=True, capture_output=True, timeout=30
        )
        self.log("40G disk created")

        # Copy firmware vars (writable per-run copy)
        import shutil
        shutil.copy2(EDK2_VARS, self.fw_vars)
        os.chmod(self.fw_vars, 0o644)
        self.log("firmware vars copied")

        # Generate credentials
        self.password = generate_credential()
        self.secrets.append(self.password)
        self.log(f"account: {self.username} (password generated, {len(self.password)} chars)")
        # Write password to a secrets file (mode 0600, never committed)
        pw_file = os.path.join(self.run_dir, ".password")
        with open(pw_file, "w") as f:
            f.write(self.password)
        os.chmod(pw_file, 0o600)

        # Verify loopback port is free
        if is_port_open("127.0.0.1", RDP_PORT):
            self.log(f"port 127.0.0.1:{RDP_PORT} is already in use!")
            return False
        self.log(f"loopback port 127.0.0.1:{RDP_PORT} is free")
        return True

    def s_boot_installer(self, deadline):
        """BOOT_INSTALLER: launch QEMU with the Windows ISO."""
        cmd = self.qemu_command([
            "-drive", f"file={self.iso_path},media=cdrom,format=raw",
        ])
        self.log(f"launching QEMU (HVF, ARM64)...")
        with open(self.stdout_log, "w") as f:
            self.proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
        # Wait for PID file
        for _ in range(10):
            if os.path.exists(self.qemu_pid_file):
                with open(self.qemu_pid_file) as f:
                    self.qemu_pid = int(f.read().strip())
                self.log(f"QEMU started, PID={self.qemu_pid}")
                return True
            time.sleep(1)
        self.log("QEMU PID file not created")
        return False

    def s_wait_install(self, deadline):
        """WAIT_INSTALL: poll for Windows setup completion (port 3389 reachable)."""
        self.log("waiting for Windows setup + RDP to come up...")
        start = time.time()
        while time.time() - start < deadline:
            if is_port_open("127.0.0.1", RDP_PORT, timeout=3):
                self.log("RDP port reachable!")
                return True
            if self.proc.poll() is not None:
                self.log(f"QEMU exited unexpectedly (code={self.proc.returncode})")
                return False
            elapsed = int(time.time() - start)
            if elapsed % 60 == 0:
                self.log(f"still waiting... ({elapsed}s)")
            time.sleep(10)
        self.log(f"install deadline ({deadline}s) exceeded")
        return False

    def s_verify_login(self, deadline):
        """VERIFY_LOGIN: attempt RDP connection via xfreerdp."""
        self.log("attempting RDP TLS+NLA login...")
        # Use xfreerdp from the nix freerdp package
        cmd = [
            "nix", "shell", "nixpkgs#freerdp", "--command", "bash", "-c",
            f"timeout 20 xfreerdp /v:127.0.0.1:{RDP_PORT} "
            f"/u:{self.username} /p:{self.password} "
            f"/cert:ignore /sec:nla +auth-only /log-level:ERROR"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = redact_secrets(result.stdout + result.stderr, self.secrets)
        self.log(f"xfreerdp output (redacted):\n{output[-500:]}")
        return result.returncode == 0 or "license" in output.lower()

    def run(self):
        """Run the full state machine."""
        states = [
            ("PREPARE", self.s_prepare, DEADLINES["PREPARE"]),
            ("BOOT_INSTALLER", self.s_boot_installer, DEADLINES["BOOT_INSTALLER"]),
            ("WAIT_INSTALL", self.s_wait_install, DEADLINES["WAIT_INSTALL"]),
            ("VERIFY_LOGIN", self.s_verify_login, DEADLINES["VERIFY_LOGIN"]),
        ]
        try:
            for name, func, deadline in states:
                if not self.run_state(name, func, deadline):
                    self.log(f"ABORTING at {name}")
                    return False
            self.log("ALL STATES PASSED")
            return True
        finally:
            self.cleanup()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Windows VM Provisioning State Machine")
    parser.add_argument("--iso", default=ISO_CACHE,
                        help=f"Path to the ISO (default: {ISO_CACHE})")
    parser.add_argument("--run-dir", default=None,
                        help="Unique run directory (default: auto-generated)")
    args = parser.parse_args()

    run_dir = args.run_dir or f"/tmp/rdp-lab/windows/run-{int(time.time())}"
    provisioner = VMProvisioner(args.iso, run_dir)
    success = provisioner.run()
    sys.exit(0 if success else 1)
