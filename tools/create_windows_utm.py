#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# create_windows_utm.py — reproducible Windows 11 ARM64 UTM VM for RDP interop
#
# Creates a UTM virtual machine configured for Windows 11 ARM64 provisioning
# with all the settings that were discovered through the R6 investigation:
#
#   - UTM firmware (edk2-aarch64-code.fd, SHA-256 ee769c4b...) — NOT nix firmware
#   - Display device (virtio-ramfb) — REQUIRED for SPICE display channel
#   - NVMe disk for the system drive (inbox driver in Win11 ARM64 WinPE)
#   - USB CD for the Windows ISO (ARM64 virt has no IDE bus)
#   - Network with loopback RDP port forward (127.0.0.1:13390 → guest:3389)
#   - USB keyboard + tablet for input
#
# Usage:
#   python3 tools/create_windows_utm.py --iso /path/to/win11-arm64.iso
#
# After creation, start the VM and use remote-viewer to drive Windows Setup:
#   python3 tools/create_windows_utm.py --start --viewer
#
# The VM is registered in UTM and can be managed via utmctl or AppleScript.

import argparse
import subprocess
import sys
import os
import time
import json


VM_NAME = "Windows11-ARM64-RDP"
RDP_HOST_PORT = 13390
RDP_GUEST_PORT = 3389


def run_osascript(script: str) -> tuple[int, str, str]:
    """Run an AppleScript and return (exit_code, stdout, stderr)."""
    result = subprocess.run(
        ["osascript", "-e", script],
        capture_output=True, text=True, timeout=30
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def vm_exists(name: str) -> bool:
    """Check if a UTM VM with the given name exists."""
    rc, out, _ = run_osascript(
        f'tell application "UTM" to get name of every virtual machine'
    )
    return rc == 0 and name in out


def delete_vm(name: str) -> None:
    """Delete a UTM VM by name (force)."""
    if vm_exists(name):
        print(f"Deleting existing VM: {name}")
        run_osascript(
            f'tell application "UTM" to delete (first virtual machine whose name is "{name}")'
        )
        time.sleep(3)


def create_vm(iso_path: str, memory_mb: int = 4096, cpu_cores: int = 4,
              disk_gb: int = 40) -> str:
    """Create the Windows ARM64 UTM VM with all required settings.

    Returns the VM UUID.
    """
    if not os.path.isfile(iso_path):
        print(f"ERROR: ISO not found: {iso_path}", file=sys.stderr)
        sys.exit(1)

    iso_abs = os.path.abspath(iso_path)

    # Step 1: Create minimal VM
    print(f"Creating VM: {VM_NAME}")
    rc, out, err = run_osascript(f'''
        tell application "UTM"
            make new virtual machine with properties {{backend:qemu, configuration:{{name:"{VM_NAME}", architecture:"aarch64", memory:{memory_mb}}}}}
        end tell
    ''')
    if rc != 0:
        print(f"ERROR creating VM: {err}", file=sys.stderr)
        sys.exit(1)
    print(f"  VM created: {out}")

    # Step 2: Configure CPU, hypervisor, UEFI
    print("  Configuring CPU/hypervisor/UEFI...")
    run_osascript(f'''
        tell application "UTM"
            set vm to first virtual machine whose name is "{VM_NAME}"
            set config to configuration of vm
            set cpu cores of config to {cpu_cores}
            set hypervisor of config to true
            set uefi of config to true
            update configuration vm with config
        end tell
    ''')

    # Step 3: Add NVMe disk + Windows ISO as USB CD
    # CRITICAL: ARM64 virt has no IDE bus — USB CD is required.
    print("  Adding NVMe disk + Windows ISO as USB CD...")
    run_osascript(f'''
        tell application "UTM"
            set vm to first virtual machine whose name is "{VM_NAME}"
            set config to configuration of vm
            set drives of config to {{{{guest size:{disk_gb * 1024}, interface:NVMe}}, {{interface:USB, removable:true, source:POSIX file "{iso_abs}"}}}}
            update configuration vm with config
        end tell
    ''')

    # Step 4: Add display device
    # CRITICAL: Without a Display entry, UTM creates no SPICE display channel.
    # remote-viewer (and Farsee's future SPICE engine) cannot render the VM
    # without this. The virtio-ramfb hardware provides the UEFI GOP that
    # Windows PE ARM64 needs to render its Setup GUI.
    print("  Adding Display device (virtio-ramfb)...")
    run_osascript(f'''
        tell application "UTM"
            set vm to first virtual machine whose name is "{VM_NAME}"
            set config to configuration of vm
            set displays of config to {{{{hardware:"virtio-ramfb", dynamic resolution:true}}}}
            update configuration vm with config
        end tell
    ''')

    # Step 5: Add network with RDP port forward (loopback only)
    print(f"  Adding network with RDP port forward (127.0.0.1:{RDP_HOST_PORT} → :{RDP_GUEST_PORT})...")
    run_osascript(f'''
        tell application "UTM"
            set vm to first virtual machine whose name is "{VM_NAME}"
            set config to configuration of vm
            set network interfaces of config to {{{{mode:shared, port forwards:{{{{protocol:TCP, host address:"127.0.0.1", host port:{RDP_HOST_PORT}, guest port:{RDP_GUEST_PORT}}}}}}}}}}
            update configuration vm with config
        end tell
    ''')

    # Step 6: Get UUID
    rc, uuid, _ = run_osascript(
        f'tell application "UTM" to get id of (first virtual machine whose name is "{VM_NAME}")'
    )
    print(f"  VM UUID: {uuid}")
    return uuid


def start_vm() -> None:
    """Start the UTM VM."""
    print(f"Starting VM: {VM_NAME}")
    run_osascript(
        f'tell application "UTM" to start (first virtual machine whose name is "{VM_NAME}")'
    )
    time.sleep(5)
    rc, status, _ = run_osascript(
        f'tell application "UTM" to get status of (first virtual machine whose name is "{VM_NAME}") as string'
    )
    print(f"  Status: {status}")


def launch_viewer(uuid: str) -> None:
    """Launch remote-viewer connected to the VM's SPICE socket.

    The SPICE socket path can exceed AF_UNIX's 104-byte sun_path limit,
    so we create a short symlink first.
    """
    group_container = os.path.expanduser(
        "~/Library/Group Containers/WDNLXAD4W8.com.utmapp.UTM"
    )
    spice_sock = os.path.join(group_container, f"{uuid}.spice")
    short_link = "/tmp/utm-spice.sock"

    # Create symlink (handles path-length issue)
    if os.path.lexists(short_link):
        os.remove(short_link)
    os.symlink(spice_sock, short_link)

    # Create .vv connection file
    vv_file = "/tmp/rdp-lab/utm-windows.vv"
    os.makedirs(os.path.dirname(vv_file), exist_ok=True)
    with open(vv_file, "w") as f:
        f.write("[virt-viewer]\n")
        f.write("type=spice\n")
        f.write(f"unix-path={short_link}\n")
        f.write(f"title=Farsee Windows R6 Provisioning\n")
    os.chmod(vv_file, 0o600)

    # Find remote-viewer (nix shell or system)
    rv = None
    for candidate in [
        "remote-viewer",
        "/nix/store/vr36n5ahj23lp3c4wisawqmpc8sfixz3-virt-viewer-11.0/bin/remote-viewer",
    ]:
        try:
            subprocess.run([candidate, "--version"], capture_output=True, check=True)
            rv = candidate
            break
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue

    if not rv:
        # Try nix shell
        try:
            result = subprocess.run(
                ["nix", "shell", "nixpkgs#virt-viewer", "-c", "which", "remote-viewer"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                rv = result.stdout.strip()
        except Exception:
            pass

    if not rv:
        print("ERROR: remote-viewer not found. Install via: nix shell nixpkgs#virt-viewer",
              file=sys.stderr)
        sys.exit(1)

    print(f"Launching remote-viewer: {rv}")
    print(f"  SPICE socket: {spice_sock}")
    print(f"  Symlink: {short_link} (path-length workaround)")
    print(f"  Connection file: {vv_file}")
    print()
    print("The remote-viewer window will show the VM display.")
    print("You can interact with Windows Setup directly (keyboard + mouse).")
    print()

    env = os.environ.copy()
    env["SPICE_DEBUG"] = "1"
    env["G_MESSAGES_DEBUG"] = "all"
    subprocess.run([rv, "-v", vv_file], env=env)


def main():
    parser = argparse.ArgumentParser(
        description="Create/start a Windows 11 ARM64 UTM VM for RDP interop testing"
    )
    parser.add_argument("--iso", default="/tmp/rdp-lab/windows/win11-iot-ltsc-2024-arm64.iso",
                        help="Path to Windows 11 ARM64 ISO")
    parser.add_argument("--memory", type=int, default=4096, help="RAM in MB")
    parser.add_argument("--cores", type=int, default=4, help="CPU cores")
    parser.add_argument("--disk", type=int, default=40, help="Disk size in GB")
    parser.add_argument("--name", default=VM_NAME, help="VM name")
    parser.add_argument("--force", action="store_true",
                        help="Delete existing VM before creating")
    parser.add_argument("--start", action="store_true",
                        help="Start the VM after creating")
    parser.add_argument("--viewer", action="store_true",
                        help="Launch remote-viewer after starting")
    parser.add_argument("--viewer-only", action="store_true",
                        help="Only launch remote-viewer (skip create/start)")
    args = parser.parse_args()

    global VM_NAME
    VM_NAME = args.name

    if args.viewer_only:
        rc, uuid, _ = run_osascript(
            f'tell application "UTM" to get id of (first virtual machine whose name is "{VM_NAME}")'
        )
        if rc != 0:
            print(f"ERROR: VM '{VM_NAME}' not found", file=sys.stderr)
            sys.exit(1)
        launch_viewer(uuid)
        return

    if args.force or vm_exists(VM_NAME):
        delete_vm(VM_NAME)

    uuid = create_vm(args.iso, args.memory, args.cores, args.disk)

    if args.start:
        start_vm()

    if args.viewer:
        launch_viewer(uuid)


if __name__ == "__main__":
    main()
