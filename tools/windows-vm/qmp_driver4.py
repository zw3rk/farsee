#!/usr/bin/env python3
"""
QMP headless driver v4 — ramfb + serial file polling.

Uses ramfb (provides GOP via QemuRamfbDxe). Polls the serial log file
for new content. Sends Enter during boot window, waits for WinPE,
then Shift+F10 + for-loop to call f.cmd.
"""
import socket, json, time, sys, os

QMP_SOCK = "/tmp/rdp-lab/windows/run-vnc/qmp.sock"
SERIAL_LOG = "/tmp/rdp-lab/windows/run-vnc/serial.log"

SCANCODES = {
    'a': 0x1e, 'b': 0x30, 'c': 0x2e, 'd': 0x20, 'e': 0x12,
    'f': 0x21, 'g': 0x22, 'h': 0x23, 'i': 0x17, 'j': 0x24,
    'k': 0x25, 'l': 0x26, 'm': 0x32, 'n': 0x31, 'o': 0x18,
    'p': 0x19, 'q': 0x10, 'r': 0x13, 's': 0x1f, 't': 0x14,
    'u': 0x16, 'v': 0x2f, 'w': 0x11, 'x': 0x2d, 'y': 0x15,
    'z': 0x2c,
    '0': 0x0b, '1': 0x02, '2': 0x03, '3': 0x04, '4': 0x05,
    '5': 0x06, '6': 0x07, '7': 0x08, '8': 0x09, '9': 0x0a,
    ' ': 0x39, '-': 0x0c, '=': 0x0d, '\\': 0x2b,
    ';': 0x27, ',': 0x33, '.': 0x34, '/': 0x35,
    '%': (0x06, True), '(': (0x0a, True), ')': (0x0b, True),
    '@': (0x03, True), ':': (0x27, True), '_': (0x0c, True),
}
SHIFT = 0x2a
ENTER = 0x1c
F10 = 0x44

def qmp_connect():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(QMP_SOCK)
    s.recv(4096)
    s.sendall(json.dumps({"execute": "qmp_capabilities"}).encode())
    time.sleep(0.5)
    s.recv(4096)
    return s

def qmp_drain(s):
    s.settimeout(0.3)
    try:
        while True:
            if not s.recv(4096): break
    except socket.timeout: pass
    s.settimeout(10)

def key_event(s, sc, down):
    val = sc if down else (sc | 0x80)
    s.sendall(json.dumps({
        "execute": "send-key",
        "arguments": {"keys": [{"type": "number", "data": val}]}
    }).encode())
    time.sleep(0.02)
    qmp_drain(s)

def press(s, sc, delay=0.15):
    key_event(s, sc, True)
    time.sleep(0.03)
    key_event(s, sc, False)
    time.sleep(delay)

def press_shift(s, sc, delay=0.15):
    key_event(s, SHIFT, True)
    time.sleep(0.03)
    key_event(s, sc, True)
    time.sleep(0.03)
    key_event(s, sc, False)
    time.sleep(0.03)
    key_event(s, SHIFT, False)
    time.sleep(delay)

def type_str(s, text, delay=0.1):
    for c in text:
        sc = SCANCODES.get(c.lower())
        if sc is None: continue
        if isinstance(sc, tuple):
            press_shift(s, sc[0], delay)
        else:
            press(s, sc, delay)

def read_serial():
    try:
        with open(SERIAL_LOG, 'rb') as f:
            return f.read().decode('ascii', errors='replace')
    except FileNotFoundError:
        return ''

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

# ============================================================
log("Connecting to QMP...")
qmp = qmp_connect()
log("QMP connected.")

# Phase 1: Enter spam during boot window
log("Phase 1: Enter spam (catching 'Press any key')...")
for i in range(15):
    press(qmp, ENTER, 0.3)
    serial = read_serial()
    if "Press any key" in serial:
        log(">>> 'Press any key' detected!")
    if "Loading files" in serial or "llll" in serial:
        log(">>> WinPE loading!")
        break
    if "Shell>" in serial:
        log(">>> EFI Shell (CD boot missed)")
        break

# Phase 2: Wait for WinPE to load
log("Phase 2: Waiting for WinPE...")
winpe_ready = False
for wait in range(36):  # 360s max
    time.sleep(10)
    serial = read_serial()

    if "llll" in serial or "Loading files" in serial:
        if not winpe_ready:
            log(">>> WinPE progress bars detected")
            winpe_ready = True
    if winpe_ready and wait >= 9:  # 90s after first progress bar
        log("WinPE should be ready.")
        break
    if wait % 3 == 2:
        log(f"  Waiting... ({(wait+1)*10}s, serial={len(serial)} bytes)")

# Print serial summary
serial = read_serial()
log(f"Serial total: {len(serial)} bytes")
# Show last meaningful content
for line in serial[-500:].split('\n'):
    s = line.strip().replace('\x1b[', '')
    if s and not all(c in '=0123456789;Hm' for c in s):
        log(f"  TAIL: {s[:100]}")

# Phase 3: Shift+F10
log("Phase 3: Shift+F10...")
key_event(qmp, SHIFT, True)
time.sleep(0.05)
key_event(qmp, F10, True)
time.sleep(0.05)
key_event(qmp, F10, False)
time.sleep(0.05)
key_event(qmp, SHIFT, False)
time.sleep(5)

# Phase 4: Type for-loop
cmd = 'for %d in (d e f g h i j k) do @if exist %d:\\f.cmd call %d:\\f.cmd'
log(f"Phase 4: Typing ({len(cmd)} chars)...")
type_str(qmp, cmd, 0.1)
time.sleep(1)
press(qmp, ENTER, 2)

# Phase 5: Monitor serial for COM1 markers
log("Phase 5: Monitoring for f.cmd output (300s)...")
seen = set()
for check in range(60):
    time.sleep(5)
    serial = read_serial()
    markers = [
        "F.CMD", "Autounattend", "install.wim", "setup.exe",
        "FINISHED", "ERROR", "DEPLOY", "COLLECT", "COM1",
        "Panther", "DiskPart", "DISM", "BCDBoot",
    ]
    for m in markers:
        if m in serial and m not in seen:
            seen.add(m)
            # Find the line containing it
            for line in serial.split('\n'):
                if m in line:
                    log(f">>> [{m}] {line.strip()[:150]}")
                    break
    if "F.CMD FINISHED" in serial or "DEPLOY.CMD COMPLETE" in serial:
        log("Deployment complete!")
        break

# Disk check
r = os.popen('ls -la /tmp/rdp-lab/windows/qemu-nvme.qcow2').read().strip()
log(f"Disk: {r}")

log("\n=== SERIAL (last 2000 chars) ===")
print(read_serial()[-2000:])

qmp.close()
log("Done.")
