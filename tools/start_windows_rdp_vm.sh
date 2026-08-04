#!/usr/bin/env bash
# Boot the lab Win11-RDP UTM disk with RDP hostfwd on 127.0.0.1:13390.
# Daemonizes QEMU so this script exits after the guest is up (pidfile written).
set -euo pipefail

DISK="${DISK:-$HOME/Library/Containers/com.utmapp.UTM/Data/Documents/Win11-RDP.utm/Data/DD1F7D67-0DE3-4D76-A246-97F76B76D1C1.qcow2}"
BIOS="${BIOS:-/Applications/UTM.app/Contents/Resources/qemu/edk2-aarch64-code.fd}"
PIDFILE="${PIDFILE:-/tmp/qemu.pid}"
SERIAL="${SERIAL:-/tmp/serial.log}"
VNC="${VNC:-127.0.0.1:1}"
RDP_FWD="${RDP_FWD:-tcp:127.0.0.1:13390-:3389}"

if [[ ! -f "$DISK" ]]; then
  echo "error: disk not found: $DISK" >&2
  exit 1
fi
if [[ ! -f "$BIOS" ]]; then
  echo "error: BIOS not found: $BIOS" >&2
  exit 1
fi

if [[ -f "$PIDFILE" ]]; then
  old=$(cat "$PIDFILE" 2>/dev/null || true)
  if [[ -n "${old:-}" ]] && kill -0 "$old" 2>/dev/null; then
    echo "already running pid=$old"
    exit 0
  fi
  rm -f "$PIDFILE"
fi

# Stop a previous instance by pidfile / basename only (no self-matching -f).
if pgrep -x qemu-system-aarch64 >/dev/null 2>&1; then
  pkill -x qemu-system-aarch64 || true
  sleep 1
fi

rm -f "$SERIAL"
cd /Users/angerman/Projects/zw3rk/vnc

# Prefer nix-provided QEMU when available.
QEMU_BIN=$(command -v qemu-system-aarch64 || true)
if [[ -z "$QEMU_BIN" ]]; then
  echo "error: qemu-system-aarch64 not in PATH (enter nix develop)" >&2
  exit 1
fi

echo "starting: $QEMU_BIN"
echo "  disk=$DISK"
echo "  rdp-forward=$RDP_FWD"
echo "  pidfile=$PIDFILE"
echo "  vnc=$VNC (display :${VNC##*:} → TCP $((5900 + ${VNC##*:})) )"

# Background so the launcher exits; agent UIs do not look "stuck" on exec.
"$QEMU_BIN" \
  -accel hvf -cpu host -smp 4 -m 4096 -machine virt \
  -bios "$BIOS" \
  -device ramfb -display none -vnc "$VNC" \
  -device qemu-xhci -device usb-kbd -device usb-tablet \
  -drive "file=$DISK,if=none,id=nvme0" \
  -device nvme,drive=nvme0,serial=nvme0 \
  -netdev "user,id=net0,hostfwd=$RDP_FWD" \
  -device virtio-net-pci,netdev=net0 \
  -serial "file:$SERIAL" \
  -pidfile "$PIDFILE" \
  -daemonize

# Wait briefly for pidfile (daemonize writes it before returning).
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if [[ -f "$PIDFILE" ]]; then
    pid=$(cat "$PIDFILE" 2>/dev/null || true)
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      echo "running pid=$pid"
      echo "  RDP: 127.0.0.1:13390"
      echo "  VNC: 127.0.0.1:$((5900 + ${VNC##*:}))"
      echo "  stop: kill \$(cat $PIDFILE)"
      exit 0
    fi
  fi
  sleep 0.2
done

echo "error: QEMU did not write a live pidfile at $PIDFILE" >&2
exit 1
