#!/usr/bin/env python3
"""VNC key event sender for QEMU ARM64 VM.
Sends key press/release events via VNC protocol.
Keys use X11 keysym values.
"""
import socket, struct, sys, time

# X11 keysym values for common keys
KEYSYM = {
    'enter': 0xFF0D,
    'esc': 0xFF1B,
    'tab': 0xFF09,
    'space': 0x0020,
    'backspace': 0xFF08,
    'up': 0xFF52,
    'down': 0xFF54,
    'left': 0xFF51,
    'right': 0xFF53,
    'f1': 0xFFBE, 'f2': 0xFFBF, 'f3': 0xFFC0, 'f4': 0xFFC1,
    'f5': 0xFFC2, 'f6': 0xFFC3, 'f7': 0xFFC4, 'f8': 0xFFC5,
    'f9': 0xFFC6, 'f10': 0xFFC7, 'f11': 0xFFC8, 'f12': 0xFFC9,
    'shift': 0xFFE1,
    'ctrl': 0xFFE3,
    'alt': 0xFFE9,
    'home': 0xFF50,
    'end': 0xFF57,
    'pageup': 0xFF55,
    'pagedown': 0xFF56,
    'delete': 0xFFFF,
    'insert': 0xFF63,
}

def char_to_keysym(c):
    """Convert ASCII character to X11 keysym"""
    return ord(c)

def vnc_connect(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15)
    s.connect((host, port))
    # Handshake
    s.recv(12)
    s.sendall(b'RFB 003.008\n')
    n = struct.unpack('>B', s.recv(1))[0]
    if n > 0: s.recv(n)
    s.sendall(struct.pack('>B', 1))  # None
    struct.unpack('>I', s.recv(4))[0]
    s.sendall(struct.pack('>B', 1))  # shared
    w = struct.unpack('>H', s.recv(2))[0]
    h = struct.unpack('>H', s.recv(2))[0]
    s.recv(16)  # pixel format
    name_len = struct.unpack('>I', s.recv(4))[0]
    s.recv(name_len)
    return s, w, h

def vnc_key_event(s, keysym, down=True):
    """Send a VNC key event. down=True for press, False for release."""
    s.sendall(struct.pack('>BBHI', 4, 1 if down else 0, 0, keysym))

def vnc_press_key(s, keysym, delay=0.2):
    """Press and release a key."""
    vnc_key_event(s, keysym, True)
    time.sleep(0.05)
    vnc_key_event(s, keysym, False)
    time.sleep(delay)

def vnc_type_string(s, text, delay=0.15):
    """Type a string character by character."""
    for c in text:
        vnc_press_key(s, char_to_keysym(c), delay)

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5901
    key = sys.argv[3] if len(sys.argv) > 3 else 'enter'
    count = int(sys.argv[4]) if len(sys.argv) > 4 else 1

    s, w, h = vnc_connect(host, port)
    print(f"Connected to VNC {w}x{h}")

    if key in KEYSYM:
        ks = KEYSYM[key]
        for _ in range(count):
            vnc_press_key(s, ks, 0.5)
            print(f"Sent: {key}")
    elif key == 'type':
        # type a string: arg5 is the string
        text = sys.argv[5] if len(sys.argv) > 5 else ''
        vnc_type_string(s, text)
        print(f"Typed: {text}")
    else:
        # Treat as literal characters
        vnc_type_string(s, key)
        print(f"Typed: {key}")

    s.close()
