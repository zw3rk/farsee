#!/usr/bin/env python3
"""Minimal VNC client for automating macOS Setup Assistant via tart's experimental VNC."""
import socket, struct, hashlib, sys, time

def vnc_auth(host, port, password):
    s = socket.create_connection((host, port), timeout=10)
    s.recv(12)  # banner
    s.sendall(b'RFB 003.008\n')
    # security types
    data = s.recv(100)
    # type 2 = VNC auth
    s.sendall(bytes([2]))
    # 16-byte challenge
    challenge = s.recv(16)
    # DES-encrypt challenge with bit-reversed password key
    from Crypto.Cipher import DES
    key = password.ljust(8, '\0')[:8].encode()
    key = bytes(int('{:08b}'.format(b)[::-1], 2) for b in key)
    cipher = DES.new(key, DES.MODE_ECB)
    response = cipher.encrypt(challenge)
    s.sendall(response)
    # security result
    result = struct.unpack('>I', s.recv(4))[0]
    if result != 0:
        raise Exception(f"VNC auth failed: {result}")
    # ClientInit (shared=1)
    s.sendall(bytes([1]))
    # ServerInit
    data = b''
    while len(data) < 24:
        data += s.recv(24 - len(data))
    w, h = struct.unpack('>HH', data[0:4])
    name_len = struct.unpack('>I', data[20:24])[0]
    name = s.recv(name_len)
    print(f"ServerInit: {w}x{h} name={name}")
    return s, w, h

def send_key(s, down, key):
    s.sendall(struct.pack('>BBHI', 4, down, 0, key))

def send_pointer(s, x, y, mask):
    s.sendall(struct.pack('>BBHH', 5, mask, x, y))

def click(s, x, y):
    send_pointer(s, x, y, 0)
    time.sleep(0.1)
    send_pointer(s, x, y, 1)  # left button down
    time.sleep(0.1)
    send_pointer(s, x, y, 0)  # release

def type_text(s, text):
    for c in text:
        send_key(s, 1, ord(c))
        time.sleep(0.05)
        send_key(s, 0, ord(c))
        time.sleep(0.05)

def request_framebuffer(s, w, h):
    # SetPixelFormat (32bpp RGBA-ish)
    s.sendall(struct.pack('>BBBBHHHBBBBBB', 0,0,0,0, 32,24,1,0,255,0,255,0,255) + b'\x00\x10\x08\x00\x00\x00')
    # FramebufferUpdateRequest (incremental=0)
    s.sendall(struct.pack('>BBHHHHH', 3, 0, 0, 0, w, h))
    time.sleep(1)
    data = s.recv(65536)
    return data

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 60303
    password = sys.argv[3] if len(sys.argv) > 3 else 'coach-team-zoo-noise'
    s, w, h = vnc_auth(host, port, password)
    print(f"Connected: {w}x{h}")
    # Grab a framebuffer frame
    data = request_framebuffer(s, w, h)
    with open('/tmp/vnc_frame.bin', 'wb') as f:
        f.write(data)
    print(f"Saved {len(data)} bytes to /tmp/vnc_frame.bin")
    s.close()
