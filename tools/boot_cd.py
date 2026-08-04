import socket, struct, time, sys, threading

def vnc_connect_key(host, port, key_sym, delay_before, delay_after):
    """Connect to VNC and press a single key after delay_before seconds."""
    time.sleep(delay_before)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))
        s.recv(12)
        s.sendall(b'RFB 003.008\n')
        n = struct.unpack('>B', s.recv(1))[0]
        if n > 0: s.recv(n)
        s.sendall(struct.pack('>B', 1))
        struct.unpack('>I', s.recv(4))[0]
        s.sendall(struct.pack('>B', 1))
        w = struct.unpack('>H', s.recv(2))[0]
        h = struct.unpack('>H', s.recv(2))[0]
        s.recv(16)
        name_len = struct.unpack('>I', s.recv(4))[0]
        s.recv(name_len)
        # Press key
        s.sendall(struct.pack('>BBHI', 4, 1, 0, key_sym))  # down
        time.sleep(0.1)
        s.sendall(struct.pack('>BBHI', 4, 0, 0, key_sym))  # up
        print(f"Pressed key {key_sym} on {w}x{h} display")
        time.sleep(delay_after)
        s.close()
    except Exception as e:
        print(f"VNC key error: {e}")

# Connect and press space at exactly 3s into the boot
t = threading.Thread(target=vnc_connect_key, args=("127.0.0.1", 5901, 0x0020, 3.0, 1.0))
t.start()
t.join()
print("Done")
