#!/usr/bin/env python3
"""VNC framebuffer capture for QEMU ARM64 VM.
Connects to QEMU's VNC display, reads the full framebuffer, saves as PNG.
"""
import socket, struct, sys, time, os

def capture(host, port, output_path):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15)
    s.connect((host, port))

    # Handshake
    s.recv(12)  # RFB version
    s.sendall(b'RFB 003.008\n')
    n = struct.unpack('>B', s.recv(1))[0]
    if n > 0: s.recv(n)  # security types
    s.sendall(struct.pack('>B', 1))  # None
    struct.unpack('>I', s.recv(4))[0]  # result
    s.sendall(struct.pack('>B', 1))  # ClientInit shared

    w = struct.unpack('>H', s.recv(2))[0]
    h = struct.unpack('>H', s.recv(2))[0]
    pf = s.recv(16)
    bpp = pf[0]
    name_len = struct.unpack('>I', s.recv(4))[0]
    name = s.recv(name_len)

    # Request full framebuffer (incremental=0)
    s.sendall(struct.pack('>BBHHHH', 3, 0, 0, 0, w, h))
    time.sleep(2)

    # Read FramebufferUpdate header
    header = b''
    while len(header) < 4:
        chunk = s.recv(4 - len(header))
        if not chunk: break
        header += chunk

    if header[0] != 0:
        print(f"Unexpected message type: {header[0]}")
        s.close()
        return False

    num_rects = struct.unpack('>H', header[2:4])[0]

    for i in range(num_rects):
        # Read rectangle header
        rect_hdr = b''
        while len(rect_hdr) < 12:
            chunk = s.recv(12 - len(rect_hdr))
            if not chunk: break
            rect_hdr += chunk

        x, y, rw, rh, enc = struct.unpack('>HHHHI', rect_hdr)

        if enc == 0:  # Raw
            bytes_per_pixel = bpp // 8
            expected = rw * rh * bytes_per_pixel
            data = b''
            while len(data) < expected:
                chunk = s.recv(min(131072, expected - len(data)))
                if not chunk: break
                data += chunk

            # Save as PNG using PIL if available
            try:
                from PIL import Image
                # QEMU VNC sends XRGB (BGRX in little-endian memory)
                img = Image.frombytes('RGBX', (rw, rh), data, 'raw', 'BGRX')
                img = img.convert('RGB')
                img.save(output_path)
                print(f"Saved {output_path} ({rw}x{rh})")
            except ImportError:
                # Save as PPM
                with open(output_path + '.ppm', 'wb') as f:
                    f.write(f'P6\n{rw} {rh}\n255\n'.encode())
                    for idx in range(0, len(data), 4):
                        b, g, r = data[idx], data[idx+1], data[idx+2]
                        f.write(bytes([r, g, b]))
                print(f"Saved {output_path}.ppm ({rw}x{rh})")
        elif enc == 16:  # DesktopSize pseudo-encoding
            print(f"  Desktop size changed to {rw}x{rh}")
        else:
            print(f"  Unsupported encoding {enc}, skipping")
            break

    s.close()
    return True

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5901
    output = sys.argv[3] if len(sys.argv) > 3 else '/tmp/rdp-lab/windows/run-vnc/vnc_capture.png'
    capture(host, port, output)
