#!/usr/bin/env python3
import socket, struct, sys, time, subprocess, tempfile, os

SPICE_MAGIC = 0x51444552
OPENSSL = "/nix/store/vp9hb4wm56q2sl63q936crr0a0fr20d4-openssl-3.6.3-bin/bin/openssl"
HDR = struct.Struct("<HI")

def recv_exact(s, n):
    d = b''
    while len(d) < n:
        c = s.recv(n - len(d))
        if not c: raise EOFError
        d += c
    return d

def recv_msg(s):
    hdr = recv_exact(s, 6)
    mtype, msize = HDR.unpack(hdr)
    body = recv_exact(s, msize) if msize > 0 else b''
    return mtype, body

def pack_link(conn_id, chan_type, chan_id=0):
    caps = [0x0D]; ccaps = [0x0F] if chan_type == 1 else [0x01]
    body = struct.pack('<IBBIII', conn_id, chan_type, chan_id, len(caps), len(ccaps), 18)
    for c in caps: body += struct.pack('<I', c)
    for c in ccaps: body += struct.pack('<I', c)
    return struct.pack('<IIII', SPICE_MAGIC, 2, 2, len(body)) + body

def rsa_oaep(pk, plain=b'\x00'):
    with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as f:
        f.write(pk); kf = f.name
    pf,ef,inf = kf+'.pem',kf+'.enc',kf+'.in'
    try:
        subprocess.run([OPENSSL,'rsa','-inform','DER','-pubin','-in',kf,'-outform','PEM','-out',pf],capture_output=True,check=True)
        with open(inf,'wb') as i: i.write(plain)
        subprocess.run([OPENSSL,'pkeyutl','-encrypt','-inkey',pf,'-pubin','-pkeyopt','rsa_padding_mode:oaep','-pkeyopt','rsa_oaep_md:sha1','-in',inf,'-out',ef],capture_output=True,check=True)
        with open(ef,'rb') as e: return e.read()
    finally:
        for x in [kf,pf,ef,inf]:
            if os.path.exists(x): os.unlink(x)

def connect_channel(sock, ct, cid=0, chid=0):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10); s.connect(sock)
    s.sendall(pack_link(cid, ct, chid))
    h = recv_exact(s,16); _,_,_,sz = struct.unpack('<IIII',h)
    b = recv_exact(s,sz)
    if struct.unpack('<I',b[0:4])[0]: return None
    pk = b[4:166]
    s.sendall(struct.pack('<I',1)); s.sendall(rsa_oaep(pk))
    if struct.unpack('<I',recv_exact(s,4))[0]: return None
    return s

def main():
    sock = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/rdp-lab/win_setup.ppm"
    
    ms = connect_channel(sock, 1)
    if not ms: sys.exit(1)
    sid = None
    for _ in range(10):
        t, b = recv_msg(ms)
        if t == 103 and len(b) >= 4: sid = struct.unpack('<I', b[0:4])[0]; break
    ms.sendall(HDR.pack(104, 0))
    for _ in range(10):
        t, b = recv_msg(ms)
        if t == 104: break
    
    ds = connect_channel(sock, 2, cid=sid)
    if not ds: sys.exit(1)
    ds.sendall(HDR.pack(101, 24) + struct.pack('<IqQI', 0, 0, 0, 0))
    
    width, height = 800, 600
    for i in range(20):
        t, b = recv_msg(ds)
        print(f"  type={t} size={len(b)}")
        
        if t == 314 and len(b) >= 20:
            _, width, height, bpp, _ = struct.unpack('<IIIII', b[0:20])
            print(f"  Display info: {width}x{height} {bpp}bpp")
        
        if t == 304 and len(b) > 100:
            # This is the framebuffer data
            # Save raw for analysis
            with open(out + '.raw', 'wb') as f:
                f.write(b)
            
            # Try to save as PPM assuming BGRA 32bpp
            bpp = 4
            total = width * height * bpp
            print(f"  Pixel data: {len(b)} bytes, expected {total}")
            
            with open(out, 'wb') as f:
                f.write(f'P6\n{width} {height}\n255\n'.encode())
                for off in range(0, min(len(b), total), 4):
                    # BGRA -> RGB
                    if off + 2 < len(b):
                        f.write(bytes([b[off+2], b[off+1], b[off]]))
                    else:
                        f.write(b'\x00\x00\x00')
            
            print(f"  Saved PPM: {out}")
            png = out.replace('.ppm', '.png')
            subprocess.run(['sips', '-s', 'format', 'png', out, '--out', png], capture_output=True)
            print(f"  Saved PNG: {png}")
            break
    
    ds.close(); ms.close()

if __name__ == "__main__":
    main()
