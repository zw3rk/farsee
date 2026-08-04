#!/usr/bin/env python3
"""SPICE client — keep main channel open while connecting inputs."""
import socket, struct, sys, time, subprocess, tempfile, os

SPICE_MAGIC = 0x51444552
OPENSSL = "/nix/store/vp9hb4wm56q2sl63q936crr0a0fr20d4-openssl-3.6.3-bin/bin/openssl"
HDR = struct.Struct("<HI")  # 6-byte mini header

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
    caps = [0x0D]
    ccaps = [0x0F] if chan_type == 1 else [0x01]
    body = struct.pack('<IBBIII', conn_id, chan_type, chan_id, len(caps), len(ccaps), 18)
    for c in caps: body += struct.pack('<I', c)
    for c in ccaps: body += struct.pack('<I', c)
    return struct.pack('<IIII', SPICE_MAGIC, 2, 2, len(body)) + body

def rsa_oaep(pubkey_der, plain=b'\x00'):
    with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as f:
        f.write(pubkey_der); kf = f.name
    pf, ef, inf = kf+'.pem', kf+'.enc', kf+'.in'
    try:
        subprocess.run([OPENSSL,'rsa','-inform','DER','-pubin','-in',kf,'-outform','PEM','-out',pf], capture_output=True, check=True)
        with open(inf,'wb') as i: i.write(plain)
        subprocess.run([OPENSSL,'pkeyutl','-encrypt','-inkey',pf,'-pubin','-pkeyopt','rsa_padding_mode:oaep','-pkeyopt','rsa_oaep_md:sha1','-in',inf,'-out',ef], capture_output=True, check=True)
        with open(ef,'rb') as e: return e.read()
    finally:
        for x in [kf,pf,ef,inf]:
            if os.path.exists(x): os.unlink(x)

def connect_channel(sock_path, chan_type, conn_id=0, chan_id=0):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sock_path)
    s.sendall(pack_link(conn_id, chan_type, chan_id))
    hdr = recv_exact(s, 16)
    _, _, _, size = struct.unpack('<IIII', hdr)
    body = recv_exact(s, size)
    err = struct.unpack('<I', body[0:4])[0]
    if err: return None, err
    pubkey = body[4:4+162]
    s.sendall(struct.pack('<I', 1))
    s.sendall(rsa_oaep(pubkey))
    r = struct.unpack('<I', recv_exact(s, 4))[0]
    if r: return None, r
    return s, 0

def send_key(s, scancode, down):
    mtype = 101 if down else 102
    body = struct.pack('<I', scancode)
    s.sendall(HDR.pack(mtype, len(body)) + body)

def main():
    sock = sys.argv[1] if len(sys.argv) > 1 else "/tmp/utm-spice.sock"
    keys = [int(x) for x in sys.argv[2:]] if len(sys.argv) > 2 else [57]
    
    # Step 1: Main channel (KEEP OPEN)
    print("Main channel...")
    main_s, err = connect_channel(sock, 1)
    if err: print(f"  Error: {err}", file=sys.stderr); sys.exit(1)
    print("  Authenticated!")
    
    # Read MAIN_INIT
    session_id = None
    for _ in range(10):
        mtype, mbody = recv_msg(main_s)
        if mtype == 103 and len(mbody) >= 4:
            session_id = struct.unpack('<I', mbody[0:4])[0]
            print(f"  Session: {session_id}")
            break
    
    if not session_id: sys.exit(1)
    
    # Send ATTACH_CHANNELS
    main_s.sendall(HDR.pack(104, 0))
    
    # Read CHANNELS_LIST
    inputs_id = None
    for _ in range(10):
        mtype, mbody = recv_msg(main_s)
        if mtype == 104 and len(mbody) >= 4:
            count = struct.unpack('<I', mbody[0:4])[0]
            off = 4
            for i in range(count):
                ct = mbody[off]; ci = mbody[off+1]
                if ct == 3: inputs_id = ci
                off += 2
            break
    
    print(f"  Inputs channel id: {inputs_id}")
    
    # Step 2: Inputs channel (while main stays open)
    print("Inputs channel...")
    in_s, err = connect_channel(sock, 3, conn_id=session_id, chan_id=inputs_id)
    if err:
        print(f"  Error: {err}", file=sys.stderr)
        # Try without chan_id
        print("  Retrying with chan_id=0...")
        in_s, err = connect_channel(sock, 3, conn_id=session_id, chan_id=0)
        if err: print(f"  Still error: {err}", file=sys.stderr); sys.exit(1)
    
    print("  Authenticated!")
    
    # Read INPUTS_INIT
    mtype, mbody = recv_msg(in_s)
    print(f"  msg type={mtype} size={len(mbody)}")
    
    # Send keys!
    for k in keys:
        send_key(in_s, k, True)
        time.sleep(0.05)
        send_key(in_s, k, False)
        time.sleep(0.1)
        print(f"  Sent key {k}")
    
    time.sleep(0.5)
    in_s.close()
    main_s.close()
    print("Done!")

if __name__ == "__main__":
    main()
