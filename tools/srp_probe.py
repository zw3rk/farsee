#!/usr/bin/env python3
"""Systematically test SRP formula variants against the live VM."""
import hashlib, hmac, socket, struct, subprocess, time, sys, os

def pbkdf2(password, salt, iterations, dklen=128):
    return hashlib.pbkdf2_hmac('sha512', password, salt, iterations, dklen)

def sha512(*args):
    h = hashlib.sha512()
    for a in args:
        h.update(a)
    return h.digest()

def sha256(data):
    return hashlib.sha256(data).digest()

def modexp(base, exp, mod):
    return pow(int.from_bytes(base, 'big'), int.from_bytes(exp, 'big'), int.from_bytes(mod, 'big')).to_bytes(len(mod), 'big')

def modmul(a, b, mod):
    return ((int.from_bytes(a, 'big') * int.from_bytes(b, 'big')) % int.from_bytes(mod, 'big')).to_bytes(len(mod), 'big')

def modadd(a, b, mod):
    return ((int.from_bytes(a, 'big') + int.from_bytes(b, 'big')) % int.from_bytes(mod, 'big')).to_bytes(len(mod), 'big')

def modsub(a, b, mod):
    N = int.from_bytes(mod, 'big')
    return ((int.from_bytes(a, 'big') - int.from_bytes(b, 'big')) % N).to_bytes(len(mod), 'big')

def pad(val, n):
    b = val if isinstance(val, bytes) else val.to_bytes((val.bit_length()+7)//8 or 1, 'big')
    return b.rjust(n, b'\x00')

def do_auth(host, port, username, password, variant_x, variant_m1_i):
    """Try one SRP variant. Returns (success, sr_result, resp_hex)."""
    try:
        s = socket.create_connection((host, port), timeout=10)
        s.recv(12)
        s.sendall(b'RFB 003.889\n')
        count = s.recv(1)[0]
        s.recv(count)
        s.sendall(bytes([33]))

        # Key request
        s.sendall(bytes([0x21,0x00,0x00,0x00,0x0a,0x01,0x00,0x52,0x53,0x41,0x31,0x00,0x00,0x00,0x00]))

        # Key response
        kr = s.recv(4096)
        der_len = struct.unpack(">H", kr[8:10])[0]
        spki = kr[10:10+der_len]

        # Packet 1
        proc = subprocess.run(["build/probe_packet1"], input=spki, capture_output=True)
        s.sendall(proc.stdout)

        # Challenge
        time.sleep(1)
        ch = s.recv(8192)
        total_len = struct.unpack(">I", ch[0:4])[0]

        # Parse challenge
        N = ch[17:17+512]
        g = ch[531]  # g_len=1 at 529-530, g at 531
        salt_len = ch[532]
        salt = ch[533:533+salt_len]
        b_start = 533+salt_len
        b_len = struct.unpack(">H", ch[b_start:b_start+2])[0]
        B = ch[b_start+2:b_start+2+b_len]
        after_b = b_start+2+b_len
        iters = struct.unpack(">I", ch[after_b+4:after_b+8])[0]
        opt_len = struct.unpack(">H", ch[after_b+8:after_b+10])[0]
        options = ch[after_b+10:after_b+10+opt_len]

        # P'
        P_prime = pbkdf2(password.encode(), salt, iters, 128)

        # x variant
        if variant_x == 'username_colon':
            x = sha512(salt, sha512(username.encode(), b':', P_prime))
        elif variant_x == 'empty_colon':
            x = sha512(salt, sha512(b':', P_prime))
        elif variant_x == 'salt_P':
            x = sha512(salt, P_prime)
        elif variant_x == 'P_only':
            x = sha512(P_prime)
        elif variant_x == 'salt_hash_P':
            x = sha512(salt, sha512(P_prime))
        elif variant_x == 'username_colon_P_trunc':
            x = sha512(salt, sha512(username.encode(), b':', P_prime[:64]))

        N_int = int.from_bytes(N, 'big')
        g_int = g

        # k
        k = sha512(pad(N, 512), pad(bytes([g]), 512))
        k_int = int.from_bytes(k, 'big')

        # Random a (32 bytes)
        a = os.urandom(32)
        a_int = int.from_bytes(a, 'big')

        # A = g^a mod N
        A_int = pow(g_int, a_int, N_int)
        A = A_int.to_bytes(512, 'big')

        # u
        u = sha512(pad(A, 512), pad(B, 512))
        u_int = int.from_bytes(u, 'big')

        # x as int
        x_int = int.from_bytes(x, 'big')

        # S = (B - k*g^x)^(a + u*x) mod N
        gx_int = pow(g_int, x_int, N_int)
        kgx_int = (k_int * gx_int) % N_int
        B_int = int.from_bytes(B, 'big')
        base_int = (B_int - kgx_int) % N_int
        exp_int = (a_int + u_int * x_int) % N_int
        S_int = pow(base_int, exp_int, N_int)
        S = S_int.to_bytes(512, 'big')

        # K = SHA512(PAD(S))
        K = sha512(pad(S, 512))

        # M1
        h_N = sha512(pad(N, 512))
        h_g = sha512(pad(bytes([g]), 512))
        hN_xor_hg = bytes(a^b for a,b in zip(h_N, h_g))

        if variant_m1_i == 'empty':
            h_I = sha512(b'')
        elif variant_m1_i == 'username':
            h_I = sha512(username.encode())

        M1 = sha512(hN_xor_hg, h_I, salt, pad(A, 512), pad(B, 512), K)

        # Build packet 2 manually
        # Inner: %m A | %o M1 | %s options | %o client_random(16)
        inner = struct.pack(">H", 512) + A
        inner += struct.pack("B", 64) + M1
        inner += struct.pack(">H", opt_len) + options
        cr = os.urandom(16)
        inner += struct.pack("B", 16) + cr

        meaningful = struct.pack(">H", 0) + struct.pack(">H", len(inner)) + inner
        total_body = struct.pack(">H", 0x0100) + b'RSA1' + struct.pack(">H", 2) + struct.pack(">H", len(meaningful)) + meaningful
        total_len2 = len(total_body) + 384
        packet2 = struct.pack(">I", total_len2) + total_body + b'\x00' * 384

        s.sendall(packet2)

        # Get response
        time.sleep(2)
        resp = s.recv(4096)
        s.close()

        if len(resp) >= 8:
            sr_result = struct.unpack(">I", resp[4:8])[0]
            return (sr_result == 0, sr_result, resp[:10].hex())
        elif len(resp) == 0:
            return (False, -1, 'FIN')
        else:
            return (False, -2, resp.hex())
    except Exception as e:
        return (False, -3, str(e))

host = sys.argv[1] if len(sys.argv) > 1 else '192.168.64.3'
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5900
username = 'admin'
password = 'admin'

variants_x = ['username_colon', 'empty_colon', 'salt_P', 'P_only', 'salt_hash_P', 'username_colon_P_trunc']
variants_m1 = ['empty', 'username']

print(f"Testing SRP variants against {host}:{port}")
print(f"{'x_formula':<30} {'M1_I':<10} {'result':<10} {'sr':<5} {'resp'}")
print("-" * 80)

for vx in variants_x:
    for vm in variants_m1:
        success, sr, resp = do_auth(host, port, username, password, vx, vm)
        status = 'SUCCESS' if success else 'FAIL'
        print(f"{vx:<30} {vm:<10} {status:<10} {sr:<5} {resp}")
        time.sleep(1)  # rate limit
