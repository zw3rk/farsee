# Apple type-33 RSA1 wire note

**Status:** project-owned wire facts (G18A) · **Date:** 2026-07-22  
Implementation derives from this note + authorized captures (`docs/apple/`).  
Do not copy AGPL third-party source.

## 3. Branch entry + public-key request

After `RFB 003.889\n`, server offers type `33` (`0x21`). When the key is not
cached, send one contiguous buffer (`TCP_NODELAY`; do not split selector
from envelope):

```text
u8      selector       = 0x21
u32_be  total_len      = 10
u16_be  version        = 0x0100       # wire bytes 01 00
byte[4] algorithm      = "RSA1"
u16_be  authtype       = 0            # key request
u16_be  inner_len      = 0
```

Exact bytes: `21 00 00 00 0a 01 00 52 53 41 31 00 00 00 00`

Key response:

```text
u32_be  total_len      = der_len + 7
u32_le  version        = 0x00000100
u16_be  der_len
byte[]  DER SubjectPublicKeyInfo
u8      trailing_zero  = 0
```

Validate: `total_len == der_len + 7`, DER within policy, RSA-2048 modulus,
no unexpected trailing bytes, host-key policy before identity.

## 4. Packet 1 (`authtype = 2`)

Identity plaintext (before RSA PKCS#1 v1.5 encryption — **not** OAEP):

```text
u32_be  payload_len        = username_len + 7
u32_be  username_len
byte[]  username_utf8
u16_be  empty_string_len   = 0
u8      empty_opaque_len   = 0
```

Plaintext length = `username_len + 11`. Reject overlong usernames.

Packet 1:

```text
u32_be  total_len      = 650          # bytes after this field
u16_be  version        = 0x0100
byte[4] algorithm      = "RSA1"
u16_be  authtype       = 2
u16_be  inner_len      = 256
byte[256] rsa_ciphertext
byte[384] zero_tail
```

Total 654 bytes. Without a prior key request, concatenate selector + packet 1
(655 bytes). A valid SRP challenge next proves RSA1 acceptance.

## 5. Packet 2 envelope

After SRP challenge, with `A` and `M1`:

```text
inner =
    u16_be len(A)            || A
 || u8     len(M1)           || M1
 || u16_be len(options)      || options
 || u8     len(client_random)|| client_random

meaningful_body = u16_be 0 || u16_be inner_len || inner

packet =
    u32_be total_len
 || u16_be version = 0x0100
 || "RSA1"
 || u16_be authtype = 2
 || u16_be meaningful_body_len
 || meaningful_body
 || trailing
```

Observed profile: A=512, M1=64, options=80, client_random=16;
`inner_len=678`, meaningful=682, `total_len=1076` (`0x0434`).

## 6. Common faults

1. Split `0x21` from first envelope · 2. version `00 01` vs `01 00` ·
3. `total_len` includes leading u32 · 4. missing 384-byte zero tail ·
5. OAEP instead of PKCS#1 v1.5 · 6. wrong identity field order ·
7. stale host key · 8. debugging RSA after SRP challenge already arrived.
