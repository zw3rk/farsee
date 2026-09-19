# Apple RFB protocol reference

**Status:** Implemented protocol profile

## Banner / security list

| Field | Value |
|-------|-------|
| Banner | `RFB 003.889\n` |
| List format | 3.7/3.8 u8 count + types |
| Offered | `[30, 33, 36, 35]` raw `041e212423` |
| Client banner first | YES |

## Type 33

Not classic RFC 5054-only SRP: RSA1 envelopes + SRP-like proof + options
string advertising SHA-512 / ChaCha20-Poly1305 / SALTED-SHA512-PBKDF2.

Normative byte layouts: **`rsa1-wire-format.md`** and
**`srp-challenge-offsets.md`**.

| Phase | Dir | Profile size | Notes |
|-------|-----|-------------|-------|
| Key request | C→S | 15 B | selector+authtype0 |
| Key response | S→C | ~305 B | DER SPKI |
| Packet 1 identity | C→S | 654 B | RSA PKCS#1 v1.5 |
| SRP challenge | S→C | ~1169 B | N/g/salt/B/iters/opts |
| Packet 2 | C→S | ~1080 B | A, M1, options, random |
| M2 / result | S→C | ~100 B | then SecurityResult |
| Cleartext post-auth | both | varies | hostname/device; then records |

## Type 36

Type 36 omits the type-33 RSA1 exchange. The client sends the selected
security type and a length-prefixed identity, then performs the same supported
SRP profile and derives the same post-authentication key material as type 33.
The client validates the challenge envelope, sends the type-36 proof envelope,
verifies the server proof and SecurityResult, and fails closed before publishing
the wrap key when any check fails.

### Post-auth product paths

| Path | Wire |
|------|------|
| **Cleartext MVP** (default) | After type-33: SetEncodings ZRLE+Raw + FBUR; **no** `0x044f` |
| **Protected** (`--apple-postauth=records`) | Cleartext cfg21(66)+msg12-part(16)+SetEncodings → server setup52 type **`0x044f`** + payload32 → client cleartext msg12 ack → **AES-128-CBC records both ways** |

### Modern AES record format

| Field | Value |
|-------|-------|
| Outer | `u16be(ct_len) \|\| CBC(ct_len)` |
| `ct_len` | multiple of 16; min 32 |
| Key install | `content_key \|\| iv0 = AES-ECB-dec(wrap_key, payload32)` |
| IV chain | per direction; next IV = last ciphertext block |
| Plaintext | `u16be(msg_len) \|\| msg \|\| zero_pad \|\| SHA1(be32(seq)\|\|body)` |
| `body` | plaintext without trailing 20-byte SHA-1 |
| `seq` | per-direction counter from 0 after enable |
| Product C→S first | sealed **FBUR** |
| Product encodings | ZRLE + Raw (+ DesktopSize, Cursor); private encoding list opt-in |

Options may advertise other suites. The supported `0x044f` path uses AES-CBC
with the unkeyed SHA-1 checksum above and fails closed on unsupported suites.

## Other offered types

| Type | Meaning | Detail |
|------|---------|--------|
| 30 | Legacy DH | UNKNOWN |
| 35 | Kerberos/GSS | UNKNOWN |
