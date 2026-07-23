# SRP challenge layout (type-33)

**Source:** authorized VM capture · **Size:** 1169 bytes (dynamic; never hardcode)

## Outer (RSA1-style)

| Off | Size | Field | Notes |
|-----|------|-------|-------|
| 0 | 4 | total_len | u32_be = data_len − 4 |
| 4 | 2 | version | u16_be 0 |
| 6 | 2 | authtype | 2 |
| 8 | 2 | body_len | total_len − 6 |
| 10 | 2 | preamble | 0 |
| 12 | 2 | inner_len | body_len − 4 |

## Inner SRP

| Off | Size | Field | Notes |
|-----|------|-------|-------|
| 14 | 1 | control | 0 |
| 15 | 2 | N_len | 512 |
| 17 | 512 | N | RFC 5054 4096-bit prime |
| 529 | 2 | g_len | 1 |
| 531 | 1 | g | 5 |
| 532 | 1 | salt_len | 32 |
| 533 | 32 | salt | per session |
| 565 | 2 | B_len | 512 |
| 567 | 512 | B | 0 < B < N |
| 1079 | 4 | padding | 0 |
| 1083 | 4 | iterations | e.g. 19417 (policy-capped) |
| 1087 | 2 | options_len | 80 |
| 1089 | 80 | options | see below |

## Options string (captured)

```
mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2
```

Record-layer cipher is decided by live post-auth bytes, not this string alone.
