# Apple RFB wire spec (project-owned capture)

**Status:** CAPTURED 2026-07-22 · authorized Screen Sharing session  
Fields: **CAPTURED** · **INFERRED** · **UNKNOWN** · **CONFLICTING**

## Banner / security list

| Field | Value | Ev |
|-------|-------|-----|
| Banner | `RFB 003.889\n` | C |
| List format | 3.7/3.8 u8 count + types | C |
| Offered | `[30, 33, 36, 35]` raw `041e212423` | C |
| Client banner first | YES | C |

## Type 33 (selected path)

Not classic RFC 5054-only SRP: RSA1 envelopes + SRP-like proof + options
string advertising SHA-512 / ChaCha20-Poly1305 / SALTED-SHA512-PBKDF2.

Normative byte layouts: **`RSA1-UNBLOCK.md`**, **`srp-challenge-offsets.md`**.

| Phase | Dir | Size (obs.) | Notes |
|-------|-----|-------------|-------|
| Key request | C→S | 15 B | selector+authtype0 |
| Key response | S→C | ~305 B | DER SPKI |
| Packet 1 identity | C→S | 654 B | RSA PKCS#1 v1.5 |
| SRP challenge | S→C | ~1169 B | N/g/salt/B/iters/opts |
| Packet 2 | C→S | ~1080 B | A, M1, options, random |
| M2 / result | S→C | ~100 B | then SecurityResult |
| Cleartext post-auth | both | varies | hostname/device; then records |

Post-auth **cleartext MVP** is the shipping path; full ChaCha record product
path is open (see known-limitations).

## Other types (offered, not productized)

| Type | Meaning | Detail |
|------|---------|--------|
| 30 | Legacy DH | UNKNOWN |
| 36 | Direct SRP | UNKNOWN |
| 35 | Kerberos/GSS | UNKNOWN |

## Capture policy

Authorized host only. No passwords in cleartext in pcap. Do not import
AGPL third-party source; confirm every field via project capture or test.
