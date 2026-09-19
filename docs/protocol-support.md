# Protocol support

## RFB

| Feature | Status |
|---------|--------|
| RFB 3.3 / 3.7 / 3.8 | yes |
| Security None (opt-in) | yes |
| VNC Authentication | yes (CommonCrypto / OpenSSL) |
| Apple security type 33 (RSA1+SRP) | yes |
| Apple security type 36 | live identity + SRP authentication; `--apple-security=36` requires it |
| Apple post-auth records | optional `--apple-postauth=records`: AES-CBC + SHA-1 records, sealed FBUR, and ZRLE paint |
| Apple `0x03f3` | type-0 command validation and image paint; structurally invalid bodies fail closed; validated unpainted forms consume with no damage |
| Apple `0x0450` | alpha-cursor decode and presentation-copy composition; malformed or unsupported profiles fail closed |
| Raw, CopyRect, ZRLE | yes |
| Cursor, DesktopSize | yes |
| Key / Pointer / CutText / Bell | yes |
| TLS / VeNCrypt | no (contracts only; F7) |
| Tight / Hextile / AHPSS | no |

The Apple rows describe implementation status, not release approval. The Apple
feature set remains blocked from release under ADR-0013 pending the required
governance decision and any required counsel review.

**Vendor banners:** default-deny; map only with tests (plan.md §11).

## RDP

FreeRDP 3.x (ADR-0008). Live Kitty via SHARED-MT. Windows first-frame
interop PASS; full matrix partial (R6).

## Presenters

null · Kitty direct · Kitty POSIX SHM.
