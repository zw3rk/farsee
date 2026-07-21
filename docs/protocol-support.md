# Protocol support

## RFB

| Feature | Status |
|---------|--------|
| RFB 3.3 / 3.7 / 3.8 | yes |
| Security None (opt-in) | yes |
| VNC Authentication | yes (CommonCrypto / OpenSSL) |
| Apple type-33 (RSA1+SRP) | yes (cleartext MVP post-auth) |
| Raw, CopyRect, ZRLE | yes |
| Cursor, DesktopSize | yes |
| Key / Pointer / CutText / Bell | yes |
| TLS / VeNCrypt | no (contracts only; F7) |
| Tight / Hextile / AHPSS | no |

**Vendor banners:** default-deny; map only with tests (plan.md §11).

## RDP

FreeRDP 3.x (ADR-0008). Live Kitty via SHARED-MT. Windows first-frame
interop PASS; full matrix partial (R6).

## Presenters

null · dump · Kitty direct · Kitty POSIX SHM.
