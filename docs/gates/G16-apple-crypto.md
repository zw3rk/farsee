# G16 — Apple crypto provider (OpenSSL 3.x)

- **Status:** PASS_INTEGRATED
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

A permissive crypto provider for all Apple-auth primitives, selected via OpenSSL 3.x EVP/BN interfaces on both macOS and Linux. The VNC-auth DES provider (CommonCrypto/OpenSSL, G2) is left unchanged.


## Key paths

- `include/farsee/apple_crypto.h`
- `src/crypto/apple_crypto.c`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
