# G19 — Usable Apple Full-Quality framebuffer session

- **Status:** PASS_INTEGRATED; sustained real-system matrix remains open
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

A usable Apple Full-Quality framebuffer session after successful type-33 or
type-36 authentication, excluding Adaptive/HEVC media. Type 36 reuses the
verified Apple SRP and wrap-key derivation without the type-33 RSA1 prelude.
Apple `0x0450` supplies the separate alpha cursor, which is composited into the
copied presentation frame. G15, G17, and G18 feed the post-auth event loop.
Current integration tests are the machine acceptance criterion; sustained
real-system coverage remains partial.


## Key paths

- `tests/unit/apple_rsa1__tests.c`
- `docs/apple/apple-wire-spec.md`
## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
