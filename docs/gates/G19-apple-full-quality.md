# G19 — Usable Apple Full-Quality framebuffer session

- **Status:** PASS_INTEGRATED (machine-verifiable, 557 tests) · NEEDS_HARDWARE (real macOS)
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

A usable Apple Full-Quality framebuffer session after successful type-33 authentication, excluding Adaptive/HEVC media. Connects G15/G17/G18 into the post-auth event loop. The deterministic fake-server path is the PASS criterion; real macOS is NEEDS_HARDWARE.


## Key paths

- `tests/unit/apple_rsa1__tests.c`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
