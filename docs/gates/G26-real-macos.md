# G26 — Authorized real-macOS interoperability qualification

- **Status:** PASS_BASIC_HARDWARE
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

The authorized type-33 path covers authentication, session entry, framebuffer
rendering, and basic input. The forced type-36 path covers direct identity/SRP
authentication, server-proof verification, session entry, and protected Apple
AES-CBC record activation. That earlier bounded hardware run used the null
presenter. The current-candidate retry did not activate protected records.
Neither run establishes type-36 framebuffer or input acceptance.

Apple `0x0450` uses the profile-1000 alpha-cursor contract and hotspot
semantics. The presentation-copy compositor keeps cursor pixels out of the
authoritative framebuffer. Extended fidelity and sustained-session matrices
remain open and are documented as limitations.


## Product and test paths

- `docs/apple/srp-challenge-offsets.md`
- `docs/apple/apple-wire-spec.md`
- `src/rfb/apple_srp.c`
- `src/rfb/apple_type33_live.c`
- `include/farsee/apple_type36_live.h`
- `tests/unit/apple_srp__tests.c`
- `tests/unit/apple_type33_live__tests.c`
## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
