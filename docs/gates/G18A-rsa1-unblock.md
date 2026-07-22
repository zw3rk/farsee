# G18A — RSA1 branch-entry wire format unblock

- **Status:** PASS_INTEGRATED (machine-verifiable, 521 tests) · PASS_HARDWARE (§3 + §4 confirmed against real macOS)
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

Isolate and prove the Apple type-33 RSA1 branch-entry wire format — the selector + authtype-0 key request, the mixed-endian DER SPKI response, the packet-1 identity plaintext, and the packet-1 envelope — as pure, bounded serializers/parsers with no socket or crypto-provider assumptions. The acceptance oracle is a fake server that validates packet 1 and emits a synthetic SRP challenge.


## Key paths

- `docs/gates/G18A-rsa1-unblock.md`
- `include/farsee/apple_rsa1.h`
- `src/rfb/apple_rsa1.c`
- `tests/fuzz/fuzz_apple_rsa1_key_response.c`
- `tests/unit/apple_rsa1__tests.c`
- `tests/unit/socket_nodelay__tests.c`
- `tools/probe_rsa1.py`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
