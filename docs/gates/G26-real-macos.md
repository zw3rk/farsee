# G26 — Authorized real-macOS interoperability qualification

- **Status:** PASS (real type-33 login, M2 verified, framebuffer rendered, input accepted)
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

Real type-33 login, lifecycle, interaction, fidelity, and redacted evidence on authorized macOS hardware.


## Key paths

- `docs/apple/srp-challenge-offsets.md`
- `src/rfb/apple_srp.c`
- `tools/capture_challenge.py`
- `tools/live_auth.c`
- `tools/probe_packet1.c`
- `tools/probe_rsa1.py`
- `tools/srp_probe.py`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
