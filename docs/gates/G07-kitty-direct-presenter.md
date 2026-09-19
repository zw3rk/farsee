# G7 — Kitty direct-transfer presenter

- **Status:** PASS_MACHINE; extended terminal matrix remains partial
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Display the remote framebuffer through the Kitty graphics protocol: base64 streaming encoder; Kitty capability query and response parser; RGB24/RGBA32 direct-transfer command generation with ≤4096-byte base64 chunks; image/placement IDs; acknowledgement flag; terminal cleanup commands. The fake Kitty terminal reconstructs exact source bytes.


## Key paths

- `src/present/base64.c`
- `src/present/kitty_protocol.c`
- `tests/integration/fake_kitty_terminal.py`
## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
