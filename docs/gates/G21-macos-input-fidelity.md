# G21 — macOS keyboard, pointer, scroll, and clipboard fidelity

- **Status:** PASS (machine-verifiable, 713 tests) · NEEDS_HARDWARE (real macOS interactive)
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

macOS-focused keyboard, pointer, scroll, and clipboard fidelity for both classic and Apple encrypted sessions. A presenter-independent normalized input layer carries physical key identity, Unicode text, modifier state, repeat state, and source protocol. Classic sessions emit standard RFB KeyEvent/PointerEvent; Apple sessions use verified standard messages inside G17 records (apple-wire-spec.md has no captured Apple-specific input messages). Bidirectional clipboard policy enforces size caps, UTF-


## Key paths

- `src/input/normalized_input.c`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
