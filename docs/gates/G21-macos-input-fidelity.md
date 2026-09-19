# G21 — macOS keyboard, pointer, scroll, and clipboard fidelity

- **Status:** PASS_MACHINE; basic authorized interaction passed in G26; extended matrix open
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

macOS-focused keyboard, pointer, scroll, and clipboard fidelity for classic
and Apple protected sessions. A presenter-independent normalized input layer
carries physical key identity, Unicode text, modifier state, repeat state, and
source protocol. Classic sessions emit standard RFB input messages; Apple
protected sessions seal those messages through G17. Clipboard policy enforces
size caps and UTF-8 validation.


## Key paths

- `src/input/normalized_input.c`
## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
