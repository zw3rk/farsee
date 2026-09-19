# F5 — Common input and clipboard brokers

- **Status:** PASS_MACHINE
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Defines protocol-neutral keyboard and pointer events, including physical and
logical key identity, modifier state, pointer buttons, and wheel input. It also
defines a bounded key ledger and a plain-text clipboard policy with explicit
direction, size limits, encoding conversion, and terminal-control sanitization.

## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
