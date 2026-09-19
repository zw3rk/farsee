# R2–R5 — RDP trust, display, input, clipboard bridges — PASS (Farsee-owned core)

- **Status:** PASS_MACHINE
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

- **R2 trust and credentials:** classify peer certificates, apply CA and TOFU
  policy, reject changed identities by default, and block credentials until
  peer trust permits them.
- **R3 display:** validate FreeRDP software-GDI dimensions, stride, byte count,
  and damage before publishing BGRA frame commits.
- **R4 input:** map normalized keyboard, pointer, and wheel events to RDP
  scan-code, Unicode, mouse, and extended-mouse paths with key/button state.
- **R5 clipboard:** connect text-only `cliprdr` handling to the common
  direction, format, size, and sanitization policy.

## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
