# G15 — Apple dialect and authentication state-machine framework

- **Status:** PASS_ISOLATED
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Apple RFB dialect and authentication state-machine framework without real Apple cryptography. Classic RFB behavior unchanged.

## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
