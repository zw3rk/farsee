# R1 — RDP worker, settings, and cancellation — PASS

- **Status:** PASS_MACHINE
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Defines the Farsee-owned RDP settings bundle, secure TLS+NLA defaults, explicit
channel allowlist, and the confined FreeRDP worker lifecycle. The worker owns
the FreeRDP instance and context, supports interruptible cancellation, and is
destructible from each partial state without exposing FreeRDP types.

## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
