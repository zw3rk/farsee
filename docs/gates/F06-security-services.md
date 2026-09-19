# F6 — Security services

- **Status:** PASS_MACHINE
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Defines protocol-neutral secret ownership, credential requests and responses,
typed peer identities, trust decisions, and fail-closed security policy. It
keeps cryptographic primitives, TLS sessions, credential acquisition, and peer
authorization as separate services.

## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
