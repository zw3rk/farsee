# F8 — RFB engine adapter completion

- **Status:** PASS_SCAFFOLD; not the live product path
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Wraps the RFB handshake and session lifecycle behind the protocol-neutral
`farsee_engine` contract. The adapter covers start, cancellation, capability
queries, deterministic teardown, and typed errors while keeping RFB types at
the adapter boundary. ADR-0011 keeps this adapter in the scaffold test link set,
not the live CLI path.

## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
