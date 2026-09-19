# F7 — Transport set and secure RFB (contract layer)

- **Status:** PASS_CONTRACT_ONLY; secure RFB transport is not implemented
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Defines bounded transport sets with explicit lane semantics, ownership, waitable
descriptors, and payload-free metrics. It also defines the client TLS provider
contract for incremental handshake, peer-identity extraction, record I/O, and
separate trust authorization. The secure RFB transport implementation is not
part of the live product path yet.

## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
