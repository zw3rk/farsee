# G18 — Apple security type 33 RSA/SRP authentication

- **Status:** PASS_INTEGRATED; basic authorized hardware acceptance passed in G26
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Apple type-33 RSA key exchange and credential authentication feed the record-layer wrap-key interface. The byte contract is in `docs/apple/apple-wire-spec.md`.


## Key paths

- `docs/apple/apple-wire-spec.md`
## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
