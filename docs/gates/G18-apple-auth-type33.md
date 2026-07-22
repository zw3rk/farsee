# G18 — Apple security type 33 RSA/SRP authentication

- **Status:** PASS_INTEGRATED (machine-verifiable) · NEEDS_HARDWARE (real-macOS)
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

Apple type-33 RSA key exchange + credential authentication, feeding G17's wrap-key interface. Proceeds from the CAPTURED wire-spec evidence in `docs/apple/apple-wire-spec.md`.


## Key paths

- `docs/apple/apple-wire-spec.md`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
