# G17 — Apple encrypted record layer

- **Status:** PASS_INTEGRATED (deterministic) · KNOWN DIVERGENCE (cipher)
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

Apple rekey + encrypted record layer for the post-auth session. Provides confidential encryption/decryption of RFB records with a rekey mechanism.


## Key paths

- `docs/apple/apple-wire-spec.md`
- `include/farsee/apple_record.h`
- `src/rfb/apple_record.c`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
