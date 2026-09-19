# G28 — Future Apple High Performance/Adaptive media feasibility

- **Status:** PLANNING_ONLY
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Adaptive/HEVC media is not implemented or enabled in the product.


## Key paths

- `docs/apple/apple-wire-spec.md`
- `docs/apple/rsa1-wire-format.md`
- `docs/known-limitations.md`
- `docs/protocol-support.md`
- `docs/threat-model.md`
- `include/farsee/encoding.h`
- `include/farsee/encoding_zrle.h`
## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
