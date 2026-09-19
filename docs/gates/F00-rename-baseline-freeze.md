# F0 — Rename baseline and freeze

- **Status:** PASS_BASELINE; use the current candidate gate for release status
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

This gate preserves the `G0–G28` requirements and adds the F-series baseline.


## Key paths

- `docs/implementation-status.md`
- `src/io/known_hosts.c`
## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
