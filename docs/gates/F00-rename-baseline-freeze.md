# F0 — Rename baseline and freeze

- **Status:** | Unit/integration suite (dev) | `make test` | 786 ran, 786 passed, 0 failed |
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

This gate does not replace any historical `G0–G28` evidence; it sits above it.


## Key paths

- `docs/implementation-status.md`
- `src/io/known_hosts.c`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
