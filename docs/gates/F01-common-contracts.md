# F1 — Common error, lifecycle, and capability contracts

- **Status:** PASS_MACHINE
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

This gate defines the common contracts in §§6, 7, and 22/F1. It complements
the `G0–G28` RFB gates.


## Key paths

- `include/farsee/farsee_*.h`
- `tests/fakes/fake_engine.c`
- `tools/check_common_headers.py`
## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
