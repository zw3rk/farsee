# F1 — Common error, lifecycle, and capability contracts

- **Status:** failed with `fatal error: 'farsee/farsee_error.h' file not found`:
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

§6, §7, §22/F1). Sits above the historical `G0–G28` RFB evidence.


## Key paths

- `include/farsee/farsee_*.h`
- `tests/fakes/fake_engine.c`
- `tools/check_common_headers.py`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
