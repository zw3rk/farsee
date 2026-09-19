# G9 — Damage scheduling, request pacing, and observability

- **Status:** ✅ PASS
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Prevent the network stream or presenter from overrunning the terminal: update-request state machine (one outstanding request); bounded damage accumulator with cap-to-full-frame; present cadence (monotonic clock, max FPS); backpressure pause/resume; metrics counters.


## Key paths

- `src/fb/damage.c`
- `src/fb/pacing.c`
## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
