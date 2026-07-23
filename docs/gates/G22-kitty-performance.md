# G22 — Kitty presentation and backpressure performance

- **Status:** ✅ PASS (machine-verifiable); 🔶 NEEDS-HARDWARE (manual terminal acceptance)
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

High-throughput pixel-exact Kitty presentation and measured backpressure improvements without changing protocol semantics. A tile/damage-aware presenter that preserves stable Kitty image/placement IDs per tile and retransmits only the tiles intersecting the current damage.


## Key paths

- `include/farsee/kitty_tile.h`
- `src/present/kitty_tile.c`
- `tests/unit/kitty_tile__tests.c`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
