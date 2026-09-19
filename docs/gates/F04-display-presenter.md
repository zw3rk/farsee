# F4 — Display scene and presenter v2 + v1 adapter

- **Status:** PASS_MACHINE
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Defines checked display surfaces, damage rectangles, cursor state, and atomic
frame commits. It also defines presenter v2 capabilities and lifecycle, plus
the single v1 adapter that converts supported source formats to canonical RGBA8
for the existing null and Kitty presenters.

## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
