# R0 — FreeRDP dependency and provenance

- **Status:** PASS_DARWIN_POLICY; Linux remains build/test only
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Pins the minimized FreeRDP 3.15.0 client dependency under ADR-0008. The gate
covers the optional `FARSEE_WITH_RDP` build dimension, the FreeRDP facade and
version guard, the no-RDP build, declared licenses, and the final binary's
runtime-closure policy.

The minimized runtime closure must pass the required audit on each published
release platform. The current machine-readable policy permits Apple silicon
and Intel macOS. Linux remains in the build and test matrix, but it cannot
stage a release artifact under the locked license allowlist.

## Key paths

- `docs/adr/0008-freerdp-integration.md`
- `src/protocol/rdp/*.c`
- `tests/unit/rdp/*.c`
- `tools/gen_test_registry.py`

## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
