# R0 — FreeRDP dependency and provenance — PASS

- **Status:** # R0 — FreeRDP dependency and provenance — PASS
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

§22/R0, ADR-RDP-001).


## Key paths

- `docs/adr/0008-freerdp-integration.md`
- `src/protocol/rdp/*.c`
- `tests/unit/rdp/*.c`
- `tools/gen_test_registry.py`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
