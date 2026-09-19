# R6 — FreeRDP callback wiring

- **Status:** PASS_MACHINE; extended interoperability matrix remains partial
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Installs the FreeRDP 3.15 callback table for certificate verification,
credential application, pre-connect settings, GDI setup, paint, desktop
resize, disconnect, and text clipboard events. Callbacks delegate to the
Farsee-owned R2–R5 bridges and publish frames through the SHARED-MT product
path without process-global callback state.

## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
