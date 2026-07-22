# G11 — Real macOS interoperability and fidelity acceptance

- **Status:** 🔶 NEEDS-HARDWARE
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

Validate the client against an actual macOS Screen Sharing server rather than only synthetic fixtures. This is the external acceptance gate.


## Key paths

- `tests/macos/keyboard_matrix.md`
- `tools/macos_acceptance.sh`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
