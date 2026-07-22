# G12 — Hardening, release engineering, and audit

- **Status:** ✅ PASS (machine-verifiable parts)
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

Fuzz smoke + sanitizer matrix; dependency/license audit; CLI documentation and secure usage; threat-model review; version/protocol-capabilities output; crash diagnostics that omit secrets; changelog and known- limitations; installation documentation.


## Key paths

- `docs/known-limitations.md`
- `src/app/main.c`
- `tools/check_license.py`
- `tools/macos_acceptance.sh`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
