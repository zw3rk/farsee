# G27 — Release readiness and reverse audit

- **Status:** BLOCKED_BY_G26
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

Release readiness: versioning, changelog, license audit, build reproducibility, security review sign-off, and a reverse audit of the entire goal. PASS requires G26 PASS.

## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
