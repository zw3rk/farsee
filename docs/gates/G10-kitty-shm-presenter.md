# G10 — Kitty POSIX shared-memory presenter

- **Status:** ✅ PASS (machine-verifiable); 🔶 NEEDS-HARDWARE (manual acceptance)
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

Avoid base64 and PTY bulk transfer for local compatible terminals while retaining exact fallback behavior. Kitty `t=s` is a one-shot transfer object: the terminal reads the object and unlinks/closes it on POSIX.


## Key paths

- `src/present/kitty_shm.c`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
