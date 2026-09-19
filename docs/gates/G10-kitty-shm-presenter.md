# G10 — Kitty POSIX shared-memory presenter

- **Status:** PASS_MACHINE; extended terminal matrix remains partial
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Avoid base64 and PTY bulk transfer for local compatible terminals while retaining exact fallback behavior. Kitty `t=s` is a one-shot transfer object: the terminal reads the object and unlinks/closes it on POSIX.


## Key paths

- `src/present/kitty_shm.c`
## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
