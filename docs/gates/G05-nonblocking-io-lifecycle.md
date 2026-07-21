# G5 — Nonblocking connection, outbound queue, and session lifecycle

- **Status:** ✅ PASS
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

Turn the parser into a robust interactive client process: nonblocking IPv4/IPv6 connect with getaddrinfo; poll()-based event loop; bounded input/output buffers; short I/O, EINTR, EAGAIN/EWOULDBLOCK, peer close, half-close handling; monotonic-clock timeouts; connection cancellation; graceful close and resource cleanup; typed exit status.


## Key paths

- `src/io/outbound.c`
- `src/io/poller_posix.c`
- `src/io/socket_posix.c`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
