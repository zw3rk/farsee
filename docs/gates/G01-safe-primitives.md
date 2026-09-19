# G1 — Safe primitives and deterministic parser substrate

- **Status:** ✅ PASS
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Build the low-level facilities on which all network parsing depends: checked `size_t` add/multiply and rectangle-size helpers; bounded byte reader/writer for big-endian fields; growable buffer with hard limit; typed error system with stable error codes; injectable allocator; compiler-resistant secret zeroization helper; logging API that distinguishes trusted static strings from escaped remote text; parser progress-invariant helper.


## Key paths

- `include/farsee/progress.h`
- `src/core/allocator.c`
- `src/core/buffer.c`
- `src/core/bytes.c`
- `src/core/checked.c`
- `src/core/error.c`
- `src/core/log.c`
- `src/core/secret.c`
- `tests/fuzz/fuzz_bytes_and_buffer.c`
## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
