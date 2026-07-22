# G8 — ZRLE decoder

- **Status:** ✅ PASS (all subencodings)
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

zlib adapter; ZRLE 64×64 tile traversal; all ZRLE subencodings: raw-tile (0), solid-tile (1), packed-palette (2..16), plain RLE (128), palette RLE (129+); CPIXEL handling; persistent zlib stream; bounds validation; exact framebuffer verification.


## Key paths

- `src/rfb/encoding_zrle.c`
- `src/rfb/zlib_adapter.c`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
