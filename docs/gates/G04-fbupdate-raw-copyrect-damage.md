# G4 — FramebufferUpdate, Raw, CopyRect, and damage

- **Status:** ✅ PASS
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Decode the first useful screen losslessly: FramebufferUpdate header; rectangle headers; Raw decoding for the negotiated pixel format; CopyRect with overlap-safe row ordering; bounds validation before any write; multiple rectangles per update; damage emitted only after a fully- successful rectangle; framebuffer generation counters. Golden framebuffer tests prove pixel-exact output.


## Key paths

- `src/rfb/encoding_copyrect.c`
- `src/rfb/encoding_raw.c`
- `src/rfb/fbupdate.c`
- `src/rfb/pixel_convert.c`
- `tests/fuzz/fuzz_raw_decoder.c`
## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
