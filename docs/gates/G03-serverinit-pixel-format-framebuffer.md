# G3 — ServerInit, pixel format, and transactional framebuffer

- **Status:** ✅ PASS
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

Complete initialization after authentication: parse ServerInit (width, height, pixel format, desktop name); enforce dimension/name limits before allocation; validate pixel-format fields; allocate aligned RGBA8 framebuffer with checked stride/size; initialize alpha=255/RGB=0; emit SetPixelFormat and SetEncodings; transactional resize; null and dump presenters.


## Key paths

- `src/fb/framebuffer.c`
- `src/rfb/pixel_format.c`
- `src/rfb/server_init.c`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
