# G6 — Input, cursor, resize, clipboard, and bell

- **Status:** ✅ PASS
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

Make the client usable for ordinary desktop interaction: encode KeyEvent, PointerEvent, ClientCutText; parse ServerCutText and Bell; implement the Cursor pseudo-encoding (shape, mask, hotspot); implement DesktopSize pseudo-encoding (transactional resize).


## Key paths

- `src/rfb/encoding_cursor_desktopsize.c`
- `src/rfb/input.c`
- `src/rfb/server_messages.c`
- `tests/macos/keyboard_matrix.md`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
