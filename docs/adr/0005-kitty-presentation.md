# ADR-0005: Kitty graphics presentation strategy

- **Status:** Accepted (strategy); backend implementations land in G7/G10.
- **Date:** 2026-07-21

## Context

`plan.md` §2 and §21 require presenting the remote framebuffer through the
Kitty graphics protocol. Two transfer backends are in scope:

- **direct (PTY):** base64-encoded RGB or RGBA data travels inline through
  the terminal output stream (G7); and
- **shared memory (POSIX `t=s`):** pixel bytes are staged in a one-shot POSIX
  shared-memory object, and only its name travels over the PTY (G10).

The public [Kitty graphics protocol specification](https://sw.kovidgoyal.net/kitty/graphics-protocol/)
is the controlling reference under `plan.md` §5.2.

## Decision

1. **Presenter abstraction** (`plan.md` §10.5). One `rfb_presenter_ops`
   interface serves null, Kitty-direct, Kitty-SHM, and future presenters.
   A presenter never mutates the authoritative framebuffer.
2. **Capability selection.** Query encode/decode helpers exist, but the live
   RFB and RDP paths currently select Kitty from the CLI and do not perform
   a capability exchange before emitting graphics. Unsupported terminals
   require the operator to choose a different presenter.
3. **Chunk limit 4096 bytes.** Each direct-transfer payload chunk is at most
   4096 base64 bytes (`plan.md` §21.1). A non-final chunk is a multiple of four
   bytes, and its `m` flag marks continuation.
4. **SHM is one-shot.** A Kitty `t=s` command names one shared-memory object.
   The terminal reads the object. Farsee closes and unlinks each object after
   acknowledgement, timeout, replacement, or shutdown. The in-flight table is
   bounded, and SHM failure falls back to direct transfer.

## Consequences

- A fake Kitty terminal (`tests/integration/fake_kitty_terminal.py`)
  reconstructs the exact source bytes for both backends.
- The SHM suite checks `0600` mode, bounded in-flight objects, cleanup, and
  deterministic direct fallback (G10).
- The direct suite checks the 4096-byte chunk limit, continuation flags,
  acknowledgement and error handling, and terminal restoration (G7).
- Damage-bounded presentation follows `plan.md` §21.3; resize or coalesced
  damage can require a full-frame present.
