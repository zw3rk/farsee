# ADR-0005: Kitty graphics presentation strategy

- **Status:** Accepted (strategy); backend implementations land in G7/G10.
- **Date:** 2026-07-21
- **direct (PTY)** — base64-encoded RGB/RGBA sent inline through the
- **shared memory (POSIX `t=s`)** — pixel bytes staged in a one-shot

## Context

plan.md §2 and §21 require presenting the remote framebuffer through the Kitty graphics protocol. Two transfer backends are in scope: terminal's output stream (G7); POSIX shared-memory object, only the object name sent over the PTY (G10). The Kitty graphics protocol specification (https://sw.kovidgoyal.net/kitty/graphics-protocol/) is the controlling reference, derived clean-room (plan.md §5.2). No Kitty source code is read.

## Decision

1. **Presenter abstraction** (plan.md §10.5). One `rfb_presenter_ops` interface serves null, dump, Kitty-direct, Kitty-SHM, and future presenters. The presenter **never mutates** the authoritative framebuffer (plan.md §8, principle 4).
2. **Capability query first.** Before emitting any graphics command, the presenter queries the terminal for Kitty graphics support and (for SHM) shared-memory support. Absent support → deterministic fallback per CLI policy (G7, G10).
3. **Chunk limit 4096 bytes.** Every direct-transfer payload chunk is at most 4096 base64 bytes (plan.md §21.1). Non-final chunks are a multiple of four bytes; the `m` flag marks continuation. This is a fuzz-tested invariant.
4. **SHM is one-shot.** Kitty `t=s` transfers a single object: the terminal reads it and unlinks/closes

## Consequences

- A fake Kitty terminal (`tests/integration/fake_kitty_terminal.py`) reconstructs exact source bytes from the protocol commands; that is the golden path for both backends. - The SHM suite must prove: no leaked objects, `0600` mode, bounded in-flight, and deterministic direct fallback (G10). - The direct suite must prove: ≤4096-byte chunks, correct `m` flags, ack/error handling, and full restoration (G7). - Partial-update tiling is deferred (plan.md §21.3) until a pixel-exact seam test exists.
