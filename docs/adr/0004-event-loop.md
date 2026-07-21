# ADR-0004: Event loop and session architecture

- **Status:** Accepted
- **Date:** 2026-07-21

## Context

plan.md §8 ("architecture principles") and §G5 require a deterministic single-threaded event loop with bounded queues, injectable time, and no hidden global state. The loop must service: - the RFB protocol parser (input bytes → events / framebuffer damage); - the outbound queue (client messages: requests, keys, pointer, clipboard); - the presenter cadence (damage → terminal); - the terminal input path (keyboard, mouse, clipboard, focus); - timeouts (connect, idle, request pacing).

## Decision

1. **Single-threaded by default.** No mutex in the hot path. Threads are a deferred, profile-driven optimization (plan.md §4.1).
2. **Nonblocking I/O everywhere.** Sockets, the PTY, and (where supported) the controlling tty are set non-blocking; the loop drives everything through `poll()` behind a thin adapter (`src/io/poller_posix.c`).
3. **Bounded queues (plan.md §6.4).** Input buffer, output queue, damage queue, and presentation queue each have hard caps. Overflow is a typed error or a documented coalescing policy — never silent growth.
4. **Injectable time and clock.** The clock is a function pointer on the session context so tests use a deterministic fake clock (plan.md §13.3 forbids sleeps for synchronization).
5. **Parser returns one of** `PROGRESS | NEED_INPUT | NEED_OUTPUT_DRAIN |

## Consequences

- The session object is large but plain; no singleton, no `static` mutable state in core modules. - The poller adapter makes the loop testable without sockets by feeding byte queues and a fake clock. - Signal handlers do only signal-safe work: set a flag, restore the terminal via an async-signal-safe helper (G7, plan.md §6.3).
