# ADR-0004: Event loop and session architecture

- **Status:** Accepted; single-threaded live default superseded by ADR-0010
- **Date:** 2026-07-21

## Context

`plan.md` §8 and G5 require a deterministic single-threaded event loop with
bounded queues, injectable time, and no hidden global state. The loop services:

- the RFB protocol parser, which converts input bytes into events and
  framebuffer damage;
- the outbound queue for requests, keys, pointer input, and clipboard data;
- the presenter cadence;
- terminal keyboard, mouse, clipboard, and focus input; and
- connect, idle, and request-pacing timeouts.

## Decision

1. **Single-threaded by default.** No mutex is in the hot path. Threads are a
   deferred, profile-driven optimization (`plan.md` §4.1).
2. **Nonblocking I/O everywhere.** Sockets, the PTY, and, where supported, the
   controlling TTY are nonblocking. The loop drives them through `poll()`
   behind `src/io/poller_posix.c`.
3. **Bounded queues (`plan.md` §6.4).** Input, output, damage, and presentation
   queues each have hard caps. Overflow produces a typed error or uses a
   documented coalescing policy. Queues never grow without a bound.
4. **Injectable time and clock.** The session context stores the clock
   callback, so tests can use a deterministic fake clock without sleeps.
5. **Parser step outcomes** are conceptually `PROGRESS`, `NEED_INPUT`,
   `NEED_OUTPUT_DRAIN`, `DONE`, or `ERROR`. `PROGRESS` is valid only when
   the step consumed input, produced output, emitted an event, or changed
   state. `ERROR` is typed and fails closed. These outcomes are a session-loop
   contract, not one shared C enum.

## Consequences

- The session object is plain data. Core modules have no singleton or mutable
  `static` state.
- The poller adapter lets tests use byte queues and a fake clock without
  sockets.
- Signal handlers do only signal-safe work: set a flag and restore the
  terminal through the signal-safe path (G7, `plan.md` §6.3).
