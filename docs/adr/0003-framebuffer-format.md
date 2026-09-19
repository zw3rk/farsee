# ADR-0003: Canonical framebuffer format — RGBA8

- **Status:** Accepted
- **Date:** 2026-07-21

## Context

`plan.md` §12.1 requires one canonical in-memory framebuffer format. The choice
affects pixel conversion cost, golden-image tests, Kitty RGBA compatibility,
and host-endianness sensitivity.

## Decision

The authoritative framebuffer is **RGBA8**:

- each channel uses one byte;
- byte order in memory is R, G, B, A at offsets 0, 1, 2, and 3;
- framebuffer alpha is **255** because the framebuffer is opaque; cursors
  carry their own alpha layer;
- pixel stride is exactly 4 bytes; and
- the default row stride is `width * 4`, without padding.

## Consequences

- A 1 GiB framebuffer cap (`plan.md` §6.4) permits at most about 268
  million pixels. Code computes `width * height * 4` through
  `rfb_checked_rect_bytes` (G1).
- Integer-only pixel conversion supports validated 8-, 16-, and 32-bpp wire
  formats and has exhaustive small-range tests (G3, §12.3).
- Test-only in-memory presentation captures RGBA data for fixture checks.
