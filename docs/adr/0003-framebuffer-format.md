# ADR-0003: Canonical framebuffer format — RGBA8

- **Status:** Accepted
- **Date:** 2026-07-21

## Context

plan.md §12.1 mandates a single canonical in-memory framebuffer format. The choice affects: pixel conversion cost, golden-image test ergonomics, Kitty/RGBA compatibility, and host endianness sensitivity.

## Decision

The authoritative framebuffer is **RGBA8**: - one byte red, one byte green, one byte blue, one byte alpha; - byte order in memory: R, G, B, A (offsets 0, 1, 2, 3); - alpha is **255** for framebuffer pixels (the framebuffer is opaque by construction; cursors carry their own alpha layer); - pixel stride is exactly 4 bytes; row stride is `width * 4` (no padding by default, see "stride" below).

## Consequences

- A 1 GiB framebuffer cap (plan.md §6.4) corresponds to at most ~268 million pixels; `width * height * 4` is computed only through `rfb_checked_rect_bytes` (G1). - Pixel conversion for 8/16/32-bpp wire formats is covered by exhaustive small-range tests (G3, §12.3). No floating-point. - The dump presenter emits RGBA directly; a `.ppm`/`.rgba` golden fixture is one SHA-256 check away.
