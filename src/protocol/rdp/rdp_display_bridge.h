// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP display/frame bridge (R3 gate, §15.8).
//
// Validates backend (FreeRDP software-GDI) damage metadata and publishes a
// farsee_surface_view + farsee_frame_commit. §15.8: "The adapter MUST
// validate every width, height, stride, region, and byte count received
// from backend structures before copying. 'FreeRDP already validated it'
// is not sufficient at the Farsee ownership boundary."
//
// The validation logic is pure and deterministic (testable without a live
// server). The live BeginPaint/EndPaint wiring runs against an independent
// RDP endpoint for PASS_INTEROP.
//
// PRIVATE to src/protocol/rdp/.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_DISPLAY_BRIDGE_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_DISPLAY_BRIDGE_H

#include "farsee/farsee_display.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// A raw damage rect as a backend would report it (signed, since some
// backends report negative offsets before clipping).
typedef struct rdp_backend_rect {
    int32_t x;
    int32_t y;
    int32_t width;
    int32_t height;
} rdp_backend_rect;

// Validate a backend frame descriptor: surface dimensions, stride, byte
// count, and that every damage rect lies within the surface. Returns the
// count of valid damage rects (0 means full-frame), or -1 on any failure
// (bad dimensions, overflow, out-of-bounds rect). Fail closed.
//
// `bgra_stride` is the byte stride of the backend's BGRA buffer; the
// surface is `width x height`. `max_dim` is the configured maximum.
int rdp_frame_validate(uint32_t width, uint32_t height, size_t bgra_stride,
                       size_t data_size, uint32_t max_dim,
                       const rdp_backend_rect *rects, size_t rect_count);

// Clip a backend rect to the surface [0,width)x[0,height). Returns false
// if the rect is entirely outside the surface or has non-positive extent;
// otherwise writes the clipped non-negative rect to `out`.
bool rdp_frame_clip_rect(const rdp_backend_rect *in, uint32_t width,
                         uint32_t height, farsee_rect *out);

// Build a farsee_surface_view for a BGRA8888 backend buffer of the given
// dimensions/stride. Validates first; returns false on failure. The view
// does NOT own `data` — the caller guarantees it lives until the frame
// commit is consumed (§11.2).
bool rdp_frame_build_surface_view(farsee_surface_view *out,
                                  farsee_surface_id id,
                                  uint32_t width, uint32_t height,
                                  size_t bgra_stride,
                                  const uint8_t *data, size_t data_size,
                                  uint32_t max_dim, uint64_t generation);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_PROTOCOL_RDP_RDP_DISPLAY_BRIDGE_H
