// SPDX-License-Identifier: Apache-2.0
//
// farsee — Kitty graphics protocol (plan.md §G7, ADR-0005).
//
// Generates the Kitty graphics protocol escape sequences for direct
// RGB/RGBA transfer. The protocol reference is the official Kitty
// graphics protocol specification (clean-room; no Kitty source consulted).
//
// Key constraints (plan.md §G7):
//   - payload chunks ≤ 4096 base64 bytes (plan.md §21.1);
//   - non-final chunks have `m=1` (more follows); final chunk has `m=0`;
//   - image IDs and placement IDs identify the image/placement;
//   - `q=0` permits a response; `q=2` suppresses responses;
//   - `C=1` places without moving the cursor (image still at cursor cell);
//   - `a=T` transmits and displays; `a=d` selects the delete action;
//   - Absolute screen position is the client's job: home the cursor before
//     emitting a placement when mouse hit-testing needs a fixed origin.

#ifndef FARSEE_INCLUDE_FARSEE_KITTY_PROTOCOL_H
#define FARSEE_INCLUDE_FARSEE_KITTY_PROTOCOL_H

#include "farsee/buffer.h"
#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum base64 payload per chunk (plan.md §G7, §21.1: ≤4096 bytes).
#define KITTY_MAX_CHUNK_BYTES 4096u

// Kitty graphics transmission mode.
typedef enum {
    KITTY_TRANSMIT_DIRECT = 0,  // t=d (base64 inline in the PTY)
} kitty_transmit;

// Kitty pixel format for the payload.
typedef enum {
    KITTY_FMT_RGB24 = 24,  // f=24
    KITTY_FMT_RGBA32 = 32, // f=32
} kitty_format;

// Kitty capability query result (from the terminal's response to our query).
typedef struct {
    bool supported;
    bool queried;
} kitty_capability;

// Generate the fixed Gi=31 capability query APC sequence and append it
// to `out`. The query contains `Gi=31,s=1,a=q,t=d,v=1`.
//
// The parser below looks for a `Gi=31` response marker and treats a nearby
// literal `OK` as support.
rfb_error kitty_query_capability(rfb_buffer *out);

// Parse raw terminal response bytes using the marker rule above. The parser
// sets `queried` when it finds Gi=31 and `supported` when `OK` follows
// within its bounded search window.
rfb_error kitty_parse_capability_response(const uint8_t *response, size_t len,
                                          kitty_capability *cap);

// Encode a full RGBA8 framebuffer image into Kitty direct-transfer
// commands, appending them to `out`. Chunks the base64 payload so no
// single chunk exceeds KITTY_MAX_CHUNK_BYTES (plan.md §G7). Each chunk
// is a complete ESC _ G ... ESC \ sequence.
//
// `image_id` identifies the image for later deletion; `placement_id`
// identifies this placement (for update-in-place).
// `place_cols` / `place_rows`: optional Kitty c/r placement size in cells
// (0 = omit; Kitty uses native pixel size). When set, the image is scaled
// into that rectangle so a status band can sit below the image.
rfb_error kitty_encode_direct_framebuffer(rfb_buffer *out,
                                          const uint8_t *rgba,
                                          uint32_t width, uint32_t height,
                                          kitty_format fmt,
                                          uint32_t image_id,
                                          uint32_t placement_id,
                                          bool request_ack,
                                          uint32_t place_cols,
                                          uint32_t place_rows);

// Generate the Kitty image/placement deletion escape sequence.
// Deletes all placements of the given image ID.
rfb_error kitty_encode_delete_image(rfb_buffer *out, uint32_t image_id);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_KITTY_PROTOCOL_H
