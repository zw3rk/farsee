// SPDX-License-Identifier: Apache-2.0
//
// farsee — rectangle header + Raw/CopyRect decoders (plan.md §G4, RFC 6143
// §7.6.1, §7.7.1, §7.7.2).
//
// Decoders validate every rectangle against framebuffer bounds before any
// write, convert wire pixels into the canonical RGBA8 framebuffer, and
// report the decoded rectangle as damage. No damage is emitted for a
// partially-decoded rectangle (plan.md §G4).

#ifndef FARSEE_INCLUDE_FARSEE_ENCODING_H
#define FARSEE_INCLUDE_FARSEE_ENCODING_H

#include "farsee/error.h"
#include "farsee/framebuffer.h"
#include "farsee/pixel_format.h"
#include "farsee/presenter.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// IANA encoding numbers (RFC 6143 §7.7, IANA RFB registry).
typedef enum {
    RFB_ENCODING_RAW         = 0,
    RFB_ENCODING_COPYRECT    = 1,
    RFB_ENCODING_ZRLE        = 16,
    RFB_ENCODING_CURSOR      = -239,
    RFB_ENCODING_DESKTOPSIZE = -223,
} rfb_encoding;

// A rectangle header as it appears in FramebufferUpdate.
typedef struct rfb_rect_header {
    uint16_t x;
    uint16_t y;
    uint16_t width;
    uint16_t height;
    int32_t  encoding;   // signed: pseudo-encodings are negative
} rfb_rect_header;

// Decode a Raw rectangle (RFC 6143 §7.7.1).
//
// `payload` is the wire bytes for this rectangle only (width*height*bpp/8
// bytes). The decoder:
//   1. validates x+width, y+height against the framebuffer (overflow-safe);
//   2. validates payload_len is exactly width*height*bpp/8;
//   3. converts each wire pixel to RGBA8 and writes it into the framebuffer;
//   4. on any failure returns an error and writes NO pixels (the framebuffer
//      is left untouched — no partial damage);
//   5. on success fills `*out_damage` with the decoded rectangle.
rfb_error rfb_decode_raw(rfb_framebuffer *fb,
                         const rfb_pixel_format *pf,
                         const rfb_rect_header *rh,
                         const uint8_t *payload, size_t payload_len,
                         rfb_rect *out_damage);

// Decode a CopyRect rectangle (RFC 6143 §7.7.2).
//
// `payload` is the 4 bytes: u16 src-x, u16 src-y (big-endian). The
// decoder copies the source rectangle into the destination, handling
// overlap correctly via memmove semantics (plan.md §G4). Bounds are
// validated for both source and destination before any write.
rfb_error rfb_decode_copyrect(rfb_framebuffer *fb,
                              const rfb_rect_header *rh,
                              const uint8_t *payload, size_t payload_len,
                              rfb_rect *out_damage);

// A decoded cursor sprite (Cursor pseudo-encoding, RFC 6143 §7.7.9). The
// cursor is NOT written into the authoritative framebuffer (plan.md §G6:
// "cursor excluded from authoritative remote framebuffer"); the presenter
// composites it as a separate layer.
typedef struct rfb_cursor {
    uint16_t hotspot_x;
    uint16_t hotspot_y;
    uint16_t width;
    uint16_t height;
    uint8_t *rgba;   // width*height*4 bytes, owned by the caller's buffer
    bool     valid;
} rfb_cursor;

// Decode a Cursor pseudo-encoding rectangle (RFC 6143 §7.7.9).
//
// `payload` is width*height*bpp/8 bytes of source pixel data followed by
// width*height/8 bytes of monochrome mask (1 = visible, 0 = transparent).
// The decoder converts the cursor into RGBA8 with proper alpha from the
// mask: masked-off pixels get alpha=0, visible pixels get alpha=255.
// `cursor->rgba` is heap-allocated via the framebuffer's allocator.
rfb_error rfb_decode_cursor(rfb_cursor *cursor,
                            const rfb_pixel_format *pf,
                            const rfb_rect_header *rh,
                            const uint8_t *payload, size_t payload_len,
                            rfb_allocator *alloc);

// Release a decoded cursor's storage.
void rfb_cursor_destroy(rfb_cursor *cursor, rfb_allocator *alloc);

// Decode a DesktopSize pseudo-encoding rectangle (RFC 6143 §7.7.10).
//
// DesktopSize has NO payload; the rectangle's width/height is the new
// framebuffer size. The decoder transactionally resizes the framebuffer
// (plan.md §G6: "resize allocation failure leaves session operational on
// old framebuffer"). Returns RFB_OK and bumps generation on success.
// `byte_limit` bounds the new allocation.
rfb_error rfb_decode_desktopsize(rfb_framebuffer *fb,
                                 const rfb_rect_header *rh,
                                 size_t byte_limit,
                                 rfb_rect *out_damage);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_ENCODING_H
