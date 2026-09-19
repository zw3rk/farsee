// SPDX-License-Identifier: Apache-2.0
//
// farsee — rectangle headers plus Raw, CopyRect, Cursor, and DesktopSize
// decoders (plan.md §G4, §G6; RFC 6143 §7.6.1, §7.7.1, §7.7.2,
// §7.7.9, §7.7.10).
//
// Raw and CopyRect validate geometry before writing. Raw converts wire
// pixels to RGBA8, CopyRect handles overlap, Cursor returns a separate RGBA
// sprite, and DesktopSize resizes the framebuffer transactionally.

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
// Apple encodings 0x03f3 and 0x0450 are private.
typedef enum {
    RFB_ENCODING_RAW         = 0,
    RFB_ENCODING_COPYRECT    = 1,
    RFB_ENCODING_ZRLE        = 16,
    RFB_ENCODING_APPLE_MVS   = 0x03f3, // MultiVariant (MVS)
    RFB_ENCODING_APPLE_0450  = 0x0450, // five-byte-per-pixel envelope
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
// "cursor excluded from authoritative remote framebuffer"); the presentation
// path composites it into its copied frame.
typedef struct rfb_cursor {
    uint16_t hotspot_x;
    uint16_t hotspot_y;
    uint16_t width;
    uint16_t height;
    uint8_t *rgba;   // width*height*4 bytes; release with rfb_cursor_destroy
    bool     valid;
} rfb_cursor;

// Decode a Cursor pseudo-encoding rectangle (RFC 6143 §7.7.9).
//
// `payload` is width*height*bpp/8 bytes of source pixels followed by
// `height` mask rows of ceil(width/8) bytes (MSB first, row-padded).
// The decoder converts the cursor to RGBA8 and sets alpha to 255 for a
// visible mask bit or 0 otherwise. It allocates `cursor->rgba` with `alloc`;
// release that storage with the same allocator through rfb_cursor_destroy.
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
