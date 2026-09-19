// SPDX-License-Identifier: Apache-2.0
//
// farsee — Kitty graphics protocol (ADR-0005).
//
// Generates the APC (ESC _) escape sequences for the Kitty graphics
// protocol. The protocol reference is the official Kitty graphics spec
// (clean-room). Key invariants:
//   - payload chunks ≤ 4096 base64 bytes;
//   - non-final chunks have m=1; final has m=0;
//   - control fields come from project constants (never from framebuffer data).

#include "farsee/checked.h"
#include "farsee/kitty_protocol.h"
#include "farsee/base64.h"

#include <stdio.h>
#include <string.h>

// APC start and end. Kitty graphics uses Application Program Command:
// ESC _ (APC), then 'G', control fields, payload, ESC \ (ST).
static const uint8_t APC_START[] = { 0x1B, '_' };
static const uint8_t APC_END[]   = { 0x1B, '\\' };

// Emit one chunk: ESC _ G <control>;<payload> ESC \. The semicolon that
// separates control data from the base64 payload is required by the Kitty
// graphics protocol (https://sw.kovidgoyal.net/kitty/graphics-protocol/).
// Chunks with no payload (e.g. delete) omit the semicolon.
static rfb_error emit_chunk(rfb_buffer *out,
                            const char *control_fields, size_t control_len,
                            const char *payload, size_t payload_len)
{
    // Truncate to the mark on failure so delete and direct transfers share
    // one rollback contract.
    const size_t mark = rfb_buffer_length(out);
    rfb_error e = rfb_buffer_append(out, APC_START, sizeof APC_START);
    if (e != RFB_OK) {
        rfb_buffer_truncate(out, mark);
        return e;
    }
    uint8_t g = 'G';
    e = rfb_buffer_append(out, &g, 1);
    if (e != RFB_OK) {
        rfb_buffer_truncate(out, mark);
        return e;
    }
    e = rfb_buffer_append(out, control_fields, control_len);
    if (e != RFB_OK) {
        rfb_buffer_truncate(out, mark);
        return e;
    }
    if (payload_len > 0) {
        static const uint8_t sep = (uint8_t)';';
        e = rfb_buffer_append(out, &sep, 1);
        if (e != RFB_OK) {
            rfb_buffer_truncate(out, mark);
            return e;
        }
        e = rfb_buffer_append(out, payload, payload_len);
        if (e != RFB_OK) {
            rfb_buffer_truncate(out, mark);
            return e;
        }
    }
    e = rfb_buffer_append(out, APC_END, sizeof APC_END);
    if (e != RFB_OK) {
        rfb_buffer_truncate(out, mark);
        return e;
    }
    return RFB_OK;
}

rfb_error kitty_query_capability(rfb_buffer *out)
{
    if (out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    // Query graphics support: Gi=31,s=1,a=q,t=d,v=1
    static const char query[] = "Gi=31,s=1,a=q,t=d,v=1";
    rfb_error e = rfb_buffer_append(out, APC_START, sizeof APC_START);
    if (e != RFB_OK) return e;
    e = rfb_buffer_append(out, query, sizeof query - 1);
    if (e != RFB_OK) return e;
    e = rfb_buffer_append(out, APC_END, sizeof APC_END);
    return e;
}

rfb_error kitty_parse_capability_response(const uint8_t *response, size_t len,
                                          kitty_capability *cap)
{
    if (cap == NULL) {
        return RFB_ERR_INTERNAL;
    }
    cap->supported = false;
    cap->queried = false;
    if (response == NULL || len == 0) {
        return RFB_OK;  // no response → unsupported
    }
    // Look for the graphics-support response: it contains "Gi=31" and
    // typically "OK". The exact format is ESC [ > Gi=31;OK ESC \  or
    // similar. We look for the literal "Gi=31" as a positive signal.
    for (size_t i = 0; i + 4 < len; i++) {
        if (response[i] == 'G' && response[i + 1] == 'i' &&
            response[i + 2] == '=' && response[i + 3] == '3' &&
            response[i + 4] == '1') {
            cap->queried = true;
            // Check for "OK" within the next few bytes.
            for (size_t j = i + 5; j + 1 < len && j < i + 20; j++) {
                if (response[j] == 'O' && response[j + 1] == 'K') {
                    cap->supported = true;
                    break;
                }
            }
            break;
        }
    }
    return RFB_OK;
}

rfb_error kitty_encode_direct_framebuffer(rfb_buffer *out,
                                          const uint8_t *rgba,
                                          uint32_t width, uint32_t height,
                                          kitty_format fmt,
                                          uint32_t image_id,
                                          uint32_t placement_id,
                                          bool request_ack,
                                          uint32_t place_cols,
                                          uint32_t place_rows)
{
    if (out == NULL || rgba == NULL || width == 0 || height == 0) {
        return RFB_ERR_INTERNAL;
    }
    if (out->alloc == NULL || out->alloc->alloc == NULL ||
        out->alloc->free == NULL) {
        return RFB_ERR_INTERNAL;
    }
    // Determine bytes per pixel based on format.
    uint32_t bpp = (fmt == KITTY_FMT_RGBA32) ? 4u : 3u;
    // Checked multiply: u16-source dims are capped by adapters today, but
    // this is a public emitter, and a wrapped product would undersize the
    // base64 buffer.
    size_t px = 0;
    size_t total_bytes = 0;
    if (!rfb_checked_mul_size((size_t)width, (size_t)height, &px) ||
        !rfb_checked_mul_size(px, (size_t)bpp, &total_bytes)) {
        return RFB_ERR_LIMIT;
    }
    // Base64-encode the whole image, then chunk the encoded output.
    size_t rounded = 0u;
    size_t b64_len = 0u;
    size_t b64_storage = 0u;
    if (!rfb_checked_add_size(total_bytes, 2u, &rounded) ||
        !rfb_checked_mul_size(rounded / 3u, 4u, &b64_len) ||
        !rfb_checked_add_size(b64_len, 1u, &b64_storage)) {
        return RFB_ERR_LIMIT;
    }
    rfb_allocator *allocator = out->alloc;
    char *b64 = (char *)allocator->alloc(allocator, b64_storage);
    if (b64 == NULL) {
        return RFB_ERR_NOMEM;
    }
    size_t written = rfb_base64_encode(rgba, total_bytes, b64, b64_len);
    b64[written] = '\0';

    // First chunk: include all metadata. Subsequent chunks: only m=1.
    // Control fields for the first chunk (Kitty graphics protocol):
    //   a=T  transmit+display (required — without it many terminals drop the cmd)
    //   f=<24|32>,s=<w>,v=<h>,t=d,i=<image_id>,p=<placement_id>,C=1,q=<0|1>
    //   optional c/r = placement size in cells (scaled display rectangle).
    // Placement is at the *current cursor* (upper-left of that cell). C=1
    // leaves the cursor put so status text can be parked below the image.
    char ctrl_first[192];
    int n;
    if (place_cols > 0u && place_rows > 0u) {
        n = snprintf(ctrl_first, sizeof ctrl_first,
                     "a=T,f=%u,s=%u,v=%u,t=d,i=%u,p=%u,C=1,q=%u,c=%u,r=%u",
                     (unsigned)fmt, (unsigned)width, (unsigned)height,
                     (unsigned)image_id, (unsigned)placement_id,
                     request_ack ? 0u : 2u,
                     (unsigned)place_cols, (unsigned)place_rows);
    } else if (place_rows > 0u) {
        n = snprintf(ctrl_first, sizeof ctrl_first,
                     "a=T,f=%u,s=%u,v=%u,t=d,i=%u,p=%u,C=1,q=%u,r=%u",
                     (unsigned)fmt, (unsigned)width, (unsigned)height,
                     (unsigned)image_id, (unsigned)placement_id,
                     request_ack ? 0u : 2u, (unsigned)place_rows);
    } else if (place_cols > 0u) {
        n = snprintf(ctrl_first, sizeof ctrl_first,
                     "a=T,f=%u,s=%u,v=%u,t=d,i=%u,p=%u,C=1,q=%u,c=%u",
                     (unsigned)fmt, (unsigned)width, (unsigned)height,
                     (unsigned)image_id, (unsigned)placement_id,
                     request_ack ? 0u : 2u, (unsigned)place_cols);
    } else {
        n = snprintf(ctrl_first, sizeof ctrl_first,
                     "a=T,f=%u,s=%u,v=%u,t=d,i=%u,p=%u,C=1,q=%u",
                     (unsigned)fmt, (unsigned)width, (unsigned)height,
                     (unsigned)image_id, (unsigned)placement_id,
                     request_ack ? 0u : 2u);
    }
    if (n <= 0 || (size_t)n >= sizeof ctrl_first) {
        allocator->free(allocator, b64);
        return RFB_ERR_INTERNAL;
    }

    // Emit chunks of at most KITTY_MAX_CHUNK_BYTES base64 bytes each.
    // Snapshot length so LIMIT/error rolls back only this encode's suffix
    // without removing undrained bytes from prior tiles.
    const size_t mark = rfb_buffer_length(out);
    size_t offset = 0;
    bool is_first = true;
    while (offset < written) {
        size_t remaining = written - offset;
        size_t chunk_len = remaining < KITTY_MAX_CHUNK_BYTES ? remaining : KITTY_MAX_CHUNK_BYTES;
        bool is_last = (offset + chunk_len == written);

        char ctrl[192];
        if (is_first) {
            // First chunk: full metadata + m=0 (if also last) or m=1.
            int cn = snprintf(ctrl, sizeof ctrl, "%s,m=%u",
                              ctrl_first, is_last ? 0u : 1u);
            if (cn <= 0 || (size_t)cn >= sizeof ctrl) {
                allocator->free(allocator, b64);
                rfb_buffer_truncate(out, mark);
                return RFB_ERR_INTERNAL;
            }
            rfb_error e = emit_chunk(out, ctrl, (size_t)cn, b64 + offset, chunk_len);
            if (e != RFB_OK) {
                allocator->free(allocator, b64);
                rfb_buffer_truncate(out, mark);
                return e;
            }
        } else {
            // Continuation: m=1 (or m=0 on last).
            int cn = snprintf(ctrl, sizeof ctrl, "m=%u", is_last ? 0u : 1u);
            if (cn <= 0 || (size_t)cn >= sizeof ctrl) {
                allocator->free(allocator, b64);
                rfb_buffer_truncate(out, mark);
                return RFB_ERR_INTERNAL;
            }
            rfb_error e = emit_chunk(out, ctrl, (size_t)cn, b64 + offset, chunk_len);
            if (e != RFB_OK) {
                allocator->free(allocator, b64);
                rfb_buffer_truncate(out, mark);
                return e;
            }
        }
        offset += chunk_len;
        is_first = false;
    }

    allocator->free(allocator, b64);
    return RFB_OK;
}

rfb_error kitty_encode_delete_image(rfb_buffer *out, uint32_t image_id)
{
    if (out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    char ctrl[64];
    int n = snprintf(ctrl, sizeof ctrl, "a=d,d=I,i=%u", (unsigned)image_id);
    if (n <= 0 || (size_t)n >= sizeof ctrl) {
        return RFB_ERR_INTERNAL;
    }
    return emit_chunk(out, ctrl, (size_t)n, NULL, 0);
}
