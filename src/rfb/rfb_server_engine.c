// SPDX-License-Identifier: Apache-2.0
//
// farsee — pure RFB server→client demux/decode (extracted from rfb_session).
// Buffer in → progress out. No fd, no getenv, no product fprintf.

#include "farsee/rfb_server_engine.h"

#include "farsee/bytes.h"
#include "farsee/checked.h"
#include "farsee/encoding_zrle.h"
#include "farsee/fbupdate.h"
#include "farsee/limits.h"
#include "farsee/server_messages.h"

#include <string.h>

void rfb_server_engine_init(rfb_server_engine *eng)
{
    if (eng == NULL) {
        return;
    }
    memset(eng, 0, sizeof *eng);
}

// --- payload length / decode -----------------------------------------------

static rfb_error payload_len_for_rect(const rfb_pixel_format *pf,
                                      const rfb_rect_header *rh,
                                      const uint8_t *after_header,
                                      size_t avail_after,
                                      size_t *out_payload,
                                      size_t *out_prefix)
{
    *out_prefix = 0;
    *out_payload = 0;
    const uint32_t bpp = (uint32_t)pf->bits_per_pixel / 8u;

    switch (rh->encoding) {
    case RFB_ENCODING_RAW: {
        size_t n = 0;
        if (!rfb_checked_rect_bytes(rh->width, rh->height, bpp, &n)) {
            return RFB_ERR_LIMIT;
        }
        *out_payload = n;
        return RFB_OK;
    }
    case RFB_ENCODING_COPYRECT:
        *out_payload = 4u;
        return RFB_OK;
    case RFB_ENCODING_ZRLE: {
        // u32 length + that many zlib bytes (RFC 6143 §7.7.6).
        if (avail_after < 4u) {
            return RFB_ERR_PROTOCOL; // incomplete length; caller waits
        }
        uint32_t zlen = ((uint32_t)after_header[0] << 24) |
                        ((uint32_t)after_header[1] << 16) |
                        ((uint32_t)after_header[2] << 8) |
                        (uint32_t)after_header[3];
        if ((size_t)zlen > RFB_LIMIT_COMPRESSED_RECT_BYTES) {
            return RFB_ERR_LIMIT;
        }
        *out_prefix = 4u;
        *out_payload = (size_t)zlen;
        return RFB_OK;
    }
    case RFB_ENCODING_CURSOR: {
        size_t pixel_bytes = 0;
        if (rh->width == 0 || rh->height == 0) {
            *out_payload = 0;
            return RFB_OK;
        }
        if (!rfb_checked_rect_bytes(rh->width, rh->height, bpp, &pixel_bytes)) {
            return RFB_ERR_LIMIT;
        }
        size_t mask_row = ((size_t)rh->width + 7u) / 8u;
        size_t mask_bytes = 0;
        if (!rfb_checked_mul_size(mask_row, rh->height, &mask_bytes)) {
            return RFB_ERR_LIMIT;
        }
        size_t total = 0;
        if (!rfb_checked_add_size(pixel_bytes, mask_bytes, &total)) {
            return RFB_ERR_LIMIT;
        }
        *out_payload = total;
        return RFB_OK;
    }
    case RFB_ENCODING_DESKTOPSIZE:
        *out_payload = 0;
        return RFB_OK;
    default:
        return RFB_ERR_UNSUPPORTED;
    }
}

static rfb_error decode_one_rect(rfb_server_engine_ctx *ctx,
                                 const rfb_rect_header *rh,
                                 const uint8_t *payload,
                                 size_t payload_len)
{
    rfb_rect dmg;
    memset(&dmg, 0, sizeof dmg);
    rfb_error e = RFB_OK;

    switch (rh->encoding) {
    case RFB_ENCODING_RAW:
        e = rfb_decode_raw(ctx->fb, ctx->pf, rh, payload, payload_len, &dmg);
        break;
    case RFB_ENCODING_COPYRECT:
        e = rfb_decode_copyrect(ctx->fb, rh, payload, payload_len, &dmg);
        break;
    case RFB_ENCODING_ZRLE:
        if (ctx->zstream == NULL) {
            e = RFB_ERR_INTERNAL;
            break;
        }
        e = rfb_decode_zrle(ctx->fb, ctx->pf, rh, ctx->zstream,
                            payload, payload_len,
                            RFB_LIMIT_COMPRESSED_RECT_BYTES, &dmg);
        break;
    case RFB_ENCODING_CURSOR:
        rfb_cursor_destroy(ctx->cursor, ctx->alloc);
        e = rfb_decode_cursor(ctx->cursor, ctx->pf, rh, payload, payload_len,
                              ctx->alloc);
        break;
    case RFB_ENCODING_DESKTOPSIZE:
        e = rfb_decode_desktopsize(ctx->fb, rh, RFB_LIMIT_FB_BYTES_POLICY,
                                   &dmg);
        if (e == RFB_OK) {
            if (ctx->fb_width != NULL) {
                *ctx->fb_width = rh->width;
            }
            if (ctx->fb_height != NULL) {
                *ctx->fb_height = rh->height;
            }
            if (ctx->pacing != NULL) {
                rfb_pacing_force_full_refresh(ctx->pacing);
            }
            if (ctx->hooks.on_desktop_size != NULL) {
                ctx->hooks.on_desktop_size(ctx->hooks.hook_ctx, rh->width,
                                           rh->height);
            }
        }
        break;
    default:
        e = RFB_ERR_UNSUPPORTED;
        break;
    }
    return e;
}

static void hook_publish(rfb_server_engine_ctx *ctx)
{
    if (ctx->hooks.on_publish != NULL) {
        ctx->hooks.on_publish(ctx->hooks.hook_ctx);
    }
}

// --- demux -----------------------------------------------------------------

rfb_error rfb_server_engine_process_in(rfb_server_engine_ctx *ctx,
                                       bool *progress)
{
    if (ctx == NULL || progress == NULL || ctx->eng == NULL ||
        ctx->in == NULL || ctx->fb == NULL || ctx->pf == NULL ||
        ctx->cursor == NULL || ctx->alloc == NULL) {
        return RFB_ERR_INTERNAL;
    }
    *progress = false;
    rfb_server_engine *eng = ctx->eng;

    for (;;) {
        const uint8_t *data = rfb_buffer_data(ctx->in);
        size_t len = rfb_buffer_length(ctx->in);

        if (!eng->in_fbupdate) {
            if (len < 1u) {
                return RFB_OK;
            }
            uint8_t type = data[0];

            // Apple cleartext MVP: u16be control records before classic FBU.
            {
                size_t need = 0u;
                if (rfb_session_apple_u16be_control_eligible(
                        ctx->dialect, data, len, &need)) {
                    if (len < need) {
                        return RFB_OK;
                    }
                    rfb_buffer_consume(ctx->in, need);
                    *progress = true;
                    continue;
                }
            }

            if (type == 0) {
                // FramebufferUpdate header: 4 bytes.
                if (len < 4u) {
                    return RFB_OK;
                }
                rfb_reader r = rfb_reader_make(data, 4u);
                uint16_t nrects = 0;
                rfb_error e = rfb_parse_fbupdate_header(&r, &nrects);
                if (e != RFB_OK) {
                    return e;
                }
                rfb_buffer_consume(ctx->in, 4u);
                *progress = true;
                eng->in_fbupdate = true;
                eng->rects_remaining = nrects;
                eng->rects_total = nrects;
                eng->rects_decoded = 0;
                if (ctx->pacing != NULL) {
                    rfb_pacing_update_received(ctx->pacing);
                }
                if (ctx->hooks.on_fbu_begin != NULL) {
                    ctx->hooks.on_fbu_begin(ctx->hooks.hook_ctx, nrects);
                }
                if (nrects == 0) {
                    eng->in_fbupdate = false;
                    hook_publish(ctx);
                }
                continue;
            }
            if (type == 1) {
                // SetColourMapEntries: type + pad + first + count + 6*count.
                if (len < 6u) {
                    return RFB_OK;
                }
                uint16_t count =
                    (uint16_t)(((uint16_t)data[4] << 8) | data[5]);
                size_t need = 6u + (size_t)count * 6u;
                if (len < need) {
                    return RFB_OK;
                }
                rfb_buffer_consume(ctx->in, need);
                *progress = true;
                continue;
            }
            if (type == 2) {
                // Bell (RFC 6143 §7.6.3): single type byte, no payload.
                rfb_buffer_consume(ctx->in, 1u);
                *progress = true;
                {
                    // Type already consumed; parser expects empty remainder.
                    static const uint8_t empty = 0;
                    rfb_reader r = rfb_reader_make(&empty, 0);
                    rfb_error e = rfb_parse_bell(&r);
                    if (e != RFB_OK) {
                        return e;
                    }
                }
                if (ctx->hooks.on_bell != NULL) {
                    ctx->hooks.on_bell(ctx->hooks.hook_ctx);
                }
                continue;
            }
            if (type == 3) {
                // ServerCutText: type + pad[3] + u32 len + bytes.
                if (len < 8u) {
                    return RFB_OK;
                }
                uint32_t clen = ((uint32_t)data[4] << 24) |
                                ((uint32_t)data[5] << 16) |
                                ((uint32_t)data[6] << 8) |
                                (uint32_t)data[7];
                if ((size_t)clen > RFB_LIMIT_CLIPBOARD_BYTES) {
                    return RFB_ERR_LIMIT;
                }
                size_t need = 8u + (size_t)clen;
                if (len < need) {
                    return RFB_OK;
                }
                // Validate with the shared parser (type already at data[0];
                // parser consumes pad+len+bytes after the type byte).
                {
                    rfb_reader r = rfb_reader_make(data + 1u, need - 1u);
                    // Stack scratch for small texts; for large lengths the
                    // hook may still observe the wire slice below. Parser
                    // hard-limit already checked; cap scratch to avoid VLA.
                    uint8_t scratch[256];
                    size_t out_len = 0;
                    size_t cap = sizeof scratch;
                    if ((size_t)clen > cap) {
                        // Skip full parse copy for oversize; length already
                        // bounded by RFB_LIMIT_CLIPBOARD_BYTES and presence
                        // of the full message is verified.
                        out_len = (size_t)clen;
                    } else {
                        rfb_error e = rfb_parse_server_cut_text(
                            &r, scratch, cap, &out_len,
                            RFB_LIMIT_CLIPBOARD_BYTES);
                        if (e != RFB_OK) {
                            return e;
                        }
                    }
                    if (ctx->hooks.on_cut_text != NULL) {
                        const uint8_t *text =
                            (clen == 0u) ? NULL : (data + 8u);
                        ctx->hooks.on_cut_text(ctx->hooks.hook_ctx, text,
                                               (size_t)clen);
                    }
                    (void)out_len;
                }
                rfb_buffer_consume(ctx->in, need);
                *progress = true;
                continue;
            }
            // Unknown message type — fail closed.
            if (eng->last_unexpected_type == 0u) {
                eng->last_unexpected_type = type;
            }
            return RFB_ERR_PROTOCOL;
        }

        // In FramebufferUpdate: next rectangle.
        if (eng->rects_remaining == 0) {
            eng->in_fbupdate = false;
            hook_publish(ctx);
            continue;
        }
        if (len < 12u) {
            return RFB_OK;
        }
        rfb_reader r = rfb_reader_make(data, len);
        rfb_rect_header rh;
        rfb_error e = rfb_parse_rect_header(&r, &rh);
        if (e != RFB_OK) {
            return e;
        }
        // Bounds / size gates *before* waiting for a multi-MiB payload
        // (full2 T8): hostile huge RAW/Cursor headers must not grow the
        // input buffer to the hard limit first.
        if (rh.encoding == RFB_ENCODING_CURSOR) {
            if (rh.width > 256u || rh.height > 256u) {
                return RFB_ERR_LIMIT;
            }
        } else if (rh.encoding != RFB_ENCODING_DESKTOPSIZE) {
            if (ctx->fb != NULL) {
                const uint32_t fw = ctx->fb->width;
                const uint32_t fh = ctx->fb->height;
                if (fw > 0u && fh > 0u) {
                    if ((uint32_t)rh.x + (uint32_t)rh.width > fw ||
                        (uint32_t)rh.y + (uint32_t)rh.height > fh) {
                        return RFB_ERR_PROTOCOL;
                    }
                }
            }
            if (rh.width > RFB_LIMIT_FB_WIDTH_MAX ||
                rh.height > RFB_LIMIT_FB_HEIGHT_MAX) {
                return RFB_ERR_LIMIT;
            }
        }
        const uint8_t *after = data + 12u;
        size_t avail_after = len - 12u;
        size_t payload = 0;
        size_t prefix = 0;
        e = payload_len_for_rect(ctx->pf, &rh, after, avail_after, &payload,
                                 &prefix);
        if (e == RFB_ERR_PROTOCOL && rh.encoding == RFB_ENCODING_ZRLE &&
            avail_after < 4u) {
            return RFB_OK; // incomplete ZRLE length prefix
        }
        if (e != RFB_OK) {
            return e;
        }
        // Cap assembled rect against presentation budget before waiting.
        if (payload > RFB_LIMIT_PRESENTATION_BYTES) {
            return RFB_ERR_LIMIT;
        }
        size_t total_need = 12u + prefix + payload;
        if (len < total_need) {
            return RFB_OK;
        }
        const uint8_t *body = data + 12u + prefix;
        e = decode_one_rect(ctx, &rh, body, payload);
        if (e != RFB_OK) {
            return e;
        }
        rfb_buffer_consume(ctx->in, total_need);
        *progress = true;
        eng->rects_remaining--;
        eng->rects_decoded++;
        if (eng->rects_remaining == 0) {
            eng->in_fbupdate = false;
            hook_publish(ctx);
        }
    }
}
