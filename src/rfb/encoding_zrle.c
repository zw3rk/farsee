// SPDX-License-Identifier: Apache-2.0
//
// farsee — ZRLE decoder (plan.md §G8, RFC 6143 §7.7.6).
//
// ZRLE splits a rectangle into 64×64 tiles. The entire rectangle's tile
// data is zlib-compressed as one stream (persistent across rectangles).
// Each tile begins with a subencoding byte:
//   0:                raw (uncompressed pixels)
//   1:                solid (single color fills the tile)
//   2..16:            packed palette
//   128:              plain RLE
//   129..255:         palette RLE
//
// This slice implements: bounds validation, zlib inflation, 64×64 tile
// traversal, and the raw + solid subencodings. RLE subencodings will be
// added in the next slice.

#include "farsee/encoding_zrle.h"
#include "farsee/checked.h"
#include "farsee/pixel_convert.h"
#include "farsee/bytes.h"

#include <stdlib.h>
#include <string.h>

#define ZRLE_TILE_SIZE 64u

// Validate that (x,y,w,h) lies entirely within the framebuffer.
static bool rect_in_bounds(const rfb_framebuffer *fb,
                           uint32_t x, uint32_t y, uint32_t w, uint32_t h)
{
    if (w == 0 || h == 0) return false;  // LCOV_EXCL_BR_LINE
    uint32_t xe = 0, ye = 0;
    if (!rfb_checked_add_u32(x, w, &xe)) return false;  // LCOV_EXCL_BR_LINE
    if (!rfb_checked_add_u32(y, h, &ye)) return false;  // LCOV_EXCL_BR_LINE
    return xe <= fb->width && ye <= fb->height;
}

// --- CPIXEL helpers (RFC 6143 §7.7.6) -----------------------------------
// For 32bpp depth-24 with max=255 and shifts R=16,G=8,B=0, a CPIXEL is
// 3 bytes: the low 3 bytes of the pixel word (the high byte is always 0).
// For other formats, CPIXEL uses the full pixel width. We detect CPIXEL
// size by checking if the format is the canonical 32bpp.

static size_t cpixel_size(const rfb_pixel_format *pf)
{
    // For 32bpp with depth <= 24 and all channel maxima fitting in a byte,
    // CPIXEL is 3 bytes (drop the unused high byte).
    if (pf->bits_per_pixel == 32 && pf->depth <= 24 &&  // LCOV_EXCL_BR_LINE
        pf->red_max <= 255 && pf->green_max <= 255 && pf->blue_max <= 255) {  // LCOV_EXCL_BR_LINE
        return 3u;
    }
    return (size_t)pf->bits_per_pixel / 8u;
}

// Read a CPIXEL from `data` and convert to RGBA8. Returns the number of
// bytes consumed (cpixel_size). Sets `*consumed` on success.
static rfb_error read_cpixel(const rfb_pixel_format *pf,
                             const uint8_t *data, size_t data_len,
                             uint8_t out_rgba[4], size_t *consumed)
{
    size_t cs = cpixel_size(pf);
    if (data_len < cs) {  // LCOV_EXCL_BR_LINE
        return RFB_ERR_PROTOCOL;
    }
    // 3-byte CPIXEL on 32bpp (RFC 6143 §7.7.6): reconstruct a full PIXEL
    // then convert via the shared path (must match Raw — type-33 keeps PF).
    // LE: CPIXEL is least-significant 3 bytes → pad high byte 0 at end.
    // BE: most-significant byte of PIXEL is omitted → pad 0 at the start.
    if (cs == 3 && pf->bits_per_pixel == 32) {  // LCOV_EXCL_BR_LINE
        uint8_t full[4];
        if (pf->big_endian) {
            full[0] = 0;
            full[1] = data[0];
            full[2] = data[1];
            full[3] = data[2];
        } else {
            full[0] = data[0];
            full[1] = data[1];
            full[2] = data[2];
            full[3] = 0;
        }
        rfb_pixel_to_rgba8(pf, full, out_rgba);
        *consumed = 3;
        return RFB_OK;
    }
    // Full pixel (1/2/4-byte).
    rfb_pixel_to_rgba8(pf, data, out_rgba);
    *consumed = cs;
    return RFB_OK;
}

// Max legal run for any tile (64×64). Cap early so uint32 accumulation
// cannot wrap past the fill-guard (multi-review 2026-07-31 T1).
#define ZRLE_MAX_RUN_PIXELS (ZRLE_TILE_SIZE * ZRLE_TILE_SIZE)

// Read a ZRLE run length from `data`. The encoding is: a sequence of
// bytes where 255 means "add 255 and continue", and a byte < 255 means
// "add (byte+1) and stop". Returns total run length, sets *consumed.
// Fails closed if the run would exceed a full tile or wrap uint32_t.
static rfb_error read_run_length(const uint8_t *data, size_t data_len,
                                 uint32_t *out_len, size_t *consumed)
{
    uint32_t total = 0;
    size_t i = 0;
    while (i < data_len) {
        uint8_t b = data[i];
        i++;
        uint32_t add = (b == 255) ? 255u : ((uint32_t)b + 1u);
        // Wrap or oversize → protocol error before fill loop can smash stack.
        if (total > ZRLE_MAX_RUN_PIXELS ||
            add > ZRLE_MAX_RUN_PIXELS - total) {
            return RFB_ERR_PROTOCOL;
        }
        total += add;
        if (b != 255) {
            *out_len = total;
            *consumed = i;
            return RFB_OK;
        }
    }
    return RFB_ERR_PROTOCOL;  // ran out of data
}

// Decode one tile using the subencoding dispatch. Returns the number of
// tile-data bytes consumed. Decodes into a temporary RGBA buffer and only
// commits to the framebuffer on full success — preserves the "no partial
// damage on failure" transactional invariant (encoding.h contract).
static rfb_error decode_tile(rfb_framebuffer *fb,
                             const rfb_pixel_format *pf,
                             uint32_t origin_x, uint32_t origin_y,
                             uint32_t tile_w, uint32_t tile_h,
                             const uint8_t *data, size_t data_len,
                             size_t *consumed)
{
    if (data_len < 1) {
        return RFB_ERR_PROTOCOL;
    }
    uint8_t subenc = data[0];
    size_t bpp = (size_t)pf->bits_per_pixel / 8u;
    uint32_t total_pixels = tile_w * tile_h;

    // Temporary RGBA staging buffer. Max tile = 64×64 = 4096 pixels.
    // 4096 * 4 = 16384 bytes — fits on the stack.
    uint8_t tile_rgba[ZRLE_TILE_SIZE * ZRLE_TILE_SIZE * 4];
    size_t tile_rgba_len = (size_t)total_pixels * 4u;

    if (subenc == 0) {
        // Raw tile: sequence of CPIXEL values (RFC 6143 §7.7.6), NOT
        // full-width wire pixels. For 32bpp/depth≤24 that is 3 bytes per
        // pixel; otherwise bits_per_pixel/8. Real macOS Screen Sharing
        // type-33 cleartext ZRLE uses CPIXEL raw tiles exclusively on
        // large desktops — treating them as 4-byte pixels mis-sized the
        // stream and failed with RFB_ERR_PROTOCOL mid-frame.
        size_t cs = cpixel_size(pf);
        size_t pixel_bytes = 0;
        if (!rfb_checked_mul_size((size_t)total_pixels, cs, &pixel_bytes)) {
            return RFB_ERR_LIMIT;
        }
        if (data_len < 1u + pixel_bytes) {
            return RFB_ERR_PROTOCOL;
        }
        const uint8_t *src = data + 1;
        if (cs == (size_t)bpp) {
            // Full-width CPIXEL (8/16 bpp or 32bpp without 3-byte packing).
            for (uint32_t row = 0; row < tile_h; row++) {
                rfb_convert_run(pf, src, tile_rgba + row * tile_w * 4u, tile_w);
                src += tile_w * bpp;
            }
        } else {
            // 3-byte CPIXEL path (common 32bpp depth-24).
            for (uint32_t i = 0; i < total_pixels; i++) {
                size_t c = 0;
                rfb_error e = read_cpixel(pf, src, data_len - 1u - (size_t)i * cs,
                                          tile_rgba + i * 4u, &c);
                if (e != RFB_OK) {
                    return e;
                }
                src += c;
            }
        }
        *consumed = 1u + pixel_bytes;
    } else if (subenc == 1) {
        // Solid tile: one CPIXEL fills the entire tile.
        uint8_t rgba[4];
        size_t cpix_consumed = 0;
        rfb_error e = read_cpixel(pf, data + 1, data_len - 1, rgba, &cpix_consumed);
        if (e != RFB_OK) return e;
        for (uint32_t i = 0; i < total_pixels; i++) {
            tile_rgba[i * 4u]     = rgba[0];
            tile_rgba[i * 4u + 1] = rgba[1];
            tile_rgba[i * 4u + 2] = rgba[2];
            tile_rgba[i * 4u + 3] = rgba[3];
        }
        *consumed = 1u + cpix_consumed;
    } else if (subenc >= 2 && subenc <= 16) {
        // Packed-palette: subenc = palette size (2..16).
        // RFC 6143 §7.7.6: index width is ONLY 1, 2, or 4 bits —
        //   paletteSize == 2       → 1 bit
        //   3 ≤ paletteSize ≤ 4    → 2 bits
        //   5 ≤ paletteSize ≤ 16   → 4 bits
        // Never ceil(log2): sizes 5–8 would wrongly use 3 bits and desync.
        uint32_t pal_size = subenc;
        const uint32_t bits_per_idx =
            (pal_size == 2u) ? 1u : (pal_size <= 4u) ? 2u : 4u;
        uint8_t pal_rgba[16][4];
        size_t pos = 1;
        for (uint32_t i = 0; i < pal_size; i++) {
            size_t cpix_consumed = 0;
            rfb_error e = read_cpixel(pf, data + pos, data_len - pos,
                                      pal_rgba[i], &cpix_consumed);
            if (e != RFB_OK) return e;
            pos += cpix_consumed;
        }
        // RFC 6143 §7.7.6: packed palette is encoded row-by-row; each row
        // is padded to a byte boundary. Flat bitstreams across rows desync
        // on multi-row tiles with edge widths (width*bpp not multiple of 8).
        const size_t row_bytes =
            (size_t)((tile_w * bits_per_idx + 7u) / 8u);
        size_t packed_bytes = 0;
        if (!rfb_checked_mul_size(row_bytes, (size_t)tile_h, &packed_bytes)) {
            return RFB_ERR_LIMIT;
        }
        if (data_len < pos + packed_bytes) {
            return RFB_ERR_PROTOCOL;
        }
        const uint8_t *packed = data + pos;
        for (uint32_t row = 0; row < tile_h; row++) {
            const uint8_t *rowp = packed + (size_t)row * row_bytes;
            uint32_t bit_pos = 0;
            for (uint32_t col = 0; col < tile_w; col++) {
                size_t byte_pos = bit_pos / 8u;
                uint32_t bit_off = bit_pos % 8u;
                uint32_t idx = 0;
                for (uint32_t b = 0; b < bits_per_idx; b++) {
                    size_t bp = byte_pos + (bit_off + b) / 8u;
                    uint32_t bo = 7u - ((bit_off + b) % 8u);
                    if (bp < row_bytes) {
                        idx = (idx << 1) | ((rowp[bp] >> bo) & 1u);
                    }
                }
                if (idx >= pal_size) {
                    return RFB_ERR_PROTOCOL;
                }
                const uint32_t i = row * tile_w + col;
                tile_rgba[i * 4u]     = pal_rgba[idx][0];
                tile_rgba[i * 4u + 1] = pal_rgba[idx][1];
                tile_rgba[i * 4u + 2] = pal_rgba[idx][2];
                tile_rgba[i * 4u + 3] = pal_rgba[idx][3];
                bit_pos += bits_per_idx;
            }
        }
        *consumed = pos + packed_bytes;
    } else if (subenc == 128) {
        // Plain RLE: runs of identical pixels.
        size_t pos = 1;
        uint32_t pixels_written = 0;
        while (pixels_written < total_pixels) {
            uint8_t rgba[4];
            size_t cpix_consumed = 0;
            rfb_error e = read_cpixel(pf, data + pos, data_len - pos,
                                      rgba, &cpix_consumed);
            if (e != RFB_OK) return e;
            pos += cpix_consumed;
            uint32_t run = 0;
            size_t run_consumed = 0;
            e = read_run_length(data + pos, data_len - pos, &run, &run_consumed);
            if (e != RFB_OK) return e;
            pos += run_consumed;
            // Subtraction form: immune to uint32 wrap of sum (T1).
            if (run == 0u || run > total_pixels - pixels_written) {
                return RFB_ERR_PROTOCOL;
            }
            for (uint32_t i = 0; i < run; i++) {
                uint32_t idx = pixels_written + i;
                tile_rgba[idx * 4u]     = rgba[0];
                tile_rgba[idx * 4u + 1] = rgba[1];
                tile_rgba[idx * 4u + 2] = rgba[2];
                tile_rgba[idx * 4u + 3] = rgba[3];
            }
            pixels_written += run;
        }
        *consumed = pos;
    } else if (subenc >= 129) {
        // Palette RLE: subenc = 128 + palette_size (RFC 6143 §7.7.6).
        // Each run is a palette index byte:
        //   - bottom 7 bits = palette index
        //   - top bit set   → run length follows (same encoding as plain RLE)
        //   - top bit clear → run length is 1
        // Real Screen Sharing (type-33 cleartext ZRLE) uses this form; always
        // reading a run length after every index was a protocol bug.
        uint32_t pal_size = subenc - 128u;
        uint8_t pal_rgba[127][4];
        size_t pos = 1;
        for (uint32_t i = 0; i < pal_size; i++) {
            size_t cpix_consumed = 0;
            rfb_error e = read_cpixel(pf, data + pos, data_len - pos,
                                      pal_rgba[i], &cpix_consumed);
            if (e != RFB_OK) return e;
            pos += cpix_consumed;
        }
        uint32_t pixels_written = 0;
        while (pixels_written < total_pixels) {
            if (pos >= data_len) return RFB_ERR_PROTOCOL;
            uint8_t b = data[pos++];
            uint32_t idx = (uint32_t)(b & 0x7fu);
            if (idx >= pal_size) {
                return RFB_ERR_PROTOCOL;
            }
            uint32_t run = 1u;
            if ((b & 0x80u) != 0u) {
                size_t run_consumed = 0;
                rfb_error e = read_run_length(data + pos, data_len - pos,
                                              &run, &run_consumed);
                if (e != RFB_OK) return e;
                pos += run_consumed;
            }
            if (run == 0u || run > total_pixels - pixels_written) {
                return RFB_ERR_PROTOCOL;
            }
            for (uint32_t i = 0; i < run; i++) {
                uint32_t pidx = pixels_written + i;
                tile_rgba[pidx * 4u]     = pal_rgba[idx][0];
                tile_rgba[pidx * 4u + 1] = pal_rgba[idx][1];
                tile_rgba[pidx * 4u + 2] = pal_rgba[idx][2];
                tile_rgba[pidx * 4u + 3] = pal_rgba[idx][3];
            }
            pixels_written += run;
        }
        *consumed = pos;
    } else {
        // LCOV_EXCL_START
        // subenc 17..127: undefined in the spec.
        return RFB_ERR_UNSUPPORTED;
        // LCOV_EXCL_STOP
    }

    // Commit the decoded tile to the framebuffer only after full success.
    for (uint32_t row = 0; row < tile_h; row++) {
        uint8_t *dst = rfb_framebuffer_pixel(fb, origin_x, origin_y + row);
        memcpy(dst, tile_rgba + (size_t)row * tile_w * 4u,
               (size_t)tile_w * 4u);
    }
    (void)tile_rgba_len;
    return RFB_OK;
}

rfb_error rfb_decode_zrle(rfb_framebuffer *fb,
                          const rfb_pixel_format *pf,
                          const rfb_rect_header *rh,
                          rfb_zlib_stream *zstream,
                          const uint8_t *payload, size_t payload_len,
                          size_t byte_limit,
                          rfb_rect *out_damage)
{
    // LCOV_EXCL_START
    if (fb == NULL || pf == NULL || rh == NULL || zstream == NULL ||  // LCOV_EXCL_BR_LINE
        payload == NULL || out_damage == NULL) {
        return RFB_ERR_INTERNAL;
    }
    // LCOV_EXCL_STOP
    if (!rfb_pixel_format_valid(pf)) {  // LCOV_EXCL_BR_LINE
        return RFB_ERR_PROTOCOL;
    }
    // Bounds check before any write.
    if (!rect_in_bounds(fb, rh->x, rh->y, rh->width, rh->height)) {
        return RFB_ERR_PROTOCOL;
    }
    // Inflate scratch: max of plain-RLE unit runs and palette-RLE unit runs
    // (loop r2): plain = 1 + tile_px*(cs+1); palette = 1 + 127*cs + tile_px*2
    // (127-entry palette + index|0x80 + len0 per pixel). At cs==1 palette
    // is larger (8320 vs 8193).
    const size_t cs = cpixel_size(pf);
    const uint32_t tiles_x =
        (rh->width + ZRLE_TILE_SIZE - 1u) / ZRLE_TILE_SIZE;
    const uint32_t tiles_y =
        (rh->height + ZRLE_TILE_SIZE - 1u) / ZRLE_TILE_SIZE;
    size_t need = 0;
    {
        size_t tiles = 0;
        size_t tile_px = (size_t)ZRLE_TILE_SIZE * (size_t)ZRLE_TILE_SIZE;
        size_t plain = 0;
        size_t palette = 0;
        size_t per_tile = 0;
        if (!rfb_checked_mul_size((size_t)tiles_x, (size_t)tiles_y, &tiles)) {
            return RFB_ERR_LIMIT;
        }
        // plain: 1 + tile_px*(cs+1)
        if (!rfb_checked_mul_size(tile_px, cs + 1u, &plain) ||
            plain > SIZE_MAX - 1u) {
            return RFB_ERR_LIMIT;
        }
        plain += 1u;
        // palette: 1 + 127*cs + 2*tile_px
        if (!rfb_checked_mul_size(127u, cs, &palette) ||
            palette > SIZE_MAX - 1u) {
            return RFB_ERR_LIMIT;
        }
        palette += 1u;
        size_t runs = 0;
        if (!rfb_checked_mul_size(tile_px, 2u, &runs) ||
            palette > SIZE_MAX - runs) {
            return RFB_ERR_LIMIT;
        }
        palette += runs;
        per_tile = (plain > palette) ? plain : palette;
        if (!rfb_checked_mul_size(tiles, per_tile, &need)) {
            return RFB_ERR_LIMIT;
        }
    }
    if (need == 0u) {
        need = 1u;
    }
    if (need > byte_limit) {
        need = byte_limit;
    }
    uint8_t *inflated = rfb_zlib_ensure_scratch(zstream, need);
    if (inflated == NULL) {  // LCOV_EXCL_BR_LINE
        return RFB_ERR_NOMEM;
    }
    size_t inflated_len = 0;
    rfb_error e = rfb_zlib_inflate(zstream, payload, payload_len,
                                   inflated, need, &inflated_len);
    if (e != RFB_OK) {
        // ZRLE zlib stream is continuous across rectangles (RFC 6143).
        // Errors are fatal for the session: do not inflateReset — that
        // desyncs subsequent rects if a caller ever treated LIMIT as
        // recoverable (reaudit T8). Propagate and fail closed.
        return e;
    }

    // Process 64×64 tiles left-to-right, top-to-bottom.
    size_t pos = 0;
    for (uint32_t ty = 0; ty < rh->height; ty += ZRLE_TILE_SIZE) {
        uint32_t tile_h = (rh->height - ty < ZRLE_TILE_SIZE)  // LCOV_EXCL_BR_LINE
                          ? (rh->height - ty) : ZRLE_TILE_SIZE;
        for (uint32_t tx = 0; tx < rh->width; tx += ZRLE_TILE_SIZE) {
            uint32_t tile_w = (rh->width - tx < ZRLE_TILE_SIZE)
                              ? (rh->width - tx) : ZRLE_TILE_SIZE;
            size_t consumed = 0;
            e = decode_tile(fb, pf, rh->x + tx, rh->y + ty,
                            tile_w, tile_h,
                            inflated + pos, inflated_len - pos, &consumed);
            if (e != RFB_OK) {
                return e;
            }
            pos += consumed;
        }
    }

    out_damage->x = rh->x;
    out_damage->y = rh->y;
    out_damage->width = rh->width;
    out_damage->height = rh->height;
    return RFB_OK;
}
