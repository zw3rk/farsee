// SPDX-License-Identifier: Apache-2.0
//
// Copyright (c) Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
//
// Apple MultiVariant (0x03f3) type-0 IMAGE-plane decoder.
//
// Supporting code: the residual magnitude ladder (`apple_mvs_mag.c`), the
// MSB-first bit reader (`apple_mvs_bits.c`), the JPEG zig-zag table and the
// integer IDCT and YCbCr conversion (`apple_mvs_dct.c`), and the transmitted
// quantisation tables (`apple_wire_decode.c`).
//
// The image plane holds one variable-length record per tile of a paying
// class, in the command plane's tile scan order. Nothing is painted until the
// whole plane has been walked once and shown to end exactly on the payload
// endpoint that `apple_wire_validate_mvs_partial_image_suffix` validates, so a
// grammar miss anywhere leaves the framebuffer byte-identical.

#include "farsee/apple_mvs_image.h"

#include "farsee/apple_mvs_bits.h"
#include "farsee/apple_mvs_dct.h"
#include "farsee/apple_mvs_mag.h"
#include "farsee/checked.h"

#include <string.h>

#define MVS_IMG_TILE 8u

// The last zig-zag ordinal. Reaching it terminates a record by coefficient
// count, with no trailer.
#define MVS_IMG_LAST_ORDINAL 63u

// WIDE ladder for zig-zag ordinals 1..5, NARROW (the `mag` ladder) beyond.
// Selected by the ORDINAL, never by the codeword index.
#define MVS_IMG_WIDE_MAX_ORDINAL 5u

// Unary prefix caps. The mag ladder itself accepts prefixes to 38 ones; the
// AC codewords never need more than 12.
#define MVS_IMG_MAX_UNARY 12u

// |F| can never exceed 2048 for any 8-bit input block, and a legitimate
// coarse-band reconstruction adds at most half a step on top. Anything past
// this bound comes from a corrupt stream; clamping it keeps the fixed-point
// IDCT's int32 intermediates far from overflow while never touching a value a
// real encoder can produce.
#define MVS_IMG_COEF_LIMIT 8192

// Cb/Cr are stored centred on 0; an 8-bit chroma sample cannot leave this.
#define MVS_IMG_CHROMA_LIMIT 128

// One 20-bit T(rgb) colour: Y:8 | cb:6 | cr:6.
#define MVS_IMG_COLOR_BITS 20u

typedef struct mvs_img_state {
    apple_mvs_bit_reader br;
    size_t payload_bits;
    const uint8_t *qt0;
    const uint8_t *qt1;
    apple_mvs_image_tier tier;
    int32_t chroma_step;      // 2 * QT1[0][0]
    // TWO_COLOR registers. The solid slot is written by '00' and read by '01';
    // the ordered pair is written by '10' and read by '11'. They are separate:
    // an intervening solid literal must not disturb a later pair record.
    uint32_t solid_code;
    bool solid_valid;
    uint32_t pair_code[2];
    bool pair_valid;
    // DC DPCM predictor: the quantised levels of the previous DCT tile in scan
    // order, in symbol order Y, Cb, Cr.
    int32_t dc_level[3];
} mvs_img_state;

// --- bit access, bounded by the derived payload endpoint -------------------

static bool mvs_img_get(mvs_img_state *s, unsigned nbits, uint32_t *out)
{
    if (!apple_mvs_bit_reader_get(&s->br, nbits, out)) {
        return false;
    }
    return apple_mvs_bit_reader_bits_consumed(&s->br) <= s->payload_bits;
}

static size_t mvs_img_pos(const mvs_img_state *s)
{
    return apple_mvs_bit_reader_bits_consumed(&s->br);
}

// --- quantiser ladder ------------------------------------------------------

bool apple_mvs_image_tier_for(uint16_t normal_count, uint8_t large_count,
                              apple_mvs_image_tier *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof *out);
    // Only the two tiers the corpora carry. `normal - 1` is the quantiser
    // band boundary; the step pair itself is not derivable from it, so an
    // unmeasured quality pair has no ladder and must fail closed.
    if (normal_count == 15u && large_count == 25u) {
        out->fine_max_ordinal = 14u;
        out->s_fine = 2u;
        out->s_coarse = 8u;
        return true;
    }
    if (normal_count == 3u && large_count == 5u) {
        out->fine_max_ordinal = 2u;
        out->s_fine = 8u;
        out->s_coarse = 16u;
        return true;
    }
    return false;
}

// --- AC codewords ----------------------------------------------------------

typedef enum mvs_ac_kind {
    MVS_AC_LEVEL = 0,
    MVS_AC_ESCAPE
} mvs_ac_kind;

// One AC codeword: k leading '1's, a '0', then the payload.
//   k = 0        : 2 bits, '00' -> 0, '01' -> escape, '10' -> +1, '11' -> -1
//   k >= 1 WIDE  : flat 3-bit payload, magnitude bases 2, 6, 10, 14, ...
//   k >= 1 NARROW: the project's own `mag` ladder widths and bases
static bool mvs_ac_codeword(mvs_img_state *s, bool wide, int32_t *out_level,
                            mvs_ac_kind *out_kind)
{
    uint32_t k = 0u;
    for (;;) {
        uint32_t bit = 0u;
        if (!mvs_img_get(s, 1u, &bit)) {
            return false;
        }
        if (bit == 0u) {
            break;
        }
        k++;
        if (k > MVS_IMG_MAX_UNARY) {
            return false;
        }
    }

    uint32_t payload = 0u;
    if (k == 0u) {
        if (!mvs_img_get(s, 2u, &payload)) {
            return false;
        }
        *out_kind = MVS_AC_LEVEL;
        switch (payload) {
        case 0u:
            *out_level = 0;
            return true;
        case 1u:
            *out_kind = MVS_AC_ESCAPE;
            *out_level = 0;
            return true;
        case 2u:
            *out_level = 1;
            return true;
        default:
            *out_level = -1;
            return true;
        }
    }

    int32_t mag = 0;
    if (wide) {
        if (!mvs_img_get(s, 3u, &payload)) {
            return false;
        }
        mag = (int32_t)(2u + 4u * (k - 1u) + (payload >> 1u));
    } else {
        const unsigned width = (k == 1u) ? 2u : ((k == 2u) ? 3u : 4u);
        if (!mvs_img_get(s, width, &payload)) {
            return false;
        }
        if (k == 1u) {
            mag = (int32_t)(2u | (payload >> 1u));
        } else if (k == 2u) {
            mag = (int32_t)(4u | (payload >> 1u));
        } else {
            mag = (int32_t)((k - 2u) * 8u + (payload >> 1u));
        }
    }
    *out_kind = MVS_AC_LEVEL;
    *out_level = ((payload & 1u) != 0u) ? -mag : mag;
    return true;
}

// The escape's zero run: 3-bit groups, '111' adds 7 and continues. The run
// value r advances the scan by r - 1 ordinals before the next codeword.
static bool mvs_ac_zero_run(mvs_img_state *s, uint32_t *out_run)
{
    uint32_t total = 0u;
    for (;;) {
        uint32_t group = 0u;
        if (!mvs_img_get(s, 3u, &group)) {
            return false;
        }
        if (group == 7u) {
            total += 7u;
            if (total > MVS_IMG_LAST_ORDINAL) {
                return false;
            }
            continue;
        }
        *out_run = total + group;
        return true;
    }
}

// --- one DCT record --------------------------------------------------------

static int32_t mvs_clamp_i32(int32_t v, int32_t limit)
{
    if (v > limit) {
        return limit;
    }
    if (v < -limit) {
        return -limit;
    }
    return v;
}

// Round to nearest, halves away from zero. `den` is positive.
static int32_t mvs_div_round(int32_t num, int32_t den)
{
    if (num >= 0) {
        return (num + den / 2) / den;
    }
    return -((-num + den / 2) / den);
}

// Decode one image-plane record for a DCT tile. On success the DC predictor
// has advanced and `coef` holds the dequantised luma plane in natural order
// (index = vertical frequency * 8 + horizontal frequency), with the tile's
// flat chroma in *cb/*cr centred on zero.
static bool mvs_decode_dct(mvs_img_state *s, int16_t coef[64], int16_t *cb,
                           int16_t *cr)
{
    memset(coef, 0, sizeof(int16_t) * 64u);

    uint32_t lead = 0u;
    if (!mvs_img_get(s, 1u, &lead)) {
        return false;
    }
    if (lead == 0u) {
        uint32_t dc_form = 0u;
        if (!mvs_img_get(s, 2u, &dc_form)) {
            return false;
        }
        int32_t d[3] = {0, 0, 0};   // dCb, dCr, dY in wire order
        if (dc_form == 0u) {
            // 000 carries all three DC deltas.
            for (size_t i = 0u; i < 3u; i++) {
                if (!apple_mvs_mag_get(&s->br, &d[i]) ||
                    mvs_img_pos(s) > s->payload_bits) {
                    return false;
                }
            }
        } else if (dc_form == 1u) {
            // 001 reuses all three predictors but still carries AC data.
        } else if (dc_form == 2u) {
            // 010 is the common zero-chroma form and carries only dY.
            if (!apple_mvs_mag_get(&s->br, &d[2]) ||
                mvs_img_pos(s) > s->payload_bits) {
                return false;
            }
        } else {
            // 011 has not appeared in a valid generated wire vector.
            return false;
        }
        // dX = -(level(this tile) - level(previous DCT tile in scan order)).
        s->dc_level[0] -= d[2];
        s->dc_level[1] -= d[0];
        s->dc_level[2] -= d[1];

        uint32_t ordinal_done = 0u;   // ordinals already scanned
        while (ordinal_done < MVS_IMG_LAST_ORDINAL) {
            // The trailer is present exactly when the scan stops BEFORE
            // ordinal 63, so it is only ever tested — and consumed — here.
            // Reaching ordinal 63 ends the record with the coefficient count
            // as its terminator and no trailer at all.
            const apple_mvs_bit_reader saved = s->br;
            uint32_t peek = 0u;
            if (mvs_img_get(s, 4u, &peek) && peek == 2u) {   // '0010'
                break;
            }
            s->br = saved;

            bool wide = (ordinal_done + 1u) <= MVS_IMG_WIDE_MAX_ORDINAL;
            int32_t level = 0;
            mvs_ac_kind kind = MVS_AC_LEVEL;
            if (!mvs_ac_codeword(s, wide, &level, &kind)) {
                return false;
            }
            if (kind == MVS_AC_ESCAPE) {
                uint32_t run = 0u;
                if (!mvs_ac_zero_run(s, &run) || run == 0u) {
                    return false;
                }
                ordinal_done += run - 1u;
                if (ordinal_done >= MVS_IMG_LAST_ORDINAL) {
                    return false;   // nothing left to code
                }
                wide = (ordinal_done + 1u) <= MVS_IMG_WIDE_MAX_ORDINAL;
                if (!mvs_ac_codeword(s, wide, &level, &kind) ||
                    kind == MVS_AC_ESCAPE) {
                    return false;
                }
            }
            if (level != 0) {
                const uint32_t ordinal = ordinal_done + 1u;
                const uint8_t nat = apple_mvs_zigzag[ordinal];
                const int32_t step =
                    (ordinal <= s->tier.fine_max_ordinal)
                        ? (int32_t)s->tier.s_fine
                        : (int32_t)s->tier.s_coarse;
                const int64_t wide_val = (int64_t)level * step *
                                         (int64_t)s->qt0[nat];
                int32_t val;
                if (wide_val > MVS_IMG_COEF_LIMIT) {
                    val = MVS_IMG_COEF_LIMIT;
                } else if (wide_val < -MVS_IMG_COEF_LIMIT) {
                    val = -MVS_IMG_COEF_LIMIT;
                } else {
                    val = (int32_t)wide_val;
                }
                coef[nat] = (int16_t)val;
            }
            // Every iteration advances the scan by at least one ordinal,
            // so the loop is bounded by MVS_IMG_LAST_ORDINAL.
            ordinal_done++;
        }
    }
    // lead == 1 is the one-bit "nothing to send" record: the predictor and the
    // chroma carry over unchanged and the tile is flat at the predicted DC.

    const int64_t dc = (int64_t)s->dc_level[0] * (int64_t)s->qt0[0];
    coef[0] = (int16_t)((dc > MVS_IMG_COEF_LIMIT)
                            ? MVS_IMG_COEF_LIMIT
                            : ((dc < -MVS_IMG_COEF_LIMIT)
                                   ? -MVS_IMG_COEF_LIMIT
                                   : dc));
    // dc_C = 8 * (mean chroma - 128), reconstructed at level * 2 * QT1[0][0].
    const int32_t cb_raw =
        mvs_div_round(mvs_clamp_i32(s->dc_level[1], 1 << 20) * s->chroma_step,
                      8);
    const int32_t cr_raw =
        mvs_div_round(mvs_clamp_i32(s->dc_level[2], 1 << 20) * s->chroma_step,
                      8);
    *cb = (int16_t)mvs_clamp_i32(cb_raw, MVS_IMG_CHROMA_LIMIT);
    *cr = (int16_t)mvs_clamp_i32(cr_raw, MVS_IMG_CHROMA_LIMIT);
    return true;
}

// --- one TWO_COLOR record --------------------------------------------------

static bool mvs_two_color_mask(mvs_img_state *s, uint32_t c0, uint32_t c1,
                               uint32_t codes[64])
{
    uint32_t rowflags = 0u;
    if (!mvs_img_get(s, 8u, &rowflags)) {
        return false;
    }
    unsigned mixed = 0u;
    for (unsigned row = 0u; row < 8u; row++) {
        if (((rowflags >> (7u - row)) & 1u) == 0u) {
            mixed++;
        }
    }
    if (mixed == 0u) {
        return false;   // a uniform pair record is not a pair record
    }
    for (unsigned row = 0u; row < 8u; row++) {
        if (((rowflags >> (7u - row)) & 1u) != 0u) {
            for (unsigned col = 0u; col < 8u; col++) {
                codes[row * 8u + col] = c0;
            }
            continue;
        }
        uint32_t mask = 0u;
        if (!mvs_img_get(s, 8u, &mask)) {
            return false;
        }
        for (unsigned col = 0u; col < 8u; col++) {
            codes[row * 8u + col] =
                (((mask >> (7u - col)) & 1u) != 0u) ? c0 : c1;
        }
    }
    return true;
}

static bool mvs_decode_two_color(mvs_img_state *s, uint32_t codes[64])
{
    uint32_t form = 0u;
    if (!mvs_img_get(s, 2u, &form)) {
        return false;
    }
    if (form == 0u) {                      // '00' solid, literal colour
        uint32_t c = 0u;
        if (!mvs_img_get(s, MVS_IMG_COLOR_BITS, &c)) {
            return false;
        }
        s->solid_code = c;
        s->solid_valid = true;
        for (size_t i = 0u; i < 64u; i++) {
            codes[i] = c;
        }
        return true;
    }
    if (form == 1u) {                      // '01' solid, colour from register
        if (!s->solid_valid) {
            return false;
        }
        for (size_t i = 0u; i < 64u; i++) {
            codes[i] = s->solid_code;
        }
        return true;
    }
    if (form == 2u) {                      // '10' pair literal; writes register
        uint32_t c0 = 0u;
        uint32_t c1 = 0u;
        if (!mvs_img_get(s, MVS_IMG_COLOR_BITS, &c0) ||
            !mvs_img_get(s, MVS_IMG_COLOR_BITS, &c1)) {
            return false;
        }
        if (!mvs_two_color_mask(s, c0, c1, codes)) {
            return false;
        }
        s->pair_code[0] = c0;
        s->pair_code[1] = c1;
        s->pair_valid = true;
        return true;
    }
    if (!s->pair_valid) {                  // '11' pair from register
        return false;
    }
    return mvs_two_color_mask(s, s->pair_code[0], s->pair_code[1], codes);
}

// --- painting --------------------------------------------------------------

static void mvs_fill_tile(rfb_framebuffer *fb, uint16_t x, uint16_t y,
                          uint16_t tw, uint16_t th, uint8_t r, uint8_t g,
                          uint8_t b)
{
    for (uint16_t row = 0u; row < th; row++) {
        uint8_t *p = rfb_framebuffer_pixel(fb, x, (uint32_t)y + row);
        for (uint16_t col = 0u; col < tw; col++) {
            p[0] = r;
            p[1] = g;
            p[2] = b;
            p[3] = 255u;
            p += 4;
        }
    }
}

static void mvs_copy_tile(rfb_framebuffer *fb, uint16_t dx, uint16_t dy,
                          uint16_t sx, uint16_t sy, uint16_t tw, uint16_t th)
{
    for (uint16_t row = 0u; row < th; row++) {
        uint8_t *dst = rfb_framebuffer_pixel(fb, dx, (uint32_t)dy + row);
        const uint8_t *src =
            rfb_framebuffer_pixel_c(fb, sx, (uint32_t)sy + row);
        memcpy(dst, src, (size_t)tw * 4u);
    }
}

// T(rgb) = Y:8 | cb:6 | cr:6 with cb = (Cb8 + 2) >> 2, so the 8-bit chroma is
// recovered at the centre of its four-wide bin.
static void mvs_color_planes(const uint32_t codes[64], int16_t y[64],
                             int16_t cb[64], int16_t cr[64])
{
    for (size_t i = 0u; i < 64u; i++) {
        const uint32_t c = codes[i];
        y[i] = (int16_t)((int32_t)((c >> 12) & 0xffu) - 128);
        cb[i] = (int16_t)((int32_t)(((c >> 6) & 0x3fu) * 4u) - 128);
        cr[i] = (int16_t)((int32_t)((c & 0x3fu) * 4u) - 128);
    }
}

static void mvs_paint_tile_planes(rfb_framebuffer *fb, uint16_t x, uint16_t y,
                                  uint16_t tw, uint16_t th,
                                  const int16_t luma[64], const int16_t cb[64],
                                  const int16_t cr[64])
{
    uint8_t *base = rfb_framebuffer_pixel(fb, x, y);
    apple_mvs_ycbcr_tile_to_rgba(luma, cb, cr, base, (uint32_t)fb->stride, tw,
                                 th);
}

// --- the plane walk --------------------------------------------------------

typedef struct mvs_class_fill {
    uint8_t *classes;
    uint32_t ntiles;
    bool ok;
} mvs_class_fill;

static bool mvs_class_visitor(void *opaque,
                              const apple_wire_mvs_command_record *record)
{
    mvs_class_fill *f = (mvs_class_fill *)opaque;
    if (f == NULL || record == NULL) {
        return false;
    }
    if (record->first_tile > f->ntiles ||
        record->run > f->ntiles - record->first_tile) {
        f->ok = false;
        return false;
    }
    memset(f->classes + record->first_tile, record->command, record->run);
    return true;
}

// `fb` NULL walks without painting. The two passes take exactly the same
// decisions, so a successful validation pass proves the paint pass cannot
// fail part way and leave a half-written rectangle.
static rfb_error mvs_walk(mvs_img_state *s, const uint8_t *classes,
                          uint32_t tiles_x, uint32_t tiles_y,
                          rfb_framebuffer *fb, const rfb_rect_header *rh)
{
    const uint32_t ntiles = tiles_x * tiles_y;
    for (uint32_t index = 0u; index < ntiles; index++) {
        const uint32_t col = index % tiles_x;
        const uint32_t row = index / tiles_x;
        const uint16_t tx = (uint16_t)(rh->x + col * MVS_IMG_TILE);
        const uint16_t ty = (uint16_t)(rh->y + row * MVS_IMG_TILE);
        const uint16_t tw =
            (uint16_t)((col + 1u == tiles_x) ? (rh->width - col * MVS_IMG_TILE)
                                             : MVS_IMG_TILE);
        const uint16_t th =
            (uint16_t)((row + 1u == tiles_y)
                           ? (rh->height - row * MVS_IMG_TILE)
                           : MVS_IMG_TILE);
        uint32_t codes[64];
        int16_t luma[64];
        int16_t cb[64];
        int16_t cr[64];

        switch (classes[index]) {
        case APPLE_MVS_TILE_WHITE:
            if (fb != NULL) {
                mvs_fill_tile(fb, tx, ty, tw, th, 255u, 255u, 255u);
            }
            break;
        case APPLE_MVS_TILE_LAST_MATCH:
            if (col == 0u) {
                return RFB_ERR_PROTOCOL;
            }
            if (fb != NULL) {
                mvs_copy_tile(fb, tx, ty, (uint16_t)(tx - MVS_IMG_TILE), ty,
                              tw, th);
            }
            break;
        case APPLE_MVS_TILE_UPPER_MATCH:
            if (row == 0u) {
                return RFB_ERR_PROTOCOL;
            }
            if (fb != NULL) {
                mvs_copy_tile(fb, tx, ty, tx, (uint16_t)(ty - MVS_IMG_TILE),
                              tw, th);
            }
            break;
        case APPLE_MVS_TILE_TWO_COLOR:
            if (!mvs_decode_two_color(s, codes)) {
                return RFB_ERR_PROTOCOL;
            }
            if (fb != NULL) {
                mvs_color_planes(codes, luma, cb, cr);
                mvs_paint_tile_planes(fb, tx, ty, tw, th, luma, cb, cr);
            }
            break;
        case APPLE_MVS_TILE_DCT: {
            int16_t coef[64];
            int16_t cb_dc = 0;
            int16_t cr_dc = 0;
            if (!mvs_decode_dct(s, coef, &cb_dc, &cr_dc)) {
                return RFB_ERR_PROTOCOL;
            }
            if (fb != NULL) {
                apple_mvs_idct_8x8(coef, luma);
                for (size_t i = 0u; i < 64u; i++) {
                    cb[i] = cb_dc;
                    cr[i] = cr_dc;
                }
                mvs_paint_tile_planes(fb, tx, ty, tw, th, luma, cb, cr);
            }
            break;
        }
        default:
            // BLACK_WHITE (3), 6, and 7 are unsupported. Fail closed rather
            // than guess a length and desynchronise the plane.
            return RFB_ERR_UNSUPPORTED;
        }
    }
    if (mvs_img_pos(s) != s->payload_bits) {
        return RFB_ERR_PROTOCOL;
    }
    return RFB_OK;
}

static void mvs_state_reset(mvs_img_state *s, const uint8_t *data,
                            size_t payload_bits, const uint8_t *qt0,
                            const uint8_t *qt1,
                            const apple_mvs_image_tier *tier)
{
    memset(s, 0, sizeof *s);
    // Bound the reader to the bytes the payload actually spans; the residual
    // bits of the final byte are caught by the per-read endpoint check.
    apple_mvs_bit_reader_init(&s->br, data, (payload_bits + 7u) / 8u);
    s->payload_bits = payload_bits;
    s->qt0 = qt0;
    s->qt1 = qt1;
    s->tier = *tier;
    s->chroma_step = 2 * (int32_t)qt1[0];
}

rfb_error apple_mvs_image_paint_rect(rfb_framebuffer *fb,
                                     const rfb_rect_header *rh,
                                     const apple_wire_mvs_rect_hdr *hdr,
                                     const apple_wire_mvs_image_stats *image,
                                     const uint8_t *qt0, const uint8_t *qt1,
                                     rfb_rect *out_damage)
{
    if (fb == NULL || rh == NULL || hdr == NULL || image == NULL ||
        out_damage == NULL) {
        return RFB_ERR_INTERNAL;
    }
    memset(out_damage, 0, sizeof *out_damage);
    if (hdr->type != 0u || hdr->image_buffer == NULL) {
        return RFB_ERR_PROTOCOL;
    }
    if (qt0 == NULL || qt1 == NULL || qt0[0] == 0u || qt1[0] == 0u) {
        return RFB_ERR_UNSUPPORTED;
    }
    apple_mvs_image_tier tier;
    if (!apple_mvs_image_tier_for(hdr->normal_count, hdr->large_count,
                                  &tier)) {
        return RFB_ERR_UNSUPPORTED;
    }

    uint32_t tiles_x = 0u;
    uint32_t tiles_y = 0u;
    uint32_t ntiles = 0u;
    if (!apple_wire_mvs_tile_grid_checked(rh->width, rh->height, &tiles_x,
                                          &tiles_y, &ntiles) ||
        ntiles == 0u) {
        return RFB_ERR_PROTOCOL;
    }
    if (image->marker_start_bits > hdr->image_buffer_len * 8u) {
        return RFB_ERR_PROTOCOL;
    }

    rfb_allocator *alloc = fb->alloc;
    if (alloc == NULL) {
        return RFB_ERR_INTERNAL;
    }
    uint8_t *classes = (uint8_t *)alloc->alloc(alloc, ntiles);
    if (classes == NULL) {
        return RFB_ERR_NOMEM;
    }
    memset(classes, APPLE_MVS_TILE_INVALID, ntiles);

    mvs_class_fill fill = {.classes = classes, .ntiles = ntiles, .ok = true};
    if (!apple_wire_walk_mvs_partial_commands(hdr, ntiles, mvs_class_visitor,
                                              &fill, NULL) ||
        !fill.ok) {
        alloc->free(alloc, classes);
        return RFB_ERR_PROTOCOL;
    }

    mvs_img_state s;
    mvs_state_reset(&s, hdr->image_buffer, image->marker_start_bits, qt0, qt1,
                    &tier);
    rfb_error e = mvs_walk(&s, classes, tiles_x, tiles_y, NULL, rh);
    if (e != RFB_OK) {
        alloc->free(alloc, classes);
        return e;
    }

    mvs_state_reset(&s, hdr->image_buffer, image->marker_start_bits, qt0, qt1,
                    &tier);
    e = mvs_walk(&s, classes, tiles_x, tiles_y, fb, rh);
    alloc->free(alloc, classes);
    if (e != RFB_OK) {
        // Unreachable: the validation pass above took the same decisions.
        return e;
    }

    fb->generation += 1u;
    out_damage->x = rh->x;
    out_damage->y = rh->y;
    out_damage->width = rh->width;
    out_damage->height = rh->height;
    return RFB_OK;
}
