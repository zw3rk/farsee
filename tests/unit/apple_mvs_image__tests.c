// SPDX-License-Identifier: Apache-2.0
//
// Copyright (c) Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
//
// Unit tests: Apple MultiVariant (0x03f3) type-0 image-plane decoder.
//
// Every vector here is synthetic: bit strings follow the decoder grammar and
// use a synthetic quantisation table.
//
// Expected pixels follow the dequantiser and the
// project's own integer IDCT (`src/rfb/apple_mvs_dct.c`); the two AC vectors
// pin the scan orientation from the DCT definition itself (ordinal 1 is a
// horizontal basis function, ordinal 2 a vertical one).

#include "rfb_test.h"
#include "farsee/apple_mvs_image.h"
#include "farsee/apple_wire_decode.h"
#include "farsee/encoding_apple_mvs.h"
#include "farsee/framebuffer.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// --- synthetic plane / body builders --------------------------------------

typedef struct mvs_pb {
    uint8_t bits[2048];
    size_t nbits;
} mvs_pb;

typedef struct mvs_body {
    mvs_pb cmd;
    mvs_pb img;
    uint8_t bytes[8192];
    size_t len;
} mvs_body;

static void mvs_pb_reset(mvs_pb *pb)
{
    memset(pb->bits, 0, sizeof pb->bits);
    pb->nbits = 0u;
}

// Append the '0'/'1' characters of `s`; any other character is a separator.
static void mvs_pb_put(mvs_pb *pb, const char *s)
{
    for (const char *p = s; *p != '\0'; p++) {
        if (*p != '0' && *p != '1') {
            continue;
        }
        RFB_CHECK(pb->nbits < sizeof pb->bits * 8u);
        if (pb->nbits >= sizeof pb->bits * 8u) {
            return;
        }
        if (*p == '1') {
            pb->bits[pb->nbits >> 3] |=
                (uint8_t)(0x80u >> (unsigned)(pb->nbits & 7u));
        }
        pb->nbits++;
    }
}

static void mvs_pb_put_u(mvs_pb *pb, uint32_t value, unsigned nbits)
{
    for (unsigned i = nbits; i > 0u; i--) {
        mvs_pb_put(pb, ((value >> (i - 1u)) & 1u) != 0u ? "1" : "0");
    }
}

// One unaligned 0x6d marker plus zero pad to the byte end, then serialize.
static size_t mvs_pb_close(mvs_pb *pb, uint8_t *out, size_t cap)
{
    mvs_pb_put_u(pb, 0x6du, 8u);
    while ((pb->nbits & 7u) != 0u) {
        mvs_pb_put(pb, "0");
    }
    const size_t n = pb->nbits / 8u;
    RFB_CHECK(n <= cap);
    if (n > cap) {
        return 0u;
    }
    memcpy(out, pb->bits, n);
    return n;
}

static void mvs_body_begin(mvs_body *b)
{
    memset(b, 0, sizeof *b);
    mvs_pb_reset(&b->cmd);
    mvs_pb_reset(&b->img);
    mvs_pb_put(&b->cmd, "0"); // type-0 command plane leading flag
}

// One command record: 3-bit class then the repeat code. run 1 => '0';
// run 2..16 => '1' + 4-bit (run - 2).
static void mvs_body_tiles(mvs_body *b, unsigned cls, unsigned run)
{
    RFB_CHECK(cls < 8u);
    RFB_CHECK(run >= 1u && run <= 16u);
    mvs_pb_put_u(&b->cmd, cls, 3u);
    if (run == 1u) {
        mvs_pb_put(&b->cmd, "0");
    } else {
        mvs_pb_put(&b->cmd, "1");
        mvs_pb_put_u(&b->cmd, run - 2u, 4u);
    }
}

static void mvs_body_img(mvs_body *b, const char *bits)
{
    mvs_pb_put(&b->img, bits);
}

static void mvs_body_img_u(mvs_body *b, uint32_t v, unsigned nbits)
{
    mvs_pb_put_u(&b->img, v, nbits);
}

static void mvs_body_finish(mvs_body *b, uint16_t normal, uint8_t large)
{
    uint8_t cmdb[1024];
    uint8_t imgb[2048];
    const size_t cmd_len = mvs_pb_close(&b->cmd, cmdb, sizeof cmdb);
    const size_t img_len = mvs_pb_close(&b->img, imgb, sizeof imgb);
    const size_t ibo = 6u + cmd_len;
    RFB_CHECK(ibo + img_len <= sizeof b->bytes);
    if (ibo + img_len > sizeof b->bytes) {
        return;
    }
    b->bytes[0] = 0u;
    b->bytes[1] = (uint8_t)normal;
    b->bytes[2] = large;
    b->bytes[3] = (uint8_t)((ibo >> 16) & 0xffu);
    b->bytes[4] = (uint8_t)((ibo >> 8) & 0xffu);
    b->bytes[5] = (uint8_t)(ibo & 0xffu);
    memcpy(b->bytes + 6u, cmdb, cmd_len);
    memcpy(b->bytes + ibo, imgb, img_len);
    b->len = ibo + img_len;
}

// Synthetic quantisation tables. Only qt0[0] (=12) and 2*qt1[0] (=30) carry
// values used by the supported profile; the rest is uniform so
// the expected pixels stay hand-checkable.
static void mvs_test_tables(uint8_t qt0[64], uint8_t qt1[64])
{
    for (size_t i = 0u; i < 64u; i++) {
        qt0[i] = 16u;
        qt1[i] = 15u;
    }
    qt0[0] = 12u;
}

// The production call sequence: header, command plane, image suffix, paint.
static rfb_error mvs_paint(rfb_framebuffer *fb, const rfb_rect_header *rh,
                           const uint8_t *body, size_t len,
                           const uint8_t *qt0, const uint8_t *qt1,
                           rfb_rect *dmg)
{
    apple_wire_mvs_rect_hdr hdr;
    apple_wire_mvs_image_stats img;
    uint32_t tiles = 0u;
    memset(dmg, 0, sizeof *dmg);
    if (!apple_wire_decode_mvs_rect_hdr(body, len, &hdr)) {
        return RFB_ERR_PROTOCOL;
    }
    if (!apple_wire_mvs_tile_grid_checked(rh->width, rh->height, NULL, NULL,
                                          &tiles)) {
        return RFB_ERR_PROTOCOL;
    }
    if (!apple_wire_validate_mvs_partial_commands(&hdr, tiles, NULL)) {
        return RFB_ERR_PROTOCOL;
    }
    if (!apple_wire_validate_mvs_partial_image_suffix(&hdr, &img)) {
        return RFB_ERR_PROTOCOL;
    }
    return apple_mvs_image_paint_rect(fb, rh, &hdr, &img, qt0, qt1, dmg);
}

typedef struct mvs_fb {
    rfb_framebuffer fb;
    uint8_t before[64u * 64u * 4u];
    uint64_t generation;
} mvs_fb;

static void mvs_fb_open(mvs_fb *m, uint32_t w, uint32_t h)
{
    rfb_framebuffer_init(&m->fb, rfb_default_allocator());
    RFB_CHECK(rfb_framebuffer_resize(&m->fb, w, h, 1u << 20) == RFB_OK);
    rfb_framebuffer_fill(&m->fb, 3u, 5u, 7u, 9u);
    RFB_CHECK((size_t)w * h * 4u <= sizeof m->before);
    memcpy(m->before, m->fb.rgba, (size_t)w * h * 4u);
    m->generation = m->fb.generation;
}

static void mvs_fb_close(mvs_fb *m)
{
    rfb_framebuffer_destroy(&m->fb);
}

// Fail closed: not one byte of the framebuffer moved, no generation bump,
// and no damage reported.
static void mvs_check_untouched(mvs_fb *m, const rfb_rect *dmg)
{
    RFB_CHECK(memcmp(m->fb.rgba, m->before,
                     (size_t)m->fb.width * m->fb.height * 4u) == 0);
    RFB_CHECK_EQ_UINT(m->fb.generation, m->generation);
    RFB_CHECK_EQ_UINT(dmg->width, 0u);
    RFB_CHECK_EQ_UINT(dmg->height, 0u);
}

static void mvs_check_px(const rfb_framebuffer *fb, uint32_t x, uint32_t y,
                         uint8_t r, uint8_t g, uint8_t bl)
{
    const uint8_t *p = rfb_framebuffer_pixel_c(fb, x, y);
    RFB_CHECK_EQ_UINT(p[0], r);
    RFB_CHECK_EQ_UINT(p[1], g);
    RFB_CHECK_EQ_UINT(p[2], bl);
    RFB_CHECK_EQ_UINT(p[3], 255u);
}

// A 20-bit T(rgb) colour code: Y:8 | cb:6 | cr:6.
static uint32_t mvs_code(uint32_t y, uint32_t cb6, uint32_t cr6)
{
    return (y << 12) | (cb6 << 6) | cr6;
}

// --- the quantiser ladder -------------------------------------------------

RFB_TEST(apple_mvs_image, tier_known_pairs_match_expected_values)
{
    apple_mvs_image_tier t;
    memset(&t, 0, sizeof t);
    RFB_CHECK(apple_mvs_image_tier_for(15u, 25u, &t));
    RFB_CHECK_EQ_UINT(t.fine_max_ordinal, 14u);
    RFB_CHECK_EQ_UINT(t.s_fine, 2u);
    RFB_CHECK_EQ_UINT(t.s_coarse, 8u);
    memset(&t, 0, sizeof t);
    RFB_CHECK(apple_mvs_image_tier_for(3u, 5u, &t));
    RFB_CHECK_EQ_UINT(t.fine_max_ordinal, 2u);
    RFB_CHECK_EQ_UINT(t.s_fine, 8u);
    RFB_CHECK_EQ_UINT(t.s_coarse, 16u);
}

RFB_TEST(apple_mvs_image, tier_unsupported_pairs_rejected)
{
    apple_mvs_image_tier t;
    RFB_CHECK(!apple_mvs_image_tier_for(15u, 5u, &t));
    RFB_CHECK(!apple_mvs_image_tier_for(3u, 25u, &t));
    RFB_CHECK(!apple_mvs_image_tier_for(0u, 0u, &t));
    RFB_CHECK(!apple_mvs_image_tier_for(7u, 9u, &t));
    RFB_CHECK(!apple_mvs_image_tier_for(15u, 25u, NULL));
}

// --- zero-cost classes ----------------------------------------------------

RFB_TEST(apple_mvs_image, white_class_costs_no_image_bits_and_paints_white)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 0u, 1u);   // one WHITE tile
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(dmg.x, 0u);
    RFB_CHECK_EQ_UINT(dmg.y, 0u);
    RFB_CHECK_EQ_UINT(dmg.width, 8u);
    RFB_CHECK_EQ_UINT(dmg.height, 8u);
    RFB_CHECK(m.fb.generation != m.generation);
    for (uint32_t y = 0u; y < 8u; y++) {
        for (uint32_t x = 0u; x < 8u; x++) {
            mvs_check_px(&m.fb, x, y, 255u, 255u, 255u);
        }
    }
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, match_classes_copy_left_and_upper_neighbours)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    // 24x16 = 3x2 tiles. Row 0: TWO_COLOR(A) LAST_MATCH TWO_COLOR(B).
    // Row 1: UPPER_MATCH LAST_MATCH UPPER_MATCH.
    const uint32_t a = mvs_code(200u, 32u, 32u); // grey 200
    const uint32_t bcode = mvs_code(100u, 32u, 32u);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 4u, 1u);
    mvs_body_tiles(&b, 1u, 1u);
    mvs_body_tiles(&b, 4u, 1u);
    mvs_body_tiles(&b, 2u, 1u);
    mvs_body_tiles(&b, 1u, 1u);
    mvs_body_tiles(&b, 2u, 1u);
    mvs_body_img(&b, "00");
    mvs_body_img_u(&b, a, 20u);
    mvs_body_img(&b, "00");
    mvs_body_img_u(&b, bcode, 20u);
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 24u, 16u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 24, .height = 16,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(dmg.width, 24u);
    RFB_CHECK_EQ_UINT(dmg.height, 16u);
    // Tiles 0,1 and 3,4 are colour A; tiles 2 and 5 are colour B.
    mvs_check_px(&m.fb, 0u, 0u, 200u, 200u, 200u);
    mvs_check_px(&m.fb, 8u, 0u, 200u, 200u, 200u);
    mvs_check_px(&m.fb, 16u, 0u, 100u, 100u, 100u);
    mvs_check_px(&m.fb, 0u, 8u, 200u, 200u, 200u);
    mvs_check_px(&m.fb, 8u, 8u, 200u, 200u, 200u);
    mvs_check_px(&m.fb, 16u, 8u, 100u, 100u, 100u);
    mvs_check_px(&m.fb, 23u, 15u, 100u, 100u, 100u);
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, last_match_in_column_zero_fails_closed)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 1u, 1u);   // LAST_MATCH has no left neighbour
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_ERR_PROTOCOL);
    mvs_check_untouched(&m, &dmg);
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, upper_match_in_row_zero_fails_closed)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 0u, 1u);
    mvs_body_tiles(&b, 2u, 1u);   // UPPER_MATCH still in row 0
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 16u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 16, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_ERR_PROTOCOL);
    mvs_check_untouched(&m, &dmg);
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, unhandled_tile_classes_fail_closed)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    // BLACK_WHITE (3) has no supported grammar; 6 and 7 are undefined. All
    // three must fail closed.
    const unsigned classes[3] = {3u, 6u, 7u};
    for (size_t i = 0u; i < 3u; i++) {
        mvs_body b;
        mvs_body_begin(&b);
        mvs_body_tiles(&b, classes[i], 1u);
        mvs_body_finish(&b, 15u, 25u);
        mvs_fb m;
        mvs_fb_open(&m, 8u, 8u);
        rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                              .encoding = RFB_ENCODING_APPLE_MVS};
        rfb_rect dmg;
        RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                         RFB_ERR_UNSUPPORTED);
        mvs_check_untouched(&m, &dmg);
        mvs_fb_close(&m);
    }
}

// --- TWO_COLOR register machine -------------------------------------------

RFB_TEST(apple_mvs_image, two_color_solid_literal_then_register_repeat)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    const uint32_t c = mvs_code(143u, 32u, 32u);  // Y=143, Cb=Cr=128
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 4u, 2u);
    mvs_body_img(&b, "00");
    mvs_body_img_u(&b, c, 20u);
    mvs_body_img(&b, "01");      // solid, colour from the register
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 16u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 16, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_OK);
    for (uint32_t x = 0u; x < 16u; x++) {
        mvs_check_px(&m.fb, x, 0u, 143u, 143u, 143u);
        mvs_check_px(&m.fb, x, 7u, 143u, 143u, 143u);
    }
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, two_color_pair_literal_then_pair_from_register)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    const uint32_t c0 = mvs_code(200u, 32u, 32u);
    const uint32_t c1 = mvs_code(60u, 32u, 32u);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 4u, 2u);
    // '10' pair literal: rows 0..6 all c0, row 7 mixed (mask 00111111).
    mvs_body_img(&b, "10");
    mvs_body_img_u(&b, c0, 20u);
    mvs_body_img_u(&b, c1, 20u);
    mvs_body_img(&b, "11111110");
    mvs_body_img(&b, "00111111");
    // '11' pair from the register, same shape.
    mvs_body_img(&b, "11");
    mvs_body_img(&b, "11111110");
    mvs_body_img(&b, "00111111");
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 16u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 16, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_OK);
    for (uint32_t tile = 0u; tile < 2u; tile++) {
        const uint32_t ox = tile * 8u;
        for (uint32_t y = 0u; y < 7u; y++) {
            for (uint32_t x = 0u; x < 8u; x++) {
                mvs_check_px(&m.fb, ox + x, y, 200u, 200u, 200u);
            }
        }
        mvs_check_px(&m.fb, ox + 0u, 7u, 60u, 60u, 60u);
        mvs_check_px(&m.fb, ox + 1u, 7u, 60u, 60u, 60u);
        for (uint32_t x = 2u; x < 8u; x++) {
            mvs_check_px(&m.fb, ox + x, 7u, 200u, 200u, 200u);
        }
    }
    mvs_fb_close(&m);
}

// The pair register is written only by '10' and survives
// intervening records, so an interleaved '00' must not disturb a later '11'.
RFB_TEST(apple_mvs_image, two_color_pair_register_survives_solid_literal)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    const uint32_t c0 = mvs_code(200u, 32u, 32u);
    const uint32_t c1 = mvs_code(60u, 32u, 32u);
    const uint32_t solid = mvs_code(10u, 32u, 32u);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 4u, 3u);
    mvs_body_img(&b, "10");
    mvs_body_img_u(&b, c0, 20u);
    mvs_body_img_u(&b, c1, 20u);
    mvs_body_img(&b, "11111110");
    mvs_body_img(&b, "00111111");
    mvs_body_img(&b, "00");          // solid literal in between
    mvs_body_img_u(&b, solid, 20u);
    mvs_body_img(&b, "11");          // still the '10' pair
    mvs_body_img(&b, "11111110");
    mvs_body_img(&b, "00111111");
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 24u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 24, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_OK);
    mvs_check_px(&m.fb, 8u, 0u, 10u, 10u, 10u);      // the '00' tile
    mvs_check_px(&m.fb, 16u, 0u, 200u, 200u, 200u);  // '11' row 0 = c0
    mvs_check_px(&m.fb, 16u, 7u, 60u, 60u, 60u);     // '11' row 7 col 0 = c1
    mvs_check_px(&m.fb, 18u, 7u, 200u, 200u, 200u);
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, two_color_register_read_before_write_fails_closed)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    // '01' with no solid literal ever written, and '11' with no pair literal
    // ever written (not even after a '00', which writes only the solid slot).
    static const char *const forms[3] = {"01", "11 11111110 00111111",
                                         "11 11111111"};
    for (size_t i = 0u; i < 3u; i++) {
        mvs_body b;
        mvs_body_begin(&b);
        mvs_body_tiles(&b, 4u, i == 2u ? 1u : 1u);
        if (i == 1u) {
            // A preceding '00' must not satisfy a '11'.
            mvs_body_begin(&b);
            mvs_body_tiles(&b, 4u, 2u);
            mvs_body_img(&b, "00");
            mvs_body_img_u(&b, mvs_code(120u, 32u, 32u), 20u);
        }
        mvs_body_img(&b, forms[i]);
        mvs_body_finish(&b, 15u, 25u);
        mvs_fb m;
        const uint32_t w = (i == 1u) ? 16u : 8u;
        mvs_fb_open(&m, w, 8u);
        rfb_rect_header rh = {.x = 0, .y = 0, .width = (uint16_t)w,
                              .height = 8,
                              .encoding = RFB_ENCODING_APPLE_MVS};
        rfb_rect dmg;
        RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                         RFB_ERR_PROTOCOL);
        mvs_check_untouched(&m, &dmg);
        mvs_fb_close(&m);
    }
}

// --- DCT records: DC ------------------------------------------------------

// Form B (flag=1) carries only mag(dY). dY = -(level - previous level), so
// mag(-10) sets the first DCT tile's luma DC level to 10 and F[0] = 12*10.
// The integer IDCT reduces a DC-only tile to (8*120 + 32) >> 6 = 15, so the
// tile is a flat Y = 143 with Cb = Cr = 128.
RFB_TEST(apple_mvs_image, dct_dc_only_chroma_escape_paints_flat_luma)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 1 0");          // record, chroma-pair escape
    mvs_body_img(&b, "1110 0101");      // mag(-10)
    mvs_body_img(&b, "0010");           // early-stop trailer
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_OK);
    for (uint32_t y = 0u; y < 8u; y++) {
        for (uint32_t x = 0u; x < 8u; x++) {
            mvs_check_px(&m.fb, x, y, 143u, 143u, 143u);
        }
    }
    mvs_fb_close(&m);
}

// Form A carries mag(dCb) mag(dCr) mag(dY) in that order. dCb = -1 gives
// chroma level 1, i.e. Cb - 128 = round(30/8) = 4, with Cr and Y unchanged.
// A swapped symbol order would tint the tile red instead of blue.
RFB_TEST(apple_mvs_image, dct_chroma_symbol_order_is_cb_cr_y)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 0 0");   // record, chroma pair present
    mvs_body_img(&b, "011");     // mag(dCb) = -1
    mvs_body_img(&b, "00");      // mag(dCr) = 0
    mvs_body_img(&b, "00");      // mag(dY)  = 0
    mvs_body_img(&b, "0010");
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_OK);
    mvs_check_px(&m.fb, 0u, 0u, 128u, 127u, 135u);
    mvs_check_px(&m.fb, 7u, 7u, 128u, 127u, 135u);
    mvs_fb_close(&m);
}

// The DC is DPCM against the previous DCT tile in scan order, and the 1-bit
// '1' record ("nothing to send") leaves that predictor alone.
RFB_TEST(apple_mvs_image, dct_dc_dpcm_carries_into_nothing_to_send_record)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 2u);
    mvs_body_img(&b, "0 1 0 1110 0101 0010");  // level 10
    mvs_body_img(&b, "1");                     // nothing to send
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 16u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 16, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_OK);
    for (uint32_t x = 0u; x < 16u; x++) {
        mvs_check_px(&m.fb, x, 3u, 143u, 143u, 143u);
    }
    mvs_fb_close(&m);
}

// --- DCT records: AC and the scan orientation ------------------------------

// The 8 luma samples of a single unit-amplitude basis function, computed by
// the project's integer IDCT from level 2 at a QT-16 position with s_fine = 2
// (F = 64): a strictly monotone ramp, antisymmetric about 128.
static const uint8_t k_ramp[8] = {139u, 137u, 134u, 130u, 126u, 122u, 119u,
                                  117u};

// Zig-zag ordinal 1 is natural index 1 = horizontal frequency 1: the tile
// must vary along x and be constant along y. Ordinal 2 is natural index 8 =
// vertical frequency 1 and must do the opposite. Together these pin the scan
// orientation against the DCT definition.
RFB_TEST(apple_mvs_image, ac_ordinal_one_is_a_horizontal_basis_function)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 1 0");
    mvs_body_img(&b, "00");        // mag(dY) = 0
    mvs_body_img(&b, "10 000");    // WIDE level +2 at ordinal 1
    mvs_body_img(&b, "0010");
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_OK);
    for (uint32_t y = 0u; y < 8u; y++) {
        for (uint32_t x = 0u; x < 8u; x++) {
            mvs_check_px(&m.fb, x, y, k_ramp[x], k_ramp[x], k_ramp[x]);
        }
    }
    mvs_fb_close(&m);
}

// The live high-quality stream uses selector 001 when all three DC predictors
// carry over but the tile still has AC coefficients. This is distinct from the
// one-bit "nothing to send" record, which has no AC payload.
RFB_TEST(apple_mvs_image, ac_dc_reuse_selector_paints_coefficients)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 0 1");       // record, reuse Y/Cb/Cr predictors
    mvs_body_img(&b, "10 000");      // WIDE level +2 at ordinal 1
    mvs_body_img(&b, "0010");        // early-stop trailer
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_OK);
    for (uint32_t y = 0u; y < 8u; y++) {
        for (uint32_t x = 0u; x < 8u; x++) {
            mvs_check_px(&m.fb, x, y, k_ramp[x], k_ramp[x], k_ramp[x]);
        }
    }
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, ac_ordinal_two_is_a_vertical_basis_function)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 1 0");
    mvs_body_img(&b, "00");        // mag(dY) = 0
    mvs_body_img(&b, "000");       // WIDE level 0 at ordinal 1
    mvs_body_img(&b, "10 000");    // WIDE level +2 at ordinal 2
    mvs_body_img(&b, "0010");
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_OK);
    for (uint32_t y = 0u; y < 8u; y++) {
        for (uint32_t x = 0u; x < 8u; x++) {
            mvs_check_px(&m.fb, x, y, k_ramp[y], k_ramp[y], k_ramp[y]);
        }
    }
    mvs_fb_close(&m);
}

// The zero-run escape ('0' '01' then 3-bit run groups) and the explicit
// zero codewords are two encodings of the same coefficient set; a decoder
// must render them identically. Here both place level +2 at ordinal 5.
RFB_TEST(apple_mvs_image, ac_zero_run_escape_matches_explicit_zeros)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    uint8_t escaped[8u * 8u * 4u];
    for (unsigned variant = 0u; variant < 2u; variant++) {
        mvs_body b;
        mvs_body_begin(&b);
        mvs_body_tiles(&b, 5u, 1u);
        mvs_body_img(&b, "0 1 0");
        mvs_body_img(&b, "00");
        mvs_body_img(&b, "10 000");     // level +2 at ordinal 1
        if (variant == 0u) {
            // ESCAPE, run value 4 => the next coefficient sits 3 further on.
            mvs_body_img(&b, "0 01");
            mvs_body_img(&b, "100");
        } else {
            mvs_body_img(&b, "000 000 000");   // ordinals 2,3,4 explicit zero
        }
        mvs_body_img(&b, "10 000");     // level +2 at ordinal 5
        mvs_body_img(&b, "0010");
        mvs_body_finish(&b, 15u, 25u);

        mvs_fb m;
        mvs_fb_open(&m, 8u, 8u);
        rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                              .encoding = RFB_ENCODING_APPLE_MVS};
        rfb_rect dmg;
        RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                         RFB_OK);
        if (variant == 0u) {
            memcpy(escaped, m.fb.rgba, sizeof escaped);
        } else {
            RFB_CHECK(memcmp(escaped, m.fb.rgba, sizeof escaped) == 0);
        }
        mvs_fb_close(&m);
    }
}

// The trailer is present exactly when the AC scan stops before zig-zag
// ordinal 63. A record that reaches ordinal 63 ends with the
// coefficient count as its terminator and emits no trailer. A walker without
// this rule reads three phantom bits as an "ordinal 64" and four more as a
// trailer, desynchronising the rest of the plane.
RFB_TEST(apple_mvs_image, ac_record_reaching_ordinal_63_has_no_trailer)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 1 0");
    mvs_body_img(&b, "00");                            // mag(dY) = 0
    mvs_body_img(&b, "0 01");                          // ESCAPE
    mvs_body_img(&b, "111 111 111 111 111 111 111 111 111 000"); // run 63
    mvs_body_img(&b, "0 10");                          // NARROW +1, ordinal 63
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(dmg.width, 8u);
    // Highest-frequency basis function: the corner samples alternate around
    // the flat 128 level, so the tile is not flat.
    const uint8_t *p00 = rfb_framebuffer_pixel_c(&m.fb, 0u, 0u);
    const uint8_t *p10 = rfb_framebuffer_pixel_c(&m.fb, 1u, 0u);
    RFB_CHECK(p00[0] != p10[0]);
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, ac_ordinal_63_record_with_trailer_fails_closed)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 1 0");
    mvs_body_img(&b, "00");
    mvs_body_img(&b, "0 01");
    mvs_body_img(&b, "111 111 111 111 111 111 111 111 111 000");
    mvs_body_img(&b, "0 10");
    mvs_body_img(&b, "0010");   // trailer that must not be there
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_ERR_PROTOCOL);
    mvs_check_untouched(&m, &dmg);
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, ac_zero_run_past_ordinal_63_fails_closed)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 1 0");
    mvs_body_img(&b, "00");
    mvs_body_img(&b, "0 01");
    // run 70: nine '111' groups (63) plus '111' (70) then '000'.
    mvs_body_img(&b, "111 111 111 111 111 111 111 111 111 111 000");
    mvs_body_img(&b, "0 10");
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_ERR_PROTOCOL);
    mvs_check_untouched(&m, &dmg);
    mvs_fb_close(&m);
}

// --- endpoint and plane closure -------------------------------------------

RFB_TEST(apple_mvs_image, image_plane_with_leftover_bits_fails_closed)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 0u, 1u);   // WHITE costs zero image bits
    mvs_body_img(&b, "0000000");  // ... so these seven bits are unaccounted
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_ERR_PROTOCOL);
    mvs_check_untouched(&m, &dmg);
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, truncated_record_fails_closed)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 1 0");
    mvs_body_img(&b, "00");   // mag(dY) = 0, then the record just stops
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_ERR_PROTOCOL);
    mvs_check_untouched(&m, &dmg);
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, reserved_dc_selector_fails_closed)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 1 1");   // selector 011 is reserved
    mvs_body_img(&b, "1110 0101 0010");
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_ERR_PROTOCOL);
    mvs_check_untouched(&m, &dmg);
    mvs_fb_close(&m);
}

// --- required inputs ------------------------------------------------------

RFB_TEST(apple_mvs_image, unknown_quality_tier_fails_closed)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 0u, 1u);
    mvs_body_finish(&b, 7u, 9u);   // unsupported quantiser pair

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_ERR_UNSUPPORTED);
    mvs_check_untouched(&m, &dmg);
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, missing_or_degenerate_tables_fail_closed)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    uint8_t zero0[64], zero1[64];
    mvs_test_tables(zero0, zero1);
    zero0[0] = 0u;
    uint8_t zerochroma[64];
    mvs_test_tables(qt0, zerochroma);
    zerochroma[0] = 0u;

    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 0u, 1u);
    mvs_body_finish(&b, 15u, 25u);

    const uint8_t *t0[4] = {NULL, qt0, zero0, qt0};
    const uint8_t *t1[4] = {qt1, NULL, qt1, zerochroma};
    for (size_t i = 0u; i < 4u; i++) {
        mvs_fb m;
        mvs_fb_open(&m, 8u, 8u);
        rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                              .encoding = RFB_ENCODING_APPLE_MVS};
        rfb_rect dmg;
        RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, t0[i], t1[i],
                                   &dmg),
                         RFB_ERR_UNSUPPORTED);
        mvs_check_untouched(&m, &dmg);
        mvs_fb_close(&m);
    }
}

RFB_TEST(apple_mvs_image, null_arguments_fail_closed)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 0u, 1u);
    mvs_body_finish(&b, 15u, 25u);

    apple_wire_mvs_rect_hdr hdr;
    apple_wire_mvs_image_stats img;
    RFB_CHECK(apple_wire_decode_mvs_rect_hdr(b.bytes, b.len, &hdr));
    RFB_CHECK(apple_wire_validate_mvs_partial_image_suffix(&hdr, &img));

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    memset(&dmg, 0, sizeof dmg);
    RFB_CHECK_EQ_INT(apple_mvs_image_paint_rect(NULL, &rh, &hdr, &img, qt0,
                                                qt1, &dmg),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_mvs_image_paint_rect(&m.fb, NULL, &hdr, &img, qt0,
                                                qt1, &dmg),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_mvs_image_paint_rect(&m.fb, &rh, NULL, &img, qt0,
                                                qt1, &dmg),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_mvs_image_paint_rect(&m.fb, &rh, &hdr, NULL, qt0,
                                                qt1, &dmg),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_mvs_image_paint_rect(&m.fb, &rh, &hdr, &img, qt0,
                                                qt1, NULL),
                     RFB_ERR_INTERNAL);
    mvs_check_untouched(&m, &dmg);
    mvs_fb_close(&m);
}

// --- allocation failure ---------------------------------------------------

typedef struct mvs_fault_alloc {
    int fail_at;
    int calls;
} mvs_fault_alloc;

static void *mvs_fault_alloc_fn(rfb_allocator *self, size_t n)
{
    mvs_fault_alloc *f = (mvs_fault_alloc *)self->user;
    f->calls++;
    if (f->calls == f->fail_at) {
        return NULL;
    }
    return malloc(n);
}

static void mvs_fault_free_fn(rfb_allocator *self, void *p)
{
    (void)self;
    free(p);
}

RFB_TEST(apple_mvs_image, class_table_allocation_failure_fails_closed)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 0u, 1u);
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    mvs_fault_alloc fault = {.fail_at = 1, .calls = 0};
    rfb_allocator failing = {.alloc = mvs_fault_alloc_fn,
                             .free = mvs_fault_free_fn,
                             .user = &fault};
    m.fb.alloc = &failing;
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_ERR_NOMEM);
    mvs_check_untouched(&m, &dmg);
    RFB_CHECK_EQ_INT(fault.calls, 1);
    m.fb.alloc = rfb_default_allocator();
    mvs_fb_close(&m);
}

// --- bounded arithmetic ---------------------------------------------------

// A corrupt stream can encode dequantised coefficients far outside the range
// any 8-bit image can produce (|F| <= 2048). Those must be clamped, not fed
// to the fixed-point IDCT, whose int32 intermediates would otherwise
// overflow. Every pixel must still be a valid opaque colour.
RFB_TEST(apple_mvs_image, extreme_levels_stay_bounded_and_opaque)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    for (size_t i = 0u; i < 64u; i++) {
        qt0[i] = 255u;
    }
    qt0[0] = 255u;
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 0 0");
    // Largest magnitudes the mag ladder reaches at a 4-bit tail.
    mvs_body_img(&b, "111111111111111111111111111111111111111 0 1111");
    mvs_body_img(&b, "111111111111111111111111111111111111111 0 1111");
    mvs_body_img(&b, "111111111111111111111111111111111111111 0 1111");
    // Six WIDE codewords at the top unary class, then NARROW ones.
    for (unsigned k = 0u; k < 5u; k++) {
        mvs_body_img(&b, "111111111111 0 111");
    }
    for (unsigned k = 0u; k < 10u; k++) {
        mvs_body_img(&b, "111111111111 0 1111");
    }
    mvs_body_img(&b, "0010");
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    const rfb_error e =
        mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg);
    RFB_CHECK(e == RFB_OK || e == RFB_ERR_PROTOCOL);
    if (e == RFB_OK) {
        for (uint32_t y = 0u; y < 8u; y++) {
            for (uint32_t x = 0u; x < 8u; x++) {
                RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&m.fb, x, y)[3],
                                  255u);
            }
        }
    } else {
        mvs_check_untouched(&m, &dmg);
    }
    mvs_fb_close(&m);
}

// --- partial edge tiles ---------------------------------------------------

// A rectangle whose width and height are not multiples of 8 still has a full
// tile grid; only the visible part of an edge tile is painted, and nothing
// outside the rectangle moves.
RFB_TEST(apple_mvs_image, partial_edge_tiles_stay_inside_the_rectangle)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 0u, 4u);   // 2x2 tile grid for a 12x11 rect
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 16u, 16u);
    rfb_rect_header rh = {.x = 2, .y = 3, .width = 12, .height = 11,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(mvs_paint(&m.fb, &rh, b.bytes, b.len, qt0, qt1, &dmg),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(dmg.x, 2u);
    RFB_CHECK_EQ_UINT(dmg.y, 3u);
    RFB_CHECK_EQ_UINT(dmg.width, 12u);
    RFB_CHECK_EQ_UINT(dmg.height, 11u);
    for (uint32_t y = 0u; y < 16u; y++) {
        for (uint32_t x = 0u; x < 16u; x++) {
            const bool inside = (x >= 2u && x < 14u && y >= 3u && y < 14u);
            const uint8_t *p = rfb_framebuffer_pixel_c(&m.fb, x, y);
            if (inside) {
                RFB_CHECK_EQ_UINT(p[0], 255u);
                RFB_CHECK_EQ_UINT(p[3], 255u);
            } else {
                RFB_CHECK_EQ_UINT(p[0], 3u);
                RFB_CHECK_EQ_UINT(p[1], 5u);
                RFB_CHECK_EQ_UINT(p[2], 7u);
                RFB_CHECK_EQ_UINT(p[3], 9u);
            }
        }
    }
    mvs_fb_close(&m);
}

// --- the product seam ------------------------------------------------------
//
// rfb_decode_apple_mvs now paints general type-0 bodies. Everything it cannot
// render keeps the pre-decoder contract: validate, consume, damage nothing.

RFB_TEST(apple_mvs_image, product_seam_paints_a_general_type0_body)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 1 0 1110 0101 0010");   // luma DC level 10
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(rfb_decode_apple_mvs(&m.fb, &rh, b.bytes, b.len, false,
                                          qt0, qt1, NULL, &dmg),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(dmg.width, 8u);
    RFB_CHECK_EQ_UINT(dmg.height, 8u);
    RFB_CHECK(m.fb.generation != m.generation);
    mvs_check_px(&m.fb, 0u, 0u, 143u, 143u, 143u);
    mvs_check_px(&m.fb, 7u, 7u, 143u, 143u, 143u);
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, product_seam_without_tables_consumes_without_damage)
{
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 1 0 1110 0101 0010");
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    // No 0x03f3 quantisation-table message has arrived yet.
    RFB_CHECK_EQ_INT(rfb_decode_apple_mvs(&m.fb, &rh, b.bytes, b.len, false,
                                          NULL, NULL, NULL, &dmg),
                     RFB_OK);
    mvs_check_untouched(&m, &dmg);
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, product_seam_undecodable_plane_consumes_without_damage)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    // A structurally valid envelope — the command plane closes on its marker
    // and the image plane ends on a unique unaligned 0x6d — whose image
    // record does not parse. The rectangle is consumed, nothing is painted,
    // and the session is not torn down.
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 1 1 1110 0101 0010");   // reserved selector 011
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(rfb_decode_apple_mvs(&m.fb, &rh, b.bytes, b.len, false,
                                          qt0, qt1, NULL, &dmg),
                     RFB_OK);
    mvs_check_untouched(&m, &dmg);
    mvs_fb_close(&m);
}

RFB_TEST(apple_mvs_image, product_seam_unhandled_class_consumes_without_damage)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 3u, 1u);   // BLACK_WHITE: unsupported command
    mvs_body_finish(&b, 15u, 25u);

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(rfb_decode_apple_mvs(&m.fb, &rh, b.bytes, b.len, false,
                                          qt0, qt1, NULL, &dmg),
                     RFB_OK);
    mvs_check_untouched(&m, &dmg);
    mvs_fb_close(&m);
}

// A malformed envelope still fails closed with a protocol error, exactly as
// before the decoder existed: the image plane must end on one unaligned 0x6d
// marker plus zero pad.
RFB_TEST(apple_mvs_image, product_seam_malformed_envelope_still_protocol)
{
    uint8_t qt0[64], qt1[64];
    mvs_test_tables(qt0, qt1);
    mvs_body b;
    mvs_body_begin(&b);
    mvs_body_tiles(&b, 5u, 1u);
    mvs_body_img(&b, "0 1 0 1110 0101 0010");
    mvs_body_finish(&b, 15u, 25u);
    b.bytes[b.len - 1u] ^= 0x10u;   // break the image endpoint

    mvs_fb m;
    mvs_fb_open(&m, 8u, 8u);
    rfb_rect_header rh = {.x = 0, .y = 0, .width = 8, .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    for (unsigned skip = 0u; skip < 2u; skip++) {
        memset(&dmg, 0, sizeof dmg);
        RFB_CHECK_EQ_INT(rfb_decode_apple_mvs(&m.fb, &rh, b.bytes, b.len,
                                              skip != 0u, qt0, qt1, NULL,
                                              &dmg),
                         RFB_ERR_PROTOCOL);
        mvs_check_untouched(&m, &dmg);
    }
    mvs_fb_close(&m);
}
