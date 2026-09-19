// SPDX-License-Identifier: Apache-2.0
//
// Unit tests: Apple MultiVariant (0x03f3) solid-black KAT + product expand.

#include "rfb_test.h"
#include "farsee/apple_mvs_bits.h"
#include "farsee/apple_mvs_stream.h"
#include "farsee/apple_wire_decode.h"
#include "farsee/encoding_apple_mvs.h"
#include "farsee/framebuffer.h"

#include <stdint.h>
#include <string.h>

static const uint8_t k_black15[] = {0x00, 0x03, 0x05, 0x00, 0x00, 0x0b, 0x41,
                                    0xff, 0x72, 0xfb, 0x68, 0x00, 0x20, 0x81,
                                    0xb4};

static size_t build_type0_body(uint8_t *body, size_t body_cap)
{
    RFB_CHECK(body_cap >= 9u);
    uint8_t stream[8];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, stream, sizeof stream);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u)); // type-0 leading flag
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 3u)); // command 0
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u)); // repeat 0 => one tile
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0x6du, 8u)); // command marker
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));
    body[0] = 0x00;
    body[1] = 0x0f;
    body[2] = 0x19;
    body[3] = 0x00;
    body[4] = 0x00;
    body[5] = 0x08;
    memcpy(body + 6u, stream, bw.len);
    body[8] = 0x6du; // independent image-plane endpoint (empty payload)
    return 9u;
}

RFB_TEST(encoding_apple_mvs, solid_black_fills_rect)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK(rfb_framebuffer_resize(&fb, 32, 16, 1u << 20) == RFB_OK);
    rfb_framebuffer_fill(&fb, 10, 20, 30, 255);

    rfb_rect_header rh = {.x = 0,
                          .y = 0,
                          .width = 32,
                          .height = 16,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK(rfb_decode_apple_mvs(&fb, &rh, k_black15, sizeof k_black15, false,
                                   NULL, NULL, NULL, &dmg) == RFB_OK);
    RFB_CHECK_EQ_UINT(dmg.width, 32u);
    RFB_CHECK_EQ_UINT(dmg.height, 16u);
    const uint8_t *p = rfb_framebuffer_pixel_c(&fb, 0, 0);
    RFB_CHECK_EQ_UINT(p[0], 0u);
    RFB_CHECK_EQ_UINT(p[1], 0u);
    RFB_CHECK_EQ_UINT(p[2], 0u);
    RFB_CHECK_EQ_UINT(p[3], 255u);
    p = rfb_framebuffer_pixel_c(&fb, 31, 15);
    RFB_CHECK_EQ_UINT(p[0], 0u);
    RFB_CHECK_EQ_UINT(p[3], 255u);
    rfb_framebuffer_destroy(&fb);
}

// A 4-byte inline/type-1 fixture must not be accepted as type-0.
RFB_TEST(encoding_apple_mvs, legacy_inline_white_rejected)
{
    uint8_t stream[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, stream, sizeof stream);
    for (int i = 0; i < 4; i++) {
        RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 2u));
    }
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    uint8_t body[4 + 16];
    body[0] = 0x00;
    body[1] = 0x03;
    body[2] = 0x05;
    body[3] = 0x00;
    memcpy(body + 4, stream, bw.len);
    size_t body_len = 4u + bw.len;

    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK(rfb_framebuffer_resize(&fb, 16, 16, 1u << 20) == RFB_OK);
    rfb_framebuffer_fill(&fb, 1, 2, 3, 255);

    rfb_rect_header rh = {.x = 0,
                          .y = 0,
                          .width = 16,
                          .height = 16,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK(rfb_decode_apple_mvs(&fb, &rh, body, body_len, false, NULL, NULL,
                                   NULL, &dmg) == RFB_ERR_PROTOCOL);
    const uint8_t *p = rfb_framebuffer_pixel_c(&fb, 0, 0);
    RFB_CHECK_EQ_UINT(p[0], 1u);
    RFB_CHECK_EQ_UINT(p[1], 2u);
    RFB_CHECK_EQ_UINT(p[2], 3u);
    p = rfb_framebuffer_pixel_c(&fb, 15, 15);
    RFB_CHECK_EQ_UINT(p[0], 1u);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(encoding_apple_mvs, legacy_inline_last_match_rejected)
{
    uint8_t stream[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, stream, sizeof stream);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 2u)); // White
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 2u, 2u)); // LastMatch
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 2u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 2u));
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    uint8_t body[4 + 16];
    body[0] = 0x00;
    body[1] = 0x0f;
    body[2] = 0x19;
    body[3] = 0x00;
    memcpy(body + 4, stream, bw.len);

    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK(rfb_framebuffer_resize(&fb, 16, 16, 1u << 20) == RFB_OK);
    rfb_framebuffer_fill(&fb, 9, 9, 9, 255);

    rfb_rect_header rh = {.x = 0,
                          .y = 0,
                          .width = 16,
                          .height = 16,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK(rfb_decode_apple_mvs(&fb, &rh, body, 4u + bw.len, false, NULL,
                                   NULL, NULL, &dmg) == RFB_ERR_PROTOCOL);
    const uint8_t *p = rfb_framebuffer_pixel_c(&fb, 8, 0);
    RFB_CHECK_EQ_UINT(p[0], 9u);
    RFB_CHECK_EQ_UINT(p[1], 9u);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(encoding_apple_mvs, short_body_protocol_or_skip)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK(rfb_framebuffer_resize(&fb, 8, 8, 1u << 20) == RFB_OK);
    rfb_rect_header rh = {.x = 0,
                          .y = 0,
                          .width = 8,
                          .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    uint8_t junk[2] = {0xde, 0xad};
    rfb_rect dmg;
    RFB_CHECK(rfb_decode_apple_mvs(&fb, &rh, junk, sizeof junk, false, NULL,
                                   NULL, NULL, &dmg) == RFB_ERR_PROTOCOL);
    RFB_CHECK(rfb_decode_apple_mvs(&fb, &rh, junk, sizeof junk, true, NULL,
                                   NULL, NULL, &dmg) == RFB_OK);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(encoding_apple_mvs, malformed_type0_header_never_skips)
{
    static const uint8_t offset_too_small[] = {
        0x00u, 0x03u, 0x05u, 0x00u, 0x00u, 0x05u};
    static const uint8_t offset_at_len[] = {
        0x00u, 0x03u, 0x05u, 0x00u, 0x00u, 0x06u};
    static const uint8_t offset_too_large[] = {
        0x00u, 0x03u, 0x05u, 0x00u, 0x00u, 0x07u};
    static const struct {
        const uint8_t *body;
        size_t len;
    } cases[] = {
        {offset_too_small, sizeof offset_too_small},
        {offset_at_len, sizeof offset_at_len},
        {offset_too_large, sizeof offset_too_large},
    };

    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK(rfb_framebuffer_resize(&fb, 8, 8, 1u << 20) == RFB_OK);
    rfb_framebuffer_fill(&fb, 9u, 8u, 7u, 6u);
    const uint64_t generation = fb.generation;
    uint8_t before[8u * 8u * 4u];
    memcpy(before, fb.rgba, sizeof before);
    rfb_rect_header rh = {.x = 0,
                          .y = 0,
                          .width = 8,
                          .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        rfb_rect damage = {.x = 1u, .y = 2u, .width = 3u, .height = 4u};
        RFB_CHECK_EQ_INT(rfb_decode_apple_mvs(
                             &fb, &rh, cases[i].body, cases[i].len, true,
                             NULL, NULL, NULL, &damage),
                         RFB_ERR_PROTOCOL);
        RFB_CHECK_EQ_UINT(damage.width, 0u);
        RFB_CHECK_EQ_UINT(damage.height, 0u);
        RFB_CHECK_EQ_UINT(fb.generation, generation);
        RFB_CHECK(memcmp(fb.rgba, before, sizeof before) == 0);
    }
    rfb_framebuffer_destroy(&fb);
}

// Called without quantisation tables, so the image decoder cannot render and
// the pre-decoder contract applies: consume, damage nothing, leave the
// coefficient store alone. A broken image endpoint still fails closed.
// The tables-present paint path is covered in apple_mvs_image__tests.c.
RFB_TEST(encoding_apple_mvs, type0_image_endpoint_is_transactional)
{
    uint8_t body[12];
    const size_t body_len = build_type0_body(body, sizeof body);
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK(rfb_framebuffer_resize(&fb, 8, 8, 1u << 20) == RFB_OK);
    rfb_framebuffer_fill(&fb, 11u, 22u, 33u, 44u);
    const uint64_t generation = fb.generation;
    uint8_t before_rgba[8u * 8u * 4u];
    memcpy(before_rgba, fb.rgba, sizeof before_rgba);

    apple_mvs_coeff_store store;
    memset(&store, 0, sizeof store);
    RFB_CHECK(apple_mvs_coeff_store_ensure(&store, 8u, 8u));
    apple_mvs_tile_state *slot = apple_mvs_coeff_store_at(&store, 0u, 0u);
    RFB_CHECK(slot != NULL);
    slot->y[0] = 123;
    slot->cb[0] = -45;
    slot->valid = true;
    const apple_mvs_tile_state before_tile = *slot;

    rfb_rect_header rh = {.x = 0,
                          .y = 0,
                          .width = 8,
                          .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect damage = {.x = 1u, .y = 2u, .width = 3u, .height = 4u};
    RFB_CHECK_EQ_INT(rfb_decode_apple_mvs(&fb, &rh, body, body_len, false,
                                          NULL, NULL, &store, &damage),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(damage.width, 0u);
    RFB_CHECK_EQ_UINT(damage.height, 0u);
    RFB_CHECK_EQ_UINT(fb.generation, generation);
    RFB_CHECK(memcmp(fb.rgba, before_rgba, sizeof before_rgba) == 0);
    RFB_CHECK(memcmp(slot, &before_tile, sizeof before_tile) == 0);

    body[body_len - 1u] ^= 0x10u;
    for (unsigned skip = 0u; skip < 2u; skip++) {
        damage = (rfb_rect){.x = 1u, .y = 2u, .width = 3u, .height = 4u};
        RFB_CHECK_EQ_INT(rfb_decode_apple_mvs(&fb, &rh, body, body_len,
                                              skip != 0u, NULL, NULL, &store,
                                              &damage),
                         RFB_ERR_PROTOCOL);
        RFB_CHECK_EQ_UINT(damage.width, 0u);
        RFB_CHECK_EQ_UINT(damage.height, 0u);
        RFB_CHECK_EQ_UINT(fb.generation, generation);
        RFB_CHECK(memcmp(fb.rgba, before_rgba, sizeof before_rgba) == 0);
        RFB_CHECK(memcmp(slot, &before_tile, sizeof before_tile) == 0);
    }

    apple_mvs_coeff_store_free(&store);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(encoding_apple_mvs, oob_rect_protocol)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK(rfb_framebuffer_resize(&fb, 8, 8, 1u << 20) == RFB_OK);
    rfb_rect_header rh = {.x = 4,
                          .y = 4,
                          .width = 8,
                          .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK(rfb_decode_apple_mvs(&fb, &rh, k_black15, sizeof k_black15, true,
                                   NULL, NULL, NULL, &dmg) == RFB_ERR_PROTOCOL);
    rfb_framebuffer_destroy(&fb);
}

// Type-0 envelope validation rejects an inline tile body before tile decoding
// or framebuffer exposure. This body contains one White prefix followed by an
// invalid 3-bit tile prefix, but it does not provide independently bounded
// command and image planes. The decoder returns RFB_ERR_PROTOCOL atomically.
RFB_TEST(encoding_apple_mvs, legacy_inline_stream_failure_rejected)
{
    uint8_t stream[4];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, stream, sizeof stream);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 2u));   // White (tile 0)
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0x3u, 2u)); // peek2 = 11 → 3-bit branch
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0x0u, 3u)); // b3 = 000 → PROTOCOL
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    uint8_t body[4 + 4];
    body[0] = 0x00;
    body[1] = 0x03;  // normal_count = 3
    body[2] = 0x05;  // large_count = 5
    body[3] = 0x00;  // flags
    memcpy(body + 4, stream, bw.len);
    const size_t body_len = 4u + bw.len;

    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK(rfb_framebuffer_resize(&fb, 16, 16, 1u << 20) == RFB_OK);
    rfb_framebuffer_fill(&fb, 9, 9, 9, 255);

    rfb_rect_header rh = {.x = 0,
                          .y = 0,
                          .width = 16,
                          .height = 16,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK(rfb_decode_apple_mvs(&fb, &rh, body, body_len, false, NULL, NULL,
                                   NULL, &dmg) == RFB_ERR_PROTOCOL);
    // Atomic rejection leaves the framebuffer unchanged.
    const uint8_t *p = rfb_framebuffer_pixel_c(&fb, 0, 0);
    RFB_CHECK_EQ_UINT(p[0], 9u);
    RFB_CHECK_EQ_UINT(p[1], 9u);
    RFB_CHECK_EQ_UINT(p[2], 9u);
    rfb_framebuffer_destroy(&fb);
}

// Type-0 envelope validation also rejects an inline FULL body when a coefficient
// store is present. It returns zero damage without painting, uses no
// quantisation table, and does not replace pre-existing coefficient state. The
// body contains a FULL prefix, one DC coefficient, and Cb/Cr DC differences,
// but it does not provide independently bounded command and image planes.
RFB_TEST(encoding_apple_mvs, legacy_inline_full_rejected_without_paint)
{
    uint8_t stream[8];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, stream, sizeof stream);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 1u, 2u));  // FULL prefix
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 6u));  // n_sig-1=0 → DC-only
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));  // cb DC small_diff = 0
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));  // cr DC small_diff = 0
    // The byte padding is not interpreted because envelope validation fails.
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    uint8_t body[4 + 8];
    body[0] = 0x00;
    body[1] = 0x0f;  // normal_count = 15 (high-tier)
    body[2] = 0x19;  // large_count = 25
    body[3] = 0x00;  // flags
    memcpy(body + 4, stream, bw.len);
    const size_t body_len = 4u + bw.len;

    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK(rfb_framebuffer_resize(&fb, 8, 8, 1u << 20) == RFB_OK);
    rfb_framebuffer_fill(&fb, 0, 0, 0, 0);  // transparent black baseline

    // Pre-existing Cb, Cr, and count state must remain unchanged alongside the
    // transparent framebuffer.
    apple_mvs_coeff_store store;
    memset(&store, 0, sizeof store);
    RFB_CHECK(apple_mvs_coeff_store_ensure(&store, 8u, 8u));
    apple_mvs_tile_state *slot = apple_mvs_coeff_store_at(&store, 0u, 0u);
    RFB_CHECK(slot != NULL);
    slot->cb[0] = 80;
    slot->cr[0] = -80;
    slot->valid = true;

    rfb_rect_header rh = {.x = 0,
                          .y = 0,
                          .width = 8,
                          .height = 8,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    RFB_CHECK(rfb_decode_apple_mvs(&fb, &rh, body, body_len, false, NULL, NULL,
                                   &store, &dmg) == RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(dmg.width, 0u);
    RFB_CHECK_EQ_UINT(dmg.height, 0u);

    // Rejection is atomic: the framebuffer stays at its transparent baseline.
    const uint8_t *p = rfb_framebuffer_pixel_c(&fb, 0, 0);
    RFB_CHECK_EQ_UINT(p[3], 0u);
    const uint8_t *q = rfb_framebuffer_pixel_c(&fb, 7, 7);
    RFB_CHECK_EQ_UINT(q[3], 0u);

    // The legacy payload also cannot mutate the pre-existing coefficient slot.
    apple_mvs_tile_state *after = apple_mvs_coeff_store_at(&store, 0u, 0u);
    RFB_CHECK(after != NULL);
    RFB_CHECK(after->valid);
    RFB_CHECK_EQ_INT(after->cb[0], 80);
    RFB_CHECK_EQ_INT(after->cr[0], -80);
    RFB_CHECK_EQ_UINT(after->cb_count, 0u);
    RFB_CHECK_EQ_UINT(after->cr_count, 0u);

    apple_mvs_coeff_store_free(&store);
    rfb_framebuffer_destroy(&fb);
}
