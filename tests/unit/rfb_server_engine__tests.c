// SPDX-License-Identifier: Apache-2.0
//
// Pure buffer demux/decode tests with synthetic FBU, Apple 0x0450, Bell,
// ServerCutText, and SetColourMapEntries vectors. No fd or environment access.

#include "rfb_test.h"
#include "farsee/rfb_server_engine.h"
#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/error.h"
#include "farsee/framebuffer.h"
#include "farsee/pacing.h"
#include "farsee/pixel_format.h"

#include <string.h>
#include <zlib.h>

// --- test fixture ----------------------------------------------------------

typedef struct eng_fixture {
    rfb_server_engine eng;
    rfb_buffer in;
    rfb_framebuffer fb;
    rfb_pixel_format pf;
    rfb_cursor cursor;
    rfb_pacing pacing;
    rfb_allocator *alloc;
    uint16_t fb_w;
    uint16_t fb_h;
    unsigned publish_count;
    unsigned bell_count;
    unsigned cut_count;
    size_t cut_last_len;
    unsigned fbu_begin_count;
    uint16_t fbu_last_nrects;
    unsigned rect_decoded_count;
    rfb_rect_header rect_decoded_last;
    unsigned rect_decoded_publish_count;
    unsigned desktop_size_count;
    uint16_t desktop_last_w;
    uint16_t desktop_last_h;
    rfb_error publish_error;
    rfb_error fbu_begin_error;
    rfb_error rect_decoded_error;
} eng_fixture;

static rfb_error fixture_on_publish(void *ctx)
{
    eng_fixture *f = (eng_fixture *)ctx;
    f->publish_count++;
    return f->publish_error;
}

static void fixture_on_bell(void *ctx)
{
    eng_fixture *f = (eng_fixture *)ctx;
    f->bell_count++;
}

static void fixture_on_cut(void *ctx, const uint8_t *text, size_t len)
{
    eng_fixture *f = (eng_fixture *)ctx;
    (void)text;
    f->cut_count++;
    f->cut_last_len = len;
}

static rfb_error fixture_on_fbu_begin(void *ctx, uint16_t nrects)
{
    eng_fixture *f = (eng_fixture *)ctx;
    f->fbu_begin_count++;
    f->fbu_last_nrects = nrects;
    return f->fbu_begin_error;
}

static rfb_error fixture_on_rect_decoded(void *ctx,
                                         const rfb_rect_header *rect,
                                         const uint8_t *payload,
                                         size_t payload_len)
{
    eng_fixture *f = (eng_fixture *)ctx;
    (void)payload;
    (void)payload_len;
    f->rect_decoded_count++;
    f->rect_decoded_last = *rect;
    f->rect_decoded_publish_count = f->publish_count;
    return f->rect_decoded_error;
}

static void fixture_on_desktop_size(void *ctx, uint16_t width,
                                    uint16_t height)
{
    eng_fixture *f = (eng_fixture *)ctx;
    f->desktop_size_count++;
    f->desktop_last_w = width;
    f->desktop_last_h = height;
}

static void fixture_init(eng_fixture *f, uint16_t w, uint16_t h)
{
    memset(f, 0, sizeof *f);
    f->alloc = rfb_default_allocator();
    rfb_server_engine_init(&f->eng);
    rfb_buffer_init(&f->in, f->alloc, 1u << 20);
    rfb_framebuffer_init(&f->fb, f->alloc);
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&f->fb, w, h, 1u << 20), RFB_OK);
    f->pf = rfb_pixel_format_canonical_request();
    memset(&f->cursor, 0, sizeof f->cursor);
    rfb_pacing_init(&f->pacing, 0);
    f->fb_w = w;
    f->fb_h = h;
}

static void fixture_destroy(eng_fixture *f)
{
    rfb_cursor_destroy(&f->cursor, f->alloc);
    rfb_framebuffer_destroy(&f->fb);
    rfb_buffer_destroy(&f->in);
}

static rfb_server_engine_ctx fixture_ctx(eng_fixture *f)
{
    rfb_server_engine_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.eng = &f->eng;
    ctx.in = &f->in;
    ctx.fb = &f->fb;
    ctx.pf = &f->pf;
    ctx.zstream = NULL;
    ctx.cursor = &f->cursor;
    ctx.alloc = f->alloc;
    ctx.pacing = &f->pacing;
    ctx.dialect = RFB_SESSION_DIALECT_CLASSIC;
    ctx.fb_width = &f->fb_w;
    ctx.fb_height = &f->fb_h;
    ctx.hooks.hook_ctx = f;
    ctx.hooks.on_publish = fixture_on_publish;
    ctx.hooks.on_bell = fixture_on_bell;
    ctx.hooks.on_cut_text = fixture_on_cut;
    ctx.hooks.on_fbu_begin = fixture_on_fbu_begin;
    return ctx;
}

// 1x1 Raw red FBU (canonical 32bpp LE: R at shift 16 → bytes 00 00 FF 00).
static const uint8_t k_fbu_1x1_red[] = {
    0x00, 0x00,       // type=0, pad
    0x00, 0x01,       // nrects = 1
    0x00, 0x00,       // x
    0x00, 0x00,       // y
    0x00, 0x01,       // w
    0x00, 0x01,       // h
    0x00, 0x00, 0x00, 0x00, // encoding = Raw
    0x00, 0x00, 0xFF, 0x00, // red pixel
};

// Supported 0x0450 profile with one transparent alpha-cursor pixel.
static const uint8_t k_fbu_1x1_apple_0450[] = {
    0x00, 0x00, 0x00, 0x01, // FBU, one rectangle
    0x00, 0x00, 0x00, 0x00, // x, y
    0x00, 0x01, 0x00, 0x01, // width, height
    0x00, 0x00, 0x04, 0x50, // encoding 0x0450
    0x00, 0x00, 0x03, 0xe8, // profile parameter 1000
    0x00, 0x00, 0x00, 0x0c, // compressed length 12
    0x78, 0xda, 0x62, 0x60, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
};

static size_t build_single_rect_fbu(uint8_t *out, size_t out_capacity,
                                    uint16_t x, uint16_t y,
                                    uint16_t width, uint16_t height,
                                    int32_t encoding,
                                    const uint8_t *after_header,
                                    size_t after_header_length)
{
    if (out == NULL || out_capacity < 16u + after_header_length ||
        (after_header == NULL && after_header_length > 0u)) {
        return 0u;
    }
    const uint32_t wire_encoding = (uint32_t)encoding;
    out[0] = 0u;
    out[1] = 0u;
    out[2] = 0u;
    out[3] = 1u;
    out[4] = (uint8_t)(x >> 8u);
    out[5] = (uint8_t)x;
    out[6] = (uint8_t)(y >> 8u);
    out[7] = (uint8_t)y;
    out[8] = (uint8_t)(width >> 8u);
    out[9] = (uint8_t)width;
    out[10] = (uint8_t)(height >> 8u);
    out[11] = (uint8_t)height;
    out[12] = (uint8_t)(wire_encoding >> 24u);
    out[13] = (uint8_t)(wire_encoding >> 16u);
    out[14] = (uint8_t)(wire_encoding >> 8u);
    out[15] = (uint8_t)wire_encoding;
    if (after_header_length > 0u) {
        memcpy(out + 16u, after_header, after_header_length);
    }
    return 16u + after_header_length;
}

// --- null / empty ----------------------------------------------------------

RFB_TEST(rfb_server_engine, process_in__null_ctx__returns_internal)
{
    bool progress = true;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(NULL, &progress),
                     RFB_ERR_INTERNAL);
}

RFB_TEST(rfb_server_engine, process_in__empty_buffer__need_more_no_progress)
{
    eng_fixture f;
    fixture_init(&f, 1, 1);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = true;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(!progress);
    RFB_CHECK_EQ_UINT(f.publish_count, 0u);
    fixture_destroy(&f);
}

// --- negative: truncated headers -------------------------------------------

RFB_TEST(rfb_server_engine, process_in__truncated_fbu_type_only__need_more)
{
    eng_fixture f;
    fixture_init(&f, 1, 1);
    static const uint8_t partial[] = { 0x00 }; // type only
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, partial, sizeof partial),
                     RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = true;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(!progress);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 1u);
    RFB_CHECK(!f.eng.in_fbupdate);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__truncated_fbu_header_3bytes__need_more)
{
    eng_fixture f;
    fixture_init(&f, 1, 1);
    static const uint8_t partial[] = { 0x00, 0x00, 0x00 }; // missing nrects low
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, partial, sizeof partial),
                     RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(!progress);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 3u);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__fbu_header_only_no_rect__need_more)
{
    eng_fixture f;
    fixture_init(&f, 1, 1);
    // Full FBU header, nrects=1, no rectangle bytes yet.
    static const uint8_t hdr[] = { 0x00, 0x00, 0x00, 0x01 };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, hdr, sizeof hdr), RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress); // header consumed
    RFB_CHECK(f.eng.in_fbupdate);
    RFB_CHECK_EQ_UINT(f.eng.rects_remaining, 1u);
    RFB_CHECK_EQ_UINT(f.fbu_begin_count, 1u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 0u);
    RFB_CHECK_EQ_UINT(f.publish_count, 0u);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__truncated_rect_header__need_more)
{
    eng_fixture f;
    fixture_init(&f, 1, 1);
    static const uint8_t partial[] = {
        0x00, 0x00, 0x00, 0x01, // FBU hdr nrects=1
        0x00, 0x00, 0x00, 0x00, // incomplete rect (only 4 of 12)
    };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, partial, sizeof partial),
                     RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK(f.eng.in_fbupdate);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 4u); // residual rect prefix
    fixture_destroy(&f);
}

// --- positive: 1x1 raw red -------------------------------------------------

RFB_TEST(rfb_server_engine, process_in__1x1_raw_red__writes_pixel_and_publishes)
{
    eng_fixture f;
    fixture_init(&f, 1, 1);
    RFB_CHECK_EQ_INT(
        rfb_buffer_append(&f.in, k_fbu_1x1_red, sizeof k_fbu_1x1_red),
        RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK(!f.eng.in_fbupdate);
    RFB_CHECK_EQ_UINT(f.eng.rects_decoded, 1u);
    RFB_CHECK_EQ_UINT(f.publish_count, 1u);
    RFB_CHECK_EQ_UINT(f.fbu_begin_count, 1u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 0u);
    const uint8_t *p = rfb_framebuffer_pixel_c(&f.fb, 0, 0);
    RFB_CHECK(p != NULL);
    RFB_CHECK_EQ_UINT(p[0], 0xFFu);
    RFB_CHECK_EQ_UINT(p[1], 0x00u);
    RFB_CHECK_EQ_UINT(p[2], 0x00u);
    RFB_CHECK_EQ_UINT(p[3], 0xFFu);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__rect_decoded_hook__defaults_to_null)
{
    eng_fixture f;
    fixture_init(&f, 1u, 1u);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    RFB_CHECK(ctx.hooks.on_rect_decoded == NULL);
    RFB_CHECK_EQ_INT(
        rfb_buffer_append(&f.in, k_fbu_1x1_red, sizeof k_fbu_1x1_red),
        RFB_OK);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK_EQ_UINT(f.publish_count, 1u);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine,
         process_in__rect_decoded_hook__fires_only_after_complete_rectangle)
{
    eng_fixture f;
    fixture_init(&f, 1u, 1u);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    ctx.hooks.on_rect_decoded = fixture_on_rect_decoded;

    const size_t split = sizeof k_fbu_1x1_red - 1u;
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, k_fbu_1x1_red, split), RFB_OK);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress); // FBU header consumed; rectangle remains incomplete.
    RFB_CHECK_EQ_UINT(f.rect_decoded_count, 0u);
    RFB_CHECK_EQ_UINT(f.eng.rects_decoded, 0u);
    RFB_CHECK_EQ_UINT(f.publish_count, 0u);

    RFB_CHECK_EQ_INT(
        rfb_buffer_append(&f.in, &k_fbu_1x1_red[split], 1u), RFB_OK);
    progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK_EQ_UINT(f.rect_decoded_count, 1u);
    RFB_CHECK_EQ_UINT(f.rect_decoded_publish_count, 0u);
    RFB_CHECK_EQ_UINT(f.rect_decoded_last.x, 0u);
    RFB_CHECK_EQ_UINT(f.rect_decoded_last.y, 0u);
    RFB_CHECK_EQ_UINT(f.rect_decoded_last.width, 1u);
    RFB_CHECK_EQ_UINT(f.rect_decoded_last.height, 1u);
    RFB_CHECK_EQ_INT(f.rect_decoded_last.encoding, RFB_ENCODING_RAW);
    RFB_CHECK_EQ_UINT(f.eng.rects_decoded, 1u);
    RFB_CHECK_EQ_UINT(f.publish_count, 1u);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__apple_0450_decodes_separate_cursor)
{
    eng_fixture f;
    fixture_init(&f, 1u, 1u);
    rfb_framebuffer_fill(&f.fb, 9u, 8u, 7u, 6u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, k_fbu_1x1_apple_0450,
                                       sizeof k_fbu_1x1_apple_0450),
                     RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 0u);
    RFB_CHECK_EQ_UINT(f.publish_count, 1u);
    const uint8_t *pixel = rfb_framebuffer_pixel_c(&f.fb, 0u, 0u);
    RFB_CHECK_EQ_UINT(pixel[0], 9u);
    RFB_CHECK_EQ_UINT(pixel[1], 8u);
    RFB_CHECK_EQ_UINT(pixel[2], 7u);
    RFB_CHECK_EQ_UINT(pixel[3], 6u);
    RFB_CHECK(f.cursor.valid);
    RFB_CHECK_EQ_UINT(f.cursor.width, 1u);
    RFB_CHECK_EQ_UINT(f.cursor.height, 1u);
    static const uint8_t transparent[] = {0u, 0u, 0u, 0u};
    RFB_CHECK_MEM_EQ(f.cursor.rgba, transparent, sizeof transparent);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__apple_0450_xy_are_hotspot_not_damage)
{
    eng_fixture f;
    fixture_init(&f, 1u, 1u);
    uint8_t message[sizeof k_fbu_1x1_apple_0450];
    memcpy(message, k_fbu_1x1_apple_0450, sizeof message);
    message[4] = 0x01u;
    message[5] = 0x23u;
    message[6] = 0x02u;
    message[7] = 0x34u;
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, message, sizeof message),
                     RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK(f.cursor.valid);
    RFB_CHECK_EQ_UINT(f.cursor.hotspot_x, 0x0123u);
    RFB_CHECK_EQ_UINT(f.cursor.hotspot_y, 0x0234u);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__apple_0450_byte_at_a_time)
{
    eng_fixture f;
    fixture_init(&f, 1u, 1u);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    for (size_t i = 0u; i < sizeof k_fbu_1x1_apple_0450; i++) {
        RFB_CHECK_EQ_INT(rfb_buffer_append(
                             &f.in, k_fbu_1x1_apple_0450 + i, 1u),
                         RFB_OK);
        bool progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_OK);
    }
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 0u);
    RFB_CHECK_EQ_UINT(f.publish_count, 1u);
    RFB_CHECK_EQ_UINT(f.eng.rects_decoded, 1u);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__apple_0450_then_raw_stays_aligned)
{
    eng_fixture f;
    fixture_init(&f, 1u, 1u);
    uint8_t message[sizeof k_fbu_1x1_apple_0450 + 16u];
    memcpy(message, k_fbu_1x1_apple_0450,
           sizeof k_fbu_1x1_apple_0450);
    message[3] = 2u; // two rectangles in this update
    static const uint8_t raw_rect[] = {
        0x00, 0x00, 0x00, 0x00, // x, y
        0x00, 0x01, 0x00, 0x01, // width, height
        0x00, 0x00, 0x00, 0x00, // Raw
        0x00, 0x00, 0xff, 0x00, // red pixel
    };
    memcpy(message + sizeof k_fbu_1x1_apple_0450, raw_rect,
           sizeof raw_rect);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, message, sizeof message), RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK_EQ_UINT(f.publish_count, 1u);
    RFB_CHECK_EQ_UINT(f.eng.rects_decoded, 2u);
    const uint8_t *pixel = rfb_framebuffer_pixel_c(&f.fb, 0u, 0u);
    RFB_CHECK_EQ_UINT(pixel[0], 255u);
    RFB_CHECK_EQ_UINT(pixel[1], 0u);
    RFB_CHECK_EQ_UINT(pixel[2], 0u);
    RFB_CHECK_EQ_UINT(pixel[3], 255u);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__apple_0450_corrupt_zlib_fails)
{
    eng_fixture f;
    fixture_init(&f, 1u, 1u);
    uint8_t corrupt[sizeof k_fbu_1x1_apple_0450];
    memcpy(corrupt, k_fbu_1x1_apple_0450, sizeof corrupt);
    corrupt[24] = 0u; // first zlib header byte
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, corrupt, sizeof corrupt), RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(f.publish_count, 0u);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__apple_0450_rejects_prefix_early)
{
    static const uint8_t rect_and_envelope[] = {
        0x00, 0x00, 0x00, 0x01, // FBU, one rectangle
        0x00, 0x00, 0x00, 0x00, // x, y
        0x00, 0x01, 0x00, 0x01, // width, height
        0x00, 0x00, 0x04, 0x50, // encoding 0x0450
        0x00, 0x00, 0x03, 0xe7, // unsupported parameter 999
        0x00, 0x00, 0x00, 0x0d, // body is deliberately absent
    };
    eng_fixture f;
    fixture_init(&f, 1u, 1u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, rect_and_envelope,
                                       sizeof rect_and_envelope),
                     RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 20u);
    RFB_CHECK_EQ_UINT(f.publish_count, 0u);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__apple_0450_waits_for_eight_byte_prefix)
{
    static const uint8_t through_seven_envelope_bytes[] = {
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x04, 0x50,
        0x00, 0x00, 0x03, 0xe8,
        0x00, 0x00, 0x00,
    };
    eng_fixture f;
    fixture_init(&f, 1u, 1u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, through_seven_envelope_bytes,
                                       sizeof through_seven_envelope_bytes),
                     RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress); // only the four-byte FBU header was consumed
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 19u);
    RFB_CHECK_EQ_UINT(f.eng.rects_decoded, 0u);

    static const uint8_t compressed_len_low = 0x0du;
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, &compressed_len_low, 1u), RFB_OK);
    progress = true;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(!progress);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 20u);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__apple_0450_overlimit_prefix_fails)
{
    static const uint8_t rect_and_envelope[] = {
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x04, 0x50,
        0x00, 0x00, 0x03, 0xe8,
        0x10, 0x00, 0x00, 0x01, // compressed limit + 1
    };
    eng_fixture f;
    fixture_init(&f, 1u, 1u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, rect_and_envelope,
                                       sizeof rect_and_envelope),
                     RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 20u);
    RFB_CHECK_EQ_UINT(f.publish_count, 0u);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__1x1_raw_red_byte_at_a_time__same_result)
{
    eng_fixture f;
    fixture_init(&f, 1, 1);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    for (size_t i = 0; i < sizeof k_fbu_1x1_red; i++) {
        RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, &k_fbu_1x1_red[i], 1u),
                         RFB_OK);
        bool progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_OK);
    }
    RFB_CHECK_EQ_UINT(f.publish_count, 1u);
    const uint8_t *p = rfb_framebuffer_pixel_c(&f.fb, 0, 0);
    RFB_CHECK_EQ_UINT(p[0], 0xFFu);
    RFB_CHECK_EQ_UINT(p[1], 0x00u);
    RFB_CHECK_EQ_UINT(p[2], 0x00u);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__zero_rect_fbu__publishes_once)
{
    eng_fixture f;
    fixture_init(&f, 1, 1);
    static const uint8_t z[] = { 0x00, 0x00, 0x00, 0x00 }; // nrects=0
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, z, sizeof z), RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK_EQ_UINT(f.publish_count, 1u);
    RFB_CHECK(!f.eng.in_fbupdate);
    fixture_destroy(&f);
}

// --- Bell (wired via rfb_parse_bell) ---------------------------------------

RFB_TEST(rfb_server_engine, process_in__bell__invokes_on_bell)
{
    eng_fixture f;
    fixture_init(&f, 1, 1);
    static const uint8_t bell[] = { 0x02 };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, bell, sizeof bell), RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK_EQ_UINT(f.bell_count, 1u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 0u);
    fixture_destroy(&f);
}

// --- ServerCutText ---------------------------------------------------------

RFB_TEST(rfb_server_engine, process_in__server_cut_text__invokes_on_cut)
{
    eng_fixture f;
    fixture_init(&f, 1, 1);
    static const uint8_t msg[] = {
        0x03,                   // type
        0x00, 0x00, 0x00,       // pad
        0x00, 0x00, 0x00, 0x03, // len=3
        'h', 'i', '!',
    };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, msg, sizeof msg), RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK_EQ_UINT(f.cut_count, 1u);
    RFB_CHECK_EQ_UINT(f.cut_last_len, 3u);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__server_cut_text_truncated__need_more)
{
    eng_fixture f;
    fixture_init(&f, 1, 1);
    static const uint8_t msg[] = {
        0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x05, // claims 5 bytes
        'a', 'b',               // only 2
    };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, msg, sizeof msg), RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = true;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(!progress);
    RFB_CHECK_EQ_UINT(f.cut_count, 0u);
    fixture_destroy(&f);
}

// --- fail closed -----------------------------------------------------------

RFB_TEST(rfb_server_engine, process_in__unknown_type__protocol_and_records)
{
    eng_fixture f;
    fixture_init(&f, 1, 1);
    static const uint8_t bad[] = { 0x7F };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, bad, sizeof bad), RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = true;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK(!progress);
    RFB_CHECK_EQ_UINT(f.eng.last_unexpected_type, 0x7Fu);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__unsupported_encoding__fails)
{
    eng_fixture f;
    fixture_init(&f, 1, 1);
    static const uint8_t msg[] = {
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x63, // encoding 99
    };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, msg, sizeof msg), RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                     RFB_ERR_UNSUPPORTED);
    RFB_CHECK_EQ_UINT(f.publish_count, 0u);
    fixture_destroy(&f);
}

// --- SetColourMapEntries skip ----------------------------------------------

RFB_TEST(rfb_server_engine, process_in__colour_map_entries__skipped)
{
    eng_fixture f;
    fixture_init(&f, 1, 1);
    // type=1, pad, first=0, count=1 → 6 + 6 = 12 bytes total
    static const uint8_t msg[] = {
        0x01, 0x00,
        0x00, 0x00, // first
        0x00, 0x01, // count
        0x00, 0x01, 0x00, 0x02, 0x00, 0x03, // one RGB entry
    };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, msg, sizeof msg), RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 0u);
    fixture_destroy(&f);
}

// A 65535x65535 Raw rectangle is outside the 64x64 framebuffer and is
// rejected from its header before payload bytes are present.
RFB_TEST(rfb_server_engine, process_in__huge_raw_rect_header__protocol_or_limit)
{
    eng_fixture f;
    fixture_init(&f, 64, 64);
    // FBU nrects=1 + rect w=65535 h=65535 RAW (outside 64x64 fb).
    static const uint8_t hdr[] = {
        0x00, 0x00,             // type=0, pad
        0x00, 0x01,             // nrects = 1
        0x00, 0x00,             // x
        0x00, 0x00,             // y
        0xff, 0xff,             // w = 65535
        0xff, 0xff,             // h = 65535
        0x00, 0x00, 0x00, 0x00, // encoding = Raw
    };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, hdr, sizeof hdr), RFB_OK);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = false;
    rfb_error e = rfb_server_engine_process_in(&ctx, &progress);
    RFB_CHECK(e == RFB_ERR_PROTOCOL || e == RFB_ERR_LIMIT);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine, process_in__required_context_guards__fail_closed)
{
    eng_fixture f;
    fixture_init(&f, 1u, 1u);
    rfb_server_engine_ctx ctx = fixture_ctx(&f);
    bool progress = true;

    rfb_server_engine_init(NULL);
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, NULL),
                     RFB_ERR_INTERNAL);
    ctx.eng = NULL;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                     RFB_ERR_INTERNAL);
    ctx = fixture_ctx(&f);
    ctx.in = NULL;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                     RFB_ERR_INTERNAL);
    ctx = fixture_ctx(&f);
    ctx.fb = NULL;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                     RFB_ERR_INTERNAL);
    ctx = fixture_ctx(&f);
    ctx.pf = NULL;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                     RFB_ERR_INTERNAL);
    ctx = fixture_ctx(&f);
    ctx.cursor = NULL;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                     RFB_ERR_INTERNAL);
    ctx = fixture_ctx(&f);
    ctx.alloc = NULL;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                     RFB_ERR_INTERNAL);
    fixture_destroy(&f);
}

RFB_TEST(rfb_server_engine,
         process_in__copy_cursor_and_desktopsize__dispatch_and_publish)
{
    uint8_t wire[64];
    bool progress = false;

    {
        eng_fixture f;
        fixture_init(&f, 2u, 1u);
        static const uint8_t copy_source[] = {0u, 0u, 0u, 0u};
        const size_t wire_length = build_single_rect_fbu(
            wire, sizeof wire, 1u, 0u, 1u, 1u, RFB_ENCODING_COPYRECT,
            copy_source, sizeof copy_source);
        RFB_CHECK(wire_length > 0u);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, wire, wire_length), RFB_OK);
        rfb_server_engine_ctx ctx = fixture_ctx(&f);
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_OK);
        RFB_CHECK(progress);
        RFB_CHECK_EQ_UINT(f.publish_count, 1u);
        fixture_destroy(&f);
    }

    {
        eng_fixture f;
        fixture_init(&f, 1u, 1u);
        static const uint8_t cursor_payload[] = {
            0u, 0u, 0xffu, 0u, 0x80u,
        };
        const size_t wire_length = build_single_rect_fbu(
            wire, sizeof wire, 0u, 0u, 1u, 1u, RFB_ENCODING_CURSOR,
            cursor_payload, sizeof cursor_payload);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, wire, wire_length), RFB_OK);
        rfb_server_engine_ctx ctx = fixture_ctx(&f);
        progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_OK);
        RFB_CHECK(progress);
        RFB_CHECK_EQ_UINT(f.publish_count, 1u);
        fixture_destroy(&f);
    }

    {
        eng_fixture f;
        fixture_init(&f, 1u, 1u);
        const size_t wire_length = build_single_rect_fbu(
            wire, sizeof wire, 0u, 0u, 2u, 3u,
            RFB_ENCODING_DESKTOPSIZE, NULL, 0u);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, wire, wire_length), RFB_OK);
        rfb_server_engine_ctx ctx = fixture_ctx(&f);
        ctx.hooks.on_desktop_size = fixture_on_desktop_size;
        progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_OK);
        RFB_CHECK(progress);
        RFB_CHECK_EQ_UINT(f.fb.width, 2u);
        RFB_CHECK_EQ_UINT(f.fb.height, 3u);
        RFB_CHECK_EQ_UINT(f.fb_w, 2u);
        RFB_CHECK_EQ_UINT(f.fb_h, 3u);
        RFB_CHECK_EQ_UINT(f.desktop_size_count, 1u);
        RFB_CHECK_EQ_UINT(f.desktop_last_w, 2u);
        RFB_CHECK_EQ_UINT(f.desktop_last_h, 3u);
        fixture_destroy(&f);
    }
}

RFB_TEST(rfb_server_engine, process_in__zero_area_cursor__fails_protocol)
{
    static const struct {
        uint16_t width;
        uint16_t height;
    } dimensions[] = {
        {0u, 1u},
        {1u, 0u},
    };
    uint8_t wire[32];

    for (size_t i = 0u; i < sizeof dimensions / sizeof dimensions[0]; i++) {
        eng_fixture f;
        fixture_init(&f, 1u, 1u);
        const size_t wire_length = build_single_rect_fbu(
            wire, sizeof wire, 0u, 0u, dimensions[i].width,
            dimensions[i].height, RFB_ENCODING_CURSOR, NULL, 0u);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, wire, wire_length), RFB_OK);
        rfb_server_engine_ctx ctx = fixture_ctx(&f);
        bool progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_ERR_PROTOCOL);
        RFB_CHECK(progress);
        fixture_destroy(&f);
    }
}

RFB_TEST(rfb_server_engine,
         process_in__zrle_and_mvs_envelopes__bound_then_decode)
{
    uint8_t wire[128];
    uint8_t after_header[80];
    bool progress = false;

    static const int32_t variable_encodings[] = {
        RFB_ENCODING_ZRLE,
        RFB_ENCODING_APPLE_MVS,
    };
    for (size_t i = 0u;
         i < sizeof variable_encodings / sizeof variable_encodings[0]; i++) {
        eng_fixture f;
        fixture_init(&f, 1u, 1u);
        const size_t wire_length = build_single_rect_fbu(
            wire, sizeof wire, 0u, 0u, 1u, 1u, variable_encodings[i],
            NULL, 0u);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, wire, wire_length), RFB_OK);
        rfb_server_engine_ctx ctx = fixture_ctx(&f);
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_OK);
        RFB_CHECK(progress);
        RFB_CHECK(f.eng.in_fbupdate);
        fixture_destroy(&f);

        fixture_init(&f, 1u, 1u);
        memset(after_header, 0xff, 4u);
        const size_t over_limit_length = build_single_rect_fbu(
            wire, sizeof wire, 0u, 0u, 1u, 1u, variable_encodings[i],
            after_header, 4u);
        RFB_CHECK_EQ_INT(
            rfb_buffer_append(&f.in, wire, over_limit_length), RFB_OK);
        ctx = fixture_ctx(&f);
        progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_ERR_LIMIT);
        fixture_destroy(&f);
    }

    {
        static const uint8_t tile[] = {1u, 0u, 0u, 0xffu};
        uLongf compressed_length = sizeof after_header - 4u;
        RFB_CHECK_EQ_INT(compress2(after_header + 4u, &compressed_length,
                                   tile, sizeof tile,
                                   Z_DEFAULT_COMPRESSION), Z_OK);
        after_header[0] = (uint8_t)(compressed_length >> 24u);
        after_header[1] = (uint8_t)(compressed_length >> 16u);
        after_header[2] = (uint8_t)(compressed_length >> 8u);
        after_header[3] = (uint8_t)compressed_length;
        const size_t wire_length = build_single_rect_fbu(
            wire, sizeof wire, 0u, 0u, 1u, 1u, RFB_ENCODING_ZRLE,
            after_header, 4u + (size_t)compressed_length);

        eng_fixture f;
        fixture_init(&f, 1u, 1u);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, wire, wire_length), RFB_OK);
        rfb_server_engine_ctx ctx = fixture_ctx(&f);
        progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_ERR_INTERNAL);
        fixture_destroy(&f);

        fixture_init(&f, 1u, 1u);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, wire, wire_length), RFB_OK);
        ctx = fixture_ctx(&f);
        ctx.zstream = rfb_zlib_create();
        RFB_CHECK(ctx.zstream != NULL);
        progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_OK);
        RFB_CHECK(progress);
        RFB_CHECK_EQ_UINT(f.publish_count, 1u);
        rfb_zlib_destroy(ctx.zstream);
        fixture_destroy(&f);
    }

    {
        static const uint8_t black_mvs[] = {
            0x00u, 0x03u, 0x05u, 0x00u, 0x00u, 0x0bu, 0x41u, 0xffu,
            0x72u, 0xfbu, 0x68u, 0x00u, 0x20u, 0x81u, 0xb4u,
        };
        after_header[0] = 0u;
        after_header[1] = 0u;
        after_header[2] = 0u;
        after_header[3] = (uint8_t)sizeof black_mvs;
        memcpy(after_header + 4u, black_mvs, sizeof black_mvs);
        const size_t wire_length = build_single_rect_fbu(
            wire, sizeof wire, 0u, 0u, 32u, 16u,
            RFB_ENCODING_APPLE_MVS, after_header,
            4u + sizeof black_mvs);

        eng_fixture f;
        fixture_init(&f, 32u, 16u);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, wire, wire_length), RFB_OK);
        rfb_server_engine_ctx ctx = fixture_ctx(&f);
        progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_OK);
        RFB_CHECK(progress);
        RFB_CHECK_EQ_UINT(f.publish_count, 1u);
        const uint8_t *pixel = rfb_framebuffer_pixel_c(&f.fb, 0u, 0u);
        RFB_CHECK_EQ_UINT(pixel[0], 0u);
        RFB_CHECK_EQ_UINT(pixel[1], 0u);
        RFB_CHECK_EQ_UINT(pixel[2], 0u);
        fixture_destroy(&f);
    }
}

RFB_TEST(rfb_server_engine,
         process_in__optional_hooks_and_error_hooks__keep_exact_ownership)
{
    bool progress = false;

    {
        eng_fixture f;
        fixture_init(&f, 1u, 1u);
        f.fbu_begin_error = RFB_ERR_INTERNAL;
        RFB_CHECK_EQ_INT(rfb_buffer_append(
                             &f.in, k_fbu_1x1_red,
                             sizeof k_fbu_1x1_red), RFB_OK);
        rfb_server_engine_ctx ctx = fixture_ctx(&f);
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_ERR_INTERNAL);
        RFB_CHECK_EQ_UINT(f.fbu_begin_count, 1u);
        fixture_destroy(&f);
    }

    {
        static const uint8_t empty_fbu[] = {0u, 0u, 0u, 0u};
        eng_fixture f;
        fixture_init(&f, 1u, 1u);
        f.publish_error = RFB_ERR_INTERNAL;
        RFB_CHECK_EQ_INT(rfb_buffer_append(
                             &f.in, empty_fbu, sizeof empty_fbu), RFB_OK);
        rfb_server_engine_ctx ctx = fixture_ctx(&f);
        progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_ERR_INTERNAL);
        RFB_CHECK_EQ_UINT(f.publish_count, 1u);
        fixture_destroy(&f);

        fixture_init(&f, 1u, 1u);
        RFB_CHECK_EQ_INT(rfb_buffer_append(
                             &f.in, empty_fbu, sizeof empty_fbu), RFB_OK);
        ctx = fixture_ctx(&f);
        ctx.pacing = NULL;
        memset(&ctx.hooks, 0, sizeof ctx.hooks);
        progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_OK);
        RFB_CHECK(progress);
        fixture_destroy(&f);
    }

    {
        eng_fixture f;
        fixture_init(&f, 1u, 1u);
        f.rect_decoded_error = RFB_ERR_INTERNAL;
        RFB_CHECK_EQ_INT(rfb_buffer_append(
                             &f.in, k_fbu_1x1_red,
                             sizeof k_fbu_1x1_red), RFB_OK);
        rfb_server_engine_ctx ctx = fixture_ctx(&f);
        ctx.hooks.on_rect_decoded = fixture_on_rect_decoded;
        progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_ERR_INTERNAL);
        RFB_CHECK_EQ_UINT(f.rect_decoded_count, 1u);
        RFB_CHECK_EQ_UINT(f.publish_count, 0u);
        fixture_destroy(&f);

        fixture_init(&f, 1u, 1u);
        f.publish_error = RFB_ERR_INTERNAL;
        RFB_CHECK_EQ_INT(rfb_buffer_append(
                             &f.in, k_fbu_1x1_red,
                             sizeof k_fbu_1x1_red), RFB_OK);
        ctx = fixture_ctx(&f);
        progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_ERR_INTERNAL);
        RFB_CHECK_EQ_UINT(f.publish_count, 1u);
        fixture_destroy(&f);
    }

    {
        static const uint8_t bell_and_empty_cut[] = {
            2u,
            3u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
        };
        eng_fixture f;
        fixture_init(&f, 1u, 1u);
        RFB_CHECK_EQ_INT(rfb_buffer_append(
                             &f.in, bell_and_empty_cut,
                             sizeof bell_and_empty_cut), RFB_OK);
        rfb_server_engine_ctx ctx = fixture_ctx(&f);
        ctx.hooks.on_bell = NULL;
        ctx.hooks.on_cut_text = NULL;
        progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_OK);
        RFB_CHECK(progress);
        RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 0u);
        fixture_destroy(&f);
    }

    {
        uint8_t long_cut[8u + 257u];
        memset(long_cut, 'x', sizeof long_cut);
        long_cut[0] = 3u;
        long_cut[1] = 0u;
        long_cut[2] = 0u;
        long_cut[3] = 0u;
        long_cut[4] = 0u;
        long_cut[5] = 0u;
        long_cut[6] = 1u;
        long_cut[7] = 1u;
        eng_fixture f;
        fixture_init(&f, 1u, 1u);
        RFB_CHECK_EQ_INT(rfb_buffer_append(
                             &f.in, long_cut, sizeof long_cut), RFB_OK);
        rfb_server_engine_ctx ctx = fixture_ctx(&f);
        progress = false;
        RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                         RFB_OK);
        RFB_CHECK_EQ_UINT(f.cut_count, 1u);
        RFB_CHECK_EQ_UINT(f.cut_last_len, 257u);
        fixture_destroy(&f);
    }
}
