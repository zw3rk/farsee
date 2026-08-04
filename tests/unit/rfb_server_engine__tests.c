// SPDX-License-Identifier: Apache-2.0
//
// Pure rfb_server_engine demux/decode tests (Q3 extract).
// No fd, no getenv. Synthetic FBU + Bell vectors only.

#include "rfb_test.h"
#include "farsee/rfb_server_engine.h"
#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/error.h"
#include "farsee/framebuffer.h"
#include "farsee/pacing.h"
#include "farsee/pixel_format.h"

#include <string.h>

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
} eng_fixture;

static void fixture_on_publish(void *ctx)
{
    eng_fixture *f = (eng_fixture *)ctx;
    f->publish_count++;
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

static void fixture_on_fbu_begin(void *ctx, uint16_t nrects)
{
    eng_fixture *f = (eng_fixture *)ctx;
    f->fbu_begin_count++;
    f->fbu_last_nrects = nrects;
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

// full2 T8: huge RAW rect header rejected before multi-MiB wait.
// full2 T8: out-of-bounds RAW rect rejected before multi-MiB wait.
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

