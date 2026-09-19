// SPDX-License-Identifier: Apache-2.0
//
// Rectangle dimension cap versus post-DesktopSize geometry.
//
// Content rectangles are bounded by the current framebuffer and byte budget.
// A wide DesktopSize resize followed by a full-width RAW rectangle decodes.

#include "rfb_test.h"
#include "farsee/rfb_server_engine.h"
#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/error.h"
#include "farsee/framebuffer.h"
#include "farsee/pacing.h"
#include "farsee/pixel_format.h"

#include <stdlib.h>
#include <string.h>

typedef struct wide_engine_fixture {
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
} wide_engine_fixture;

static void wide_engine_init(wide_engine_fixture *f, uint16_t w, uint16_t h)
{
    memset(f, 0, sizeof *f);
    f->alloc = rfb_default_allocator();
    rfb_server_engine_init(&f->eng);
    // Wide input window: a full-width RAW row on a 32768-wide desktop is
    // 128 KiB of payload.
    rfb_buffer_init(&f->in, f->alloc, 1u << 20);
    rfb_framebuffer_init(&f->fb, f->alloc);
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&f->fb, w, h, 8u << 20), RFB_OK);
    f->pf = rfb_pixel_format_canonical_request();
    memset(&f->cursor, 0, sizeof f->cursor);
    rfb_pacing_init(&f->pacing, 0);
    f->fb_w = w;
    f->fb_h = h;
}

static void wide_engine_destroy(wide_engine_fixture *f)
{
    rfb_cursor_destroy(&f->cursor, f->alloc);
    rfb_framebuffer_destroy(&f->fb);
    rfb_buffer_destroy(&f->in);
}

static rfb_server_engine_ctx wide_engine_ctx(wide_engine_fixture *f)
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
    return ctx;
}

// DesktopSize to 32768x8 (1 MiB framebuffer — well inside the resize byte
// budget), then a full-width RAW rect on the last row decodes.
RFB_TEST(rfb_engine_wide_desktopsize, desktopsize_32768_wide__full_width_raw_decodes)
{
    wide_engine_fixture f;
    wide_engine_init(&f, 4, 4);
    rfb_server_engine_ctx ctx = wide_engine_ctx(&f);

    // FBU with two rects: DesktopSize(-223) 32768x8, then RAW 32768x1 @y=7.
    const uint16_t wide = 32768u;
    uint8_t hdr[4u + 12u + 12u];
    size_t n = 0;
    hdr[n++] = 0x00; hdr[n++] = 0x00;              // type=0, pad
    hdr[n++] = 0x00; hdr[n++] = 0x02;              // nrects = 2
    // rect 1: DesktopSize
    hdr[n++] = 0x00; hdr[n++] = 0x00;              // x
    hdr[n++] = 0x00; hdr[n++] = 0x00;              // y
    hdr[n++] = (uint8_t)(wide >> 8); hdr[n++] = (uint8_t)wide;   // w
    hdr[n++] = 0x00; hdr[n++] = 0x08;              // h
    hdr[n++] = 0xFF; hdr[n++] = 0xFF; hdr[n++] = 0xFF; hdr[n++] = 0x21; // -223
    // rect 2: RAW full width, one row
    hdr[n++] = 0x00; hdr[n++] = 0x00;              // x
    hdr[n++] = 0x00; hdr[n++] = 0x07;              // y = 7
    hdr[n++] = (uint8_t)(wide >> 8); hdr[n++] = (uint8_t)wide;   // w
    hdr[n++] = 0x00; hdr[n++] = 0x01;              // h
    hdr[n++] = 0x00; hdr[n++] = 0x00; hdr[n++] = 0x00; hdr[n++] = 0x00; // Raw
    RFB_CHECK_EQ_UINT(n, sizeof hdr);

    const size_t payload = (size_t)wide * 4u;      // 32bpp canonical
    uint8_t *msg = (uint8_t *)malloc(n + payload);
    RFB_CHECK(msg != NULL);
    memcpy(msg, hdr, n);
    // All pixels red: canonical LE wire bytes 00 00 FF 00.
    for (size_t i = 0; i < wide; i++) {
        msg[n + i * 4u + 0u] = 0x00;
        msg[n + i * 4u + 1u] = 0x00;
        msg[n + i * 4u + 2u] = 0xFF;
        msg[n + i * 4u + 3u] = 0x00;
    }
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, msg, n + payload), RFB_OK);

    bool progress = false;
    // The 32768-pixel RAW rectangle is valid after the resize.
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress), RFB_OK);
    RFB_CHECK(progress);

    RFB_CHECK_EQ_UINT(f.fb_w, wide);
    RFB_CHECK_EQ_UINT(f.fb_h, 8u);
    RFB_CHECK_EQ_UINT(f.fb.width, (uint32_t)wide);
    RFB_CHECK_EQ_UINT(f.eng.rects_decoded, 2u);
    const uint8_t *first = rfb_framebuffer_pixel_c(&f.fb, 0, 7);
    const uint8_t *last = rfb_framebuffer_pixel_c(&f.fb, wide - 1u, 7);
    RFB_CHECK_EQ_UINT(first[0], 0xFFu);
    RFB_CHECK_EQ_UINT(first[3], 0xFFu);
    RFB_CHECK_EQ_UINT(last[0], 0xFFu);
    RFB_CHECK_EQ_UINT(last[3], 0xFFu);
    free(msg);
    wide_engine_destroy(&f);
}

// The absolute cap is gone, but hostile geometry still fails closed: a
// rect outside the (post-resize) framebuffer bounds is rejected before
// any payload wait.
RFB_TEST(rfb_engine_wide_desktopsize, wide_geometry__out_of_bounds_rect_still_rejected)
{
    wide_engine_fixture f;
    wide_engine_init(&f, 4, 4);
    rfb_server_engine_ctx ctx = wide_engine_ctx(&f);

    static const uint8_t msg[] = {
        0x00, 0x00,             // type=0, pad
        0x00, 0x01,             // nrects = 1
        0x00, 0x00, 0x00, 0x00, // x, y
        0x80, 0x00,             // w = 32768 (fb is 4 wide)
        0x00, 0x01,             // h = 1
        0x00, 0x00, 0x00, 0x00, // Raw
    };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, msg, sizeof msg), RFB_OK);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_server_engine_process_in(&ctx, &progress),
                     RFB_ERR_PROTOCOL);
    wide_engine_destroy(&f);
}
