// SPDX-License-Identifier: Apache-2.0
//
// F4 — display scene + presenter v2 + v1 adapter tests (§11).
//
// Covers:
//   - pixel format byte sizes (positive + unknown negative);
//   - farsee_rect_within checked clipping (overflow-safe);
//   - farsee_surface_view_valid (positive + every negative: zero dim,
//     over-max, short stride, data_size mismatch, overflow);
//   - presenter v2 dispatch;
//   - v1 adapter equivalence: a BGRA8888 surface commit through the adapter
//     produces byte-identical dump output to a canonical RGBA8 framebuffer
//     fed directly to the v1 presenter (no visual change, §11.8).

#include "farsee/farsee_display.h"
#include "farsee/farsee_presenter_v2.h"
#include "farsee/presenter_v1_adapter.h"
#include "farsee/allocator.h"
#include "farsee/framebuffer.h"
#include "farsee/presenter.h"
#include "tests/test_framework/rfb_test.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// --- pixel format bytes ----------------------------------------------------

RFB_TEST(farsee_display, pixel_format_bytes__per_format)
{
    RFB_CHECK_EQ_UINT(farsee_pixel_format_bytes(FARSEE_PIXEL_RGBA8888), 4);
    RFB_CHECK_EQ_UINT(farsee_pixel_format_bytes(FARSEE_PIXEL_BGRA8888), 4);
    RFB_CHECK_EQ_UINT(farsee_pixel_format_bytes(FARSEE_PIXEL_RGBX8888), 4);
    RFB_CHECK_EQ_UINT(farsee_pixel_format_bytes(FARSEE_PIXEL_RGB888), 3);
}

// --- rect_within (checked clipping) ----------------------------------------

RFB_TEST(farsee_display, rect_within__clipping)
{
    farsee_rect r = {0, 0, 10, 10};
    RFB_CHECK(farsee_rect_within(&r, 10, 10));     // exact fit
    RFB_CHECK(farsee_rect_within(&r, 20, 20));     // fits in larger surface
    farsee_rect r2 = {5, 5, 5, 5};
    RFB_CHECK(farsee_rect_within(&r2, 10, 10));     // bottom-right corner fit
    RFB_CHECK(farsee_rect_within(&r2, 10, 9) == false);  // overflows height
    farsee_rect r3 = {8, 0, 5, 5};
    RFB_CHECK(farsee_rect_within(&r3, 10, 10) == false);  // 8+5 > 10, overflow-safe
    // Overflow that would wrap a naive x+width check.
    farsee_rect overflow = {0xFFFFFFFFu, 0, 1, 1};
    RFB_CHECK(farsee_rect_within(&overflow, 10, 10) == false);
    farsee_rect zero = {0, 0, 0, 5};
    RFB_CHECK(farsee_rect_within(&zero, 10, 10) == false);
}

// --- surface_view_valid (positive + negatives) -----------------------------

RFB_TEST(farsee_display, surface_view_valid__positives)
{
    uint8_t buf[4 * 4 * 4];  // 4x4 RGBA
    farsee_surface_view v = {
        .id = 1, .width = 4, .height = 4,
        .stride = 16, .format = FARSEE_PIXEL_RGBA8888,
        .data = buf, .data_size = sizeof(buf), .generation = 7,
    };
    RFB_CHECK(farsee_surface_view_valid(&v, 16384));

    // Padded stride is allowed if data_size matches stride*height.
    uint8_t pbuf[5 * 4 * 4];  // 4x4 with stride 20
    farsee_surface_view vp = {
        .width = 4, .height = 4, .stride = 20,
        .format = FARSEE_PIXEL_RGBA8888,
        .data = pbuf, .data_size = 5 * 4 * 4,
    };
    RFB_CHECK(farsee_surface_view_valid(&vp, 16384));
}

RFB_TEST(farsee_display, surface_view_valid__negatives)
{
    uint8_t buf[64];
    // zero width
    farsee_surface_view z = {.width = 0, .height = 4, .stride = 16,
        .format = FARSEE_PIXEL_RGBA8888, .data = buf, .data_size = 0};
    RFB_CHECK(farsee_surface_view_valid(&z, 16384) == false);
    // over max dimension
    farsee_surface_view big = {.width = 20000, .height = 4, .stride = 80000,
        .format = FARSEE_PIXEL_RGBA8888, .data = buf, .data_size = 0};
    RFB_CHECK(farsee_surface_view_valid(&big, 16384) == false);
    // stride too short
    farsee_surface_view ss = {.width = 4, .height = 4, .stride = 8,
        .format = FARSEE_PIXEL_RGBA8888, .data = buf, .data_size = 32};
    RFB_CHECK(farsee_surface_view_valid(&ss, 16384) == false);
    // data_size mismatch
    farsee_surface_view dm = {.width = 4, .height = 4, .stride = 16,
        .format = FARSEE_PIXEL_RGBA8888, .data = buf, .data_size = 99};
    RFB_CHECK(farsee_surface_view_valid(&dm, 16384) == false);
    // NULL data
    farsee_surface_view nd = {.width = 4, .height = 4, .stride = 16,
        .format = FARSEE_PIXEL_RGBA8888, .data = NULL, .data_size = 64};
    RFB_CHECK(farsee_surface_view_valid(&nd, 16384) == false);
}

// --- v1 adapter equivalence (the §11.8 exit criterion) ---------------------

// Build a 3x2 BGRA8888 surface: pixel (x,y) = (R=x*10, G=y*10, B=128, A=255).
// The expected canonical RGBA8 is (R=x*10, G=y*10, B=128, A=255).
static void fill_bgra(uint8_t *buf, uint32_t w, uint32_t h, size_t stride)
{
    for (uint32_t y = 0; y < h; ++y) {
        for (uint32_t x = 0; x < w; ++x) {
            uint8_t *p = buf + y * stride + x * 4;
            p[0] = 128;          // B
            p[1] = (uint8_t)(y * 10); // G
            p[2] = (uint8_t)(x * 10); // R
            p[3] = 255;          // A
        }
    }
}

RFB_TEST(farsee_presenter, v1_adapter__bgra_commit_matches_direct_rgba)
{
    enum { W = 3, H = 2 };
    uint8_t bgra[W * H * 4];
    fill_bgra(bgra, W, H, (size_t)W * 4);

    // --- Path A: BGRA surface -> v1 adapter -> dump presenter ---
    rfb_presenter_dump dump_a;
    rfb_presenter_dump_init(&dump_a, "/tmp/farsee_adapter_a.rgba", false);
    rfb_presenter v1_a = {.ops = &rfb_presenter_dump_ops, .ctx = &dump_a};

    farsee_presenter_v1_adapter adapter;
    farsee_presenter_v1_adapter_init(&adapter, v1_a, 64u * 1024u * 1024u);
    farsee_presenter *pv2 = (farsee_presenter *)&adapter;
    // Point the v2 ops at the adapter's table.
    pv2->ops = farsee_presenter_v1_adapter_ops();

    farsee_presenter_caps caps;
    RFB_CHECK(farsee_presenter_open(pv2, &caps).code == FARSEE_E_OK);
    RFB_CHECK(caps.accepts_rgba8888);

    farsee_surface_view sv = {
        .id = 1, .width = W, .height = H, .stride = (size_t)W * 4,
        .format = FARSEE_PIXEL_BGRA8888, .data = bgra,
        .data_size = sizeof(bgra), .generation = 1,
    };
    farsee_surface_update upd = {.view = sv, .damage = NULL, .damage_count = 0};
    farsee_frame_commit frame = {
        .frame_id = 1, .updates = &upd, .update_count = 1,
        .cursor = NULL, .complete_snapshot = true,
    };
    RFB_CHECK(farsee_presenter_present(pv2, &frame).code == FARSEE_E_OK);
    farsee_presenter_close(&pv2);
    RFB_CHECK(pv2 == NULL);

    // --- Path B: direct RGBA8 framebuffer -> v1 dump presenter ---
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK(rfb_framebuffer_resize(&fb, W, H, 64u * 1024u * 1024u) == RFB_OK);
    // Build the expected RGBA8 directly: (R=x*10, G=y*10, B=128, A=255).
    for (uint32_t y = 0; y < H; ++y) {
        for (uint32_t x = 0; x < W; ++x) {
            uint8_t *p = fb.rgba + y * fb.stride + x * 4;
            p[0] = (uint8_t)(x * 10);
            p[1] = (uint8_t)(y * 10);
            p[2] = 128;
            p[3] = 255;
        }
    }
    rfb_presenter_dump dump_b;
    rfb_presenter_dump_init(&dump_b, "/tmp/farsee_direct_b.rgba", false);
    rfb_presenter v1_b = {.ops = &rfb_presenter_dump_ops, .ctx = &dump_b};
    rfb_presenter_present(&v1_b, &fb, NULL);
    rfb_presenter_close(&v1_b);
    rfb_framebuffer_destroy(&fb);

    // --- Compare: the two dump files must be byte-identical ---
    FILE *fa = fopen("/tmp/farsee_adapter_a.rgba", "rb");
    FILE *fbf = fopen("/tmp/farsee_direct_b.rgba", "rb");
    RFB_CHECK_MSG(fa != NULL, "adapter dump missing");
    RFB_CHECK_MSG(fbf != NULL, "direct dump missing");
    size_t idx = 0;
    int ra, rb;
    bool match = true;
    while (1) {
        ra = fgetc(fa);
        rb = fgetc(fbf);
        if (ra != rb) { match = false; break; }
        if (ra == EOF) { break; }
        ++idx;
    }
    fclose(fa);
    fclose(fbf);
    RFB_CHECK_MSG(match, "adapter dump differs from direct at/around byte");
    RFB_CHECK_EQ_UINT(idx, (size_t)W * H * 4);
}

// --- adapter rejects invalid surface (fail closed) -------------------------

RFB_TEST(farsee_presenter, v1_adapter__rejects_invalid_surface)
{
    rfb_presenter v1 = {.ops = &rfb_presenter_null_ops, .ctx = NULL};
    farsee_presenter_v1_adapter adapter;
    farsee_presenter_v1_adapter_init(&adapter, v1, 64u * 1024u * 1024u);
    farsee_presenter *pv2 = (farsee_presenter *)&adapter;
    pv2->ops = farsee_presenter_v1_adapter_ops();
    farsee_presenter_caps caps;
    RFB_CHECK(farsee_presenter_open(pv2, &caps).code == FARSEE_E_OK);

    // Zero-width surface -> protocol violation, no presenter call.
    farsee_surface_view bad = {.width = 0, .height = 4, .stride = 0,
        .format = FARSEE_PIXEL_RGBA8888, .data = NULL, .data_size = 0};
    farsee_surface_update upd = {.view = bad};
    farsee_frame_commit frame = {.frame_id = 1, .updates = &upd, .update_count = 1};
    RFB_CHECK(farsee_presenter_present(pv2, &frame).code ==
              FARSEE_ERR_PROTOCOL_VIOLATION);
    farsee_presenter_close(&pv2);
}

// --- double-open rejected --------------------------------------------------

RFB_TEST(farsee_presenter, v1_adapter__double_open_rejected)
{
    rfb_presenter v1 = {.ops = &rfb_presenter_null_ops, .ctx = NULL};
    farsee_presenter_v1_adapter adapter;
    farsee_presenter_v1_adapter_init(&adapter, v1, 64u * 1024u * 1024u);
    farsee_presenter *pv2 = (farsee_presenter *)&adapter;
    pv2->ops = farsee_presenter_v1_adapter_ops();
    farsee_presenter_caps caps;
    RFB_CHECK(farsee_presenter_open(pv2, &caps).code == FARSEE_E_OK);
    RFB_CHECK(farsee_presenter_open(pv2, &caps).code == FARSEE_ERR_STATE);
    farsee_presenter_close(&pv2);
}

// --- caps advertise BGRA8888 (RDP software-GDI output path, §11.7) ----------
// The adapter converts BGRA->RGBA8 in copy_surface_to_scratch, so advertising
// accepts_bgra8888 is honest and lets the RDP engine publish BGRA frames
// directly without a pre-conversion copy.

RFB_TEST(farsee_presenter, v1_adapter__caps_advertise_bgra8888)
{
    rfb_presenter v1 = {.ops = &rfb_presenter_null_ops, .ctx = NULL};
    farsee_presenter_v1_adapter adapter;
    farsee_presenter_v1_adapter_init(&adapter, v1, 64u * 1024u * 1024u);
    farsee_presenter *pv2 = (farsee_presenter *)&adapter;
    pv2->ops = farsee_presenter_v1_adapter_ops();
    farsee_presenter_caps caps;
    RFB_CHECK(farsee_presenter_open(pv2, &caps).code == FARSEE_E_OK);
    RFB_CHECK(caps.accepts_rgba8888);
    RFB_CHECK(caps.accepts_bgra8888);
    farsee_presenter_close(&pv2);
}
