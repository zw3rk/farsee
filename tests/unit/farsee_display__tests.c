// SPDX-License-Identifier: Apache-2.0
//
// Display-scene, presenter-v2, and v1-adapter unit tests.
//
// Covers pixel-format sizes, selected rectangle and surface-validation cases,
// presenter v2 dispatch, and v1-adapter behavior. The adapter comparison uses
// one 3x2 BGRA sample and checks captured bytes against direct canonical RGBA.

#include "farsee/farsee_display.h"
#include "farsee/farsee_presenter_v2.h"
#include "farsee/presenter_v1_adapter.h"
#include "farsee/allocator.h"
#include "farsee/damage.h"
#include "farsee/framebuffer.h"
#include "farsee/memory_budget.h"
#include "farsee/presenter.h"
#include "tests/test_framework/rfb_test.h"
#include "tests/test_framework/memory_presenter.h"
#include <stdint.h>
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

// --- v1 adapter BGRA-to-RGBA equivalence -------------------------------

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
    uint8_t adapter_pixels[W * H * 4];
    uint8_t direct_pixels[W * H * 4];
    fill_bgra(bgra, W, H, (size_t)W * 4);

    rfb_test_memory_presenter memory_a;
    rfb_test_memory_presenter_init(
        &memory_a, adapter_pixels, sizeof adapter_pixels);
    rfb_presenter v1_a = {
        .ops = &rfb_test_memory_presenter_ops,
        .ctx = &memory_a,
    };

    farsee_presenter_v1_adapter adapter;
    farsee_presenter_v1_adapter_init(&adapter, v1_a, 64u * 1024u * 1024u);
    farsee_presenter *pv2 = (farsee_presenter *)&adapter;
    pv2->ops = farsee_presenter_v1_adapter_ops();

    farsee_presenter_caps caps;
    RFB_CHECK(farsee_presenter_open(pv2, &caps).code == FARSEE_E_OK);
    RFB_CHECK(caps.accepts_rgba8888);

    farsee_surface_view sv = {
        .id = 1, .width = W, .height = H, .stride = (size_t)W * 4,
        .format = FARSEE_PIXEL_BGRA8888, .data = bgra,
        .data_size = sizeof bgra, .generation = 1,
    };
    farsee_surface_update upd = {
        .view = sv,
        .damage = NULL,
        .damage_count = 0,
    };
    farsee_frame_commit frame = {
        .frame_id = 1,
        .updates = &upd,
        .update_count = 1,
        .cursor = NULL,
        .complete_snapshot = true,
    };
    RFB_CHECK(farsee_presenter_present(pv2, &frame).code == FARSEE_E_OK);
    farsee_presenter_close(&pv2);
    RFB_CHECK(pv2 == NULL);

    rfb_framebuffer framebuffer;
    rfb_framebuffer_init(&framebuffer, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(
                         &framebuffer, W, H, 64u * 1024u * 1024u),
                     RFB_OK);
    for (uint32_t y = 0; y < H; ++y) {
        for (uint32_t x = 0; x < W; ++x) {
            uint8_t *pixel =
                framebuffer.rgba + y * framebuffer.stride + x * 4u;
            pixel[0] = (uint8_t)(x * 10u);
            pixel[1] = (uint8_t)(y * 10u);
            pixel[2] = 128u;
            pixel[3] = 255u;
        }
    }
    rfb_test_memory_presenter memory_b;
    rfb_test_memory_presenter_init(
        &memory_b, direct_pixels, sizeof direct_pixels);
    rfb_presenter v1_b = {
        .ops = &rfb_test_memory_presenter_ops,
        .ctx = &memory_b,
    };
    RFB_CHECK_EQ_INT(rfb_presenter_open(&v1_b, &framebuffer), 0);
    RFB_CHECK_EQ_INT(rfb_presenter_present(&v1_b, &framebuffer, NULL), 0);
    rfb_presenter_close(&v1_b);
    rfb_framebuffer_destroy(&framebuffer);

    RFB_CHECK_EQ_UINT(memory_a.open_count, 1u);
    RFB_CHECK_EQ_UINT(memory_a.present_count, 1u);
    RFB_CHECK_EQ_UINT(memory_a.close_count, 1u);
    RFB_CHECK_EQ_UINT(memory_b.open_count, 1u);
    RFB_CHECK_EQ_UINT(memory_b.present_count, 1u);
    RFB_CHECK_EQ_UINT(memory_b.close_count, 1u);
    RFB_CHECK_EQ_UINT(memory_a.size, (size_t)W * H * 4u);
    RFB_CHECK_EQ_UINT(memory_b.size, memory_a.size);
    RFB_CHECK_MEM_EQ(adapter_pixels, direct_pixels, memory_a.size);
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

// --- caps advertise the adapter's BGRA8888 conversion support ---------------
// This test checks the capability bit; copy_surface_to_scratch performs the
// BGRA-to-RGBA conversion when such a view is presented.

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

typedef struct damage_capture {
    bool called;
    rfb_rect rect;
    size_t count;
    bool full_frame;
} damage_capture;

static int damage_capture_present(void *ctx, const rfb_framebuffer *fb,
                                  const rfb_damage_batch *damage)
{
    damage_capture *capture = (damage_capture *)ctx;
    (void)fb;
    capture->called = true;
    capture->count = damage != NULL ? damage->count : 0u;
    capture->full_frame = damage != NULL && damage->full_frame;
    if (damage != NULL && damage->count == 1u && damage->rects != NULL) {
        capture->rect = damage->rects[0];
    }
    return 0;
}

static const rfb_presenter_ops DAMAGE_CAPTURE_OPS = {
    .present = damage_capture_present,
};

static void init_adapter_frame(farsee_presenter_v1_adapter *adapter,
                               farsee_presenter **presenter_out,
                               damage_capture *capture,
                               farsee_surface_update *update_out,
                               farsee_frame_commit *frame_out,
                               uint8_t pixels[16])
{
    rfb_presenter v1 = { .ops = &DAMAGE_CAPTURE_OPS, .ctx = capture };
    farsee_presenter_v1_adapter_init(adapter, v1, 1u << 20);
    *presenter_out = (farsee_presenter *)adapter;
    (*presenter_out)->ops = farsee_presenter_v1_adapter_ops();
    *update_out = (farsee_surface_update){
        .view = {
            .width = 2u, .height = 2u, .stride = 8u,
            .format = FARSEE_PIXEL_RGBA8888, .data = pixels,
            .data_size = 16u, .generation = 1u,
        },
    };
    *frame_out = (farsee_frame_commit){
        .frame_id = 1u, .updates = update_out, .update_count = 1u,
    };
}

RFB_TEST(farsee_presenter, v1_adapter_allocator_observes_scratch_budget)
{
    rfb_presenter_null nul;
    rfb_presenter_null_init(&nul);
    rfb_presenter v1 = {
        .ops = &rfb_presenter_null_ops,
        .ctx = &nul,
    };

    farsee_memory_budget too_small;
    RFB_CHECK(farsee_memory_budget_init(&too_small, rfb_default_allocator(),
                                        3u));
    farsee_presenter_v1_adapter adapter;
    farsee_presenter_v1_adapter_init_with_allocator(
        &adapter, v1, 1024u, farsee_memory_budget_allocator(&too_small));
    farsee_presenter *presenter = (farsee_presenter *)&adapter;
    presenter->ops = farsee_presenter_v1_adapter_ops();
    RFB_CHECK(farsee_presenter_open(presenter, NULL).code ==
              FARSEE_ERR_OUT_OF_MEMORY);
    farsee_presenter_close(&presenter);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&too_small), 0u);

    farsee_memory_budget exact;
    RFB_CHECK(farsee_memory_budget_init(&exact, rfb_default_allocator(), 4u));
    farsee_presenter_v1_adapter_init_with_allocator(
        &adapter, v1, 1024u, farsee_memory_budget_allocator(&exact));
    presenter = (farsee_presenter *)&adapter;
    presenter->ops = farsee_presenter_v1_adapter_ops();
    RFB_CHECK(farsee_presenter_open(presenter, NULL).code == FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&exact), 4u);
    farsee_presenter_close(&presenter);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&exact), 0u);
}

RFB_TEST(farsee_presenter, v1_adapter__rejects_missing_or_multiple_updates)
{
    uint8_t pixels[16] = { 0 };
    damage_capture capture = { 0 };
    farsee_presenter_v1_adapter adapter;
    farsee_presenter *presenter = NULL;
    farsee_surface_update update;
    farsee_frame_commit frame;
    init_adapter_frame(&adapter, &presenter, &capture, &update, &frame, pixels);
    RFB_CHECK(farsee_presenter_open(presenter, NULL).code == FARSEE_E_OK);

    frame.updates = NULL;
    RFB_CHECK(farsee_presenter_present(presenter, &frame).code ==
              FARSEE_ERR_PROTOCOL_VIOLATION);
    frame.updates = &update;
    frame.update_count = 2u;
    RFB_CHECK(farsee_presenter_present(presenter, &frame).code ==
              FARSEE_ERR_PROTOCOL_VIOLATION);
    RFB_CHECK(!capture.called);
    farsee_presenter_close(&presenter);
}

RFB_TEST(farsee_presenter, v1_adapter__damage_is_validated_and_copied)
{
    uint8_t pixels[16] = { 0 };
    damage_capture capture = { 0 };
    farsee_presenter_v1_adapter adapter;
    farsee_presenter *presenter = NULL;
    farsee_surface_update update;
    farsee_frame_commit frame;
    init_adapter_frame(&adapter, &presenter, &capture, &update, &frame, pixels);
    RFB_CHECK(farsee_presenter_open(presenter, NULL).code == FARSEE_E_OK);

    update.damage_count = 1u;
    update.damage = NULL;
    RFB_CHECK(farsee_presenter_present(presenter, &frame).code ==
              FARSEE_ERR_PROTOCOL_VIOLATION);
    farsee_rect bad = { .x = 1u, .y = 1u, .width = 2u, .height = 1u };
    update.damage = &bad;
    RFB_CHECK(farsee_presenter_present(presenter, &frame).code ==
              FARSEE_ERR_PROTOCOL_VIOLATION);
    RFB_CHECK(!capture.called);

    farsee_rect good = { .x = 1u, .y = 0u, .width = 1u, .height = 2u };
    update.damage = &good;
    RFB_CHECK(farsee_presenter_present(presenter, &frame).code == FARSEE_E_OK);
    RFB_CHECK(capture.called);
    RFB_CHECK_EQ_UINT(capture.count, 1u);
    RFB_CHECK(!capture.full_frame);
    RFB_CHECK_EQ_UINT(capture.rect.x, good.x);
    RFB_CHECK_EQ_UINT(capture.rect.y, good.y);
    RFB_CHECK_EQ_UINT(capture.rect.width, good.width);
    RFB_CHECK_EQ_UINT(capture.rect.height, good.height);
    farsee_presenter_close(&presenter);
}

typedef struct adapter_v1_probe {
    int open_result;
    int resize_result;
    int present_result;
    unsigned open_count;
    unsigned resize_count;
    unsigned present_count;
    unsigned close_count;
} adapter_v1_probe;

static int adapter_probe_open(void *ctx, const rfb_framebuffer *framebuffer)
{
    adapter_v1_probe *probe = (adapter_v1_probe *)ctx;
    probe->open_count++;
    RFB_CHECK(framebuffer != NULL);
    return probe->open_result;
}

static int adapter_probe_resize(void *ctx, const rfb_framebuffer *framebuffer)
{
    adapter_v1_probe *probe = (adapter_v1_probe *)ctx;
    probe->resize_count++;
    RFB_CHECK(framebuffer != NULL);
    return probe->resize_result;
}

static int adapter_probe_present(void *ctx, const rfb_framebuffer *framebuffer,
                                 const rfb_damage_batch *damage)
{
    adapter_v1_probe *probe = (adapter_v1_probe *)ctx;
    probe->present_count++;
    RFB_CHECK(framebuffer != NULL);
    (void)damage;
    return probe->present_result;
}

static void adapter_probe_close(void *ctx)
{
    adapter_v1_probe *probe = (adapter_v1_probe *)ctx;
    probe->close_count++;
}

static const rfb_presenter_ops ADAPTER_PROBE_OPS = {
    .open = adapter_probe_open,
    .resize = adapter_probe_resize,
    .present = adapter_probe_present,
    .close = adapter_probe_close,
};

static void adapter_make_single_update(farsee_surface_update *update,
                                       farsee_frame_commit *frame,
                                       const uint8_t *pixels,
                                       uint32_t width, uint32_t height,
                                       size_t stride, size_t data_size,
                                       farsee_pixel_format_kind format)
{
    *update = (farsee_surface_update){
        .view = {
            .width = width,
            .height = height,
            .stride = stride,
            .format = format,
            .data = pixels,
            .data_size = data_size,
            .generation = 7u,
        },
    };
    *frame = (farsee_frame_commit){
        .frame_id = 9u,
        .updates = update,
        .update_count = 1u,
        .complete_snapshot = true,
    };
}

RFB_TEST(farsee_presenter, v1_adapter__converts_all_opaque_rgb_formats)
{
    static const struct {
        farsee_pixel_format_kind format;
        size_t stride;
        size_t data_size;
        uint8_t source[8];
        uint8_t expected[8];
    } cases[] = {
        {
            .format = FARSEE_PIXEL_RGBX8888,
            .stride = 8u,
            .data_size = 8u,
            .source = {1u, 2u, 3u, 0u, 4u, 5u, 6u, 0u},
            .expected = {1u, 2u, 3u, 255u, 4u, 5u, 6u, 255u},
        },
        {
            .format = FARSEE_PIXEL_BGRX8888,
            .stride = 8u,
            .data_size = 8u,
            .source = {3u, 2u, 1u, 0u, 6u, 5u, 4u, 0u},
            .expected = {1u, 2u, 3u, 255u, 4u, 5u, 6u, 255u},
        },
        {
            .format = FARSEE_PIXEL_RGB888,
            .stride = 6u,
            .data_size = 6u,
            .source = {1u, 2u, 3u, 4u, 5u, 6u, 0u, 0u},
            .expected = {1u, 2u, 3u, 255u, 4u, 5u, 6u, 255u},
        },
    };

    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        uint8_t output_pixels[8] = { 0 };
        rfb_test_memory_presenter memory;
        rfb_test_memory_presenter_init(
            &memory, output_pixels, sizeof output_pixels);
        rfb_presenter v1 = {
            .ops = &rfb_test_memory_presenter_ops,
            .ctx = &memory,
        };
        farsee_presenter_v1_adapter adapter;
        farsee_presenter_v1_adapter_init(&adapter, v1, 64u);
        farsee_presenter *presenter = (farsee_presenter *)&adapter;
        presenter->ops = farsee_presenter_v1_adapter_ops();
        RFB_CHECK(farsee_presenter_open(presenter, NULL).code == FARSEE_E_OK);

        farsee_surface_update update;
        farsee_frame_commit frame;
        adapter_make_single_update(
            &update, &frame, cases[i].source, 2u, 1u, cases[i].stride,
            cases[i].data_size, cases[i].format);
        RFB_CHECK(farsee_presenter_present(presenter, &frame).code ==
                  FARSEE_E_OK);
        RFB_CHECK_MEM_EQ(output_pixels, cases[i].expected,
                         sizeof output_pixels);
        farsee_presenter_close(&presenter);
    }
}

RFB_TEST(farsee_presenter, v1_adapter__wrapped_failures_propagate)
{
    uint8_t pixels[16] = { 0 };
    farsee_surface_update update;
    farsee_frame_commit frame;
    adapter_make_single_update(
        &update, &frame, pixels, 2u, 2u, 8u, sizeof pixels,
        FARSEE_PIXEL_RGBA8888);

    {
        adapter_v1_probe probe = { .open_result = -1 };
        rfb_presenter v1 = { .ops = &ADAPTER_PROBE_OPS, .ctx = &probe };
        farsee_presenter_v1_adapter adapter;
        farsee_presenter_v1_adapter_init(&adapter, v1, 64u);
        farsee_presenter *presenter = (farsee_presenter *)&adapter;
        presenter->ops = farsee_presenter_v1_adapter_ops();
        RFB_CHECK(farsee_presenter_open(presenter, NULL).code ==
                  FARSEE_ERR_PRESENTER_FAILURE);
        RFB_CHECK_EQ_UINT(probe.open_count, 1u);
        farsee_presenter_close(&presenter);
        RFB_CHECK_EQ_UINT(probe.close_count, 0u);
    }

    {
        adapter_v1_probe probe = { .resize_result = -1 };
        rfb_presenter v1 = { .ops = &ADAPTER_PROBE_OPS, .ctx = &probe };
        farsee_presenter_v1_adapter adapter;
        farsee_presenter_v1_adapter_init(&adapter, v1, 64u);
        farsee_presenter *presenter = (farsee_presenter *)&adapter;
        presenter->ops = farsee_presenter_v1_adapter_ops();
        RFB_CHECK(farsee_presenter_open(presenter, NULL).code == FARSEE_E_OK);
        RFB_CHECK(farsee_presenter_present(presenter, &frame).code ==
                  FARSEE_ERR_PRESENTER_FAILURE);
        RFB_CHECK_EQ_UINT(probe.resize_count, 1u);
        RFB_CHECK_EQ_UINT(probe.present_count, 0u);
        farsee_presenter_close(&presenter);
        RFB_CHECK_EQ_UINT(probe.close_count, 1u);
    }

    {
        adapter_v1_probe probe = { .present_result = -1 };
        rfb_presenter v1 = { .ops = &ADAPTER_PROBE_OPS, .ctx = &probe };
        farsee_presenter_v1_adapter adapter;
        farsee_presenter_v1_adapter_init(&adapter, v1, 64u);
        farsee_presenter *presenter = (farsee_presenter *)&adapter;
        presenter->ops = farsee_presenter_v1_adapter_ops();
        RFB_CHECK(farsee_presenter_open(presenter, NULL).code == FARSEE_E_OK);
        RFB_CHECK(farsee_presenter_present(presenter, &frame).code ==
                  FARSEE_ERR_PRESENTER_FAILURE);
        RFB_CHECK_EQ_UINT(probe.present_count, 1u);
        farsee_presenter_close(&presenter);
    }

    {
        adapter_v1_probe probe = { 0 };
        rfb_presenter v1 = { .ops = &ADAPTER_PROBE_OPS, .ctx = &probe };
        farsee_presenter_v1_adapter adapter;
        farsee_presenter_v1_adapter_init(&adapter, v1, 4u);
        farsee_presenter *presenter = (farsee_presenter *)&adapter;
        presenter->ops = farsee_presenter_v1_adapter_ops();
        RFB_CHECK(farsee_presenter_open(presenter, NULL).code == FARSEE_E_OK);
        RFB_CHECK(farsee_presenter_present(presenter, &frame).code ==
                  FARSEE_ERR_RESOURCE_LIMIT);
        RFB_CHECK_EQ_UINT(probe.resize_count, 0u);
        farsee_presenter_close(&presenter);
    }
}

RFB_TEST(farsee_presenter, v1_adapter__state_damage_and_init_guards)
{
    rfb_presenter_null null_presenter;
    rfb_presenter_null_init(&null_presenter);
    const rfb_presenter v1 = {
        .ops = &rfb_presenter_null_ops,
        .ctx = &null_presenter,
    };
    farsee_presenter_v1_adapter adapter;
    farsee_presenter_v1_adapter_init(&adapter, v1, 0u);
    RFB_CHECK_EQ_UINT(adapter.byte_limit, 256u * 1024u * 1024u);
    farsee_presenter *presenter = (farsee_presenter *)&adapter;
    presenter->ops = farsee_presenter_v1_adapter_ops();

    uint8_t pixels[4] = { 0 };
    farsee_surface_update update;
    farsee_frame_commit frame;
    adapter_make_single_update(
        &update, &frame, pixels, 1u, 1u, 4u, sizeof pixels,
        FARSEE_PIXEL_RGBA8888);
    RFB_CHECK(farsee_presenter_present(presenter, &frame).code ==
              FARSEE_ERR_STATE);
    RFB_CHECK(farsee_presenter_open(presenter, NULL).code == FARSEE_E_OK);
    RFB_CHECK(farsee_presenter_present(presenter, NULL).code ==
              FARSEE_ERR_STATE);
    frame.update_count = 0u;
    RFB_CHECK(farsee_presenter_present(presenter, &frame).code ==
              FARSEE_ERR_STATE);
    frame.update_count = 1u;
    farsee_rect damage = { .x = 0u, .y = 0u, .width = 1u, .height = 1u };
    update.damage = &damage;
    update.damage_count = RFB_DAMAGE_MAX_RECTS + 1u;
    RFB_CHECK(farsee_presenter_present(presenter, &frame).code ==
              FARSEE_ERR_PROTOCOL_VIOLATION);
    farsee_presenter_close(&presenter);

    farsee_presenter *none = NULL;
    farsee_presenter_v1_adapter_ops()->close(NULL);
    farsee_presenter_v1_adapter_ops()->close(&none);
    farsee_presenter_v1_adapter_init_with_allocator(
        NULL, v1, 1u, rfb_default_allocator());
    farsee_presenter_v1_adapter_init_with_allocator(
        &adapter, v1, 1u, NULL);
    rfb_allocator invalid = { 0 };
    farsee_presenter_v1_adapter_init_with_allocator(
        &adapter, v1, 1u, &invalid);
    invalid.alloc = rfb_default_allocator()->alloc;
    farsee_presenter_v1_adapter_init_with_allocator(
        &adapter, v1, 1u, &invalid);
}
