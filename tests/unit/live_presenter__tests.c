// SPDX-License-Identifier: Apache-2.0
//
// Shared live-presenter selection, construction, and ownership tests.

#include "rfb_test.h"

#include "app/live_presenter.h"
#include "farsee/allocator.h"
#include "farsee/framebuffer.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct presenter_fault_allocator {
    size_t calls;
    size_t frees;
    size_t fail_at;
} presenter_fault_allocator;

static void *presenter_fault_alloc(rfb_allocator *allocator, size_t size)
{
    presenter_fault_allocator *fault =
        (presenter_fault_allocator *)allocator->user;
    fault->calls++;
    if (fault->fail_at != 0u && fault->calls == fault->fail_at) {
        return NULL;
    }
    return malloc(size);
}

static void presenter_fault_free(rfb_allocator *allocator, void *ptr)
{
    presenter_fault_allocator *fault =
        (presenter_fault_allocator *)allocator->user;
    if (ptr != NULL) {
        fault->frees++;
    }
    free(ptr);
}

RFB_TEST(live_presenter, selection__preserves_protocol_name_table)
{
    typedef struct select_case {
        farsee_live_presenter_protocol protocol;
        const char *name;
        bool tty;
        farsee_live_presenter_kind expected;
    } select_case;
    const select_case cases[] = {
        {FARSEE_LIVE_PRESENTER_RFB, NULL, false,
         FARSEE_LIVE_PRESENTER_NULL},
        {FARSEE_LIVE_PRESENTER_RFB, "auto", true,
         FARSEE_LIVE_PRESENTER_KITTY_SHM},
        {FARSEE_LIVE_PRESENTER_RFB, "null", true,
         FARSEE_LIVE_PRESENTER_NULL},
        {FARSEE_LIVE_PRESENTER_RFB, "kitty", false,
         FARSEE_LIVE_PRESENTER_KITTY_DIRECT},
        {FARSEE_LIVE_PRESENTER_RFB, "kitty-direct", false,
         FARSEE_LIVE_PRESENTER_KITTY_DIRECT},
        {FARSEE_LIVE_PRESENTER_RFB, "kitty-shm", false,
         FARSEE_LIVE_PRESENTER_KITTY_SHM},
        {FARSEE_LIVE_PRESENTER_RFB, "unknown", true,
         FARSEE_LIVE_PRESENTER_KITTY_SHM},
        {FARSEE_LIVE_PRESENTER_RFB, "unknown", false,
         FARSEE_LIVE_PRESENTER_NULL},
        {FARSEE_LIVE_PRESENTER_RDP, NULL, false,
         FARSEE_LIVE_PRESENTER_NULL},
        {FARSEE_LIVE_PRESENTER_RDP, "auto", true,
         FARSEE_LIVE_PRESENTER_KITTY_SHM},
        {FARSEE_LIVE_PRESENTER_RDP, "null", true,
         FARSEE_LIVE_PRESENTER_NULL},
        {FARSEE_LIVE_PRESENTER_RDP, "kitty", false,
         FARSEE_LIVE_PRESENTER_KITTY_SHM},
        {FARSEE_LIVE_PRESENTER_RDP, "kitty-shm", false,
         FARSEE_LIVE_PRESENTER_KITTY_SHM},
        {FARSEE_LIVE_PRESENTER_RDP, "kitty-direct", false,
         FARSEE_LIVE_PRESENTER_KITTY_DIRECT},
        {FARSEE_LIVE_PRESENTER_RDP, "unknown", true,
         FARSEE_LIVE_PRESENTER_NULL},
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        RFB_CHECK(farsee_live_presenter_select(
                      cases[i].protocol, cases[i].name, cases[i].tty) ==
                  cases[i].expected);
    }
}

RFB_TEST(live_presenter, rfb_kitty__is_lazy_direct_and_uses_fixed_limits)
{
    farsee_live_presenter owner;
    memset(&owner, 0, sizeof owner);
    RFB_CHECK_EQ_INT(
        farsee_live_presenter_init(
            &owner, FARSEE_LIVE_PRESENTER_RFB, "kitty", false, 1920u,
            1080u, rfb_default_allocator()),
        FARSEE_LIVE_PRESENTER_INIT_OK);
    RFB_CHECK(farsee_live_presenter_is_kitty(&owner));
    RFB_CHECK(!owner.v1_opened);
    RFB_CHECK_EQ_UINT(owner.kitty.tile_edge, 8192u);
    RFB_CHECK(!owner.kitty.use_shm);
    RFB_CHECK_EQ_UINT(owner.kitty_out.hard_limit, 64u * 1024u * 1024u);
    farsee_live_presenter_destroy(&owner);
}

RFB_TEST(live_presenter, rdp_kitty__is_eager_shm_through_v2_adapter)
{
    farsee_live_presenter owner;
    memset(&owner, 0, sizeof owner);
    RFB_CHECK_EQ_INT(
        farsee_live_presenter_init(
            &owner, FARSEE_LIVE_PRESENTER_RDP, "kitty", false, 32u, 40u,
            rfb_default_allocator()),
        FARSEE_LIVE_PRESENTER_INIT_OK);
    RFB_CHECK(farsee_live_presenter_is_kitty(&owner));
    RFB_CHECK(owner.v2_opened);
    RFB_CHECK(owner.v1_opened);
    RFB_CHECK(owner.kitty.use_shm);
    RFB_CHECK_EQ_UINT(owner.kitty.tile_edge, 64u);
    RFB_CHECK_EQ_UINT(owner.kitty.fb_width, 1u);
    RFB_CHECK_EQ_UINT(owner.kitty.fb_height, 1u);
    RFB_CHECK(farsee_live_presenter_v2(&owner) != NULL);
    farsee_live_presenter_close(&owner);
    static const uint8_t expected_close[] = "\033_Ga=d,d=I,i=1\033\\";
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&owner.kitty_out),
                      sizeof expected_close - 1u);
    RFB_CHECK(memcmp(rfb_buffer_data(&owner.kitty_out), expected_close,
                     sizeof expected_close - 1u) == 0);
    farsee_live_presenter_destroy(&owner);
}

RFB_TEST(live_presenter, rdp_tile_edge__uses_larger_initial_dimension)
{
    farsee_live_presenter owner;
    memset(&owner, 0, sizeof owner);
    RFB_CHECK_EQ_INT(
        farsee_live_presenter_init(
            &owner, FARSEE_LIVE_PRESENTER_RDP, "kitty-direct", false,
            1280u, 800u, rfb_default_allocator()),
        FARSEE_LIVE_PRESENTER_INIT_OK);
    RFB_CHECK_EQ_UINT(owner.kitty.tile_edge, 1280u);
    RFB_CHECK(!owner.kitty.use_shm);
    farsee_live_presenter_destroy(&owner);
}

RFB_TEST(live_presenter, rdp_present__uses_v2_adapter_and_queues_kitty)
{
    farsee_live_presenter owner;
    memset(&owner, 0, sizeof owner);
    RFB_CHECK_EQ_INT(
        farsee_live_presenter_init(
            &owner, FARSEE_LIVE_PRESENTER_RDP, "kitty-direct", false, 1u,
            1u, rfb_default_allocator()),
        FARSEE_LIVE_PRESENTER_INIT_OK);

    const uint8_t bgra[] = {0x30u, 0x20u, 0x10u, 0xffu};
    const farsee_surface_view view = {
        .id = 1u,
        .width = 1u,
        .height = 1u,
        .stride = 4u,
        .format = FARSEE_PIXEL_BGRA8888,
        .data = bgra,
        .data_size = sizeof bgra,
        .generation = 7u,
    };
    const farsee_surface_update update = {
        .view = view,
        .damage = NULL,
        .damage_count = 0u,
    };
    const farsee_frame_commit frame = {
        .frame_id = 7u,
        .updates = &update,
        .update_count = 1u,
        .cursor = NULL,
        .complete_snapshot = true,
    };
    RFB_CHECK(farsee_presenter_present(
                  farsee_live_presenter_v2(&owner), &frame)
                  .code == FARSEE_E_OK);
    RFB_CHECK(rfb_buffer_length(&owner.kitty_out) > 0u);
    RFB_CHECK_EQ_UINT(owner.kitty.fb_width, 1u);
    RFB_CHECK_EQ_UINT(owner.kitty.metrics.presents, 1u);
    farsee_live_presenter_destroy(&owner);
}

RFB_TEST(live_presenter, rfb_lifecycle__opens_resizes_and_closes_once)
{
    farsee_live_presenter owner;
    rfb_framebuffer framebuffer;
    memset(&owner, 0, sizeof owner);
    rfb_framebuffer_init(&framebuffer, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&framebuffer, 2u, 2u, 1024u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        farsee_live_presenter_init(
            &owner, FARSEE_LIVE_PRESENTER_RFB, "kitty-direct", false, 0u,
            0u, rfb_default_allocator()),
        FARSEE_LIVE_PRESENTER_INIT_OK);
    RFB_CHECK_EQ_INT(farsee_live_presenter_rfb_open(&owner, &framebuffer), 0);
    RFB_CHECK(owner.v1_opened);
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&framebuffer, 3u, 1u, 1024u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(farsee_live_presenter_rfb_resize(&owner, &framebuffer),
                     0);
    RFB_CHECK_EQ_UINT(owner.kitty.fb_width, 3u);
    farsee_live_presenter_close(&owner);
    const size_t teardown_length = rfb_buffer_length(&owner.kitty_out);
    RFB_CHECK(teardown_length > 0u);
    RFB_CHECK(farsee_live_presenter_kitty_out(&owner) == &owner.kitty_out);
    RFB_CHECK_EQ_INT(
        farsee_live_presenter_rfb_present(&owner, &framebuffer, NULL), -1);
    farsee_live_presenter_close(&owner);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&owner.kitty_out), teardown_length);
    farsee_live_presenter_destroy(&owner);
    farsee_live_presenter_destroy(&owner);
    rfb_framebuffer_destroy(&framebuffer);
}

RFB_TEST(live_presenter, rdp_null__opens_eagerly_and_closes_idempotently)
{
    farsee_live_presenter owner;
    memset(&owner, 0, sizeof owner);
    RFB_CHECK_EQ_INT(
        farsee_live_presenter_init(
            &owner, FARSEE_LIVE_PRESENTER_RDP, "null", true, 1280u, 800u,
            rfb_default_allocator()),
        FARSEE_LIVE_PRESENTER_INIT_OK);
    RFB_CHECK(owner.v2_opened);
    RFB_CHECK(owner.v1_opened);
    RFB_CHECK(!farsee_live_presenter_is_kitty(&owner));
    RFB_CHECK(farsee_live_presenter_v2(&owner) != NULL);
    farsee_live_presenter_close(&owner);
    RFB_CHECK(farsee_live_presenter_v2(&owner) == NULL);
    RFB_CHECK(!owner.v2_opened);
    farsee_live_presenter_close(&owner);
    farsee_live_presenter_destroy(&owner);
    farsee_live_presenter_destroy(&owner);
}

RFB_TEST(live_presenter, rdp_open_failure__releases_partial_owner)
{
    for (size_t fail_at = 1u; fail_at <= 2u; fail_at++) {
        presenter_fault_allocator fault = {0u, 0u, fail_at};
        rfb_allocator allocator = {
            .alloc = presenter_fault_alloc,
            .free = presenter_fault_free,
            .user = &fault,
        };
        farsee_live_presenter owner;
        memset(&owner, 0, sizeof owner);
        RFB_CHECK_EQ_INT(
            farsee_live_presenter_init(
                &owner, FARSEE_LIVE_PRESENTER_RDP, "kitty-direct", false,
                1280u, 800u, &allocator),
            FARSEE_LIVE_PRESENTER_INIT_OPEN_FAILED);
        RFB_CHECK(!owner.ready);
        RFB_CHECK(!owner.kitty_out_live);
        RFB_CHECK(farsee_live_presenter_v2(&owner) == NULL);
        farsee_live_presenter_destroy(&owner);
        RFB_CHECK_EQ_UINT(fault.calls, fail_at);
        RFB_CHECK_EQ_UINT(fault.frees, fail_at - 1u);
    }
}

RFB_TEST(live_presenter, rfb_present_failure__keeps_owner_destroyable)
{
    presenter_fault_allocator fault = {0u, 0u, 2u};
    rfb_allocator allocator = {
        .alloc = presenter_fault_alloc,
        .free = presenter_fault_free,
        .user = &fault,
    };
    farsee_live_presenter owner;
    rfb_framebuffer framebuffer;
    memset(&owner, 0, sizeof owner);
    rfb_framebuffer_init(&framebuffer, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&framebuffer, 1u, 1u, 1024u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        farsee_live_presenter_init(
            &owner, FARSEE_LIVE_PRESENTER_RFB, "kitty-direct", false, 0u,
            0u, &allocator),
        FARSEE_LIVE_PRESENTER_INIT_OK);
    RFB_CHECK_EQ_INT(farsee_live_presenter_rfb_open(&owner, &framebuffer), 0);
    const rfb_damage_batch damage = {
        .rects = NULL,
        .count = 0u,
        .full_frame = true,
        .framebuffer_generation = 1u,
    };
    RFB_CHECK(farsee_live_presenter_rfb_present(
                  &owner, &framebuffer, &damage) != 0);
    RFB_CHECK(owner.ready);
    RFB_CHECK(owner.v1_opened);
    farsee_live_presenter_destroy(&owner);
    farsee_live_presenter_destroy(&owner);
    RFB_CHECK(fault.calls >= 2u);
    RFB_CHECK(fault.frees >= 1u);
    rfb_framebuffer_destroy(&framebuffer);
}

RFB_TEST(live_presenter, invalid_inputs__fail_closed)
{
    farsee_live_presenter owner;
    memset(&owner, 0, sizeof owner);
    RFB_CHECK_EQ_INT(
        farsee_live_presenter_init(
            NULL, FARSEE_LIVE_PRESENTER_RFB, "null", false, 0u, 0u,
            rfb_default_allocator()),
        FARSEE_LIVE_PRESENTER_INIT_INVALID);
    RFB_CHECK_EQ_INT(
        farsee_live_presenter_init(
            &owner, (farsee_live_presenter_protocol)99, "null", false, 0u,
            0u, rfb_default_allocator()),
        FARSEE_LIVE_PRESENTER_INIT_INVALID);
    RFB_CHECK_EQ_INT(
        farsee_live_presenter_init(
            &owner, FARSEE_LIVE_PRESENTER_RFB, "null", false, 0u, 0u,
            NULL),
        FARSEE_LIVE_PRESENTER_INIT_INVALID);
    RFB_CHECK_EQ_INT(farsee_live_presenter_rfb_open(NULL, NULL), -1);
    farsee_live_presenter_close(NULL);
    farsee_live_presenter_destroy(NULL);
}
