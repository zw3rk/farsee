// SPDX-License-Identifier: Apache-2.0
//
// Deterministic coverage for RFB session frame publication and engine hooks.

#include "rfb_test.h"

#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/farsee_display.h"
#include "farsee/farsee_frame_slot.h"
#include "farsee/framebuffer.h"
#include "farsee/limits.h"
#include "farsee/pixel_format.h"
#include "farsee/rfb_server_engine.h"
#include "rfb/rfb_session_internal.h"
#include "tests/fakes/rfb_session_test_adapter.h"
#include "tests/test_framework/fake_io.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct frame_test_fixture {
    rfb_session storage;
    rfb_session *session;
    fake_io io;
    farsee_frame_slot slot;
    bool io_ready;
    bool slot_ready;
} frame_test_fixture;

static bool frame_test_fixture_init(frame_test_fixture *fixture,
                                    bool with_slot)
{
    if (fixture == NULL) {
        return false;
    }
    memset(fixture, 0, sizeof *fixture);
    fixture->session = &fixture->storage;
    rfb_session_clear(fixture->session);
    fixture->session->alloc = rfb_default_allocator();
    fake_io_init(&fixture->io, fixture->session->alloc);
    fixture->io_ready = true;
    fixture->session->io = fake_io_adapter_make(&fixture->io);
    rfb_buffer_init(&fixture->session->in, fixture->session->alloc,
                    RFB_LIMIT_FB_BYTES_POLICY);
    rfb_buffer_init(&fixture->session->out, fixture->session->alloc,
                    RFB_LIMIT_OUTBOUND_BYTES);
    rfb_framebuffer_init(&fixture->session->fb, fixture->session->alloc);
    fixture->session->pf = rfb_pixel_format_canonical_request();
    rfb_server_engine_init(&fixture->session->eng);
    rfb_pacing_init(&fixture->session->pacing, 0u);
    if (with_slot) {
        fixture->slot_ready = farsee_frame_slot_init(&fixture->slot);
        if (!fixture->slot_ready) {
            rfb_session_destroy(fixture->session);
            fake_io_destroy(&fixture->io);
            fixture->io_ready = false;
            return false;
        }
        fixture->session->cfg.slot = &fixture->slot;
    }
    return true;
}

static void frame_test_fixture_destroy(frame_test_fixture *fixture)
{
    if (fixture == NULL) {
        return;
    }
    if (fixture->session != NULL) {
        rfb_session_destroy(fixture->session);
    }
    if (fixture->slot_ready) {
        farsee_frame_slot_destroy(&fixture->slot);
    }
    if (fixture->io_ready) {
        fake_io_destroy(&fixture->io);
    }
}

static bool frame_test_seed_frame(frame_test_fixture *fixture,
                                  uint32_t width, uint32_t height,
                                  uint8_t red)
{
    if (fixture == NULL || fixture->session == NULL) {
        return false;
    }
    if (rfb_framebuffer_resize(&fixture->session->fb, width, height,
                               RFB_LIMIT_FB_BYTES_POLICY) != RFB_OK) {
        return false;
    }
    rfb_framebuffer_fill(&fixture->session->fb, red, 0u, 0u, 0xffu);
    fixture->session->fb_width = (uint16_t)width;
    fixture->session->fb_height = (uint16_t)height;
    return true;
}

RFB_TEST(rfb_session_frame,
         publish_frame__empty_frame__is_noop)
{
    frame_test_fixture fixture;
    const bool ready = frame_test_fixture_init(&fixture, false);
    RFB_CHECK(ready);
    if (!ready) {
        return;
    }

    RFB_CHECK_EQ_INT(rfb_session_test_publish_frame(fixture.session), RFB_OK);
    RFB_CHECK_EQ_UINT(fixture.session->frames_published, 0u);
    RFB_CHECK(!fixture.session->apple_seen_nonblack);

    frame_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_frame,
         publish_frame__sparse_threshold__requires_more_than_200_samples)
{
    frame_test_fixture fixture;
    const bool ready = frame_test_fixture_init(&fixture, false);
    RFB_CHECK(ready);
    if (!ready) {
        return;
    }

    // The 16-pixel sample grid visits exactly 20 * 10 = 200 pixels.
    RFB_CHECK(frame_test_seed_frame(&fixture, 320u, 160u, 1u));
    RFB_CHECK_EQ_INT(rfb_session_test_publish_frame(fixture.session), RFB_OK);
    RFB_CHECK(!fixture.session->apple_seen_nonblack);

    // Height 161 adds one sampled row, so the strict threshold is crossed.
    RFB_CHECK(frame_test_seed_frame(&fixture, 320u, 161u, 1u));
    RFB_CHECK_EQ_INT(rfb_session_test_publish_frame(fixture.session), RFB_OK);
    RFB_CHECK(fixture.session->apple_seen_nonblack);
    RFB_CHECK_EQ_UINT(fixture.session->frames_published, 2u);

    frame_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_frame,
         publish_frame__apple_black_bootstrap__wakes_but_withholds)
{
    static const uint8_t expected_wire[] = {
        0x05u, 0x00u, 0x00u, 0x05u, 0x00u, 0x0au,
        0x05u, 0x00u, 0x00u, 0x05u, 0x00u, 0x0au,
        0x04u, 0x01u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x20u,
        0x04u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x20u,
    };
    frame_test_fixture fixture;
    const bool ready = frame_test_fixture_init(&fixture, true);
    RFB_CHECK(ready);
    if (!ready) {
        return;
    }
    RFB_CHECK(frame_test_seed_frame(&fixture, 10u, 20u, 0u));
    fixture.session->dialect = RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP;
    rfb_pacing_request_sent(&fixture.session->pacing, false, 77u);

    RFB_CHECK_EQ_INT(rfb_session_test_publish_frame(fixture.session), RFB_OK);
    RFB_CHECK(fixture.session->apple_bootstrap_done);
    RFB_CHECK_EQ_UINT(fixture.session->apple_wake_attempts, 1u);
    RFB_CHECK_EQ_UINT(fixture.slot.gen, 0u);
    RFB_CHECK(!fixture.session->pacing.request_outstanding);
    RFB_CHECK(!fixture.session->pacing.initial_sent);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fixture.io), 6u);

    // The second black frame does not wake. The third permits one key pair.
    RFB_CHECK_EQ_INT(rfb_session_test_publish_frame(fixture.session), RFB_OK);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fixture.io), 6u);
    RFB_CHECK_EQ_INT(rfb_session_test_publish_frame(fixture.session), RFB_OK);
    RFB_CHECK_EQ_UINT(fixture.session->apple_wake_attempts, 2u);
    RFB_CHECK_EQ_UINT(fixture.slot.gen, 0u);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fixture.io), sizeof expected_wire);
    RFB_CHECK_MEM_EQ(fake_io_outbox_data(&fixture.io), expected_wire,
                     sizeof expected_wire);

    frame_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_frame,
         apple_wake__policy_suppression__queues_no_input)
{
    frame_test_fixture fixture;
    const bool ready = frame_test_fixture_init(&fixture, false);
    RFB_CHECK(ready);
    if (!ready) {
        return;
    }

    // A classic session ignores the Apple-only helper completely.
    rfb_session_internal_apple_wake(fixture.session, true);
    RFB_CHECK_EQ_UINT(fixture.session->apple_wake_attempts, 0u);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fixture.io), 0u);

    // View-only suppresses input while the full-refresh path stays active.
    fixture.session->dialect = RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP;
    fixture.session->cfg.view_only = true;
    rfb_pacing_request_sent(&fixture.session->pacing, false, 11u);
    rfb_session_internal_apple_wake(fixture.session, true);
    RFB_CHECK_EQ_UINT(fixture.session->apple_wake_attempts, 1u);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fixture.io), 0u);
    RFB_CHECK(!fixture.session->pacing.request_outstanding);

    // The private suppression variant also leaves pacing untouched.
    fixture.session->wire_variants.suppress_fbur = true;
    rfb_pacing_request_sent(&fixture.session->pacing, false, 12u);
    rfb_session_internal_apple_wake(fixture.session, true);
    RFB_CHECK_EQ_UINT(fixture.session->apple_wake_attempts, 2u);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fixture.io), 0u);
    RFB_CHECK(fixture.session->pacing.request_outstanding);

    frame_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_frame,
         publish_frame__all_slot_storage_held__drops_without_error)
{
    frame_test_fixture fixture;
    const bool ready = frame_test_fixture_init(&fixture, true);
    RFB_CHECK(ready);
    if (!ready) {
        return;
    }
    RFB_CHECK(frame_test_seed_frame(&fixture, 1u, 1u, 1u));

    farsee_frame_view held[FARSEE_FRAME_SLOT_N];
    memset(held, 0, sizeof held);
    for (size_t i = 0u; i < FARSEE_FRAME_SLOT_N; i++) {
        RFB_CHECK(farsee_frame_slot_publish(
            &fixture.slot, fixture.session->fb.rgba, 1u, 1u, 4u,
            FARSEE_PIXEL_RGBA8888));
        RFB_CHECK(farsee_frame_slot_acquire(&fixture.slot, &held[i]));
    }
    RFB_CHECK_EQ_UINT(fixture.slot.gen, FARSEE_FRAME_SLOT_N);

    RFB_CHECK_EQ_INT(rfb_session_test_publish_frame(fixture.session), RFB_OK);
    RFB_CHECK_EQ_UINT(fixture.slot.gen, FARSEE_FRAME_SLOT_N);
    RFB_CHECK_EQ_UINT(fixture.session->pacing.metrics_presentations, 0u);
    RFB_CHECK_EQ_INT(fixture.session->last_error, RFB_OK);

    for (size_t i = 0u; i < FARSEE_FRAME_SLOT_N; i++) {
        farsee_frame_slot_release(&fixture.slot, &held[i]);
    }
    frame_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_frame,
         publish_frame__composites_cursor_without_changing_authoritative_fb)
{
    frame_test_fixture fixture;
    const bool ready = frame_test_fixture_init(&fixture, true);
    RFB_CHECK(ready);
    if (!ready) {
        return;
    }
    RFB_CHECK(frame_test_seed_frame(&fixture, 3u, 2u, 10u));
    for (size_t i = 0u; i < 6u; i++) {
        fixture.session->fb.rgba[i * 4u + 1u] = 20u;
        fixture.session->fb.rgba[i * 4u + 2u] = 30u;
    }
    static const uint8_t cursor[] = {
        250u, 0u, 0u, 255u,   0u, 220u, 0u, 128u,
        0u, 0u, 250u, 0u,     240u, 240u, 240u, 255u,
    };
    fixture.session->cursor.rgba =
        fixture.session->alloc->alloc(fixture.session->alloc, sizeof cursor);
    RFB_CHECK(fixture.session->cursor.rgba != NULL);
    if (fixture.session->cursor.rgba == NULL) {
        frame_test_fixture_destroy(&fixture);
        return;
    }
    memcpy(fixture.session->cursor.rgba, cursor, sizeof cursor);
    fixture.session->cursor.width = 2u;
    fixture.session->cursor.height = 2u;
    fixture.session->cursor.hotspot_x = 1u;
    fixture.session->cursor.hotspot_y = 0u;
    fixture.session->cursor.valid = true;
    fixture.session->last_ptr_x = 1u;
    fixture.session->last_ptr_y = 0u;

    RFB_CHECK_EQ_INT(rfb_session_test_publish_frame(fixture.session), RFB_OK);
    farsee_frame_view view;
    memset(&view, 0, sizeof view);
    RFB_CHECK(farsee_frame_slot_acquire(&fixture.slot, &view));
    static const uint8_t expected[] = {
        250u, 0u, 0u, 255u,   5u, 120u, 15u, 255u,
        10u, 20u, 30u, 255u,  10u, 20u, 30u, 255u,
        240u, 240u, 240u, 255u, 10u, 20u, 30u, 255u,
    };
    RFB_CHECK_MEM_EQ(view.pixels, expected, sizeof expected);
    farsee_frame_slot_release(&fixture.slot, &view);

    static const uint8_t authoritative[] = {10u, 20u, 30u, 255u};
    for (size_t i = 0u; i < 6u; i++) {
        RFB_CHECK_MEM_EQ(fixture.session->fb.rgba + i * 4u,
                         authoritative, sizeof authoritative);
    }
    frame_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_frame,
         publish_frame__valid_cursor_bypasses_apple_black_withhold)
{
    frame_test_fixture fixture;
    const bool ready = frame_test_fixture_init(&fixture, true);
    RFB_CHECK(ready);
    if (!ready) {
        return;
    }
    RFB_CHECK(frame_test_seed_frame(&fixture, 2u, 2u, 0u));
    fixture.session->dialect = RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP;
    static const uint8_t cursor[] = {200u, 100u, 50u, 255u};
    fixture.session->cursor.rgba =
        fixture.session->alloc->alloc(fixture.session->alloc, sizeof cursor);
    RFB_CHECK(fixture.session->cursor.rgba != NULL);
    if (fixture.session->cursor.rgba == NULL) {
        frame_test_fixture_destroy(&fixture);
        return;
    }
    memcpy(fixture.session->cursor.rgba, cursor, sizeof cursor);
    fixture.session->cursor.width = 1u;
    fixture.session->cursor.height = 1u;
    fixture.session->cursor.valid = true;
    fixture.session->last_ptr_x = 1u;
    fixture.session->last_ptr_y = 1u;

    RFB_CHECK_EQ_INT(rfb_session_test_publish_frame(fixture.session), RFB_OK);
    RFB_CHECK_EQ_UINT(fixture.slot.gen, 1u);
    farsee_frame_view view;
    memset(&view, 0, sizeof view);
    const bool acquired = farsee_frame_slot_acquire(&fixture.slot, &view);
    RFB_CHECK(acquired);
    if (acquired) {
        RFB_CHECK_MEM_EQ(view.pixels + 12u, cursor, sizeof cursor);
        farsee_frame_slot_release(&fixture.slot, &view);
    }
    frame_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_frame,
         process_in__desktop_size__updates_session_and_publishes)
{
    static const uint8_t desktop_size[] = {
        0x00u, 0x00u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x02u, 0x00u, 0x03u,
        0xffu, 0xffu, 0xffu, 0x21u,
    };
    frame_test_fixture fixture;
    const bool ready = frame_test_fixture_init(&fixture, true);
    RFB_CHECK(ready);
    if (!ready) {
        return;
    }
    rfb_pacing_request_sent(&fixture.session->pacing, false, 91u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.session->in, desktop_size,
                                       sizeof desktop_size),
                     RFB_OK);

    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_session_test_process_in(fixture.session, &progress),
                     RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.session->in), 0u);
    RFB_CHECK_EQ_UINT(fixture.session->fb_width, 2u);
    RFB_CHECK_EQ_UINT(fixture.session->fb_height, 3u);
    RFB_CHECK_EQ_UINT(fixture.session->fb.width, 2u);
    RFB_CHECK_EQ_UINT(fixture.session->fb.height, 3u);
    RFB_CHECK_EQ_UINT(fixture.session->mvs_coeffs.ntiles, 1u);
    RFB_CHECK(fixture.session->mvs_coeffs.tiles != NULL);
    RFB_CHECK_EQ_UINT(fixture.slot.gen, 1u);
    RFB_CHECK_EQ_UINT(fixture.session->frames_published, 1u);
    RFB_CHECK(!fixture.session->pacing.request_outstanding);
    RFB_CHECK(!fixture.session->pacing.initial_sent);

    farsee_frame_view view;
    memset(&view, 0, sizeof view);
    RFB_CHECK(farsee_frame_slot_acquire(&fixture.slot, &view));
    RFB_CHECK_EQ_UINT(view.w, 2u);
    RFB_CHECK_EQ_UINT(view.h, 3u);
    static const uint8_t black[] = {0u, 0u, 0u, 0xffu};
    RFB_CHECK_MEM_EQ(view.pixels, black, sizeof black);
    farsee_frame_slot_release(&fixture.slot, &view);

    frame_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_frame,
         process_in__invalid_desktop_size__preserves_prior_frame)
{
    static const uint8_t invalid_desktop_size[] = {
        0x00u, 0x00u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x03u,
        0xffu, 0xffu, 0xffu, 0x21u,
    };
    frame_test_fixture fixture;
    const bool ready = frame_test_fixture_init(&fixture, true);
    RFB_CHECK(ready);
    if (!ready) {
        return;
    }
    RFB_CHECK(frame_test_seed_frame(&fixture, 1u, 1u, 9u));
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.session->in,
                                       invalid_desktop_size,
                                       sizeof invalid_desktop_size),
                     RFB_OK);

    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_session_test_process_in(fixture.session, &progress),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK(progress);
    RFB_CHECK_EQ_INT(fixture.session->last_error, RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(fixture.session->fb.width, 1u);
    RFB_CHECK_EQ_UINT(fixture.session->fb.height, 1u);
    RFB_CHECK_EQ_UINT(fixture.session->fb.rgba[0], 9u);
    RFB_CHECK_EQ_UINT(fixture.session->frames_published, 0u);
    RFB_CHECK_EQ_UINT(fixture.slot.gen, 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.session->in), 12u);

    frame_test_fixture_destroy(&fixture);
}
