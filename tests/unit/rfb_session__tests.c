// SPDX-License-Identifier: Apache-2.0
//
// RFB session unit tests for config gates, helpers, and selected socket edges.
// The loopback lifecycle integration tests the lower-level handshake path.

#include "rfb_test.h"
#include "farsee/rfb_session.h"
#include "farsee/error.h"
#include "farsee/allocator.h"
#include "farsee/farsee_frame_slot.h"
#include "farsee/farsee_display.h"
#include "farsee/presenter.h"
#include "farsee/apple_wire_record.h"
#include "farsee/framebuffer.h"
#include "farsee/limits.h"
#include "tests/fakes/rfb_session_test_adapter.h"
#include "tests/test_framework/rfb_session_capture_fixture.h"
#include "tests/test_framework/memory_presenter.h"
#include "rfb/rfb_session_internal.h"
#include "rfb/rfb_session_math.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>

RFB_TEST(rfb_session, session__size__is_nonzero)
{
    RFB_CHECK(rfb_session_size() >= sizeof(void *));
}

RFB_TEST(rfb_session, connect_deadline__zero_uses_policy_default)
{
    RFB_CHECK_EQ_UINT(rfb_session_connect_deadline(1000u, 0u),
                      1000u + RFB_LIMIT_CONNECT_TIMEOUT_MS);
}

RFB_TEST(rfb_session, connect_deadline__explicit_value_is_preserved)
{
    RFB_CHECK_EQ_UINT(rfb_session_connect_deadline(1000u, 250u), 1250u);
}

RFB_TEST(rfb_session, connect_deadline__overflow_saturates)
{
    RFB_CHECK_EQ_UINT(rfb_session_connect_deadline(UINT64_MAX - 1u, 2u),
                      UINT64_MAX);
}

// Check the slot publish field and its designated initialization. Presenter
// ownership is a source-level session contract, not proved by this initializer.
RFB_TEST(rfb_session, config__slot_only__no_presenter_field)
{
    farsee_frame_slot slot;
    memset(&slot, 0, sizeof slot);
    RFB_CHECK(farsee_frame_slot_init(&slot));

    rfb_session_config cfg = {
        .host = "127.0.0.1",
        .port = 5900,
        .slot = &slot,
        .cmds = NULL,
        .stop_flag = NULL,
        .max_fps = 0,
        .view_only = false,
    };
    RFB_CHECK(cfg.slot == &slot);
    RFB_CHECK(cfg.host != NULL);
    // offsetof(slot) is valid; proves the field exists for publish path.
    RFB_CHECK(offsetof(rfb_session_config, slot) < sizeof(rfb_session_config));
    // Unspecified optional fields remain zero in this initializer.
    RFB_CHECK(cfg.cmds == NULL);

    farsee_frame_slot_destroy(&slot);
}

typedef struct session_slot_fault_allocator {
    size_t calls;
    size_t fail_at;
} session_slot_fault_allocator;

static void *session_slot_fault_alloc(rfb_allocator *allocator, size_t size)
{
    session_slot_fault_allocator *fault =
        (session_slot_fault_allocator *)allocator->user;
    fault->calls++;
    if (fault->calls == fault->fail_at) {
        return NULL;
    }
    return malloc(size);
}

static void session_slot_fault_free(rfb_allocator *allocator, void *pointer)
{
    (void)allocator;
    free(pointer);
}

RFB_TEST(rfb_session, publish_frame__allocation_failure_then_retry)
{
    session_slot_fault_allocator fault = { .calls = 0u, .fail_at = 1u };
    rfb_allocator allocator = {
        .alloc = session_slot_fault_alloc,
        .free = session_slot_fault_free,
        .user = &fault,
    };
    farsee_frame_slot slot;
    RFB_CHECK(farsee_frame_slot_init_with_allocator(&slot, &allocator));

    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    rfb_session_clear(session);
    session->cfg.slot = &slot;
    rfb_framebuffer_init(&session->fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&session->fb, 1u, 1u, 1024u),
                     RFB_OK);
    rfb_framebuffer_fill(&session->fb, 1u, 2u, 3u, 0xFFu);
    rfb_pacing_init(&session->pacing, 0u);
    session->eng.rects_decoded = 3u;

    RFB_CHECK_EQ_INT(rfb_session_test_publish_frame(session), RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(slot.gen, 0u);
    RFB_CHECK_EQ_UINT(session->pacing.metrics_presentations, 0u);
    RFB_CHECK_EQ_UINT(session->pacing.metrics_rects_decoded, 0u);
    RFB_CHECK_EQ_UINT(session->pacing.last_present_ms, 0u);

    RFB_CHECK_EQ_INT(rfb_session_test_publish_frame(session), RFB_OK);
    RFB_CHECK_EQ_UINT(slot.gen, 1u);
    RFB_CHECK_EQ_UINT(session->pacing.metrics_presentations, 1u);
    RFB_CHECK_EQ_UINT(session->pacing.metrics_rects_decoded, 3u);
    farsee_frame_view view;
    RFB_CHECK(farsee_frame_slot_acquire(&slot, &view));
    RFB_CHECK_MEM_EQ(view.pixels, session->fb.rgba, 4u);
    farsee_frame_slot_release(&slot, &view);

    rfb_framebuffer_destroy(&session->fb);
    farsee_frame_slot_destroy(&slot);
}

RFB_TEST(rfb_session, publish_frame__invalid_geometry_does_not_advance)
{
    farsee_frame_slot slot;
    RFB_CHECK(farsee_frame_slot_init(&slot));
    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    rfb_session_clear(session);
    session->cfg.slot = &slot;
    uint8_t pixel[4] = { 1u, 2u, 3u, 0xFFu };
    session->fb.rgba = pixel;
    session->fb.width = 1u;
    session->fb.height = 1u;
    session->fb.stride = 2u;
    rfb_pacing_init(&session->pacing, 0u);

    RFB_CHECK_EQ_INT(rfb_session_test_publish_frame(session), RFB_ERR_STATE);
    RFB_CHECK_EQ_UINT(slot.gen, 0u);
    RFB_CHECK_EQ_UINT(session->pacing.metrics_presentations, 0u);
    RFB_CHECK_EQ_UINT(session->pacing.last_present_ms, 0u);
    farsee_frame_slot_destroy(&slot);
}

// Check the pure publish_black_frames helper for the zero/default and explicit
// opt-in inputs. This test does not run session publication.
RFB_TEST(rfb_session, config__publish_black_frames__defaults_and_overrides_withhold)
{
    // Zero initialization leaves the below-threshold Apple frame withheld.
    rfb_session_config zeroed;
    memset(&zeroed, 0, sizeof zeroed);
    RFB_CHECK(!zeroed.publish_black_frames);
    RFB_CHECK(rfb_session_should_withhold_black_publish(
        /*apple_cleartext=*/true, /*nonblack=*/false, zeroed.publish_black_frames));

    // Explicit opt-in permits the same below-threshold frame.
    rfb_session_config optin = {
        .host = "127.0.0.1",
        .publish_black_frames = true,
    };
    RFB_CHECK(optin.publish_black_frames);
    RFB_CHECK(!rfb_session_should_withhold_black_publish(
        /*apple_cleartext=*/true, /*nonblack=*/false, optin.publish_black_frames));
    // offsetof proves the field exists inside the struct (not past the end).
    RFB_CHECK(offsetof(rfb_session_config, publish_black_frames) <
              sizeof(rfb_session_config));
}

RFB_TEST(rfb_session, config__apple_wire_policy__safe_zero_defaults)
{
    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    RFB_CHECK_EQ_INT(cfg.apple_postauth_mode,
                     RFB_APPLE_POSTAUTH_CLEARTEXT);
    RFB_CHECK(!cfg.apple_send_viewer_info);
    RFB_CHECK(!cfg.apple_disable_wake_keys);
}

RFB_TEST(rfb_session, config__apple_wire_policy__explicit_modes_remain_available)
{
    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.apple_postauth_mode = RFB_APPLE_POSTAUTH_RECORDS;
    cfg.apple_send_viewer_info = true;
    cfg.apple_disable_wake_keys = true;
    RFB_CHECK_EQ_INT(cfg.apple_postauth_mode, RFB_APPLE_POSTAUTH_RECORDS);
    RFB_CHECK(cfg.apple_send_viewer_info);
    RFB_CHECK(cfg.apple_disable_wake_keys);

    cfg.apple_postauth_mode = RFB_APPLE_POSTAUTH_PRIVATE_ENCODINGS;
    RFB_CHECK_EQ_INT(cfg.apple_postauth_mode,
                     RFB_APPLE_POSTAUTH_PRIVATE_ENCODINGS);
}

// Destroy never opens or closes a presenter. Local presenter close_count
// stays 0 across clear+destroy (session has no presenter pointer).
RFB_TEST(rfb_session, destroy__does_not_close_app_presenter)
{
    rfb_presenter_null nul;
    rfb_presenter_null_init(&nul);
    rfb_presenter app_presenter = {.ops = &rfb_presenter_null_ops, .ctx = &nul};
    // App may open its own presenter; session must not touch it.
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_presenter_open(&app_presenter, &fb), 0);

    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    rfb_session_destroy(s);
    rfb_session_destroy(s);

    // Still open and usable — session did not close it.
    RFB_CHECK_EQ_INT(rfb_presenter_present(&app_presenter, &fb, NULL), 0);
    RFB_CHECK_EQ_INT(nul.present_count, 1);
    rfb_presenter_close(&app_presenter);
    rfb_framebuffer_destroy(&fb);
}

// Demonstrate app acquire/present after a direct slot publish; no session or
// socket runs in this test.
RFB_TEST(rfb_session, publish_then_app_present__captures_rgba_in_memory)
{
    uint8_t pixels[4u * 2u * 2u];
    uint8_t captured[sizeof pixels];
    for (size_t i = 0; i < sizeof pixels; i++) {
        pixels[i] = (uint8_t)(i + 1u);
    }

    farsee_frame_slot slot;
    memset(&slot, 0, sizeof slot);
    RFB_CHECK(farsee_frame_slot_init(&slot));
    RFB_CHECK(farsee_frame_slot_publish(
        &slot, pixels, 2u, 2u, 8u, FARSEE_PIXEL_RGBA8888));

    farsee_frame_view view;
    memset(&view, 0, sizeof view);
    RFB_CHECK(farsee_frame_slot_acquire(&slot, &view));
    RFB_CHECK(view.pixels != NULL);
    RFB_CHECK_EQ_UINT(view.w, 2u);
    RFB_CHECK_EQ_UINT(view.h, 2u);

    rfb_framebuffer framebuffer;
    memset(&framebuffer, 0, sizeof framebuffer);
    framebuffer.rgba = (uint8_t *)(uintptr_t)view.pixels;
    framebuffer.width = view.w;
    framebuffer.height = view.h;
    framebuffer.stride = view.stride;
    framebuffer.generation = view.gen;

    rfb_test_memory_presenter memory;
    rfb_test_memory_presenter_init(&memory, captured, sizeof captured);
    rfb_presenter presenter = {
        .ops = &rfb_test_memory_presenter_ops,
        .ctx = &memory,
    };
    RFB_CHECK_EQ_INT(rfb_presenter_open(&presenter, &framebuffer), 0);
    RFB_CHECK_EQ_INT(
        rfb_presenter_present(&presenter, &framebuffer, NULL), 0);
    rfb_presenter_close(&presenter);
    farsee_frame_slot_release(&slot, &view);

    RFB_CHECK_EQ_UINT(memory.open_count, 1u);
    RFB_CHECK_EQ_UINT(memory.present_count, 1u);
    RFB_CHECK_EQ_UINT(memory.close_count, 1u);
    RFB_CHECK_EQ_UINT(memory.size, sizeof pixels);
    RFB_CHECK_MEM_EQ(captured, pixels, sizeof pixels);
    farsee_frame_slot_destroy(&slot);
}

RFB_TEST(rfb_session, session_connect__null_session__fails_internal)
{
    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.host = "127.0.0.1";
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(NULL, &cfg), RFB_ERR_INTERNAL);
}

RFB_TEST(rfb_session, session_connect__null_config__fails_internal)
{
    // Allocate opaque session storage on the stack via VLA ban → fixed buf.
    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(s, NULL), RFB_ERR_INTERNAL);
    rfb_session_destroy(s);
}

RFB_TEST(rfb_session, session_connect__null_host__fails_internal)
{
    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.host = NULL;
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(s, &cfg), RFB_ERR_INTERNAL);
    rfb_session_destroy(s);
}

RFB_TEST(rfb_session, session_connect__empty_host__fails_internal)
{
    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.host = "";
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(s, &cfg), RFB_ERR_INTERNAL);
    rfb_session_destroy(s);
}

RFB_TEST(rfb_session, modern_setup__production_transport_bytes_are_exact)
{
    static const uint8_t control_set_encodings[] = {
        0x02u, 0x00u, 0x00u, 0x03u,
        0x00u, 0x00u, 0x00u, 0x10u,
        0xffu, 0xffu, 0xffu, 0x21u,
        0xffu, 0xffu, 0xffu, 0x11u,
    };
    static const uint8_t default_set_encodings[] = {
        0x02u, 0x00u, 0x00u, 0x04u,
        0x00u, 0x00u, 0x00u, 0x10u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0xffu, 0xffu, 0xffu, 0x21u,
        0xffu, 0xffu, 0xffu, 0x11u,
    };
    static const struct {
        rfb_session_test_modern_setup_mode mode;
        bool initial_only;
        size_t length;
        const uint8_t *set_encodings;
        size_t set_encodings_length;
    } cases[] = {
        {RFB_SESSION_TEST_MODERN_SETUP_CONTROL, true, 98u,
         control_set_encodings, sizeof control_set_encodings},
        {RFB_SESSION_TEST_MODERN_SETUP_PRIVATE_ENCODINGS, false, 138u,
         apple_wire_modern_post_si + 82u, 56u},
        {RFB_SESSION_TEST_MODERN_SETUP_DEFAULT, false, 102u,
         default_set_encodings, sizeof default_set_encodings},
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        rfb_session_config cfg;
        memset(&cfg, 0, sizeof cfg);
        cfg.capture_initial_only = cases[i].initial_only;
        uint8_t transport_bytes[APPLE_WIRE_MODERN_POST_SI_LEN];
        size_t transport_length = 0u;
        unsigned char storage[4096];
        RFB_CHECK(rfb_session_size() <= sizeof storage);
        rfb_session *session = (rfb_session *)(void *)storage;

        RFB_CHECK_EQ_INT(rfb_session_test_capture_modern_setup(
                             session, &cfg, cases[i].mode, transport_bytes,
                             sizeof transport_bytes, &transport_length),
                         RFB_OK);
        RFB_CHECK_EQ_UINT(transport_length, cases[i].length);
        RFB_CHECK_EQ_INT(
            memcmp(transport_bytes, apple_wire_modern_post_si, 82u), 0);
        RFB_CHECK_EQ_INT(memcmp(transport_bytes + 82u,
                                cases[i].set_encodings,
                                cases[i].set_encodings_length),
                         0);
        if (cases[i].mode == RFB_SESSION_TEST_MODERN_SETUP_PRIVATE_ENCODINGS) {
            RFB_CHECK_EQ_INT(memcmp(transport_bytes,
                                    apple_wire_modern_post_si,
                                    APPLE_WIRE_MODERN_POST_SI_LEN),
                             0);
        }
    }
}

RFB_TEST(rfb_session, session_destroy__null_and_cleared__safe)
{
    rfb_session_destroy(NULL);
    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    rfb_session_destroy(s);
    rfb_session_destroy(s);  // idempotent
}

RFB_TEST(rfb_session, session_protocol_loop__inactive__no_crash)
{
    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    rfb_session_protocol_loop(s);  // not active → immediate return
    rfb_session_protocol_loop(NULL);
    rfb_session_destroy(s);
}

RFB_TEST(rfb_session, session_last_error__null__internal)
{
    RFB_CHECK_EQ_INT(rfb_session_last_error(NULL), RFB_ERR_INTERNAL);
}

RFB_TEST(rfb_session, session_framebuffer__null__null)
{
    RFB_CHECK(rfb_session_framebuffer(NULL) == NULL);
}

// A NULL session snapshot claims nothing.
RFB_TEST(rfb_session, link_snapshot__null_session__reports_nothing)
{
    uint32_t rtt = 99u;
    bool have_rtt = true;
    uint64_t rx = 99u;
    bool have_rx = true;
    rfb_session_link_snapshot(NULL, &rtt, &have_rtt, &rx, &have_rx);
    RFB_CHECK(!have_rtt);
    RFB_CHECK(!have_rx);
}

// snapshot_ex clears have_rate for a NULL session.
RFB_TEST(rfb_session, link_snapshot_ex__null_session__zero_rate)
{
    uint32_t rtt = 1u;
    bool have_rtt = true;
    uint64_t rx = 1u;
    bool have_rx = true;
    uint32_t rate = 7u;
    bool have_rate = true;
    rfb_session_link_snapshot_ex(NULL, &rtt, &have_rtt, &rx, &have_rx, &rate,
                                 &have_rate);
    RFB_CHECK(!have_rtt);
    RFB_CHECK(!have_rx);
    RFB_CHECK(!have_rate);
}

// sample_link is a no-op for an inactive session.
RFB_TEST(rfb_session, sample_link__closed_session__is_noop)
{
    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    rfb_session_sample_link(s);
    rfb_session_sample_link(NULL);
    uint32_t rtt = 1u;
    bool have_rtt = true;
    uint64_t rx = 1u;
    bool have_rx = true;
    uint32_t rate = 1u;
    bool have_rate = true;
    rfb_session_link_snapshot_ex(s, &rtt, &have_rtt, &rx, &have_rx, &rate,
                                 &have_rate);
    RFB_CHECK(!have_rtt);
    RFB_CHECK(!have_rx);
    RFB_CHECK(!have_rate);
    rfb_session_destroy(s);
}

RFB_TEST(rfb_session, session_connect_classic__apple_auth_mode__unsupported)
{
    // Classic-only entry still rejects APPLE mode before I/O.
    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.host = "127.0.0.1";
    cfg.auth_mode = FARSEE_AUTH_MODE_APPLE;
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(s, &cfg), RFB_ERR_UNSUPPORTED);
    RFB_CHECK_EQ_INT(rfb_session_last_error(s), RFB_ERR_UNSUPPORTED);
    rfb_session_destroy(s);
}

RFB_TEST(rfb_session, session_connect_auto__null_session__fails_internal)
{
    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.host = "127.0.0.1";
    RFB_CHECK_EQ_INT(rfb_session_connect(NULL, &cfg), RFB_ERR_INTERNAL);
}

RFB_TEST(rfb_session, session_connect_auto__null_config__fails_internal)
{
    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    RFB_CHECK_EQ_INT(rfb_session_connect(s, NULL), RFB_ERR_INTERNAL);
    rfb_session_destroy(s);
}

RFB_TEST(rfb_session, session_wrap_key__absent_after_clear)
{
    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    RFB_CHECK(!rfb_session_has_wrap_key(s));
    uint8_t out[16];
    RFB_CHECK(!rfb_session_copy_wrap_key(s, out));
    RFB_CHECK(!rfb_session_copy_wrap_key(NULL, out));
    RFB_CHECK(!rfb_session_has_wrap_key(NULL));
    rfb_session_destroy(s);
}

RFB_TEST(rfb_session, black_hint_due__only_at_threshold)
{
    RFB_CHECK(!rfb_black_hint_due(0u));
    RFB_CHECK(!rfb_black_hint_due(1u));
    RFB_CHECK(!rfb_black_hint_due(RFB_BLACK_FRAME_HINT_FRAMES - 1u));
    RFB_CHECK(rfb_black_hint_due(RFB_BLACK_FRAME_HINT_FRAMES));
    RFB_CHECK(!rfb_black_hint_due(RFB_BLACK_FRAME_HINT_FRAMES + 1u));
    RFB_CHECK(!rfb_black_hint_due(UINT32_MAX));
}

// Pure classification from the supplied Apple, record-state, sampled-colour,
// and frame-count inputs. These tests do not establish live record state or the
// cause of framebuffer data.
RFB_TEST(rfb_session, black_hint_kind__records_active__names_encrypted_path)
{
    // records_active=true at the threshold selects the records enum.
    RFB_CHECK_EQ_UINT(
        (unsigned)rfb_black_hint_kind_for(/*apple_dialect=*/true,
                                          /*records_active=*/true,
                                          /*nonblack_seen=*/false,
                                          RFB_BLACK_FRAME_HINT_FRAMES),
        (unsigned)RFB_BLACK_HINT_APPLE_RECORDS);
}

RFB_TEST(rfb_session, black_hint_kind__cleartext__names_modern_optin)
{
    // records_active=false at the threshold selects the cleartext enum.
    RFB_CHECK_EQ_UINT(
        (unsigned)rfb_black_hint_kind_for(/*apple_dialect=*/true,
                                          /*records_active=*/false,
                                          /*nonblack_seen=*/false,
                                          RFB_BLACK_FRAME_HINT_FRAMES),
        (unsigned)RFB_BLACK_HINT_APPLE_CLEARTEXT);
}

RFB_TEST(rfb_session, black_hint_kind__not_due_or_not_apple__none)
{
    // Other counts, non-Apple dialect, or sampled colour select none.
    RFB_CHECK_EQ_UINT(
        (unsigned)rfb_black_hint_kind_for(true, true, false,
                                          RFB_BLACK_FRAME_HINT_FRAMES - 1u),
        (unsigned)RFB_BLACK_HINT_NONE);
    RFB_CHECK_EQ_UINT(
        (unsigned)rfb_black_hint_kind_for(true, true, false,
                                          RFB_BLACK_FRAME_HINT_FRAMES + 1u),
        (unsigned)RFB_BLACK_HINT_NONE);
    RFB_CHECK_EQ_UINT(
        (unsigned)rfb_black_hint_kind_for(false, true, false,
                                          RFB_BLACK_FRAME_HINT_FRAMES),
        (unsigned)RFB_BLACK_HINT_NONE);
    RFB_CHECK_EQ_UINT(
        (unsigned)rfb_black_hint_kind_for(true, true, /*nonblack_seen=*/true,
                                          RFB_BLACK_FRAME_HINT_FRAMES),
        (unsigned)RFB_BLACK_HINT_NONE);
}

RFB_TEST(rfb_session, black_hint_text__never_names_the_wrong_cipher)
{
    // Check the fixed hint strings: neither contains ChaCha, and the records
    // string names the configured 0x044f path.
    static const rfb_black_hint_kind kinds[] = {
        RFB_BLACK_HINT_NONE,
        RFB_BLACK_HINT_APPLE_CLEARTEXT,
        RFB_BLACK_HINT_APPLE_RECORDS
    };
    for (size_t i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        const char *t = rfb_black_hint_text(kinds[i]);
        RFB_CHECK(t != NULL);
        RFB_CHECK(strstr(t, "ChaCha") == NULL);
        RFB_CHECK(strstr(t, "chacha") == NULL);
    }
    // NONE is empty; the other fixed strings identify their configured path.
    RFB_CHECK_EQ_UINT(strlen(rfb_black_hint_text(RFB_BLACK_HINT_NONE)), 0u);
    RFB_CHECK(strstr(rfb_black_hint_text(RFB_BLACK_HINT_APPLE_CLEARTEXT),
                     "--apple-postauth=records") != NULL);
    RFB_CHECK(strstr(rfb_black_hint_text(RFB_BLACK_HINT_APPLE_RECORDS),
                     "0x044f") != NULL);
    // The records string omits the word `cleartext`.
    RFB_CHECK(strstr(rfb_black_hint_text(RFB_BLACK_HINT_APPLE_RECORDS),
                     "cleartext") == NULL);
}

// Pure Apple cleartext sampled-threshold withhold decision matrix.
RFB_TEST(rfb_session, withhold_black_publish__apple_black_no_optin__withholds)
{
    // Default input asks the helper to withhold this frame.
    RFB_CHECK(rfb_session_should_withhold_black_publish(
        /*apple_cleartext=*/true, /*nonblack=*/false,
        /*publish_black_frames=*/false));
}

RFB_TEST(rfb_session, withhold_black_publish__apple_black_optin__publishes)
{
    // Opt-in input asks the helper to permit this frame.
    RFB_CHECK(!rfb_session_should_withhold_black_publish(
        /*apple_cleartext=*/true, /*nonblack=*/false,
        /*publish_black_frames=*/true));
}

RFB_TEST(rfb_session, withhold_black_publish__apple_nonblack__publishes)
{
    // The supplied nonblack flag bypasses the withhold.
    RFB_CHECK(!rfb_session_should_withhold_black_publish(
        /*apple_cleartext=*/true, /*nonblack=*/true,
        /*publish_black_frames=*/false));
}

RFB_TEST(rfb_session, withhold_black_publish__non_apple__publishes)
{
    // The supplied classic-path flag bypasses the withhold.
    RFB_CHECK(!rfb_session_should_withhold_black_publish(
        /*apple_cleartext=*/false, /*nonblack=*/false,
        /*publish_black_frames=*/false));
}

RFB_TEST(rfb_session, session_last_unexpected_type__cleared_is_zero)
{
    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    RFB_CHECK_EQ_UINT(rfb_session_last_unexpected_type(s), 0u);
    RFB_CHECK_EQ_UINT(rfb_session_last_unexpected_type(NULL), 0u);
    rfb_session_destroy(s);
}

// A silent peer returns RFB_ERR_TIMEOUT with the configured connect budget.
RFB_TEST(rfb_session, connect_classic__silent_peer__timeout_within_budget)
{
    int lst = socket(AF_INET, SOCK_STREAM, 0);
    RFB_CHECK(lst >= 0);
    int one = 1;
    (void)setsockopt(lst, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    RFB_CHECK(bind(lst, (struct sockaddr *)&addr, sizeof addr) == 0);
    RFB_CHECK(listen(lst, 1) == 0);
    socklen_t alen = sizeof addr;
    RFB_CHECK(getsockname(lst, (struct sockaddr *)&addr, &alen) == 0);
    const uint16_t port = ntohs(addr.sin_port);

    pid_t pid = fork();
    RFB_CHECK(pid >= 0);
    if (pid == 0) {
        int c = accept(lst, NULL, NULL);
        if (c >= 0) {
            sleep(3); // silent: no RFB banner
            close(c);
        }
        close(lst);
        _exit(0);
    }
    close(lst);

    unsigned char storage[8192];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.host = "127.0.0.1";
    cfg.port = port;
    cfg.connect_timeout_ms = 250u;
    cfg.allow_none_auth = true;
    cfg.auth_mode = FARSEE_AUTH_MODE_VNC;

    rfb_error e = rfb_session_connect_classic(s, &cfg);
    RFB_CHECK_EQ_INT(e, RFB_ERR_TIMEOUT);
    rfb_session_destroy(s);
    (void)kill(pid, SIGTERM);
    int st = 0;
    (void)waitpid(pid, &st, 0);
}

RFB_TEST(rfb_session, connect_classic__borrowed_tcp_fd__times_out_and_stays_open)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    RFB_CHECK(listener >= 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    RFB_CHECK(bind(listener, (struct sockaddr *)&address, sizeof address) == 0);
    RFB_CHECK(listen(listener, 1) == 0);
    socklen_t length = sizeof address;
    RFB_CHECK(getsockname(listener, (struct sockaddr *)&address, &length) == 0);

    int client = socket(AF_INET, SOCK_STREAM, 0);
    RFB_CHECK(client >= 0);
    RFB_CHECK(connect(client, (struct sockaddr *)&address, sizeof address) == 0);
    int server = accept(listener, NULL, NULL);
    RFB_CHECK(server >= 0);
    close(listener);

    unsigned char storage[8192];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    rfb_session_clear(session);
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.use_connected_fd = true;
    config.connected_fd = client;
    config.connect_timeout_ms = 50u;
    config.allow_none_auth = true;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;

    RFB_CHECK_EQ_INT(rfb_session_connect_classic(session, &config),
                     RFB_ERR_TIMEOUT);
    int nodelay = 0;
    socklen_t nodelay_length = (socklen_t)sizeof nodelay;
    RFB_CHECK_EQ_INT(getsockopt(client, IPPROTO_TCP, TCP_NODELAY, &nodelay,
                                &nodelay_length), 0);
    RFB_CHECK(nodelay != 0);
    rfb_session_destroy(session);
    RFB_CHECK(fcntl(client, F_GETFD) >= 0);
    RFB_CHECK_EQ_INT(close(client), 0);

    struct pollfd peer_poll;
    memset(&peer_poll, 0, sizeof peer_poll);
    peer_poll.fd = server;
    peer_poll.events = POLLIN | POLLHUP;
    RFB_CHECK_EQ_INT(poll(&peer_poll, 1, 1000), 1);
    uint8_t byte = 0u;
    RFB_CHECK_EQ_INT((int)recv(server, &byte, 1u, 0), 0);
    RFB_CHECK_EQ_INT(close(server), 0);
}

static bool make_connected_tcp_pair(int *out_client, int *out_server)
{
    if (out_client == NULL || out_server == NULL) {
        return false;
    }
    *out_client = -1;
    *out_server = -1;
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return false;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    socklen_t length = (socklen_t)sizeof address;
    int client = -1;
    int server = -1;
    bool ok = bind(listener, (struct sockaddr *)&address, sizeof address) == 0 &&
              listen(listener, 1) == 0 &&
              getsockname(listener, (struct sockaddr *)&address, &length) == 0;
    if (ok) {
        client = socket(AF_INET, SOCK_STREAM, 0);
        ok = client >= 0 &&
             connect(client, (struct sockaddr *)&address, sizeof address) == 0;
    }
    if (ok) {
        server = accept(listener, NULL, NULL);
        ok = server >= 0;
    }
    (void)close(listener);
    if (!ok) {
        if (client >= 0) {
            (void)close(client);
        }
        if (server >= 0) {
            (void)close(server);
        }
        return false;
    }
    *out_client = client;
    *out_server = server;
    return true;
}

static rfb_session_config connected_config_with_credentials(
    int connected_fd, const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len)
{
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.use_connected_fd = true;
    config.connected_fd = connected_fd;
    config.username = username;
    config.username_len = username_len;
    config.password = password;
    config.password_len = password_len;
    config.connect_timeout_ms = 50u;
    config.allow_none_auth = true;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;
    return config;
}

static void check_session_credentials_forgotten(const rfb_session *session)
{
    RFB_CHECK(session->cfg.username == NULL);
    RFB_CHECK_EQ_UINT(session->cfg.username_len, 0u);
    RFB_CHECK(session->cfg.password == NULL);
    RFB_CHECK_EQ_UINT(session->cfg.password_len, 0u);
}

RFB_TEST(rfb_session, connect_classic__failure_forgets_borrowed_credentials)
{
    int client = -1;
    int server = -1;
    RFB_CHECK(make_connected_tcp_pair(&client, &server));
    static const uint8_t username[] = "user";
    static const uint8_t password[] = "password";
    rfb_session_config config = connected_config_with_credentials(
        client, username, sizeof username - 1u,
        password, sizeof password - 1u);

    unsigned char storage[8192];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    rfb_session_clear(session);
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(session, &config),
                     RFB_ERR_TIMEOUT);
    check_session_credentials_forgotten(session);

    rfb_session_destroy(session);
    RFB_CHECK_EQ_INT(close(client), 0);
    RFB_CHECK_EQ_INT(close(server), 0);
}

RFB_TEST(rfb_session,
         session_connect__coalesced_classic_success_forgets_credentials)
{
    int client = -1;
    int server = -1;
    RFB_CHECK(make_connected_tcp_pair(&client, &server));
    static const uint8_t server_wire[] = {
        'R', 'F', 'B', ' ', '0', '0', '3', '.', '0', '0', '8', '\n',
        0x01, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x01,
        0x20, 0x18, 0x00, 0x01,
        0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
        0x10, 0x08, 0x00,
        0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    RFB_CHECK_EQ_INT((int)send(server, server_wire, sizeof server_wire, 0),
                     (int)sizeof server_wire);
    static const uint8_t username[] = "user";
    static const uint8_t password[] = "password";
    rfb_session_config config = connected_config_with_credentials(
        client, username, sizeof username - 1u,
        password, sizeof password - 1u);

    unsigned char storage[8192];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    rfb_session_clear(session);
    RFB_CHECK_EQ_INT(rfb_session_connect(session, &config), RFB_OK);
    check_session_credentials_forgotten(session);

    rfb_session_destroy(session);
    RFB_CHECK_EQ_INT(close(client), 0);
    RFB_CHECK_EQ_INT(close(server), 0);
}

RFB_TEST(rfb_session, session_connect__apple_failure_forgets_credentials)
{
    int client = -1;
    int server = -1;
    RFB_CHECK(make_connected_tcp_pair(&client, &server));
    static const uint8_t apple_banner[] = "RFB 003.889\n";
    RFB_CHECK_EQ_INT((int)send(server, apple_banner,
                               sizeof apple_banner - 1u, 0),
                     (int)(sizeof apple_banner - 1u));
    static const uint8_t username[] = "user";
    static const uint8_t password[] = "password";
    rfb_session_config config = connected_config_with_credentials(
        client, username, sizeof username - 1u,
        password, sizeof password - 1u);
    config.auth_mode = FARSEE_AUTH_MODE_APPLE;

    unsigned char storage[8192];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    rfb_session_clear(session);
    RFB_CHECK(rfb_session_connect(session, &config) != RFB_OK);
    check_session_credentials_forgotten(session);

    rfb_session_destroy(session);
    RFB_CHECK_EQ_INT(close(client), 0);
    RFB_CHECK_EQ_INT(close(server), 0);
}

RFB_TEST(rfb_session, sample_link__connected_session__publishes_rx_counter)
{
    int client = -1;
    int server = -1;
    RFB_CHECK(make_connected_tcp_pair(&client, &server));

    unsigned char storage[8192];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    rfb_session_clear(session);
    RFB_CHECK(rfb_session_test_attach_connected_fd(session, client));
    farsee_atomic_u64_store(&session->sock.rx_bytes, 37u);

    rfb_session_sample_link(session);
    uint64_t rx = 0u;
    bool have_rx = false;
    rfb_session_link_snapshot(session, NULL, NULL, &rx, &have_rx);
    RFB_CHECK(have_rx);
    RFB_CHECK_EQ_UINT(rx, 37u);

    rfb_session_destroy(session);
    RFB_CHECK_EQ_INT(close(server), 0);
}

static void check_ambiguous_connected_config(const char *host, uint16_t port)
{
    int client = -1;
    int server = -1;
    RFB_CHECK(make_connected_tcp_pair(&client, &server));
    unsigned char storage[8192];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    rfb_session_clear(session);
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.host = host;
    config.port = port;
    config.use_connected_fd = true;
    config.connected_fd = client;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;

    RFB_CHECK_EQ_INT(rfb_session_connect_classic(session, &config),
                     RFB_ERR_INTERNAL);
    rfb_session_destroy(session);
    RFB_CHECK(fcntl(client, F_GETFD) >= 0);
    struct pollfd peer_poll;
    memset(&peer_poll, 0, sizeof peer_poll);
    peer_poll.fd = server;
    peer_poll.events = POLLIN | POLLHUP;
    RFB_CHECK_EQ_INT(poll(&peer_poll, 1, 0), 0);
    RFB_CHECK_EQ_INT(close(client), 0);
    RFB_CHECK_EQ_INT(close(server), 0);
}

RFB_TEST(rfb_session, connect_classic__borrowed_tcp_with_host__rejected_before_io)
{
    check_ambiguous_connected_config("127.0.0.1", 0u);
}

RFB_TEST(rfb_session, connect_classic__borrowed_tcp_with_port__rejected_before_io)
{
    check_ambiguous_connected_config(NULL, 5900u);
}

RFB_TEST(rfb_session, connect_classic__negative_borrowed_fd__rejected)
{
    unsigned char storage[8192];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    rfb_session_clear(session);
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.use_connected_fd = true;
    config.connected_fd = -1;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(session, &config),
                     RFB_ERR_INTERNAL);
    rfb_session_destroy(session);
}

RFB_TEST(rfb_session, connect_classic__borrowed_tcp_listener__rejected_and_stays_open)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    RFB_CHECK(listener >= 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    RFB_CHECK(bind(listener, (struct sockaddr *)&address, sizeof address) == 0);
    RFB_CHECK(listen(listener, 1) == 0);

    unsigned char storage[8192];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    rfb_session_clear(session);
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.use_connected_fd = true;
    config.connected_fd = listener;
    config.connect_timeout_ms = 50u;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;

    RFB_CHECK_EQ_INT(rfb_session_connect_classic(session, &config),
                     RFB_ERR_PROTOCOL);
    rfb_session_destroy(session);
    RFB_CHECK(fcntl(listener, F_GETFD) >= 0);
    RFB_CHECK_EQ_INT(close(listener), 0);
}

RFB_TEST(rfb_session, connect_classic__borrowed_unix_fd__rejected)
{
    int pair[2];
    RFB_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    unsigned char storage[8192];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    rfb_session_clear(session);
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.use_connected_fd = true;
    config.connected_fd = pair[0];
    config.connect_timeout_ms = 50u;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(session, &config),
                     RFB_ERR_PROTOCOL);
    rfb_session_destroy(session);
    RFB_CHECK(fcntl(pair[0], F_GETFD) >= 0);
    RFB_CHECK_EQ_INT(close(pair[0]), 0);
    RFB_CHECK_EQ_INT(close(pair[1]), 0);
}

RFB_TEST(rfb_session, connect_classic__borrowed_regular_fd__rejected_and_stays_open)
{
    char path[] = "/tmp/farsee-connected-fd-XXXXXX";
    int file = mkstemp(path);
    RFB_CHECK(file >= 0);
    RFB_CHECK_EQ_INT(unlink(path), 0);

    unsigned char storage[8192];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    rfb_session_clear(session);
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.use_connected_fd = true;
    config.connected_fd = file;
    config.connect_timeout_ms = 50u;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;

    RFB_CHECK_EQ_INT(rfb_session_connect_classic(session, &config),
                     RFB_ERR_PROTOCOL);
    rfb_session_destroy(session);
    RFB_CHECK(fcntl(file, F_GETFD) >= 0);
    RFB_CHECK_EQ_INT(close(file), 0);
}
