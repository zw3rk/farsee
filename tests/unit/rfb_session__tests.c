// SPDX-License-Identifier: Apache-2.0
//
// Classic RFB session — null-safety / config gate tests.
// Full connect paths are covered by lifecycle_integration (TCP).
//
// P1 contract: session publishes frames only (slot). App owns
// open/present/close of any presenter (dump/null/kitty).

#include "rfb_test.h"
#include "farsee/rfb_session.h"
#include "farsee/error.h"
#include "farsee/allocator.h"
#include "farsee/farsee_frame_slot.h"
#include "farsee/farsee_display.h"
#include "farsee/presenter.h"
#include "farsee/framebuffer.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

RFB_TEST(rfb_session, session__size__is_nonzero)
{
    RFB_CHECK(rfb_session_size() >= sizeof(void *));
}

// P1: rfb_session_config is slot-only for frames (no presenter field).
// Designated init without a presenter member must compile; slot is the
// publish path. Re-adding cfg.presenter would break this ownership model.
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
    // Config has no presenter: zero-init must not invent one; only slot.
    RFB_CHECK(cfg.cmds == NULL);

    farsee_frame_slot_destroy(&slot);
}

// P1: destroy never opens/closes a presenter. Local presenter close_count
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

// P1 ownership model: publish → slot; app acquires and presents (dump).
// Mirrors rfb_live ST dump path without going through a live connect.
RFB_TEST(rfb_session, publish_then_app_present__dump_writes_rgba)
{
    const char *path = "/tmp/farsee_session_publish_dump.rgba";
    (void)unlink(path);

    uint8_t pixels[4 * 2 * 2];
    for (size_t i = 0; i < sizeof pixels; i++) {
        pixels[i] = (uint8_t)(i + 1u);
    }

    farsee_frame_slot slot;
    memset(&slot, 0, sizeof slot);
    RFB_CHECK(farsee_frame_slot_init(&slot));
    RFB_CHECK(farsee_frame_slot_publish(&slot, pixels, 2, 2, 8,
                                       FARSEE_PIXEL_RGBA8888));

    farsee_frame_view v;
    memset(&v, 0, sizeof v);
    RFB_CHECK(farsee_frame_slot_acquire(&slot, &v));
    RFB_CHECK(v.pixels != NULL);
    RFB_CHECK_EQ_UINT(v.w, 2u);
    RFB_CHECK_EQ_UINT(v.h, 2u);

    rfb_framebuffer fb;
    memset(&fb, 0, sizeof fb);
    fb.rgba = (uint8_t *)(uintptr_t)v.pixels;
    fb.width = v.w;
    fb.height = v.h;
    fb.stride = v.stride;
    fb.generation = v.gen;

    rfb_presenter_dump dump;
    rfb_presenter_dump_init(&dump, path, false);
    rfb_presenter p = {.ops = &rfb_presenter_dump_ops, .ctx = &dump};
    RFB_CHECK_EQ_INT(rfb_presenter_open(&p, &fb), 0);
    RFB_CHECK_EQ_INT(rfb_presenter_present(&p, &fb, NULL), 0);
    RFB_CHECK_EQ_INT(dump.present_count, 1);
    rfb_presenter_close(&p);
    farsee_frame_slot_release(&slot, &v);

    FILE *f = fopen(path, "rb");
    RFB_CHECK(f != NULL);
    uint8_t got[sizeof pixels];
    size_t n = fread(got, 1, sizeof got, f);
    fclose(f);
    (void)unlink(path);
    RFB_CHECK_EQ_UINT((unsigned)n, (unsigned)sizeof pixels);
    RFB_CHECK(memcmp(got, pixels, sizeof pixels) == 0);

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

// loop r1 T7: NULL session snapshot claims nothing.
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

// loop r3: snapshot_ex NULL session zeros have_rate.
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

// loop r1 T7: sample_link on inactive session is a no-op (no crash).
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

// Residual T9: silent peer after TCP → connect TIMEOUT within budget.
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
