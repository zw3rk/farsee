// SPDX-License-Identifier: Apache-2.0
//
// live_shell characterization: layout packing, mouse map, demux feed → ops.
// No openpty; pure bytes and fake operations.

#include "rfb_test.h"
#include "farsee/allocator.h"
#include "farsee/kitty_tile.h"
#include "farsee/buffer.h"
#include "app/live_shell.h"
#include "farsee/cli_target.h"
#include "farsee/farsee_input.h"
#include "farsee/normalized_input.h"
#include "farsee/farsee_thread.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// --- link status pure formatter / rate window ------------------------------

RFB_TEST(live_shell, format_link_extra__scale_only)
{
    char buf[128];
    farsee_live_shell_format_link_extra(buf, sizeof buf, 50u, 0u, false, 0u,
                                        false);
    RFB_CHECK(strstr(buf, "50%") != NULL);
    RFB_CHECK(strstr(buf, "ms") == NULL);
    RFB_CHECK(strstr(buf, "KiB") == NULL);
}

RFB_TEST(live_shell, format_link_extra__rtt_and_rate)
{
    char buf[128];
    farsee_live_shell_format_link_extra(buf, sizeof buf, 100u, 14u, true, 340u,
                                        true);
    RFB_CHECK(strstr(buf, "100%") != NULL);
    RFB_CHECK(strstr(buf, "14ms") != NULL);
    RFB_CHECK(strstr(buf, "340KiB/s") != NULL);
}

RFB_TEST(live_shell, format_link_extra__null_buf_safe)
{
    farsee_live_shell_format_link_extra(NULL, 10u, 50u, 1u, true, 1u, true);
    char buf[8];
    farsee_live_shell_format_link_extra(buf, 0u, 50u, 1u, true, 1u, true);
}

RFB_TEST(live_shell, link_rate_sample__window_latch)
{
    farsee_link_rate r;
    memset(&r, 0, sizeof r);
    // First sample: seed only.
    farsee_link_rate_sample(&r, 0u, true, /*now=*/1000u, /*window=*/250u);
    RFB_CHECK(!r.have_rate);
    RFB_CHECK(r.have_prev);
    // Within window: still no rate.
    farsee_link_rate_sample(&r, 102400u, true, 1100u, 250u);
    RFB_CHECK(!r.have_rate);
    // Full window with +102400 bytes over 250ms → 400 KiB/s
    // 102400 * 1000 / (250 * 1024) = 400
    farsee_link_rate_sample(&r, 102400u, true, 1250u, 250u);
    RFB_CHECK(r.have_rate);
    RFB_CHECK_EQ_UINT(r.latched_kib_s, 400u);
    // Next call mid-window keeps latch.
    farsee_link_rate_sample(&r, 200000u, true, 1300u, 250u);
    RFB_CHECK_EQ_UINT(r.latched_kib_s, 400u);
    // Idle full window → 0
    farsee_link_rate_sample(&r, 102400u, true, 1500u, 250u);
    RFB_CHECK(r.have_rate);
    RFB_CHECK_EQ_UINT(r.latched_kib_s, 0u);
}

RFB_TEST(live_shell, link_rate_sample__no_rx_clears)
{
    farsee_link_rate r;
    memset(&r, 0, sizeof r);
    farsee_link_rate_sample(&r, 1000u, true, 0u, 250u);
    farsee_link_rate_sample(&r, 2000u, true, 250u, 250u);
    RFB_CHECK(r.have_rate);
    farsee_link_rate_sample(&r, 0u, false, 500u, 250u);
    RFB_CHECK(!r.have_rate);
    RFB_CHECK(!r.have_prev);
}

// A backward clock step re-seeds without latching a garbage rate.
RFB_TEST(live_shell, link_rate_sample__clock_backwards__reseeds_without_rate)
{
    farsee_link_rate r;
    memset(&r, 0, sizeof r);
    farsee_link_rate_sample(&r, 0u, true, 1000u, 250u);
    farsee_link_rate_sample(&r, 102400u, true, 1250u, 250u);
    RFB_CHECK(r.have_rate);
    RFB_CHECK_EQ_UINT(r.latched_kib_s, 400u);
    // Clock goes backwards: re-seed, clear rate.
    farsee_link_rate_sample(&r, 200000u, true, 500u, 250u);
    RFB_CHECK(r.have_prev);
    RFB_CHECK(!r.have_rate);
    RFB_CHECK_EQ_UINT(r.prev_ms, 500u);
    RFB_CHECK_EQ_UINT(r.prev_rx, 200000u);
}

// window_ms == 0 uses FARSEE_LINK_RATE_WINDOW_MS default.
RFB_TEST(live_shell, link_rate_sample__zero_window__uses_default)
{
    farsee_link_rate r;
    memset(&r, 0, sizeof r);
    farsee_link_rate_sample(&r, 0u, true, 0u, 0u);
    RFB_CHECK(r.have_prev);
    RFB_CHECK(!r.have_rate);
    // Default window is 250 ms.
    farsee_link_rate_sample(&r, 102400u, true, 250u, 0u);
    RFB_CHECK(r.have_rate);
    RFB_CHECK_EQ_UINT(r.latched_kib_s, 400u);
}

// The snprintf length clamp never exceeds cap-1.
RFB_TEST(live_shell, clamp_snprintf_len__overflow_and_exact)
{
    RFB_CHECK_EQ_UINT(farsee_live_shell_clamp_snprintf_len(-1, 384u), 0u);
    RFB_CHECK_EQ_UINT(farsee_live_shell_clamp_snprintf_len(0, 384u), 0u);
    RFB_CHECK_EQ_UINT(farsee_live_shell_clamp_snprintf_len(100, 384u), 100u);
    RFB_CHECK_EQ_UINT(farsee_live_shell_clamp_snprintf_len(383, 384u), 383u);
    RFB_CHECK_EQ_UINT(farsee_live_shell_clamp_snprintf_len(384, 384u), 383u);
    RFB_CHECK_EQ_UINT(farsee_live_shell_clamp_snprintf_len(500, 384u), 383u);
    RFB_CHECK_EQ_UINT(farsee_live_shell_clamp_snprintf_len(10, 0u), 0u);
    RFB_CHECK_EQ_UINT(farsee_live_shell_clamp_snprintf_len(1, 1u), 0u);
}

// have_rtt with 1 ms is never formatted as a missing field.
RFB_TEST(live_shell, format_link_extra__one_ms_rtt)
{
    char buf[128];
    farsee_live_shell_format_link_extra(buf, sizeof buf, 50u, 1u, true, 0u,
                                        false);
    RFB_CHECK(strstr(buf, "1ms") != NULL);
    RFB_CHECK(strstr(buf, "0ms") == NULL);
}

// The producer rate step packs seed → rate → idle zero.
RFB_TEST(live_shell, link_rate_step__window_timeline__seed_then_rate_then_idle)
{
    farsee_link_rate r;
    memset(&r, 0, sizeof r);
    uint64_t p = farsee_link_rate_step(&r, 0u, true, 1000u, 250u);
    uint32_t kib = 1u;
    bool have = true;
    farsee_link_rate_unpack(p, &kib, &have);
    RFB_CHECK(!have); // seed only
    p = farsee_link_rate_step(&r, 102400u, true, 1250u, 250u);
    farsee_link_rate_unpack(p, &kib, &have);
    RFB_CHECK(have);
    RFB_CHECK_EQ_UINT(kib, 400u);
    // Idle full window → 0 KiB/s still have_rate.
    p = farsee_link_rate_step(&r, 102400u, true, 1500u, 250u);
    farsee_link_rate_unpack(p, &kib, &have);
    RFB_CHECK(have);
    RFB_CHECK_EQ_UINT(kib, 0u);
    p = farsee_link_rate_step(NULL, 0u, true, 0u, 250u);
    RFB_CHECK_EQ_UINT(p, 0u);
    p = farsee_link_rate_step(&r, 0u, false, 2000u, 250u);
    farsee_link_rate_unpack(p, &kib, &have);
    RFB_CHECK(!have);
}

// A truncated buffer gets a trailing SGR reset.
RFB_TEST(live_shell, ensure_ansi_reset__truncation__ends_with_reset)
{
    char buf[16];
    memset(buf, 'x', sizeof buf);
    buf[15] = '\0';
    size_t n = 15u; // cap-1 truncated
    farsee_live_shell_ensure_ansi_reset(buf, &n, sizeof buf);
    RFB_CHECK(n == 15u);
    RFB_CHECK(memcmp(buf + 11, "\033[0m", 4) == 0);
}

// An out-of-contract length fails closed and emits nothing.
RFB_TEST(live_shell, ensure_ansi_reset__len_past_cap__emits_nothing)
{
    char buf[8];
    memset(buf, 'y', sizeof buf);
    size_t n = 100u;
    farsee_live_shell_ensure_ansi_reset(buf, &n, sizeof buf);
    RFB_CHECK_EQ_UINT(n, 0u);
    RFB_CHECK(buf[0] == 'y'); // buffer unmodified
}

// probe_winsize is null-safe.
RFB_TEST(live_shell, probe_winsize__null_out__false)
{
    RFB_CHECK(!farsee_live_shell_probe_winsize(-1, NULL, NULL, NULL, NULL));
}

// The leader-arm state is atomically readable.
RFB_TEST(live_shell, leader_armed__atomic_readable)
{
    farsee_live_shell s;
    farsee_live_shell_init(&s, NULL, 2u);
    RFB_CHECK(!farsee_live_demux_leader_is_armed(&s.demux));
    farsee_atomic_int_store(&s.demux.leader_armed, 1);
    RFB_CHECK(farsee_live_demux_leader_is_armed(&s.demux));
}

// View-scale and terminal-geometry atomics round-trip.
RFB_TEST(live_shell, view_scale_term_geom__atomic_roundtrip)
{
    farsee_live_shell s;
    farsee_live_shell_init(&s, NULL, 1u);
    farsee_live_shell_set_view_scale(&s, 75u);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&s), 75u);
    farsee_live_shell_set_term_geom(&s, 120u, 40u, 960u, 640u);
    uint16_t c = 0, r = 0, pw = 0, ph = 0;
    RFB_CHECK(farsee_live_shell_get_term_geom(&s, &c, &r, &pw, &ph));
    RFB_CHECK_EQ_UINT(c, 120u);
    RFB_CHECK_EQ_UINT(r, 40u);
    RFB_CHECK_EQ_UINT(pw, 960u);
    RFB_CHECK_EQ_UINT(ph, 640u);
}

// write_all returns the written length so callers can detect a short path.
RFB_TEST(live_shell, write_all__invalid_fd__returns_zero)
{
    RFB_CHECK_EQ_UINT(farsee_live_shell_write_all(-1, "x", 1u), 0u);
    RFB_CHECK_EQ_UINT(farsee_live_shell_write_all(STDOUT_FILENO, NULL, 1u),
                      0u);
    RFB_CHECK_EQ_UINT(farsee_live_shell_write_all(STDOUT_FILENO, "x", 0u),
                      0u);
}

RFB_TEST(live_shell, write_all__pipe_receives_exact_bytes)
{
    int pfd[2];
    if (pipe(pfd) != 0) {
        RFB_CHECK(false);
        return;
    }
    static const char payload[] = "farsee-status";
    char received[sizeof payload] = {0};

    RFB_CHECK_EQ_UINT(
        farsee_live_shell_write_all(pfd[1], payload, sizeof payload - 1u),
        sizeof payload - 1u);
    RFB_CHECK_EQ_INT((int)read(pfd[0], received, sizeof payload - 1u),
                     (int)(sizeof payload - 1u));
    RFB_CHECK_MEM_EQ(received, payload, sizeof payload - 1u);

    close(pfd[0]);
    close(pfd[1]);
}

// A non-truncated buffer remains intact.
RFB_TEST(live_shell, ensure_ansi_reset__not_truncated__leaves_intact)
{
    char buf[16];
    memset(buf, 'z', sizeof buf);
    size_t n = 8u;
    farsee_live_shell_ensure_ansi_reset(buf, &n, sizeof buf);
    RFB_CHECK(n == 8u);
    RFB_CHECK(buf[0] == 'z' && buf[7] == 'z');
}

// link_rate_pack roundtrip (producer-published rate).
RFB_TEST(live_shell, link_rate_pack__roundtrip)
{
    const uint64_t p = farsee_link_rate_pack(400u, true);
    uint32_t kib = 0u;
    bool have = false;
    farsee_link_rate_unpack(p, &kib, &have);
    RFB_CHECK(have);
    RFB_CHECK_EQ_UINT(kib, 400u);
    farsee_link_rate_unpack(0u, &kib, &have);
    RFB_CHECK(!have);
}

typedef struct shell_rec {
    int nkeys;
    int nptr;
    int nquit;
    int nzoom;
    int nsusp;
    int nlayout;
    int last_zoom_delta;
    int32_t last_x;
    int32_t last_y;
    uint8_t last_buttons;
    uint32_t last_keysym;
    bool last_key_down;
} shell_rec;

static void rec_key(void *u, const rfb_norm_key *nk)
{
    shell_rec *r = (shell_rec *)u;
    if (r == NULL || nk == NULL) {
        return;
    }
    r->nkeys++;
    r->last_keysym = nk->keysym;
    r->last_key_down = nk->down;
}

static bool rec_ptr(void *u, int32_t x, int32_t y, uint8_t buttons, int wv,
                    int wh)
{
    shell_rec *r = (shell_rec *)u;
    (void)wv;
    (void)wh;
    if (r == NULL) {
        return false;
    }
    r->nptr++;
    r->last_x = x;
    r->last_y = y;
    r->last_buttons = buttons;
    return true;
}

// When injection is refused, last_buttons must not advance.
static bool rec_ptr_refuse(void *u, int32_t x, int32_t y, uint8_t buttons,
                           int wv, int wh)
{
    (void)u;
    (void)x;
    (void)y;
    (void)buttons;
    (void)wv;
    (void)wh;
    return false;
}

static void rec_quit(void *u)
{
    shell_rec *r = (shell_rec *)u;
    if (r != NULL) {
        r->nquit++;
    }
}

static void rec_zoom(void *u, int delta)
{
    shell_rec *r = (shell_rec *)u;
    if (r != NULL) {
        r->nzoom++;
        r->last_zoom_delta = delta;
    }
}

static void rec_susp(void *u)
{
    shell_rec *r = (shell_rec *)u;
    if (r != NULL) {
        r->nsusp++;
    }
}

static void rec_layout(void *u)
{
    shell_rec *r = (shell_rec *)u;
    if (r != NULL) {
        r->nlayout++;
    }
}

static void shell_bind(farsee_live_shell *s, shell_rec *r,
                       farsee_live_shell_ops *ops)
{
    memset(r, 0, sizeof(*r));
    memset(ops, 0, sizeof(*ops));
    ops->inject_key = rec_key;
    ops->inject_pointer = rec_ptr;
    ops->request_quit = rec_quit;
    ops->zoom = rec_zoom;
    ops->suspend = rec_susp;
    ops->on_layout_applied = rec_layout;
    s->ops = ops;
    s->ops_user = r;
}

RFB_TEST(live_shell, init_and_layout_fit)
{
    farsee_live_shell s;
    farsee_live_shell_init(&s, NULL, /*status_rows=*/2u);
    RFB_CHECK(s.status_rows == 2u);
    RFB_CHECK(s.demux.leader.has_c0);
    s.desk_w = 1920;
    s.desk_h = 1080;
    s.term_cols = 80;
    s.term_rows = 24;
    s.term_pw = 800;
    s.term_ph = 480;
    farsee_live_shell_set_view_scale(&s, 100u);
    s.layout_active = true;
    bool ch = farsee_live_shell_refresh_layout(&s, /*apply_kitty=*/false);
    RFB_CHECK(ch); // first compute
    RFB_CHECK(s.place_cols > 0u);
    RFB_CHECK(s.place_rows > 0u);
    RFB_CHECK(s.place_rows + s.status_rows <= s.term_rows ||
              s.term_rows <= s.status_rows);
    RFB_CHECK(farsee_atomic_int_load(&s.log_row) >= 1);
}

// Zoom/layout arms force_repaint so present re-shows the same generation.
RFB_TEST(live_shell, refresh_layout_apply_kitty__sets_force_repaint)
{
    farsee_live_shell s;
    farsee_atomic_int force = 0;
    farsee_live_shell_init(&s, NULL, 1u);
    s.desk_w = 800;
    s.desk_h = 600;
    s.term_cols = 80;
    s.term_rows = 24;
    s.term_pw = 800;
    s.term_ph = 480;
    farsee_live_shell_set_view_scale(&s, 100u);
    s.layout_active = true;
    s.force_repaint = &force;
    farsee_atomic_int_store(&force, 0);
    (void)farsee_live_shell_refresh_layout(&s, /*apply_kitty=*/true);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&force), 1);

    farsee_atomic_int_store(&force, 0);
    farsee_live_shell_set_view_scale(&s, 50u);
    (void)farsee_live_shell_refresh_layout(&s, /*apply_kitty=*/true);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&force), 1);
    RFB_CHECK(s.place_cols > 0u);
}

// apply_kitty with an attached Kitty presenter and a real io_mu must not
// self-deadlock
// by nesting kitty_pending under shell_io_lock.
RFB_TEST(live_shell, refresh_layout__with_io_mu_and_kitty__no_deadlock)
{
    farsee_live_shell s;
    farsee_atomic_int force = 0;
    farsee_live_shell_init(&s, NULL, 1u);
    s.desk_w = 800;
    s.desk_h = 600;
    s.term_cols = 80;
    s.term_rows = 24;
    s.term_pw = 800;
    s.term_ph = 480;
    farsee_live_shell_set_view_scale(&s, 100u);
    s.layout_active = true;
    s.force_repaint = &force;

    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    // Non-empty pending → CSI path skipped; still must return (no hang).
    static const uint8_t apc[] = "\033_Gx\033\\";
    RFB_CHECK(rfb_buffer_append(&out, apc, sizeof(apc) - 1u) == RFB_OK);

    rfb_kitty_tile tile;
    memset(&tile, 0, sizeof tile);
    tile.out = &out;
    s.kitty = &tile;
    s.io_mu = farsee_mutex_create();
    RFB_CHECK(s.io_mu != NULL);

    (void)farsee_live_shell_refresh_layout(&s, /*apply_kitty=*/true);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&force), 1);

    // Empty out: CSI path may run; still must not deadlock.
    rfb_buffer_clear(&out);
    farsee_atomic_int_store(&force, 0);
    farsee_live_shell_set_view_scale(&s, 50u);
    (void)farsee_live_shell_refresh_layout(&s, /*apply_kitty=*/true);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&force), 1);

    farsee_mutex_destroy(&s.io_mu);
    s.kitty = NULL;
    rfb_buffer_destroy(&out);
}

RFB_TEST(live_shell, mouse_to_desktop_inside_place)
{
    farsee_live_shell s;
    farsee_live_shell_init(&s, NULL, 1u);
    s.desk_w = 100;
    s.desk_h = 100;
    s.term_cols = 40;
    s.term_rows = 20;
    s.term_pw = 400;
    s.term_ph = 400;
    farsee_live_shell_set_view_scale(&s, 100u);
    (void)farsee_live_shell_refresh_layout(&s, false);
    RFB_CHECK(s.place_cols > 0u);

    int32_t x = -1;
    int32_t y = -1;
    // Cell (1,1) is top-left of image after home — should map near 0,0.
    bool ok = farsee_live_shell_mouse_to_desktop(&s, 1, 1, &x, &y, NULL);
    RFB_CHECK(ok);
    RFB_CHECK(x >= 0);
    RFB_CHECK(y >= 0);
    RFB_CHECK(x < (int32_t)s.desk_w);
    RFB_CHECK(y < (int32_t)s.desk_h);
}

RFB_TEST(live_shell, feed_leader_q_requests_quit)
{
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec r;
    farsee_live_shell_init(&s, NULL, 1u);
    shell_bind(&s, &r, &ops);

    // C-] then 'q' as legacy C0 leader + plain second byte.
    const uint8_t seq[] = {0x1d, 'q'}; // GS = default C-]
    farsee_live_shell_feed_tty(&s, seq, sizeof seq, /*now=*/1000u);
    RFB_CHECK_EQ_INT(r.nquit, 1);
    RFB_CHECK(!farsee_live_demux_leader_is_armed(&s.demux));
}

RFB_TEST(live_shell, feed_leader_timeout_disarms)
{
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec r;
    farsee_live_shell_init(&s, NULL, 1u);
    shell_bind(&s, &r, &ops);

    const uint8_t arm[] = {0x1d};
    farsee_live_shell_feed_tty(&s, arm, 1, /*now=*/1000u);
    RFB_CHECK(farsee_live_demux_leader_is_armed(&s.demux));

    farsee_live_shell_tick_timeout(&s, 1000u + FARSEE_LIVE_LEADER_ARM_MS + 1u);
    RFB_CHECK(!farsee_live_demux_leader_is_armed(&s.demux));
    RFB_CHECK_EQ_INT(r.nquit, 0);
}

RFB_TEST(live_shell, feed_key_injects)
{
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec r;
    farsee_live_shell_init(&s, NULL, 1u);
    shell_bind(&s, &r, &ops);

    const uint8_t a[] = {'a'};
    farsee_live_shell_feed_tty(&s, a, 1, 0u);
    RFB_CHECK(r.nkeys >= 1);
    RFB_CHECK_EQ_UINT(r.last_keysym, (uint32_t)'a');
}

RFB_TEST(live_shell, view_only_suppresses_key_and_pointer)
{
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec r;
    farsee_live_shell_init(&s, NULL, 1u);
    shell_bind(&s, &r, &ops);
    s.view_only = true;
    s.desk_w = 100;
    s.desk_h = 100;
    s.term_cols = 40;
    s.term_rows = 20;
    farsee_live_shell_set_view_scale(&s, 100u);
    (void)farsee_live_shell_refresh_layout(&s, false);

    const uint8_t a[] = {'a'};
    farsee_live_shell_feed_tty(&s, a, 1, 0u);
    RFB_CHECK_EQ_INT(r.nkeys, 0);

    // SGR press left at cell 2,2 — suppressed.
    const char *sgr = "\033[<0;2;2M";
    farsee_live_shell_feed_tty(&s, (const uint8_t *)sgr, strlen(sgr), 0u);
    RFB_CHECK_EQ_INT(r.nptr, 0);
}

RFB_TEST(live_shell, leader_zoom_calls_ops)
{
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec r;
    farsee_live_shell_init(&s, NULL, 2u);
    shell_bind(&s, &r, &ops);
    s.show_zoom = true;

    const uint8_t seq[] = {0x1d, '+'};
    farsee_live_shell_feed_tty(&s, seq, sizeof seq, 1000u);
    RFB_CHECK_EQ_INT(r.nzoom, 1);
    RFB_CHECK(r.last_zoom_delta > 0);
}

// Shell policy: ops.zoom NULL means no view-scale mutation (status only).
// Protocols that support zoom supply ops.zoom (RFB + RDP Kitty place).
RFB_TEST(live_shell, zoom_null_ops_leaves_view_scale_unchanged)
{
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec r;
    farsee_live_shell_init(&s, NULL, 1u);
    memset(&r, 0, sizeof r);
    memset(&ops, 0, sizeof ops);
    ops.request_quit = rec_quit;
    // zoom intentionally NULL (RDP)
    s.ops = &ops;
    s.ops_user = &r;
    s.show_zoom = false;
    farsee_live_shell_set_view_scale(&s, 100u);
    s.desk_w = 800u;
    s.desk_h = 600u;
    s.term_cols = 80u;
    s.term_rows = 24u;
    s.layout_active = true;
    (void)farsee_live_shell_refresh_layout(&s, false);
    const uint32_t scale0 = farsee_live_shell_view_scale(&s);
    const uint32_t cols0 = s.place_cols;
    const uint32_t rows0 = s.place_rows;

    farsee_live_shell_do_leader_cmd(&s, RFB_LEADER_CMD_ZOOM_IN);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&s), scale0);
    RFB_CHECK_EQ_UINT(s.place_cols, cols0);
    RFB_CHECK_EQ_UINT(s.place_rows, rows0);
    RFB_CHECK_EQ_INT(r.nzoom, 0);

    farsee_live_shell_do_leader_cmd(&s, RFB_LEADER_CMD_ZOOM_OUT);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&s), scale0);
    RFB_CHECK_EQ_UINT(s.place_cols, cols0);
    RFB_CHECK_EQ_UINT(s.place_rows, rows0);
    RFB_CHECK_EQ_INT(r.nzoom, 0);
}

RFB_TEST(live_shell, zoom_bare_shell__changes_scale_and_clamps_at_limits)
{
    farsee_live_shell s;
    farsee_live_shell_init(&s, NULL, 1u);
    RFB_CHECK(s.ops == NULL);

    farsee_live_shell_set_view_scale(&s, 50u);
    farsee_live_shell_zoom(&s, (int)FARSEE_VIEW_SCALE_STEP_PCT);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&s),
                      50u + FARSEE_VIEW_SCALE_STEP_PCT);

    farsee_live_shell_set_view_scale(&s, FARSEE_VIEW_SCALE_MAX_PCT);
    farsee_live_shell_zoom(&s, (int)FARSEE_VIEW_SCALE_STEP_PCT);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&s),
                      FARSEE_VIEW_SCALE_MAX_PCT);

    farsee_live_shell_set_view_scale(&s, FARSEE_VIEW_SCALE_MIN_PCT);
    farsee_live_shell_zoom(&s, -(int)FARSEE_VIEW_SCALE_STEP_PCT);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&s),
                      FARSEE_VIEW_SCALE_MIN_PCT);
}

RFB_TEST(live_shell, leader_suspend_calls_ops)
{
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec r;
    farsee_live_shell_init(&s, NULL, 1u);
    shell_bind(&s, &r, &ops);
    s.show_suspend = true;

    const uint8_t seq[] = {0x1d, 'z'};
    farsee_live_shell_feed_tty(&s, seq, sizeof seq, 1000u);
    RFB_CHECK_EQ_INT(r.nsusp, 1);
}

// RDP product: both zoom and suspend ops active (C-] +/- and C-] z).
RFB_TEST(live_shell, leader_zoom_and_suspend_both_work)
{
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec r;
    farsee_live_shell_init(&s, NULL, 1u);
    shell_bind(&s, &r, &ops);
    s.show_zoom = true;
    s.show_suspend = true;

    const uint8_t zoom[] = {0x1d, '+'};
    farsee_live_shell_feed_tty(&s, zoom, sizeof zoom, 1000u);
    RFB_CHECK_EQ_INT(r.nzoom, 1);
    RFB_CHECK(r.last_zoom_delta > 0);

    const uint8_t susp[] = {0x1d, 'z'};
    farsee_live_shell_feed_tty(&s, susp, sizeof susp, 2000u);
    RFB_CHECK_EQ_INT(r.nsusp, 1);
}

RFB_TEST(live_shell, suspend_null_falls_back_to_quit)
{
    // Named RFB policy: no suspend → quit.
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec r;
    farsee_live_shell_init(&s, NULL, 2u);
    memset(&r, 0, sizeof r);
    memset(&ops, 0, sizeof ops);
    ops.request_quit = rec_quit;
    // suspend intentionally NULL
    s.ops = &ops;
    s.ops_user = &r;

    farsee_live_shell_do_leader_cmd(&s, RFB_LEADER_CMD_SUSPEND);
    RFB_CHECK_EQ_INT(r.nquit, 1);
}

RFB_TEST(live_shell, sgr_press_maps_buttons)
{
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec r;
    farsee_live_shell_init(&s, NULL, 1u);
    shell_bind(&s, &r, &ops);
    s.desk_w = 200;
    s.desk_h = 200;
    s.term_cols = 40;
    s.term_rows = 20;
    s.term_pw = 400;
    s.term_ph = 400;
    farsee_live_shell_set_view_scale(&s, 100u);
    (void)farsee_live_shell_refresh_layout(&s, false);

    const char *sgr = "\033[<0;2;2M";
    farsee_live_shell_feed_tty(&s, (const uint8_t *)sgr, strlen(sgr), 0u);
    RFB_CHECK(r.nptr >= 1);
    RFB_CHECK((r.last_buttons & (uint8_t)FARSEE_BUTTON_LEFT) != 0u);
}

// Arm O_NONBLOCK on a pipe stand-in; restore clears the flag.
// Uses a dedicated pipe fd (not real stdout) so the test never leaves the
// calling shell nonblocking if restore is skipped mid-run.
RFB_TEST(live_shell, stdio_nonblock_arm_restore__clears_flag)
{
    // Production path: arm STDOUT_FILENO then tty_guard_restore must clear
    // O_NONBLOCK. Save/restore real stdout around the test so the runner
    // is not left nonblocking. Skip if stdout is not open (filter harness).
    farsee_live_shell_tty_guard_restore();

    int fl0 = fcntl(STDOUT_FILENO, F_GETFL, 0);
    if (fl0 < 0) {
        RFB_CHECK(true); // nothing to exercise
        return;
    }
    const int saved_flags = fl0;
    // Ensure we start without O_NONBLOCK so arm has a change to make.
    RFB_CHECK(fcntl(STDOUT_FILENO, F_SETFL, fl0 & ~O_NONBLOCK) == 0);

    farsee_live_shell_stdio_nonblock_arm(STDOUT_FILENO);
    int fl_armed = fcntl(STDOUT_FILENO, F_GETFL, 0);
    RFB_CHECK(fl_armed >= 0);
    RFB_CHECK((fl_armed & O_NONBLOCK) != 0);

    farsee_live_shell_tty_guard_restore();
    int fl_after = fcntl(STDOUT_FILENO, F_GETFL, 0);
    RFB_CHECK(fl_after >= 0);
    RFB_CHECK((fl_after & O_NONBLOCK) == 0);

    // Put back whatever flags the process had before this test.
    (void)fcntl(STDOUT_FILENO, F_SETFL, saved_flags);
}

// An SGR press on the status row (outside the place) must not inject.
RFB_TEST(live_shell, sgr_outside_place__no_pointer_inject)
{
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec r;
    farsee_live_shell_init(&s, NULL, /*status_rows=*/2u);
    shell_bind(&s, &r, &ops);
    s.desk_w = 200;
    s.desk_h = 200;
    s.term_cols = 40;
    s.term_rows = 20;
    s.term_pw = 400;
    s.term_ph = 400;
    farsee_live_shell_set_view_scale(&s, 100u);
    s.want_mouse = true;
    s.mouse_enabled = true;
    (void)farsee_live_shell_refresh_layout(&s, false);
    RFB_CHECK(s.place_rows > 0u);

    // SGR 1016 pixel coords below place box (status band).
    const int cell_h = (int)(s.term_ph / s.term_rows);
    const int status_y = (int)s.place_rows * cell_h + cell_h + 1;
    char sgr[48];
    int n = snprintf(sgr, sizeof sgr, "\033[<0;10;%dM", status_y);
    RFB_CHECK(n > 0);
    farsee_live_shell_feed_tty(&s, (const uint8_t *)sgr, (size_t)n, 0u);
    RFB_CHECK_EQ_INT(r.nptr, 0);
}

// A press inside the place followed by a release on the status row emits
// mask 0 at the last desktop position.
RFB_TEST(live_shell, sgr_press_in_release_outside__emits_mask0)
{
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec r;
    farsee_live_shell_init(&s, NULL, /*status_rows=*/2u);
    shell_bind(&s, &r, &ops);
    s.desk_w = 200;
    s.desk_h = 200;
    s.term_cols = 40;
    s.term_rows = 20;
    s.term_pw = 400;
    s.term_ph = 400;
    farsee_live_shell_set_view_scale(&s, 100u);
    s.want_mouse = true;
    s.mouse_enabled = true;
    (void)farsee_live_shell_refresh_layout(&s, false);
    RFB_CHECK(s.place_rows > 0u);

    // Press left button inside place (SGR 1016 pixel mode near origin).
    const char *press = "\033[<0;5;5M";
    farsee_live_shell_feed_tty(&s, (const uint8_t *)press, strlen(press), 0u);
    RFB_CHECK(r.nptr >= 1);
    RFB_CHECK((r.last_buttons & (uint8_t)FARSEE_BUTTON_LEFT) != 0u);
    const int32_t desk_x = r.last_x;
    const int32_t desk_y = r.last_y;
    const int n_after_press = r.nptr;

    // Release on status band (outside place).
    const int cell_h = (int)(s.term_ph / s.term_rows);
    const int status_y = (int)s.place_rows * cell_h + cell_h + 1;
    char rel[48];
    int n = snprintf(rel, sizeof rel, "\033[<0;10;%dm", status_y);
    RFB_CHECK(n > 0);
    farsee_live_shell_feed_tty(&s, (const uint8_t *)rel, (size_t)n, 1u);
    RFB_CHECK_EQ_INT(r.nptr, n_after_press + 1);
    RFB_CHECK_EQ_INT(r.last_buttons, 0);
    RFB_CHECK_EQ_INT(r.last_x, desk_x);
    RFB_CHECK_EQ_INT(r.last_y, desk_y);
    RFB_CHECK_EQ_INT(s.last_buttons, 0);
}

// A refused injection must not clear last_buttons.
RFB_TEST(live_shell, sgr_release_outside__refuse_keeps_last_buttons)
{
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec r;
    farsee_live_shell_init(&s, NULL, /*status_rows=*/2u);
    shell_bind(&s, &r, &ops);
    s.desk_w = 200;
    s.desk_h = 200;
    s.term_cols = 40;
    s.term_rows = 20;
    s.term_pw = 400;
    s.term_ph = 400;
    farsee_live_shell_set_view_scale(&s, 100u);
    s.want_mouse = true;
    s.mouse_enabled = true;
    (void)farsee_live_shell_refresh_layout(&s, false);

    const char *press = "\033[<0;5;5M";
    farsee_live_shell_feed_tty(&s, (const uint8_t *)press, strlen(press), 0u);
    RFB_CHECK(s.last_buttons != 0u);

    // Subsequent injects refuse (queue full simulation).
    ops.inject_pointer = rec_ptr_refuse;
    const int cell_h = (int)(s.term_ph / s.term_rows);
    const int status_y = (int)s.place_rows * cell_h + cell_h + 1;
    char rel[48];
    int n = snprintf(rel, sizeof rel, "\033[<0;10;%dm", status_y);
    RFB_CHECK(n > 0);
    farsee_live_shell_feed_tty(&s, (const uint8_t *)rel, (size_t)n, 1u);
    // last_buttons must stay held so a later successful release can fire.
    RFB_CHECK(s.last_buttons != 0u);
}

// Record the desktop from "present" and apply it on the writer.
RFB_TEST(live_shell, pending_desk__note_then_apply)
{
    farsee_live_shell s;
    farsee_live_shell_init(&s, NULL, /*status_rows=*/2u);
    s.desk_w = 100;
    s.desk_h = 80;
    s.term_cols = 80;
    s.term_rows = 24;
    farsee_live_shell_set_view_scale(&s, 100u);
    (void)farsee_live_shell_refresh_layout(&s, false);

    farsee_live_shell_note_desk_size(&s, 320, 240);
    RFB_CHECK_EQ_UINT(s.desk_w, 100u); // not applied yet
    RFB_CHECK(farsee_live_shell_apply_pending_desk(&s, false));
    RFB_CHECK_EQ_UINT(s.desk_w, 320u);
    RFB_CHECK_EQ_UINT(s.desk_h, 240u);
    // Idempotent when already applied.
    RFB_CHECK(!farsee_live_shell_apply_pending_desk(&s, false));
}

// refresh_layout acquires io_mu; it must not require the caller to lock it.
RFB_TEST(live_shell, refresh_layout__with_io_mu__no_deadlock)
{
    farsee_live_shell s;
    farsee_live_shell_init(&s, NULL, 1u);
    s.io_mu = farsee_mutex_create();
    RFB_CHECK(s.io_mu != NULL);
    s.desk_w = 200;
    s.desk_h = 200;
    s.term_cols = 40;
    s.term_rows = 20;
    s.term_pw = 400;
    s.term_ph = 400;
    farsee_live_shell_set_view_scale(&s, 100u);
    // Call without holding io_mu — product contract (returns promptly).
    RFB_CHECK(farsee_live_shell_refresh_layout(&s, false));
    RFB_CHECK(s.place_cols > 0u);
    farsee_mutex_destroy(&s.io_mu);
}

// With pending Kitty output, draw_status must not write while holding the lock.
RFB_TEST(live_shell, draw_status__kitty_out_pending__skips_without_hang)
{
    farsee_live_shell s;
    farsee_live_shell_init(&s, NULL, 1u);
    s.layout_active = true;
    s.io_mu = farsee_mutex_create();
    RFB_CHECK(s.io_mu != NULL);

    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    static const uint8_t apc[] = "\033_Ga=T,f=32,s=1,v=1;AA\033\\";
    RFB_CHECK(rfb_buffer_append(&out, apc, sizeof(apc) - 1u) == RFB_OK);

    rfb_kitty_tile kt;
    memset(&kt, 0, sizeof kt);
    kt.out = &out;
    s.kitty = &kt;

    // Must return promptly (skip) while out non-empty.
    farsee_live_shell_draw_status(&s);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&out), sizeof(apc) - 1u);

    // After drain empty, function may still no-op if not a tty — but must not hang.
    rfb_buffer_clear(&out);
    farsee_live_shell_draw_status(&s);

    farsee_mutex_destroy(&s.io_mu);
    rfb_buffer_destroy(&out);
}

RFB_TEST(live_shell, public_helpers__null_and_sparse_inputs_fail_closed)
{
    farsee_cli_leader leader;
    farsee_cli_leader_default(&leader);
    farsee_live_shell_init(NULL, &leader, 1u);
    farsee_live_shell_set_view_scale(NULL, 50u);
    farsee_live_shell_set_term_geom(NULL, 80u, 24u, 0u, 0u);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(NULL),
                      FARSEE_VIEW_SCALE_DEFAULT_PCT);
    RFB_CHECK(!farsee_live_shell_get_term_geom(NULL, NULL, NULL, NULL, NULL));
    RFB_CHECK(!farsee_live_shell_refresh_layout(NULL, false));
    RFB_CHECK(!farsee_live_shell_apply_pending_desk(NULL, false));

    farsee_live_shell_note_desk_size(NULL, 10u, 10u);
    farsee_live_shell_quiet_restore(NULL);
    farsee_live_shell_input_enable(NULL);
    farsee_live_shell_input_disable(NULL);
    farsee_live_shell_fix_status_rows(NULL);
    farsee_live_shell_park_status_cursor(NULL);
    farsee_live_shell_park_log_cursor(NULL);
    farsee_live_shell_draw_status(NULL);
    farsee_live_shell_feed_tty(NULL, NULL, 0u, 0u);
    farsee_live_shell_tick_timeout(NULL, 0u);
    farsee_live_shell_do_leader_cmd(NULL, RFB_LEADER_CMD_QUIT);
    farsee_live_shell_zoom(NULL, 10);

    int32_t x = 7;
    int32_t y = 9;
    bool pixel = true;
    RFB_CHECK(!farsee_live_shell_mouse_to_desktop(
        NULL, 1, 1, &x, &y, &pixel));
    RFB_CHECK_EQ_INT(x, 0);
    RFB_CHECK_EQ_INT(y, 0);
    RFB_CHECK(!pixel);

    char link[64];
    farsee_live_shell_format_link_extra(link, sizeof link, 75u, 0u, false,
                                        12u, true);
    RFB_CHECK(strstr(link, "12KiB/s") != NULL);
    size_t len = 0u;
    char ansi[8] = "plain";
    farsee_live_shell_ensure_ansi_reset(NULL, &len, sizeof ansi);
    farsee_live_shell_ensure_ansi_reset(ansi, NULL, sizeof ansi);
    farsee_live_shell_ensure_ansi_reset(ansi, &len, 0u);
    RFB_CHECK_EQ_UINT(len, 0u);
}

RFB_TEST(live_shell, sparse_geometry__uses_defaults_and_fallback_layout)
{
    farsee_cli_leader leader;
    farsee_cli_leader_default(&leader);
    leader.keysym = (uint32_t)'x';
    (void)snprintf(leader.display, sizeof leader.display, "C-X");

    farsee_live_shell s;
    farsee_live_shell_init(&s, &leader, 0u);
    RFB_CHECK_EQ_UINT(s.status_rows, 1u);
    RFB_CHECK_EQ_UINT(s.leader.keysym, (uint32_t)'x');
    farsee_atomic_int_store(&s.view_scale_pct, 0);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&s),
                      FARSEE_VIEW_SCALE_DEFAULT_PCT);

    uint16_t cols = 0u;
    uint16_t rows = 0u;
    uint16_t pw = 0u;
    uint16_t ph = 0u;
    farsee_live_shell_set_term_geom(&s, 90u, 30u, 900u, 600u);
    RFB_CHECK(farsee_live_shell_get_term_geom(
        &s, &cols, NULL, NULL, NULL));
    RFB_CHECK(farsee_live_shell_get_term_geom(
        &s, NULL, &rows, NULL, NULL));
    RFB_CHECK(farsee_live_shell_get_term_geom(
        &s, NULL, NULL, &pw, NULL));
    RFB_CHECK(farsee_live_shell_get_term_geom(
        &s, NULL, NULL, NULL, &ph));
    RFB_CHECK_EQ_UINT(cols, 90u);
    RFB_CHECK_EQ_UINT(rows, 30u);
    RFB_CHECK_EQ_UINT(pw, 900u);
    RFB_CHECK_EQ_UINT(ph, 600u);

    s.desk_w = 320u;
    s.desk_h = 200u;
    s.term_cols = 0u;
    s.term_rows = 0u;
    s.status_rows = 30u;
    shell_rec rec;
    farsee_live_shell_ops ops;
    shell_bind(&s, &rec, &ops);
    RFB_CHECK(farsee_live_shell_refresh_layout(&s, true));
    RFB_CHECK_EQ_INT(rec.nlayout, 1);
    RFB_CHECK(s.place_cols > 0u);
    RFB_CHECK(s.place_rows > 0u);

    farsee_atomic_u64_store(&s.place_cells, 0u);
    s.place_cols = 0u;
    s.place_rows = 0u;
    s.disp_w_px = 0;
    s.disp_h_px = 0;
    int32_t x = -1;
    int32_t y = -1;
    bool pixel = true;
    RFB_CHECK(farsee_live_shell_mouse_to_desktop(
        &s, 1, 1, &x, &y, &pixel));
    RFB_CHECK(x >= 0);
    RFB_CHECK(y >= 0);
}

RFB_TEST(live_shell, pending_and_leader_edges_preserve_exact_state)
{
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec rec;
    farsee_live_shell_init(&s, NULL, 1u);
    shell_bind(&s, &rec, &ops);
    s.desk_w = 100u;
    s.desk_h = 80u;
    s.term_cols = 40u;
    s.term_rows = 20u;

    farsee_live_shell_note_desk_size(&s, 0u, 10u);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&s.pending_desk), 0u);
    farsee_atomic_u64_store(&s.pending_desk, 5u);
    RFB_CHECK(!farsee_live_shell_apply_pending_desk(&s, false));
    farsee_atomic_u64_store(
        &s.pending_desk, ((uint64_t)s.desk_w << 32) | s.desk_h);
    RFB_CHECK(!farsee_live_shell_apply_pending_desk(&s, false));

    farsee_live_shell_do_leader_cmd(&s, RFB_LEADER_CMD_PASS);
    RFB_CHECK_EQ_INT(rec.nkeys, 1);
    RFB_CHECK_EQ_UINT(rec.last_keysym, s.leader.keysym);
    s.view_only = true;
    farsee_live_shell_do_leader_cmd(&s, RFB_LEADER_CMD_PASS);
    RFB_CHECK_EQ_INT(rec.nkeys, 1);
    farsee_live_shell_do_leader_cmd(&s, RFB_LEADER_CMD_CANCEL);
    farsee_live_shell_do_leader_cmd(&s, (rfb_leader_cmd)999);

    memset(&ops, 0, sizeof ops);
    s.ops = &ops;
    s.view_only = false;
    const uint8_t key[] = {'k'};
    farsee_live_shell_feed_tty(&s, key, sizeof key, 1u);
    farsee_live_shell_do_leader_cmd(&s, RFB_LEADER_CMD_QUIT);
    farsee_live_shell_do_leader_cmd(&s, RFB_LEADER_CMD_SUSPEND);
}

RFB_TEST(live_shell, sgr_middle_and_right_buttons_map_independently)
{
    farsee_live_shell s;
    farsee_live_shell_ops ops;
    shell_rec rec;
    farsee_live_shell_init(&s, NULL, 1u);
    shell_bind(&s, &rec, &ops);
    s.desk_w = 200u;
    s.desk_h = 200u;
    s.term_cols = 40u;
    s.term_rows = 20u;
    s.term_pw = 400u;
    s.term_ph = 400u;
    s.want_mouse = true;
    s.mouse_enabled = true;
    (void)farsee_live_shell_refresh_layout(&s, false);

    static const char middle[] = "\033[<1;5;5M";
    farsee_live_shell_feed_tty(
        &s, (const uint8_t *)middle, sizeof middle - 1u, 0u);
    RFB_CHECK((rec.last_buttons & FARSEE_BUTTON_MIDDLE) != 0u);
    static const char release_middle[] = "\033[<1;5;5m";
    farsee_live_shell_feed_tty(
        &s, (const uint8_t *)release_middle,
        sizeof release_middle - 1u, 1u);

    static const char right[] = "\033[<2;5;5M";
    farsee_live_shell_feed_tty(
        &s, (const uint8_t *)right, sizeof right - 1u, 2u);
    RFB_CHECK((rec.last_buttons & FARSEE_BUTTON_RIGHT) != 0u);
}
