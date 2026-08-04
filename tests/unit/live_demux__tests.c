// SPDX-License-Identifier: Apache-2.0
//
// Characterization suite for pure live_demux (Q1 / peer demux seam).
// Pipes/bytes only — no openpty, no FreeRDP. Recording ops fake counts
// keys / SGR / leader cmds.

#include "rfb_test.h"
#include "farsee/cli_target.h"
#include "farsee/live_demux.h"
#include "farsee/normalized_input.h"
#include "farsee/sgr_mouse.h"

#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Recording fake
// ---------------------------------------------------------------------------

#define REC_MAX_KEYS 4096
#define REC_MAX_SGR  64
#define REC_MAX_CMD  32

typedef struct rec {
    rfb_norm_key keys[REC_MAX_KEYS];
    size_t       nkeys;
    size_t       nkeys_down; // presses only
    rfb_sgr_event sgr[REC_MAX_SGR];
    uint8_t      sgr_buttons[REC_MAX_SGR];
    size_t       nsgr;
    rfb_leader_cmd cmds[REC_MAX_CMD];
    size_t       ncmds;
    int          arm_true;
    int          arm_false;
} rec;

static void rec_init(rec *r)
{
    memset(r, 0, sizeof(*r));
}

static void rec_on_key(void *u, const rfb_norm_key *nk)
{
    rec *r = (rec *)u;
    if (r == NULL || nk == NULL) {
        return;
    }
    if (r->nkeys < REC_MAX_KEYS) {
        r->keys[r->nkeys++] = *nk;
    } else {
        r->nkeys++; // still count beyond cap
    }
    if (nk->down) {
        r->nkeys_down++;
    }
}

static void rec_on_sgr(void *u, const rfb_sgr_event *ev, uint8_t buttons)
{
    rec *r = (rec *)u;
    if (r == NULL || ev == NULL) {
        return;
    }
    if (r->nsgr < REC_MAX_SGR) {
        r->sgr[r->nsgr] = *ev;
        r->sgr_buttons[r->nsgr] = buttons;
        r->nsgr++;
    } else {
        r->nsgr++;
    }
}

static void rec_on_leader_cmd(void *u, rfb_leader_cmd cmd)
{
    rec *r = (rec *)u;
    if (r == NULL) {
        return;
    }
    if (r->ncmds < REC_MAX_CMD) {
        r->cmds[r->ncmds++] = cmd;
    } else {
        r->ncmds++;
    }
}

static void rec_on_leader_arm(void *u, bool armed)
{
    rec *r = (rec *)u;
    if (r == NULL) {
        return;
    }
    if (armed) {
        r->arm_true++;
    } else {
        r->arm_false++;
    }
}

static farsee_live_demux_ops rec_ops(void)
{
    farsee_live_demux_ops o;
    memset(&o, 0, sizeof o);
    o.on_key = rec_on_key;
    o.on_sgr = rec_on_sgr;
    o.on_leader_cmd = rec_on_leader_cmd;
    o.on_leader_arm = rec_on_leader_arm;
    return o;
}

static void demux_default(farsee_live_demux *d)
{
    farsee_cli_leader L;
    farsee_cli_leader_default(&L);
    farsee_live_demux_init(d, &L);
}

// ---------------------------------------------------------------------------
// Leader: C0 arm + q → quit
// ---------------------------------------------------------------------------

RFB_TEST(live_demux, leader_c0_then_q__emits_quit)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    // Default leader C0 is 0x1D (Ctrl+]).
    const uint8_t arm = 0x1Du;
    farsee_live_demux_feed(&d, &arm, 1, 1000u, &ops, &r);
    RFB_CHECK(farsee_live_demux_leader_is_armed(&d));
    RFB_CHECK_EQ_INT(r.arm_true, 1);
    RFB_CHECK_EQ_UINT(r.ncmds, 0u);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u);

    const uint8_t q = (uint8_t)'q';
    farsee_live_demux_feed(&d, &q, 1, 1001u, &ops, &r);
    RFB_CHECK(!farsee_live_demux_leader_is_armed(&d));
    RFB_CHECK_EQ_UINT(r.ncmds, 1u);
    RFB_CHECK_EQ_INT(r.cmds[0], RFB_LEADER_CMD_QUIT);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u); // quit is local, not injected
}

// ---------------------------------------------------------------------------
// Leader + leader → pass
// ---------------------------------------------------------------------------

RFB_TEST(live_demux, leader_c0_then_c0__emits_pass)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    const uint8_t b = 0x1Du;
    farsee_live_demux_feed(&d, &b, 1, 1u, &ops, &r);
    RFB_CHECK(farsee_live_demux_leader_is_armed(&d));
    farsee_live_demux_feed(&d, &b, 1, 2u, &ops, &r);
    RFB_CHECK(!farsee_live_demux_leader_is_armed(&d));
    RFB_CHECK_EQ_UINT(r.ncmds, 1u);
    RFB_CHECK_EQ_INT(r.cmds[0], RFB_LEADER_CMD_PASS);
}

// ---------------------------------------------------------------------------
// Leader timeout at deadline
// ---------------------------------------------------------------------------

RFB_TEST(live_demux, leader_timeout_at_deadline__disarms)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    const uint8_t arm = 0x1Du;
    farsee_live_demux_feed(&d, &arm, 1, 1000u, &ops, &r);
    RFB_CHECK(farsee_live_demux_leader_is_armed(&d));
    RFB_CHECK_EQ_UINT(d.leader_deadline_ms, 1000u + FARSEE_LIVE_LEADER_ARM_MS);

    // Just before deadline: still armed.
    farsee_live_demux_check_timeout(&d, 1000u + FARSEE_LIVE_LEADER_ARM_MS - 1u,
                                    &ops, &r);
    RFB_CHECK(farsee_live_demux_leader_is_armed(&d));

    // At deadline: disarmed.
    farsee_live_demux_check_timeout(&d, 1000u + FARSEE_LIVE_LEADER_ARM_MS, &ops,
                                    &r);
    RFB_CHECK(!farsee_live_demux_leader_is_armed(&d));
    RFB_CHECK_EQ_UINT(d.leader_deadline_ms, 0u);
    RFB_CHECK_EQ_INT(r.arm_false, 1);
    RFB_CHECK_EQ_UINT(r.ncmds, 0u);

    // Empty feed at past deadline also disarms (already disarmed — no-op).
    farsee_live_demux_feed(&d, (const uint8_t *)"", 0, 99999u, &ops, &r);
}

// Feed with clock past deadline while armed (no second byte).
RFB_TEST(live_demux, leader_timeout_on_feed__disarms_before_bytes)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    const uint8_t arm = 0x1Du;
    farsee_live_demux_feed(&d, &arm, 1, 500u, &ops, &r);
    RFB_CHECK(farsee_live_demux_leader_is_armed(&d));

    // Printable 'a' after timeout window: timeout first, then inject key.
    const uint8_t a = (uint8_t)'a';
    farsee_live_demux_feed(&d, &a, 1, 500u + FARSEE_LIVE_LEADER_ARM_MS + 1u,
                           &ops, &r);
    RFB_CHECK(!farsee_live_demux_leader_is_armed(&d));
    RFB_CHECK_EQ_UINT(r.ncmds, 0u);
    RFB_CHECK(r.nkeys_down >= 1u);
    RFB_CHECK_EQ_UINT(r.keys[0].keysym, (uint32_t)'a');
}

// clock_ms == 0 disables timeout check this call.
RFB_TEST(live_demux, leader_timeout_clock_zero__skips_check)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    const uint8_t arm = 0x1Du;
    farsee_live_demux_feed(&d, &arm, 1, 100u, &ops, &r);
    // Feed with clock 0: still armed even if wall would have expired.
    const uint8_t a = (uint8_t)'x'; // not a leader cmd → would cancel if armed
    // Wait — if still armed, 'x' cancels arm without cmd. Use empty feed.
    farsee_live_demux_feed(&d, NULL, 0, 0u, &ops, &r);
    RFB_CHECK(farsee_live_demux_leader_is_armed(&d));
    (void)a;
}

// ---------------------------------------------------------------------------
// CSI-u C-] split across two feeds arms leader
// ---------------------------------------------------------------------------

RFB_TEST(live_demux, csi_u_leader_split_feeds__arms)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    // CSI 93 ; 5 u  (Ctrl+])
    static const uint8_t part1[] = {0x1Bu, '[', '9', '3'};
    static const uint8_t part2[] = {';', '5', 'u'};
    farsee_live_demux_feed(&d, part1, sizeof part1, 10u, &ops, &r);
    RFB_CHECK(!farsee_live_demux_leader_is_armed(&d));
    RFB_CHECK_EQ_UINT(r.nkeys, 0u);

    farsee_live_demux_feed(&d, part2, sizeof part2, 11u, &ops, &r);
    RFB_CHECK(farsee_live_demux_leader_is_armed(&d));
    RFB_CHECK_EQ_INT(r.arm_true, 1);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u); // leader chord never injected
}

// Leader release after arm must not disarm or inject.
RFB_TEST(live_demux, csi_u_leader_release__does_not_disarm)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    static const uint8_t press[] = {0x1Bu, '[', '9', '3', ';', '5', 'u'};
    static const uint8_t release[] = {
        0x1Bu, '[', '9', '3', ';', '5', ':', '3', 'u'};
    farsee_live_demux_feed(&d, press, sizeof press, 1u, &ops, &r);
    RFB_CHECK(farsee_live_demux_leader_is_armed(&d));
    farsee_live_demux_feed(&d, release, sizeof release, 2u, &ops, &r);
    RFB_CHECK(farsee_live_demux_leader_is_armed(&d));
    RFB_CHECK_EQ_UINT(r.nkeys, 0u);
    RFB_CHECK_EQ_UINT(r.ncmds, 0u);
}

// CSI-u q after arm → quit (split chord + command).
RFB_TEST(live_demux, csi_u_leader_then_q__quit)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    static const uint8_t press[] = {0x1Bu, '[', '9', '3', ';', '5', 'u'};
    farsee_live_demux_feed(&d, press, sizeof press, 1u, &ops, &r);
    RFB_CHECK(farsee_live_demux_leader_is_armed(&d));

    // Kitty CSI-u for 'q' press: code 113, mods 1 (none), press.
    static const uint8_t q[] = {0x1Bu, '[', '1', '1', '3', 'u'};
    farsee_live_demux_feed(&d, q, sizeof q, 2u, &ops, &r);
    RFB_CHECK(!farsee_live_demux_leader_is_armed(&d));
    RFB_CHECK_EQ_UINT(r.ncmds, 1u);
    RFB_CHECK_EQ_INT(r.cmds[0], RFB_LEADER_CMD_QUIT);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u);
}

// ---------------------------------------------------------------------------
// Incomplete SGR residual then complete
// ---------------------------------------------------------------------------

RFB_TEST(live_demux, sgr_incomplete_residual__then_complete)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    // ESC [ < 0 ; 10 ; 20 M  split mid-sequence
    static const uint8_t p1[] = {0x1Bu, '[', '<', '0', ';', '1'};
    static const uint8_t p2[] = {'0', ';', '2', '0', 'M'};
    farsee_live_demux_feed(&d, p1, sizeof p1, 0u, &ops, &r);
    RFB_CHECK_EQ_UINT(r.nsgr, 0u);
    RFB_CHECK(d.residual_len > 0u);

    farsee_live_demux_feed(&d, p2, sizeof p2, 0u, &ops, &r);
    RFB_CHECK_EQ_UINT(r.nsgr, 1u);
    RFB_CHECK_EQ_INT(r.sgr[0].kind, RFB_SGR_EV_PRESS);
    RFB_CHECK_EQ_INT(r.sgr[0].x, 10);
    RFB_CHECK_EQ_INT(r.sgr[0].y, 20);
    RFB_CHECK_EQ_UINT(d.residual_len, 0u);
}

// Regression (live in=0): ESC [ at end of read, then "<Pb;Px;PyM" alone.
// Must residual the prefix — NOT feed ESC[ into kb CSI (which ate SGR).
RFB_TEST(live_demux, sgr_split_esc_bracket__then_body__emits_sgr)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    static const uint8_t p1[] = {0x1Bu, '['}; // end of read mid-prefix
    static const uint8_t p2[] = {'<', '3', '5', ';', '8', '8', '5', ';',
                                 '2', '9', '3', 'M'}; // motion event body
    farsee_live_demux_feed(&d, p1, sizeof p1, 1000u, &ops, &r);
    RFB_CHECK(d.residual_len == 2u);
    RFB_CHECK_EQ_UINT(r.nsgr, 0u);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u);

    farsee_live_demux_feed(&d, p2, sizeof p2, 1001u, &ops, &r);
    RFB_CHECK_EQ_UINT(r.nsgr, 1u);
    RFB_CHECK_EQ_INT(r.sgr[0].x, 885);
    RFB_CHECK_EQ_INT(r.sgr[0].y, 293);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u); // must not leak as keyboard
    RFB_CHECK_EQ_UINT(d.residual_len, 0u);
}

// Same class: lone ESC residual, then "[<0;1;2M"
RFB_TEST(live_demux, sgr_split_lone_esc__then_sgr__emits)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    static const uint8_t p1[] = {0x1Bu};
    static const uint8_t p2[] = {'[', '<', '0', ';', '1', ';', '2', 'M'};
    farsee_live_demux_feed(&d, p1, sizeof p1, 0u, &ops, &r);
    RFB_CHECK(d.residual_len == 1u);

    farsee_live_demux_feed(&d, p2, sizeof p2, 0u, &ops, &r);
    RFB_CHECK_EQ_UINT(r.nsgr, 1u);
    RFB_CHECK_EQ_INT(r.sgr[0].kind, RFB_SGR_EV_PRESS);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u);
}

// Stale ESC[ residual abandoned when next chunk starts a new ESC sequence.
RFB_TEST(live_demux, sgr_stale_esc_bracket_residual__dropped_on_new_esc)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    static const uint8_t stale[] = {0x1Bu, '['};
    farsee_live_demux_feed(&d, stale, sizeof stale, 0u, &ops, &r);
    RFB_CHECK(d.residual_len == 2u);

    // Full new SGR (starts with ESC) — must not become ESC[ ESC[<…
    static const uint8_t full[] = {0x1Bu, '[', '<', '0', ';', '3', ';', '4',
                                   'M'};
    farsee_live_demux_feed(&d, full, sizeof full, 0u, &ops, &r);
    RFB_CHECK_EQ_UINT(r.nsgr, 1u);
    RFB_CHECK_EQ_INT(r.sgr[0].x, 3);
    RFB_CHECK_EQ_INT(r.sgr[0].y, 4);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u);
}

// ESC [ residual must still complete Kitty CSI-u (not only SGR).
RFB_TEST(live_demux, csi_u_split_esc_bracket__then_body__emits_key)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    // ESC [ 97 ; 1 : 1 u  — 'a' press (Kitty)
    static const uint8_t p1[] = {0x1Bu, '['};
    static const uint8_t p2[] = {'9', '7', ';', '1', ':', '1', 'u'};
    farsee_live_demux_feed(&d, p1, sizeof p1, 0u, &ops, &r);
    RFB_CHECK(d.residual_len == 2u);

    farsee_live_demux_feed(&d, p2, sizeof p2, 0u, &ops, &r);
    RFB_CHECK(r.nkeys >= 1u);
    RFB_CHECK_EQ_UINT(r.keys[0].keysym, (uint32_t)'a');
    RFB_CHECK(r.keys[0].down);
}

// SGR press-drag-release sequence
RFB_TEST(live_demux, sgr_press_drag_release__three_events)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    char buf[128];
    int n = snprintf(buf, sizeof buf,
                     "\033[<0;5;6M"   // press left
                     "\033[<32;7;8M"  // drag (motion+left)
                     "\033[<0;7;8m"); // release left
    RFB_CHECK(n > 0);
    farsee_live_demux_feed(&d, (const uint8_t *)buf, (size_t)n, 0u, &ops, &r);
    RFB_CHECK_EQ_UINT(r.nsgr, 3u);
    RFB_CHECK_EQ_INT(r.sgr[0].kind, RFB_SGR_EV_PRESS);
    RFB_CHECK_EQ_INT(r.sgr[1].kind, RFB_SGR_EV_MOVE);
    RFB_CHECK_EQ_INT(r.sgr[2].kind, RFB_SGR_EV_RELEASE);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u);
}

// ---------------------------------------------------------------------------
// Incomplete APC (ESC _ G …) residual then complete — discarded, no keys
// ---------------------------------------------------------------------------

RFB_TEST(live_demux, apc_incomplete_residual__then_discard)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    // ESC _ G ... ESC ST (ESC + backslash)
    static const uint8_t p1[] = {0x1Bu, '_', 'G', 'a', 'b'};
    static const uint8_t p2[] = {'c', 0x1Bu, '\\'};
    farsee_live_demux_feed(&d, p1, sizeof p1, 0u, &ops, &r);
    RFB_CHECK(d.residual_len > 0u);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u);

    farsee_live_demux_feed(&d, p2, sizeof p2, 0u, &ops, &r);
    RFB_CHECK_EQ_UINT(d.residual_len, 0u);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u);
    RFB_CHECK_EQ_UINT(r.nsgr, 0u);
}

// Stuck incomplete APC must not swallow keys forever after residual TTL.
RFB_TEST(live_demux, residual_expire__recovers_keys_after_stuck_apc)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    static const uint8_t p1[] = {0x1Bu, '_', 'G', 'a', 'b'};
    farsee_live_demux_feed(&d, p1, sizeof p1, /*clock=*/1000u, &ops, &r);
    RFB_CHECK(d.residual_len > 0u);
    RFB_CHECK(d.residual_deadline_ms == 1000u + FARSEE_LIVE_RESIDUAL_MS);

    // Keys before expiry still prepend to residual (would be stuck without TTL).
    static const uint8_t keys[] = {'x', 'y'};
    farsee_live_demux_feed(&d, keys, sizeof keys, /*clock=*/1100u, &ops, &r);
    RFB_CHECK(d.residual_len > 0u);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u);

    // Past residual deadline: residual dropped; new keys inject.
    farsee_live_demux_feed(&d, keys, sizeof keys,
                           1000u + FARSEE_LIVE_RESIDUAL_MS + 1u, &ops, &r);
    RFB_CHECK_EQ_UINT(d.residual_len, 0u);
    RFB_CHECK(r.nkeys_down >= 2u);
    RFB_CHECK_EQ_UINT(r.keys[r.nkeys - 1u].keysym, (uint32_t)'y');
}

// Complete APC in one feed: no key leakage.
RFB_TEST(live_demux, apc_complete__no_keys)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    static const uint8_t apc[] = {0x1Bu, '_', 'G', 'x', 'y', 0x1Bu, '\\'};
    farsee_live_demux_feed(&d, apc, sizeof apc, 0u, &ops, &r);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u);
}

// ---------------------------------------------------------------------------
// Large paste: 2000 printable → 2000 key downs (view_only false)
// ---------------------------------------------------------------------------

RFB_TEST(live_demux, large_paste_2000__all_key_downs)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    uint8_t paste[2000];
    memset(paste, 'Z', sizeof paste);
    farsee_live_demux_feed(&d, paste, sizeof paste, 0u, &ops, &r);
    RFB_CHECK_EQ_UINT(r.nkeys_down, 2000u);
    RFB_CHECK_EQ_UINT(r.nkeys, 2000u); // legacy: press only
    RFB_CHECK_EQ_UINT(r.keys[0].keysym, (uint32_t)'Z');
    RFB_CHECK_EQ_UINT(r.keys[1999].keysym, (uint32_t)'Z');
    RFB_CHECK_EQ_UINT(d.residual_len, 0u);
}

// ---------------------------------------------------------------------------
// view_only: suppresses key/sgr inject; may still arm leader
// ---------------------------------------------------------------------------

RFB_TEST(live_demux, view_only__suppresses_keys_and_sgr_arms_leader)
{
    farsee_live_demux d;
    demux_default(&d);
    d.view_only = true;
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    const uint8_t a = (uint8_t)'a';
    farsee_live_demux_feed(&d, &a, 1, 0u, &ops, &r);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u);

    char sgr[32];
    int n = snprintf(sgr, sizeof sgr, "\033[<0;1;1M");
    RFB_CHECK(n > 0);
    farsee_live_demux_feed(&d, (const uint8_t *)sgr, (size_t)n, 0u, &ops, &r);
    RFB_CHECK_EQ_UINT(r.nsgr, 0u);

    const uint8_t arm = 0x1Du;
    farsee_live_demux_feed(&d, &arm, 1, 1u, &ops, &r);
    RFB_CHECK(farsee_live_demux_leader_is_armed(&d));
    RFB_CHECK_EQ_INT(r.arm_true, 1);

    const uint8_t q = (uint8_t)'q';
    farsee_live_demux_feed(&d, &q, 1, 2u, &ops, &r);
    RFB_CHECK_EQ_UINT(r.ncmds, 1u);
    RFB_CHECK_EQ_INT(r.cmds[0], RFB_LEADER_CMD_QUIT);
}

// ---------------------------------------------------------------------------
// Null / empty safety
// ---------------------------------------------------------------------------

RFB_TEST(live_demux, feed_null_or_empty__no_crash)
{
    farsee_live_demux d;
    demux_default(&d);
    rec r;
    rec_init(&r);
    farsee_live_demux_ops ops = rec_ops();

    farsee_live_demux_feed(NULL, (const uint8_t *)"a", 1, 0u, &ops, &r);
    farsee_live_demux_feed(&d, NULL, 1, 0u, &ops, &r);
    farsee_live_demux_feed(&d, (const uint8_t *)"a", 0, 0u, &ops, &r);
    farsee_live_demux_init(NULL, NULL);
    RFB_CHECK_EQ_UINT(r.nkeys, 0u);
}
