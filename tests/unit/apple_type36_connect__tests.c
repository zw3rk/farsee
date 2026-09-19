// SPDX-License-Identifier: Apache-2.0
//
// Security-type 36 policy and dispatch tests for the Apple connect path.
//
// These tests cover admission and ranking before cryptography.

#include "rfb_test.h"

#include "farsee/allocator.h"
#include "farsee/apple_type33_connect.h"
#include "farsee/buffer.h"
#include "farsee/limits.h"
#include "farsee/io_adapter.h"
#include "farsee/rfb_io_pump.h"
#include "farsee/rfb_session.h"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// A real socketpair, so the pump can poll a genuine descriptor. The scripted
// security-type list is pre-written to the peer end before the run.
typedef struct { int fd; } type36_peer;

static rfb_io_result type36_read(void *ctx, uint8_t *buf, size_t n,
                                 size_t *out_n)
{
    const ssize_t got = read(((type36_peer *)ctx)->fd, buf, n);
    if (got > 0) {
        *out_n = (size_t)got;
        return RFB_IO_OK;
    }
    *out_n = 0u;
    return got == 0 ? RFB_IO_EOF : RFB_IO_ERROR;
}

static rfb_io_result type36_write(void *ctx, const uint8_t *buf, size_t n,
                                  size_t *out_n)
{
    const ssize_t put = write(((type36_peer *)ctx)->fd, buf, n);
    if (put >= 0) {
        *out_n = (size_t)put;
        return RFB_IO_OK;
    }
    *out_n = 0u;
    return RFB_IO_ERROR;
}

static void type36_close(void *ctx) { (void)ctx; }

static rfb_error type36_setup_hook(void *ctx, const rfb_server_init *si)
{
    (void)ctx;
    (void)si;
    return RFB_OK;
}

// Drive the connect guard with a scripted security-type list. Missing
// credentials make an admitted offer stop at RFB_ERR_AUTH. This proves policy
// admission, not the later wire authentication selected by the connect path.
static rfb_error type36_run(const uint8_t *script, size_t len)
{
    int sp[2] = { -1, -1 };
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
        return RFB_ERR_INTERNAL;
    }
    if (len > 0u && write(sp[1], script, len) != (ssize_t)len) {
        (void)close(sp[0]);
        (void)close(sp[1]);
        return RFB_ERR_INTERNAL;
    }
    (void)shutdown(sp[1], SHUT_WR);   // EOF once the script is consumed.

    type36_peer peer = { sp[0] };
    rfb_io_adapter adapter;
    memset(&adapter, 0, sizeof adapter);
    adapter.ctx = &peer;
    adapter.read = type36_read;
    adapter.write = type36_write;
    adapter.close = type36_close;

    rfb_allocator *alloc = rfb_default_allocator();
    rfb_buffer in;
    rfb_buffer out;
    rfb_buffer_init(&in, alloc, RFB_LIMIT_PRESENTATION_BYTES);
    rfb_buffer_init(&out, alloc, RFB_LIMIT_PRESENTATION_BYTES);

    rfb_error last = RFB_OK;
    rfb_io_pump pump;
    memset(&pump, 0, sizeof pump);
    pump.io = &adapter;
    pump.fd = sp[0];
    pump.in = &in;
    pump.out = &out;
    pump.last_error = &last;
    // Bound every read. Without a deadline, recv_exact polls up to 10000
    // times at 2 s each on a descriptor this harness does not own.
    pump.deadline_mono_ms = rfb_io_mono_ms() + 500u;

    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.auth_mode = FARSEE_AUTH_MODE_APPLE;

    apple_type33_connect_hooks hooks;
    memset(&hooks, 0, sizeof hooks);
    hooks.setup_after_server_init = type36_setup_hook;

    uint8_t wrap[16];
    bool has_wrap = false;
    rfb_session_dialect dialect = RFB_SESSION_DIALECT_CLASSIC;
    uint8_t sk32[32];

    const rfb_error e = apple_type33_connect(&pump, &cfg, &hooks, wrap,
                                             &has_wrap, &dialect, sk32);
    rfb_buffer_destroy(&in);
    rfb_buffer_destroy(&out);
    (void)close(sp[0]);
    (void)close(sp[1]);
    return e;
}

// + Value 36 is recognized by policy and reaches the credential gate.
RFB_TEST(apple_type36_connect, only_type36_offered__reaches_credential_gate)
{
    static const uint8_t script[] = { 0x01u, 36u };
    RFB_CHECK_EQ_INT(type36_run(script, sizeof script), RFB_ERR_AUTH);
}

// + When 33 and 36 are offered, the policy admits at least one value.
RFB_TEST(apple_type36_connect, type33_and_36_offered__selection_succeeds)
{
    static const uint8_t script[] = { 0x02u, 33u, 36u };
    RFB_CHECK_EQ_INT(type36_run(script, sizeof script), RFB_ERR_AUTH);
}

// − Admitting 36 must not admit the legacy Apple type, which stays off.
RFB_TEST(apple_type36_connect, only_type30_offered__still_unsupported)
{
    static const uint8_t script[] = { 0x01u, 30u };
    RFB_CHECK_EQ_INT(type36_run(script, sizeof script), RFB_ERR_UNSUPPORTED);
}

// − Nor may it admit classic VNC auth on the Apple path.
RFB_TEST(apple_type36_connect, only_classic_offered__still_unsupported)
{
    static const uint8_t script[] = { 0x01u, 2u };
    RFB_CHECK_EQ_INT(type36_run(script, sizeof script), RFB_ERR_UNSUPPORTED);
}

// − An empty list is a server-side failure, not a selection outcome.
RFB_TEST(apple_type36_connect, empty_offer_list__reports_auth_failure)
{
    static const uint8_t script[] = { 0x00u };
    RFB_CHECK_EQ_INT(type36_run(script, sizeof script), RFB_ERR_AUTH);
}

// + An offer containing only value 33 also reaches the credential check.
RFB_TEST(apple_type36_connect, only_type33_offered__selection_succeeds)
{
    static const uint8_t script[] = { 0x01u, 33u };
    RFB_CHECK_EQ_INT(type36_run(script, sizeof script), RFB_ERR_AUTH);
}

// The policy can prefer value 36 by withdrawing 33 when both are offered.
// These selector tests observe the chosen value directly; the credential-gate
// helper above does not observe the subsequent authentication wire bytes.

// + By default both Apple values are admitted, so the rank picks 33.
RFB_TEST(apple_type36_connect, default_policy_admits_both_apple_values)
{
    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.auth_mode = FARSEE_AUTH_MODE_APPLE;
    const farsee_rfb_security_policy pol = apple_connect_security_policy(&cfg);
    RFB_CHECK(pol.allow_type_33);
    RFB_CHECK(pol.allow_type_36);

    static const uint8_t offered[] = { 30u, 33u, 36u, 35u };
    uint8_t selected = 0;
    RFB_CHECK_EQ_INT(farsee_rfb_select_security(offered, sizeof offered,
                                                &pol, &selected),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(selected, 33u);
}

// + Preferring 36 must withdraw 33, since rank alone would keep choosing it.
RFB_TEST(apple_type36_connect, prefer_36_selects_36_when_both_are_offered)
{
    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.auth_mode = FARSEE_AUTH_MODE_APPLE;
    cfg.apple_prefer_type_36 = true;
    const farsee_rfb_security_policy pol = apple_connect_security_policy(&cfg);
    RFB_CHECK(!pol.allow_type_33);
    RFB_CHECK(pol.allow_type_36);

    // A peer offer containing both policy-admitted Apple values.
    static const uint8_t offered[] = { 30u, 33u, 36u, 35u };
    uint8_t selected = 0;
    RFB_CHECK_EQ_INT(farsee_rfb_select_security(offered, sizeof offered,
                                                &pol, &selected),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(selected, 36u);
}

// − Preferring 36 must not silently fall back to 33 or to a legacy type when
//   the peer does not offer 36; it must fail closed.
RFB_TEST(apple_type36_connect, prefer_36_without_36_offered_fails_closed)
{
    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.auth_mode = FARSEE_AUTH_MODE_APPLE;
    cfg.apple_prefer_type_36 = true;
    const farsee_rfb_security_policy pol = apple_connect_security_policy(&cfg);

    static const uint8_t offered[] = { 30u, 33u, 35u };
    uint8_t selected = 0;
    RFB_CHECK_EQ_INT(farsee_rfb_select_security(offered, sizeof offered,
                                                &pol, &selected),
                     RFB_ERR_UNSUPPORTED);
    RFB_CHECK_EQ_UINT(selected, 0u);
}

// + The trust-store path accepts an exact-size output buffer and preserves the
//   full HOME prefix.
RFB_TEST(apple_type36_connect, known_hosts_path__exact_fit_succeeds)
{
    static const char expected[] = "/x/.farsee/vnc_known_hosts";
    char path[sizeof expected];

    RFB_CHECK(apple_type33_known_hosts_path(path, sizeof path, "/x"));
    RFB_CHECK(strcmp(path, expected) == 0);
}

// - A path that does not fit must fail closed. It must not leave a truncated
//   trust-store name that could select a different file.
RFB_TEST(apple_type36_connect, known_hosts_path__truncation_is_rejected)
{
    static const char expected[] = "/x/.farsee/vnc_known_hosts";
    char path[sizeof expected - 1u];
    memset(path, 'x', sizeof path);

    RFB_CHECK(!apple_type33_known_hosts_path(path, sizeof path, "/x"));
    RFB_CHECK_EQ_UINT(path[0], '\0');
}

// - Missing HOME information cannot produce a stable trust-store path.
RFB_TEST(apple_type36_connect, known_hosts_path__missing_home_is_rejected)
{
    char path[32];

    memset(path, 'x', sizeof path);
    RFB_CHECK(!apple_type33_known_hosts_path(path, sizeof path, NULL));
    RFB_CHECK_EQ_UINT(path[0], '\0');

    memset(path, 'x', sizeof path);
    RFB_CHECK(!apple_type33_known_hosts_path(path, sizeof path, ""));
    RFB_CHECK_EQ_UINT(path[0], '\0');
}
