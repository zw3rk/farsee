// SPDX-License-Identifier: Apache-2.0
//
// R6 — RDP FreeRDP callback wiring tests (§15.5/§15.6/§15.7/§15.8).
//
// Exercises rdp_callbacks_apply_settings against a real FreeRDP instance
// created through the facade (no network). The settings writes are the
// deterministic, testable core of the connect wiring: endpoint, desktop
// dimensions, security posture, GDI selection, and certificate policy.
//
// Live BeginPaint/EndPaint -> presenter delivery is the NEEDS_HARDWARE
// interop step captured separately in docs/gates/R06-callback-wiring.md.

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_callbacks.h"
#include "protocol/rdp/rdp_freerdp_facade.h"
#include "protocol/rdp/rdp_settings.h"
#include "farsee/farsee_atomic.h"
#include "tests/test_framework/rfb_test.h"

#include <freerdp/freerdp.h>
#include <freerdp/settings.h>

#include <string.h>

// NULL-safe string equality (the test framework continues after a failed
// RFB_CHECK, so a raw strcmp(NULL, ...) would crash before the runner can
// record the assertion failure).
static bool streq(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return a == b;
    }
    return strcmp(a, b) == 0;
}

// Build a callback context with a settings bundle + credential response +
// APPROVE_ONCE trust. The password secret is owned by the caller.
static void build_cbctx(rdp_callback_context *cbctx,
                        farsee_rdp_settings *s,
                        farsee_credential_response *r,
                        farsee_security_policy *p,
                        const char *host, uint16_t port,
                        const char *user, const char *domain)
{
    farsee_rdp_settings_init_for_host(s, host, port, user, domain);
    s->desktop_width = 800;
    s->desktop_height = 600;
    farsee_credential_response_init(r);
    r->username = user;
    r->domain = domain;
    *p = farsee_security_policy_default_rdp();
    p->allow_insecure_cert = true;  // mirrors --cert ignore
    // Product default is REJECT until verify callback approves; tests that
    // exercise settings (not live verify) still start APPROVE_ONCE so auth
    // gate tests remain focused. Trust evaluate/reject is covered separately.
    cbctx->trust = FARSEE_TRUST_DECISION_APPROVE_ONCE;
    cbctx->peer_cert_decided = true; // tests pre-resolve trust
    cbctx->credentials = r;
    cbctx->policy = p;
    cbctx->settings = s;
    cbctx->known_hosts_path = NULL;
}

// --- apply_settings writes the endpoint + desktop dimensions ---------------

RFB_TEST(rdp_callbacks, apply_settings__writes_endpoint_and_desktop_dimensions)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    farsee_rdp_settings s;
    farsee_credential_response r;
    farsee_security_policy p;
    rdp_callback_context cbctx;
    build_cbctx(&cbctx, &s, &r, &p, "windows.example", 13390, "alice", "EXAMPLE");

    RFB_CHECK(rdp_callbacks_apply_settings(ctx, &cbctx));

    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    rdpSettings *st = inst->context->settings;

    // Endpoint. (get_string may return NULL until written; streq is NULL-safe.)
    const char *host = freerdp_settings_get_string(st, FreeRDP_ServerHostname);
    RFB_CHECK(streq(host, "windows.example"));
    RFB_CHECK_EQ_UINT(freerdp_settings_get_uint32(st, FreeRDP_ServerPort), 13390u);

    // Desktop dimensions.
    RFB_CHECK_EQ_UINT(freerdp_settings_get_uint32(st, FreeRDP_DesktopWidth), 800u);
    RFB_CHECK_EQ_UINT(freerdp_settings_get_uint32(st, FreeRDP_DesktopHeight), 600u);

    // Credentials from the response.
    const char *u = freerdp_settings_get_string(st, FreeRDP_Username);
    RFB_CHECK(streq(u, "alice"));
    const char *d = freerdp_settings_get_string(st, FreeRDP_Domain);
    RFB_CHECK(streq(d, "EXAMPLE"));

    // Security posture (§15.4 defaults).
    RFB_CHECK(freerdp_settings_get_bool(st, FreeRDP_TlsSecurity));
    RFB_CHECK(freerdp_settings_get_bool(st, FreeRDP_NlaSecurity));

    // GDI selection: software GDI so primary_buffer is populated.
    RFB_CHECK(freerdp_settings_get_bool(st, FreeRDP_SoftwareGdi));

    // --cert ignore is implemented in farsee trust (not FreeRDP_IgnoreCertificate)
    // so VerifyX509 always runs and TOFU can be written.
    RFB_CHECK(!freerdp_settings_get_bool(st, FreeRDP_IgnoreCertificate));

    rdp_freerdp_destroy(&ctx);
    RFB_CHECK(ctx == NULL);
}

// --- out-of-baseline channel allowlist rejected at the boundary ------------

RFB_TEST(rdp_callbacks, apply_settings__rejects_out_of_baseline_channels)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    farsee_rdp_settings s;
    farsee_credential_response r;
    farsee_security_policy p;
    rdp_callback_context cbctx;
    build_cbctx(&cbctx, &s, &r, &p, "h", 0, "u", NULL);
    s.channels.drive_redirection = true;  // §10.6: not in baseline

    RFB_CHECK(rdp_callbacks_apply_settings(ctx, &cbctx) == false);

    rdp_freerdp_destroy(&ctx);
}

// --- NULL / bad-arg safety -------------------------------------------------

RFB_TEST(rdp_callbacks, apply_settings__null_safe)
{
    RFB_CHECK(rdp_callbacks_apply_settings(NULL, NULL) == false);

    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    RFB_CHECK(rdp_callbacks_apply_settings(ctx, NULL) == false);

    farsee_rdp_settings s;
    farsee_credential_response r;
    farsee_security_policy p;
    rdp_callback_context cbctx;
    build_cbctx(&cbctx, &s, &r, &p, "h", 0, "u", NULL);
    cbctx.settings = NULL;  // settings missing
    RFB_CHECK(rdp_callbacks_apply_settings(ctx, &cbctx) == false);

    rdp_freerdp_destroy(&ctx);
}

// --- Presenter ownership: no process-global after install (P5) --------------
//
// Callbacks must resolve presenter/sink from the FreeRDP instance custom
// context (or facade userdata), not from process-global g_presenter/g_sink.
// Multi-context isolation proves that; present_bgra without a per-ctx
// set_presenter must fail closed even if another instance is installed.

typedef struct count_presenter {
    farsee_presenter base;
    int present_count;
    uint32_t last_w;
    uint32_t last_h;
} count_presenter;

static farsee_error_code count_open(farsee_presenter *p,
                                    farsee_presenter_caps *out_caps)
{
    (void)p;
    if (out_caps != NULL) {
        memset(out_caps, 0, sizeof(*out_caps));
        out_caps->accepts_bgra8888 = true;
        out_caps->max_dimension = 16384u;
    }
    return FARSEE_E_OK;
}

static farsee_error_code count_present(farsee_presenter *p,
                                       const farsee_frame_commit *frame)
{
    count_presenter *c = (count_presenter *)(void *)p;
    if (c == NULL || frame == NULL) {
        return FARSEE_ERR_STATE;
    }
    c->present_count++;
    if (frame->update_count > 0 && frame->updates != NULL) {
        c->last_w = frame->updates[0].view.width;
        c->last_h = frame->updates[0].view.height;
    }
    return FARSEE_E_OK;
}

static farsee_error_code count_flush(farsee_presenter *p)
{
    (void)p;
    return FARSEE_E_OK;
}

static void count_close(farsee_presenter **pp)
{
    if (pp != NULL) {
        *pp = NULL;
    }
}

static const farsee_presenter_ops_v2 COUNT_OPS = {
    .open = count_open,
    .present = count_present,
    .flush = count_flush,
    .close = count_close,
};

static void count_presenter_init(count_presenter *c)
{
    memset(c, 0, sizeof(*c));
    c->base.ops = &COUNT_OPS;
}

// Tiny solid BGRA frame (2x2, stride 8).
static void fill_bgra2x2(uint8_t out[16])
{
    // B,G,R,A per pixel — non-zero so it is clearly "content".
    for (int i = 0; i < 4; i++) {
        out[i * 4 + 0] = 0x10u;
        out[i * 4 + 1] = 0x20u;
        out[i * 4 + 2] = 0x30u;
        out[i * 4 + 3] = 0xffu;
    }
}

// present_bgra without set_presenter on that ctx fails closed (no process
// global leftover to fall back on).
RFB_TEST(rdp_callbacks, present_bgra__without_set_presenter__fails_closed)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    farsee_rdp_settings s;
    farsee_credential_response r;
    farsee_security_policy p;
    rdp_callback_context cbctx;
    build_cbctx(&cbctx, &s, &r, &p, "h", 3389, "u", NULL);
    RFB_CHECK(rdp_callbacks_install(ctx, &cbctx));

    uint8_t px[16];
    fill_bgra2x2(px);
    RFB_CHECK(rdp_callbacks_present_bgra(ctx, px, 2, 2, 8, false, 0, 0) ==
              false);

    rdp_freerdp_destroy(&ctx);
}

// Two facades, two presenters: frames must not cross instances. If
// g_presenter were still process-global, the second set_presenter would
// steal delivery from the first.
RFB_TEST(rdp_callbacks, set_presenter__multi_context__isolated)
{
    rdp_freerdp_ctx *ctx_a = rdp_freerdp_create();
    rdp_freerdp_ctx *ctx_b = rdp_freerdp_create();
    RFB_CHECK(ctx_a != NULL);
    RFB_CHECK(ctx_b != NULL);

    count_presenter pa;
    count_presenter pb;
    count_presenter_init(&pa);
    count_presenter_init(&pb);
    rdp_display_sink sink_a;
    rdp_display_sink sink_b;
    rdp_display_sink_init(&sink_a);
    rdp_display_sink_init(&sink_b);

    rdp_callbacks_set_presenter(ctx_a, &pa.base, &sink_a);
    rdp_callbacks_set_presenter(ctx_b, &pb.base, &sink_b);

    uint8_t px[16];
    fill_bgra2x2(px);

    RFB_CHECK(rdp_callbacks_present_bgra(ctx_a, px, 2, 2, 8, false, 0, 0));
    RFB_CHECK_EQ_INT(pa.present_count, 1);
    RFB_CHECK_EQ_INT(pb.present_count, 0);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink_a.frame_count), 1u);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink_b.frame_count), 0u);

    RFB_CHECK(rdp_callbacks_present_bgra(ctx_b, px, 2, 2, 8, false, 0, 0));
    RFB_CHECK_EQ_INT(pa.present_count, 1);
    RFB_CHECK_EQ_INT(pb.present_count, 1);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink_a.frame_count), 1u);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink_b.frame_count), 1u);

    // Presenting on A again still only hits A (no last-writer-wins global).
    RFB_CHECK(rdp_callbacks_present_bgra(ctx_a, px, 2, 2, 8, false, 0, 0));
    RFB_CHECK_EQ_INT(pa.present_count, 2);
    RFB_CHECK_EQ_INT(pb.present_count, 1);

    rdp_freerdp_destroy(&ctx_a);
    rdp_freerdp_destroy(&ctx_b);
}

// NULL ctx on present/flush is safe; flush with no pending is a no-op.
RFB_TEST(rdp_callbacks, present_and_flush__null_ctx__safe)
{
    RFB_CHECK(rdp_callbacks_present_bgra(NULL, NULL, 0, 0, 0, false, 0, 0) ==
              false);
    rdp_callbacks_flush_present(NULL);  // must not crash

    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    rdp_callbacks_flush_present(ctx);  // nothing pending
    rdp_freerdp_destroy(&ctx);
}

// T24: failing presenter must not advance frame_count / first_frame_delivered.
typedef struct fail_presenter {
    farsee_presenter base;
    int present_calls;
} fail_presenter;

static farsee_error_code fail_open(farsee_presenter *p,
                                   farsee_presenter_caps *out_caps)
{
    (void)p;
    if (out_caps != NULL) {
        memset(out_caps, 0, sizeof(*out_caps));
        out_caps->accepts_bgra8888 = true;
        out_caps->max_dimension = 16384u;
    }
    return FARSEE_E_OK;
}

static farsee_error_code fail_present(farsee_presenter *p,
                                      const farsee_frame_commit *frame)
{
    fail_presenter *f = (fail_presenter *)(void *)p;
    (void)frame;
    if (f != NULL) {
        f->present_calls++;
    }
    return FARSEE_ERR_PRESENTER_FAILURE;
}

static farsee_error_code fail_flush(farsee_presenter *p)
{
    (void)p;
    return FARSEE_E_OK;
}

static void fail_close(farsee_presenter **pp)
{
    if (pp != NULL) {
        *pp = NULL;
    }
}

static const farsee_presenter_ops_v2 FAIL_OPS = {
    .open = fail_open,
    .present = fail_present,
    .flush = fail_flush,
    .close = fail_close,
};

RFB_TEST(rdp_callbacks, present_bgra__presenter_fail__no_false_success)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    fail_presenter fp;
    memset(&fp, 0, sizeof(fp));
    fp.base.ops = &FAIL_OPS;
    rdp_display_sink sink;
    rdp_display_sink_init(&sink);
    rdp_callbacks_set_presenter(ctx, &fp.base, &sink);

    uint8_t px[16];
    fill_bgra2x2(px);
    RFB_CHECK(rdp_callbacks_present_bgra(ctx, px, 2, 2, 8, false, 0, 0) ==
              false);
    RFB_CHECK_EQ_INT(fp.present_calls, 1);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink.frame_count), 0u);
    RFB_CHECK(!farsee_atomic_int_load_nonzero(&sink.first_frame_delivered));

    rdp_freerdp_destroy(&ctx);
}

// T23: --connect-timeout maps to FreeRDP_TcpConnectTimeout.
RFB_TEST(rdp_callbacks, apply_settings__writes_tcp_connect_timeout)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    farsee_rdp_settings s;
    farsee_credential_response r;
    farsee_security_policy p;
    rdp_callback_context cbctx;
    build_cbctx(&cbctx, &s, &r, &p, "windows.example", 3389, "alice", NULL);
    s.connect_timeout_ms = 12345u;

    RFB_CHECK(rdp_callbacks_apply_settings(ctx, &cbctx));

    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    rdpSettings *st = inst->context->settings;
    RFB_CHECK_EQ_UINT(freerdp_settings_get_uint32(st, FreeRDP_TcpConnectTimeout),
                      12345u);

    rdp_freerdp_destroy(&ctx);
}

#endif  // FARSEE_WITH_RDP
