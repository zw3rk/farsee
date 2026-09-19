// SPDX-License-Identifier: Apache-2.0
//
// R6 — RDP FreeRDP callback wiring tests (§15.5/§15.6/§15.7/§15.8).
//
// Exercises rdp_callbacks_apply_settings against a real FreeRDP instance
// created through the facade (no network). The settings writes are the
// deterministic, testable core of the connect wiring: endpoint, desktop
// dimensions, security posture, GDI selection, and certificate policy.
//
// BeginPaint/EndPaint presenter delivery is covered by the NEEDS_HARDWARE
// interoperation gate in docs/gates/R06-callback-wiring.md.

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_callbacks.h"
#include "protocol/rdp/rdp_freerdp_facade.h"
#include "protocol/rdp/rdp_frame_slot.h"
#include "protocol/rdp/rdp_settings.h"
#include "farsee/farsee_atomic.h"
#include "farsee/memory_budget.h"
#include "tests/test_framework/rfb_test.h"

#include <freerdp/freerdp.h>
#include <freerdp/settings.h>

#include <stdlib.h>
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

typedef struct callback_fault_allocator {
    size_t calls;
    size_t fail_at;
} callback_fault_allocator;

static void *callback_fault_alloc(rfb_allocator *allocator, size_t size)
{
    callback_fault_allocator *fault =
        (callback_fault_allocator *)allocator->user;
    fault->calls++;
    if (fault->calls == fault->fail_at) {
        return NULL;
    }
    return malloc(size);
}

static void callback_fault_free(rfb_allocator *allocator, void *pointer)
{
    (void)allocator;
    free(pointer);
}

RFB_TEST(rdp_callbacks, slot_publish__allocation_failure_is_latched)
{
    callback_fault_allocator fault = { .calls = 0u, .fail_at = 1u };
    rfb_allocator allocator = {
        .alloc = callback_fault_alloc,
        .free = callback_fault_free,
        .user = &fault,
    };
    rdp_frame_slot slot;
    RFB_CHECK(farsee_frame_slot_init_with_allocator(&slot, &allocator));
    rdp_display_sink sink;
    rdp_display_sink_init(&sink);
    sink.frame_slot = &slot;
    uint8_t px[4] = { 1u, 2u, 3u, 0xFFu };

    RFB_CHECK(!rdp_display_sink_publish_frame(&sink, px, 1u, 1u, 4u));
    RFB_CHECK(farsee_atomic_int_load(&sink.frame_publish_failure) ==
              FARSEE_FRAME_PUBLISH_OUT_OF_MEMORY);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink.last_desk_size), 0u);

    RFB_CHECK(rdp_display_sink_publish_frame(&sink, px, 1u, 1u, 4u));
    RFB_CHECK(farsee_atomic_int_load(&sink.frame_publish_failure) ==
              FARSEE_FRAME_PUBLISH_OUT_OF_MEMORY);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink.last_desk_size),
                      rdp_desk_size_pack(1u, 1u));

    farsee_atomic_int_store(&sink.frame_publish_failure,
                            FARSEE_FRAME_PUBLISH_OK);
    RFB_CHECK(!rdp_display_sink_publish_frame(&sink, px, 1u, 1u, 2u));
    RFB_CHECK(farsee_atomic_int_load(&sink.frame_publish_failure) ==
              FARSEE_FRAME_PUBLISH_INVALID);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink.last_desk_size),
                      rdp_desk_size_pack(1u, 1u));
    farsee_frame_slot_destroy(&slot);
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
    memset(cbctx, 0, sizeof *cbctx);
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

RFB_TEST(rdp_callbacks, apply_settings_propagates_session_budget_to_clipboard)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    farsee_rdp_settings s;
    farsee_credential_response response;
    farsee_security_policy policy;
    farsee_rdp_settings_init_for_host(&s, "host", 3389u, "user", NULL);
    farsee_credential_response_init(&response);
    response.username = "user";
    policy = farsee_security_policy_default_rdp();

    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, rfb_default_allocator(),
                                        16u));
    RFB_CHECK(rdp_freerdp_apply_settings_with_memory_budget(
        ctx, &s, &policy, &response, FARSEE_TRUST_DECISION_APPROVE_ONCE,
        NULL, &budget));
    rdp_cliprdr_state *clip = rdp_freerdp_cliprdr_state(ctx);
    RFB_CHECK(clip != NULL);
    RFB_CHECK(clip->allocator == farsee_memory_budget_allocator(&budget));
    void *exact = clip->allocator->alloc(clip->allocator, 16u);
    RFB_CHECK(exact != NULL);
    RFB_CHECK(clip->allocator->alloc(clip->allocator, 1u) == NULL);
    clip->allocator->free(clip->allocator, exact);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
    rdp_freerdp_destroy(&ctx);
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

RFB_TEST(rdp_callbacks,
         apply_settings__external_certificate_management_is_pin_only)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    farsee_rdp_settings s;
    farsee_credential_response r;
    farsee_security_policy p;
    rdp_callback_context cbctx;
    build_cbctx(&cbctx, &s, &r, &p, "windows.example", 3389u,
                "alice", NULL);

    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    rdpSettings *st = inst->context->settings;

    p.allow_insecure_cert = false;
    p.tofu_pin_store = false;
    RFB_CHECK(rdp_callbacks_apply_settings(ctx, &cbctx));
    RFB_CHECK(!freerdp_settings_get_bool(
        st, FreeRDP_ExternalCertificateManagement));

    p.allow_insecure_cert = true;
    RFB_CHECK(rdp_callbacks_apply_settings(ctx, &cbctx));
    RFB_CHECK(!freerdp_settings_get_bool(
        st, FreeRDP_ExternalCertificateManagement));

    p.allow_insecure_cert = false;
    p.tofu_pin_store = true;
    RFB_CHECK(rdp_callbacks_apply_settings(ctx, &cbctx));
    RFB_CHECK(freerdp_settings_get_bool(
        st, FreeRDP_ExternalCertificateManagement));

    rdp_freerdp_destroy(&ctx);
}

// FreeRDP's generic channel loader treats these transport features as an
// implicit request for the rdpdr device-redirection channel. Farsee's
// allowlist excludes rdpdr, and the minimal release closure does not ship it.
// Reapply the disabled posture in PreConnect so dependency defaults cannot
// turn a clipboard-only session into an rdpdr load attempt.
RFB_TEST(rdp_callbacks, apply_settings__disables_rdpdr_trigger_features)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    farsee_rdp_settings s;
    farsee_credential_response r;
    farsee_security_policy p;
    rdp_callback_context cbctx;
    build_cbctx(&cbctx, &s, &r, &p, "windows.example", 3389u, "alice", NULL);

    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    RFB_CHECK(inst != NULL);
    rdpSettings *st = inst->context->settings;
    RFB_CHECK(freerdp_settings_set_bool(st, FreeRDP_DeviceRedirection, TRUE));
    RFB_CHECK(freerdp_settings_set_bool(st, FreeRDP_NetworkAutoDetect, TRUE));
    RFB_CHECK(freerdp_settings_set_bool(st, FreeRDP_SupportHeartbeatPdu, TRUE));
    RFB_CHECK(freerdp_settings_set_bool(st, FreeRDP_SupportMultitransport, TRUE));
    RFB_CHECK(freerdp_settings_set_bool(st, FreeRDP_RedirectHomeDrive, TRUE));

    RFB_CHECK(rdp_callbacks_apply_settings(ctx, &cbctx));
    RFB_CHECK(!freerdp_settings_get_bool(st, FreeRDP_DeviceRedirection));
    RFB_CHECK(!freerdp_settings_get_bool(st, FreeRDP_NetworkAutoDetect));
    RFB_CHECK(!freerdp_settings_get_bool(st, FreeRDP_SupportHeartbeatPdu));
    RFB_CHECK(!freerdp_settings_get_bool(st, FreeRDP_SupportMultitransport));
    RFB_CHECK(!freerdp_settings_get_bool(st, FreeRDP_RedirectHomeDrive));

    rdp_freerdp_destroy(&ctx);
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
    RFB_CHECK(rdp_callbacks_install(ctx, &cbctx) == false);

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

// --- Installed PreConnect reuses the private settings boundary -------------

RFB_TEST(rdp_callbacks, pre_connect__reapplies_and_rejects_invalid_channels)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    farsee_rdp_settings s;
    farsee_credential_response r;
    farsee_security_policy p;
    rdp_callback_context cbctx;
    build_cbctx(&cbctx, &s, &r, &p, "host", 3389u, "user", NULL);
    p.allow_insecure_cert = false;
    p.tofu_pin_store = true;
    RFB_CHECK(rdp_callbacks_install(ctx, &cbctx));

    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    RFB_CHECK(inst != NULL);
    RFB_CHECK(inst->PreConnect != NULL);
    rdpSettings *st = inst->context->settings;
    freerdp_settings_set_uint32(st, FreeRDP_DesktopWidth, 1u);
    RFB_CHECK(freerdp_settings_set_bool(
        st, FreeRDP_ExternalCertificateManagement, FALSE));

    RFB_CHECK(inst->PreConnect(inst) == TRUE);
    RFB_CHECK_EQ_UINT(freerdp_settings_get_uint32(st, FreeRDP_DesktopWidth),
                      s.desktop_width);
    RFB_CHECK(freerdp_settings_get_bool(
        st, FreeRDP_ExternalCertificateManagement));

    // The callback context is borrowed through connect. A later invalid
    // channel request must stop PreConnect before transport creation.
    s.channels.drive_redirection = true;
    RFB_CHECK(inst->PreConnect(inst) == FALSE);

    rdp_freerdp_destroy(&ctx);
}

// --- Presenter ownership: no process-global state after install -------------
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

// Two facades and two presenters: frames must not cross instances.
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

RFB_TEST(rdp_callbacks, public_context_and_presenter_edges_are_safe)
{
    freerdp raw_instance;
    memset(&raw_instance, 0, sizeof raw_instance);
    rdp_callbacks_prepare_instance(&raw_instance);
    RFB_CHECK_EQ_UINT(raw_instance.ContextSize, rdp_callbacks_context_size());
    RFB_CHECK(raw_instance.ContextFree != NULL);
    raw_instance.ContextFree(&raw_instance, NULL);

    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    RFB_CHECK(!rdp_callbacks_install(ctx, NULL));

    count_presenter presenter;
    count_presenter_init(&presenter);
    rdp_display_sink sink;
    rdp_display_sink_init(&sink);
    uint8_t pixels[16];
    fill_bgra2x2(pixels);

    rdp_callbacks_set_presenter(ctx, &presenter.base, NULL);
    RFB_CHECK(!rdp_callbacks_present_bgra(
        ctx, pixels, 2u, 2u, 8u, false, 0, 0));
    rdp_callbacks_set_presenter(ctx, NULL, &sink);
    RFB_CHECK(!rdp_callbacks_present_bgra(
        ctx, pixels, 2u, 2u, 8u, false, 0, 0));
    rdp_callbacks_set_presenter(ctx, &presenter.base, &sink);
    RFB_CHECK(!rdp_callbacks_present_bgra(
        ctx, pixels, 0u, 2u, 8u, false, 0, 0));
    RFB_CHECK(!rdp_callbacks_present_bgra(
        ctx, pixels, 2u, 0u, 8u, false, 0, 0));
    rdp_callbacks_flush_present(ctx);

    // No callback context was installed, so cursor staging uses the default
    // allocator owned by the custom FreeRDP context.
    RFB_CHECK(rdp_callbacks_present_bgra(
        ctx, pixels, 2u, 2u, 8u, true, 1, 1));
    RFB_CHECK(rdp_callbacks_present_bgra(
        ctx, pixels, 2u, 2u, 8u, true, 2, 1));
    RFB_CHECK(rdp_callbacks_present_bgra(
        ctx, pixels, 2u, 2u, 8u, true, 1, -1));
    RFB_CHECK(rdp_callbacks_present_bgra(
        ctx, pixels, 2u, 2u, 8u, true, 1, 2));
    RFB_CHECK_EQ_INT(presenter.present_count, 4);

    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_callbacks, public_helpers__null_and_uninstalled_inputs_are_safe)
{
    rdp_callbacks_prepare_instance(NULL);
    rdp_display_sink_init(NULL);
    rdp_callbacks_set_presenter(NULL, NULL, NULL);
    RFB_CHECK(rdp_callbacks_owner_from_rdp_context(NULL) == NULL);
    RFB_CHECK(!rdp_display_sink_publish_frame(NULL, NULL, 0u, 0u, 0u));

    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    freerdp *instance = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    RFB_CHECK(instance != NULL);
    RFB_CHECK(instance->context != NULL);
    RFB_CHECK(rdp_callbacks_owner_from_rdp_context(instance->context) == NULL);

    rdp_display_sink sink;
    rdp_display_sink_init(&sink);
    RFB_CHECK(!rdp_display_sink_publish_frame(&sink, NULL, 0u, 0u, 0u));
    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_callbacks,
         present_bgra__cursor_allocation_failure_uses_original_frame)
{
    callback_fault_allocator fault = { .calls = 0u, .fail_at = 1u };
    rfb_allocator allocator = {
        .alloc = callback_fault_alloc,
        .free = callback_fault_free,
        .user = &fault,
    };
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    farsee_rdp_settings settings;
    farsee_credential_response credentials;
    farsee_security_policy policy;
    rdp_callback_context callbacks;
    build_cbctx(&callbacks, &settings, &credentials, &policy, "h", 3389u,
                "u", NULL);
    callbacks.allocator = &allocator;
    RFB_CHECK(rdp_callbacks_install(ctx, &callbacks));
    RFB_CHECK_EQ_UINT(fault.calls, 0u);

    count_presenter presenter;
    count_presenter_init(&presenter);
    rdp_display_sink sink;
    rdp_display_sink_init(&sink);
    rdp_callbacks_set_presenter(ctx, &presenter.base, &sink);
    uint8_t pixels[16];
    fill_bgra2x2(pixels);

    RFB_CHECK(rdp_callbacks_present_bgra(
        ctx, pixels, 2u, 2u, 8u, true, 1, 1));
    RFB_CHECK_EQ_UINT(fault.calls, 1u);
    RFB_CHECK_EQ_INT(presenter.present_count, 1);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink.frame_count), 1u);

    sink.max_dimension = 1u;
    RFB_CHECK(!rdp_callbacks_present_bgra(
        ctx, pixels, 2u, 2u, 8u, false, 0, 0));
    RFB_CHECK_EQ_INT(presenter.present_count, 1);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink.frame_count), 1u);

    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_callbacks, flush_present__pending_without_gdi_remains_pending)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    count_presenter presenter;
    count_presenter_init(&presenter);
    rdp_display_sink sink;
    rdp_display_sink_init(&sink);
    farsee_atomic_int_store(&sink.present_pending, 1);
    rdp_callbacks_set_presenter(ctx, &presenter.base, &sink);

    rdp_callbacks_flush_present(ctx);
    RFB_CHECK_EQ_INT(presenter.present_count, 0);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&sink.present_pending));

    rdp_freerdp_destroy(&ctx);
}

// A failing presenter must not advance frame_count or first_frame_delivered.
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

// --connect-timeout maps to FreeRDP_TcpConnectTimeout.
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

RFB_TEST(rdp_callbacks, authenticate__oversized_password_fails_before_copy)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    farsee_rdp_settings s;
    farsee_credential_response r;
    farsee_security_policy p;
    rdp_callback_context cbctx;
    build_cbctx(&cbctx, &s, &r, &p, "h", 3389, "u", NULL);
    uint8_t one_byte = 0x5Au;
    r.password.data = &one_byte;
    r.password.len = SIZE_MAX;
    r.password.cap = SIZE_MAX;
    RFB_CHECK(rdp_callbacks_install(ctx, &cbctx));

    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    char *username = NULL;
    char *password = NULL;
    char *domain = NULL;
    RFB_CHECK(inst->Authenticate(inst, &username, &password, &domain) == FALSE);
    RFB_CHECK(username == NULL);
    RFB_CHECK(password == NULL);
    RFB_CHECK(domain == NULL);

    r.password.len = FARSEE_CREDENTIAL_PASSWORD_MAX + 1u;
    r.password.cap = r.password.len;
    RFB_CHECK(inst->Authenticate(inst, &username, &password, &domain) == FALSE);
    RFB_CHECK(username == NULL);
    RFB_CHECK(password == NULL);
    RFB_CHECK(domain == NULL);

    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_callbacks, authenticate__bounded_password_copies_exactly)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    farsee_rdp_settings s;
    farsee_credential_response r;
    farsee_security_policy p;
    rdp_callback_context cbctx;
    build_cbctx(&cbctx, &s, &r, &p, "h", 3389, "alice", "EXAMPLE");
    uint8_t secret[] = { 'p', 'a', 's', 's' };
    r.password.data = secret;
    r.password.len = sizeof secret;
    r.password.cap = sizeof secret;
    RFB_CHECK(rdp_callbacks_install(ctx, &cbctx));

    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    char *username = NULL;
    char *password = NULL;
    char *domain = NULL;
    RFB_CHECK(inst->Authenticate(inst, &username, &password, &domain) == TRUE);
    RFB_CHECK(streq(username, "alice"));
    RFB_CHECK(streq(password, "pass"));
    RFB_CHECK(streq(domain, "EXAMPLE"));
    free(username);
    free(password);
    free(domain);

    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_callbacks, authenticate__password_past_vnc_boundary_copies_exactly)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    farsee_rdp_settings s;
    farsee_credential_response r;
    farsee_security_policy p;
    rdp_callback_context cbctx;
    build_cbctx(&cbctx, &s, &r, &p, "h", 3389, "alice", "EXAMPLE");
    static uint8_t secret[] = "01234567-RDP-tail";
    r.password.data = secret;
    r.password.len = sizeof secret - 1u;
    r.password.cap = sizeof secret;
    RFB_CHECK(rdp_callbacks_install(ctx, &cbctx));

    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    char *username = NULL;
    char *password = NULL;
    char *domain = NULL;
    RFB_CHECK(inst->Authenticate(inst, &username, &password, &domain) == TRUE);
    RFB_CHECK(streq(username, "alice"));
    RFB_CHECK(password != NULL);
    if (password != NULL) {
        RFB_CHECK_EQ_UINT(strlen(password), sizeof secret - 1u);
        RFB_CHECK_MEM_EQ(password, secret, sizeof secret);
    }
    RFB_CHECK(streq(domain, "EXAMPLE"));
    free(username);
    free(password);
    free(domain);

    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_callbacks, authenticate__overlong_identity_text_fails_closed)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    farsee_rdp_settings s;
    farsee_credential_response r;
    farsee_security_policy p;
    rdp_callback_context cbctx;
    char overlong[FARSEE_CREDENTIAL_TEXT_MAX + 2u];
    memset(overlong, 'u', sizeof overlong);
    overlong[sizeof overlong - 1u] = '\0';
    build_cbctx(&cbctx, &s, &r, &p, "h", 3389, overlong, NULL);
    RFB_CHECK(rdp_callbacks_install(ctx, &cbctx));

    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    char *username = NULL;
    char *password = NULL;
    char *domain = NULL;
    RFB_CHECK(inst->Authenticate(inst, &username, &password, &domain) == FALSE);
    RFB_CHECK(username == NULL);
    RFB_CHECK(password == NULL);
    RFB_CHECK(domain == NULL);
    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_callbacks, authenticate__missing_and_optional_fields_fail_closed)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    farsee_rdp_settings settings;
    farsee_credential_response credentials;
    farsee_security_policy policy;
    rdp_callback_context callbacks;
    build_cbctx(&callbacks, &settings, &credentials, &policy, "h", 3389u,
                "alice", "EXAMPLE");
    RFB_CHECK(rdp_callbacks_install(ctx, &callbacks));

    freerdp *instance = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    BOOL (*authenticate)(freerdp *, char **, char **, char **) =
        instance->Authenticate;
    char sentinel = 'x';
    char *username = &sentinel;
    char *password = &sentinel;
    char *domain = &sentinel;

    rdp_freerdp_ctx *uninstalled = rdp_freerdp_create();
    RFB_CHECK(uninstalled != NULL);
    freerdp *uninstalled_instance =
        (freerdp *)rdp_freerdp_instance_opaque(uninstalled);
    RFB_CHECK(authenticate(uninstalled_instance, &username, &password,
                           &domain) == FALSE);
    RFB_CHECK(username == &sentinel);
    RFB_CHECK(password == &sentinel);
    RFB_CHECK(domain == &sentinel);
    rdp_freerdp_destroy(&uninstalled);

    callbacks.credentials = NULL;
    RFB_CHECK(authenticate(instance, &username, &password, &domain) == FALSE);
    callbacks.credentials = &credentials;
    callbacks.policy = NULL;
    RFB_CHECK(authenticate(instance, &username, &password, &domain) == FALSE);
    callbacks.policy = &policy;

    credentials.password.data = NULL;
    credentials.password.len = 1u;
    credentials.password.cap = 1u;
    RFB_CHECK(authenticate(instance, &username, &password, &domain) == FALSE);
    RFB_CHECK(username == &sentinel);
    RFB_CHECK(password == &sentinel);
    RFB_CHECK(domain == &sentinel);

    credentials.username = NULL;
    credentials.domain = NULL;
    credentials.password.len = 0u;
    credentials.password.cap = 0u;
    policy.require_nla = false;
    RFB_CHECK(authenticate(instance, NULL, NULL, NULL) == TRUE);
    RFB_CHECK(authenticate(instance, &username, &password, &domain) == TRUE);
    RFB_CHECK(username == NULL);
    RFB_CHECK(password == NULL);
    RFB_CHECK(domain == NULL);

    credentials.username = "alice";
    credentials.domain = "";
    RFB_CHECK(authenticate(instance, &username, &password, &domain) == TRUE);
    RFB_CHECK(streq(username, "alice"));
    RFB_CHECK(password == NULL);
    RFB_CHECK(domain == NULL);
    free(username);

    rdp_freerdp_destroy(&ctx);
}

#endif  // FARSEE_WITH_RDP
