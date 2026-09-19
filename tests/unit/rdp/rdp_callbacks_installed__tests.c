// SPDX-License-Identifier: Apache-2.0
//
// Deterministic tests for the callbacks installed on a FreeRDP instance.
// These use an in-memory FreeRDP context. No network or RDP server is needed.

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_callbacks.h"
#include "protocol/rdp/rdp_cliprdr.h"
#include "protocol/rdp/rdp_frame_slot.h"
#include "protocol/rdp/rdp_freerdp_facade.h"
#include "protocol/rdp/rdp_settings.h"
#include "protocol/rdp/rdp_trust_bridge.h"
#include "farsee/farsee_atomic.h"
#include "farsee/memory_budget.h"
#include "tests/test_framework/rfb_test.h"

#include <freerdp/freerdp.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/settings.h>
#include <freerdp/update.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct installed_fixture {
    rdp_freerdp_ctx *ctx;
    freerdp *instance;
    farsee_rdp_settings settings;
    farsee_credential_response credentials;
    farsee_security_policy security;
    rdp_callback_context callbacks;
} installed_fixture;

static bool installed_fixture_init(installed_fixture *fixture,
                                   uint32_t width, uint32_t height,
                                   bool clipboard,
                                   farsee_memory_budget *memory_budget)
{
    if (fixture == NULL) {
        return false;
    }
    memset(fixture, 0, sizeof(*fixture));
    fixture->ctx = rdp_freerdp_create();
    if (fixture->ctx == NULL) {
        return false;
    }
    farsee_rdp_settings_init_for_host(&fixture->settings, "rdp.test", 3389u,
                                      "alice", "EXAMPLE");
    fixture->settings.desktop_width = width;
    fixture->settings.desktop_height = height;
    fixture->settings.channels.clipboard_text = clipboard;
    farsee_credential_response_init(&fixture->credentials);
    fixture->credentials.username = "alice";
    fixture->credentials.domain = "EXAMPLE";
    fixture->security = farsee_security_policy_default_rdp();
    fixture->security.allow_insecure_cert = true;
    fixture->callbacks.allocator =
        memory_budget != NULL ? farsee_memory_budget_allocator(memory_budget)
                              : NULL;
    fixture->callbacks.memory_budget = memory_budget;
    fixture->callbacks.trust = FARSEE_TRUST_DECISION_APPROVE_ONCE;
    fixture->callbacks.peer_cert_decided = true;
    fixture->callbacks.credentials = &fixture->credentials;
    fixture->callbacks.policy = &fixture->security;
    fixture->callbacks.settings = &fixture->settings;
    if (!rdp_callbacks_install(fixture->ctx, &fixture->callbacks)) {
        rdp_freerdp_destroy(&fixture->ctx);
        return false;
    }
    fixture->instance =
        (freerdp *)rdp_freerdp_instance_opaque(fixture->ctx);
    return fixture->instance != NULL && fixture->instance->context != NULL;
}

static void installed_fixture_destroy(installed_fixture *fixture)
{
    if (fixture != NULL) {
        rdp_freerdp_destroy(&fixture->ctx);
        fixture->instance = NULL;
    }
}

typedef struct installed_presenter {
    farsee_presenter base;
    size_t present_calls;
    bool fail_present;
    uint32_t width;
    uint32_t height;
    size_t stride;
    uint8_t pixels[8192];
    size_t pixel_count;
} installed_presenter;

static farsee_error_code installed_presenter_open(
    farsee_presenter *presenter, farsee_presenter_caps *caps)
{
    (void)presenter;
    if (caps != NULL) {
        memset(caps, 0, sizeof(*caps));
        caps->accepts_bgra8888 = true;
        caps->max_dimension = 16384u;
    }
    return FARSEE_E_OK;
}

static farsee_error_code installed_presenter_present(
    farsee_presenter *presenter, const farsee_frame_commit *frame)
{
    installed_presenter *capture =
        (installed_presenter *)(void *)presenter;
    if (capture == NULL || frame == NULL || frame->update_count != 1u ||
        frame->updates == NULL) {
        return FARSEE_ERR_STATE;
    }
    capture->present_calls++;
    if (capture->fail_present) {
        return FARSEE_ERR_PRESENTER_FAILURE;
    }
    const farsee_surface_view *view = &frame->updates[0].view;
    capture->width = view->width;
    capture->height = view->height;
    capture->stride = view->stride;
    capture->pixel_count = view->data_size;
    if (capture->pixel_count > sizeof(capture->pixels)) {
        capture->pixel_count = sizeof(capture->pixels);
    }
    if (capture->pixel_count > 0u && view->data != NULL) {
        memcpy(capture->pixels, view->data, capture->pixel_count);
    }
    return FARSEE_E_OK;
}

static farsee_error_code installed_presenter_flush(farsee_presenter *presenter)
{
    (void)presenter;
    return FARSEE_E_OK;
}

static void installed_presenter_close(farsee_presenter **presenter)
{
    if (presenter != NULL) {
        *presenter = NULL;
    }
}

static const farsee_presenter_ops_v2 INSTALLED_PRESENTER_OPS = {
    .open = installed_presenter_open,
    .present = installed_presenter_present,
    .flush = installed_presenter_flush,
    .close = installed_presenter_close,
};

static void installed_presenter_init(installed_presenter *presenter)
{
    memset(presenter, 0, sizeof(*presenter));
    presenter->base.ops = &INSTALLED_PRESENTER_OPS;
}

static void fill_diverse_gdi(rdpGdi *gdi)
{
    if (gdi == NULL || gdi->primary_buffer == NULL || gdi->stride <= 0 ||
        gdi->width <= 0 || gdi->height <= 0) {
        return;
    }
    for (int y = 0; y < gdi->height; y++) {
        uint8_t *row = gdi->primary_buffer + (size_t)y * (size_t)gdi->stride;
        for (int x = 0; x < gdi->width; x++) {
            row[(size_t)x * 4u + 0u] = (uint8_t)(x + 1);
            row[(size_t)x * 4u + 1u] = (uint8_t)(x + 2);
            row[(size_t)x * 4u + 2u] = (uint8_t)(x + 3);
            row[(size_t)x * 4u + 3u] = 0xffu;
        }
    }
}

static void fill_solid_gdi(rdpGdi *gdi)
{
    if (gdi == NULL || gdi->primary_buffer == NULL || gdi->stride <= 0 ||
        gdi->height <= 0) {
        return;
    }
    memset(gdi->primary_buffer, 0x11,
           (size_t)gdi->stride * (size_t)gdi->height);
}

static void fill_high_diversity_gdi(rdpGdi *gdi)
{
    if (gdi == NULL || gdi->primary_buffer == NULL || gdi->stride <= 0 ||
        gdi->width <= 0 || gdi->height <= 0) {
        return;
    }
    memset(gdi->primary_buffer, 0x11,
           (size_t)gdi->stride * (size_t)gdi->height);
    uint32_t sample = 0u;
    uint8_t *row = gdi->primary_buffer;
    for (int x = 0; x < gdi->width; x += 16) {
        const uint32_t base = sample * 3u;
        if (base + 3u > UINT8_MAX) {
            break;
        }
        row[(size_t)x * 4u + 0u] = (uint8_t)(base + 1u);
        row[(size_t)x * 4u + 1u] = (uint8_t)(base + 2u);
        row[(size_t)x * 4u + 2u] = (uint8_t)(base + 3u);
        row[(size_t)x * 4u + 3u] = 0xffu;
        sample++;
    }
}

RFB_TEST(rdp_callbacks_installed,
         callback_table__install_and_clipboard_policy_are_per_instance)
{
    installed_fixture disabled;
    installed_fixture enabled;
    RFB_CHECK(installed_fixture_init(&disabled, 64u, 2u, false, NULL));
    RFB_CHECK(installed_fixture_init(&enabled, 64u, 2u, true, NULL));

    RFB_CHECK(disabled.instance->VerifyX509Certificate != NULL);
    RFB_CHECK(disabled.instance->Authenticate != NULL);
    RFB_CHECK(disabled.instance->PreConnect != NULL);
    RFB_CHECK(disabled.instance->PostConnect != NULL);
    RFB_CHECK(disabled.instance->PostDisconnect != NULL);
    RFB_CHECK(rdp_callbacks_owner_from_rdp_context(
                  disabled.instance->context) == disabled.ctx);
    RFB_CHECK(rdp_callbacks_owner_from_rdp_context(
                  enabled.instance->context) == enabled.ctx);
    RFB_CHECK(!rdp_cliprdr_is_enabled(disabled.ctx));
    RFB_CHECK(rdp_cliprdr_is_enabled(enabled.ctx));
    RFB_CHECK(!freerdp_settings_get_bool(disabled.instance->context->settings,
                                         FreeRDP_RedirectClipboard));
    RFB_CHECK(freerdp_settings_get_bool(enabled.instance->context->settings,
                                        FreeRDP_RedirectClipboard));

    installed_fixture_destroy(&disabled);
    installed_fixture_destroy(&enabled);
}

// The release FreeRDP closure intentionally excludes rdpdr. Loading the
// configured baseline channels must therefore succeed both without and with
// the allowlisted text clipboard channel.
RFB_TEST(rdp_callbacks_installed,
         load_channels__does_not_require_excluded_rdpdr)
{
    installed_fixture disabled;
    installed_fixture enabled;
    RFB_CHECK(installed_fixture_init(&disabled, 64u, 2u, false, NULL));
    RFB_CHECK(installed_fixture_init(&enabled, 64u, 2u, true, NULL));

    RFB_CHECK(disabled.instance->LoadChannels != NULL);
    RFB_CHECK(disabled.instance->LoadChannels(disabled.instance));
    RFB_CHECK(enabled.instance->LoadChannels != NULL);
    RFB_CHECK(enabled.instance->LoadChannels(enabled.instance));

    installed_fixture_destroy(&disabled);
    installed_fixture_destroy(&enabled);
}

RFB_TEST(rdp_callbacks_installed,
         verify_x509__invalid_rejects_and_ignore_approves_session_only)
{
    installed_fixture fixture;
    static const BYTE der[] = { 0x30u, 0x03u, 0x02u, 0x01u, 0x01u };
    char path[128];
    int written = snprintf(path, sizeof path,
                           "/tmp/farsee-rdp-callback-ignore-%ld",
                           (long)getpid());
    RFB_CHECK(written > 0 && (size_t)written < sizeof path);
    (void)unlink(path);
    RFB_CHECK(installed_fixture_init(&fixture, 64u, 2u, false, NULL));
    fixture.callbacks.known_hosts_path = path;

    fixture.callbacks.trust = FARSEE_TRUST_DECISION_APPROVE_ONCE;
    fixture.callbacks.peer_cert_decided = false;
    RFB_CHECK_EQ_INT(fixture.instance->VerifyX509Certificate(
                         fixture.instance, NULL, 0u, "rdp.test", 3389u, 0u),
                     0);
    RFB_CHECK(fixture.callbacks.peer_cert_decided);
    RFB_CHECK(fixture.callbacks.trust == FARSEE_TRUST_DECISION_REJECT);

    fixture.callbacks.peer_cert_decided = false;
    RFB_CHECK_EQ_INT(fixture.instance->VerifyX509Certificate(
                         fixture.instance, der, sizeof der, "rdp.test", 3389u,
                         RDP_VERIFY_CERT_FLAG_CHANGED),
                     2);
    RFB_CHECK(fixture.callbacks.peer_cert_decided);
    RFB_CHECK(fixture.callbacks.trust ==
              FARSEE_TRUST_DECISION_APPROVE_ONCE);
    errno = 0;
    RFB_CHECK_EQ_INT(access(path, F_OK), -1);
    RFB_CHECK_EQ_INT(errno, ENOENT);

    installed_fixture_destroy(&fixture);
    (void)unlink(path);
}

RFB_TEST(rdp_callbacks_installed,
         verify_x509__distinct_null_policy_and_hostname_arms_reject_safely)
{
    installed_fixture fixture;
    static const BYTE der[] = { 0x30u, 0x03u, 0x02u, 0x01u, 0x44u };
    RFB_CHECK(installed_fixture_init(&fixture, 64u, 2u, false, NULL));

    RFB_CHECK_EQ_INT(fixture.instance->VerifyX509Certificate(
                         NULL, der, sizeof der, "rdp.test", 3389u, 0u),
                     0);
    RFB_CHECK_EQ_INT(fixture.instance->VerifyX509Certificate(
                         fixture.instance, NULL, sizeof der, "rdp.test",
                         3389u, 0u),
                     0);
    RFB_CHECK_EQ_INT(fixture.instance->VerifyX509Certificate(
                         fixture.instance, der, 0u, "rdp.test", 3389u, 0u),
                     0);

    fixture.callbacks.policy = NULL;
    RFB_CHECK_EQ_INT(fixture.instance->VerifyX509Certificate(
                         fixture.instance, der, sizeof der, "rdp.test",
                         3389u, 0u),
                     0);
    fixture.callbacks.policy = &fixture.security;
    fixture.callbacks.known_hosts_path = "/tmp/farsee-unused-known-hosts";
    RFB_CHECK_EQ_INT(fixture.instance->VerifyX509Certificate(
                         fixture.instance, der, sizeof der, NULL, 3389u,
                         RDP_VERIFY_CERT_FLAG_CHANGED),
                     2);
    RFB_CHECK_EQ_INT(fixture.instance->VerifyX509Certificate(
                         fixture.instance, der, sizeof der, "", 3389u, 0u),
                     2);

    installed_fixture_destroy(&fixture);
}

RFB_TEST(rdp_callbacks_installed,
         verify_x509__pin_store_first_use_then_match_and_change)
{
    installed_fixture fixture;
    static const BYTE der_a[] = { 0x30u, 0x03u, 0x02u, 0x01u, 0x11u };
    static const BYTE der_b[] = { 0x30u, 0x03u, 0x02u, 0x01u, 0x22u };
    char path[128];
    int written = snprintf(path, sizeof path,
                           "/tmp/farsee-rdp-callback-pin-%ld",
                           (long)getpid());
    RFB_CHECK(written > 0 && (size_t)written < sizeof path);
    (void)unlink(path);

    RFB_CHECK(installed_fixture_init(&fixture, 64u, 2u, false, NULL));
    fixture.security.allow_insecure_cert = false;
    fixture.security.tofu_pin_store = true;
    fixture.callbacks.known_hosts_path = NULL;
    RFB_CHECK_EQ_INT(fixture.instance->VerifyX509Certificate(
                         fixture.instance, der_a, sizeof der_a, "rdp.test",
                         3389u, 0u),
                     0);
    RFB_CHECK(fixture.callbacks.trust == FARSEE_TRUST_DECISION_REJECT);

    fixture.callbacks.known_hosts_path = path;
    RFB_CHECK_EQ_INT(fixture.instance->VerifyX509Certificate(
                         fixture.instance, der_a, sizeof der_a, "rdp.test",
                         3389u, 0u),
                     2);
    RFB_CHECK_EQ_INT(fixture.instance->VerifyX509Certificate(
                         fixture.instance, der_a, sizeof der_a, "rdp.test",
                         3389u, 0u),
                     2);
    RFB_CHECK_EQ_INT(fixture.instance->VerifyX509Certificate(
                         fixture.instance, der_b, sizeof der_b, "rdp.test",
                         3389u, 0u),
                     0);

    installed_fixture_destroy(&fixture);
    (void)unlink(path);
    char lock_path[140];
    written = snprintf(lock_path, sizeof lock_path, "%s.lock", path);
    if (written > 0 && (size_t)written < sizeof lock_path) {
        (void)unlink(lock_path);
    }
}

RFB_TEST(rdp_callbacks_installed,
         verify_x509__pin_store_write_failure_rejects_first_use)
{
    installed_fixture fixture;
    static const BYTE der[] = { 0x30u, 0x03u, 0x02u, 0x01u, 0x33u };
    char directory[128];
    char blocker[160];
    char path[192];
    int written = snprintf(directory, sizeof directory,
                           "/tmp/farsee-rdp-callback-missing-%ld",
                           (long)getpid());
    RFB_CHECK(written > 0 && (size_t)written < sizeof directory);
    written = snprintf(blocker, sizeof blocker, "%s/not-a-directory",
                       directory);
    RFB_CHECK(written > 0 && (size_t)written < sizeof blocker);
    written = snprintf(path, sizeof path, "%s/known_hosts", blocker);
    RFB_CHECK(written > 0 && (size_t)written < sizeof path);
    (void)unlink(blocker);
    (void)chmod(directory, 0700);
    (void)rmdir(directory);
    RFB_CHECK_EQ_INT(mkdir(directory, 0700), 0);
    FILE *block = fopen(blocker, "wb");
    RFB_CHECK(block != NULL);
    if (block != NULL) {
        RFB_CHECK_EQ_INT(fclose(block), 0);
    }

    RFB_CHECK(installed_fixture_init(&fixture, 64u, 2u, false, NULL));
    fixture.security.allow_insecure_cert = false;
    fixture.security.tofu_pin_store = true;
    fixture.callbacks.known_hosts_path = path;

    RFB_CHECK_EQ_INT(fixture.instance->VerifyX509Certificate(
                         fixture.instance, der, sizeof der, "rdp.test",
                         3389u, 0u),
                     0);
    RFB_CHECK(fixture.callbacks.peer_cert_decided);
    RFB_CHECK(fixture.callbacks.trust == FARSEE_TRUST_DECISION_REJECT);
    errno = 0;
    RFB_CHECK_EQ_INT(access(path, F_OK), -1);
    RFB_CHECK_EQ_INT(errno, ENOTDIR);

    installed_fixture_destroy(&fixture);
    RFB_CHECK_EQ_INT(unlink(blocker), 0);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}

RFB_TEST(rdp_callbacks_installed,
         authenticate__system_trust_promotes_but_pin_requires_fingerprint)
{
    installed_fixture fixture;
    RFB_CHECK(installed_fixture_init(&fixture, 64u, 2u, false, NULL));
    fixture.security.allow_insecure_cert = false;
    fixture.security.tofu_pin_store = false;
    fixture.callbacks.peer_cert_decided = false;
    fixture.callbacks.trust = FARSEE_TRUST_DECISION_REJECT;
    static uint8_t secret[] = { 'p' };
    fixture.credentials.password.data = secret;
    fixture.credentials.password.len = sizeof secret;
    fixture.credentials.password.cap = sizeof secret;

    char *username = NULL;
    char *password = NULL;
    char *domain = NULL;
    RFB_CHECK(fixture.instance->Authenticate(
                  fixture.instance, &username, &password, &domain) == TRUE);
    RFB_CHECK(fixture.callbacks.trust ==
              FARSEE_TRUST_DECISION_APPROVE_ONCE);
    RFB_CHECK(username != NULL && strcmp(username, "alice") == 0);
    RFB_CHECK(password != NULL && strcmp(password, "p") == 0);
    RFB_CHECK(domain != NULL && strcmp(domain, "EXAMPLE") == 0);
    free(username);
    free(password);
    free(domain);

    fixture.security.tofu_pin_store = true;
    fixture.callbacks.peer_cert_decided = false;
    fixture.callbacks.trust = FARSEE_TRUST_DECISION_REJECT;
    char sentinel = 'x';
    username = &sentinel;
    password = &sentinel;
    domain = &sentinel;
    RFB_CHECK(fixture.instance->Authenticate(
                  fixture.instance, &username, &password, &domain) == FALSE);
    RFB_CHECK(fixture.callbacks.trust == FARSEE_TRUST_DECISION_REJECT);
    RFB_CHECK(username == &sentinel);
    RFB_CHECK(password == &sentinel);
    RFB_CHECK(domain == &sentinel);

    installed_fixture_destroy(&fixture);
}

RFB_TEST(rdp_callbacks_installed,
         authenticate__budget_failure_is_atomic_and_success_releases_charge)
{
    static uint8_t secret[] = { 'p', 'w' };
    farsee_memory_budget small_budget;
    installed_fixture fixture;
    RFB_CHECK(farsee_memory_budget_init(&small_budget, rfb_default_allocator(),
                                        16u));
    RFB_CHECK(installed_fixture_init(&fixture, 64u, 2u, false,
                                     &small_budget));
    fixture.credentials.password.data = secret;
    fixture.credentials.password.len = sizeof secret;
    fixture.credentials.password.cap = sizeof secret;
    char sentinel = 'x';
    char *username = &sentinel;
    char *password = &sentinel;
    char *domain = &sentinel;

    RFB_CHECK(fixture.instance->Authenticate(
                  fixture.instance, &username, &password, &domain) == FALSE);
    RFB_CHECK(username == &sentinel);
    RFB_CHECK(password == &sentinel);
    RFB_CHECK(domain == &sentinel);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&small_budget), 0u);
    installed_fixture_destroy(&fixture);

    farsee_memory_budget exact_budget;
    RFB_CHECK(farsee_memory_budget_init(&exact_budget, rfb_default_allocator(),
                                        17u));
    RFB_CHECK(installed_fixture_init(&fixture, 64u, 2u, false,
                                     &exact_budget));
    fixture.credentials.password.data = secret;
    fixture.credentials.password.len = sizeof secret;
    fixture.credentials.password.cap = sizeof secret;
    username = NULL;
    password = NULL;
    domain = NULL;

    RFB_CHECK(fixture.instance->Authenticate(
                  fixture.instance, &username, &password, &domain) == TRUE);
    RFB_CHECK(username != NULL && strcmp(username, "alice") == 0);
    RFB_CHECK(password != NULL && strcmp(password, "pw") == 0);
    RFB_CHECK(domain != NULL && strcmp(domain, "EXAMPLE") == 0);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&exact_budget), 17u);
    free(username);
    free(password);
    free(domain);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&exact_budget), 17u);
    installed_fixture_destroy(&fixture);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&exact_budget), 0u);
}

RFB_TEST(rdp_callbacks_installed,
         post_connect__paint_presents_and_disconnect_releases_gdi)
{
    installed_fixture fixture;
    installed_presenter presenter;
    rdp_display_sink sink;
    RFB_CHECK(installed_fixture_init(&fixture, 64u, 2u, false, NULL));
    installed_presenter_init(&presenter);
    rdp_display_sink_init(&sink);
    rdp_callbacks_set_presenter(fixture.ctx, &presenter.base, &sink);

    RFB_CHECK(fixture.instance->PostConnect(fixture.instance) == TRUE);
    RFB_CHECK(fixture.instance->context->gdi != NULL);
    RFB_CHECK(fixture.instance->context->update->BeginPaint != NULL);
    RFB_CHECK(fixture.instance->context->update->EndPaint != NULL);
    RFB_CHECK(fixture.instance->context->update->DesktopResize != NULL);
    RFB_CHECK(fixture.instance->context->update->BitmapUpdate != NULL);
    RFB_CHECK(fixture.instance->context->update->BeginPaint(
                  fixture.instance->context) == TRUE);
    fill_diverse_gdi(fixture.instance->context->gdi);
    RFB_CHECK(fixture.instance->context->update->EndPaint(
                  fixture.instance->context) == TRUE);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 1u);
    RFB_CHECK_EQ_UINT(presenter.width, 64u);
    RFB_CHECK_EQ_UINT(presenter.height, 2u);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink.end_paint_count), 1u);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink.frame_count), 1u);

    fixture.instance->PostDisconnect(fixture.instance);
    RFB_CHECK(fixture.instance->context->gdi == NULL);
    installed_fixture_destroy(&fixture);
}

RFB_TEST(rdp_callbacks_installed,
         end_paint__solid_is_skipped_then_deferred_frame_is_flushed)
{
    installed_fixture fixture;
    installed_presenter presenter;
    rdp_display_sink sink;
    RFB_CHECK(installed_fixture_init(&fixture, 64u, 2u, false, NULL));
    installed_presenter_init(&presenter);
    rdp_display_sink_init(&sink);
    sink.defer_present = true;
    rdp_callbacks_set_presenter(fixture.ctx, &presenter.base, &sink);
    RFB_CHECK(fixture.instance->PostConnect(fixture.instance) == TRUE);

    RFB_CHECK(fixture.instance->context->update->BeginPaint(
                  fixture.instance->context) == TRUE);
    fill_solid_gdi(fixture.instance->context->gdi);
    RFB_CHECK(fixture.instance->context->update->EndPaint(
                  fixture.instance->context) == TRUE);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 0u);
    RFB_CHECK(!farsee_atomic_int_load_nonzero(&sink.present_pending));

    fill_diverse_gdi(fixture.instance->context->gdi);
    RFB_CHECK(fixture.instance->context->update->BeginPaint(
                  fixture.instance->context) == TRUE);
    RFB_CHECK(fixture.instance->context->update->EndPaint(
                  fixture.instance->context) == TRUE);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&sink.present_pending));
    RFB_CHECK_EQ_UINT(presenter.present_calls, 0u);
    rdp_callbacks_flush_present(fixture.ctx);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 1u);
    RFB_CHECK(!farsee_atomic_int_load_nonzero(&sink.present_pending));
    RFB_CHECK(farsee_atomic_int_load_nonzero(&sink.first_frame_delivered));

    fixture.instance->PostDisconnect(fixture.instance);
    installed_fixture_destroy(&fixture);
}

RFB_TEST(rdp_callbacks_installed,
         end_paint__high_diversity_sets_first_frame_and_overlays_cursor)
{
    farsee_memory_budget budget;
    installed_fixture fixture;
    installed_presenter presenter;
    rdp_display_sink sink;
    RFB_CHECK(farsee_memory_budget_init(&budget, rfb_default_allocator(),
                                        9000u));
    RFB_CHECK(installed_fixture_init(&fixture, 352u, 3u, false, &budget));
    installed_presenter_init(&presenter);
    rdp_display_sink_init(&sink);
    rdp_callbacks_set_presenter(fixture.ctx, &presenter.base, &sink);
    RFB_CHECK(fixture.instance->PostConnect(fixture.instance) == TRUE);
    rdpGdi *gdi = fixture.instance->context->gdi;
    RFB_CHECK(gdi != NULL);
    const size_t gdi_size = (size_t)gdi->stride * (size_t)gdi->height;
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), gdi_size);
    fill_high_diversity_gdi(gdi);
    farsee_atomic_int_store(&sink.cursor_visible, 1);
    farsee_atomic_int_store(&sink.cursor_x, 8);
    farsee_atomic_int_store(&sink.cursor_y, 1);

    RFB_CHECK(fixture.instance->context->update->EndPaint(
                  fixture.instance->context) == TRUE);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 1u);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&sink.first_frame_delivered));
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink.frame_count), 1u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), gdi_size * 2u);
    const size_t cursor_offset = (size_t)gdi->stride + 8u * 4u;
    RFB_CHECK_EQ_UINT(gdi->primary_buffer[cursor_offset], 0x11u);
    RFB_CHECK_EQ_UINT(presenter.pixels[cursor_offset], 0xeeu);
    RFB_CHECK_EQ_UINT(presenter.pixels[cursor_offset + 3u], 0xffu);

    fixture.instance->PostDisconnect(fixture.instance);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), gdi_size);
    installed_fixture_destroy(&fixture);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
}

RFB_TEST(rdp_callbacks_installed,
         end_paint__cursor_staging_failure_presents_original_frame)
{
    farsee_memory_budget budget;
    installed_fixture fixture;
    installed_presenter presenter;
    rdp_display_sink sink;
    RFB_CHECK(farsee_memory_budget_init(&budget, rfb_default_allocator(),
                                        256u));
    RFB_CHECK(installed_fixture_init(&fixture, 64u, 1u, false, &budget));
    installed_presenter_init(&presenter);
    rdp_display_sink_init(&sink);
    rdp_callbacks_set_presenter(fixture.ctx, &presenter.base, &sink);
    RFB_CHECK(fixture.instance->PostConnect(fixture.instance) == TRUE);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 256u);
    fill_diverse_gdi(fixture.instance->context->gdi);
    farsee_atomic_int_store(&sink.cursor_visible, 1);
    farsee_atomic_int_store(&sink.cursor_x, 1);
    farsee_atomic_int_store(&sink.cursor_y, 0);

    RFB_CHECK(fixture.instance->context->update->EndPaint(
                  fixture.instance->context) == TRUE);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 1u);
    RFB_CHECK_EQ_UINT(presenter.pixels[4u], 2u);
    RFB_CHECK_EQ_UINT(presenter.pixels[5u], 3u);
    RFB_CHECK_EQ_UINT(presenter.pixels[6u], 4u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 256u);

    fixture.instance->PostDisconnect(fixture.instance);
    installed_fixture_destroy(&fixture);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
}

RFB_TEST(rdp_callbacks_installed,
         flush_present__rate_limit_and_failure_keep_pending_for_retry)
{
    installed_fixture fixture;
    installed_presenter presenter;
    rdp_display_sink sink;
    RFB_CHECK(installed_fixture_init(&fixture, 64u, 2u, false, NULL));
    installed_presenter_init(&presenter);
    rdp_display_sink_init(&sink);
    sink.defer_present = true;
    rdp_callbacks_set_presenter(fixture.ctx, &presenter.base, &sink);
    RFB_CHECK(fixture.instance->PostConnect(fixture.instance) == TRUE);
    fill_diverse_gdi(fixture.instance->context->gdi);
    RFB_CHECK(fixture.instance->context->update->EndPaint(
                  fixture.instance->context) == TRUE);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&sink.present_pending));

    sink.min_present_interval_ms = 60000u;
    sink.last_present_monotonic_ms = UINT64_MAX - 60000u;
    rdp_callbacks_flush_present(fixture.ctx);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 0u);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&sink.present_pending));

    sink.min_present_interval_ms = 1u;
    sink.last_present_monotonic_ms = 0u;
    presenter.fail_present = true;
    rdp_callbacks_flush_present(fixture.ctx);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 1u);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink.frame_count), 0u);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&sink.present_pending));
    RFB_CHECK(!farsee_atomic_int_load_nonzero(&sink.first_frame_delivered));

    sink.min_present_interval_ms = 0u;
    presenter.fail_present = false;
    rdp_callbacks_flush_present(fixture.ctx);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 2u);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sink.frame_count), 1u);
    RFB_CHECK(!farsee_atomic_int_load_nonzero(&sink.present_pending));
    RFB_CHECK(farsee_atomic_int_load_nonzero(&sink.first_frame_delivered));

    fixture.instance->PostDisconnect(fixture.instance);
    installed_fixture_destroy(&fixture);
}

RFB_TEST(rdp_callbacks_installed,
         presenter_lifecycle__invalid_gdi_retries_then_presents_again)
{
    installed_fixture fixture;
    installed_presenter presenter;
    rdp_display_sink sink;
    RFB_CHECK(installed_fixture_init(&fixture, 64u, 2u, false, NULL));
    installed_presenter_init(&presenter);
    rdp_display_sink_init(&sink);
    RFB_CHECK(fixture.instance->PostConnect(fixture.instance) == TRUE);
    rdpUpdate *update = fixture.instance->context->update;
    rdpGdi *gdi = fixture.instance->context->gdi;
    RFB_CHECK(update != NULL);
    RFB_CHECK(gdi != NULL);
    fill_diverse_gdi(gdi);

    rdp_callbacks_set_presenter(fixture.ctx, NULL, &sink);
    RFB_CHECK(update->EndPaint(fixture.instance->context) == TRUE);
    rdp_callbacks_set_presenter(fixture.ctx, &presenter.base, NULL);
    RFB_CHECK(update->EndPaint(fixture.instance->context) == TRUE);
    rdp_callbacks_set_presenter(fixture.ctx, &presenter.base, &sink);

    fixture.instance->context->gdi = NULL;
    RFB_CHECK(update->EndPaint(fixture.instance->context) == TRUE);
    fixture.instance->context->gdi = gdi;
    const int height = gdi->height;
    gdi->height = 0;
    RFB_CHECK(update->EndPaint(fixture.instance->context) == TRUE);
    gdi->height = height;

    farsee_atomic_int_store(&sink.present_pending, 1);
    BYTE *primary_buffer = gdi->primary_buffer;
    gdi->primary_buffer = NULL;
    rdp_callbacks_flush_present(fixture.ctx);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 0u);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&sink.present_pending));
    gdi->primary_buffer = primary_buffer;

    const int width = gdi->width;
    gdi->width = 0;
    rdp_callbacks_flush_present(fixture.ctx);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 0u);
    gdi->width = width;

    sink.max_dimension = 1u;
    rdp_callbacks_flush_present(fixture.ctx);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 0u);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&sink.present_pending));
    sink.max_dimension = 16384u;
    rdp_callbacks_flush_present(fixture.ctx);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 1u);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&sink.first_frame_delivered));
    RFB_CHECK(!farsee_atomic_int_load_nonzero(&sink.present_pending));

    // Once a real frame was delivered, a later solid update must not be
    // mistaken for the initial solid-color preamble.
    fill_solid_gdi(gdi);
    RFB_CHECK(update->EndPaint(fixture.instance->context) == TRUE);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 2u);

    fixture.instance->PostDisconnect(fixture.instance);
    installed_fixture_destroy(&fixture);
}

typedef struct always_fail_allocator {
    size_t calls;
} always_fail_allocator;

static void *always_fail_alloc(rfb_allocator *allocator, size_t size)
{
    always_fail_allocator *state =
        (always_fail_allocator *)allocator->user;
    (void)size;
    state->calls++;
    return NULL;
}

static void always_fail_free(rfb_allocator *allocator, void *pointer)
{
    (void)allocator;
    (void)pointer;
}

RFB_TEST(rdp_callbacks_installed,
         end_paint__frame_slot_publishes_and_reports_allocation_failure)
{
    installed_fixture fixture;
    installed_presenter presenter;
    rdp_display_sink sink;
    rdp_frame_slot slot;
    RFB_CHECK(installed_fixture_init(&fixture, 64u, 2u, false, NULL));
    installed_presenter_init(&presenter);
    rdp_display_sink_init(&sink);
    RFB_CHECK(rdp_frame_slot_init(&slot));
    sink.frame_slot = &slot;
    rdp_callbacks_set_presenter(fixture.ctx, &presenter.base, &sink);
    RFB_CHECK(fixture.instance->PostConnect(fixture.instance) == TRUE);
    fill_diverse_gdi(fixture.instance->context->gdi);

    RFB_CHECK(fixture.instance->context->update->BeginPaint(
                  fixture.instance->context) == TRUE);
    RFB_CHECK(fixture.instance->context->update->EndPaint(
                  fixture.instance->context) == TRUE);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 0u);
    farsee_atomic_int_store(&sink.present_pending, 1);
    rdp_callbacks_flush_present(fixture.ctx);
    RFB_CHECK_EQ_UINT(presenter.present_calls, 0u);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&sink.present_pending));
    farsee_atomic_int_store(&sink.present_pending, 0);
    rdp_frame_view view;
    RFB_CHECK(rdp_frame_slot_acquire(&slot, &view));
    RFB_CHECK_EQ_UINT(view.w, 64u);
    RFB_CHECK_EQ_UINT(view.h, 2u);
    rdp_frame_slot_release(&slot, &view);
    sink.frame_slot = NULL;
    rdp_frame_slot_destroy(&slot);

    always_fail_allocator fail_state = { 0u };
    rfb_allocator fail_allocator = {
        .alloc = always_fail_alloc,
        .free = always_fail_free,
        .user = &fail_state,
    };
    RFB_CHECK(rdp_frame_slot_init_with_allocator(&slot, &fail_allocator));
    sink.frame_slot = &slot;
    RFB_CHECK(fixture.instance->context->update->BeginPaint(
                  fixture.instance->context) == TRUE);
    RFB_CHECK(fixture.instance->context->update->EndPaint(
                  fixture.instance->context) == FALSE);
    RFB_CHECK_EQ_UINT(fail_state.calls, 1u);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&sink.frame_publish_failure),
                     FARSEE_FRAME_PUBLISH_OUT_OF_MEMORY);
    sink.frame_slot = NULL;
    rdp_frame_slot_destroy(&slot);

    fixture.instance->PostDisconnect(fixture.instance);
    installed_fixture_destroy(&fixture);
}

RFB_TEST(rdp_callbacks_installed,
         desktop_resize__updates_gdi_and_honors_session_budget)
{
    farsee_memory_budget budget;
    installed_fixture fixture;
    RFB_CHECK(farsee_memory_budget_init(&budget, rfb_default_allocator(),
                                        256u));
    RFB_CHECK(installed_fixture_init(&fixture, 4u, 4u, false, &budget));
    RFB_CHECK(fixture.instance->PostConnect(fixture.instance) == TRUE);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 64u);

    RFB_CHECK(freerdp_settings_set_uint32(fixture.instance->context->settings,
                                          FreeRDP_DesktopWidth, 9u));
    RFB_CHECK(freerdp_settings_set_uint32(fixture.instance->context->settings,
                                          FreeRDP_DesktopHeight, 9u));
    RFB_CHECK(fixture.instance->context->update->DesktopResize(
                  fixture.instance->context) == FALSE);
    RFB_CHECK_EQ_INT(fixture.instance->context->gdi->width, 4);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 64u);

    RFB_CHECK(freerdp_settings_set_uint32(fixture.instance->context->settings,
                                          FreeRDP_DesktopWidth, 2u));
    RFB_CHECK(freerdp_settings_set_uint32(fixture.instance->context->settings,
                                          FreeRDP_DesktopHeight, 2u));
    RFB_CHECK(fixture.instance->context->update->DesktopResize(
                  fixture.instance->context) == TRUE);
    RFB_CHECK_EQ_INT(fixture.instance->context->gdi->width, 2);
    RFB_CHECK_EQ_INT(fixture.instance->context->gdi->height, 2);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 16u);

    fixture.instance->PostDisconnect(fixture.instance);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
    installed_fixture_destroy(&fixture);
}

RFB_TEST(rdp_callbacks_installed,
         post_connect_and_resize__invalid_inputs_fail_closed)
{
    farsee_memory_budget budget;
    installed_fixture fixture;
    RFB_CHECK(farsee_memory_budget_init(&budget, rfb_default_allocator(),
                                        15u));
    RFB_CHECK(installed_fixture_init(&fixture, 2u, 2u, false, &budget));
    RFB_CHECK(fixture.instance->PostConnect(NULL) == FALSE);
    RFB_CHECK(fixture.instance->PostConnect(fixture.instance) == FALSE);
    RFB_CHECK(fixture.instance->context->gdi == NULL);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
    fixture.instance->PostDisconnect(NULL);
    installed_fixture_destroy(&fixture);

    RFB_CHECK(installed_fixture_init(&fixture, 0u, 2u, false, NULL));
    RFB_CHECK(fixture.instance->PostConnect(fixture.instance) == FALSE);
    installed_fixture_destroy(&fixture);
}

RFB_TEST(rdp_callbacks_installed,
         post_connect_resize_and_teardown_cover_distinct_lifecycle_bounds)
{
    installed_fixture fixture;
    RFB_CHECK(installed_fixture_init(&fixture, 2u, 2u, false, NULL));
    BOOL (*post_connect)(freerdp *) = fixture.instance->PostConnect;
    void (*post_disconnect)(freerdp *) = fixture.instance->PostDisconnect;
    freerdp raw_instance;
    memset(&raw_instance, 0, sizeof raw_instance);
    RFB_CHECK(post_connect(&raw_instance) == FALSE);
    post_disconnect(&raw_instance);

    RFB_CHECK(freerdp_settings_set_uint32(fixture.instance->context->settings,
                                          FreeRDP_DesktopHeight, 0u));
    RFB_CHECK(post_connect(fixture.instance) == FALSE);
    RFB_CHECK(freerdp_settings_set_uint32(fixture.instance->context->settings,
                                          FreeRDP_DesktopWidth,
                                          UINT32_MAX));
    RFB_CHECK(freerdp_settings_set_uint32(fixture.instance->context->settings,
                                          FreeRDP_DesktopHeight,
                                          UINT32_MAX));
    RFB_CHECK(post_connect(fixture.instance) == FALSE);
    RFB_CHECK(freerdp_settings_set_uint32(fixture.instance->context->settings,
                                          FreeRDP_DesktopWidth, 2u));
    RFB_CHECK(freerdp_settings_set_uint32(fixture.instance->context->settings,
                                          FreeRDP_DesktopHeight, 2u));
    RFB_CHECK(post_connect(fixture.instance) == TRUE);

    rdpContext *context = fixture.instance->context;
    rdpUpdate *update = context->update;
    rdpGdi *gdi = context->gdi;
    rdpSettings *settings = context->settings;
    context->gdi = NULL;
    RFB_CHECK(update->DesktopResize(context) == FALSE);
    context->gdi = gdi;
    context->settings = NULL;
    RFB_CHECK(update->DesktopResize(context) == FALSE);
    context->settings = settings;
    RFB_CHECK(freerdp_settings_set_uint32(settings, FreeRDP_DesktopHeight,
                                          0u));
    RFB_CHECK(update->DesktopResize(context) == FALSE);
    RFB_CHECK(freerdp_settings_set_uint32(settings, FreeRDP_DesktopWidth,
                                          UINT32_MAX));
    RFB_CHECK(freerdp_settings_set_uint32(settings, FreeRDP_DesktopHeight,
                                          UINT32_MAX));
    RFB_CHECK(update->DesktopResize(context) == FALSE);

    post_disconnect(fixture.instance);
    installed_fixture_destroy(&fixture);

    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, rfb_default_allocator(),
                                        64u));
    RFB_CHECK(installed_fixture_init(&fixture, 4u, 4u, false, &budget));
    RFB_CHECK(fixture.instance->PostConnect(fixture.instance) == TRUE);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 64u);
    // The facade teardown must release the logical GDI reservation even when
    // the transport never reached PostDisconnect.
    installed_fixture_destroy(&fixture);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
}

RFB_TEST(rdp_callbacks_installed,
         installed_boundaries__invalid_context_and_gdi_fail_closed)
{
    installed_fixture fixture;
    installed_presenter presenter;
    rdp_display_sink sink;
    RFB_CHECK(installed_fixture_init(&fixture, 64u, 2u, false, NULL));
    installed_presenter_init(&presenter);
    rdp_display_sink_init(&sink);
    rdp_callbacks_set_presenter(fixture.ctx, &presenter.base, &sink);

    RFB_CHECK(fixture.instance->Authenticate(NULL, NULL, NULL, NULL) == FALSE);
    static uint8_t secret[] = { 'p' };
    char overlong[FARSEE_CREDENTIAL_TEXT_MAX + 1u];
    memset(overlong, 'u', sizeof overlong);
    fixture.credentials.username = overlong;
    fixture.credentials.password.data = secret;
    fixture.credentials.password.len = sizeof secret;
    fixture.credentials.password.cap = sizeof secret;
    char sentinel = 'x';
    char *username = &sentinel;
    RFB_CHECK(fixture.instance->Authenticate(
                  fixture.instance, &username, NULL, NULL) == FALSE);
    RFB_CHECK(username == &sentinel);
    fixture.credentials.username = "alice";

    RFB_CHECK(fixture.instance->PreConnect(NULL) == FALSE);
    rdpSettings *settings = fixture.instance->context->settings;
    fixture.instance->context->settings = NULL;
    RFB_CHECK(fixture.instance->PostConnect(fixture.instance) == FALSE);
    fixture.instance->context->settings = settings;
    RFB_CHECK(fixture.instance->PostConnect(fixture.instance) == TRUE);
    rdpUpdate *update = fixture.instance->context->update;
    RFB_CHECK(update->EndPaint(NULL) == TRUE);
    RFB_CHECK(update->DesktopResize(NULL) == FALSE);

    rdpGdi *gdi = fixture.instance->context->gdi;
    BYTE *primary_buffer = gdi->primary_buffer;
    const int width = gdi->width;
    const UINT32 stride = gdi->stride;
    gdi->primary_buffer = NULL;
    RFB_CHECK(update->EndPaint(fixture.instance->context) == TRUE);
    gdi->primary_buffer = primary_buffer;
    gdi->width = 0;
    RFB_CHECK(update->EndPaint(fixture.instance->context) == TRUE);
    gdi->width = width;
    gdi->stride = 0;
    RFB_CHECK(update->EndPaint(fixture.instance->context) == FALSE);
    gdi->stride = stride;
    RFB_CHECK_EQ_UINT(presenter.present_calls, 0u);

    RFB_CHECK(freerdp_settings_set_uint32(settings, FreeRDP_DesktopWidth, 0u));
    RFB_CHECK(update->DesktopResize(fixture.instance->context) == FALSE);
    RFB_CHECK_EQ_INT(gdi->width, width);
    RFB_CHECK(freerdp_settings_set_uint32(
        settings, FreeRDP_DesktopWidth, (UINT32)width));

    fixture.instance->PostDisconnect(fixture.instance);
    installed_fixture_destroy(&fixture);
}

RFB_TEST(rdp_callbacks_installed,
         present_bgra__validates_surface_and_overlays_cursor_on_copy)
{
    installed_fixture fixture;
    installed_presenter presenter;
    rdp_display_sink sink;
    uint8_t pixels[16] = {
        1u, 2u, 3u, 0xffu, 4u, 5u, 6u, 0xffu,
        7u, 8u, 9u, 0xffu, 10u, 11u, 12u, 0xffu,
    };
    uint8_t original[sizeof pixels];
    memcpy(original, pixels, sizeof pixels);
    RFB_CHECK(installed_fixture_init(&fixture, 2u, 2u, false, NULL));
    installed_presenter_init(&presenter);
    rdp_display_sink_init(&sink);
    rdp_callbacks_set_presenter(fixture.ctx, &presenter.base, &sink);

    RFB_CHECK(!rdp_callbacks_present_bgra(
        fixture.ctx, NULL, 2u, 2u, 8u, false, 0, 0));
    RFB_CHECK(!rdp_callbacks_present_bgra(
        fixture.ctx, pixels, 2u, 2u, 7u, false, 0, 0));
    sink.max_dimension = 1u;
    RFB_CHECK(!rdp_callbacks_present_bgra(
        fixture.ctx, pixels, 2u, 2u, 8u, false, 0, 0));
    sink.max_dimension = 16384u;
    RFB_CHECK(rdp_callbacks_present_bgra(
        fixture.ctx, pixels, 2u, 2u, 8u, true, 0, 0));
    RFB_CHECK_EQ_UINT(presenter.present_calls, 1u);
    RFB_CHECK_EQ_UINT(presenter.pixel_count, sizeof pixels);
    RFB_CHECK_EQ_UINT(presenter.pixels[0], 254u);
    RFB_CHECK_EQ_UINT(presenter.pixels[1], 253u);
    RFB_CHECK_EQ_UINT(presenter.pixels[2], 252u);
    RFB_CHECK_MEM_EQ(pixels, original, sizeof pixels);

    RFB_CHECK(rdp_callbacks_present_bgra(
        fixture.ctx, pixels, 2u, 2u, 8u, true, -1, 0));
    RFB_CHECK_MEM_EQ(presenter.pixels, original, sizeof pixels);
    installed_fixture_destroy(&fixture);
}

RFB_TEST(rdp_callbacks_installed,
         public_boundaries__null_and_unprepared_inputs_are_safe)
{
    rdp_display_sink sink;
    rdp_display_sink_init(NULL);
    rdp_display_sink_init(&sink);
    RFB_CHECK(!rdp_display_sink_publish_frame(NULL, NULL, 0u, 0u, 0u));
    RFB_CHECK(!rdp_display_sink_publish_frame(&sink, NULL, 0u, 0u, 0u));
    RFB_CHECK(rdp_callbacks_owner_from_rdp_context(NULL) == NULL);
    RFB_CHECK(rdp_callbacks_context_size() > sizeof(rdpContext));
    rdp_callbacks_prepare_instance(NULL);
    rdp_callbacks_set_presenter(NULL, NULL, NULL);
    RFB_CHECK(!rdp_callbacks_install(NULL, NULL));
}

#endif  // FARSEE_WITH_RDP
