// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP FreeRDP callback wiring implementation (R6 in-process wiring).
//
// Connects FreeRDP's instance callback table to the Farsee-owned bridges.
// FreeRDP/WinPR types are confined to the private callback implementation.
//
// Each FreeRDP custom context owns its Farsee callback context, presenter,
// sink, and staging state. No process-global presenter state is used.

#include "rdp_callbacks.h"
#include "rdp_callbacks_settings.h"
#include "rdp_cliprdr.h"
#include "rdp_display_bridge.h"
#include "rdp_frame_slot.h"
#include "rdp_trust_bridge.h"

#include <freerdp/codec/color.h>
#include <freerdp/freerdp.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/settings.h>
#include <freerdp/update.h>

#include "farsee/apple_crypto.h"
#include "farsee/checked.h"
#include "farsee/farsee_clipboard.h"
#include "farsee/farsee_thread.h"
#include "farsee/known_hosts.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// FreeRDP custom context: rdpContext MUST be the first member so FreeRDP
// can treat instance->context as a normal rdpContext*. All Farsee-owned
// callback state hangs off this structure (no process globals).
//
// cbctx is non-const so VerifyX509Certificate can update trust after
// fingerprinting the peer certificate (§15.7).
typedef struct rdp_farsee_context {
    rdpContext context;  // MUST be first
    rdp_callback_context *cbctx;
    farsee_presenter *presenter;
    rdp_display_sink *sink;
    // Owning facade handle, so PubSub handlers (which receive only the
    // rdpContext) can recover per-instance state such as cliprdr.
    rdp_freerdp_ctx *owner;
    // Monotonic content generation for the surface view (bumped per
    // published frame so the presenter sees a fresh generation each commit).
    uint64_t generation;
    // Staging buffer for present with local cursor overlay (owned here).
    uint8_t *present_staging;
    size_t present_staging_cap;
    rfb_allocator *allocator;
    farsee_memory_budget *memory_budget;
    size_t gdi_reserved;
    // Authenticate returns malloc-compatible strings that FreeRDP frees.
    // Keep a conservative logical charge until context teardown because the
    // callback API does not expose that dependency-owned free point.
    size_t credential_reserved;
} rdp_farsee_context;

static rdp_farsee_context *rdp_fcc_from_instance(freerdp *instance)
{
    if (instance == NULL || instance->context == NULL) {
        return NULL;
    }
    return (rdp_farsee_context *)instance->context;
}

static rdp_farsee_context *rdp_fcc_from_rdp_context(rdpContext *context)
{
    return (rdp_farsee_context *)context;
}

static rdp_farsee_context *rdp_fcc_from_facade(const rdp_freerdp_ctx *ctx)
{
    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    return rdp_fcc_from_instance(inst);
}

static rfb_allocator *rdp_fcc_allocator(rdp_farsee_context *fcc)
{
    return fcc != NULL && fcc->allocator != NULL
               ? fcc->allocator
               : rfb_default_allocator();
}

static bool bounded_credential_text_length(const char *text, size_t *out)
{
    if (text == NULL || out == NULL) {
        return false;
    }
    for (size_t i = 0u; i <= FARSEE_CREDENTIAL_TEXT_MAX; i++) {
        if (text[i] == '\0') {
            *out = i;
            return true;
        }
    }
    return false;
}

size_t rdp_callbacks_context_size(void)
{
    return sizeof(rdp_farsee_context);
}

// FreeRDP ContextFree: release Farsee-owned fields before FreeRDP frees the
// context block. Does not free presenter/sink/cbctx (caller-owned).
static void rdp_cb_context_free(freerdp *instance, rdpContext *context)
{
    (void)instance;
    rdp_farsee_context *fcc = rdp_fcc_from_rdp_context(context);
    if (fcc == NULL) {
        return;
    }
    rfb_allocator *allocator = fcc->allocator != NULL
                                   ? fcc->allocator
                                   : rfb_default_allocator();
    if (fcc->present_staging != NULL) {
        allocator->free(allocator, fcc->present_staging);
    }
    if (fcc->memory_budget != NULL && fcc->gdi_reserved != 0u) {
        (void)farsee_memory_budget_replace_reservation(
            fcc->memory_budget, &fcc->gdi_reserved, 0u);
    }
    if (fcc->memory_budget != NULL && fcc->credential_reserved != 0u) {
        (void)farsee_memory_budget_replace_reservation(
            fcc->memory_budget, &fcc->credential_reserved, 0u);
    }
    fcc->present_staging = NULL;
    fcc->present_staging_cap = 0;
    fcc->presenter = NULL;
    fcc->sink = NULL;
    fcc->cbctx = NULL;
    fcc->owner = NULL;
    fcc->generation = 0;
    fcc->allocator = NULL;
    fcc->memory_budget = NULL;
}

// Recover the owning facade handle from the FreeRDP rdpContext PubSub
// handlers receive. Per-instance cliprdr state hangs off the handle.
rdp_freerdp_ctx *rdp_callbacks_owner_from_rdp_context(void *rdp_context)
{
    if (rdp_context == NULL) {
        return NULL;
    }
    rdp_farsee_context *fcc = rdp_fcc_from_rdp_context((rdpContext *)rdp_context);
    return (fcc != NULL) ? fcc->owner : NULL;
}

void rdp_callbacks_prepare_instance(void *freerdp_instance)
{
    freerdp *inst = (freerdp *)freerdp_instance;
    if (inst == NULL) {
        return;
    }
    inst->ContextSize = sizeof(rdp_farsee_context);
    inst->ContextFree = rdp_cb_context_free;
}

void rdp_display_sink_init(rdp_display_sink *sink)
{
    if (sink == NULL) {
        return;
    }
    sink->presenter = NULL;
    farsee_atomic_int_store(&sink->first_frame_delivered, 0);
    farsee_atomic_u64_store(&sink->frame_count, 0u);
    farsee_atomic_u64_store(&sink->last_desk_size, 0u);
    sink->max_dimension = 16384;  // §15.8 cap; matches the v1 adapter
    sink->min_present_interval_ms = 0;
    sink->last_present_monotonic_ms = 0;
    sink->defer_present = false;
    farsee_atomic_int_store(&sink->present_pending, 0);
    farsee_atomic_u64_store(&sink->end_paint_count, 0u);
    farsee_atomic_int_store(&sink->frame_publish_failure,
                            FARSEE_FRAME_PUBLISH_OK);
    farsee_atomic_int_store(&sink->cursor_visible, 0);
    farsee_atomic_int_store(&sink->cursor_x, 0);
    farsee_atomic_int_store(&sink->cursor_y, 0);
    sink->frame_slot = NULL;
}

bool rdp_display_sink_publish_frame(rdp_display_sink *sink,
                                    const uint8_t *bgra, uint32_t w,
                                    uint32_t h, uint32_t stride)
{
    if (sink == NULL || sink->frame_slot == NULL) {
        return false;
    }
    const farsee_frame_publish_result result = rdp_frame_slot_publish_ex(
        sink->frame_slot, bgra, w, h, stride);
    if (result != FARSEE_FRAME_PUBLISH_OK) {
        int expected = FARSEE_FRAME_PUBLISH_OK;
        (void)farsee_atomic_int_compare_exchange(
            &sink->frame_publish_failure, &expected, (int)result);
        return false;
    }
    farsee_atomic_u64_store(&sink->last_desk_size,
                            rdp_desk_size_pack(w, h));
    return true;
}

void rdp_callbacks_set_presenter(rdp_freerdp_ctx *ctx,
                                 farsee_presenter *presenter,
                                 rdp_display_sink *sink)
{
    rdp_farsee_context *fcc = rdp_fcc_from_facade(ctx);
    if (fcc == NULL) {
        return;
    }
    fcc->presenter = presenter;
    fcc->sink = sink;
    if (sink != NULL) {
        sink->presenter = presenter;
    }
}

// --- Certificate verification -> rdp_trust_bridge (§15.7) ------------------
//
// FreeRDP invokes this when the peer cert needs a decision. We fingerprint
// the exact full-chain PEM bytes, classify against known_hosts (if configured)
// / FreeRDP flags,
// evaluate via rdp_trust_evaluate_classified, and store the decision on
// cbctx so Authenticate can gate credentials (§10.4).
static int rdp_cb_verify_x509(freerdp *instance,
                              const BYTE *data, size_t length,
                              const char *hostname, uint16_t port,
                              uint32_t flags)
{
    rdp_farsee_context *fcc = rdp_fcc_from_instance(instance);
    if (fcc == NULL || fcc->cbctx == NULL) {
        return 0;  // fail closed
    }
    rdp_callback_context *cbctx = fcc->cbctx;

    // Pin mode uses external certificate management, so FreeRDP reaches this
    // callback for every peer certificate. Other modes reach it only when
    // FreeRDP needs an application decision. In either case, the callback
    // decision is required before any credentials (§10.4).
    cbctx->peer_cert_decided = true;
    cbctx->trust = FARSEE_TRUST_DECISION_REJECT;

    if (data == NULL || length == 0u) {
        return 0;
    }

    // The callback flags contain no positive proof that both CA and hostname
    // validation succeeded. They only refine CHANGED vs FIRST_USE here.
    const bool ca_hostname_ok = rdp_trust_ca_hostname_ok_from_flags(flags);
    rdp_trust_classification classification =
        rdp_trust_classify_from_flags(flags);

    // TOFU store: fingerprint the full-chain PEM bytes and classify against
    // known_hosts. Any chain or representation change fails closed as a new
    // fingerprint.
    uint8_t fp[32];
    if (!rfb_crypto_sha256(data, length, fp)) {
        // Fail closed: digest failure is not "first use".
        return 0;
    }

    if (cbctx->known_hosts_path != NULL && hostname != NULL &&
        hostname[0] != '\0') {
        known_hosts_result kh =
            known_hosts_check(hostname, port, fp, cbctx->known_hosts_path);
        if (kh == KNOWN_HOSTS_MATCH) {
            classification = RDP_TRUST_UNCHANGED;
        } else if (kh == KNOWN_HOSTS_MISMATCH) {
            classification = RDP_TRUST_CHANGED;
        } else if (classification != RDP_TRUST_CHANGED) {
            classification = RDP_TRUST_FIRST_USE;
        }
    }

    const bool allow_insecure =
        cbctx->policy != NULL && cbctx->policy->allow_insecure_cert;
    const bool pin_store =
        cbctx->policy != NULL && cbctx->policy->tofu_pin_store;
    farsee_trust_decision d = rdp_trust_decide_ex(
        classification, ca_hostname_ok, allow_insecure, pin_store);
    cbctx->trust = d;

    if (classification == RDP_TRUST_CHANGED && allow_insecure &&
        rdp_trust_allows_credentials(d)) {
        fprintf(stderr,
                "farsee rdp: WARNING: peer certificate fingerprint CHANGED "
                "for %s:%u (approved only because --cert ignore)\n",
                hostname != NULL ? hostname : "?", (unsigned)port);
        (void)fflush(stderr);
    }

    // TOFU store policy:
    //   --cert ignore → session-only; NEVER write known_hosts.
    //   --cert pin    → store on FIRST_USE only; MUST succeed or REJECT
    //                   (never approve without a durable pin).
    if (rdp_trust_allows_credentials(d) && pin_store &&
        classification == RDP_TRUST_FIRST_USE) {
        if (cbctx->known_hosts_path == NULL || hostname == NULL ||
            hostname[0] == '\0') {
            fprintf(stderr,
                    "farsee rdp: --cert pin requires a writable known_hosts "
                    "path (HOME unset or store disabled)\n");
            (void)fflush(stderr);
            cbctx->trust = FARSEE_TRUST_DECISION_REJECT;
            return 0;
        }
        if (!known_hosts_add(hostname, port, fp, cbctx->known_hosts_path)) {
            fprintf(stderr,
                    "farsee rdp: failed to store TOFU pin for %s:%u under %s "
                    "(--cert pin fails closed)\n",
                    hostname, (unsigned)port, cbctx->known_hosts_path);
            (void)fflush(stderr);
            cbctx->trust = FARSEE_TRUST_DECISION_REJECT;
            return 0;
        }
    }

    // FreeRDP 3.x VerifyX509Certificate return codes (freerdp.h):
    //   0 = reject
    //   1 = accept and permanently store in FreeRDP's cert store
    //   2 = accept for this session only (do not store)
    // --cert pin stores FIRST_USE through known_hosts; --cert ignore does not.
    // Return 2 for every approved session so FreeRDP cannot persist a separate
    // decision that bypasses this callback on a later run.
    return rdp_verify_x509_freerdp_return(cbctx->trust);
}

// --- Authentication -> credential bridge (§15.6) ---------------------------
static BOOL rdp_cb_authenticate(freerdp *instance,
                                char **username, char **password,
                                char **domain)
{
    rdp_farsee_context *fcc = rdp_fcc_from_instance(instance);
    if (fcc == NULL || fcc->cbctx == NULL || fcc->cbctx->credentials == NULL ||
        fcc->cbctx->policy == NULL) {
        return FALSE;  // no credentials -> auth fails
    }
    rdp_callback_context *cbctx = fcc->cbctx;
    // If FreeRDP never asked VerifyX509, it accepted the peer via the TLS
    // stack (system CA + hostname). Promote REJECT → APPROVE_ONCE so NLA
    // can proceed — but NOT under --cert pin: pin mode requires a fingerprint
    // via VerifyX509 (known_hosts). Blind promote would make pin a no-op for
    // CA-valid peers and miss rotations.
    if (!cbctx->peer_cert_decided &&
        cbctx->trust == FARSEE_TRUST_DECISION_REJECT &&
        (cbctx->policy == NULL || !cbctx->policy->allow_insecure_cert)) {
        if (cbctx->policy != NULL && cbctx->policy->tofu_pin_store) {
            fprintf(stderr,
                    "farsee rdp: --cert pin requires a VerifyX509 fingerprint "
                    "(CA-trusted peer skipped pin check); refusing credentials\n");
            (void)fflush(stderr);
            // leave REJECT
        } else {
            // System-validated peer: FreeRDP skipped the user-accept hook.
            cbctx->trust = FARSEE_TRUST_DECISION_APPROVE_ONCE;
        }
    }
    // §10.4 gate: never supply credentials to a rejected peer.
    if (!rdp_credential_may_apply(cbctx->trust, cbctx->policy,
                                  cbctx->credentials)) {
        return FALSE;
    }
    const farsee_credential_response *r = cbctx->credentials;
    if (r->password.len > FARSEE_CREDENTIAL_PASSWORD_MAX ||
        r->password.len > r->password.cap ||
        (r->password.len > 0u && r->password.data == NULL)) {
        return FALSE;
    }
    size_t username_len = 0u;
    size_t domain_len = 0u;
    if ((r->username != NULL &&
         !bounded_credential_text_length(r->username, &username_len)) ||
        (r->domain != NULL &&
         !bounded_credential_text_length(r->domain, &domain_len))) {
        return FALSE;
    }
    char *user_copy = NULL;
    char *domain_copy = NULL;
    char *pass_copy = NULL;

    size_t charge = 0u;
    size_t storage = 0u;
    if (username != NULL && r->username != NULL) {
        if (!rfb_checked_add_size(username_len, 1u, &storage) ||
            !rfb_checked_add_size(charge, storage, &charge)) {
            return FALSE;
        }
    }
    if (domain != NULL && r->domain != NULL && r->domain[0] != '\0') {
        if (!rfb_checked_add_size(domain_len, 1u, &storage) ||
            !rfb_checked_add_size(charge, storage, &charge)) {
            return FALSE;
        }
    }
    if (password != NULL && r->password.data != NULL && r->password.len > 0u) {
        if (!rfb_checked_add_size(r->password.len, 1u, &storage) ||
            !rfb_checked_add_size(charge, storage, &charge)) {
            return FALSE;
        }
    }
    const size_t old_charge = fcc->credential_reserved;
    size_t new_charge = 0u;
    if (!rfb_checked_add_size(old_charge, charge, &new_charge) ||
        (fcc->memory_budget != NULL &&
         !farsee_memory_budget_replace_reservation(
             fcc->memory_budget, &fcc->credential_reserved, new_charge))) {
        return FALSE;
    }

    if (username != NULL && r->username != NULL) {
        user_copy = (char *)malloc(username_len + 1u);
        if (user_copy == NULL) {
            if (fcc->memory_budget != NULL) {
                (void)farsee_memory_budget_replace_reservation(
                    fcc->memory_budget, &fcc->credential_reserved, old_charge);
            }
            return FALSE;  // required user present but alloc failed
        }
        memcpy(user_copy, r->username, username_len + 1u);
    }
    if (domain != NULL && r->domain != NULL && r->domain[0] != '\0') {
        domain_copy = (char *)malloc(domain_len + 1u);
        if (domain_copy == NULL) {
            free(user_copy);
            if (fcc->memory_budget != NULL) {
                (void)farsee_memory_budget_replace_reservation(
                    fcc->memory_budget, &fcc->credential_reserved, old_charge);
            }
            return FALSE;
        }
        memcpy(domain_copy, r->domain, domain_len + 1u);
    }
    if (password != NULL && r->password.data != NULL && r->password.len > 0) {
        // NUL-terminated secret copy for FreeRDP's wide-char path.
        pass_copy = (char *)calloc(1, r->password.len + 1u);
        if (pass_copy == NULL) {
            free(user_copy);
            free(domain_copy);
            if (fcc->memory_budget != NULL) {
                (void)farsee_memory_budget_replace_reservation(
                    fcc->memory_budget, &fcc->credential_reserved, old_charge);
            }
            return FALSE;  // password required but alloc failed — fail closed
        }
        memcpy(pass_copy, r->password.data, r->password.len);
    }

    if (username != NULL) {
        *username = user_copy;
    }
    if (domain != NULL) {
        *domain = domain_copy;
    }
    if (password != NULL) {
        *password = pass_copy;
    }
    return TRUE;
}

// --- Display callbacks -> rdp_display_bridge + presenter (§15.8) -----------
//
// FreeRDP's software-GDI backend decodes every drawing order into
// gdi->primary_buffer (BGRA8888, stride gdi->stride). BeginPaint/EndPaint
// bracket a frame; we publish the full primary_buffer as a complete snapshot
// at EndPaint. This is the deterministic first-frame path; partial damage
// forwarding is a refinement that rides the same rdp_frame_build_surface_view.

// Sample unique B/G/R channel byte values in a BGRA buffer (stride by
// RDP_UNIQUE_SAMPLE_STRIDE pixels). Full-frame scans of 1280x800 every
// EndPaint are too expensive on the live path; sampling is enough to reject
// solid white/black preambles. Caps at `cap` so the scan can early-exit.
#define RDP_UNIQUE_SAMPLE_STRIDE 16u  // every 16th pixel

static uint32_t rdp_count_unique_bgr(const uint8_t *bgra, size_t data_size,
                                    uint32_t cap)
{
    bool seen[256] = {false};
    uint32_t unique = 0;
    if (bgra == NULL || data_size < 4 || cap == 0) {
        return 0;
    }
    const size_t step = (size_t)RDP_UNIQUE_SAMPLE_STRIDE * 4u;
    for (size_t i = 0; i + 3 < data_size; i += step) {
        uint8_t b = bgra[i];
        uint8_t g = bgra[i + 1];
        uint8_t r = bgra[i + 2];
        if (!seen[b]) {
            seen[b] = true;
            unique++;
        }
        if (!seen[g]) {
            seen[g] = true;
            unique++;
        }
        if (!seen[r]) {
            seen[r] = true;
            unique++;
        }
        if (unique >= cap) {
            break;
        }
    }
    return unique;
}

// Sampled B/G/R component-value threshold used by the single-thread settle
// path to set first_frame_delivered. The count is not a content guarantee.
#define RDP_REAL_FRAME_UNIQUE_BGR 64u

// Minimum sampled component diversity while first_frame_delivered is false.
// Updates below this threshold are not published or presented.
#define RDP_PRESENT_MIN_UNIQUE_BGR 4u

// Draw a simple inverted crosshair into a BGRA buffer (does not touch GDI).
static void rdp_draw_local_cursor(uint8_t *bgra, uint32_t w, uint32_t h,
                                  size_t stride, int32_t cx, int32_t cy)
{
    if (bgra == NULL || w == 0 || h == 0) {
        return;
    }
    if (cx < 0 || cy < 0 || (uint32_t)cx >= w || (uint32_t)cy >= h) {
        return;
    }
    const int arm = 8;
    for (int d = -arm; d <= arm; ++d) {
        int x = cx + d;
        int y = cy;
        if (x >= 0 && (uint32_t)x < w) {
            uint8_t *p = bgra + (size_t)y * stride + (size_t)x * 4u;
            p[0] = (uint8_t)(255u - p[0]);
            p[1] = (uint8_t)(255u - p[1]);
            p[2] = (uint8_t)(255u - p[2]);
            p[3] = 255u;
        }
        x = cx;
        y = cy + d;
        if (y >= 0 && (uint32_t)y < h && d != 0) {
            uint8_t *p = bgra + (size_t)y * stride + (size_t)x * 4u;
            p[0] = (uint8_t)(255u - p[0]);
            p[1] = (uint8_t)(255u - p[1]);
            p[2] = (uint8_t)(255u - p[2]);
            p[3] = 255u;
        }
    }
}

// Push GDI primary_buffer to the presenter (rate-limited).
static void rdp_do_present_gdi(rdp_farsee_context *fcc, uint32_t unique_hint)
{
    if (fcc == NULL || fcc->context.gdi == NULL || fcc->presenter == NULL ||
        fcc->sink == NULL) {
        return;
    }
    rdpGdi *gdi = fcc->context.gdi;
    rdp_display_sink *sink = fcc->sink;
    farsee_presenter *presenter = fcc->presenter;
    if (gdi->primary_buffer == NULL || gdi->width <= 0 || gdi->height <= 0) {
        return;
    }

    if (sink->min_present_interval_ms > 0) {
        const uint64_t now = farsee_thread_monotonic_ms();
        if (sink->last_present_monotonic_ms != 0 &&
            now < sink->last_present_monotonic_ms +
                      sink->min_present_interval_ms) {
            return;  // keep present_pending; try next tick
        }
        sink->last_present_monotonic_ms = now;
    }

    const uint32_t max_dim = sink->max_dimension;
    const uint32_t w = (uint32_t)gdi->width;
    const uint32_t h = (uint32_t)gdi->height;
    const size_t stride = (size_t)gdi->stride;
    size_t data_size = 0u;
    if (!rfb_checked_mul_size(stride, (size_t)h, &data_size)) {
        return;
    }

    const uint8_t *pixels = gdi->primary_buffer;
    // Local software cursor: only pay for a full-frame copy when the
    // cursor is on and we already decided to present a server frame.
    // Mouse moves do not force presents; the fixed cadence presents server
    // frames.
    {
        const bool cur_vis =
            farsee_atomic_int_load_nonzero(&sink->cursor_visible);
        const int32_t cx = farsee_atomic_int_load(&sink->cursor_x);
        const int32_t cy = farsee_atomic_int_load(&sink->cursor_y);
        if (cur_vis) {
            if (fcc->present_staging_cap < data_size) {
                uint8_t *nbuf = (uint8_t *)rfb_allocator_realloc(
                    rdp_fcc_allocator(fcc), fcc->present_staging,
                    fcc->present_staging_cap, data_size);
                if (nbuf != NULL) {
                    fcc->present_staging = nbuf;
                    fcc->present_staging_cap = data_size;
                }
            }
            if (fcc->present_staging != NULL &&
                fcc->present_staging_cap >= data_size) {
                memcpy(fcc->present_staging, gdi->primary_buffer, data_size);
                rdp_draw_local_cursor(fcc->present_staging, w, h, stride, cx,
                                      cy);
                pixels = fcc->present_staging;
            }
        }
    }

    farsee_surface_view view;
    if (!rdp_frame_build_surface_view(&view, /*id=*/1, w, h, stride,
                                      pixels, data_size,
                                      max_dim, ++fcc->generation)) {
        return;
    }

    farsee_surface_update upd = {
        .view = view,
        .damage = NULL,
        .damage_count = 0,
    };
    const uint64_t prev_fc = farsee_atomic_u64_load(&sink->frame_count);
    farsee_frame_commit frame = {
        .frame_id = (farsee_frame_id)prev_fc + 1u,
        .updates = &upd,
        .update_count = 1,
        .cursor = NULL,
        .presentation_time_ns = 0,
        .complete_snapshot = true,
    };

    // Update success state only after present succeeds.
    farsee_error pe = farsee_presenter_present(presenter, &frame);
    if (farsee_error_failed(pe)) {
        return;
    }
    (void)farsee_atomic_u64_fetch_add(&sink->frame_count, 1u);
    farsee_atomic_u64_store(&sink->last_desk_size,
                           rdp_desk_size_pack(w, h));
    farsee_atomic_int_store(&sink->present_pending, 0);
    if (unique_hint >= RDP_REAL_FRAME_UNIQUE_BGR) {
        farsee_atomic_int_store(&sink->first_frame_delivered, 1);
    }
}

void rdp_callbacks_flush_present(rdp_freerdp_ctx *ctx)
{
    rdp_farsee_context *fcc = rdp_fcc_from_facade(ctx);
    if (fcc == NULL || fcc->sink == NULL ||
        !farsee_atomic_int_load_nonzero(&fcc->sink->present_pending)) {
        return;
    }
    // Multi-thread path publishes via frame_slot; no single-thread flush.
    if (fcc->sink->frame_slot != NULL) {
        return;
    }
    rdp_do_present_gdi(fcc, RDP_REAL_FRAME_UNIQUE_BGR);
}

bool rdp_callbacks_present_bgra(rdp_freerdp_ctx *ctx, const uint8_t *bgra,
                                uint32_t w, uint32_t h, uint32_t stride,
                                bool cursor_visible, int32_t cursor_x,
                                int32_t cursor_y)
{
    rdp_farsee_context *fcc = rdp_fcc_from_facade(ctx);
    if (fcc == NULL || bgra == NULL || w == 0 || h == 0 ||
        fcc->presenter == NULL || fcc->sink == NULL) {
        return false;
    }
    rdp_display_sink *sink = fcc->sink;
    if (stride < w * 4u) {
        return false;
    }
    size_t data_size = 0u;
    if (!rfb_checked_mul_size((size_t)stride, (size_t)h, &data_size)) {
        return false;
    }
    const uint8_t *pixels = bgra;
    if (cursor_visible) {
        if (fcc->present_staging_cap < data_size) {
            uint8_t *nbuf = (uint8_t *)rfb_allocator_realloc(
                rdp_fcc_allocator(fcc), fcc->present_staging,
                fcc->present_staging_cap, data_size);
            if (nbuf != NULL) {
                fcc->present_staging = nbuf;
                fcc->present_staging_cap = data_size;
            }
        }
        if (fcc->present_staging != NULL &&
            fcc->present_staging_cap >= data_size) {
            memcpy(fcc->present_staging, bgra, data_size);
            rdp_draw_local_cursor(fcc->present_staging, w, h, stride, cursor_x,
                                  cursor_y);
            pixels = fcc->present_staging;
        }
    }
    farsee_surface_view view;
    if (!rdp_frame_build_surface_view(&view, /*id=*/1, w, h, stride, pixels,
                                      data_size, sink->max_dimension,
                                      ++fcc->generation)) {
        return false;
    }
    farsee_surface_update upd = {
        .view = view,
        .damage = NULL,
        .damage_count = 0,
    };
    const uint64_t prev_fc = farsee_atomic_u64_load(&sink->frame_count);
    farsee_frame_commit frame = {
        .frame_id = (farsee_frame_id)prev_fc + 1u,
        .updates = &upd,
        .update_count = 1,
        .cursor = NULL,
        .presentation_time_ns = 0,
        .complete_snapshot = true,
    };
    // Set success flags only after present returns OK.
    farsee_error pe = farsee_presenter_present(fcc->presenter, &frame);
    if (farsee_error_failed(pe)) {
        return false;
    }
    (void)farsee_atomic_u64_fetch_add(&sink->frame_count, 1u);
    farsee_atomic_u64_store(&sink->last_desk_size,
                           rdp_desk_size_pack(w, h));
    farsee_atomic_int_store(&sink->first_frame_delivered, 1);
    return true;
}

// EndPaint path: optionally defer the heavy presenter work so FreeRDP's
// event pump and TTY input stay responsive on the same thread.
static BOOL rdp_publish_gdi_frame(rdpContext *context)
{
    rdp_farsee_context *fcc = rdp_fcc_from_rdp_context(context);
    if (fcc == NULL || fcc->context.gdi == NULL) {
        return TRUE;
    }
    rdpGdi *gdi = fcc->context.gdi;
    if (gdi->primary_buffer == NULL || gdi->width <= 0 || gdi->height <= 0) {
        return TRUE;
    }
    if (fcc->presenter == NULL || fcc->sink == NULL) {
        return TRUE;
    }
    rdp_display_sink *sink = fcc->sink;

    size_t data_size = 0u;
    if (gdi->stride <= 0 ||
        !rfb_checked_mul_size((size_t)gdi->stride,
                              (size_t)gdi->height, &data_size)) {
        return FALSE;
    }
    uint32_t unique = RDP_REAL_FRAME_UNIQUE_BGR;
    if (!farsee_atomic_int_load_nonzero(&sink->first_frame_delivered)) {
        unique = rdp_count_unique_bgr(gdi->primary_buffer, data_size,
                                      RDP_REAL_FRAME_UNIQUE_BGR);
        if (unique < RDP_PRESENT_MIN_UNIQUE_BGR) {
            return TRUE;
        }
    }

    (void)farsee_atomic_u64_fetch_add(&sink->end_paint_count, 1u);

    // Multi-thread path: publish latest BGRA into the frame slot; a
    // dedicated present thread shows at fixed FPS (latest-wins).
    // first_frame_delivered is set only after a successful present on the
    // present thread, not after publication.
    if (sink->frame_slot != NULL) {
        if (!rdp_display_sink_publish_frame(
                sink, gdi->primary_buffer, (uint32_t)gdi->width,
                (uint32_t)gdi->height, (uint32_t)gdi->stride)) {
            return FALSE;
        }
        return TRUE;
    }

    if (sink->defer_present) {
        // Mark dirty only — flush_present runs after TTY input.
        // first_frame_delivered is set only when flush present succeeds.
        farsee_atomic_int_store(&sink->present_pending, 1);
        return TRUE;
    }

    rdp_do_present_gdi(fcc, unique);
    return TRUE;
}

static BOOL rdp_cb_begin_paint(rdpContext *context)
{
    // FreeRDP may set gdi->inGfxFrame; nothing else for the snapshot path.
    (void)context;
    return TRUE;
}

static BOOL rdp_cb_end_paint(rdpContext *context)
{
    return rdp_publish_gdi_frame(context);
}

static BOOL rdp_cb_desktop_resize(rdpContext *context)
{
    // gdi_resize reallocates primary_buffer for the negotiated desktop size.
    // FreeRDP's GFX ResetGraphics path asserts DesktopResize is non-NULL.
    if (context == NULL || context->gdi == NULL || context->settings == NULL) {
        return FALSE;
    }
    const UINT32 w = freerdp_settings_get_uint32(context->settings,
                                                 FreeRDP_DesktopWidth);
    const UINT32 h = freerdp_settings_get_uint32(context->settings,
                                                 FreeRDP_DesktopHeight);
    rdp_farsee_context *fcc = rdp_fcc_from_rdp_context(context);
    size_t pixels = 0u;
    size_t requested = 0u;
    if (fcc == NULL || w == 0u || h == 0u ||
        !rfb_checked_mul_size((size_t)w, (size_t)h, &pixels) ||
        !rfb_checked_mul_size(pixels, 4u, &requested)) {
        return FALSE;
    }
    const size_t old_reservation = fcc->gdi_reserved;
    if (fcc->memory_budget != NULL && requested > old_reservation &&
        !farsee_memory_budget_replace_reservation(
            fcc->memory_budget, &fcc->gdi_reserved, requested)) {
        return FALSE;
    }
    if (!gdi_resize(context->gdi, w, h)) {
        if (fcc->memory_budget != NULL) {
            (void)farsee_memory_budget_replace_reservation(
                fcc->memory_budget, &fcc->gdi_reserved, old_reservation);
        }
        return FALSE;
    }
    size_t actual = 0u;
    if (context->gdi->stride <= 0 || context->gdi->height <= 0 ||
        !rfb_checked_mul_size((size_t)context->gdi->stride,
                              (size_t)context->gdi->height, &actual) ||
        (fcc->memory_budget != NULL &&
         !farsee_memory_budget_replace_reservation(
             fcc->memory_budget, &fcc->gdi_reserved, actual))) {
        return FALSE;
    }
    return rdp_publish_gdi_frame(context);
}

// --- Connect-sequence callbacks -------------------------------------------

// PreConnect: apply settings + channel allowlist immediately before the
// transport opens. Idempotent with rdp_callbacks_apply_settings.
static BOOL rdp_cb_pre_connect(freerdp *instance)
{
    rdp_farsee_context *fcc = rdp_fcc_from_instance(instance);
    if (fcc == NULL || fcc->cbctx == NULL) {
        return FALSE;
    }
    return rdp_callbacks_apply_instance_settings(instance, fcc->cbctx)
               ? TRUE
               : FALSE;
}

// PostConnect: initialize the software-GDI framebuffer (BGRA8888) and
// register the display update callbacks (§15.8).
//
// IMPORTANT: do NOT overwrite update->BitmapUpdate. gdi_init registers the
// bitmap-cache/primary drawing ops (via bitmap_cache_register_callbacks and
// gdi_register_update_callbacks) that decode BitmapUpdate PDUs and primary
// drawing orders into gdi->primary_buffer. Replacing BitmapUpdate with a
// no-op leaves primary_buffer stuck on the solid-fill preamble (OpaqueRect)
// and never receives icons/glyphs/window content.
static BOOL rdp_cb_post_connect(freerdp *instance)
{
    if (instance == NULL || instance->context == NULL) {
        return FALSE;
    }
    rdp_farsee_context *fcc = rdp_fcc_from_instance(instance);
    if (fcc == NULL || instance->context->settings == NULL) {
        return FALSE;
    }
    const UINT32 w = freerdp_settings_get_uint32(
        instance->context->settings, FreeRDP_DesktopWidth);
    const UINT32 h = freerdp_settings_get_uint32(
        instance->context->settings, FreeRDP_DesktopHeight);
    size_t pixels = 0u;
    size_t requested = 0u;
    if (w == 0u || h == 0u ||
        !rfb_checked_mul_size((size_t)w, (size_t)h, &pixels) ||
        !rfb_checked_mul_size(pixels, 4u, &requested)) {
        return FALSE;
    }
    if (fcc->memory_budget != NULL &&
        !farsee_memory_budget_replace_reservation(
            fcc->memory_budget, &fcc->gdi_reserved, requested)) {
        return FALSE;
    }
    // PIXEL_FORMAT_BGRA32 == BGRA8888 (freerdp/codec/color.h). The GDI backend
    // decodes into gdi->primary_buffer in this format; the display bridge
    // publishes it as FARSEE_PIXEL_BGRA8888.
    if (!gdi_init(instance, PIXEL_FORMAT_BGRA32)) {
        if (fcc->memory_budget != NULL) {
            (void)farsee_memory_budget_replace_reservation(
                fcc->memory_budget, &fcc->gdi_reserved, 0u);
        }
        return FALSE;
    }
    size_t actual = 0u;
    if (instance->context->gdi == NULL ||
        instance->context->gdi->stride <= 0 ||
        instance->context->gdi->height <= 0 ||
        !rfb_checked_mul_size((size_t)instance->context->gdi->stride,
                              (size_t)instance->context->gdi->height,
                              &actual) ||
        (fcc->memory_budget != NULL &&
         !farsee_memory_budget_replace_reservation(
             fcc->memory_budget, &fcc->gdi_reserved, actual))) {
        gdi_free(instance);
        if (fcc->memory_budget != NULL) {
            (void)farsee_memory_budget_replace_reservation(
                fcc->memory_budget, &fcc->gdi_reserved, 0u);
        }
        return FALSE;
    }
    rdpUpdate *update = instance->context->update;
    if (update != NULL) {
        // Presentation only: GDI already owns decode into primary_buffer.
        update->BeginPaint = rdp_cb_begin_paint;
        update->EndPaint = rdp_cb_end_paint;
        update->DesktopResize = rdp_cb_desktop_resize;
    }
    return TRUE;
}

// PostDisconnect: release the GDI framebuffer (paired with gdi_init).
static void rdp_cb_post_disconnect(freerdp *instance)
{
    if (instance != NULL && instance->context != NULL) {
        rdp_farsee_context *fcc = rdp_fcc_from_instance(instance);
        gdi_free(instance);
        if (fcc != NULL && fcc->memory_budget != NULL) {
            (void)farsee_memory_budget_replace_reservation(
                fcc->memory_budget, &fcc->gdi_reserved, 0u);
        }
    }
}

bool rdp_callbacks_install(rdp_freerdp_ctx *ctx,
                           const rdp_callback_context *cbctx)
{
    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    rdp_farsee_context *fcc = rdp_fcc_from_instance(inst);
    if (inst == NULL || cbctx == NULL || fcc == NULL) {
        return false;
    }
    if (!rdp_callbacks_apply_settings(ctx, cbctx)) {
        return false;
    }
    // Stash the callback context on the FreeRDP custom context (per-instance).
    // Cast away const: trust is updated by VerifyX509Certificate; storage
    // is owned by the facade (mutable) for the connection lifetime.
    fcc->cbctx = (rdp_callback_context *)(uintptr_t)cbctx;
    fcc->allocator = cbctx->allocator != NULL ? cbctx->allocator
                                              : rfb_default_allocator();
    fcc->memory_budget = cbctx->memory_budget;
    // Owner back-pointer so PubSub handlers can find the facade handle's
    // per-instance state such as cliprdr.
    fcc->owner = ctx;
    rdp_cliprdr_state *cliprdr = rdp_freerdp_cliprdr_state(ctx);
    if (cliprdr != NULL) {
        cliprdr->allocator = fcc->allocator;
    }
    // Register the callback table; each delegates to a Farsee bridge.
    //   §15.7 VerifyX509Certificate, §15.6 Authenticate,
    //   §10.6/§15.4 PreConnect (settings), §15.8 PostConnect (gdi+update),
    //   PostDisconnect (gdi_free).
    inst->VerifyX509Certificate = rdp_cb_verify_x509;
    inst->Authenticate = rdp_cb_authenticate;
    inst->PreConnect = rdp_cb_pre_connect;
    inst->PostConnect = rdp_cb_post_connect;
    inst->PostDisconnect = rdp_cb_post_disconnect;

    // R6 cliprdr: register static addin provider + LoadChannels + PubSub
    // so freerdp_connect can attach cliprdr when RedirectClipboard is on.
    // Policy/enable is applied by rdp_cliprdr_configure (caller or below).
    if (!rdp_cliprdr_prepare_instance(ctx)) {
        return false;
    }
    // Default configure from the channel allowlist: clipboard_text on ⇒
    // enabled with bidirectional policy.
    // When clipboard_text is false, disable so ChannelConnected is a no-op.
    if (cbctx->settings != NULL && cbctx->settings->channels.clipboard_text) {
        farsee_clip_policy pol = farsee_clip_policy_default();
        pol.direction = FARSEE_CLIP_DIRECTION_BIDIRECTIONAL;
        rdp_cliprdr_configure(ctx, &pol, true);
    } else {
        rdp_cliprdr_configure(ctx, NULL, false);
    }
    return true;
}
