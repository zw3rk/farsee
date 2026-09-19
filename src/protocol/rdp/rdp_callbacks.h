// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP FreeRDP callback wiring (R6 in-process wiring, §15.5/§15.6/§15.7).
//
// Installs FreeRDP instance callbacks that delegate to the Farsee-owned
// bridges (rdp_trust_bridge, rdp_display_bridge, rdp_input_bridge,
// rdp_clipboard_bridge) and applies settings (username/domain from the
// credential response, channel allowlist). FreeRDP types stay confined to
// the private callback implementation; bridges receive Farsee-owned types.
//
// The callbacks target the pinned FreeRDP 3.15.0 API.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_CALLBACKS_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_CALLBACKS_H

#include "rdp_freerdp_facade.h"
#include "rdp_settings.h"
#include "farsee/farsee_atomic.h"
#include "farsee/farsee_presenter_v2.h"
#include "farsee/farsee_security.h"
#include "farsee/memory_budget.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// User-context bundle passed to the FreeRDP callbacks. It carries the
// trust decision + credential response so the callbacks can delegate to
// the bridges without re-prompting. Owned by the worker.
//
// `trust` is mutable: apply_settings starts at REJECT; VerifyX509Certificate
// updates it after fingerprinting the peer cert (§15.7 / §10.4).
// `peer_cert_decided`: set true when FreeRDP invokes VerifyX509Certificate.
// Outside pin mode, FreeRDP can skip it for a system-CA trusted peer and
// Authenticate may treat that peer as TLS-validated. Pin mode enables external
// certificate management and requires the callback for every peer. If the
// callback runs, only `trust` after evaluation governs credentials.
// `known_hosts_path`: TOFU store path (product always sets a default path).
typedef struct rdp_callback_context {
    rfb_allocator *allocator;            // borrowed; NULL selects default
    farsee_memory_budget *memory_budget; // borrowed; optional logical GDI cap
    farsee_trust_decision trust;
    bool peer_cert_decided;
    const farsee_credential_response *credentials;
    const farsee_security_policy *policy;
    const farsee_rdp_settings *settings;
    const char *known_hosts_path;  // TOFU; NULL disables store
} rdp_callback_context;

// Display sink: the run loop and the EndPaint callback cooperate through
// this small shared state. The CLI allocates one, calls
// rdp_callbacks_set_presenter before connect, and the run loop reads
// first_frame_delivered to decide when to stop (stop_on_first_frame).
// Cross-thread counters/flags use farsee_atomic_* (not volatile).
// Desk size is published as ONE atomic u64 — (width << 32) | height — so
// the present-thread reader always observes a consistent pair; two plain
// uint32 fields would race during resize. Helpers below.
static inline uint64_t rdp_desk_size_pack(uint32_t w, uint32_t h)
{
    return ((uint64_t)w << 32) | (uint64_t)h;
}

static inline void rdp_desk_size_unpack(uint64_t packed, uint32_t *w,
                                        uint32_t *h)
{
    *w = (uint32_t)(packed >> 32);
    *h = (uint32_t)(packed & 0xFFFFFFFFu);
}

typedef struct rdp_display_sink {
    farsee_presenter *presenter;       // NULL until set_presenter
    farsee_atomic_int first_frame_delivered; // 0/1
    farsee_atomic_u64 frame_count;
    farsee_atomic_u64 last_desk_size;  // rdp_desk_size_pack(w, h)
    uint32_t max_dimension;            // validation cap (§15.8)
    // Optional minimum ms between local presents. 0 = no artificial cap
    // (preferred for Kitty SHM). Only useful for expensive paths (base64
    // t=d) where flooding the TTY is worse than slight visual lag.
    uint64_t min_present_interval_ms;
    uint64_t last_present_monotonic_ms;
    // When true, EndPaint only marks present_pending; the run loop calls
    // rdp_callbacks_flush_present() after pumping TTY input so SHM/Kitty
    // work never starves keyboard/mouse on the same thread.
    bool defer_present;
    farsee_atomic_int present_pending; // 0/1
    // Local software cursor (live mode): drawn into a present staging
    // buffer so the operator sees where clicks aim. Remote RDP has its own
    // server cursor; this is display-only. Position is published by the
    // input thread; the present thread loads a snapshot. Overlay is only
    // painted when a protocol frame is presented (never force a
    // full-frame present for cursor alone).
    farsee_atomic_int cursor_visible; // 0/1
    farsee_atomic_int cursor_x;
    farsee_atomic_int cursor_y;
    // EndPaint marks (server-driven paints) vs presents we actually pushed
    // to Kitty — for FPS diagnostics in WLog-enabled developer builds.
    farsee_atomic_u64 end_paint_count;
    // First failed frame publication while frame_slot is active. Stores a
    // farsee_frame_publish_result value for the protocol thread.
    farsee_atomic_int frame_publish_failure;
    // Multi-thread latest-frame publish. If non-NULL, EndPaint copies the
    // GDI primary into the slot instead of setting present_pending.
    // (struct farsee_frame_slot — rdp_frame_slot is a typedef of this.)
    struct farsee_frame_slot *frame_slot;
} rdp_display_sink;

// Present a raw BGRA buffer through the presenter installed on `ctx`
// (cursor overlay optional). Used by the dedicated present thread.
// Thread-safe only if the presenter itself is; FreeRDP is not touched.
// Resolves presenter/sink from the FreeRDP custom context for `ctx` —
// never from process globals. Returns false if ctx has no presenter/sink.
bool rdp_callbacks_present_bgra(rdp_freerdp_ctx *ctx, const uint8_t *bgra,
                                uint32_t w, uint32_t h, uint32_t stride,
                                bool cursor_visible, int32_t cursor_x,
                                int32_t cursor_y);

// Initialize a sink (no presenter, no frames delivered).
void rdp_display_sink_init(rdp_display_sink *sink);

// Publish one BGRA frame to the configured MT slot. A failure is latched in
// frame_publish_failure so the protocol runner can preserve its exact cause.
bool rdp_display_sink_publish_frame(rdp_display_sink *sink,
                                    const uint8_t *bgra, uint32_t w,
                                    uint32_t h, uint32_t stride);

// If defer_present is set and a frame is pending (and rate-limit allows),
// push the latest GDI primary_buffer to the presenter on `ctx`. Call from
// the live tick AFTER reading TTY input. No-op if nothing pending / NULL ctx.
void rdp_callbacks_flush_present(rdp_freerdp_ctx *ctx);

// Recover the owning facade handle from the FreeRDP rdpContext that PubSub
// handlers receive. Per-instance state such as cliprdr hangs off the
// facade handle; NULL-safe).
rdp_freerdp_ctx *rdp_callbacks_owner_from_rdp_context(void *rdp_context);

// FreeRDP custom-context size (rdpContext + Farsee callback fields). The
// facade must set freerdp->ContextSize to this before freerdp_context_new.
size_t rdp_callbacks_context_size(void);

// Prepare a raw freerdp* (from freerdp_new) for Farsee: ContextSize +
// ContextFree. Call before freerdp_context_new. Opaque void* so callers
// outside this TU need not include FreeRDP headers beyond the facade.
void rdp_callbacks_prepare_instance(void *freerdp_instance);

// Install the Farsee callback table on the facade's FreeRDP instance:
//   - VerifyX509Certificate  -> rdp_trust_bridge (§15.7)
//   - Authenticate           -> credential bridge (§15.6)
//   - PreConnect             -> apply settings + channel allowlist (§10.6)
//   - PostConnect            -> gdi_init(BGRA8888) + register update cb (§15.8)
//   - PostDisconnect         -> gdi_free
//   - update->BeginPaint/EndPaint/DesktopResize -> display bridge
//     (BitmapUpdate is left to gdi_init's registered decoder)
// Stores cbctx on the FreeRDP custom context (not a process global).
// Returns false if the facade/context is invalid. Does NOT connect.
bool rdp_callbacks_install(rdp_freerdp_ctx *ctx,
                           const rdp_callback_context *cbctx);

// Stash the presenter + sink on the FreeRDP custom context for `ctx` so
// EndPaint / present_bgra can deliver frames. Safe to call before connect.
// The caller owns both. NULL ctx is a no-op.
void rdp_callbacks_set_presenter(rdp_freerdp_ctx *ctx,
                                 farsee_presenter *presenter,
                                 rdp_display_sink *sink);

// Settings application (PreConnect-equivalent): write hostname/port/desktop
// dimensions, username/domain from the credential response, the security
// posture (§15.4), and disable every non-allowlisted channel (§10.6).
// Returns false on a settings write failure or an out-of-baseline channel.
bool rdp_callbacks_apply_settings(rdp_freerdp_ctx *ctx,
                                  const rdp_callback_context *cbctx);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_PROTOCOL_RDP_RDP_CALLBACKS_H
