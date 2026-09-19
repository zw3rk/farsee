// SPDX-License-Identifier: Apache-2.0
//
// Private RDP live orchestration seam for deterministic lifecycle tests.

#ifndef FARSEE_SRC_APP_RDP_LIVE_INTERNAL_H
#define FARSEE_SRC_APP_RDP_LIVE_INTERNAL_H

#include "app/rdp_live.h"

#ifdef FARSEE_WITH_RDP

#include "farsee/memory_budget.h"
#include "protocol/rdp/rdp_callbacks.h"

struct rdp_live_tick;

// A supplied table must contain every operation. The runner rejects partial
// tables before it reads credentials or calls an operation.
typedef struct rdp_live_facade_ops {
    bool (*set_library_log_level)(rdp_liblog_level level);
    rdp_freerdp_ctx *(*create)(void);
    void (*destroy)(rdp_freerdp_ctx **ctx);
    void (*set_presenter)(rdp_freerdp_ctx *ctx,
                          farsee_presenter *presenter,
                          rdp_display_sink *sink);
    bool (*apply_settings_with_memory_budget)(
        rdp_freerdp_ctx *ctx, const farsee_rdp_settings *settings,
        const farsee_security_policy *policy,
        const farsee_credential_response *credentials,
        farsee_trust_decision trust, const char *known_hosts_path,
        farsee_memory_budget *memory_budget);
    bool (*connect_with_stop)(rdp_freerdp_ctx *ctx,
                              farsee_atomic_int *stop);
    void (*clear_credentials)(rdp_freerdp_ctx *ctx);
    farsee_error (*run_until)(rdp_freerdp_ctx *ctx,
                              const rdp_run_budget *budget,
                              bool *out_first_frame);
    void (*request_stop)(rdp_freerdp_ctx *ctx);
    void (*disconnect)(rdp_freerdp_ctx *ctx);
    const char *(*last_error_name)(const rdp_freerdp_ctx *ctx);
    bool (*is_clean_peer_disconnect)(const rdp_freerdp_ctx *ctx);
} rdp_live_facade_ops;

int farsee_run_rdp_with_facade_ops(
    const char *host, uint16_t port, const char *user, const char *domain,
    const char *cert_policy, int password_fd, uint32_t desk_w,
    uint32_t desk_h, const char *presenter_name,
    uint64_t connect_timeout_ms, bool view_only, bool clipboard_on,
    rdp_liblog_level liblog, const farsee_cli_leader *leader_spec,
    const rdp_live_facade_ops *facade_ops);

// Private live-owner operations. The caller retains the tick and descriptor;
// these operations do not close or free either one.
void rdp_live_flush_pending_graphics(struct rdp_live_tick *tick);
void rdp_live_discard_tty_responses(int tty_fd);

// Saturating absolute deadline used by the bounded null-presenter session.
uint64_t rdp_live_deadline_after(uint64_t now, uint64_t timeout,
                                 uint64_t settle);

#endif  // FARSEE_WITH_RDP

#endif  // FARSEE_SRC_APP_RDP_LIVE_INTERNAL_H
