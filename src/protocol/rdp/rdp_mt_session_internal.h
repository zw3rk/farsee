// SPDX-License-Identifier: Apache-2.0
//
// Private deterministic seam for the RDP multi-thread session owner.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_MT_SESSION_INTERNAL_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_MT_SESSION_INTERNAL_H

#include "rdp_mt_session.h"

typedef enum rdp_mt_pump_result {
    RDP_MT_PUMP_IDLE = 0,
    RDP_MT_PUMP_PROGRESS,
    RDP_MT_PUMP_TRANSPORT_FAILURE,
    RDP_MT_PUMP_DISPATCH_FAILURE,
} rdp_mt_pump_result;

typedef struct rdp_mt_session_ops {
    void *user;

    farsee_error (*run_threads)(void *user, const farsee_mt_config *cfg,
                                farsee_mt_outcome *outcome);
    farsee_mt_terminal_kind (*present_loop)(
        void *user, farsee_frame_slot *slot, farsee_atomic_int *stop,
        uint32_t interval_ms, farsee_mt_on_frame_fn on_frame,
        void *on_frame_user, farsee_mt_after_present_fn after_present,
        void *after_present_user, farsee_atomic_int *force_repaint,
        farsee_mt_terminal *terminal);

    void *(*protocol_context)(void *user, rdp_freerdp_ctx *ctx);
    bool (*shall_disconnect)(void *user, void *protocol_context);
    rdp_mt_pump_result (*pump_once)(void *user, void *protocol_context);
    bool (*clean_peer_disconnect)(void *user, rdp_freerdp_ctx *ctx);

    uint64_t (*monotonic_ms)(void *user);
    bool (*wire_stats)(void *user, rdp_freerdp_ctx *ctx,
                       uint64_t *out_in_bytes, uint64_t *out_out_bytes);
    int (*wire_fd)(void *user, rdp_freerdp_ctx *ctx);
    uint32_t (*tcp_stats)(void *user, int fd, uint32_t *out_rtt_ms);

    bool (*key_event_from_keysym)(void *user, farsee_key_event *out,
                                  uint32_t keysym, uint32_t unicode,
                                  bool down, bool repeat);
    bool (*inject_key_from_keysym)(void *user, rdp_freerdp_ctx *ctx,
                                   uint32_t keysym, uint32_t unicode,
                                   bool down, bool repeat);
    bool (*inject_pointer)(void *user, rdp_freerdp_ctx *ctx,
                           const farsee_pointer_event *event,
                           unsigned previous_buttons,
                           unsigned *out_reached);
    void (*release_all)(void *user, rdp_freerdp_ctx *ctx,
                        farsee_key_ledger *ledger);
    void (*request_stop)(void *user, rdp_freerdp_ctx *ctx);
    bool (*present_bgra)(void *user, rdp_freerdp_ctx *ctx,
                         const uint8_t *pixels, uint32_t width,
                         uint32_t height, uint32_t stride,
                         bool cursor_visible, int32_t cursor_x,
                         int32_t cursor_y);
} rdp_mt_session_ops;

// Private entry used by deterministic tests. NULL operation members use the
// production implementation. All pointers are borrowed through the call.
farsee_error rdp_mt_run_with_ops(const rdp_mt_config *cfg,
                                 bool *out_got_frame,
                                 farsee_mt_outcome *outcome,
                                 const rdp_mt_session_ops *ops);

#endif  // FARSEE_SRC_PROTOCOL_RDP_RDP_MT_SESSION_INTERNAL_H
