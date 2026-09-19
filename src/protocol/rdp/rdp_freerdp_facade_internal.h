// SPDX-License-Identifier: Apache-2.0
//
// Private deterministic seam for the FreeRDP event-pump facade.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_FREERDP_FACADE_INTERNAL_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_FREERDP_FACADE_INTERNAL_H

#include "rdp_freerdp_facade.h"

typedef void *rdp_freerdp_wait_handle;

typedef enum rdp_freerdp_wait_result {
    RDP_FREERDP_WAIT_FAILED = 0,
    RDP_FREERDP_WAIT_TIMEOUT,
    RDP_FREERDP_WAIT_SIGNALED,
} rdp_freerdp_wait_result;

typedef struct rdp_freerdp_run_ops {
    void *user;
    bool (*shall_disconnect)(void *user, void *context);
    void (*abort_connect)(void *user, void *context);
    size_t (*get_event_handles)(void *user, void *context,
                                rdp_freerdp_wait_handle *handles,
                                size_t capacity);
    rdp_freerdp_wait_handle (*abort_event)(void *user, void *context);
    rdp_freerdp_wait_result (*wait)(
        void *user, const rdp_freerdp_wait_handle *handles,
        size_t handle_count, uint32_t timeout_ms);
    bool (*check_event_handles)(void *user, void *context);
    uint64_t (*monotonic_ms)(void *user);
    uint32_t (*last_error)(void *user, void *context);
} rdp_freerdp_run_ops;

typedef struct rdp_freerdp_stats_ops {
    void *user;
    bool (*is_active)(void *user, void *context);
    bool (*get_stats)(void *user, void *context, uint64_t *out_in_bytes,
                      uint64_t *out_out_bytes);
} rdp_freerdp_stats_ops;

// Private stats entry used to verify inactive, unavailable, and successful
// counter states without a network endpoint.
bool rdp_freerdp_wire_stats_context(
    void *context, uint64_t *out_in_bytes, uint64_t *out_out_bytes,
    const rdp_freerdp_stats_ops *ops);

// Private entry used by deterministic tests. The context is opaque to this
// state machine. Every operation must be supplied and remains borrowed.
farsee_error rdp_freerdp_run_context_until(
    void *context, const rdp_run_budget *budget, bool *out_first_frame,
    const rdp_freerdp_run_ops *ops);

#endif  // FARSEE_SRC_PROTOCOL_RDP_RDP_FREERDP_FACADE_INTERNAL_H
