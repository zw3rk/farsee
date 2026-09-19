// SPDX-License-Identifier: Apache-2.0
//
// Versioned pathless control datagrams for capture-only scene mutation.

#ifndef FARSEE_INCLUDE_FARSEE_RFB_CAPTURE_CONTROL_H
#define FARSEE_INCLUDE_FARSEE_RFB_CAPTURE_CONTROL_H

#if defined(FARSEE_RELEASE_BUILD) && \
    defined(FARSEE_ENABLE_CAPTURE_DIAGNOSTICS)
#error "capture diagnostics cannot be enabled in release builds"
#endif

#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RFB_CAPTURE_CONTROL_WIRE_SIZE ((size_t)52u)
#define RFB_CAPTURE_CONTROL_BINDING_SIZE ((size_t)32u)

typedef enum rfb_capture_control_kind {
    RFB_CAPTURE_CONTROL_READY_FOR_MUTATION = 1,
    RFB_CAPTURE_CONTROL_MUTATION_ACK = 2
} rfb_capture_control_kind;

typedef struct rfb_capture_control_message {
    rfb_capture_control_kind kind;
    uint64_t slot_nonce;
    uint32_t transition_id;
    uint8_t source_b_binding[RFB_CAPTURE_CONTROL_BINDING_SIZE];
} rfb_capture_control_message;

rfb_error rfb_capture_control_encode(
    const rfb_capture_control_message *message, uint8_t *out,
    size_t out_capacity, size_t *out_length);
rfb_error rfb_capture_control_decode(
    const uint8_t *wire, size_t wire_length,
    rfb_capture_control_message *out);

// True only for one endpoint of a connected, pathless, nonblocking
// AF_UNIX/SOCK_DGRAM socketpair. Filesystem and abstract names are rejected.
bool rfb_capture_control_endpoint_valid(int fd);

// Drain all currently queued datagrams through EAGAIN. Exactly one matching
// ACK is accepted only after the drain completes; duplicates and any malformed
// or early traffic fail atomically with *accepted false.
rfb_error rfb_capture_control_drain_ack(
    int fd, bool allow_ack, uint64_t slot_nonce, uint32_t transition_id,
    const uint8_t source_b_binding[RFB_CAPTURE_CONTROL_BINDING_SIZE],
    bool *accepted);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_RFB_CAPTURE_CONTROL_H
