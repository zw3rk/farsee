// SPDX-License-Identifier: Apache-2.0
//
// Farsee common transport: lanes and transport sets.
//
// Transport is a SET of lanes, not one stream (§9.1). A lane has explicit
// semantics describing what the engine may assume — it does NOT pretend
// that TCP and an RDP virtual channel are identical.
//
// Lane semantics:
//   RELIABLE_ORDERED_STREAM  — TCP-like; read/write, partial delivery ok
//   RELIABLE_MESSAGE         — SCTP-like message boundary
//   UNRELIABLE_DATAGRAM      — UDP; send/recv, loss/reorder possible
//   RELIABLE_DATAGRAM        — acknowledged datagrams (protocol-owned)
//   ENGINE_OWNED             — the backend owns transport (FreeRDP); Farsee
//                              supplies policy/metrics only, not I/O.
//
// Opaque: no raw POSIX fd as the only waitable form (§4.2). Engines that
// need reactor integration register via farsee_transport_lane_descriptor.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_TRANSPORT_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_TRANSPORT_H

#include "farsee/farsee_error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FARSEE_LANE_RELIABLE_ORDERED_STREAM = 1,
    FARSEE_LANE_RELIABLE_MESSAGE        = 2,
    FARSEE_LANE_UNRELIABLE_DATAGRAM     = 3,
    FARSEE_LANE_RELIABLE_DATAGRAM       = 4,
    FARSEE_LANE_ENGINE_OWNED            = 5,
} farsee_lane_semantics;

// A descriptor a lane can expose for reactor integration. Only meaningful
// for Farsee-owned lanes; engine-owned lanes return fd=-1.
typedef struct farsee_transport_lane_descriptor {
    int fd;                          // -1 if engine-owned / not pollable
    unsigned read_ready : 1;
    unsigned write_ready : 1;
} farsee_transport_lane_descriptor;

// Opaque lane and set.
typedef struct farsee_transport_lane farsee_transport_lane;
typedef struct farsee_transport_set  farsee_transport_set;

// Per-lane counters (§9.8). No payload content.
typedef struct farsee_transport_metrics {
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t packets_in;     // datagram lanes; 0 for streams
    uint64_t packets_out;
    uint64_t short_read_count;
    uint64_t short_write_count;
} farsee_transport_metrics;

// --- Set lifecycle ---------------------------------------------------------
// A transport set owns its lanes. max_lanes caps registration.
farsee_transport_set *farsee_transport_set_create(size_t max_lanes);
void farsee_transport_set_destroy(farsee_transport_set **s);
size_t farsee_transport_set_count(const farsee_transport_set *s);

// Add an engine-owned lane placeholder (semantics ENGINE_OWNED). Returns a
// stable index or SIZE_MAX on failure. Used by FreeRDP-backed engines to
// declare their owned transports for metrics/policy without exposing fds.
size_t farsee_transport_set_add_engine_owned(farsee_transport_set *s);

// --- Lane queries ----------------------------------------------------------
farsee_lane_semantics farsee_transport_lane_semantics(const farsee_transport_set *s,
                                                      size_t lane_index);
const farsee_transport_metrics *farsee_transport_lane_metrics(const farsee_transport_set *s,
                                                              size_t lane_index);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_TRANSPORT_H
