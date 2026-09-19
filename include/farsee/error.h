// SPDX-License-Identifier: Apache-2.0
//
// farsee — typed error system (plan.md §G1: "typed error system with
// stable error codes").
//
// rfb_error values are stable so callers can switch on them. APIs that
// return rfb_error map failures to this enum. rfb_strerror returns only
// static text and does not include remote input (plan.md §6.3).

#ifndef FARSEE_INCLUDE_FARSEE_ERROR_H
#define FARSEE_INCLUDE_FARSEE_ERROR_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Stable error codes. Append-only; never renumber an existing value.
typedef enum {
    RFB_OK              = 0,
    RFB_ERR_NOMEM       = 1,   // allocation failure (injectable)
    RFB_ERR_OVERFLOW    = 2,   // checked arithmetic rejected an operation
    RFB_ERR_LIMIT       = 3,   // a configured hard limit was exceeded
    RFB_ERR_EOF         = 4,   // peer closed the connection
    RFB_ERR_IO          = 5,   // I/O error
    RFB_ERR_PROTOCOL    = 6,   // the peer violated the protocol
    RFB_ERR_STATE       = 7,   // operation not valid in current state
    RFB_ERR_UNSUPPORTED = 8,   // feature is intentionally not implemented
    RFB_ERR_AUTH        = 9,   // authentication failed or was cancelled
    RFB_ERR_CANCELLED   = 10,  // session cancelled by caller
    RFB_ERR_TIMEOUT     = 11,  // a configured timeout elapsed
    RFB_ERR_INTERNAL    = 12,  // bug: invariant violated, no remote cause
} rfb_error;

// Human-readable description. Returned strings are static literals and
// never include remote-controlled text.
const char *rfb_strerror(rfb_error e);

// Convenience: true iff the error code represents a failure.
static inline bool rfb_failed(rfb_error e)
{
    return e != RFB_OK;
}

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_ERROR_H
