// SPDX-License-Identifier: Apache-2.0
//
// farsee — typed error string table.
//
// Messages are static literals only. They never embed remote-controlled
// text; per-call diagnostics are produced by the logging layer, which is
// responsible for escaping untrusted text before display.

#include "farsee/error.h"

const char *rfb_strerror(rfb_error e)
{
    switch (e) {
    case RFB_OK:              return "ok";
    case RFB_ERR_NOMEM:       return "out of memory";
    case RFB_ERR_OVERFLOW:    return "checked-arithmetic overflow";
    case RFB_ERR_LIMIT:       return "configured hard limit exceeded";
    case RFB_ERR_EOF:         return "peer closed the connection";
    case RFB_ERR_IO:          return "I/O error";
    case RFB_ERR_PROTOCOL:    return "protocol error";
    case RFB_ERR_STATE:       return "invalid state for operation";
    case RFB_ERR_UNSUPPORTED: return "feature is not implemented";
    case RFB_ERR_AUTH:        return "authentication failed";
    case RFB_ERR_CANCELLED:   return "cancelled";
    case RFB_ERR_TIMEOUT:     return "timeout";
    case RFB_ERR_INTERNAL:    return "internal error";
    }
    // No default: -Wswitch-enum forces the compiler to
    // keep this exhaustive. If a new code is added without a case, the
    // build fails.
    return "unknown error";
}
