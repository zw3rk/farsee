// SPDX-License-Identifier: Apache-2.0
//
// farsee — server→client message parsers (plan.md §G6, RFC 6143 §7.6).

#include "farsee/server_messages.h"

rfb_error rfb_parse_bell(rfb_reader *r)
{
    // Bell is just the type byte (already consumed by the caller). No
    // additional payload to read.
    if (r == NULL) {
        return RFB_ERR_INTERNAL;
    }
    return RFB_OK;
}

rfb_error rfb_parse_server_cut_text(rfb_reader *r,
                                    uint8_t *out, size_t cap, size_t *out_len,
                                    size_t hard_limit)
{
    if (r == NULL || out_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    *out_len = 0;
    // u8 pad[3]
    if (!rfb_reader_skip(r, 3)) {
        return RFB_ERR_PROTOCOL;
    }
    uint32_t len = 0;
    if (!rfb_read_u32(r, &len)) {
        return RFB_ERR_PROTOCOL;
    }
    if (len > hard_limit) {
        return RFB_ERR_LIMIT;
    }
    if (out == NULL && len > 0) {
        return RFB_ERR_INTERNAL;
    }
    if ((size_t)len > cap) {
        return RFB_ERR_LIMIT;
    }
    if (len > 0) {
        if (!rfb_read_bytes(r, out, len)) {
            return RFB_ERR_PROTOCOL;
        }
    }
    *out_len = len;
    return RFB_OK;
}
