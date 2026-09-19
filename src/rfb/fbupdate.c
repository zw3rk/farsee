// SPDX-License-Identifier: Apache-2.0
//
// farsee — FramebufferUpdate header parser (plan.md §G4, RFC 6143 §7.6.1).

#include "farsee/fbupdate.h"

rfb_error rfb_parse_fbupdate_header(rfb_reader *r, uint16_t *out_num_rects)
{
    if (r == NULL || out_num_rects == NULL) {
        return RFB_ERR_INTERNAL;
    }
    uint8_t type = 0;
    if (!rfb_read_u8(r, &type)) {
        return RFB_ERR_PROTOCOL;
    }
    if (type != 0) {  // FramebufferUpdate is message-type 0
        return RFB_ERR_PROTOCOL;
    }
    uint8_t pad = 0;
    if (!rfb_read_u8(r, &pad)) {
        return RFB_ERR_PROTOCOL;
    }
    (void)pad;
    if (!rfb_read_u16(r, out_num_rects)) {
        return RFB_ERR_PROTOCOL;
    }
    return RFB_OK;
}

rfb_error rfb_parse_rect_header(rfb_reader *r, rfb_rect_header *out)
{
    if (r == NULL || out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    uint16_t x = 0, y = 0, w = 0, h = 0;
    uint32_t enc = 0;
    if (!rfb_read_u16(r, &x) || !rfb_read_u16(r, &y) ||
        !rfb_read_u16(r, &w) || !rfb_read_u16(r, &h) ||
        !rfb_read_u32(r, &enc)) {
        return RFB_ERR_PROTOCOL;
    }
    out->x = x;
    out->y = y;
    out->width = w;
    out->height = h;
    out->encoding = (int32_t)enc;  // reinterpret bits; pseudo-encodings are negative
    return RFB_OK;
}
