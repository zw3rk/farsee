// SPDX-License-Identifier: Apache-2.0
//
// farsee — ServerInit parsing + SetPixelFormat/SetEncodings emission
// (plan.md §G3, RFC 6143 §7.3.2, §7.4.1, §7.5.1, §7.5.2).

#include "farsee/server_init.h"

#include "farsee/allocator.h"
#include "farsee/limits.h"

#include <stdlib.h>
#include <string.h>

rfb_error rfb_parse_server_init(const uint8_t *in, size_t in_len,
                                rfb_server_init *out, size_t name_cap)
{
    if (out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    memset(out, 0, sizeof *out);
    if (in == NULL) {
        return RFB_ERR_PROTOCOL;
    }
    // Fixed header is 24 bytes: u16 width, u16 height, 16-byte PIXEL_FORMAT,
    // u32 name-length.
    if (in_len < 24) {
        return RFB_ERR_PROTOCOL;
    }
    rfb_reader r = rfb_reader_make(in, in_len);
    uint16_t width = 0, height = 0;
    if (!rfb_read_u16(&r, &width) || !rfb_read_u16(&r, &height)) {
        return RFB_ERR_PROTOCOL;
    }
    // PIXEL_FORMAT fields (RFC 6143 §7.4.1).
    rfb_pixel_format pf;
    memset(&pf, 0, sizeof pf);
    uint8_t bpp = 0, depth = 0, be = 0, tc = 0;
    uint16_t rmax = 0, gmax = 0, bmax = 0;
    uint8_t rshift = 0, gshift = 0, bshift = 0;
    if (!rfb_read_u8(&r, &bpp) || !rfb_read_u8(&r, &depth) ||
        !rfb_read_u8(&r, &be) || !rfb_read_u8(&r, &tc) ||
        !rfb_read_u16(&r, &rmax) || !rfb_read_u16(&r, &gmax) ||
        !rfb_read_u16(&r, &bmax) ||
        !rfb_read_u8(&r, &rshift) || !rfb_read_u8(&r, &gshift) ||
        !rfb_read_u8(&r, &bshift)) {
        return RFB_ERR_PROTOCOL;
    }
    pf.bits_per_pixel = bpp;
    pf.depth = depth;
    pf.big_endian = be;
    pf.true_color = tc;
    pf.red_max = rmax;
    pf.green_max = gmax;
    pf.blue_max = bmax;
    pf.red_shift = rshift;
    pf.green_shift = gshift;
    pf.blue_shift = bshift;
    // 3 bytes of padding.
    if (!rfb_reader_skip(&r, 3)) {
        return RFB_ERR_PROTOCOL;
    }
    // Validate the format before committing (plan.md §12.3).
    if (!rfb_pixel_format_valid(&pf)) {
        return RFB_ERR_PROTOCOL;
    }
    // Validate framebuffer dimensions against policy limits (H16 from review).
    if (width == 0 || height == 0 ||
        (uint32_t)width > RFB_LIMIT_FB_WIDTH_MAX ||
        (uint32_t)height > RFB_LIMIT_FB_HEIGHT_MAX) {
        return RFB_ERR_PROTOCOL;
    }
    // Name length (u32) + name bytes.
    uint32_t name_len = 0;
    if (!rfb_read_u32(&r, &name_len)) {
        return RFB_ERR_PROTOCOL;
    }
    if (name_len > name_cap) {
        return RFB_ERR_LIMIT;
    }
    if (rfb_reader_remaining(&r) < name_len) {
        return RFB_ERR_PROTOCOL;
    }
    // Allocate name_len + 1 for the null terminator.
    char *name = NULL;
    if (name_len > 0) {
        rfb_allocator *a = rfb_default_allocator();
        name = (char *)a->alloc(a, (size_t)name_len + 1);
        if (name == NULL) {
            return RFB_ERR_NOMEM;
        }
        if (!rfb_read_bytes(&r, name, name_len)) {
            a->free(a, name);
            return RFB_ERR_PROTOCOL;
        }
        name[name_len] = '\0';
    } else {
        // Empty name: still provide a non-NULL empty string for convenience.
        rfb_allocator *a = rfb_default_allocator();
        name = (char *)a->alloc(a, 1);
        if (name == NULL) {
            return RFB_ERR_NOMEM;
        }
        name[0] = '\0';
    }
    out->width = width;
    out->height = height;
    out->pixel_format = pf;
    out->name_length = name_len;
    out->name = name;
    return RFB_OK;
}

void rfb_server_init_destroy(rfb_server_init *si)
{
    if (si == NULL) {
        return;
    }
    if (si->name != NULL) {
        rfb_allocator *a = rfb_default_allocator();
        a->free(a, si->name);
    }
    si->name = NULL;
    si->name_length = 0;
}

rfb_error rfb_format_set_pixel_format(rfb_writer *w, const rfb_pixel_format *pf)
{
    if (w == NULL || pf == NULL) {
        return RFB_ERR_INTERNAL;
    }
    // message-type 0, 3 pad bytes.
    if (!rfb_write_u8(w, 0)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(w, 0)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(w, 0)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(w, 0)) return RFB_ERR_LIMIT;
    // PIXEL_FORMAT (16 bytes).
    if (!rfb_write_u8(w, pf->bits_per_pixel)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(w, pf->depth)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(w, pf->big_endian)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(w, pf->true_color)) return RFB_ERR_LIMIT;
    if (!rfb_write_u16(w, pf->red_max)) return RFB_ERR_LIMIT;
    if (!rfb_write_u16(w, pf->green_max)) return RFB_ERR_LIMIT;
    if (!rfb_write_u16(w, pf->blue_max)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(w, pf->red_shift)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(w, pf->green_shift)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(w, pf->blue_shift)) return RFB_ERR_LIMIT;
    // 3 bytes padding.
    if (!rfb_write_u8(w, 0)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(w, 0)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(w, 0)) return RFB_ERR_LIMIT;
    return RFB_OK;
}

rfb_error rfb_format_set_encodings(rfb_writer *w,
                                   const int32_t *encodings, uint16_t count)
{
    if (w == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (count > 0 && encodings == NULL) {
        return RFB_ERR_INTERNAL;
    }
    // message-type 2, 1 pad byte, u16 count, then count big-endian i32s.
    if (!rfb_write_u8(w, 2)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(w, 0)) return RFB_ERR_LIMIT;
    if (!rfb_write_u16(w, count)) return RFB_ERR_LIMIT;
    for (uint16_t i = 0; i < count; i++) {
        // Reinterpret the signed value as unsigned for big-endian emission;
        // the bits are identical.
        uint32_t u = (uint32_t)encodings[i];
        if (!rfb_write_u32(w, u)) return RFB_ERR_LIMIT;
    }
    return RFB_OK;
}
