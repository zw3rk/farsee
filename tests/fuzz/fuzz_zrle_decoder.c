// SPDX-License-Identifier: Apache-2.0
//
// G8 fuzz target: ZRLE decoder (plan.md §14.9: "fuzz_zrle_decoder").
//
// Feeds arbitrary bytes as a ZRLE compressed payload into a small fixed
// framebuffer and asserts no crash, no sanitizer finding, and no
// out-of-bounds write.

#include "farsee/encoding_zrle.h"
#include "farsee/framebuffer.h"
#include "farsee/pixel_format.h"
#include "farsee/zlib_adapter.h"
#include "farsee/allocator.h"

#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) return 0;
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    if (rfb_framebuffer_resize(&fb, 16, 16, 1u << 20) != RFB_OK) {
        rfb_framebuffer_destroy(&fb);
        return 0;
    }
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 16, .height = 16,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    (void)rfb_decode_zrle(&fb, &pf, &rh, zs, data, size, 1u << 20, &dmg);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
    return 0;
}
