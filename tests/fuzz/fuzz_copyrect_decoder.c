// SPDX-License-Identifier: Apache-2.0
// G12 fuzz: CopyRect decoder (plan.md §14.9).
#include "farsee/encoding.h"
#include "farsee/framebuffer.h"
#include "farsee/allocator.h"
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 12) return 0;
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    if (rfb_framebuffer_resize(&fb, 16, 16, 1u<<20) != RFB_OK) { rfb_framebuffer_destroy(&fb); return 0; }
    rfb_rect_header rh = { .x = data[0]%16, .y = data[1]%16,
                           .width = data[2]%4+1, .height = data[3]%4+1,
                           .encoding = RFB_ENCODING_COPYRECT };
    rfb_rect dmg = {0};
    (void)rfb_decode_copyrect(&fb, &rh, data+4, size-4, &dmg);
    rfb_framebuffer_destroy(&fb);
    return 0;
}
