// SPDX-License-Identifier: Apache-2.0
//
// Copyright (c) Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
//
// Fuzz target for the Apple MultiVariant (0x03f3) type-0 image decoder.
//
// The first byte selects tile geometry and a decode flag. The next 128 bytes
// supply two quantization tables; the remaining bytes are the image payload.
// The harness calls the decoder against a bounded framebuffer and relies on
// sanitizer instrumentation. It does not inspect the status or damage result.

#include "farsee/allocator.h"
#include "farsee/encoding_apple_mvs.h"
#include "farsee/framebuffer.h"

#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // 1 byte of geometry + 2 x 64 table bytes + the payload.
    if (size < 130u) {
        return 0;
    }
    const uint32_t tiles_w = 1u + (data[0] & 3u);
    const uint32_t tiles_h = 1u + ((data[0] >> 2) & 3u);
    const uint32_t w = tiles_w * 8u;
    const uint32_t h = tiles_h * 8u;
    uint8_t qt0[64];
    uint8_t qt1[64];
    memcpy(qt0, data + 1, sizeof qt0);
    memcpy(qt1, data + 65, sizeof qt1);

    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    if (rfb_framebuffer_resize(&fb, w, h, 1u << 20) != RFB_OK) {
        rfb_framebuffer_destroy(&fb);
        return 0;
    }
    rfb_rect_header rh = {.x = 0,
                          .y = 0,
                          .width = (uint16_t)w,
                          .height = (uint16_t)h,
                          .encoding = RFB_ENCODING_APPLE_MVS};
    rfb_rect dmg;
    memset(&dmg, 0, sizeof dmg);
    (void)rfb_decode_apple_mvs(&fb, &rh, data + 129, size - 129u,
                               (data[0] & 0x40u) != 0u, qt0, qt1, NULL, &dmg);
    rfb_framebuffer_destroy(&fb);
    return 0;
}
