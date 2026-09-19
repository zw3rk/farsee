// SPDX-License-Identifier: Apache-2.0
//
// G4 fuzz target for the Raw decoder (plan.md §G4, §14.9).
//
// Builds a bounded framebuffer, derives a one-pixel rectangle position from
// the first four input bytes, and passes the remaining bytes to rfb_decode_raw.
// The harness relies on sanitizer instrumentation and does not inspect the
// decoder status or damage result.

#include "farsee/encoding.h"
#include "farsee/framebuffer.h"
#include "farsee/pixel_format.h"
#include "farsee/allocator.h"

#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define FUZZ_FB_W 16u
#define FUZZ_FB_H 16u

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4) {
        return 0;  // need at least a rect header-ish prefix
    }
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    if (rfb_framebuffer_resize(&fb, FUZZ_FB_W, FUZZ_FB_H, 1u << 20) != RFB_OK) {
        rfb_framebuffer_destroy(&fb);
        return 0;
    }
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    // Derive a rectangle header from the first few bytes.
    rfb_rect_header rh;
    rh.x = (uint16_t)(data[0] % FUZZ_FB_W);
    rh.y = (uint16_t)(data[1] % FUZZ_FB_H);
    rh.width = (uint16_t)((data[2] % (FUZZ_FB_W + 1 - rh.x)) ? 1 : 1);
    rh.height = (uint16_t)((data[3] % (FUZZ_FB_H + 1 - rh.y)) ? 1 : 1);
    // Keep the rectangle small so the fuzzer explores payloads deeply.
    rh.width = 1;
    rh.height = 1;
    rh.encoding = RFB_ENCODING_RAW;
    const uint8_t *payload = data + 4;
    size_t payload_len = size > 4 ? size - 4 : 0;
    rfb_rect damage = { 0 };
    (void)rfb_decode_raw(&fb, &pf, &rh, payload, payload_len, &damage);
    rfb_framebuffer_destroy(&fb);
    return 0;
}
