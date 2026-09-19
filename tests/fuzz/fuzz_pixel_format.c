// SPDX-License-Identifier: Apache-2.0
// G12 fuzz: pixel format validation (plan.md §14.9).
#include "farsee/pixel_format.h"
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 10) return 0;
    rfb_pixel_format pf;
    pf.bits_per_pixel = data[0];
    pf.depth = data[1];
    pf.big_endian = data[2];
    pf.true_color = data[3];
    pf.red_max = (uint16_t)((data[4]<<8)|data[5]);
    pf.green_max = (uint16_t)((data[6]<<8)|data[7]);
    pf.blue_max = (uint16_t)((data[8]<<8)|data[9]);
    pf.red_shift = size > 10 ? data[10] : 0;
    pf.green_shift = size > 11 ? data[11] : 0;
    pf.blue_shift = size > 12 ? data[12] : 0;
    (void)rfb_pixel_format_valid(&pf);
    return 0;
}
