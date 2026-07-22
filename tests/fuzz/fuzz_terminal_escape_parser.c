// SPDX-License-Identifier: Apache-2.0
// G12 fuzz: terminal escape / remote-text escape parser (plan.md §14.9).
#include "farsee/log.h"
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char out[512];
    (void)rfb_log_escape_remote(data, size, out, sizeof out);
    return 0;
}
