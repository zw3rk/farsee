// SPDX-License-Identifier: Apache-2.0
// G12 fuzz: Kitty response parser (plan.md §14.9).
#include "farsee/kitty_protocol.h"
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    kitty_capability cap = {0};
    (void)kitty_parse_capability_response(data, size, &cap);
    return 0;
}
