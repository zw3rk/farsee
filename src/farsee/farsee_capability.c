// SPDX-License-Identifier: Apache-2.0
//
// Farsee common capability set implementation (F1 gate, §6.5).

#include "farsee/farsee_capability.h"

#include <stddef.h>

void farsee_capability_set_init(farsee_capability_set *caps)
{
    if (caps == NULL) {
        return;
    }
    // Zero all bits: every capability absent by default (§6.5).
    for (size_t i = 0; i < sizeof(caps->bits); ++i) {
        caps->bits[i] = 0;
    }
}

bool farsee_capability_get(const farsee_capability_set *caps,
                           farsee_capability_id id)
{
    if (caps == NULL || id < 0 || id >= FARSEE_CAP_COUNT) {
        return false;
    }
    size_t byte = (size_t)id / 8u;
    size_t bit = (size_t)id % 8u;
    return (caps->bits[byte] & (unsigned char)(1u << bit)) != 0u;
}

void farsee_capability_set_set(farsee_capability_set *caps,
                               farsee_capability_id id, bool present)
{
    if (caps == NULL || id < 0 || id >= FARSEE_CAP_COUNT) {
        return;
    }
    size_t byte = (size_t)id / 8u;
    size_t bit = (size_t)id % 8u;
    if (present) {
        caps->bits[byte] = (unsigned char)(caps->bits[byte] | (unsigned char)(1u << bit));
    } else {
        caps->bits[byte] = (unsigned char)(caps->bits[byte] & (unsigned char)~(1u << bit));
    }
}
