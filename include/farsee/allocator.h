// SPDX-License-Identifier: Apache-2.0
//
// Compatibility names for the original RFB allocator API.

#ifndef FARSEE_INCLUDE_FARSEE_ALLOCATOR_H
#define FARSEE_INCLUDE_FARSEE_ALLOCATOR_H

#include "farsee/farsee_allocator.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef farsee_allocator rfb_allocator;

// The default allocator (malloc/free). Never NULL.
rfb_allocator *rfb_default_allocator(void);

// A realloc-like helper: allocate a new block of new_n, copy min(old_n,
// new_n) bytes from old, free old. Returns NULL on failure (old is NOT
// freed on failure — caller still owns it). Callers can update their pointer
// only after success to make growth transactional.
void *rfb_allocator_realloc(
    rfb_allocator *a,
    void *old, size_t old_n,
    size_t new_n);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_ALLOCATOR_H
