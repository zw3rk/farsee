// SPDX-License-Identifier: Apache-2.0
//
// farsee — injectable allocator (plan.md §G1, §14.6).
//
// Core modules that allocate take a `rfb_allocator *` so tests can inject
// deterministic allocation failure (plan.md §14.6: "rerun while failing
// allocation 1 through N"). The production allocator wraps malloc/free;
// the test allocator counts calls and fails at a configurable index.

#ifndef FARSEE_INCLUDE_FARSEE_ALLOCATOR_H
#define FARSEE_INCLUDE_FARSEE_ALLOCATOR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rfb_allocator {
    void *(*alloc)(struct rfb_allocator *self, size_t n);
    void  (*free)(struct rfb_allocator *self, void *p);
    // `user` is opaque state for the implementation (e.g. the test
    // fault-injector's counter). Production ignores it.
    void *user;
} rfb_allocator;

// The default allocator (malloc/free). Never NULL.
rfb_allocator *rfb_default_allocator(void);

// A realloc-like helper: allocate a new block of new_n, copy min(old_n,
// new_n) bytes from old, free old. Returns NULL on failure (old is NOT
// freed on failure — caller still owns it). This is the transactional
// growth primitive used by buffer.c.
void *rfb_allocator_realloc(
    rfb_allocator *a,
    void *old, size_t old_n,
    size_t new_n);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_ALLOCATOR_H
