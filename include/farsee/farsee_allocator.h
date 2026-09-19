// SPDX-License-Identifier: Apache-2.0
//
// Protocol-neutral injectable allocator.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_ALLOCATOR_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_ALLOCATOR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct farsee_allocator {
    void *(*alloc)(struct farsee_allocator *self, size_t size);
    void (*free)(struct farsee_allocator *self, void *allocation);
    void *user;
} farsee_allocator;

// The default malloc/free allocator. Never NULL.
farsee_allocator *farsee_default_allocator(void);

// Allocate a replacement block, copy min(old_size, new_size) bytes, and free
// the old block only after allocation succeeds. The caller retains the old
// block on failure.
void *farsee_allocator_realloc(farsee_allocator *allocator, void *old,
                               size_t old_size, size_t new_size);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_ALLOCATOR_H
