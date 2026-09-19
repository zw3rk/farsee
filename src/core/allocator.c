// SPDX-License-Identifier: Apache-2.0
//
// farsee — injectable allocator.

#include "farsee/allocator.h"

#include <stdlib.h>
#include <string.h>

static void *default_alloc(farsee_allocator *self, size_t n)
{
    (void)self;
    if (n == 0) {
        return NULL;  // This allocator rejects zero-byte requests.
    }
    return malloc(n);
}

static void default_free(farsee_allocator *self, void *p)
{
    (void)self;
    free(p);
}

static farsee_allocator g_default = {
    .alloc = default_alloc,
    .free  = default_free,
    .user  = NULL,
};

farsee_allocator *farsee_default_allocator(void)
{
    return &g_default;
}

void *farsee_allocator_realloc(
    farsee_allocator *a,
    void *old, size_t old_n,
    size_t new_n)
{
    if (a == NULL || a->alloc == NULL || a->free == NULL) {
        return NULL;
    }
    void *p = a->alloc(a, new_n);
    if (p == NULL) {
        return NULL;  // caller still owns `old`
    }
    if (old != NULL && old_n > 0 && new_n > 0) {
        size_t copy_n = old_n < new_n ? old_n : new_n;
        memcpy(p, old, copy_n);
    }
    if (old != NULL) {
        a->free(a, old);
    }
    return p;
}

rfb_allocator *rfb_default_allocator(void)
{
    return farsee_default_allocator();
}

void *rfb_allocator_realloc(rfb_allocator *a, void *old, size_t old_n,
                            size_t new_n)
{
    return farsee_allocator_realloc(a, old, old_n, new_n);
}
