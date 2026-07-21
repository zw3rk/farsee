// SPDX-License-Identifier: Apache-2.0
//
// farsee — injectable allocator (plan.md §G1, §14.6).

#include "farsee/allocator.h"

#include <stdlib.h>
#include <string.h>

static void *default_alloc(rfb_allocator *self, size_t n)
{
    (void)self;
    if (n == 0) {
        return NULL;  // match malloc(0) policy: return NULL
    }
    return malloc(n);
}

static void default_free(rfb_allocator *self, void *p)
{
    (void)self;
    free(p);
}

static rfb_allocator g_default = {
    .alloc = default_alloc,
    .free  = default_free,
    .user  = NULL,
};

rfb_allocator *rfb_default_allocator(void)
{
    return &g_default;
}

void *rfb_allocator_realloc(
    rfb_allocator *a,
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
