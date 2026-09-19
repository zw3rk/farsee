// SPDX-License-Identifier: Apache-2.0
//
// SHM-table capacity/ack/clear, framebuffer byte-limit, failed-resize state,
// and allocation-failure cleanup tests.

#include "rfb_test.h"
#include "farsee/kitty_shm_table.h"
#include "farsee/framebuffer.h"
#include "farsee/apple_type33.h"
#include "farsee/apple_crypto.h"
#include "farsee/allocator.h"
#include "farsee/limits.h"
#include "farsee/secret.h"

#include <string.h>
#include <stdlib.h>

// --- SHM table is bounded -----------------------------------------------

RFB_TEST(security_cleanup, shm_table__bounded_at_max_inflight) {
    rfb_shm_table t;
    rfb_shm_table_init(&t);
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 0u);
    RFB_CHECK(!rfb_shm_table_full(&t));

    // Fill to the cap.
    for (size_t i = 0; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        RFB_CHECK(rfb_shm_table_add(&t, "/shm-dummy", (uint32_t)(i + 1)));
    }
    RFB_CHECK(rfb_shm_table_full(&t));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), KITTY_SHM_MAX_INFLIGHT);

    // The next add fails and the count remains at the cap.
    RFB_CHECK(!rfb_shm_table_add(&t, "/shm-overflow", 9999));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), KITTY_SHM_MAX_INFLIGHT);
}

RFB_TEST(security_cleanup, shm_table__ack_removes_and_frees_slot) {
    rfb_shm_table t;
    rfb_shm_table_init(&t);
    RFB_CHECK(rfb_shm_table_add(&t, "/shm-a", 10));
    RFB_CHECK(rfb_shm_table_add(&t, "/shm-b", 20));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 2u);

    RFB_CHECK(rfb_shm_table_ack(&t, 10));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 1u);
    // Ack of unknown id is harmless.
    RFB_CHECK(!rfb_shm_table_ack(&t, 999));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 1u);

    // Now the freed slot can be reused.
    RFB_CHECK(rfb_shm_table_add(&t, "/shm-c", 30));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 2u);
}

RFB_TEST(security_cleanup, shm_table__clear_empties_all_slots) {
    rfb_shm_table t;
    rfb_shm_table_init(&t);
    for (size_t i = 0; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        rfb_shm_table_add(&t, "/shm", (uint32_t)(i + 1));
    }
    rfb_shm_table_clear(&t);
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 0u);
    RFB_CHECK(!rfb_shm_table_full(&t));
    // After clear the table is usable again.
    RFB_CHECK(rfb_shm_table_add(&t, "/shm-new", 1));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 1u);
}

// --- Framebuffer enforces byte cap --------------------------------------

RFB_TEST(security_cleanup, framebuffer__rejects_oversized_dimensions) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    // 16384 × 16384 × 4 bytes = 1 GiB (RFB_LIMIT_FB_BYTES_ABSOLUTE).
    // This request exceeds the supplied 256 MiB policy cap.
    rfb_error e = rfb_framebuffer_resize(&fb, RFB_LIMIT_FB_WIDTH_MAX,
                                         RFB_LIMIT_FB_HEIGHT_MAX,
                                         RFB_LIMIT_FB_BYTES_POLICY);
    RFB_CHECK(e != RFB_OK);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(security_cleanup, framebuffer__resize_failure_preserves_old_state) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    // Establish a valid small framebuffer.
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 4, 4, 1u << 20), RFB_OK);
    RFB_CHECK_EQ_UINT(fb.width, 4u);
    RFB_CHECK_EQ_UINT(fb.height, 4u);

    // Attempt an oversized resize and inspect the existing 4×4 state.
    rfb_error e = rfb_framebuffer_resize(&fb, RFB_LIMIT_FB_WIDTH_MAX,
                                         RFB_LIMIT_FB_HEIGHT_MAX,
                                         RFB_LIMIT_FB_BYTES_POLICY);
    RFB_CHECK(e != RFB_OK);
    // Old state preserved (transactional).
    RFB_CHECK_EQ_UINT(fb.width, 4u);
    RFB_CHECK_EQ_UINT(fb.height, 4u);
    rfb_framebuffer_destroy(&fb);
}

// --- Fault-injecting allocator ------------------------------------------
typedef struct g25_fault_state {
    int calls;
    int fail_at;
} g25_fault_state;

static void *g25_fault_alloc_fn(rfb_allocator *self, size_t n)
{
    g25_fault_state *f = (g25_fault_state *)self->user;
    f->calls++;
    if (f->calls == f->fail_at) {
        return NULL;
    }
    if (n == 0) {
        return NULL;
    }
    return malloc(n);
}

static void g25_fault_free_fn(rfb_allocator *self, void *p)
{
    (void)self;
    free(p);
}

RFB_TEST(security_cleanup, framebuffer__allocation_failure_destructible) {
    // Fail the resize allocation, then destroy the framebuffer.
    // We use a fault-injecting allocator that fails the first alloc.
    g25_fault_state fs = { .calls = 0, .fail_at = 1 };
    rfb_allocator a = { .alloc = g25_fault_alloc_fn,
                        .free = g25_fault_free_fn, .user = &fs };

    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, &a);
    // Resize will hit the failing allocator.
    rfb_error e = rfb_framebuffer_resize(&fb, 16, 16, 1u << 20);
    RFB_CHECK(e != RFB_OK);  // allocation failure surfaced
    // Destroy the framebuffer after the failed resize.
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(security_cleanup, framebuffer__failure_index_sweep_is_destructible) {
    // Sweep four failure indices and destroy the framebuffer after each
    // resize result. Only an index reached by the allocator injects failure.
    static const uint32_t dim = 8;
    for (int fail = 1; fail <= 4; fail++) {
        g25_fault_state fs = { .calls = 0, .fail_at = fail };
        rfb_allocator a = { .alloc = g25_fault_alloc_fn,
                            .free = g25_fault_free_fn, .user = &fs };
        rfb_framebuffer fb;
        rfb_framebuffer_init(&fb, &a);
        (void)rfb_framebuffer_resize(&fb, dim, dim, 1u << 20);
        rfb_framebuffer_destroy(&fb);
    }
}
