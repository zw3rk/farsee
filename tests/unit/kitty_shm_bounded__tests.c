// SPDX-License-Identifier: Apache-2.0
//
// G10 — SHM bounded in-flight wiring tests.
// Verifies rfb_shm_transfer uses the table and falls back when full.

#include "rfb_test.h"
#include "farsee/kitty_shm.h"
#include "farsee/kitty_shm_table.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

RFB_TEST(shm_bounded, shm_transfer__table_full__falls_back_to_io_error) {
    rfb_shm_table t;
    rfb_shm_table_init(&t);
    // Fill the table.
    for (size_t i = 0; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        rfb_shm_table_add(&t, "/dummy", (uint32_t)(i + 1));
    }
    RFB_CHECK(rfb_shm_table_full(&t));

    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 20);
    static const uint8_t src[16] = { 0 };
    // With a full table, rfb_shm_transfer should return RFB_ERR_IO so the
    // caller falls back to direct transfer (plan.md §G10).
    rfb_error e = rfb_shm_transfer(&out, src, 2, 2, KITTY_FMT_RGBA32,
                                   100, 100, false, &t, 0, 0);
    RFB_CHECK_EQ_INT(e, RFB_ERR_IO);
    // Table count unchanged.
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), KITTY_SHM_MAX_INFLIGHT);
    rfb_buffer_destroy(&out);
}

RFB_TEST(shm_bounded, shm_transfer__table_not_full__registers_and_succeeds) {
    rfb_shm_table t;
    rfb_shm_table_init(&t);

    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 20);
    static const uint8_t src[16] = {
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        0x00,0x00,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    };
    rfb_error e = rfb_shm_transfer(&out, src, 2, 2, KITTY_FMT_RGBA32,
                                   42, 1, false, &t, 0, 0);
    RFB_CHECK_EQ_INT(e, RFB_OK);
    // The transfer was registered in the table.
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 1u);
    // Ack it.
    RFB_CHECK(rfb_shm_table_ack(&t, 42));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 0u);
    rfb_buffer_destroy(&out);
}
