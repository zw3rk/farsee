// SPDX-License-Identifier: Apache-2.0
//
// G10 — SHM in-flight table tests (plan.md §G10).

#include "rfb_test.h"
#include "farsee/kitty_shm_table.h"

RFB_TEST(shm_tbl, table__add_and_ack__count_tracks) {
    rfb_shm_table t;
    rfb_shm_table_init(&t);
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 0u);
    RFB_CHECK(rfb_shm_table_add(&t, "/farsee-aaa", 1));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 1u);
    RFB_CHECK(rfb_shm_table_add(&t, "/farsee-bbb", 2));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 2u);
    RFB_CHECK(rfb_shm_table_ack(&t, 1));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 1u);
    RFB_CHECK(rfb_shm_table_ack(&t, 2));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 0u);
}

RFB_TEST(shm_tbl, table__full__returns_false) {
    rfb_shm_table t;
    rfb_shm_table_init(&t);
    for (size_t i = 0; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        char name[32];
        snprintf(name, sizeof name, "/farsee-%zu", i);
        RFB_CHECK(rfb_shm_table_add(&t, name, (uint32_t)(i + 1)));
    }
    RFB_CHECK(rfb_shm_table_full(&t));
    RFB_CHECK(!rfb_shm_table_add(&t, "/farsee-overflow", 99));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), KITTY_SHM_MAX_INFLIGHT);
}

RFB_TEST(shm_tbl, table__ack_unknown_id__returns_false) {
    rfb_shm_table t;
    rfb_shm_table_init(&t);
    rfb_shm_table_add(&t, "/farsee-x", 1);
    RFB_CHECK(!rfb_shm_table_ack(&t, 999));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 1u);
}

RFB_TEST(shm_tbl, table__clear__empties) {
    rfb_shm_table t;
    rfb_shm_table_init(&t);
    rfb_shm_table_add(&t, "/farsee-a", 1);
    rfb_shm_table_add(&t, "/farsee-b", 2);
    rfb_shm_table_clear(&t);
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&t), 0u);
    RFB_CHECK(!rfb_shm_table_full(&t));
}

RFB_TEST(shm_tbl, table__reuse_after_ack) {
    rfb_shm_table t;
    rfb_shm_table_init(&t);
    for (size_t i = 0; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        rfb_shm_table_add(&t, "/x", (uint32_t)(i + 1));
    }
    RFB_CHECK(rfb_shm_table_full(&t));
    // Ack one, then add another.
    rfb_shm_table_ack(&t, 1);
    RFB_CHECK(!rfb_shm_table_full(&t));
    RFB_CHECK(rfb_shm_table_add(&t, "/y", 100));
    RFB_CHECK(rfb_shm_table_full(&t));
}
