// SPDX-License-Identifier: Apache-2.0
//
// Queue push contracts: TERMINAL entries bypass capacity caps, while normal
// entries remain bounded. A NULL payload with nonzero length fails closed.

#include "farsee/farsee_queue.h"
#include "tests/test_framework/rfb_test.h"

RFB_TEST(farsee_queue_contract, queue_push__terminal_payload_over_max_bytes__delivered)
{
    farsee_queue_config cfg = {4, 8};  // max_items=4, max_bytes=8
    farsee_queue *q = farsee_queue_create(cfg);
    RFB_CHECK(q != NULL);

    static const uint8_t big[16] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    };
    // TERMINAL must bypass the byte cap.
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_TERMINAL,
                                big, sizeof big, NULL, NULL));

    const void *pl = NULL;
    size_t bl = 0;
    farsee_queue_tag tag = FARSEE_QUEUE_TAG_NORMAL;
    void *user = NULL;
    RFB_CHECK(farsee_queue_pop(q, &pl, &bl, &tag, &user));
    RFB_CHECK_EQ_UINT((unsigned)tag, (unsigned)FARSEE_QUEUE_TAG_TERMINAL);
    RFB_CHECK_EQ_UINT(bl, sizeof big);
    RFB_CHECK_MSG(pl != NULL, "TERMINAL payload buffer missing");
    if (pl != NULL) {
        RFB_CHECK_MEM_EQ(pl, big, sizeof big);
    }

    farsee_queue_destroy(&q);
}

RFB_TEST(farsee_queue_contract, queue_push__normal_payload_over_max_bytes__still_rejected)
{
    // The caps keep holding for non-TERMINAL tags.
    farsee_queue_config cfg = {4, 8};
    farsee_queue *q = farsee_queue_create(cfg);
    RFB_CHECK(q != NULL);

    uint8_t big[9] = {0};
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL,
                                big, sizeof big, NULL, NULL) == false);
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_PRIORITY,
                                big, sizeof big, NULL, NULL) == false);

    farsee_queue_destroy(&q);
}

RFB_TEST(farsee_queue_contract, queue_push__null_payload_with_bytes__rejected)
{
    farsee_queue_config cfg = {4, 64};
    farsee_queue *q = farsee_queue_create(cfg);
    RFB_CHECK(q != NULL);

    // A NULL payload with nonzero length must fail.
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL,
                                NULL, 4, NULL, NULL) == false);
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_PRIORITY,
                                NULL, 4, NULL, NULL) == false);
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_TERMINAL,
                                NULL, 4, NULL, NULL) == false);
    // NULL payload with ZERO bytes remains a valid empty entry.
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL,
                                NULL, 0, NULL, NULL));
    const void *pl = (const void *)0x1;
    size_t bl = 99;
    RFB_CHECK(farsee_queue_pop(q, &pl, &bl, NULL, NULL));
    RFB_CHECK(pl == NULL);
    RFB_CHECK_EQ_UINT(bl, 0u);

    farsee_queue_destroy(&q);
}
