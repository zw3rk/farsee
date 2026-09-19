// SPDX-License-Identifier: Apache-2.0
//
// Null-presenter and wrapper tests.

#include "rfb_test.h"
#include "farsee/presenter.h"
#include "farsee/framebuffer.h"
#include "farsee/allocator.h"

// --- null presenter ------------------------------------------------------

RFB_TEST(presenter, null__present_increments_count) {
    rfb_presenter_null n;
    rfb_presenter_null_init(&n);
    rfb_presenter p = { .ops = &rfb_presenter_null_ops, .ctx = &n };
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    RFB_CHECK_EQ_INT(rfb_presenter_present(&p, &fb, NULL), 0);
    RFB_CHECK_EQ_INT(n.present_count, 1);
    RFB_CHECK_EQ_INT(rfb_presenter_present(&p, &fb, NULL), 0);
    RFB_CHECK_EQ_INT(n.present_count, 2);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(presenter, null__open_resize_close_are_noops) {
    rfb_presenter_null n;
    rfb_presenter_null_init(&n);
    rfb_presenter p = { .ops = &rfb_presenter_null_ops, .ctx = &n };
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_presenter_open(&p, &fb), 0);
    RFB_CHECK_EQ_INT(rfb_presenter_resize(&p, &fb), 0);
    rfb_presenter_close(&p);
    rfb_framebuffer_destroy(&fb);
}

// --- wrapper tolerates NULL ops ------------------------------------------

RFB_TEST(presenter, wrappers__null_presenter_pointer__safe) {
    RFB_CHECK_EQ_INT(rfb_presenter_open(NULL, NULL), 0);
    RFB_CHECK_EQ_INT(rfb_presenter_resize(NULL, NULL), 0);
    RFB_CHECK_EQ_INT(rfb_presenter_present(NULL, NULL, NULL), 0);
    rfb_presenter_close(NULL);
}
