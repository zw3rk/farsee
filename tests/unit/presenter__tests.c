// SPDX-License-Identifier: Apache-2.0
//
// G3 — null and dump presenter tests (plan.md §G3, §10.5). RED step.

#include "rfb_test.h"
#include "farsee/presenter.h"
#include "farsee/framebuffer.h"
#include "farsee/allocator.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

// --- dump presenter: writes RGBA bytes -----------------------------------

RFB_TEST(presenter, dump__writes_rgba_exact_bytes) {
    // Make a temp path.
    char path[] = "/tmp/farsee_dump_XXXXXX";
    int fd = mkstemp(path);
    RFB_CHECK(fd >= 0);
    close(fd);
    unlink(path);  // dump opens it fresh

    rfb_presenter_dump d;
    rfb_presenter_dump_init(&d, path, false);
    rfb_presenter p = { .ops = &rfb_presenter_dump_ops, .ctx = &d };
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 1, 1u << 20);
    // Paint two known pixels.
    uint8_t *px0 = rfb_framebuffer_pixel(&fb, 0, 0);
    px0[0] = 0xFF; px0[1] = 0x00; px0[2] = 0x80; px0[3] = 0xFF;
    uint8_t *px1 = rfb_framebuffer_pixel(&fb, 1, 0);
    px1[0] = 0x01; px1[1] = 0x02; px1[2] = 0x03; px1[3] = 0x04;

    RFB_CHECK_EQ_INT(rfb_presenter_present(&p, &fb, NULL), 0);
    rfb_framebuffer_destroy(&fb);

    // Read back the file and verify.
    FILE *f = fopen(path, "rb");
    RFB_CHECK(f != NULL);
    uint8_t got[8];
    size_t rd = fread(got, 1, sizeof got, f);
    fclose(f);
    RFB_CHECK_EQ_UINT(rd, 8u);
    static const uint8_t expect[8] = {
        0xFF, 0x00, 0x80, 0xFF,
        0x01, 0x02, 0x03, 0x04,
    };
    RFB_CHECK_MEM_EQ(got, expect, 8);
    unlink(path);
}

// --- dump presenter: PPM option ------------------------------------------

RFB_TEST(presenter, dump__ppm_has_correct_header_and_rgb) {
    char path[] = "/tmp/farsee_ppm_XXXXXX";
    int fd = mkstemp(path);
    RFB_CHECK(fd >= 0);
    close(fd);
    unlink(path);

    rfb_presenter_dump d;
    rfb_presenter_dump_init(&d, path, true);
    rfb_presenter p = { .ops = &rfb_presenter_dump_ops, .ctx = &d };
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 1, 1, 1u << 20);
    uint8_t *px = rfb_framebuffer_pixel(&fb, 0, 0);
    px[0] = 10; px[1] = 20; px[2] = 30; px[3] = 40;

    RFB_CHECK_EQ_INT(rfb_presenter_present(&p, &fb, NULL), 0);
    rfb_framebuffer_destroy(&fb);

    // PPM file = path + ".ppm"
    char ppm_path[1024];
    snprintf(ppm_path, sizeof ppm_path, "%s.ppm", path);
    FILE *f = fopen(ppm_path, "rb");
    RFB_CHECK(f != NULL);
    char header[64] = { 0 };
    size_t rd = fread(header, 1, sizeof header - 1, f);
    fclose(f);
    RFB_CHECK(rd > 0);
    // P6 header: "P6\n1 1\n255\n" then 3 bytes RGB.
    RFB_CHECK(strncmp(header, "P6\n1 1\n255\n", 11) == 0);
    // The 3 RGB bytes follow.
    RFB_CHECK_EQ_UINT((uint8_t)header[11], 10u);
    RFB_CHECK_EQ_UINT((uint8_t)header[12], 20u);
    RFB_CHECK_EQ_UINT((uint8_t)header[13], 30u);
    unlink(path);
    unlink(ppm_path);
}
