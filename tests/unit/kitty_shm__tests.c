// SPDX-License-Identifier: Apache-2.0
//
// G10 — Kitty POSIX SHM presenter tests (plan.md §G10). RED step.

#include "rfb_test.h"
#include "farsee/kitty_shm.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>

// --- name generation ----------------------------------------------------

RFB_TEST(shm, shm_name__starts_with_slash) {
    char name[64];
    RFB_CHECK(rfb_shm_generate_name(name, sizeof name));
    RFB_CHECK_EQ_UINT(name[0], '/');
    RFB_CHECK(strlen(name) > 1);
}

RFB_TEST(shm, shm_name__two_calls_differ) {
    char a[64], b[64];
    RFB_CHECK(rfb_shm_generate_name(a, sizeof a));
    RFB_CHECK(rfb_shm_generate_name(b, sizeof b));
    RFB_CHECK(strcmp(a, b) != 0);
}

// T15: name pattern /farsee-<16 hex> and multi-call uniqueness.
RFB_TEST(shm, shm_name__pattern_and_uniqueness)
{
    char names[8][32];
    for (int i = 0; i < 8; i++) {
        RFB_CHECK(rfb_shm_generate_name(names[i], sizeof names[i]));
        RFB_CHECK(names[i][0] == '/');
        RFB_CHECK(strncmp(names[i] + 1, "farsee-", 7) == 0);
        RFB_CHECK_EQ_UINT(strlen(names[i]), 24u);
        for (size_t j = 8; j < 24; j++) {
            char c = names[i][j];
            RFB_CHECK((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
        }
        for (int k = 0; k < i; k++) {
            RFB_CHECK(strcmp(names[i], names[k]) != 0);
        }
    }
}

RFB_TEST(shm, shm_name__too_small_cap__returns_false) {
    char name[4];  // need at least '/' + some chars + null
    RFB_CHECK(!rfb_shm_generate_name(name, sizeof name));
}

RFB_TEST(shm, shm_name__no_path_traversal) {
    char name[64];
    rfb_shm_generate_name(name, sizeof name);
    // Must not contain '..' or '/' after the leading '/'.
    for (size_t i = 1; i < strlen(name); i++) {
        RFB_CHECK(name[i] != '/');
    }
    RFB_CHECK(strstr(name, "..") == NULL);
}

// --- transfer: 2x2 RGBA via SHM -----------------------------------------

RFB_TEST(shm, shm_transfer__2x2_rgba__creates_and_fills_object) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 20);
    static const uint8_t src[16] = {
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        0x00,0x00,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    };
    rfb_error e = rfb_shm_transfer(&out, src, 2, 2, KITTY_FMT_RGBA32, 1, 1, false, NULL, 0, 0);
    RFB_CHECK_EQ_INT(e, RFB_OK);
    // The output should be a valid APC Kitty command with t=s.
    RFB_CHECK(rfb_buffer_length(&out) > 0);
    const uint8_t *d = rfb_buffer_data(&out);
    RFB_CHECK_EQ_UINT(d[0], 0x1Bu);
    RFB_CHECK_EQ_UINT(d[1], '_');
    RFB_CHECK_EQ_UINT(d[2], 'G');
    // Look for t=s in the command.
    bool found_ts = false;
    size_t len = rfb_buffer_length(&out);
    for (size_t i = 3; i + 2 < len; i++) {
        if (d[i] == 't' && d[i+1] == '=' && d[i+2] == 's') {
            found_ts = true;
            break;
        }
    }
    RFB_CHECK(found_ts);
    rfb_buffer_destroy(&out);
}

// --- transfer: output contains no raw pixel bytes (only base64 name) ----

RFB_TEST(shm, shm_transfer__no_raw_pixel_bytes_in_output) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 20);
    static const uint8_t src[16] = {
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        0x00,0x00,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    };
    rfb_shm_transfer(&out, src, 2, 2, KITTY_FMT_RGBA32, 1, 1, false, NULL, 0, 0);
    // The output is the Kitty command; the pixel bytes are in the shm
    // object, NOT in the output buffer. Verify the output is much smaller
    // than the raw pixel data would be via base64 (16 bytes → ~24 base64).
    // The shm command's payload is just the name (~20 base64 bytes), so
    // total output should be well under 100 bytes.
    RFB_CHECK(rfb_buffer_length(&out) < 200u);
    rfb_buffer_destroy(&out);
}

// --- transfer: cleanup leaves no leaked object ---------------------------
// (We can't easily enumerate /dev/shm on macOS, but we verify the transfer
// succeeds and the function doesn't crash on re-invocation.)

RFB_TEST(shm, shm_transfer__two_transfers_succeed_no_crash) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 20);
    static const uint8_t src[16] = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer(&out, src, 2, 2, KITTY_FMT_RGBA32, 1, 1, false, NULL, 0, 0),
        RFB_OK);
    rfb_buffer_clear(&out);
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer(&out, src, 2, 2, KITTY_FMT_RGBA32, 2, 2, false, NULL, 0, 0),
        RFB_OK);
    rfb_buffer_destroy(&out);
}
