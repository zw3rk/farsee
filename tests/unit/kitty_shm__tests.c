// SPDX-License-Identifier: Apache-2.0
//
// Kitty POSIX SHM presenter tests.

#include "rfb_test.h"
#include "farsee/kitty_shm.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

#include <errno.h>
#include <stdint.h>
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

// Generated names must match /farsee-<16 hex> and remain unique.
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

RFB_TEST(shm, shm_name__exact_bounds)
{
    char name[25];

    RFB_CHECK(!rfb_shm_generate_name(NULL, sizeof name));
    RFB_CHECK(!rfb_shm_generate_name(name, sizeof name - 1u));
    RFB_CHECK(rfb_shm_generate_name(name, sizeof name));
    RFB_CHECK_EQ_UINT(strlen(name), 24u);
    RFB_CHECK_EQ_UINT(name[24], '\0');
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

typedef enum shm_fault_stage {
    SHM_FAULT_NONE = 0,
    SHM_FAULT_UNMAP = 1,
    SHM_FAULT_CLOSE = 2,
    SHM_FAULT_UNLINK = 3,
    SHM_FAULT_UNLINK_ENOENT = 4,
} shm_fault_stage;

typedef struct shm_fault_context {
    shm_fault_stage stage;
} shm_fault_context;

static int shm_fault_unmap(void *context, void *address, size_t length)
{
    const shm_fault_context *fault = (const shm_fault_context *)context;
    const int result = munmap(address, length);
    if (result == 0 && fault->stage == SHM_FAULT_UNMAP) {
        errno = EIO;
        return -1;
    }
    return result;
}

static int shm_fault_close(void *context, int fd)
{
    const shm_fault_context *fault = (const shm_fault_context *)context;
    const int result = close(fd);
    if (result == 0 && fault->stage == SHM_FAULT_CLOSE) {
        errno = EIO;
        return -1;
    }
    return result;
}

static int shm_fault_unlink(void *context, const char *name)
{
    const shm_fault_context *fault = (const shm_fault_context *)context;
    const int result = shm_unlink(name);
    if (result == 0 && fault->stage == SHM_FAULT_UNLINK) {
        errno = EIO;
        return -1;
    }
    if (result == 0 && fault->stage == SHM_FAULT_UNLINK_ENOENT) {
        errno = ENOENT;
        return -1;
    }
    return result;
}

static rfb_error shm_transfer_with_fault(shm_fault_stage stage,
                                         size_t *output_length)
{
    rfb_buffer output;
    rfb_buffer_init(&output, rfb_default_allocator(), 1u << 20);
    static const uint8_t pixels[4] = {1u, 2u, 3u, 255u};
    shm_fault_context context = {.stage = stage};
    const rfb_shm_platform_ops ops = {
        .context = &context,
        .unmap_fn = shm_fault_unmap,
        .close_fn = shm_fault_close,
        .unlink_fn = shm_fault_unlink,
    };
    const rfb_error error = rfb_shm_transfer_with_ops(
        &output, pixels, 1u, 1u, KITTY_FMT_RGBA32, 91u, 91u, false,
        NULL, 0u, 0u, &ops);
    *output_length = rfb_buffer_length(&output);
    rfb_buffer_destroy(&output);
    return error;
}

static bool shm_output_contains(const rfb_buffer *output, const char *text)
{
    const size_t text_length = strlen(text);
    const size_t output_length = rfb_buffer_length(output);
    const uint8_t *data = rfb_buffer_data(output);
    if (text_length > output_length) {
        return false;
    }
    for (size_t i = 0u; i <= output_length - text_length; i++) {
        if (memcmp(data + i, text, text_length) == 0) {
            return true;
        }
    }
    return false;
}

RFB_TEST(shm, shm_transfer__unmap_failure_is_reported)
{
    size_t output_length = 99u;
    RFB_CHECK_EQ_INT(
        shm_transfer_with_fault(SHM_FAULT_UNMAP, &output_length), RFB_ERR_IO);
    RFB_CHECK_EQ_UINT(output_length, 0u);
}

RFB_TEST(shm, shm_transfer__close_failure_is_reported)
{
    size_t output_length = 99u;
    RFB_CHECK_EQ_INT(
        shm_transfer_with_fault(SHM_FAULT_CLOSE, &output_length), RFB_ERR_IO);
    RFB_CHECK_EQ_UINT(output_length, 0u);
}

RFB_TEST(shm, shm_transfer__unlink_failure_is_reported)
{
    size_t output_length = 99u;
    RFB_CHECK_EQ_INT(
        shm_transfer_with_fault(SHM_FAULT_UNLINK, &output_length), RFB_ERR_IO);
    RFB_CHECK_EQ_UINT(output_length, 0u);
}

RFB_TEST(shm, shm_transfer__already_unlinked_is_benign)
{
    size_t output_length = 0u;
    RFB_CHECK_EQ_INT(
        shm_transfer_with_fault(SHM_FAULT_UNLINK_ENOENT, &output_length),
        RFB_OK);
    RFB_CHECK(output_length > 0u);
}

RFB_TEST(shm, shm_transfer__rejects_invalid_inputs_and_full_table)
{
    static const uint8_t pixels[4] = {1u, 2u, 3u, 255u};
    shm_fault_context context = {.stage = SHM_FAULT_UNLINK_ENOENT};
    const rfb_shm_platform_ops ops = {
        .context = &context,
        .unmap_fn = shm_fault_unmap,
        .close_fn = shm_fault_close,
        .unlink_fn = shm_fault_unlink,
    };
    rfb_buffer output;
    rfb_buffer_init(&output, rfb_default_allocator(), 1u << 20);

    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(NULL, pixels, 1u, 1u, KITTY_FMT_RGBA32,
                                  1u, 1u, false, NULL, 0u, 0u, &ops),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(&output, NULL, 1u, 1u, KITTY_FMT_RGBA32,
                                  1u, 1u, false, NULL, 0u, 0u, &ops),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(&output, pixels, 0u, 1u, KITTY_FMT_RGBA32,
                                  1u, 1u, false, NULL, 0u, 0u, &ops),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(&output, pixels, 1u, 0u, KITTY_FMT_RGBA32,
                                  1u, 1u, false, NULL, 0u, 0u, &ops),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(&output, pixels, 1u, 1u, KITTY_FMT_RGBA32,
                                  1u, 1u, false, NULL, 0u, 0u, NULL),
        RFB_ERR_INTERNAL);

    rfb_shm_platform_ops incomplete = ops;
    incomplete.unmap_fn = NULL;
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(&output, pixels, 1u, 1u, KITTY_FMT_RGBA32,
                                  1u, 1u, false, NULL, 0u, 0u, &incomplete),
        RFB_ERR_INTERNAL);
    incomplete = ops;
    incomplete.close_fn = NULL;
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(&output, pixels, 1u, 1u, KITTY_FMT_RGBA32,
                                  1u, 1u, false, NULL, 0u, 0u, &incomplete),
        RFB_ERR_INTERNAL);
    incomplete = ops;
    incomplete.unlink_fn = NULL;
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(&output, pixels, 1u, 1u, KITTY_FMT_RGBA32,
                                  1u, 1u, false, NULL, 0u, 0u, &incomplete),
        RFB_ERR_INTERNAL);

    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(&output, pixels, UINT32_MAX, UINT32_MAX,
                                  KITTY_FMT_RGBA32, 1u, 1u, false, NULL,
                                  0u, 0u, &ops),
        RFB_ERR_INTERNAL);

    rfb_shm_table table;
    rfb_shm_table_init(&table);
    for (uint32_t i = 0u; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        RFB_CHECK(rfb_shm_table_add(&table, "/occupied", i));
    }
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(&output, pixels, 1u, 1u, KITTY_FMT_RGBA32,
                                  1u, 1u, false, &table, 0u, 0u, &ops),
        RFB_ERR_IO);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&output), 0u);
    rfb_buffer_destroy(&output);
}

RFB_TEST(shm, shm_transfer__encodes_rgb24_ack_and_placement_variants)
{
    static const uint8_t pixels[4] = {1u, 2u, 3u, 255u};
    shm_fault_context context = {.stage = SHM_FAULT_UNLINK_ENOENT};
    const rfb_shm_platform_ops ops = {
        .context = &context,
        .unmap_fn = shm_fault_unmap,
        .close_fn = shm_fault_close,
        .unlink_fn = shm_fault_unlink,
    };
    rfb_buffer output;
    rfb_buffer_init(&output, rfb_default_allocator(), 1u << 20);

    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(&output, pixels, 1u, 1u, KITTY_FMT_RGB24,
                                  91u, 92u, true, NULL, 80u, 24u, &ops),
        RFB_OK);
    RFB_CHECK(shm_output_contains(
        &output,
        "a=T,f=24,s=1,v=1,t=s,i=91,p=92,C=1,q=0,c=80,r=24,m=0;"));

    rfb_buffer_clear(&output);
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(&output, pixels, 1u, 1u, KITTY_FMT_RGBA32,
                                  91u, 92u, false, NULL, 0u, 24u, &ops),
        RFB_OK);
    RFB_CHECK(shm_output_contains(&output, "q=2,r=24,m=0;"));

    rfb_buffer_clear(&output);
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(&output, pixels, 1u, 1u, KITTY_FMT_RGBA32,
                                  91u, 92u, false, NULL, 80u, 0u, &ops),
        RFB_OK);
    RFB_CHECK(shm_output_contains(&output, "q=2,c=80,m=0;"));
    rfb_buffer_destroy(&output);
}

RFB_TEST(shm, shm_transfer__each_output_limit_rolls_back_to_mark)
{
    static const uint8_t pixels[4] = {1u, 2u, 3u, 255u};
    static const uint8_t prefix = 0xA5u;
    shm_fault_context context = {.stage = SHM_FAULT_UNLINK_ENOENT};
    const rfb_shm_platform_ops ops = {
        .context = &context,
        .unmap_fn = shm_fault_unmap,
        .close_fn = shm_fault_close,
        .unlink_fn = shm_fault_unlink,
    };
    rfb_buffer reference;
    rfb_buffer_init(&reference, rfb_default_allocator(), 1u << 20);
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(&reference, pixels, 1u, 1u,
                                  KITTY_FMT_RGBA32, 91u, 92u, false, NULL,
                                  80u, 24u, &ops),
        RFB_OK);
    const size_t wire_length = rfb_buffer_length(&reference);
    RFB_CHECK(wire_length > 0u);

    for (size_t suffix_limit = 0u; suffix_limit < wire_length;
         suffix_limit++) {
        rfb_buffer output;
        rfb_buffer_init(&output, rfb_default_allocator(), suffix_limit + 1u);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&output, &prefix, 1u), RFB_OK);
        RFB_CHECK_EQ_INT(
            rfb_shm_transfer_with_ops(&output, pixels, 1u, 1u,
                                      KITTY_FMT_RGBA32, 91u, 92u, false,
                                      NULL, 80u, 24u, &ops),
            RFB_ERR_LIMIT);
        RFB_CHECK_EQ_UINT(rfb_buffer_length(&output), 1u);
        RFB_CHECK_EQ_UINT(rfb_buffer_data(&output)[0], prefix);
        rfb_buffer_destroy(&output);
    }
    rfb_buffer_destroy(&reference);
}

RFB_TEST(shm, shm_transfer__table_add_failure_rolls_back)
{
    static const uint8_t pixels[4] = {1u, 2u, 3u, 255u};
    static const uint8_t prefix = 0x5Au;
    shm_fault_context context = {.stage = SHM_FAULT_UNLINK_ENOENT};
    const rfb_shm_platform_ops ops = {
        .context = &context,
        .unmap_fn = shm_fault_unmap,
        .close_fn = shm_fault_close,
        .unlink_fn = shm_fault_unlink,
    };
    rfb_shm_table table;
    rfb_shm_table_init(&table);
    for (size_t i = 0u; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        table.entries[i].in_use = true;
    }

    rfb_buffer output;
    rfb_buffer_init(&output, rfb_default_allocator(), 1u << 20);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&output, &prefix, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer_with_ops(&output, pixels, 1u, 1u, KITTY_FMT_RGBA32,
                                  91u, 92u, false, &table, 0u, 0u, &ops),
        RFB_ERR_IO);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&output), 1u);
    RFB_CHECK_EQ_UINT(rfb_buffer_data(&output)[0], prefix);
    rfb_buffer_destroy(&output);
}
