// SPDX-License-Identifier: Apache-2.0
//
// Dormant client fresh rekey must prepare bytes and record state as one
// transaction. It is private and cannot be selected by public configuration.

#include "rfb_test.h"

#include "farsee/allocator.h"
#include "farsee/apple_record.h"
#include "farsee/apple_wire_record.h"
#include "farsee/buffer.h"
#include "farsee/limits.h"
#include "farsee/rfb_session.h"
#include "rfb/rfb_session_internal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const uint8_t rekey_wrap[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
};
static const uint8_t rekey_old_key[16] = {
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
    0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
};
static const uint8_t rekey_old_iv[16] = {
    0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,
    0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf,
};
static const uint8_t rekey_decrypt_key[16] = {
    0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,
    0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf,
};
static const uint8_t rekey_decrypt_iv[16] = {
    0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,
    0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,
};
static const uint8_t rekey_fresh_key[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
};
static const uint8_t rekey_fresh_iv[16] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
};

typedef struct rekey_rng {
    size_t calls;
    size_t fail_call;
} rekey_rng;

static bool rekey_fixed_random(void *opaque, uint8_t *out, size_t length)
{
    rekey_rng *rng = (rekey_rng *)opaque;
    rng->calls++;
    if (length != 16u) {
        return false;
    }
    memcpy(out, rng->calls == 1u ? rekey_fresh_key : rekey_fresh_iv,
           length);
    return rng->calls != rng->fail_call;
}

static void rekey_session_init(rfb_session *session, size_t output_limit)
{
    rfb_session_clear(session);
    session->alloc = rfb_default_allocator();
    rfb_buffer_init(&session->out, session->alloc, output_limit);
    apple_record_init(&session->apple_rl, rekey_wrap);
    RFB_CHECK(apple_record_set_direction(&session->apple_rl,
                                         APPLE_DIR_ENCRYPT,
                                         rekey_old_key, rekey_old_iv));
    RFB_CHECK(apple_record_set_direction(&session->apple_rl,
                                         APPLE_DIR_DECRYPT,
                                         rekey_decrypt_key,
                                         rekey_decrypt_iv));
    session->apple_rl.encrypt.sequence = 7u;
    session->apple_rl.decrypt.sequence = 9u;
    session->apple_rl_inited = true;
    session->apple_records_active = true;
}

static void rekey_assert_old_state(
    const rfb_session *session, const rfb_crypto_cbc_ctx *old_encrypt_cbc,
    const rfb_crypto_cbc_ctx *old_decrypt_cbc)
{
    RFB_CHECK(session->apple_rl.encrypt.cbc == old_encrypt_cbc);
    RFB_CHECK_MEM_EQ(session->apple_rl.encrypt.content_key,
                     rekey_old_key, sizeof rekey_old_key);
    RFB_CHECK_MEM_EQ(session->apple_rl.encrypt.iv,
                     rekey_old_iv, sizeof rekey_old_iv);
    RFB_CHECK_EQ_UINT(session->apple_rl.encrypt.sequence, 7u);
    RFB_CHECK(session->apple_rl.encrypt.active);
    RFB_CHECK(session->apple_rl.decrypt.cbc == old_decrypt_cbc);
    RFB_CHECK_MEM_EQ(session->apple_rl.decrypt.content_key,
                     rekey_decrypt_key, sizeof rekey_decrypt_key);
    RFB_CHECK_MEM_EQ(session->apple_rl.decrypt.iv,
                     rekey_decrypt_iv, sizeof rekey_decrypt_iv);
    RFB_CHECK_EQ_UINT(session->apple_rl.decrypt.sequence, 9u);
    RFB_CHECK(session->apple_rl.decrypt.active);
    RFB_CHECK_MEM_EQ(session->apple_rl.wrap_key,
                     rekey_wrap, sizeof rekey_wrap);
}

RFB_TEST(rfb_session_fresh_rekey,
         fixed_material__queues_exact_wire_and_commits_direction)
{
    static const uint8_t expected[68] = {
        0x00,0x20,
        0x50,0xfe,0x67,0xcc,0x99,0x6d,0x32,0xb6,
        0xda,0x09,0x37,0xe9,0x9b,0xaf,0xec,0x60,
        0xc8,0x4a,0xf0,0xb6,0x13,0x43,0x5d,0x5d,
        0x91,0x82,0x80,0x1a,0x9b,0xd9,0x32,0x0b,
        0x00,0x20,
        0x64,0xee,0x27,0x6a,0xac,0xbd,0x92,0xb9,
        0x5b,0x00,0x01,0x68,0x74,0x21,0x73,0xb3,
        0xcc,0xec,0x3a,0xf5,0x8d,0xf7,0xa7,0xbd,
        0xc3,0x99,0x36,0xd6,0x6b,0x67,0x30,0xc0,
    };
    rfb_session session_storage;
    rfb_session *session = &session_storage;
    rekey_rng rng = { .calls = 0u, .fail_call = 0u };
    rekey_session_init(session, RFB_LIMIT_OUTBOUND_BYTES);
    const rfb_crypto_cbc_ctx *old_decrypt_cbc =
        session->apple_rl.decrypt.cbc;
    const uint8_t prefix = 0x5au;
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session->out, &prefix, sizeof prefix),
                     RFB_OK);

    RFB_CHECK_EQ_INT(
        rfb_session_internal_queue_fresh_rekey(
            session, rekey_fixed_random, &rng),
        RFB_OK);
    RFB_CHECK_EQ_UINT(rng.calls, 2u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out),
                      sizeof prefix + sizeof expected);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&session->out), &prefix, sizeof prefix);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&session->out) + sizeof prefix, expected,
                     sizeof expected);
    RFB_CHECK_MEM_EQ(session->apple_rl.encrypt.content_key,
                     rekey_fresh_key, sizeof rekey_fresh_key);
    RFB_CHECK_MEM_EQ(session->apple_rl.encrypt.iv,
                     rekey_fresh_iv, sizeof rekey_fresh_iv);
    RFB_CHECK_EQ_UINT(session->apple_rl.encrypt.sequence, 1u);
    RFB_CHECK(session->apple_rl.encrypt.active);
    RFB_CHECK(session->apple_rl.decrypt.cbc == old_decrypt_cbc);
    RFB_CHECK_MEM_EQ(session->apple_rl.decrypt.content_key,
                     rekey_decrypt_key, sizeof rekey_decrypt_key);
    RFB_CHECK_MEM_EQ(session->apple_rl.decrypt.iv,
                     rekey_decrypt_iv, sizeof rekey_decrypt_iv);
    RFB_CHECK_EQ_UINT(session->apple_rl.decrypt.sequence, 9u);
    RFB_CHECK_MEM_EQ(session->apple_rl.wrap_key,
                     rekey_wrap, sizeof rekey_wrap);
    rfb_session_destroy(session);
}

RFB_TEST(rfb_session_fresh_rekey,
         random_failure__leaves_output_and_direction_unchanged)
{
    for (size_t fail_call = 1u; fail_call <= 2u; fail_call++) {
        rfb_session session_storage;
        rfb_session *session = &session_storage;
        rekey_rng rng = { .calls = 0u, .fail_call = fail_call };
        rekey_session_init(session, RFB_LIMIT_OUTBOUND_BYTES);
        const rfb_crypto_cbc_ctx *old_encrypt_cbc =
            session->apple_rl.encrypt.cbc;
        const rfb_crypto_cbc_ctx *old_decrypt_cbc =
            session->apple_rl.decrypt.cbc;

        RFB_CHECK_EQ_INT(
            rfb_session_internal_queue_fresh_rekey(
                session, rekey_fixed_random, &rng),
            RFB_ERR_INTERNAL);
        RFB_CHECK_EQ_UINT(rng.calls, fail_call);
        RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), 0u);
        rekey_assert_old_state(session, old_encrypt_cbc, old_decrypt_cbc);
        rfb_session_destroy(session);
    }
}

static void *rekey_reject_alloc(rfb_allocator *allocator, size_t size)
{
    (void)allocator;
    (void)size;
    return NULL;
}

static void rekey_noop_free(rfb_allocator *allocator, void *allocation)
{
    (void)allocator;
    (void)allocation;
}

RFB_TEST(rfb_session_fresh_rekey,
         seal_allocation_failure__leaves_output_and_direction_unchanged)
{
    rfb_session session_storage;
    rfb_session *session = &session_storage;
    rekey_rng rng = { .calls = 0u, .fail_call = 0u };
    rekey_session_init(session, 68u);
    const rfb_crypto_cbc_ctx *old_encrypt_cbc =
        session->apple_rl.encrypt.cbc;
    const rfb_crypto_cbc_ctx *old_decrypt_cbc =
        session->apple_rl.decrypt.cbc;
    rfb_allocator rejecting = {
        .alloc = rekey_reject_alloc,
        .free = rekey_noop_free,
        .user = NULL,
    };
    session->alloc = &rejecting;

    RFB_CHECK_EQ_INT(
        rfb_session_internal_queue_fresh_rekey(
            session, rekey_fixed_random, &rng),
        RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), 0u);
    rekey_assert_old_state(session, old_encrypt_cbc, old_decrypt_cbc);
    session->alloc = rfb_default_allocator();
    rfb_session_destroy(session);
}

RFB_TEST(rfb_session_fresh_rekey,
         output_reserve_failure__does_not_generate_or_change_state)
{
    rfb_session session_storage;
    rfb_session *session = &session_storage;
    rekey_rng rng = { .calls = 0u, .fail_call = 0u };
    rekey_session_init(session, 68u);
    const rfb_crypto_cbc_ctx *old_encrypt_cbc =
        session->apple_rl.encrypt.cbc;
    const rfb_crypto_cbc_ctx *old_decrypt_cbc =
        session->apple_rl.decrypt.cbc;
    rfb_allocator rejecting = {
        .alloc = rekey_reject_alloc,
        .free = rekey_noop_free,
        .user = NULL,
    };
    session->out.alloc = &rejecting;

    RFB_CHECK_EQ_INT(
        rfb_session_internal_queue_fresh_rekey(
            session, rekey_fixed_random, &rng),
        RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(rng.calls, 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), 0u);
    rekey_assert_old_state(session, old_encrypt_cbc, old_decrypt_cbc);
    session->out.alloc = rfb_default_allocator();
    rfb_session_destroy(session);
}

RFB_TEST(rfb_session_fresh_rekey,
         output_limit__does_not_generate_or_change_direction)
{
    rfb_session session_storage;
    rfb_session *session = &session_storage;
    rekey_rng rng = { .calls = 0u, .fail_call = 0u };
    rekey_session_init(session, 67u);
    const rfb_crypto_cbc_ctx *old_encrypt_cbc =
        session->apple_rl.encrypt.cbc;
    const rfb_crypto_cbc_ctx *old_decrypt_cbc =
        session->apple_rl.decrypt.cbc;

    RFB_CHECK_EQ_INT(
        rfb_session_internal_queue_fresh_rekey(
            session, rekey_fixed_random, &rng),
        RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(rng.calls, 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), 0u);
    rekey_assert_old_state(session, old_encrypt_cbc, old_decrypt_cbc);
    rfb_session_destroy(session);
}
