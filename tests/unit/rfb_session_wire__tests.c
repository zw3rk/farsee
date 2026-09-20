// SPDX-License-Identifier: Apache-2.0
//
// Deterministic byte contracts for the RFB session wire owner.

#include "rfb_test.h"

#include "farsee/allocator.h"
#include "farsee/apple_crypto.h"
#include "farsee/apple_record.h"
#include "farsee/apple_wire_record.h"
#include "farsee/buffer.h"
#include "farsee/encoding.h"
#include "farsee/error.h"
#include "farsee/framebuffer.h"
#include "farsee/limits.h"
#include "farsee/pixel_format.h"
#include "farsee/rfb_session.h"
#include "farsee/server_init.h"
#include "rfb/rfb_session_internal.h"
#include "tests/test_framework/fake_io.h"

#include <stdbool.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static const uint8_t wire_test_wrap_key[16] = {
    0x2bu, 0x7eu, 0x15u, 0x16u, 0x28u, 0xaeu, 0xd2u, 0xa6u,
    0xabu, 0xf7u, 0x15u, 0x88u, 0x09u, 0xcfu, 0x4fu, 0x3cu,
};

static const uint8_t wire_test_content_key[16] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu,
};

static const uint8_t wire_test_iv[16] = {
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1au, 0x1bu, 0x1cu, 0x1du, 0x1eu, 0x1fu,
};

// Project-owned post-ServerInit byte contracts. These constants are kept
// separate from the product arrays so a product edit cannot update both the
// writer and its expected output at run time.
static const uint8_t wire_test_modern_prefix[82] = {
    0x21u, 0x00u, 0x00u, 0x3eu, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u, 0x02u,
    0x00u, 0x00u, 0x00u, 0x06u, 0x00u, 0x00u, 0x00u, 0x01u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x1au, 0x00u, 0x00u, 0x00u, 0x05u,
    0x00u, 0x00u, 0x00u, 0x02u, 0xb0u, 0x00u, 0x0cu, 0x03u, 0x90u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x40u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x12u, 0x00u, 0x00u, 0x01u, 0x00u, 0x01u, 0x00u, 0x01u, 0x00u, 0x00u,
    0x00u, 0x01u, 0x0au, 0x00u, 0x00u, 0x01u,
};

static const uint8_t wire_test_classic_pixel_format[20] = {
    0x00u, 0x00u, 0x00u, 0x00u,
    0x20u, 0x18u, 0x00u, 0x01u,
    0x00u, 0xffu, 0x00u, 0xffu, 0x00u, 0xffu,
    0x10u, 0x08u, 0x00u, 0x00u, 0x00u, 0x00u,
};

static const uint8_t wire_test_setenc_clear[16] = {
    0x02u, 0x00u, 0x00u, 0x03u,
    0x00u, 0x00u, 0x00u, 0x10u,
    0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x04u, 0x50u,
};

static const uint8_t wire_test_setenc_control[16] = {
    0x02u, 0x00u, 0x00u, 0x03u,
    0x00u, 0x00u, 0x00u, 0x10u,
    0xffu, 0xffu, 0xffu, 0x21u,
    0xffu, 0xffu, 0xffu, 0x11u,
};

static const uint8_t wire_test_setenc_records[20] = {
    0x02u, 0x00u, 0x00u, 0x04u,
    0x00u, 0x00u, 0x00u, 0x10u,
    0x00u, 0x00u, 0x00u, 0x00u,
    0xffu, 0xffu, 0xffu, 0x21u,
    0xffu, 0xffu, 0xffu, 0x11u,
};

static const uint8_t wire_test_setenc_private[56] = {
    0x02u, 0x00u, 0x00u, 0x0du, 0x00u, 0x00u, 0x03u, 0xf3u,
    0x00u, 0x00u, 0x03u, 0xeau, 0x00u, 0x00u, 0x00u, 0x06u,
    0x00u, 0x00u, 0x00u, 0x10u, 0xffu, 0xffu, 0xffu, 0x11u,
    0x00u, 0x00u, 0x04u, 0x50u, 0x00u, 0x00u, 0x04u, 0x4cu,
    0xffu, 0xffu, 0xffu, 0x21u, 0x00u, 0x00u, 0x04u, 0x4du,
    0x00u, 0x00u, 0x04u, 0x51u, 0x00u, 0x00u, 0x04u, 0x53u,
    0x00u, 0x00u, 0x04u, 0x55u, 0x00u, 0x00u, 0x04u, 0x56u,
};

static const uint8_t wire_test_fbur[10] = {
    0x03u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x02u, 0x00u, 0x03u,
};

static const uint8_t wire_test_setup_pointer[18] = {
    0x05u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x05u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x05u, 0x00u, 0x00u, 0x01u, 0x00u, 0x01u,
};

static bool wire_test_expect_fragment(const uint8_t *wire,
                                      size_t wire_length, size_t *offset,
                                      const uint8_t *expected,
                                      size_t expected_length)
{
    if (wire == NULL || offset == NULL || expected == NULL ||
        *offset > wire_length || expected_length > wire_length - *offset) {
        return false;
    }
    if (memcmp(wire + *offset, expected, expected_length) != 0) {
        return false;
    }
    *offset += expected_length;
    return true;
}

static void wire_test_put_u32be(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24u);
    out[1] = (uint8_t)(value >> 16u);
    out[2] = (uint8_t)(value >> 8u);
    out[3] = (uint8_t)value;
}

static void wire_test_make_setup(uint8_t setup[APPLE_WIRE_SETUP_LEN],
                                 uint32_t type, uint32_t method)
{
    memset(setup, 0, APPLE_WIRE_SETUP_LEN);
    wire_test_put_u32be(setup, 1u);
    wire_test_put_u32be(setup + 12u, type);
    wire_test_put_u32be(setup + 16u, method);
    RFB_CHECK(rfb_crypto_aes128_ecb_encrypt(
        wire_test_wrap_key, wire_test_content_key, setup + 20u));
    RFB_CHECK(rfb_crypto_aes128_ecb_encrypt(
        wire_test_wrap_key, wire_test_iv, setup + 36u));
}

static bool wire_test_expected_c2s(uint8_t mode, const uint8_t *setup,
                                   const uint8_t sk32[32], uint8_t key[16],
                                   uint8_t iv[16], bool *active)
{
    if (setup == NULL || sk32 == NULL || key == NULL || iv == NULL ||
        active == NULL || mode > 12u) {
        return false;
    }
    memset(key, 0, 16u);
    memset(iv, 0, 16u);
    *active = mode != 4u;
    switch (mode) {
    case 0u:
        memcpy(key, wire_test_content_key, 16u);
        memcpy(iv, wire_test_iv, 16u);
        return true;
    case 1u:
        memcpy(key, wire_test_content_key, 16u);
        return true;
    case 2u:
        memcpy(key, wire_test_iv, 16u);
        memcpy(iv, wire_test_content_key, 16u);
        return true;
    case 3u:
        memcpy(key, wire_test_wrap_key, 16u);
        memcpy(iv, wire_test_iv, 16u);
        return true;
    case 4u:
        return true;
    case 5u:
        memcpy(key, setup + 20u, 16u);
        memcpy(iv, setup + 36u, 16u);
        return true;
    case 6u:
        memcpy(key, wire_test_wrap_key, 16u);
        return true;
    case 7u:
        memcpy(key, sk32, 16u);
        memcpy(iv, sk32 + 16u, 16u);
        return true;
    case 8u:
        return rfb_crypto_aes128_ecb_encrypt(
                   wire_test_wrap_key, setup + 20u, key) &&
               rfb_crypto_aes128_ecb_encrypt(
                   wire_test_wrap_key, setup + 36u, iv);
    case 9u:
        memcpy(key, wire_test_content_key, 16u);
        memcpy(iv, setup + 36u, 16u);
        return true;
    case 10u: {
        uint8_t label[19];
        uint8_t digest[32];
        memcpy(label, wire_test_content_key, 16u);
        label[16] = (uint8_t)'C';
        label[17] = (uint8_t)'2';
        label[18] = (uint8_t)'S';
        if (!rfb_crypto_sha256(label, sizeof label, digest)) {
            return false;
        }
        memcpy(key, digest, 16u);
        memcpy(iv, wire_test_iv, 16u);
        return true;
    }
    case 11u: {
        uint8_t label[64];
        uint8_t digest[32];
        memcpy(label, sk32, 32u);
        memcpy(label + 32u, setup + 20u, 32u);
        if (!rfb_crypto_sha256(label, sizeof label, digest)) {
            return false;
        }
        memcpy(key, digest, 16u);
        memcpy(iv, digest + 16u, 16u);
        return true;
    }
    case 12u:
        return rfb_crypto_aes128_ecb_encrypt(
                   wire_test_wrap_key, wire_test_content_key, key) &&
               rfb_crypto_aes128_ecb_encrypt(
                   wire_test_wrap_key, wire_test_iv, iv);
    default:
        return false;
    }
}

static void wire_test_session_init(rfb_session *session, fake_io *io,
                                   rfb_session_dialect dialect)
{
    rfb_session_clear(session);
    session->alloc = rfb_default_allocator();
    fake_io_init(io, session->alloc);
    session->io = fake_io_adapter_make(io);
    session->io_open = true;
    rfb_buffer_init(&session->in, session->alloc,
                    RFB_LIMIT_FB_BYTES_POLICY);
    rfb_buffer_init(&session->out, session->alloc,
                    RFB_LIMIT_OUTBOUND_BYTES);
    rfb_framebuffer_init(&session->fb, session->alloc);
    session->dialect = dialect;
    session->fb_width = 2u;
    session->fb_height = 3u;
}

static void wire_test_session_destroy(rfb_session *session, fake_io *io)
{
    rfb_session_destroy(session);
    fake_io_destroy(io);
}

static rfb_server_init wire_test_server_init(void)
{
    rfb_server_init init;
    memset(&init, 0, sizeof init);
    init.width = 2u;
    init.height = 3u;
    init.pixel_format = rfb_pixel_format_canonical_request();
    return init;
}

static size_t wire_test_open_record(apple_record_layer *mirror,
                                    const uint8_t *wire, size_t wire_length,
                                    uint8_t *plaintext,
                                    size_t plaintext_capacity,
                                    size_t *plaintext_length)
{
    const size_t total = apple_wire_cipher_record_len(
        wire, wire_length, APPLE_RECORD_MAX_BODY);
    if (total == 0u || total == (size_t)-1 || total > wire_length ||
        total < 2u) {
        RFB_FAIL("invalid sealed record framing");
        if (plaintext_length != NULL) {
            *plaintext_length = 0u;
        }
        return 0u;
    }
    RFB_CHECK_EQ_INT(apple_wire_record_open(
                         mirror, wire + 2u, total - 2u, plaintext,
                         plaintext_capacity, plaintext_length),
                     RFB_OK);
    return total;
}

static bool wire_test_random_ok(void *opaque, uint8_t *out, size_t length)
{
    (void)opaque;
    memset(out, 0x5au, length);
    return true;
}

static void *wire_test_reject_alloc(rfb_allocator *allocator, size_t size)
{
    (void)allocator;
    (void)size;
    return NULL;
}

static void wire_test_reject_free(rfb_allocator *allocator, void *allocation)
{
    (void)allocator;
    (void)allocation;
}

static rfb_io_result wire_test_write_zero(void *context, const uint8_t *data,
                                          size_t length, size_t *out_length)
{
    (void)context;
    (void)data;
    (void)length;
    *out_length = 0u;
    return RFB_IO_OK;
}

typedef struct wire_test_random_script {
    unsigned calls;
    unsigned fail_on_call;
} wire_test_random_script;

static bool wire_test_random_scripted(void *opaque, uint8_t *out,
                                      size_t length)
{
    wire_test_random_script *script = (wire_test_random_script *)opaque;
    script->calls++;
    if (script->calls == script->fail_on_call) {
        return false;
    }
    memset(out, (int)(0x40u + script->calls), length);
    return true;
}

static void wire_test_rekey_session_init(rfb_session *session, fake_io *io)
{
    wire_test_session_init(session, io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    apple_record_init(&session->apple_rl, wire_test_wrap_key);
    RFB_CHECK(apple_record_set_direction(&session->apple_rl,
                                         APPLE_DIR_ENCRYPT,
                                         wire_test_content_key,
                                         wire_test_iv));
    session->apple_rl_inited = true;
    session->apple_records_active = true;
}

static void wire_test_check_original_encrypt_state(
    const rfb_session *session)
{
    RFB_CHECK(session->apple_rl.encrypt.active);
    RFB_CHECK(session->apple_rl.encrypt.cbc != NULL);
    RFB_CHECK_MEM_EQ(session->apple_rl.encrypt.content_key,
                     wire_test_content_key, sizeof wire_test_content_key);
    RFB_CHECK_MEM_EQ(session->apple_rl.encrypt.iv,
                     wire_test_iv, sizeof wire_test_iv);
    RFB_CHECK_EQ_UINT(session->apple_rl.encrypt.sequence, 0u);
}

RFB_TEST(rfb_session_wire, queue_bytes__clear_and_sealed_guards)
{
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    wire_test_session_init(session, &io, RFB_SESSION_DIALECT_CLASSIC);

    static const uint8_t clear[] = {0x03u, 0x01u, 0x02u, 0x03u};
    RFB_CHECK_EQ_INT(session_queue_bytes(session, clear, sizeof clear), RFB_OK);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), sizeof clear);
    RFB_CHECK_MEM_EQ(fake_io_outbox_data(&io), clear, sizeof clear);

    apple_record_init(&session->apple_rl, wire_test_wrap_key);
    RFB_CHECK(apple_record_set_direction(&session->apple_rl,
                                         APPLE_DIR_ENCRYPT,
                                         wire_test_content_key,
                                         wire_test_iv));
    session->apple_rl_inited = true;
    session->apple_records_active = true;
    uint8_t ignored = 0u;
    RFB_CHECK_EQ_INT(session_queue_bytes(session, &ignored,
                                         (size_t)UINT16_MAX + 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(session_queue_bytes(session, &ignored, 4095u),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_LIMIT);

    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire, queue_bytes__null_session_fails_closed)
{
    static const uint8_t message[] = {0x03u};
    RFB_CHECK_EQ_INT(session_queue_bytes(NULL, message, sizeof message),
                     RFB_ERR_INTERNAL);
}

RFB_TEST(rfb_session_wire, queue_bytes__active_zero_and_null_passthrough)
{
    static const uint8_t byte = 0x03u;
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    wire_test_rekey_session_init(session, &io);

    RFB_CHECK_EQ_INT(session_queue_bytes(session, NULL, 0u), RFB_OK);
    RFB_CHECK_EQ_INT(session_queue_bytes(session, &byte, 0u), RFB_OK);
    RFB_CHECK_EQ_INT(session_queue_bytes(session, NULL, 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(session->apple_rl.encrypt.sequence, 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), 0u);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), 0u);

    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire, queue_bytes__reserve_and_seal_fail_closed)
{
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    apple_record_init(&session->apple_rl, wire_test_wrap_key);
    RFB_CHECK(apple_record_set_direction(&session->apple_rl,
                                         APPLE_DIR_ENCRYPT,
                                         wire_test_content_key,
                                         wire_test_iv));
    session->apple_rl_inited = true;
    session->apple_records_active = true;
    static const uint8_t message[] = {0x03u, 0x00u};
    rfb_allocator rejecting = {
        .alloc = wire_test_reject_alloc,
        .free = wire_test_reject_free,
        .user = NULL,
    };
    session->out.alloc = &rejecting;
    RFB_CHECK_EQ_INT(session_queue_bytes(session, message, sizeof message),
                     RFB_ERR_NOMEM);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(session->apple_rl.encrypt.sequence, 0u);

    session->out.alloc = rfb_default_allocator();
    session->apple_rl.encrypt.active = false;
    RFB_CHECK_EQ_INT(session_queue_bytes(session, message, sizeof message),
                     RFB_ERR_STATE);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_STATE);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), 0u);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire,
         queue_bytes__hard_limit_guards_preserve_queue_and_record_state)
{
    static const uint8_t queued[] = {0xa5u};
    static const uint8_t message[] = {0x03u, 0x00u};
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    wire_test_rekey_session_init(session, &io);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session->out, queued, sizeof queued),
                     RFB_OK);

    session->out.hard_limit = 0u;
    RFB_CHECK_EQ_INT(session_queue_bytes(session, message, sizeof message),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), sizeof queued);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&session->out), queued, sizeof queued);
    wire_test_check_original_encrypt_state(session);

    session->out.hard_limit = sizeof queued + 33u;
    RFB_CHECK_EQ_INT(session_queue_bytes(session, message, sizeof message),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), sizeof queued);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&session->out), queued, sizeof queued);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), 0u);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_LIMIT);
    wire_test_check_original_encrypt_state(session);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire, fresh_rekey__state_guards)
{
    RFB_CHECK_EQ_INT(rfb_session_internal_queue_fresh_rekey(
                         NULL, wire_test_random_ok, NULL),
                     RFB_ERR_STATE);

    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    RFB_CHECK_EQ_INT(rfb_session_internal_queue_fresh_rekey(
                         session, wire_test_random_ok, NULL),
                     RFB_ERR_STATE);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_STATE);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire, fresh_rekey__each_state_guard_preserves_queue)
{
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    wire_test_rekey_session_init(session, &io);
    wire_test_random_script random = {0u, 0u};

    RFB_CHECK_EQ_INT(rfb_session_internal_queue_fresh_rekey(
                         session, NULL, &random),
                     RFB_ERR_STATE);

    session->apple_rl_inited = false;
    RFB_CHECK_EQ_INT(rfb_session_internal_queue_fresh_rekey(
                         session, wire_test_random_scripted, &random),
                     RFB_ERR_STATE);
    session->apple_rl_inited = true;

    session->apple_records_active = false;
    RFB_CHECK_EQ_INT(rfb_session_internal_queue_fresh_rekey(
                         session, wire_test_random_scripted, &random),
                     RFB_ERR_STATE);
    session->apple_records_active = true;

    session->apple_rl.initialized = false;
    RFB_CHECK_EQ_INT(rfb_session_internal_queue_fresh_rekey(
                         session, wire_test_random_scripted, &random),
                     RFB_ERR_STATE);
    session->apple_rl.initialized = true;

    session->apple_rl.encrypt.active = false;
    RFB_CHECK_EQ_INT(rfb_session_internal_queue_fresh_rekey(
                         session, wire_test_random_scripted, &random),
                     RFB_ERR_STATE);
    session->apple_rl.encrypt.active = true;

    rfb_crypto_cbc_ctx *cbc = session->apple_rl.encrypt.cbc;
    session->apple_rl.encrypt.cbc = NULL;
    RFB_CHECK_EQ_INT(rfb_session_internal_queue_fresh_rekey(
                         session, wire_test_random_scripted, &random),
                     RFB_ERR_STATE);
    session->apple_rl.encrypt.cbc = cbc;

    RFB_CHECK_EQ_UINT(random.calls, 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), 0u);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), 0u);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_STATE);
    wire_test_check_original_encrypt_state(session);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire,
         fresh_rekey__limits_random_and_allocator_fail_transactionally)
{
    static const uint8_t queued[] = {0xa5u};
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    wire_test_random_script random = {0u, 0u};

    wire_test_rekey_session_init(session, &io);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session->out, queued, sizeof queued),
                     RFB_OK);
    session->out.hard_limit = 0u;
    RFB_CHECK_EQ_INT(rfb_session_internal_queue_fresh_rekey(
                         session, wire_test_random_scripted, &random),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(random.calls, 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), sizeof queued);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&session->out), queued, sizeof queued);
    wire_test_check_original_encrypt_state(session);
    wire_test_session_destroy(session, &io);

    wire_test_rekey_session_init(session, &io);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session->out, queued, sizeof queued),
                     RFB_OK);
    session->out.hard_limit = 68u;
    random = (wire_test_random_script){0u, 0u};
    RFB_CHECK_EQ_INT(rfb_session_internal_queue_fresh_rekey(
                         session, wire_test_random_scripted, &random),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(random.calls, 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), sizeof queued);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&session->out), queued, sizeof queued);
    wire_test_check_original_encrypt_state(session);
    wire_test_session_destroy(session, &io);

    rfb_allocator rejecting = {
        .alloc = wire_test_reject_alloc,
        .free = wire_test_reject_free,
        .user = NULL,
    };
    wire_test_rekey_session_init(session, &io);
    session->out.alloc = &rejecting;
    random = (wire_test_random_script){0u, 0u};
    RFB_CHECK_EQ_INT(rfb_session_internal_queue_fresh_rekey(
                         session, wire_test_random_scripted, &random),
                     RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(random.calls, 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), 0u);
    wire_test_check_original_encrypt_state(session);
    wire_test_session_destroy(session, &io);

    for (unsigned fail_on_call = 1u; fail_on_call <= 2u; fail_on_call++) {
        wire_test_rekey_session_init(session, &io);
        random = (wire_test_random_script){0u, fail_on_call};
        RFB_CHECK_EQ_INT(rfb_session_internal_queue_fresh_rekey(
                             session, wire_test_random_scripted, &random),
                         RFB_ERR_INTERNAL);
        RFB_CHECK_EQ_UINT(random.calls, fail_on_call);
        RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), 0u);
        wire_test_check_original_encrypt_state(session);
        wire_test_session_destroy(session, &io);
    }

    wire_test_rekey_session_init(session, &io);
    session->alloc = &rejecting;
    random = (wire_test_random_script){0u, 0u};
    RFB_CHECK_EQ_INT(rfb_session_internal_queue_fresh_rekey(
                         session, wire_test_random_scripted, &random),
                     RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(random.calls, 2u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), 0u);
    wire_test_check_original_encrypt_state(session);
    session->alloc = rfb_default_allocator();
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire, setup_after_server_init__classic_exact_order)
{
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    wire_test_session_init(session, &io, RFB_SESSION_DIALECT_CLASSIC);
    const rfb_server_init init = wire_test_server_init();

    RFB_CHECK_EQ_INT(
        rfb_session_internal_setup_after_server_init(session, &init), RFB_OK);
    const uint8_t *wire = fake_io_outbox_data(&io);
    static const uint8_t setenc[24] = {
        0x02u, 0x00u, 0x00u, 0x05u,
        0x00u, 0x00u, 0x00u, 0x10u,
        0x00u, 0x00u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0xffu, 0xffu, 0xffu, 0x11u,
        0xffu, 0xffu, 0xffu, 0x21u,
    };
    const size_t wire_length = fake_io_outbox_len(&io);
    size_t offset = 0u;
    RFB_CHECK(wire_test_expect_fragment(
        wire, wire_length, &offset, wire_test_classic_pixel_format,
        sizeof wire_test_classic_pixel_format));
    RFB_CHECK(wire_test_expect_fragment(
        wire, wire_length, &offset, setenc, sizeof setenc));
    RFB_CHECK(wire_test_expect_fragment(
        wire, wire_length, &offset, wire_test_fbur,
        sizeof wire_test_fbur));
    RFB_CHECK_EQ_UINT(offset, wire_length);
    RFB_CHECK(rfb_pixel_format_is_canonical(&session->pf));
    RFB_CHECK_EQ_UINT(session->fb.width, 2u);
    RFB_CHECK_EQ_UINT(session->fb.height, 3u);
    RFB_CHECK_EQ_UINT(session->last_ptr_x, 1u);
    RFB_CHECK_EQ_UINT(session->last_ptr_y, 1u);

    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire, setup_after_server_init__failure_paths)
{
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    wire_test_session_init(session, &io, RFB_SESSION_DIALECT_CLASSIC);
    rfb_server_init init = wire_test_server_init();
    init.width = 0u;
    RFB_CHECK_EQ_INT(
        rfb_session_internal_setup_after_server_init(session, &init),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_PROTOCOL);
    wire_test_session_destroy(session, &io);

    wire_test_session_init(session, &io, RFB_SESSION_DIALECT_CLASSIC);
    init = wire_test_server_init();
    session->cfg.capture_initial_only = true;
    RFB_CHECK_EQ_INT(
        rfb_session_internal_setup_after_server_init(session, &init),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_PROTOCOL);
    wire_test_session_destroy(session, &io);

    wire_test_session_init(session, &io, RFB_SESSION_DIALECT_CLASSIC);
    init = wire_test_server_init();
    rfb_allocator rejecting = {
        .alloc = wire_test_reject_alloc,
        .free = wire_test_reject_free,
        .user = NULL,
    };
    session->alloc = &rejecting;
    RFB_CHECK_EQ_INT(
        rfb_session_internal_setup_after_server_init(session, &init),
        RFB_ERR_NOMEM);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_NOMEM);
    session->alloc = rfb_default_allocator();
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire,
         setup_after_server_init__queue_failures_preserve_exact_stage)
{
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    rfb_server_init init = wire_test_server_init();

    wire_test_session_init(session, &io, RFB_SESSION_DIALECT_CLASSIC);
    session->out.hard_limit = sizeof wire_test_classic_pixel_format;
    RFB_CHECK_EQ_INT(
        rfb_session_internal_setup_after_server_init(session, &init),
        RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io),
                      sizeof wire_test_classic_pixel_format);
    RFB_CHECK_MEM_EQ(fake_io_outbox_data(&io),
                     wire_test_classic_pixel_format,
                     sizeof wire_test_classic_pixel_format);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), 0u);
    RFB_CHECK(session->zstream != NULL);
    wire_test_session_destroy(session, &io);

    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session->out.hard_limit = sizeof wire_test_setenc_clear - 1u;
    RFB_CHECK_EQ_INT(
        rfb_session_internal_setup_after_server_init(session, &init),
        RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), 0u);
    RFB_CHECK(session->zstream != NULL);
    wire_test_session_destroy(session, &io);

    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session->cfg.apple_postauth_mode = RFB_APPLE_POSTAUTH_RECORDS;
    io.wmode = FAKE_W_ERROR;
    RFB_CHECK_EQ_INT(
        rfb_session_internal_setup_after_server_init(session, &init),
        RFB_ERR_IO);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_IO);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out),
                      sizeof wire_test_modern_prefix +
                          sizeof wire_test_setenc_records);
    size_t offset = 0u;
    RFB_CHECK(wire_test_expect_fragment(
        rfb_buffer_data(&session->out), rfb_buffer_length(&session->out),
        &offset, wire_test_modern_prefix, sizeof wire_test_modern_prefix));
    RFB_CHECK(wire_test_expect_fragment(
        rfb_buffer_data(&session->out), rfb_buffer_length(&session->out),
        &offset, wire_test_setenc_records, sizeof wire_test_setenc_records));
    RFB_CHECK_EQ_UINT(offset, rfb_buffer_length(&session->out));
    RFB_CHECK(session->zstream != NULL);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire,
         setup_after_server_init__each_queue_stage_fails_closed)
{
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    const rfb_server_init init = wire_test_server_init();

    wire_test_session_init(session, &io, RFB_SESSION_DIALECT_CLASSIC);
    session->out.hard_limit = sizeof wire_test_classic_pixel_format - 1u;
    RFB_CHECK_EQ_INT(
        rfb_session_internal_setup_after_server_init(session, &init),
        RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), 0u);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), 0u);
    RFB_CHECK(session->zstream == NULL);
    wire_test_session_destroy(session, &io);

    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session->io.write = wire_test_write_zero;
    session->out.hard_limit = sizeof wire_test_setenc_clear;
    RFB_CHECK_EQ_INT(
        rfb_session_internal_setup_after_server_init(session, &init),
        RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out),
                      sizeof wire_test_setenc_clear);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&session->out), wire_test_setenc_clear,
                     sizeof wire_test_setenc_clear);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), 0u);
    RFB_CHECK(session->zstream != NULL);
    wire_test_session_destroy(session, &io);

    wire_test_session_init(session, &io, RFB_SESSION_DIALECT_CLASSIC);
    session->io.write = wire_test_write_zero;
    session->out.hard_limit = sizeof wire_test_classic_pixel_format + 24u;
    RFB_CHECK_EQ_INT(
        rfb_session_internal_setup_after_server_init(session, &init),
        RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out),
                      sizeof wire_test_classic_pixel_format + 24u);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&session->out),
                     wire_test_classic_pixel_format,
                     sizeof wire_test_classic_pixel_format);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), 0u);
    RFB_CHECK(session->zstream != NULL);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire,
         setup_after_server_init__invalid_apple_format_and_query_capture)
{
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    rfb_server_init init = wire_test_server_init();

    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    init.pixel_format.bits_per_pixel = 0u;
    RFB_CHECK_EQ_INT(
        rfb_session_internal_setup_after_server_init(session, &init), RFB_OK);
    RFB_CHECK(rfb_pixel_format_is_canonical(&session->pf));
    wire_test_session_destroy(session, &io);

    static const rfb_capture_query query = {
        .id = 77u,
        .incremental = false,
        .geometry_policy = RFB_CAPTURE_GEOMETRY_EXACT,
        .x = 0u,
        .y = 0u,
        .width = 8u,
        .height = 8u,
    };
    wire_test_session_init(session, &io, RFB_SESSION_DIALECT_CLASSIC);
    session->cfg.capture_queries = &query;
    session->cfg.capture_query_count = 1u;
    session->cfg.capture_response_timeout_ms = 100u;
    session->cfg.capture_quiet_ms = 10u;
    init = wire_test_server_init();
    init.width = 8u;
    init.height = 8u;
    RFB_CHECK_EQ_INT(
        rfb_session_internal_setup_after_server_init(session, &init), RFB_OK);
    RFB_CHECK(session->capture_enabled);
    RFB_CHECK_EQ_INT(session->capture.state,
                     RFB_CAPTURE_SCHEDULER_WAIT_INITIAL);
    RFB_CHECK_EQ_UINT(session->capture.query_count, 1u);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire, setup_after_server_init__classic_capture_contract)
{
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    wire_test_session_init(session, &io, RFB_SESSION_DIALECT_CLASSIC);
    session->cfg.capture_initial_only = true;
    session->cfg.capture_initial_zrle_only = true;
    session->cfg.capture_response_timeout_ms = 100u;
    session->cfg.capture_quiet_ms = 10u;
    const rfb_server_init init = wire_test_server_init();
    RFB_CHECK_EQ_INT(
        rfb_session_internal_setup_after_server_init(session, &init), RFB_OK);
    RFB_CHECK(session->capture_enabled);
    const uint8_t *wire = fake_io_outbox_data(&io);
    const size_t wire_length = fake_io_outbox_len(&io);
    size_t offset = 0u;
    RFB_CHECK(wire_test_expect_fragment(
        wire, wire_length, &offset, wire_test_classic_pixel_format,
        sizeof wire_test_classic_pixel_format));
    RFB_CHECK(wire_test_expect_fragment(
        wire, wire_length, &offset, wire_test_setenc_control,
        sizeof wire_test_setenc_control));
    RFB_CHECK(wire_test_expect_fragment(
        wire, wire_length, &offset, wire_test_fbur,
        sizeof wire_test_fbur));
    RFB_CHECK_EQ_UINT(offset, wire_length);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire, modern_setup__null_and_queue_limit)
{
    RFB_CHECK_EQ_INT(session_queue_apple_modern_setup(NULL, false),
                     RFB_ERR_INTERNAL);

    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session->out.hard_limit = 80u;
    RFB_CHECK_EQ_INT(session_queue_apple_modern_setup(session, false),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_LIMIT);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire, setup_after_server_init__apple_mode_contracts)
{
    typedef struct setup_case {
        rfb_apple_postauth_mode mode;
        bool capture_initial_only;
        bool view_only;
        size_t expected_length;
    } setup_case;
    static const setup_case cases[] = {
        {RFB_APPLE_POSTAUTH_CLEARTEXT, false, false, 44u},
        {RFB_APPLE_POSTAUTH_CLEARTEXT, false, true, 26u},
        {RFB_APPLE_POSTAUTH_CLEARTEXT, true, false, 26u},
        {RFB_APPLE_POSTAUTH_RECORDS, false, false, 102u},
        {RFB_APPLE_POSTAUTH_PRIVATE_ENCODINGS, false, false,
         APPLE_WIRE_MODERN_POST_SI_LEN},
        {RFB_APPLE_POSTAUTH_RECORDS, true, false, 98u},
    };

    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        rfb_session storage;
        rfb_session *session = &storage;
        fake_io io;
        wire_test_session_init(session, &io,
                               RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
        session->cfg.apple_postauth_mode = cases[i].mode;
        session->cfg.view_only = cases[i].view_only;
        session->cfg.capture_initial_only = cases[i].capture_initial_only;
        if (cases[i].capture_initial_only) {
            session->cfg.capture_initial_zrle_only = true;
            session->cfg.capture_response_timeout_ms = 100u;
            session->cfg.capture_quiet_ms = 10u;
        }
        const rfb_server_init init = wire_test_server_init();

        RFB_CHECK_EQ_INT(
            rfb_session_internal_setup_after_server_init(session, &init),
            RFB_OK);
        RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), cases[i].expected_length);
        RFB_CHECK(rfb_pixel_format_eq(&session->pf, &init.pixel_format));
        RFB_CHECK_EQ_UINT(session->last_ptr_x, 1u);
        RFB_CHECK_EQ_UINT(session->last_ptr_y, 1u);
        if (cases[i].capture_initial_only) {
            RFB_CHECK(session->capture_enabled);
        }
        const uint8_t *wire = fake_io_outbox_data(&io);
        const size_t wire_length = fake_io_outbox_len(&io);
        size_t offset = 0u;
        if (cases[i].mode == RFB_APPLE_POSTAUTH_CLEARTEXT) {
            const uint8_t *setenc = cases[i].capture_initial_only
                                        ? wire_test_setenc_control
                                        : wire_test_setenc_clear;
            const size_t setenc_length = cases[i].capture_initial_only
                                              ? sizeof wire_test_setenc_control
                                              : sizeof wire_test_setenc_clear;
            RFB_CHECK(wire_test_expect_fragment(
                wire, wire_length, &offset, setenc, setenc_length));
            RFB_CHECK(wire_test_expect_fragment(
                wire, wire_length, &offset, wire_test_fbur,
                sizeof wire_test_fbur));
            if (!cases[i].view_only && !cases[i].capture_initial_only) {
                RFB_CHECK(wire_test_expect_fragment(
                    wire, wire_length, &offset, wire_test_setup_pointer,
                    sizeof wire_test_setup_pointer));
            }
        } else {
            RFB_CHECK(wire_test_expect_fragment(
                wire, wire_length, &offset, wire_test_modern_prefix,
                sizeof wire_test_modern_prefix));
            const uint8_t *setenc = wire_test_setenc_records;
            size_t setenc_length = sizeof wire_test_setenc_records;
            if (cases[i].mode == RFB_APPLE_POSTAUTH_PRIVATE_ENCODINGS) {
                setenc = wire_test_setenc_private;
                setenc_length = sizeof wire_test_setenc_private;
            } else if (cases[i].capture_initial_only) {
                setenc = wire_test_setenc_control;
                setenc_length = sizeof wire_test_setenc_control;
            }
            RFB_CHECK(wire_test_expect_fragment(
                wire, wire_length, &offset, setenc, setenc_length));
        }
        RFB_CHECK_EQ_UINT(offset, wire_length);

        wire_test_session_destroy(session, &io);
    }
}

RFB_TEST(rfb_session_wire, enable_apple_records__rejects_invalid_setup)
{
    RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(NULL),
                     RFB_ERR_INTERNAL);

    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                     RFB_ERR_INTERNAL);
    wire_test_session_destroy(session, &io);

    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session->has_wrap_key = true;
    memcpy(session->wrap_key, wire_test_wrap_key, sizeof session->wrap_key);
    static const uint8_t bad[APPLE_WIRE_SETUP_LEN] = {0xffu};
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session->in, bad, sizeof bad), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_PROTOCOL);
    wire_test_session_destroy(session, &io);

    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session->has_wrap_key = true;
    memcpy(session->wrap_key, wire_test_wrap_key, sizeof session->wrap_key);
    uint8_t unsupported[APPLE_WIRE_SETUP_LEN];
    wire_test_make_setup(unsupported, APPLE_WIRE_TYPE_ENABLE, 2u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session->in, unsupported,
                                       sizeof unsupported),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                     RFB_ERR_UNSUPPORTED);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_UNSUPPORTED);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire, enable_apple_records__cancel_deadline_and_ack_io)
{
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session->has_wrap_key = true;
    memcpy(session->wrap_key, wire_test_wrap_key, sizeof session->wrap_key);
    farsee_atomic_int stop;
    farsee_atomic_int_store(&stop, 1);
    session->cfg.stop_flag = &stop;
    RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                     RFB_ERR_CANCELLED);
    wire_test_session_destroy(session, &io);

    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session->has_wrap_key = true;
    memcpy(session->wrap_key, wire_test_wrap_key, sizeof session->wrap_key);
    session->connect_deadline_mono_ms = 1u;
    RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                     RFB_ERR_TIMEOUT);
    wire_test_session_destroy(session, &io);

    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session->has_wrap_key = true;
    memcpy(session->wrap_key, wire_test_wrap_key, sizeof session->wrap_key);
    uint8_t setup[APPLE_WIRE_SETUP_LEN];
    wire_test_make_setup(setup, APPLE_WIRE_TYPE_ENABLE,
                         APPLE_WIRE_SETUP_METHOD_AES_CBC);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session->in, setup, sizeof setup),
                     RFB_OK);
    io.wmode = FAKE_W_ERROR;
    RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                     RFB_ERR_IO);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_IO);
    RFB_CHECK(!session->apple_records_active);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire,
         enable_apple_records__preflight_failures_preserve_queued_state)
{
    static const uint8_t queued[] = {0xa5u, 0x5au};
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;

    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session->has_wrap_key = true;
    memcpy(session->wrap_key, wire_test_wrap_key, sizeof session->wrap_key);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session->out, queued, sizeof queued),
                     RFB_OK);
    io.wmode = FAKE_W_ERROR;
    RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                     RFB_ERR_IO);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), sizeof queued);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&session->out), queued, sizeof queued);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), 0u);
    RFB_CHECK(!session->apple_records_active);
    wire_test_session_destroy(session, &io);

    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session->has_wrap_key = true;
    memcpy(session->wrap_key, wire_test_wrap_key, sizeof session->wrap_key);
    session->apple_rl_inited = true;
    uint8_t setup[APPLE_WIRE_SETUP_LEN];
    wire_test_make_setup(setup, APPLE_WIRE_TYPE_ENABLE,
                         APPLE_WIRE_SETUP_METHOD_AES_CBC);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session->in, setup, sizeof setup),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->in), sizeof setup);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&session->in), setup, sizeof setup);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), 0u);
    RFB_CHECK(!session->apple_records_active);
    RFB_CHECK(!session->apple_have_setup_payload);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire, enable_apple_records__all_key_modes_activate)
{
    for (uint8_t mode = 0u; mode <= 12u; mode++) {
        rfb_session storage;
        rfb_session *session = &storage;
        fake_io io;
        wire_test_session_init(session, &io,
                               RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
        session->has_wrap_key = true;
        memcpy(session->wrap_key, wire_test_wrap_key,
               sizeof session->wrap_key);
        session->wire_variants.c2s_key_mode = mode;
        session->wire_variants.suppress_fbur = true;
        uint8_t sk32[32];
        for (size_t i = 0u; i < sizeof sk32; i++) {
            sk32[i] = (uint8_t)(0x80u + i);
        }
        if (mode == 7u || mode == 11u) {
            memcpy(session->apple_sk32, sk32, sizeof sk32);
            session->apple_have_sk32 = true;
        }
        uint8_t setup[APPLE_WIRE_SETUP_LEN];
        wire_test_make_setup(setup, APPLE_WIRE_TYPE_ENABLE,
                             APPLE_WIRE_SETUP_METHOD_AES_CBC);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&session->in, setup, sizeof setup),
                         RFB_OK);

        RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                         RFB_OK);
        RFB_CHECK(session->apple_records_active);
        RFB_CHECK(session->apple_rl.decrypt.active);
        RFB_CHECK_MEM_EQ(session->apple_rl.decrypt.content_key,
                         wire_test_content_key, 16u);
        RFB_CHECK_MEM_EQ(session->apple_rl.decrypt.iv, wire_test_iv, 16u);
        RFB_CHECK_EQ_UINT(session->apple_rl.decrypt.sequence, 0u);
        uint8_t expected_key[16];
        uint8_t expected_iv[16];
        bool expected_active = false;
        RFB_CHECK(wire_test_expected_c2s(
            mode, setup, sk32, expected_key, expected_iv, &expected_active));
        RFB_CHECK(session->apple_rl.encrypt.active == expected_active);
        if (expected_active) {
            RFB_CHECK_MEM_EQ(session->apple_rl.encrypt.content_key,
                             expected_key, sizeof expected_key);
            RFB_CHECK_MEM_EQ(session->apple_rl.encrypt.iv,
                             expected_iv, sizeof expected_iv);
            RFB_CHECK_EQ_UINT(session->apple_rl.encrypt.sequence, 0u);
        }
        RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->in), 0u);
        RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io),
                          APPLE_WIRE_MSG12_ACK_LEN);
        RFB_CHECK_MEM_EQ(fake_io_outbox_data(&io), apple_wire_msg12_ack,
                         APPLE_WIRE_MSG12_ACK_LEN);
        RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                         RFB_OK);

        wire_test_session_destroy(session, &io);
    }
}

RFB_TEST(rfb_session_wire,
         enable_apple_records__missing_private_secret_uses_default_keys)
{
    for (uint8_t mode = 7u; mode <= 11u; mode += 4u) {
        rfb_session storage;
        rfb_session *session = &storage;
        fake_io io;
        wire_test_session_init(session, &io,
                               RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
        session->has_wrap_key = true;
        memcpy(session->wrap_key, wire_test_wrap_key,
               sizeof session->wrap_key);
        session->wire_variants.c2s_key_mode = mode;
        session->wire_variants.suppress_fbur = true;
        session->connect_deadline_mono_ms = UINT64_MAX;
        uint8_t setup[APPLE_WIRE_SETUP_LEN];
        wire_test_make_setup(setup, APPLE_WIRE_TYPE_ENABLE,
                             APPLE_WIRE_SETUP_METHOD_AES_CBC);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&session->in, setup, sizeof setup),
                         RFB_OK);

        RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                         RFB_OK);
        RFB_CHECK(session->apple_rl.encrypt.active);
        RFB_CHECK_MEM_EQ(session->apple_rl.encrypt.content_key,
                         wire_test_content_key,
                         sizeof wire_test_content_key);
        RFB_CHECK_MEM_EQ(session->apple_rl.encrypt.iv, wire_test_iv,
                         sizeof wire_test_iv);
        RFB_CHECK(!session->apple_have_sk32);
        wire_test_session_destroy(session, &io);
    }
}

RFB_TEST(rfb_session_wire,
         enable_apple_records__incremental_read_and_poll_error)
{
    uint8_t setup[APPLE_WIRE_SETUP_LEN];
    wire_test_make_setup(setup, APPLE_WIRE_TYPE_ENABLE,
                         APPLE_WIRE_SETUP_METHOD_AES_CBC);
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    int ready_pipe[2];
    RFB_CHECK_EQ_INT(pipe(ready_pipe), 0);

    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session->has_wrap_key = true;
    memcpy(session->wrap_key, wire_test_wrap_key, sizeof session->wrap_key);
    session->wire_variants.suppress_fbur = true;
    session->sock.fd = ready_pipe[0];
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session->in, setup, 1u), RFB_OK);
    fake_io_seed_inbox(&io, setup + 1u, sizeof setup - 1u);
    RFB_CHECK_EQ_UINT((size_t)write(ready_pipe[1], setup, 1u), 1u);
    RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                     RFB_OK);
    RFB_CHECK(session->apple_records_active);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->in), 0u);
    wire_test_session_destroy(session, &io);
    RFB_CHECK_EQ_INT(close(ready_pipe[0]), 0);
    RFB_CHECK_EQ_INT(close(ready_pipe[1]), 0);

    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session->has_wrap_key = true;
    memcpy(session->wrap_key, wire_test_wrap_key, sizeof session->wrap_key);
    session->sock.fd = INT_MAX;
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session->in, setup, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                     RFB_ERR_IO);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_IO);
    RFB_CHECK(!session->apple_records_active);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire, enable_apple_records__initial_output_order)
{
    typedef struct output_case {
        rfb_apple_initial_output_variant variant;
        bool suppress_fbur;
        size_t messages;
        bool msg14_first;
    } output_case;
    static const output_case cases[] = {
        {RFB_APPLE_INITIAL_OUTPUT_STANDARD, false, 1u, false},
        {RFB_APPLE_INITIAL_OUTPUT_STANDARD, true, 0u, false},
        {RFB_APPLE_INITIAL_OUTPUT_FBUR_ONLY, false, 1u, false},
        {RFB_APPLE_INITIAL_OUTPUT_FBUR_ONLY, true, 0u, false},
        {RFB_APPLE_INITIAL_OUTPUT_MSG14_THEN_FBUR, false, 2u, true},
        {RFB_APPLE_INITIAL_OUTPUT_FBUR_THEN_MSG14, false, 2u, false},
    };
    static const uint8_t expected_fbur[10] = {
        0x03u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x02u, 0x00u, 0x03u,
    };

    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        rfb_session storage;
        rfb_session *session = &storage;
        fake_io io;
        wire_test_session_init(session, &io,
                               RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
        session->has_wrap_key = true;
        memcpy(session->wrap_key, wire_test_wrap_key,
               sizeof session->wrap_key);
        session->wire_variants.initial_output = cases[i].variant;
        session->wire_variants.suppress_fbur = cases[i].suppress_fbur;
        uint8_t setup[APPLE_WIRE_SETUP_LEN];
        wire_test_make_setup(setup, APPLE_WIRE_TYPE_ENABLE,
                             APPLE_WIRE_SETUP_METHOD_AES_CBC);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&session->in, setup, sizeof setup),
                         RFB_OK);

        RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                         RFB_OK);
        const uint8_t *wire = fake_io_outbox_data(&io);
        const size_t wire_length = fake_io_outbox_len(&io);
        if (wire_length < APPLE_WIRE_MSG12_ACK_LEN) {
            RFB_FAIL("initial output omitted the record acknowledgement");
            wire_test_session_destroy(session, &io);
            continue;
        }
        RFB_CHECK_MEM_EQ(wire, apple_wire_msg12_ack,
                         APPLE_WIRE_MSG12_ACK_LEN);

        apple_record_layer mirror;
        apple_record_init(&mirror, wire_test_wrap_key);
        RFB_CHECK(apple_record_set_direction(&mirror, APPLE_DIR_DECRYPT,
                                             wire_test_content_key,
                                             wire_test_iv));
        size_t offset = APPLE_WIRE_MSG12_ACK_LEN;
        for (size_t message = 0u; message < cases[i].messages; message++) {
            uint8_t plaintext[32];
            size_t plaintext_length = 0u;
            const size_t total = wire_test_open_record(
                &mirror, wire + offset, wire_length - offset, plaintext,
                sizeof plaintext, &plaintext_length);
            const bool expect_msg14 =
                cases[i].messages == 2u &&
                (message == 0u ? cases[i].msg14_first
                               : !cases[i].msg14_first);
            if (expect_msg14) {
                RFB_CHECK_EQ_UINT(plaintext_length,
                                  APPLE_WIRE_MSG14_LEN);
                RFB_CHECK_MEM_EQ(plaintext, apple_wire_msg14,
                                 APPLE_WIRE_MSG14_LEN);
            } else {
                RFB_CHECK_EQ_UINT(plaintext_length,
                                  sizeof expected_fbur);
                RFB_CHECK_MEM_EQ(plaintext, expected_fbur,
                                 sizeof expected_fbur);
            }
            offset += total;
        }
        RFB_CHECK_EQ_UINT(offset, wire_length);
        apple_record_destroy(&mirror);
        wire_test_session_destroy(session, &io);
    }
}

RFB_TEST(rfb_session_wire,
         enable_apple_records__output_limits_keep_ack_and_record_state_exact)
{
    typedef struct output_failure_case {
        rfb_apple_rekey_variant rekey;
        rfb_apple_initial_output_variant initial_output;
    } output_failure_case;
    static const output_failure_case cases[] = {
        {RFB_APPLE_REKEY_ECHO, RFB_APPLE_INITIAL_OUTPUT_STANDARD},
        {RFB_APPLE_REKEY_FRESH, RFB_APPLE_INITIAL_OUTPUT_STANDARD},
        {RFB_APPLE_REKEY_NONE, RFB_APPLE_INITIAL_OUTPUT_FBUR_ONLY},
        {RFB_APPLE_REKEY_NONE,
         RFB_APPLE_INITIAL_OUTPUT_MSG14_THEN_FBUR},
        {RFB_APPLE_REKEY_NONE,
         RFB_APPLE_INITIAL_OUTPUT_FBUR_THEN_MSG14},
        {RFB_APPLE_REKEY_NONE, RFB_APPLE_INITIAL_OUTPUT_STANDARD},
    };

    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        rfb_session storage;
        rfb_session *session = &storage;
        fake_io io;
        wire_test_session_init(session, &io,
                               RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
        session->has_wrap_key = true;
        memcpy(session->wrap_key, wire_test_wrap_key,
               sizeof session->wrap_key);
        session->wire_variants.rekey = cases[i].rekey;
        session->wire_variants.initial_output = cases[i].initial_output;
        session->out.hard_limit = APPLE_WIRE_MSG12_ACK_LEN;
        uint8_t setup[APPLE_WIRE_SETUP_LEN];
        wire_test_make_setup(setup, APPLE_WIRE_TYPE_ENABLE,
                             APPLE_WIRE_SETUP_METHOD_AES_CBC);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&session->in, setup, sizeof setup),
                         RFB_OK);

        RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                         RFB_ERR_LIMIT);
        RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_LIMIT);
        RFB_CHECK(session->apple_records_active);
        RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->in), 0u);
        RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->out), 0u);
        RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io),
                          APPLE_WIRE_MSG12_ACK_LEN);
        RFB_CHECK_MEM_EQ(fake_io_outbox_data(&io), apple_wire_msg12_ack,
                         APPLE_WIRE_MSG12_ACK_LEN);
        RFB_CHECK_EQ_UINT(session->apple_rl.encrypt.sequence, 0u);
        wire_test_session_destroy(session, &io);
    }
}

RFB_TEST(rfb_session_wire, enable_apple_records__rekey_variants)
{
    for (int variant = (int)RFB_APPLE_REKEY_ECHO;
         variant <= (int)RFB_APPLE_REKEY_FRESH; variant++) {
        rfb_session storage;
        rfb_session *session = &storage;
        fake_io io;
        wire_test_session_init(session, &io,
                               RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
        session->has_wrap_key = true;
        memcpy(session->wrap_key, wire_test_wrap_key,
               sizeof session->wrap_key);
        session->wire_variants.rekey = (rfb_apple_rekey_variant)variant;
        uint8_t setup[APPLE_WIRE_SETUP_LEN];
        wire_test_make_setup(setup, APPLE_WIRE_TYPE_ENABLE,
                             APPLE_WIRE_SETUP_METHOD_AES_CBC);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&session->in, setup, sizeof setup),
                         RFB_OK);

        RFB_CHECK_EQ_INT(rfb_session_internal_enable_apple_records(session),
                         RFB_OK);
        const uint8_t *wire = fake_io_outbox_data(&io);
        const size_t wire_length = fake_io_outbox_len(&io);
        if (wire_length != 76u) {
            RFB_FAIL("rekey transaction has the wrong length");
            wire_test_session_destroy(session, &io);
            continue;
        }
        RFB_CHECK_MEM_EQ(wire, apple_wire_msg12_ack,
                         APPLE_WIRE_MSG12_ACK_LEN);
        RFB_CHECK_EQ_UINT(wire[8], 0u);
        RFB_CHECK_EQ_UINT(wire[9], 32u);

        uint8_t key[16];
        uint8_t iv[16];
        apple_record_layer mirror;
        if (variant == (int)RFB_APPLE_REKEY_ECHO) {
            RFB_CHECK_MEM_EQ(wire + 10u, setup + 20u, 32u);
            memcpy(key, wire_test_content_key, sizeof key);
            memcpy(iv, wire_test_iv, sizeof iv);
        } else {
            if (!rfb_crypto_aes128_ecb_decrypt(
                    wire_test_wrap_key, wire + 10u, key) ||
                !rfb_crypto_aes128_ecb_decrypt(
                    wire_test_wrap_key, wire + 26u, iv)) {
                RFB_FAIL("cannot unwrap fresh rekey transaction");
                wire_test_session_destroy(session, &io);
                continue;
            }
        }
        apple_record_init(&mirror, wire_test_wrap_key);
        RFB_CHECK(apple_record_set_direction(&mirror, APPLE_DIR_DECRYPT,
                                             key, iv));
        uint8_t plaintext[32];
        size_t plaintext_length = 0u;
        const size_t total = wire_test_open_record(
            &mirror, wire + 42u, wire_length - 42u, plaintext,
            sizeof plaintext, &plaintext_length);
        RFB_CHECK_EQ_UINT(total, 34u);
        RFB_CHECK_EQ_UINT(plaintext_length, APPLE_WIRE_MSG14_LEN);
        RFB_CHECK_MEM_EQ(plaintext, apple_wire_msg14,
                         APPLE_WIRE_MSG14_LEN);
        apple_record_destroy(&mirror);

        wire_test_session_destroy(session, &io);
    }
}

static void wire_test_record_session_init(rfb_session *session, fake_io *io,
                                          apple_record_layer *peer)
{
    wire_test_session_init(session, io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    rfb_buffer_init(&session->apple_plain, session->alloc,
                    RFB_LIMIT_FB_BYTES_POLICY);
    rfb_buffer_init(&session->apple_stage, session->alloc,
                    RFB_LIMIT_FB_BYTES_POLICY);
    apple_record_init(&session->apple_rl, wire_test_wrap_key);
    RFB_CHECK(apple_record_set_direction(&session->apple_rl,
                                         APPLE_DIR_DECRYPT,
                                         wire_test_content_key,
                                         wire_test_iv));
    RFB_CHECK(apple_record_set_direction(&session->apple_rl,
                                         APPLE_DIR_ENCRYPT,
                                         wire_test_content_key,
                                         wire_test_iv));
    session->apple_rl_inited = true;
    session->apple_records_active = true;

    apple_record_init(peer, wire_test_wrap_key);
    RFB_CHECK(apple_record_set_direction(peer, APPLE_DIR_ENCRYPT,
                                         wire_test_content_key,
                                         wire_test_iv));
}

static void wire_test_append_sealed(rfb_session *session,
                                    apple_record_layer *peer,
                                    const uint8_t *message,
                                    size_t message_length)
{
    uint8_t wire[512];
    size_t wire_length = 0u;
    RFB_CHECK_EQ_INT(apple_wire_record_seal(
                         peer, message, message_length, wire, sizeof wire,
                         &wire_length),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session->in, wire, wire_length),
                     RFB_OK);
}

RFB_TEST(rfb_session_wire, decrypt_apple_records__argument_and_frame_guards)
{
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_session_internal_decrypt_apple_records(NULL,
                                                                &progress),
                     RFB_ERR_INTERNAL);

    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    wire_test_session_init(session, &io,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    RFB_CHECK_EQ_INT(rfb_session_internal_decrypt_apple_records(session,
                                                                &progress),
                     RFB_ERR_INTERNAL);
    session->apple_records_active = true;
    RFB_CHECK_EQ_INT(rfb_session_internal_decrypt_apple_records(session,
                                                                NULL),
                     RFB_ERR_INTERNAL);
    static const uint8_t incomplete[] = {0x00u, 0x20u};
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session->in, incomplete,
                                       sizeof incomplete),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_internal_decrypt_apple_records(session,
                                                                &progress),
                     RFB_OK);
    RFB_CHECK(!progress);
    rfb_buffer_consume(&session->in, sizeof incomplete);
    static const uint8_t invalid[] = {0x00u, 0x01u};
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session->in, invalid,
                                       sizeof invalid),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_internal_decrypt_apple_records(session,
                                                                &progress),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_PROTOCOL);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire, decrypt_apple_records__demuxes_control_and_rfb)
{
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    apple_record_layer peer;
    wire_test_record_session_init(session, &io, &peer);

    wire_test_append_sealed(session, &peer, apple_wire_msg14,
                            APPLE_WIRE_MSG14_LEN);
    uint8_t typed_other[16];
    memset(typed_other, 0, sizeof typed_other);
    wire_test_put_u32be(typed_other, 1u);
    wire_test_put_u32be(typed_other + 12u, 0x0455u);
    wire_test_append_sealed(session, &peer, typed_other,
                            sizeof typed_other);

    uint8_t typed_tables[16u + 4u + 1u + 128u];
    memset(typed_tables, 0, sizeof typed_tables);
    wire_test_put_u32be(typed_tables, 1u);
    wire_test_put_u32be(typed_tables + 12u, 0x03f3u);
    wire_test_put_u32be(typed_tables + 16u, 129u);
    typed_tables[20] = 2u;
    for (size_t i = 0u; i < 128u; i++) {
        typed_tables[21u + i] = (uint8_t)(i + 1u);
    }
    wire_test_append_sealed(session, &peer, typed_tables,
                            sizeof typed_tables);

    static const uint8_t classic[] = {0x00u, 0x00u, 0x00u, 0x00u};
    wire_test_append_sealed(session, &peer, classic, sizeof classic);

    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_session_internal_decrypt_apple_records(session,
                                                                &progress),
                     RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK_EQ_UINT(session->apple_s2c_opened, 4u);
    RFB_CHECK(session->apple_have_last_s2c_ct);
    RFB_CHECK(session->mvs_have_qt);
    RFB_CHECK_MEM_EQ(session->mvs_qt0, typed_tables + 21u, 64u);
    RFB_CHECK_MEM_EQ(session->mvs_qt1, typed_tables + 85u, 64u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->apple_plain),
                      sizeof classic);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&session->apple_plain), classic,
                     sizeof classic);

    apple_record_destroy(&peer);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire, decrypt_apple_records__open_and_stage_failures)
{
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    apple_record_layer peer;
    wire_test_record_session_init(session, &io, &peer);
    wire_test_append_sealed(session, &peer, apple_wire_msg14,
                            APPLE_WIRE_MSG14_LEN);
    session->in.data[session->in.length - 1u] ^= 0x01u;
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_session_internal_decrypt_apple_records(session,
                                                                &progress),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_PROTOCOL);
    RFB_CHECK(!progress);
    RFB_CHECK(rfb_buffer_length(&session->in) > 0u);
    RFB_CHECK_EQ_UINT(session->apple_rl.decrypt.sequence, 1u);
    apple_record_destroy(&peer);
    wire_test_session_destroy(session, &io);

    wire_test_record_session_init(session, &io, &peer);
    rfb_buffer_destroy(&session->apple_stage);
    rfb_buffer_init(&session->apple_stage, session->alloc, 16u);
    wire_test_append_sealed(session, &peer, apple_wire_msg14,
                            APPLE_WIRE_MSG14_LEN);
    progress = false;
    RFB_CHECK_EQ_INT(rfb_session_internal_decrypt_apple_records(session,
                                                                &progress),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_LIMIT);
    RFB_CHECK(!progress);
    RFB_CHECK(rfb_buffer_length(&session->in) > 0u);
    RFB_CHECK_EQ_UINT(session->apple_rl.decrypt.sequence, 0u);
    apple_record_destroy(&peer);
    wire_test_session_destroy(session, &io);
}

RFB_TEST(rfb_session_wire,
         decrypt_apple_records__append_failures_leave_terminal_state_exact)
{
    static const uint8_t classic[] = {0x00u, 0x00u, 0x00u, 0x00u};
    rfb_allocator rejecting = {
        .alloc = wire_test_reject_alloc,
        .free = wire_test_reject_free,
        .user = NULL,
    };
    for (unsigned failure = 0u; failure < 2u; failure++) {
        rfb_session storage;
        rfb_session *session = &storage;
        fake_io io;
        apple_record_layer peer;
        wire_test_record_session_init(session, &io, &peer);
        if (failure == 0u) {
            session->apple_plain.hard_limit = 0u;
        } else {
            session->apple_plain.alloc = &rejecting;
        }
        wire_test_append_sealed(session, &peer, classic, sizeof classic);

        bool progress = false;
        const rfb_error expected =
            failure == 0u ? RFB_ERR_LIMIT : RFB_ERR_NOMEM;
        RFB_CHECK_EQ_INT(rfb_session_internal_decrypt_apple_records(
                             session, &progress),
                         expected);
        RFB_CHECK_EQ_INT(session->last_error, expected);
        RFB_CHECK(progress);
        RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->in), 0u);
        RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->apple_plain), 0u);
        RFB_CHECK_EQ_UINT(session->apple_s2c_opened, 1u);
        RFB_CHECK_EQ_UINT(session->apple_rl.decrypt.sequence, 1u);
        RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), 0u);

        apple_record_destroy(&peer);
        wire_test_session_destroy(session, &io);
    }
}

RFB_TEST(rfb_session_wire,
         decrypt_apple_records__deferred_limit_is_terminal_and_exact)
{
    static const uint8_t classic[] = {0x00u, 0x00u, 0x00u, 0x00u};
    for (unsigned output = 0u; output < 2u; output++) {
        rfb_session storage;
        rfb_session *session = &storage;
        fake_io io;
        apple_record_layer peer;
        wire_test_record_session_init(session, &io, &peer);
        session->out.hard_limit = 0u;
        session->wire_variants.deferred_output_after_s2c = 1u;
        session->wire_variants.deferred_output_is_msg14 = output != 0u;
        wire_test_append_sealed(session, &peer, classic, sizeof classic);

        bool progress = false;
        RFB_CHECK_EQ_INT(rfb_session_internal_decrypt_apple_records(
                             session, &progress),
                         RFB_ERR_LIMIT);
        RFB_CHECK_EQ_INT(session->last_error, RFB_ERR_LIMIT);
        RFB_CHECK(progress);
        RFB_CHECK(session->apple_deferred_seal_sent);
        RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->in), 0u);
        RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->apple_plain), 0u);
        RFB_CHECK_EQ_UINT(session->apple_s2c_opened, 1u);
        RFB_CHECK_EQ_UINT(session->apple_rl.decrypt.sequence, 1u);
        RFB_CHECK_EQ_UINT(session->apple_rl.encrypt.sequence, 0u);
        RFB_CHECK_EQ_UINT(fake_io_outbox_len(&io), 0u);

        apple_record_destroy(&peer);
        wire_test_session_destroy(session, &io);
    }
}

RFB_TEST(rfb_session_wire, decrypt_apple_records__deferred_output_variants)
{
    static const uint8_t classic[] = {0x00u, 0x00u, 0x00u, 0x00u};
    static const uint8_t expected_fbur[10] = {
        0x03u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x02u, 0x00u, 0x03u,
    };
    for (unsigned mode = 0u; mode < 2u; mode++) {
        rfb_session storage;
        rfb_session *session = &storage;
        fake_io io;
        apple_record_layer peer;
        wire_test_record_session_init(session, &io, &peer);
        session->wire_variants.deferred_output_after_s2c = 1u;
        session->wire_variants.deferred_output_is_msg14 = mode == 0u;
        session->wire_variants.deferred_iv_follows_s2c = mode == 0u;
        session->wire_variants.deferred_sequence_follows_s2c = mode == 0u;
        wire_test_append_sealed(session, &peer, classic, sizeof classic);

        bool progress = false;
        RFB_CHECK_EQ_INT(rfb_session_internal_decrypt_apple_records(
                             session, &progress),
                         RFB_OK);
        RFB_CHECK(progress);
        RFB_CHECK(session->apple_deferred_seal_sent);
        const uint8_t *wire = fake_io_outbox_data(&io);
        const size_t wire_length = fake_io_outbox_len(&io);
        RFB_CHECK(wire_length > 0u);

        apple_record_layer mirror;
        apple_record_init(&mirror, wire_test_wrap_key);
        const uint8_t *decrypt_iv =
            mode == 0u ? session->apple_last_s2c_ct : wire_test_iv;
        RFB_CHECK(apple_record_set_direction(&mirror, APPLE_DIR_DECRYPT,
                                             wire_test_content_key,
                                             decrypt_iv));
        if (mode == 0u) {
            mirror.decrypt.sequence = 1u;
        }
        uint8_t plaintext[32];
        size_t plaintext_length = 0u;
        const size_t total = wire_test_open_record(
            &mirror, wire, wire_length, plaintext, sizeof plaintext,
            &plaintext_length);
        RFB_CHECK_EQ_UINT(total, wire_length);
        if (mode == 0u) {
            RFB_CHECK_EQ_UINT(plaintext_length, APPLE_WIRE_MSG14_LEN);
            RFB_CHECK_MEM_EQ(plaintext, apple_wire_msg14,
                             APPLE_WIRE_MSG14_LEN);
        } else {
            RFB_CHECK_EQ_UINT(plaintext_length, sizeof expected_fbur);
            RFB_CHECK_MEM_EQ(plaintext, expected_fbur,
                             sizeof expected_fbur);
        }
        apple_record_destroy(&mirror);
        apple_record_destroy(&peer);
        wire_test_session_destroy(session, &io);
    }
}

RFB_TEST(rfb_session_wire,
         decrypt_apple_records__deferred_threshold_and_bad_tables)
{
    static const uint8_t classic[] = {0x00u, 0x00u, 0x00u, 0x00u};
    rfb_session storage;
    rfb_session *session = &storage;
    fake_io io;
    apple_record_layer peer;
    wire_test_record_session_init(session, &io, &peer);
    session->wire_variants.deferred_output_after_s2c = 2u;
    session->wire_variants.deferred_output_is_msg14 = true;
    wire_test_append_sealed(session, &peer, classic, sizeof classic);
    wire_test_append_sealed(session, &peer, classic, sizeof classic);
    wire_test_append_sealed(session, &peer, classic, sizeof classic);

    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_session_internal_decrypt_apple_records(session,
                                                                &progress),
                     RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK(session->apple_deferred_seal_sent);
    RFB_CHECK_EQ_UINT(session->apple_s2c_opened, 3u);
    RFB_CHECK_EQ_UINT(session->apple_rl.encrypt.sequence, 1u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->apple_plain),
                      3u * sizeof classic);
    apple_record_destroy(&peer);
    wire_test_session_destroy(session, &io);

    wire_test_record_session_init(session, &io, &peer);
    uint8_t typed_empty[16] = {0u};
    wire_test_put_u32be(typed_empty, 1u);
    wire_test_put_u32be(typed_empty + 12u, 0x03f3u);
    wire_test_append_sealed(session, &peer, typed_empty, sizeof typed_empty);

    uint8_t typed_no_qt0[21] = {0u};
    wire_test_put_u32be(typed_no_qt0, 1u);
    wire_test_put_u32be(typed_no_qt0 + 12u, 0x03f3u);
    wire_test_put_u32be(typed_no_qt0 + 16u, 1u);
    typed_no_qt0[20] = 1u;
    wire_test_append_sealed(session, &peer, typed_no_qt0,
                            sizeof typed_no_qt0);

    uint8_t typed_no_qt1[85] = {0u};
    wire_test_put_u32be(typed_no_qt1, 1u);
    wire_test_put_u32be(typed_no_qt1 + 12u, 0x03f3u);
    wire_test_put_u32be(typed_no_qt1 + 16u, 65u);
    typed_no_qt1[20] = 1u;
    wire_test_append_sealed(session, &peer, typed_no_qt1,
                            sizeof typed_no_qt1);
    wire_test_append_sealed(session, &peer, classic, sizeof classic);

    progress = false;
    RFB_CHECK_EQ_INT(rfb_session_internal_decrypt_apple_records(session,
                                                                &progress),
                     RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK(!session->mvs_have_qt);
    RFB_CHECK_EQ_UINT(session->apple_s2c_opened, 4u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&session->apple_plain),
                      sizeof classic);
    apple_record_destroy(&peer);
    wire_test_session_destroy(session, &io);
}
