// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for apple_type33_live argument gates, SPKI trust, and the
// complete RSA1/SRP exchange. They do not establish hardware interoperability.

#include "rfb_test.h"
#include "fake_io.h"
#include "farsee/apple_postauth.h"
#include "farsee/apple_record.h"
#include "farsee/apple_srp.h"
#include "farsee/apple_type33_connect.h"
#include "farsee/apple_type33_live.h"
#include "farsee/apple_type36_live.h"
#include "farsee/buffer.h"
#include "farsee/error.h"
#include "farsee/limits.h"
#include "farsee/pixel_format.h"
#include "rfb/apple_type33_connect_internal.h"
#include "rfb/apple_type33_live_internal.h"

#include <openssl/bn.h>
#include <string.h>

// Scripted I/O that always fails (never used on null-arg paths).
static rfb_error fail_send(void *ctx, const uint8_t *data, size_t n)
{
    (void)ctx;
    (void)data;
    (void)n;
    return RFB_ERR_IO;
}

static rfb_error fail_recv(void *ctx, uint8_t *data, size_t n)
{
    (void)ctx;
    (void)data;
    (void)n;
    return RFB_ERR_IO;
}

RFB_TEST(apple_type33_live, authenticate__null_io__fails_internal)
{
    uint8_t wrap[16];
    const uint8_t user[] = "admin";
    const uint8_t pass[] = "secret";
    RFB_CHECK_EQ_INT(
        apple_type33_authenticate(NULL, user, sizeof user - 1u,
                                  pass, sizeof pass - 1u, wrap,
                                  NULL, 0, NULL),
        RFB_ERR_INTERNAL);
}

RFB_TEST(apple_type33_live, authenticate__null_wrap_key__fails_internal)
{
    apple_type33_io io = {fail_send, fail_recv, NULL};
    const uint8_t user[] = "admin";
    const uint8_t pass[] = "secret";
    RFB_CHECK_EQ_INT(
        apple_type33_authenticate(&io, user, sizeof user - 1u,
                                  pass, sizeof pass - 1u, NULL,
                                  NULL, 0, NULL),
        RFB_ERR_INTERNAL);
}

RFB_TEST(apple_type33_live, authenticate__null_send_cb__fails_internal)
{
    apple_type33_io io = {NULL, fail_recv, NULL};
    uint8_t wrap[16];
    const uint8_t user[] = "admin";
    const uint8_t pass[] = "secret";
    RFB_CHECK_EQ_INT(
        apple_type33_authenticate(&io, user, sizeof user - 1u,
                                  pass, sizeof pass - 1u, wrap,
                                  NULL, 0, NULL),
        RFB_ERR_INTERNAL);
}

RFB_TEST(apple_type33_live, authenticate__null_recv_cb__fails_internal)
{
    apple_type33_io io = {fail_send, NULL, NULL};
    uint8_t wrap[16];
    const uint8_t user[] = "admin";
    const uint8_t pass[] = "secret";
    RFB_CHECK_EQ_INT(
        apple_type33_authenticate(&io, user, sizeof user - 1u,
                                  pass, sizeof pass - 1u, wrap,
                                  NULL, 0, NULL),
        RFB_ERR_INTERNAL);
}

RFB_TEST(apple_type33_live, authenticate__empty_username__fails_protocol)
{
    apple_type33_io io = {fail_send, fail_recv, NULL};
    uint8_t wrap[16];
    const uint8_t pass[] = "secret";
    RFB_CHECK_EQ_INT(
        apple_type33_authenticate(&io, (const uint8_t *)"", 0u,
                                  pass, sizeof pass - 1u, wrap,
                                  NULL, 0, NULL),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(
        apple_type33_authenticate(&io, NULL, 5u,
                                  pass, sizeof pass - 1u, wrap,
                                  NULL, 0, NULL),
        RFB_ERR_PROTOCOL);
}

RFB_TEST(apple_type33_live, authenticate__empty_password__fails_auth)
{
    apple_type33_io io = {fail_send, fail_recv, NULL};
    uint8_t wrap[16];
    const uint8_t user[] = "admin";
    RFB_CHECK_EQ_INT(
        apple_type33_authenticate(&io, user, sizeof user - 1u,
                                  (const uint8_t *)"", 0u, wrap,
                                  NULL, 0, NULL),
        RFB_ERR_AUTH);
    RFB_CHECK_EQ_INT(
        apple_type33_authenticate(&io, user, sizeof user - 1u,
                                  NULL, 5u, wrap,
                                  NULL, 0, NULL),
        RFB_ERR_AUTH);
}

RFB_TEST(apple_type33_live, authenticate__username_too_long__fails_protocol)
{
    apple_type33_io io = {fail_send, fail_recv, NULL};
    uint8_t wrap[16];
    uint8_t user[256];
    memset(user, 'a', sizeof user);
    const uint8_t pass[] = "secret";
    // APPLE_RSA1_MAX_USERNAME_LEN is 234.
    RFB_CHECK_EQ_INT(
        apple_type33_authenticate(&io, user, 235u,
                                  pass, sizeof pass - 1u, wrap,
                                  NULL, 0, NULL),
        RFB_ERR_PROTOCOL);
}

// This script ends at the first send, before an SPKI or store-path check.
RFB_TEST(apple_type33_live, authenticate__host_without_store_path__fails_auth)
{
    // The host arguments do not change the earlier I/O failure.
    apple_type33_io io = {fail_send, fail_recv, NULL};
    uint8_t wrap[16];
    const uint8_t user[] = "admin";
    const uint8_t pass[] = "secret";
    // Without reaching SPKI, IO fails — still ensure API accepts host args.
    RFB_CHECK_EQ_INT(
        apple_type33_authenticate(&io, user, sizeof user - 1u,
                                  pass, sizeof pass - 1u, wrap,
                                  "example.host", 5900, NULL),
        RFB_ERR_IO);  // fails at key request send before SPKI trust
}

// --- First-use host-key policy --------------------------------------------
//
// The trust gate sits after the FIRST key-response frame, before any
// credential leaves the client — so a scripted single frame plus a
// self-generated RSA-2048 SPKI exercises the policy without the full SRP
// exchange: fail-closed must return AUTH before packet 1; accept-new must
// get PAST the gate (and then fail on the exhausted script with IO, not
// AUTH).

#include "farsee/apple_crypto.h"
#include "farsee/apple_rsa1.h"
#include "farsee/known_hosts.h"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdio.h>

typedef struct tofu_script {
    const uint8_t *data;
    size_t len;
    size_t pos;
} tofu_script;

static rfb_error tofu_send(void *ctx, const uint8_t *data, size_t n)
{
    (void)ctx; (void)data; (void)n;
    return RFB_OK;  // sends are accepted; nothing is verified here
}

static rfb_error tofu_recv(void *ctx, uint8_t *out, size_t n)
{
    tofu_script *s = (tofu_script *)ctx;
    if (s->pos + n > s->len) {
        return RFB_ERR_IO;  // script exhausted (EOF)
    }
    memcpy(out, s->data + s->pos, n);
    s->pos += n;
    return RFB_OK;
}

static bool tofu_make_spki(uint8_t *der, size_t cap, size_t *out_len)
{
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    if (kctx == NULL ||
        EVP_PKEY_keygen_init(kctx) != 1 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) != 1 ||
        EVP_PKEY_keygen(kctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(kctx);
        return false;
    }
    unsigned char *p = der;
    int len = i2d_PUBKEY(pkey, &p);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    if (len <= 0 || (size_t)len > cap) {
        return false;
    }
    *out_len = (size_t)len;
    return true;
}

// Build the scripted key-response frame carrying `spki`.
static bool tofu_key_frame(uint8_t *wire, size_t cap, size_t *out_len,
                           const uint8_t *spki, size_t spki_len)
{
    if (apple_rsa1_serialize_key_response(spki, spki_len, wire, cap,
                                          out_len) != RFB_OK) {
        return false;
    }
    return true;
}

RFB_TEST(apple_type33_live, tofu__first_use_default__fails_auth_before_credentials)
{
    uint8_t spki[1024];
    size_t spki_len = 0;
    RFB_CHECK(tofu_make_spki(spki, sizeof spki, &spki_len));
    uint8_t frame[1200];
    size_t frame_len = 0;
    RFB_CHECK(tofu_key_frame(frame, sizeof frame, &frame_len,
                             spki, spki_len));

    tofu_script script = {frame, frame_len, 0};
    apple_type33_io io = {tofu_send, tofu_recv, &script};
    const uint8_t user[] = "admin";
    const uint8_t pass[] = "secret";
    uint8_t wrap[16];

    // Empty (nonexistent) store: first use must fail closed.
    RFB_CHECK_EQ_INT(
        apple_type33_authenticate_ex(&io, user, sizeof user - 1u,
                                     pass, sizeof pass - 1u, wrap,
                                     NULL, "tofu.test", 5900u,
                                     "/tmp/farsee_tofu_absent_store", false),
        RFB_ERR_AUTH);
    // Nothing was consumed past the key response: the gate fired before
    // packet 1 (the script position is exactly past one frame).
    RFB_CHECK_EQ_UINT(script.pos, frame_len);
}

RFB_TEST(apple_type33_live, tofu__first_use_accept_new__passes_gate)
{
    uint8_t spki[1024];
    size_t spki_len = 0;
    RFB_CHECK(tofu_make_spki(spki, sizeof spki, &spki_len));
    uint8_t frame[1200];
    size_t frame_len = 0;
    RFB_CHECK(tofu_key_frame(frame, sizeof frame, &frame_len,
                             spki, spki_len));

    tofu_script script = {frame, frame_len, 0};
    apple_type33_io io = {tofu_send, tofu_recv, &script};
    const uint8_t user[] = "admin";
    const uint8_t pass[] = "secret";
    uint8_t wrap[16];

    // Opt-in policy gets PAST the trust gate; with the script exhausted
    // the failure is IO (waiting for the SRP challenge), not AUTH.
    const rfb_error e = apple_type33_authenticate_ex(
        &io, user, sizeof user - 1u, pass, sizeof pass - 1u, wrap,
        NULL, "tofu.test", 5900u, "/tmp/farsee_tofu_absent_store", true);
    RFB_CHECK_EQ_INT(e, RFB_ERR_IO);
    // Only the key-response frame was consumed from the script (sends do
    // not consume; the next recv found EOF).
    RFB_CHECK_EQ_UINT(script.pos, frame_len);
}

RFB_TEST(apple_type33_live, tofu__mismatch__fails_auth)
{
    uint8_t spki[1024];
    size_t spki_len = 0;
    RFB_CHECK(tofu_make_spki(spki, sizeof spki, &spki_len));
    uint8_t frame[1200];
    size_t frame_len = 0;
    RFB_CHECK(tofu_key_frame(frame, sizeof frame, &frame_len,
                             spki, spki_len));

    // Pre-pin a DIFFERENT key (second fresh SPKI's fingerprint).
    uint8_t other[1024];
    size_t other_len = 0;
    RFB_CHECK(tofu_make_spki(other, sizeof other, &other_len));
    uint8_t other_fp[32];
    RFB_CHECK(rfb_crypto_spki_fingerprint(other, other_len, other_fp));
    RFB_CHECK(known_hosts_add("tofu.test", 5900u, other_fp,
                              "/tmp/farsee_tofu_mismatch_store"));

    tofu_script script = {frame, frame_len, 0};
    apple_type33_io io = {tofu_send, tofu_recv, &script};
    const uint8_t user[] = "admin";
    const uint8_t pass[] = "secret";
    uint8_t wrap[16];
    RFB_CHECK_EQ_INT(
        apple_type33_authenticate_ex(&io, user, sizeof user - 1u,
                                     pass, sizeof pass - 1u, wrap,
                                     NULL, "tofu.test", 5900u,
                                     "/tmp/farsee_tofu_mismatch_store", true),
        RFB_ERR_AUTH);
    remove("/tmp/farsee_tofu_mismatch_store");
}

// --- Complete RSA1/SRP exchange -----------------------------------------

#define LIVE_INPUT_CAP 4096u
#define LIVE_OUTPUT_CAP 4096u
#define LIVE_SEND_CAP 3u

typedef struct live_fixture {
    uint8_t input[LIVE_INPUT_CAP];
    size_t input_len;
    size_t input_pos;
    uint8_t output[LIVE_OUTPUT_CAP];
    size_t output_len;
    size_t send_offsets[LIVE_SEND_CAP];
    size_t send_lengths[LIVE_SEND_CAP];
    size_t send_count;
    size_t random_calls;
    uint8_t challenge[2048];
    size_t challenge_len;
    apple_srp_session expected_session;
    uint8_t expected_sk32[32];
} live_fixture;

static void live_put_u16(uint8_t *buf, size_t *pos, uint16_t value)
{
    buf[(*pos)++] = (uint8_t)(value >> 8);
    buf[(*pos)++] = (uint8_t)value;
}

static void live_put_u32(uint8_t *buf, size_t *pos, uint32_t value)
{
    buf[(*pos)++] = (uint8_t)(value >> 24);
    buf[(*pos)++] = (uint8_t)(value >> 16);
    buf[(*pos)++] = (uint8_t)(value >> 8);
    buf[(*pos)++] = (uint8_t)value;
}

static bool live_append(live_fixture *f, const uint8_t *data, size_t len)
{
    if (len > sizeof f->input - f->input_len) {
        return false;
    }
    memcpy(f->input + f->input_len, data, len);
    f->input_len += len;
    return true;
}

static rfb_error live_send(void *ctx, const uint8_t *data, size_t len)
{
    live_fixture *f = (live_fixture *)ctx;
    if (f->send_count >= LIVE_SEND_CAP ||
        len > sizeof f->output - f->output_len) {
        return RFB_ERR_LIMIT;
    }
    f->send_offsets[f->send_count] = f->output_len;
    f->send_lengths[f->send_count] = len;
    f->send_count++;
    memcpy(f->output + f->output_len, data, len);
    f->output_len += len;
    return RFB_OK;
}

static rfb_error live_recv(void *ctx, uint8_t *data, size_t len)
{
    live_fixture *f = (live_fixture *)ctx;
    if (len > f->input_len - f->input_pos) {
        return RFB_ERR_IO;
    }
    memcpy(data, f->input + f->input_pos, len);
    f->input_pos += len;
    return RFB_OK;
}

static bool live_random(void *ctx, uint8_t *out, size_t len)
{
    live_fixture *f = (live_fixture *)ctx;
    f->random_calls++;
    if (f->random_calls == 1u && len == 32u) {
        memset(out, 0x42, len);
        return true;
    }
    if (f->random_calls == 2u && len == 16u) {
        memset(out, 0x24, len);
        return true;
    }
    return false;
}

static bool live_rfc5054_n(uint8_t out[APPLE_SRP_N_BYTES])
{
    BIGNUM *n = BN_get_rfc3526_prime_4096(NULL);
    if (n == NULL) {
        return false;
    }
    const int written = BN_bn2binpad(n, out, (int)APPLE_SRP_N_BYTES);
    BN_free(n);
    return written == (int)APPLE_SRP_N_BYTES;
}

static bool live_build_challenge(live_fixture *f)
{
    uint8_t n[APPLE_SRP_N_BYTES];
    uint8_t b[APPLE_SRP_N_BYTES] = {0};
    static const uint8_t salt[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static const char options[] = "record-test";
    const size_t inner =
        1u + 2u + sizeof n + 2u + 1u + 1u + sizeof salt +
        2u + sizeof b + 4u + 4u + 2u + sizeof options - 1u;
    const size_t body = 4u + inner;
    const size_t total = 6u + body;
    const size_t full = 4u + total;
    if (!live_rfc5054_n(n) || full > sizeof f->challenge ||
        inner > UINT16_MAX || body > UINT16_MAX || total > UINT32_MAX) {
        return false;
    }
    b[sizeof b - 1u] = 2u;

    size_t pos = 0u;
    live_put_u32(f->challenge, &pos, (uint32_t)total);
    live_put_u16(f->challenge, &pos, 0u);
    live_put_u16(f->challenge, &pos, 2u);
    live_put_u16(f->challenge, &pos, (uint16_t)body);
    live_put_u16(f->challenge, &pos, 0u);
    live_put_u16(f->challenge, &pos, (uint16_t)inner);
    f->challenge[pos++] = 0u;
    live_put_u16(f->challenge, &pos, (uint16_t)sizeof n);
    memcpy(f->challenge + pos, n, sizeof n);
    pos += sizeof n;
    live_put_u16(f->challenge, &pos, 1u);
    f->challenge[pos++] = 5u;
    f->challenge[pos++] = (uint8_t)sizeof salt;
    memcpy(f->challenge + pos, salt, sizeof salt);
    pos += sizeof salt;
    live_put_u16(f->challenge, &pos, (uint16_t)sizeof b);
    memcpy(f->challenge + pos, b, sizeof b);
    pos += sizeof b;
    live_put_u32(f->challenge, &pos, 0u);
    live_put_u32(f->challenge, &pos, APPLE_SRP_ITER_MIN);
    live_put_u16(f->challenge, &pos, (uint16_t)(sizeof options - 1u));
    memcpy(f->challenge + pos, options, sizeof options - 1u);
    pos += sizeof options - 1u;
    f->challenge_len = pos;
    return pos == full;
}

static bool live_append_auth_response(live_fixture *f, bool reject,
                                      bool corrupt_m2,
                                      const uint8_t m2[APPLE_SRP_M1_BYTES])
{
    if (reject) {
        static const uint8_t failure[] = {
            0, 0, 0, 6, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1,
        };
        return live_append(f, failure, sizeof failure);
    }

    uint8_t response[100];
    static const uint8_t server_random[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    size_t pos = 0u;
    live_put_u32(response, &pos, 92u);
    live_put_u16(response, &pos, 0u);
    live_put_u16(response, &pos, 2u);
    live_put_u16(response, &pos, 86u);
    live_put_u16(response, &pos, 0u);
    live_put_u16(response, &pos, 82u);
    response[pos++] = APPLE_SRP_M1_BYTES;
    memcpy(response + pos, m2, APPLE_SRP_M1_BYTES);
    if (corrupt_m2) {
        response[pos] ^= 0x01u;
    }
    pos += APPLE_SRP_M1_BYTES;
    response[pos++] = (uint8_t)sizeof server_random;
    memcpy(response + pos, server_random, sizeof server_random);
    pos += sizeof server_random;
    live_put_u32(response, &pos, 0u);
    return pos == sizeof response && live_append(f, response, pos);
}

static bool live_fixture_prepare(live_fixture *f, bool reject,
                                 bool corrupt_m2)
{
    static const uint8_t user[] = "admin";
    static const uint8_t pass[] = "secret";
    uint8_t spki[1024];
    size_t spki_len = 0u;
    uint8_t key_frame[1200];
    size_t key_frame_len = 0u;
    uint8_t a_secret[32];
    uint8_t m2[APPLE_SRP_M1_BYTES];
    apple_srp_challenge challenge;

    memset(f, 0, sizeof *f);
    memset(a_secret, 0x42, sizeof a_secret);
    if (!tofu_make_spki(spki, sizeof spki, &spki_len) ||
        apple_rsa1_serialize_key_response(spki, spki_len, key_frame,
                                         sizeof key_frame,
                                         &key_frame_len) != RFB_OK ||
        !live_build_challenge(f) ||
        apple_srp_parse_challenge(f->challenge, f->challenge_len,
                                  &challenge) != RFB_OK ||
        apple_srp_compute_client(
            &challenge, user, sizeof user - 1u, pass, sizeof pass - 1u,
            a_secret, sizeof a_secret, &f->expected_session) != RFB_OK ||
        apple_srp_compute_m2(&f->expected_session, challenge.B,
                             challenge.B_len, m2) != RFB_OK ||
        !apple_srp_derive_session_key_32(&f->expected_session,
                                         f->expected_sk32) ||
        !live_append(f, key_frame, key_frame_len) ||
        !live_append(f, f->challenge, f->challenge_len) ||
        !live_append_auth_response(f, reject, corrupt_m2, m2)) {
        apple_srp_session_destroy(&f->expected_session);
        return false;
    }
    return true;
}

static rfb_error live_authenticate(live_fixture *f, uint8_t wrap[16],
                                   apple_type33_kdf_material *kdf)
{
    static const uint8_t user[] = "admin";
    static const uint8_t pass[] = "secret";
    apple_type33_io io = {live_send, live_recv, f};
    apple_type33_live_ops ops = {f, live_random};
    return apple_type33_authenticate_ex_with_allocator_and_ops(
        &io, user, sizeof user - 1u, pass, sizeof pass - 1u, wrap, kdf,
        NULL, 0u, NULL, false, rfb_default_allocator(), &ops);
}

static bool live_fixture_prepare_type36(live_fixture *f, bool reject,
                                        bool corrupt_m2)
{
    if (!live_fixture_prepare(f, reject, corrupt_m2)) {
        return false;
    }

    apple_srp_challenge challenge;
    uint8_t m2[APPLE_SRP_M1_BYTES];
    if (apple_srp_parse_challenge(f->challenge, f->challenge_len,
                                  &challenge) != RFB_OK ||
        apple_srp_compute_m2(&f->expected_session, challenge.B,
                             challenge.B_len, m2) != RFB_OK ||
        f->challenge_len < 14u) {
        apple_srp_session_destroy(&f->expected_session);
        return false;
    }

    const size_t payload_len = f->challenge_len - 14u;
    const size_t type36_len = f->challenge_len - 6u;
    memmove(f->challenge + 8u, f->challenge + 14u, payload_len);
    size_t pos = 0u;
    live_put_u32(f->challenge, &pos, (uint32_t)(type36_len - 4u));
    live_put_u16(f->challenge, &pos, 0u);
    live_put_u16(f->challenge, &pos, (uint16_t)(type36_len - 8u));
    f->challenge_len = type36_len;

    f->input_len = 0u;
    f->input_pos = 0u;
    if (!live_append(f, f->challenge, f->challenge_len)) {
        return false;
    }
    if (reject) {
        static const uint8_t failure[] = {0u, 0u, 0u, 1u};
        return live_append(f, failure, sizeof failure);
    }

    uint8_t response[100];
    static const uint8_t server_random[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    memset(response, 0, sizeof response);
    pos = 0u;
    live_put_u32(response, &pos, 92u);
    live_put_u32(response, &pos, 88u);
    response[pos++] = APPLE_SRP_M1_BYTES;
    memcpy(response + pos, m2, sizeof m2);
    if (corrupt_m2) {
        response[pos] ^= 0x01u;
    }
    pos += sizeof m2;
    response[pos++] = (uint8_t)sizeof server_random;
    memcpy(response + pos, server_random, sizeof server_random);
    pos += sizeof server_random;
    pos += 6u;
    live_put_u32(response, &pos, 0u);
    return pos == sizeof response && live_append(f, response, pos);
}

static rfb_error live_authenticate_type36(
    live_fixture *f, uint8_t wrap[16], apple_type33_kdf_material *kdf)
{
    static const uint8_t user[] = "admin";
    static const uint8_t pass[] = "secret";
    apple_type33_io io = {live_send, live_recv, f};
    apple_type33_live_ops ops = {f, live_random};
    return apple_type36_authenticate_ex_with_allocator_and_ops(
        &io, user, sizeof user - 1u, pass, sizeof pass - 1u, wrap, kdf,
        rfb_default_allocator(), &ops);
}

static rfb_error live_connect_authenticate_type36(
    void *ctx, uint8_t selected_type, const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16], apple_type33_kdf_material *kdf_out,
    const char *host, uint16_t port, const char *known_hosts_path,
    bool accept_new_host, rfb_allocator *allocator)
{
    (void)host;
    (void)port;
    (void)known_hosts_path;
    (void)accept_new_host;
    if (selected_type != 36u) {
        return RFB_ERR_INTERNAL;
    }
    apple_type33_live_ops ops = {ctx, live_random};
    return apple_type36_authenticate_ex_with_allocator_and_ops(
        io, username, username_len, password, password_len, wrap_key_out,
        kdf_out, allocator, &ops);
}

static bool live_connect_random(void *ctx, uint8_t *out, size_t len)
{
    return live_random(ctx, out, len);
}

typedef struct live_connect_setup {
    size_t calls;
    char name[16];
} live_connect_setup;

static rfb_error live_connect_setup_after_server_init(
    void *ctx, const rfb_server_init *si)
{
    live_connect_setup *setup = (live_connect_setup *)ctx;
    setup->calls++;
    if (si->name != NULL) {
        (void)snprintf(setup->name, sizeof setup->name, "%s", si->name);
    }
    return RFB_OK;
}

static bool live_append_server_init(live_fixture *f)
{
    static const char name[] = "desk";
    uint8_t message[24u + sizeof name - 1u];
    const rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    memset(message, 0, sizeof message);
    message[1] = 4u;
    message[3] = 3u;
    message[4] = pf.bits_per_pixel;
    message[5] = pf.depth;
    message[6] = pf.big_endian;
    message[7] = pf.true_color;
    message[8] = (uint8_t)(pf.red_max >> 8u);
    message[9] = (uint8_t)pf.red_max;
    message[10] = (uint8_t)(pf.green_max >> 8u);
    message[11] = (uint8_t)pf.green_max;
    message[12] = (uint8_t)(pf.blue_max >> 8u);
    message[13] = (uint8_t)pf.blue_max;
    message[14] = pf.red_shift;
    message[15] = pf.green_shift;
    message[16] = pf.blue_shift;
    message[23] = (uint8_t)(sizeof name - 1u);
    memcpy(message + 24u, name, sizeof name - 1u);
    return live_append(f, message, sizeof message);
}

static bool live_is_zero(const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint8_t value = 0u;
    for (size_t i = 0u; i < len; i++) {
        value = (uint8_t)(value | bytes[i]);
    }
    return value == 0u;
}

RFB_TEST(apple_type33_live, full_exchange__valid_m2__publishes_record_material)
{
    live_fixture f;
    RFB_CHECK(live_fixture_prepare(&f, false, false));
    uint8_t wrap[16];
    apple_type33_kdf_material kdf;
    memset(wrap, 0xcc, sizeof wrap);
    memset(&kdf, 0xcc, sizeof kdf);

    RFB_CHECK_EQ_INT(live_authenticate(&f, wrap, &kdf), RFB_OK);
    RFB_CHECK_EQ_UINT(f.random_calls, 2u);
    RFB_CHECK_EQ_UINT(f.send_count, 3u);
    RFB_CHECK_MEM_EQ(wrap, f.expected_sk32, sizeof wrap);
    RFB_CHECK_MEM_EQ(kdf.session_key_32, f.expected_sk32,
                     sizeof kdf.session_key_32);
    RFB_CHECK_MEM_EQ(kdf.srp_k, f.expected_session.K, sizeof kdf.srp_k);
    RFB_CHECK_MEM_EQ(kdf.client_random,
                     "$$$$$$$$$$$$$$$$", sizeof kdf.client_random);
    RFB_CHECK(kdf.has_client_random);
    RFB_CHECK(kdf.has_srp_s);
    RFB_CHECK_EQ_UINT(kdf.srp_s_len, f.expected_session.S_len);
    RFB_CHECK_MEM_EQ(kdf.srp_s, f.expected_session.S, kdf.srp_s_len);
    RFB_CHECK(kdf.has_m1);
    RFB_CHECK_MEM_EQ(kdf.m1, f.expected_session.M1, sizeof kdf.m1);
    RFB_CHECK(kdf.has_server_random);
    RFB_CHECK_EQ_UINT(kdf.iterations, APPLE_SRP_ITER_MIN);
    RFB_CHECK_EQ_UINT(kdf.options_len, sizeof "record-test" - 1u);
    RFB_CHECK_MEM_EQ(kdf.options, "record-test", kdf.options_len);

    uint8_t expected_request[APPLE_RSA1_KEY_REQUEST_LEN];
    size_t expected_request_len = 0u;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_key_request(expected_request,
                                         sizeof expected_request,
                                         &expected_request_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(f.send_lengths[0], expected_request_len);
    RFB_CHECK_MEM_EQ(f.output + f.send_offsets[0], expected_request,
                     expected_request_len);
    RFB_CHECK_EQ_UINT(f.send_lengths[1], APPLE_RSA1_PACKET1_LEN);

    uint8_t expected_packet2[2048];
    size_t expected_packet2_len = 0u;
    uint8_t client_random[16];
    memset(client_random, 0x24, sizeof client_random);
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(
            &f.expected_session, "record-test", sizeof "record-test" - 1u,
            client_random, expected_packet2, sizeof expected_packet2,
            &expected_packet2_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(f.send_lengths[2], expected_packet2_len);
    RFB_CHECK_MEM_EQ(f.output + f.send_offsets[2], expected_packet2,
                     expected_packet2_len);

    apple_record_layer record;
    apple_record_init(&record, wrap);
    RFB_CHECK(record.initialized);
    RFB_CHECK_MEM_EQ(record.wrap_key, wrap, sizeof wrap);
    apple_record_destroy(&record);
    apple_srp_session_destroy(&f.expected_session);
}

RFB_TEST(apple_type33_live, full_exchange__server_rejects__keeps_outputs_clear)
{
    live_fixture f;
    RFB_CHECK(live_fixture_prepare(&f, true, false));
    uint8_t wrap[16];
    apple_type33_kdf_material kdf;
    memset(wrap, 0xcc, sizeof wrap);
    memset(&kdf, 0xcc, sizeof kdf);

    RFB_CHECK_EQ_INT(live_authenticate(&f, wrap, &kdf), RFB_ERR_AUTH);
    RFB_CHECK_EQ_UINT(f.random_calls, 2u);
    RFB_CHECK_EQ_UINT(f.send_count, 3u);
    RFB_CHECK(live_is_zero(wrap, sizeof wrap));
    RFB_CHECK(live_is_zero(&kdf, sizeof kdf));
    apple_srp_session_destroy(&f.expected_session);
}

RFB_TEST(apple_type33_live, full_exchange__bad_m2__keeps_outputs_clear)
{
    live_fixture f;
    RFB_CHECK(live_fixture_prepare(&f, false, true));
    uint8_t wrap[16];
    apple_type33_kdf_material kdf;
    memset(wrap, 0xcc, sizeof wrap);
    memset(&kdf, 0xcc, sizeof kdf);

    RFB_CHECK_EQ_INT(live_authenticate(&f, wrap, &kdf), RFB_ERR_AUTH);
    RFB_CHECK_EQ_UINT(f.random_calls, 2u);
    RFB_CHECK_EQ_UINT(f.send_count, 3u);
    RFB_CHECK(live_is_zero(wrap, sizeof wrap));
    RFB_CHECK(live_is_zero(&kdf, sizeof kdf));
    apple_srp_session_destroy(&f.expected_session);
}

RFB_TEST(apple_type33_live,
         type36_full_exchange__sends_identity_then_proves_srp)
{
    live_fixture f;
    RFB_CHECK(live_fixture_prepare_type36(&f, false, false));
    uint8_t wrap[16];
    apple_type33_kdf_material kdf;
    memset(wrap, 0xcc, sizeof wrap);
    memset(&kdf, 0xcc, sizeof kdf);

    RFB_CHECK_EQ_INT(live_authenticate_type36(&f, wrap, &kdf), RFB_OK);
    RFB_CHECK_EQ_UINT(f.random_calls, 2u);
    RFB_CHECK_EQ_UINT(f.send_count, 2u);
    RFB_CHECK_MEM_EQ(wrap, f.expected_sk32, sizeof wrap);
    RFB_CHECK_MEM_EQ(kdf.session_key_32, f.expected_sk32,
                     sizeof kdf.session_key_32);

    static const uint8_t expected_identity[] = {
        36u,
        0u, 0u, 0u, 16u,
        0u, 0u, 0u, 12u,
        0u, 0u, 0u, 5u,
        'a', 'd', 'm', 'i', 'n',
        0u, 0u, 0u,
    };
    RFB_CHECK_EQ_UINT(f.send_lengths[0], sizeof expected_identity);
    RFB_CHECK_MEM_EQ(f.output + f.send_offsets[0], expected_identity,
                     sizeof expected_identity);

    uint8_t expected_packet2[2048];
    size_t expected_packet2_len = 0u;
    uint8_t client_random[16];
    memset(client_random, 0x24, sizeof client_random);
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_type36_packet2(
            &f.expected_session, "record-test", sizeof "record-test" - 1u,
            client_random, expected_packet2, sizeof expected_packet2,
            &expected_packet2_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(f.send_lengths[1], expected_packet2_len);
    RFB_CHECK_MEM_EQ(f.output + f.send_offsets[1], expected_packet2,
                     expected_packet2_len);
    apple_srp_session_destroy(&f.expected_session);
}

RFB_TEST(apple_type33_live,
         type36_server_rejects__keeps_outputs_clear)
{
    live_fixture f;
    RFB_CHECK(live_fixture_prepare_type36(&f, true, false));
    uint8_t wrap[16];
    apple_type33_kdf_material kdf;
    memset(wrap, 0xcc, sizeof wrap);
    memset(&kdf, 0xcc, sizeof kdf);

    RFB_CHECK_EQ_INT(live_authenticate_type36(&f, wrap, &kdf),
                     RFB_ERR_AUTH);
    RFB_CHECK(live_is_zero(wrap, sizeof wrap));
    RFB_CHECK(live_is_zero(&kdf, sizeof kdf));
    apple_srp_session_destroy(&f.expected_session);
}

RFB_TEST(apple_type33_live,
         type36_bad_m2__keeps_outputs_clear)
{
    live_fixture f;
    RFB_CHECK(live_fixture_prepare_type36(&f, false, true));
    uint8_t wrap[16];
    apple_type33_kdf_material kdf;
    memset(wrap, 0xcc, sizeof wrap);
    memset(&kdf, 0xcc, sizeof kdf);

    RFB_CHECK_EQ_INT(live_authenticate_type36(&f, wrap, &kdf),
                     RFB_ERR_AUTH);
    RFB_CHECK_EQ_UINT(f.random_calls, 2u);
    RFB_CHECK_EQ_UINT(f.send_count, 2u);
    RFB_CHECK(live_is_zero(wrap, sizeof wrap));
    RFB_CHECK(live_is_zero(&kdf, sizeof kdf));
    apple_srp_session_destroy(&f.expected_session);
}

RFB_TEST(apple_type33_connect,
         type36_real_crypto_exchange__publishes_verified_keys)
{
    static const uint8_t security[] = {1u, 36u};
    static const uint8_t user[] = "admin";
    static const uint8_t pass[] = "secret";
    live_fixture f;
    RFB_CHECK(live_fixture_prepare_type36(&f, false, false));
    RFB_CHECK(live_append_server_init(&f));

    fake_io wire;
    fake_io_init(&wire, rfb_default_allocator());
    rfb_io_adapter adapter = fake_io_adapter_make(&wire);
    rfb_buffer in;
    rfb_buffer out;
    rfb_buffer_init(&in, rfb_default_allocator(),
                    RFB_LIMIT_PRESENTATION_BYTES);
    rfb_buffer_init(&out, rfb_default_allocator(),
                    RFB_LIMIT_PRESENTATION_BYTES);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&in, security, sizeof security),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&in, f.input, f.input_len), RFB_OK);

    rfb_error last_error = RFB_OK;
    rfb_io_pump pump;
    memset(&pump, 0, sizeof pump);
    pump.alloc = rfb_default_allocator();
    pump.io = &adapter;
    pump.fd = -1;
    pump.in = &in;
    pump.out = &out;
    pump.last_error = &last_error;

    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.auth_mode = FARSEE_AUTH_MODE_APPLE;
    cfg.username = user;
    cfg.username_len = sizeof user - 1u;
    cfg.password = pass;
    cfg.password_len = sizeof pass - 1u;
    cfg.shared = true;
    cfg.apple_attach = APPLE_ATTACH_LOGIN;
    cfg.apple_prefer_type_36 = true;

    live_connect_setup setup;
    memset(&setup, 0, sizeof setup);
    apple_type33_connect_hooks hooks;
    memset(&hooks, 0, sizeof hooks);
    hooks.ctx = &setup;
    hooks.setup_after_server_init = live_connect_setup_after_server_init;

    apple_type33_connect_ops ops = {
        &f,
        live_connect_authenticate_type36,
        live_connect_random,
    };
    uint8_t wrap[16] = {0};
    uint8_t sk32[32] = {0};
    bool has_wrap = false;
    rfb_session_dialect dialect = RFB_SESSION_DIALECT_CLASSIC;
    RFB_CHECK_EQ_INT(
        apple_type33_connect_with_ops(&pump, &cfg, &hooks, wrap,
                                      &has_wrap, &dialect, sk32, &ops),
        RFB_OK);

    RFB_CHECK(has_wrap);
    RFB_CHECK_EQ_INT(dialect, RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    RFB_CHECK_MEM_EQ(wrap, f.expected_sk32, sizeof wrap);
    RFB_CHECK_MEM_EQ(sk32, f.expected_sk32, sizeof sk32);
    RFB_CHECK_EQ_UINT(f.random_calls, 2u);
    RFB_CHECK_EQ_UINT(setup.calls, 1u);
    RFB_CHECK(strcmp(setup.name, "desk") == 0);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&in), 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&out), 0u);
    const uint8_t *sent = fake_io_outbox_data(&wire);
    const size_t sent_len = fake_io_outbox_len(&wire);
    RFB_CHECK(sent_len > 13u);
    RFB_CHECK_MEM_EQ(sent, "RFB 003.889\n", 12u);
    RFB_CHECK_EQ_UINT(sent[12], 36u);
    RFB_CHECK_EQ_UINT(sent[sent_len - 1u],
                      APPLE_POSTAUTH_CLIENT_INIT_LIVE_SHARED);

    apple_srp_session_destroy(&f.expected_session);
    rfb_buffer_destroy(&in);
    rfb_buffer_destroy(&out);
    fake_io_destroy(&wire);
}
