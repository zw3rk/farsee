// SPDX-License-Identifier: Apache-2.0
//
// farsee — blocking Apple type-33 and type-36 live authentication.
//
// Type 33 implements the RSA1 and SRP authentication flow.
//   1. 15-byte key request (selector + envelope, one send)
//   2. Parse key response → SPKI
//   3. Encrypt identity (username) → packet 1
//   4. Parse SRP challenge → compute client (A, M1, K)
//   5. Packet 2 with client_random
//   6. KEEP srp session until M2 verify + wrap_key derive
//   7. Destroy session, zero secrets
// Type 36 sends the clear identity directly, then shares steps 4 through 7
// with type 33 under its distinct envelopes.
//
// Keep the SRP session alive through parse_auth_response, compute_m2, and
// derive_wrap_key. Destroying it earlier discards required key material.

#include "farsee/apple_type33_live.h"
#include "farsee/apple_type36_live.h"
#include "farsee/apple_crypto.h"
#include "farsee/apple_rsa1.h"
#include "farsee/known_hosts.h"
#include "farsee/apple_srp.h"
#include "farsee/bytes.h"
#include "farsee/secret.h"
#include "rfb/apple_type33_live_internal.h"

#include <stdio.h>
#include <string.h>

// Policy caps for wire frames (fixed stack buffers; no VLA).
// Key response: 4 + total_len, total_len = der_len + 7, der ≤ 4096 → ~4107.
#define TYPE33_KEY_RESP_MAX   8192u
// A 1169-byte SRP challenge fits with headroom for larger groups.
#define TYPE33_CHALLENGE_MAX  8192u
// Auth response bound includes the envelope and SecurityResult.
#define TYPE33_AUTH_RESP_MAX  8192u
// Packet 2 full size with 512-byte N is ~1080; 2048 is ample.
#define APPLE_SRP_PROOF_MAX   2048u
// Selector + u32 frame length + the bounded clear-text identity payload.
#define TYPE36_IDENTITY_MAX   (1u + 4u + 256u)

static bool live_random_bytes(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    return rfb_crypto_random_bytes(out, len);
}

static const apple_type33_live_ops LIVE_DEFAULT_OPS = {
    NULL,
    live_random_bytes,
};

static rfb_error io_send(const apple_type33_io *io,
                         const uint8_t *data, size_t n)
{
    if (io == NULL || io->send_all == NULL) {
        return RFB_ERR_INTERNAL;
    }
    return io->send_all(io->ctx, data, n);
}

static rfb_error io_recv(const apple_type33_io *io, uint8_t *data, size_t n)
{
    if (io == NULL || io->recv_exact == NULL) {
        return RFB_ERR_INTERNAL;
    }
    return io->recv_exact(io->ctx, data, n);
}

// Read a length-prefixed RSA1 frame: first 4 bytes are u32_be total_len
// counting the payload after those 4 bytes. Full size = 4 + total_len.
// For auth response, full size = 4 + total_len + 4 (trailing SecurityResult).
static rfb_error recv_u32be_frame(const apple_type33_io *io,
                                  uint8_t *buf, size_t buf_cap,
                                  size_t *out_len,
                                  size_t trailer)
{
    if (buf_cap < 4u) {
        return RFB_ERR_LIMIT;
    }
    rfb_error e = io_recv(io, buf, 4u);
    if (e != RFB_OK) {
        return e;
    }
    uint32_t total = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                     ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
    size_t full = 4u + (size_t)total + trailer;
    if (full < 4u || full > buf_cap) {
        return RFB_ERR_LIMIT;
    }
    if (full > 4u) {
        e = io_recv(io, buf + 4u, full - 4u);
        if (e != RFB_OK) {
            return e;
        }
    }
    *out_len = full;
    return RFB_OK;
}

static rfb_error recv_type36_auth_response(const apple_type33_io *io,
                                           uint8_t *buf, size_t buf_cap,
                                           size_t *out_len)
{
    if (buf_cap < 4u) {
        return RFB_ERR_LIMIT;
    }
    rfb_error e = io_recv(io, buf, 4u);
    if (e != RFB_OK) {
        return e;
    }
    const uint32_t first = ((uint32_t)buf[0] << 24) |
                           ((uint32_t)buf[1] << 16) |
                           ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
    if (first <= 3u) {
        if (first == 1u) {
            *out_len = 4u;
            return RFB_OK;
        }
        return RFB_ERR_PROTOCOL;
    }
    const size_t full = 4u + (size_t)first + 4u;
    if (full < 8u || full > buf_cap) {
        return RFB_ERR_LIMIT;
    }
    e = io_recv(io, buf + 4u, full - 4u);
    if (e != RFB_OK) {
        return e;
    }
    *out_len = full;
    return RFB_OK;
}

void apple_type33_kdf_material_zero(apple_type33_kdf_material *m)
{
    if (m == NULL) {
        return;
    }
    rfb_secret_zero(m, sizeof *m);
}

// Continue either Apple authentication branch after its identity exchange.
// Both security types use the same SRP challenge, proof, and key schedule.
static rfb_error authenticate_srp_continuation(
    const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16], apple_type33_kdf_material *kdf_out,
    rfb_allocator *allocator, const apple_type33_live_ops *ops,
    bool type36)
{
    uint8_t challenge[TYPE33_CHALLENGE_MAX];
    size_t ch_len = 0;
    rfb_error e = recv_u32be_frame(io, challenge, sizeof challenge, &ch_len,
                                   0u);
    if (e != RFB_OK) {
        return e;
    }

    apple_srp_challenge ch;
    e = type36
            ? apple_srp_parse_type36_challenge(challenge, ch_len, &ch)
            : apple_srp_parse_challenge(challenge, ch_len, &ch);
    if (e != RFB_OK) {
        return e;
    }

    uint8_t a_secret[32];
    if (!ops->random_bytes(ops->ctx, a_secret, sizeof a_secret)) {
        rfb_secret_zero(a_secret, sizeof a_secret);
        return RFB_ERR_INTERNAL;
    }

    apple_srp_session sess;
    memset(&sess, 0, sizeof sess);
    e = apple_srp_compute_client_with_allocator(
        &ch, username, username_len, password, password_len, a_secret,
        sizeof a_secret, &sess, allocator);
    rfb_secret_zero(a_secret, sizeof a_secret);
    if (e != RFB_OK) {
        apple_srp_session_destroy(&sess);
        return e;
    }

    uint8_t client_random[16];
    if (!ops->random_bytes(ops->ctx, client_random, sizeof client_random)) {
        apple_srp_session_destroy(&sess);
        rfb_secret_zero(client_random, sizeof client_random);
        return RFB_ERR_INTERNAL;
    }
    uint8_t client_random_save[16];
    memcpy(client_random_save, client_random, sizeof client_random_save);

    uint8_t packet2[APPLE_SRP_PROOF_MAX];
    size_t p2_len = 0;
    e = type36
            ? apple_srp_serialize_type36_packet2(
                  &sess, (const char *)ch.options, ch.options_len,
                  client_random, packet2, sizeof packet2, &p2_len)
            : apple_srp_serialize_packet2(
                  &sess, (const char *)ch.options, ch.options_len,
                  client_random, packet2, sizeof packet2, &p2_len);
    rfb_secret_zero(client_random, sizeof client_random);
    if (e != RFB_OK) {
        apple_srp_session_destroy(&sess);
        rfb_secret_zero(client_random_save, sizeof client_random_save);
        return e;
    }

    e = io_send(io, packet2, p2_len);
    if (e != RFB_OK) {
        apple_srp_session_destroy(&sess);
        rfb_secret_zero(client_random_save, sizeof client_random_save);
        return e;
    }

    uint8_t auth_buf[TYPE33_AUTH_RESP_MAX];
    size_t auth_len = 0;
    e = type36
            ? recv_type36_auth_response(io, auth_buf, sizeof auth_buf,
                                        &auth_len)
            : recv_u32be_frame(io, auth_buf, sizeof auth_buf, &auth_len, 4u);
    if (e != RFB_OK) {
        apple_srp_session_destroy(&sess);
        rfb_secret_zero(client_random_save, sizeof client_random_save);
        return e;
    }

    apple_srp_auth_response auth_resp;
    e = type36
            ? apple_srp_parse_type36_auth_response(auth_buf, auth_len,
                                                   &auth_resp)
            : apple_srp_parse_auth_response(auth_buf, auth_len, &auth_resp);
    if (e != RFB_OK) {
        apple_srp_session_destroy(&sess);
        rfb_secret_zero(client_random_save, sizeof client_random_save);
        return e;
    }
    if (auth_resp.security_result != 0u) {
        apple_srp_session_destroy(&sess);
        rfb_secret_zero(client_random_save, sizeof client_random_save);
        return RFB_ERR_AUTH;
    }
    if (auth_resp.M2 == NULL || auth_resp.M2_len != APPLE_SRP_M1_BYTES) {
        apple_srp_session_destroy(&sess);
        rfb_secret_zero(client_random_save, sizeof client_random_save);
        return RFB_ERR_PROTOCOL;
    }

    uint8_t expected_m2[APPLE_SRP_M1_BYTES];
    e = apple_srp_compute_m2_with_allocator(
        &sess, ch.B, ch.B_len, expected_m2, allocator);
    if (e != RFB_OK) {
        rfb_secret_zero(expected_m2, sizeof expected_m2);
        apple_srp_session_destroy(&sess);
        rfb_secret_zero(client_random_save, sizeof client_random_save);
        return e;
    }

    const bool m2_ok =
        rfb_crypto_ct_eq(expected_m2, auth_resp.M2, APPLE_SRP_M1_BYTES);
    rfb_secret_zero(expected_m2, sizeof expected_m2);
    if (!m2_ok) {
        apple_srp_session_destroy(&sess);
        rfb_secret_zero(client_random_save, sizeof client_random_save);
        return RFB_ERR_AUTH;
    }

    uint8_t sk32[32];
    if (!apple_srp_derive_session_key_32(&sess, sk32)) {
        apple_srp_session_destroy(&sess);
        rfb_secret_zero(wrap_key_out, 16);
        rfb_secret_zero(client_random_save, sizeof client_random_save);
        return RFB_ERR_INTERNAL;
    }
    memcpy(wrap_key_out, sk32, 16);

    if (kdf_out != NULL) {
        memcpy(kdf_out->session_key_32, sk32, 32);
        memcpy(kdf_out->srp_k, sess.K, 64);
        memcpy(kdf_out->client_random, client_random_save, 16);
        kdf_out->has_client_random = true;
        if (sess.S_len > 0u && sess.S_len <= sizeof kdf_out->srp_s) {
            memcpy(kdf_out->srp_s, sess.S, sess.S_len);
            kdf_out->srp_s_len = sess.S_len;
            kdf_out->has_srp_s = true;
        }
        if (sess.M1_len == 64u) {
            memcpy(kdf_out->m1, sess.M1, 64);
            kdf_out->has_m1 = true;
        }
        if (auth_resp.server_random != NULL &&
            auth_resp.server_random_len == 16u) {
            memcpy(kdf_out->server_random, auth_resp.server_random, 16);
            kdf_out->has_server_random = true;
        }
        if (ch.salt != NULL && ch.salt_len > 0u &&
            ch.salt_len <= sizeof kdf_out->salt) {
            memcpy(kdf_out->salt, ch.salt, ch.salt_len);
            kdf_out->salt_len = ch.salt_len;
        }
        kdf_out->iterations = ch.iterations;
        if (ch.options != NULL && ch.options_len > 0u &&
            ch.options_len <= sizeof kdf_out->options) {
            memcpy(kdf_out->options, ch.options, ch.options_len);
            kdf_out->options_len = ch.options_len;
        }
    }

    rfb_secret_zero(sk32, sizeof sk32);
    rfb_secret_zero(client_random_save, sizeof client_random_save);
    apple_srp_session_destroy(&sess);
    return RFB_OK;
}

rfb_error apple_type33_authenticate_ex(
    const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16],
    apple_type33_kdf_material *kdf_out,
    const char *host, uint16_t port,
    const char *known_hosts_path,
    bool accept_new_host)
{
    return apple_type33_authenticate_ex_with_allocator(
        io, username, username_len, password, password_len, wrap_key_out,
        kdf_out, host, port, known_hosts_path, accept_new_host,
        rfb_default_allocator());
}

rfb_error apple_type33_authenticate_ex_with_allocator_and_ops(
    const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16], apple_type33_kdf_material *kdf_out,
    const char *host, uint16_t port, const char *known_hosts_path,
    bool accept_new_host, rfb_allocator *allocator,
    const apple_type33_live_ops *ops)
{
    if (io == NULL || wrap_key_out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (io->send_all == NULL || io->recv_exact == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (allocator == NULL || allocator->alloc == NULL ||
        allocator->free == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (ops == NULL || ops->random_bytes == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (username == NULL || username_len == 0u) {
        return RFB_ERR_PROTOCOL;
    }
    if (password == NULL || password_len == 0u) {
        return RFB_ERR_AUTH;
    }
    if (username_len > APPLE_RSA1_MAX_USERNAME_LEN) {
        return RFB_ERR_PROTOCOL;
    }

    memset(wrap_key_out, 0, 16);
    if (kdf_out != NULL) {
        memset(kdf_out, 0, sizeof *kdf_out);
    }

    // --- 1. Key request (15 bytes: selector 0x21 + envelope) --------------
    uint8_t key_req[APPLE_RSA1_KEY_REQUEST_LEN];
    size_t kr_len = 0;
    rfb_error e = apple_rsa1_serialize_key_request(key_req, sizeof key_req,
                                                   &kr_len);
    if (e != RFB_OK) {
        return e;
    }
    e = io_send(io, key_req, kr_len);
    if (e != RFB_OK) {
        return e;
    }

    // --- 2. Key response --------------------------------------------------
    uint8_t key_resp[TYPE33_KEY_RESP_MAX];
    size_t key_resp_len = 0;
    e = recv_u32be_frame(io, key_resp, sizeof key_resp, &key_resp_len, 0u);
    if (e != RFB_OK) {
        return e;
    }

    apple_rsa1_key_response kresp;
    e = apple_rsa1_parse_key_response(key_resp, key_resp_len, &kresp);
    if (e != RFB_OK) {
        return e;
    }

    // Verify peer SPKI trust before encrypting identity.
    // Host set ⇒ store path required (fail closed). Pin durable store only
    // after full auth success (not on first-use mid-handshake).
    uint8_t peer_fp[32];
    bool peer_fp_ok = false;
    bool pin_on_success = false;
    const uint16_t trust_port = (port != 0u) ? port : 5900u;
    if (host != NULL && host[0] != '\0') {
        if (known_hosts_path == NULL || known_hosts_path[0] == '\0') {
            return RFB_ERR_AUTH;
        }
        memset(peer_fp, 0, sizeof peer_fp);
        if (!rfb_crypto_spki_fingerprint(kresp.spki_der, kresp.spki_len,
                                        peer_fp)) {
            return RFB_ERR_INTERNAL;
        }
        peer_fp_ok = true;
        const known_hosts_result kr =
            known_hosts_check(host, trust_port, peer_fp, known_hosts_path);
        if (kr == KNOWN_HOSTS_MISMATCH) {
            return RFB_ERR_AUTH;
        }
        if (kr == KNOWN_HOSTS_NOT_FOUND) {
            if (!accept_new_host) {
                // First use fails closed: the known_hosts
                // contract requires interactive confirmation or an explicit
                // accept-new policy. Surface the fingerprint so the operator
                // can verify the key out of band before credentials are sent.
                fprintf(stderr,
                        "farsee: unknown host key for %s:%u (first use); "
                        "SPKI fingerprint ",
                        host, trust_port);
                for (int i = 0; i < 32; i++) {
                    fprintf(stderr, "%02x", peer_fp[i]);
                }
                fprintf(stderr,
                        "\nfarsee: re-run with --accept-new-host to accept "
                        "and pin this key\n");
                return RFB_ERR_AUTH;
            }
            pin_on_success = true;  // explicit opt-in: pin after M2
        }
        // MATCH: continue without re-pin
    }

    // --- 3. Identity encrypt → packet 1 -----------------------------------
    uint8_t identity[256];
    size_t id_len = 0;
    e = apple_rsa1_serialize_identity(username, username_len,
                                      identity, sizeof identity, &id_len);
    if (e != RFB_OK) {
        rfb_secret_zero(identity, sizeof identity);
        return e;
    }

    uint8_t ciphertext[APPLE_RSA1_CIPHERTEXT_LEN];
    if (!apple_rsa1_encrypt_identity(kresp.spki_der, kresp.spki_len,
                                     identity, id_len, ciphertext)) {
        rfb_secret_zero(identity, sizeof identity);
        rfb_secret_zero(ciphertext, sizeof ciphertext);
        return RFB_ERR_INTERNAL;
    }
    rfb_secret_zero(identity, sizeof identity);

    uint8_t packet1[APPLE_RSA1_PACKET1_LEN];
    size_t p1_len = 0;
    e = apple_rsa1_serialize_packet1(ciphertext, packet1, sizeof packet1,
                                     &p1_len);
    rfb_secret_zero(ciphertext, sizeof ciphertext);
    if (e != RFB_OK) {
        return e;
    }
    e = io_send(io, packet1, p1_len);
    if (e != RFB_OK) {
        return e;
    }

    e = authenticate_srp_continuation(
        io, username, username_len, password, password_len, wrap_key_out,
        kdf_out, allocator, ops, false);
    if (e != RFB_OK) {
        return e;
    }

    // Write the durable TOFU pin only after a successful M2 proof.
    if (pin_on_success && peer_fp_ok && known_hosts_path != NULL &&
        host != NULL && host[0] != '\0') {
        if (!known_hosts_add(host, trust_port, peer_fp, known_hosts_path)) {
            rfb_secret_zero(wrap_key_out, 16);
            if (kdf_out != NULL) {
                apple_type33_kdf_material_zero(kdf_out);
            }
            return RFB_ERR_AUTH;
        }
    }

    return RFB_OK;
}

rfb_error apple_type33_authenticate_ex_with_allocator(
    const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16], apple_type33_kdf_material *kdf_out,
    const char *host, uint16_t port, const char *known_hosts_path,
    bool accept_new_host, rfb_allocator *allocator)
{
    return apple_type33_authenticate_ex_with_allocator_and_ops(
        io, username, username_len, password, password_len, wrap_key_out,
        kdf_out, host, port, known_hosts_path, accept_new_host, allocator,
        &LIVE_DEFAULT_OPS);
}

rfb_error apple_type33_authenticate(
    const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16],
    const char *host, uint16_t port,
    const char *known_hosts_path)
{
    return apple_type33_authenticate_ex(
        io, username, username_len, password, password_len, wrap_key_out,
        NULL, host, port, known_hosts_path, false);
}

rfb_error apple_type36_authenticate_ex_with_allocator_and_ops(
    const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16], apple_type33_kdf_material *kdf_out,
    rfb_allocator *allocator, const apple_type33_live_ops *ops)
{
    if (io == NULL || wrap_key_out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (io->send_all == NULL || io->recv_exact == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (allocator == NULL || allocator->alloc == NULL ||
        allocator->free == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (ops == NULL || ops->random_bytes == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (username == NULL || username_len == 0u ||
        username_len > APPLE_RSA1_MAX_USERNAME_LEN) {
        return RFB_ERR_PROTOCOL;
    }
    if (password == NULL || password_len == 0u) {
        return RFB_ERR_AUTH;
    }

    memset(wrap_key_out, 0, 16);
    if (kdf_out != NULL) {
        memset(kdf_out, 0, sizeof *kdf_out);
    }

    uint8_t identity[256];
    size_t identity_len = 0;
    rfb_error e = apple_rsa1_serialize_identity(
        username, username_len, identity, sizeof identity, &identity_len);
    if (e != RFB_OK) {
        rfb_secret_zero(identity, sizeof identity);
        return e;
    }

    uint8_t branch_entry[TYPE36_IDENTITY_MAX];
    rfb_writer w = rfb_writer_make(branch_entry, sizeof branch_entry);
    if (!rfb_write_u8(&w, 36u) ||
        !rfb_write_u32(&w, (uint32_t)identity_len) ||
        !rfb_write_bytes(&w, identity, identity_len)) {
        rfb_secret_zero(identity, sizeof identity);
        rfb_secret_zero(branch_entry, sizeof branch_entry);
        return RFB_ERR_LIMIT;
    }
    rfb_secret_zero(identity, sizeof identity);

    e = io_send(io, branch_entry, w.length);
    rfb_secret_zero(branch_entry, sizeof branch_entry);
    if (e != RFB_OK) {
        return e;
    }

    return authenticate_srp_continuation(
        io, username, username_len, password, password_len, wrap_key_out,
        kdf_out, allocator, ops, true);
}

rfb_error apple_type36_authenticate_ex_with_allocator(
    const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16], apple_type33_kdf_material *kdf_out,
    rfb_allocator *allocator)
{
    return apple_type36_authenticate_ex_with_allocator_and_ops(
        io, username, username_len, password, password_len, wrap_key_out,
        kdf_out, allocator, &LIVE_DEFAULT_OPS);
}
