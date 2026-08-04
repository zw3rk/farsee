// SPDX-License-Identifier: Apache-2.0
//
// farsee — blocking Apple type-33 live authentication (RSA1 + SRP).
//
// Flow (docs/apple/G26-AUTH-SUCCESS.md, RSA1-UNBLOCK.md):
//   1. 15-byte key request (selector + envelope, one send)
//   2. Parse key response → SPKI
//   3. Encrypt identity (username) → packet 1
//   4. Parse SRP challenge → compute client (A, M1, K)
//   5. Packet 2 with client_random
//   6. KEEP srp session until M2 verify + wrap_key derive
//   7. Destroy session, zero secrets
//
// FIX vs tools/live_auth.c: do not destroy apple_srp_session before
// parse_auth_response / compute_m2 / derive_wrap_key.

#include "farsee/apple_type33_live.h"
#include "farsee/apple_crypto.h"
#include "farsee/apple_rsa1.h"
#include "farsee/known_hosts.h"
#include "farsee/apple_srp.h"
#include "farsee/bytes.h"
#include "farsee/secret.h"

#include <string.h>

// Policy caps for wire frames (fixed stack buffers; no VLA).
// Key response: 4 + total_len, total_len = der_len + 7, der ≤ 4096 → ~4107.
#define TYPE33_KEY_RESP_MAX   8192u
// SRP challenge observed ~1169; leave headroom for larger groups.
#define TYPE33_CHALLENGE_MAX  8192u
// Auth response (envelope + SecurityResult) observed ~106.
#define TYPE33_AUTH_RESP_MAX  8192u
// Packet 2 full size with 512-byte N is ~1080; 2048 is ample.
#define TYPE33_PACKET2_MAX    2048u

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

rfb_error apple_type33_authenticate(
    const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16],
    const char *host, uint16_t port,
    const char *known_hosts_path)
{
    if (io == NULL || wrap_key_out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (io->send_all == NULL || io->recv_exact == NULL) {
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

    // Peer SPKI trust before encrypting identity (loop r1 T1 / r2 F1/F3).
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
            pin_on_success = true;  // session-accept first-use; pin after M2
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

    // --- 4. SRP challenge -------------------------------------------------
    uint8_t challenge[TYPE33_CHALLENGE_MAX];
    size_t ch_len = 0;
    e = recv_u32be_frame(io, challenge, sizeof challenge, &ch_len, 0u);
    if (e != RFB_OK) {
        return e;
    }

    apple_srp_challenge ch;
    e = apple_srp_parse_challenge(challenge, ch_len, &ch);
    if (e != RFB_OK) {
        return e;
    }

    // --- 5. SRP client computation ----------------------------------------
    uint8_t a_secret[32];
    if (!rfb_crypto_random_bytes(a_secret, sizeof a_secret)) {
        rfb_secret_zero(a_secret, sizeof a_secret);
        return RFB_ERR_INTERNAL;
    }

    apple_srp_session sess;
    memset(&sess, 0, sizeof sess);
    e = apple_srp_compute_client(&ch,
                                 username, username_len,
                                 password, password_len,
                                 a_secret, sizeof a_secret,
                                 &sess);
    rfb_secret_zero(a_secret, sizeof a_secret);
    if (e != RFB_OK) {
        apple_srp_session_destroy(&sess);
        return e;
    }

    // --- 6. Packet 2 ------------------------------------------------------
    uint8_t client_random[16];
    if (!rfb_crypto_random_bytes(client_random, sizeof client_random)) {
        apple_srp_session_destroy(&sess);
        rfb_secret_zero(client_random, sizeof client_random);
        return RFB_ERR_INTERNAL;
    }

    uint8_t packet2[TYPE33_PACKET2_MAX];
    size_t p2_len = 0;
    e = apple_srp_serialize_packet2(&sess,
                                    (const char *)ch.options, ch.options_len,
                                    client_random,
                                    packet2, sizeof packet2, &p2_len);
    rfb_secret_zero(client_random, sizeof client_random);
    if (e != RFB_OK) {
        apple_srp_session_destroy(&sess);
        return e;
    }

    e = io_send(io, packet2, p2_len);
    if (e != RFB_OK) {
        apple_srp_session_destroy(&sess);
        return e;
    }

    // --- 7. Auth response (KEEP sess for M2 + wrap_key) -------------------
    // Full frame = u32 total_len + envelope body + u32 SecurityResult.
    uint8_t auth_buf[TYPE33_AUTH_RESP_MAX];
    size_t auth_len = 0;
    e = recv_u32be_frame(io, auth_buf, sizeof auth_buf, &auth_len, 4u);
    if (e != RFB_OK) {
        apple_srp_session_destroy(&sess);
        return e;
    }

    apple_srp_auth_response auth_resp;
    e = apple_srp_parse_auth_response(auth_buf, auth_len, &auth_resp);
    if (e != RFB_OK) {
        apple_srp_session_destroy(&sess);
        return e;
    }

    if (auth_resp.security_result != 0u) {
        apple_srp_session_destroy(&sess);
        return RFB_ERR_AUTH;
    }

    // M2 verify (constant-time). Server must present M2 on success.
    if (auth_resp.M2 == NULL || auth_resp.M2_len != APPLE_SRP_M1_BYTES) {
        apple_srp_session_destroy(&sess);
        return RFB_ERR_PROTOCOL;
    }

    uint8_t expected_m2[APPLE_SRP_M1_BYTES];
    e = apple_srp_compute_m2(&sess, ch.B, ch.B_len, expected_m2);
    if (e != RFB_OK) {
        rfb_secret_zero(expected_m2, sizeof expected_m2);
        apple_srp_session_destroy(&sess);
        return e;
    }

    bool m2_ok = rfb_crypto_ct_eq(expected_m2, auth_resp.M2, APPLE_SRP_M1_BYTES);
    rfb_secret_zero(expected_m2, sizeof expected_m2);
    if (!m2_ok) {
        apple_srp_session_destroy(&sess);
        return RFB_ERR_AUTH;
    }

    // Derive wrap_key while K is still live in the session.
    if (!apple_srp_derive_wrap_key(&sess, wrap_key_out)) {
        apple_srp_session_destroy(&sess);
        rfb_secret_zero(wrap_key_out, 16);
        return RFB_ERR_INTERNAL;
    }

    // Durable TOFU pin only after successful M2 (loop r2 F1).
    if (pin_on_success && peer_fp_ok && known_hosts_path != NULL &&
        host != NULL && host[0] != '\0') {
        if (!known_hosts_add(host, trust_port, peer_fp, known_hosts_path)) {
            apple_srp_session_destroy(&sess);
            rfb_secret_zero(wrap_key_out, 16);
            return RFB_ERR_AUTH;
        }
    }

    apple_srp_session_destroy(&sess);
    // challenge buffer holds only public parameters; no secret zero needed.
    return RFB_OK;
}
