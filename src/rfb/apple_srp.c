// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple type-33 SRP challenge parser.
// Protocol contract: docs/apple/srp-challenge-offsets.md.
// RFC 5054 (SRP for TLS) parameters validated.

#include "farsee/apple_srp.h"
#include "farsee/apple_crypto.h"
#include "farsee/secret.h"
#include "farsee/bytes.h"

#include <stdlib.h>
#include <string.h>

// RFC 5054 Appendix A 4096-bit group prime (full 512 bytes).
// Compare the entire modulus — a 10-byte prefix check is not enough.
static const uint8_t RFC5054_N_4096[APPLE_SRP_N_BYTES] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
    0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
    0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D,
    0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
    0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57,
    0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
    0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
    0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73,
    0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0,
    0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
    0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20,
    0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
    0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18,
    0x6A, 0xF4, 0xE2, 0x3C, 0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
    0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 0xDB, 0xBB, 0xC2, 0xDB,
    0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
    0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F,
    0xA0, 0x90, 0xC3, 0xA2, 0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
    0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 0xB8, 0x1B, 0xDD, 0x76,
    0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
    0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC,
    0x90, 0xA6, 0xC0, 0x8F, 0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x06, 0x31, 0x99,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

// True iff all `n` bytes of `p` are zero.
static bool srp_bytes_all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    if (p == NULL) {
        return true;
    }
    for (size_t i = 0; i < n; i++) {
        acc = (uint8_t)(acc | p[i]);
    }
    return acc == 0u;
}

// Big-endian compare of equal-length limbs: <0 if a<b, 0 if equal, >0 if a>b.
static int srp_be_cmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (a[i] < b[i]) {
            return -1;
        }
        if (a[i] > b[i]) {
            return 1;
        }
    }
    return 0;
}

static rfb_error parse_challenge_payload(rfb_reader *r,
                                         apple_srp_challenge *out)
{
    // control byte
    uint8_t control = 0;
    if (!rfb_read_u8(r, &control)) return RFB_ERR_PROTOCOL;
    if (control != 0u) {
        return RFB_ERR_PROTOCOL;
    }

    // %m N: u16_be len + data
    uint16_t n_len = 0;
    if (!rfb_read_u16(r, &n_len)) return RFB_ERR_PROTOCOL;
    if (n_len != APPLE_SRP_N_BYTES) {
        return RFB_ERR_PROTOCOL;  // must be 4096-bit
    }
    out->N = r->data + r->offset;
    if (!rfb_reader_skip(r, n_len)) return RFB_ERR_PROTOCOL;
    out->N_len = n_len;

    // Validate N is the full RFC 5054 4096-bit prime (constant-time compare).
    if (out->N_len != APPLE_SRP_N_BYTES ||
        !rfb_crypto_ct_eq(out->N, RFC5054_N_4096, APPLE_SRP_N_BYTES)) {
        return RFB_ERR_PROTOCOL;
    }

    // %m g: u16_be len + data
    uint16_t g_len = 0;
    if (!rfb_read_u16(r, &g_len)) return RFB_ERR_PROTOCOL;
    if (g_len != 1u) {
        return RFB_ERR_PROTOCOL;
    }
    out->g = r->data + r->offset;
    if (!rfb_reader_skip(r, g_len)) return RFB_ERR_PROTOCOL;
    out->g_len = g_len;
    // g must be 5
    if (out->g[0] != 5u) {
        return RFB_ERR_PROTOCOL;
    }

    // %o salt: u8 len + data
    uint8_t salt_len = 0;
    if (!rfb_read_u8(r, &salt_len)) return RFB_ERR_PROTOCOL;
    if (salt_len > APPLE_SRP_SALT_MAX) {
        return RFB_ERR_LIMIT;
    }
    if (salt_len == 0u) {
        return RFB_ERR_PROTOCOL;  // salt must be non-empty
    }
    out->salt = r->data + r->offset;
    if (!rfb_reader_skip(r, salt_len)) return RFB_ERR_PROTOCOL;
    out->salt_len = salt_len;

    // %m B: u16_be len + data
    uint16_t b_len = 0;
    if (!rfb_read_u16(r, &b_len)) return RFB_ERR_PROTOCOL;
    if (b_len != APPLE_SRP_N_BYTES) {
        return RFB_ERR_PROTOCOL;  // B must be N-width
    }
    out->B = r->data + r->offset;
    if (!rfb_reader_skip(r, b_len)) return RFB_ERR_PROTOCOL;
    out->B_len = b_len;

    // Require a canonical server value 0 < B < N. This is stronger than the
    // RFC 5054 check for B modulo N equal to zero.
    if (srp_bytes_all_zero(out->B, out->B_len) ||
        srp_be_cmp(out->B, out->N, out->B_len) >= 0) {
        return RFB_ERR_PROTOCOL;
    }

    // padding u32_be (must be 0)
    if (!rfb_read_u32(r, &out->padding)) return RFB_ERR_PROTOCOL;
    if (out->padding != 0u) {
        return RFB_ERR_PROTOCOL;
    }

    // iterations u32_be
    if (!rfb_read_u32(r, &out->iterations)) return RFB_ERR_PROTOCOL;
    if (out->iterations < APPLE_SRP_ITER_MIN ||
        out->iterations > APPLE_SRP_ITER_MAX) {
        return RFB_ERR_LIMIT;
    }

    // %s options: u16_be len + string
    uint16_t opt_len = 0;
    if (!rfb_read_u16(r, &opt_len)) return RFB_ERR_PROTOCOL;
    if (opt_len > APPLE_SRP_OPTIONS_MAX) {
        return RFB_ERR_LIMIT;
    }
    out->options = r->data + r->offset;
    if (!rfb_reader_skip(r, opt_len)) return RFB_ERR_PROTOCOL;
    out->options_len = opt_len;

    // Full consumption: no remaining bytes
    if (rfb_reader_remaining(r) != 0u) {
        return RFB_ERR_PROTOCOL;
    }

    return RFB_OK;
}

rfb_error apple_srp_parse_challenge(const uint8_t *data, size_t len,
                                    apple_srp_challenge *out)
{
    if (data == NULL || out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    memset(out, 0, sizeof *out);
    rfb_reader r = rfb_reader_make(data, len);

    uint32_t total_len = 0;
    if (!rfb_read_u32(&r, &total_len) || len < 4u ||
        total_len != len - 4u) {
        return RFB_ERR_PROTOCOL;
    }
    if (!rfb_read_u16(&r, &out->version) ||
        !rfb_read_u16(&r, &out->authtype) ||
        !rfb_read_u16(&r, &out->body_len)) {
        return RFB_ERR_PROTOCOL;
    }
    if (total_len < 6u || out->version != 0u || out->authtype != 2u ||
        out->body_len != total_len - 6u) {
        return RFB_ERR_PROTOCOL;
    }
    if (!rfb_read_u16(&r, &out->preamble) ||
        !rfb_read_u16(&r, &out->inner_len)) {
        return RFB_ERR_PROTOCOL;
    }
    if (out->body_len < 4u || out->preamble != 0u ||
        out->inner_len != out->body_len - 4u) {
        return RFB_ERR_PROTOCOL;
    }
    return parse_challenge_payload(&r, out);
}

rfb_error apple_srp_parse_type36_challenge(const uint8_t *data, size_t len,
                                           apple_srp_challenge *out)
{
    if (data == NULL || out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    memset(out, 0, sizeof *out);
    rfb_reader r = rfb_reader_make(data, len);

    uint32_t total_len = 0;
    if (!rfb_read_u32(&r, &total_len) || len < 4u ||
        total_len != len - 4u || total_len < 4u ||
        !rfb_read_u16(&r, &out->version) ||
        !rfb_read_u16(&r, &out->body_len)) {
        return RFB_ERR_PROTOCOL;
    }
    if (out->version != 0u || out->body_len != total_len - 4u) {
        return RFB_ERR_PROTOCOL;
    }
    return parse_challenge_payload(&r, out);
}

// =====================================================================
// SRP Mathematics (RFC 5054 §2.6, Apple variant)
// =====================================================================
//
// The computation chain:
//   P' = PBKDF2-HMAC-SHA512(password, salt, iterations, 128)
//   x  = H(salt || H(":" || P'))
//   k  = H(PAD(N) || PAD(g))
//   a  = caller-supplied exponent (the live path uses 32 random bytes)
//   A  = g^a mod N
//   u  = H(PAD(A) || PAD(B))
//   S  = (B - k*g^x)^(a+u*x) mod N
//   K  = SHA512(PAD(S))
//   M1 = H(H(N) XOR H(g) || H(empty) || salt || PAD(A) || PAD(B) || K)
//   M2 = H(PAD(A) || M1 || K)
//   wrap_key = SHA256(K)[0:16]
//
// H = SHA-512 (64-byte output), PAD = left-pad to N-width (512 bytes).

// Zero-pad a value to N-width (left-pad with zeros).
static void pad_to_n(const uint8_t *src, size_t src_len,
                     uint8_t *out, size_t out_len)
{
    if (src_len >= out_len) {
        memcpy(out, src, out_len);
        return;
    }
    memset(out, 0, out_len - src_len);
    memcpy(out + (out_len - src_len), src, src_len);
}

// The provider's modular multiply, add, and subtract operations are
// variable-time; modular exponentiation sets BN_FLG_CONSTTIME on the exponent.
// The project threat model does not record an exception for this timing surface.

typedef struct apple_srp_compute_workspace {
    uint8_t P_prime[128];
    uint8_t inner_x[129];
    uint8_t h_inner_x[64];
    uint8_t salt_hash_buf[APPLE_SRP_SALT_MAX + 64];
    uint8_t pad_g[APPLE_SRP_N_BYTES];
    uint8_t concat_Ng[APPLE_SRP_N_BYTES * 2];
    uint8_t k[64];
    uint8_t concat_AB[APPLE_SRP_N_BYTES * 2];
    uint8_t u[64];
    uint8_t gx[APPLE_SRP_N_BYTES];
    uint8_t k_gx[APPLE_SRP_N_BYTES];
    uint8_t base[APPLE_SRP_N_BYTES];
    uint8_t ux[APPLE_SRP_N_BYTES];
    uint8_t a_padded[APPLE_SRP_N_BYTES];
    uint8_t exp_buf[APPLE_SRP_N_BYTES];
    uint8_t h_N[64];
    uint8_t h_g[64];
    uint8_t h_I[64];
    uint8_t hN_xor_hg[64];
    uint8_t *m1_input;
    size_t m1_input_len;
} apple_srp_compute_workspace;

rfb_error apple_srp_compute_client(
    const apple_srp_challenge *challenge,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    const uint8_t *a, size_t a_len,
    apple_srp_session *out)
{
    return apple_srp_compute_client_with_allocator(
        challenge, username, username_len, password, password_len, a, a_len,
        out, rfb_default_allocator());
}

rfb_error apple_srp_compute_client_with_allocator(
    const apple_srp_challenge *challenge,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    const uint8_t *a, size_t a_len, apple_srp_session *out,
    rfb_allocator *allocator)
{
    (void)username; (void)username_len;  // username is not used in x or M1
    if (challenge == NULL || out == NULL || a == NULL || password == NULL ||
        allocator == NULL || allocator->alloc == NULL ||
        allocator->free == NULL) {
        return RFB_ERR_INTERNAL;
    }

    apple_srp_compute_workspace workspace;
    rfb_error result = RFB_ERR_INTERNAL;
    size_t off = 0u;
    memset(out, 0, sizeof *out);
    memset(&workspace, 0, sizeof workspace);
    size_t N_len = challenge->N_len;

    // Store public parameters
    out->N = challenge->N;
    out->N_len = N_len;
    out->g = challenge->g;
    out->g_len = challenge->g_len;
    out->salt = challenge->salt;
    out->salt_len = challenge->salt_len;
    out->iterations = challenge->iterations;

    // Store private exponent a
    if (a_len > sizeof out->a) {
        result = RFB_ERR_PROTOCOL;
        goto cleanup;
    }
    memcpy(out->a, a, a_len);
    out->a_len = a_len;

    // Step 1: P' = PBKDF2-HMAC-SHA512(password, salt, iterations, 128)
    if (!rfb_crypto_pbkdf2_sha512(password, password_len,
                                   challenge->salt, challenge->salt_len,
                                   challenge->iterations,
                                   workspace.P_prime,
                                   sizeof workspace.P_prime)) {
        goto cleanup;
    }

    // Step 2: x = H(salt || H(":" || P'))
    // This Apple variant omits the username used by the RFC 5054 formula.
    // Hash ":" plus P' first, then prepend the salt for the outer hash.
    workspace.inner_x[0] = ':';
    memcpy(workspace.inner_x + 1, workspace.P_prime,
           sizeof workspace.P_prime);
    if (!rfb_crypto_sha512(workspace.inner_x, sizeof workspace.inner_x,
                           workspace.h_inner_x)) {
        goto cleanup;
    }

    // x = H(salt || h_inner_x)
    memcpy(workspace.salt_hash_buf, challenge->salt, challenge->salt_len);
    memcpy(workspace.salt_hash_buf + challenge->salt_len,
           workspace.h_inner_x, sizeof workspace.h_inner_x);
    if (!rfb_crypto_sha512(workspace.salt_hash_buf,
                           challenge->salt_len +
                               sizeof workspace.h_inner_x,
                           out->x)) {
        goto cleanup;
    }
    out->x_len = 64;

    // Zeroize P' and intermediates immediately (inner_x carries P' —
    // the password-derived preimage).
    rfb_secret_zero(workspace.P_prime, sizeof workspace.P_prime);
    rfb_secret_zero(workspace.inner_x, sizeof workspace.inner_x);
    rfb_secret_zero(workspace.h_inner_x, sizeof workspace.h_inner_x);
    rfb_secret_zero(workspace.salt_hash_buf,
                    sizeof workspace.salt_hash_buf);

    // Step 3: k = H(PAD(N) || PAD(g))
    pad_to_n(challenge->g, challenge->g_len, workspace.pad_g, N_len);
    memcpy(workspace.concat_Ng, challenge->N, N_len);
    memcpy(workspace.concat_Ng + N_len, workspace.pad_g, N_len);
    if (!rfb_crypto_sha512(workspace.concat_Ng, N_len * 2u,
                           workspace.k)) {
        goto cleanup;
    }

    // Step 4: A = g^a mod N
    if (!rfb_crypto_modexp(challenge->g, challenge->g_len,
                            a, a_len,
                            challenge->N, N_len,
                            out->A, N_len)) {
        goto cleanup;
    }
    out->A_len = N_len;

    // Step 5: u = H(PAD(A) || PAD(B))
    // A and B are already N-width (zero-padded by modexp / from challenge).
    memcpy(workspace.concat_AB, out->A, N_len);
    memcpy(workspace.concat_AB + N_len, challenge->B, N_len);
    if (!rfb_crypto_sha512(workspace.concat_AB, N_len * 2u,
                           workspace.u)) {
        goto cleanup;
    }

    // RFC 5054: abort if u == 0 (degenerate scrambler).
    if (srp_bytes_all_zero(workspace.u, sizeof workspace.u)) {
        result = RFB_ERR_PROTOCOL;
        goto cleanup;
    }

    // Step 6: S = (B - k*g^x)^(a + u*x) mod N
    // First compute g^x mod N
    if (!rfb_crypto_modexp(challenge->g, challenge->g_len,
                            out->x, out->x_len,
                            challenge->N, N_len,
                            workspace.gx, N_len)) {
        goto cleanup;
    }

    // Compute k_gx = (k * g^x) mod N using the modmul provider.
    // k is a 64-byte SHA-512 hash; treat it as a big integer < N.
    // Variable-time (BN_mod_mul; see the provider limitations above).
    if (!rfb_crypto_modmul(workspace.k, sizeof workspace.k,
                            workspace.gx, N_len,
                            challenge->N, N_len,
                            workspace.k_gx, N_len)) {
        goto cleanup;
    }

    // Compute base = (B - k_gx) mod N with the provider's variable-time
    // modular subtraction.
    if (!rfb_crypto_modsub(challenge->B, N_len, workspace.k_gx, N_len,
                            challenge->N, N_len, workspace.base, N_len)) {
        goto cleanup;
    }

    // Compute exponent = (a + u*x) mod N using modadd.
    // u and x are both 64-byte hashes; their product is up to 128 bytes.
    // We compute ux = (u * x) mod N, then exp = (a + ux) mod N.
    if (!rfb_crypto_modmul(workspace.u, sizeof workspace.u,
                            out->x, out->x_len,
                            challenge->N, N_len,
                            workspace.ux, N_len)) {
        goto cleanup;
    }

    // Pad a to N-width for the modadd
    if (a_len <= N_len) {
        memcpy(workspace.a_padded + (N_len - a_len), a, a_len);
    }

    if (!rfb_crypto_modadd(workspace.a_padded, N_len,
                            workspace.ux, N_len,
                            challenge->N, N_len,
                            workspace.exp_buf, N_len)) {
        goto cleanup;
    }

    // S = base^exp_buf mod N
    if (!rfb_crypto_modexp(workspace.base, N_len,
                            workspace.exp_buf, N_len,
                            challenge->N, N_len,
                            out->S, N_len)) {
        goto cleanup;
    }
    out->S_len = N_len;

    // Step 7: K = SHA512(PAD(S))
    // S is already N-width.
    if (!rfb_crypto_sha512(out->S, N_len, out->K)) {
        goto cleanup;
    }

    // Step 8: M1 = H(H(N) XOR H(g) || H(I) || salt || PAD(A) || PAD(B) || K)
    // where I = username, H = SHA-512
    if (!rfb_crypto_sha512(challenge->N, N_len, workspace.h_N) ||
        !rfb_crypto_sha512(workspace.pad_g, N_len, workspace.h_g) ||
        !rfb_crypto_sha512((const uint8_t *)"", 0, workspace.h_I)) {
        goto cleanup;
    }

    // H(N) XOR H(g)
    for (int i = 0; i < 64; i++) {
        workspace.hN_xor_hg[i] = workspace.h_N[i] ^ workspace.h_g[i];
    }

    // Concatenate: hN_xor_hg || h_I || salt || PAD(A) || PAD(B) || K
    // A and B are already N-width.
    workspace.m1_input_len = 64u + 64u + challenge->salt_len +
                             N_len + N_len + 64u;
    workspace.m1_input =
        (uint8_t *)allocator->alloc(allocator, workspace.m1_input_len);
    if (workspace.m1_input == NULL) {
        result = RFB_ERR_NOMEM;
        goto cleanup;
    }
    memcpy(workspace.m1_input + off, workspace.hN_xor_hg, 64u);
    off += 64u;
    memcpy(workspace.m1_input + off, workspace.h_I, 64u);
    off += 64u;
    memcpy(workspace.m1_input + off, challenge->salt, challenge->salt_len);
    off += challenge->salt_len;
    memcpy(workspace.m1_input + off, out->A, N_len);
    off += N_len;
    memcpy(workspace.m1_input + off, challenge->B, N_len);
    off += N_len;
    memcpy(workspace.m1_input + off, out->K, 64u);

    if (!rfb_crypto_sha512(workspace.m1_input, workspace.m1_input_len,
                           out->M1)) {
        goto cleanup;
    }
    out->M1_len = 64;
    result = RFB_OK;

cleanup:
    if (workspace.m1_input != NULL) {
        rfb_secret_zero(workspace.m1_input, workspace.m1_input_len);
        allocator->free(allocator, workspace.m1_input);
        workspace.m1_input = NULL;
    }
    rfb_secret_zero(&workspace, sizeof workspace);
    if (result != RFB_OK) {
        apple_srp_session_destroy(out);
    }
    return result;
}

bool apple_srp_derive_session_key_32(const apple_srp_session *session,
                                     uint8_t out_key[32])
{
    if (session == NULL || out_key == NULL) {
        return false;
    }
    // session_key_32 = SHA-256(K). wrap_key is the first 16 bytes.
    if (!rfb_crypto_sha256(session->K, 64, out_key)) {
        rfb_secret_zero(out_key, 32);
        return false;
    }
    return true;
}

bool apple_srp_derive_wrap_key(const apple_srp_session *session,
                                uint8_t wrap_key[16])
{
    if (session == NULL || wrap_key == NULL) return false;
    memset(wrap_key, 0, 16);
    uint8_t hash[32];
    if (!apple_srp_derive_session_key_32(session, hash)) {
        return false;
    }
    memcpy(wrap_key, hash, 16);
    rfb_secret_zero(hash, sizeof hash);
    return true;
}

rfb_error apple_srp_compute_m2(const apple_srp_session *session,
                                const uint8_t *B, size_t B_len,
                                uint8_t m2_out[APPLE_SRP_M1_BYTES])
{
    return apple_srp_compute_m2_with_allocator(
        session, B, B_len, m2_out, rfb_default_allocator());
}

rfb_error apple_srp_compute_m2_with_allocator(
    const apple_srp_session *session, const uint8_t *B, size_t B_len,
    uint8_t m2_out[APPLE_SRP_M1_BYTES], rfb_allocator *allocator)
{
    (void)B;      // B is in the challenge, not needed separately for M2
    (void)B_len;
    if (session == NULL || m2_out == NULL ||
        session->N_len > sizeof session->A || allocator == NULL ||
        allocator->alloc == NULL || allocator->free == NULL) {
        return RFB_ERR_INTERNAL;
    }

    // M2 = H(PAD(A) || M1 || K)
    // A is N-width, M1 is 64 bytes, K is 64 bytes.
    size_t N_len = session->N_len;
    size_t m2_len = N_len + 64 + 64;
    uint8_t *m2_input = (uint8_t *)allocator->alloc(allocator, m2_len);
    if (m2_input == NULL) return RFB_ERR_NOMEM;

    memcpy(m2_input, session->A, N_len);
    memcpy(m2_input + N_len, session->M1, 64);
    memcpy(m2_input + N_len + 64, session->K, 64);

    if (!rfb_crypto_sha512(m2_input, m2_len, m2_out)) {
        rfb_secret_zero(m2_input, m2_len);
        allocator->free(allocator, m2_input);
        rfb_secret_zero(m2_out, APPLE_SRP_M1_BYTES);
        return RFB_ERR_INTERNAL;
    }

    // Zeroize the input buffer (contains K, the session key).
    rfb_secret_zero(m2_input, m2_len);
    allocator->free(allocator, m2_input);
    return RFB_OK;
}

void apple_srp_session_destroy(apple_srp_session *session)
{
    if (session == NULL) return;
    rfb_secret_zero(session->a, sizeof session->a);
    rfb_secret_zero(session->x, sizeof session->x);
    rfb_secret_zero(session->S, sizeof session->S);
    rfb_secret_zero(session->K, sizeof session->K);
    rfb_secret_zero(session->M1, sizeof session->M1);
    rfb_secret_zero(session->A, sizeof session->A);
    session->a_len = 0;
    session->x_len = 0;
    session->S_len = 0;
    session->M1_len = 0;
    session->A_len = 0;
}

// ---- Packet 2 serialization ----------------------------------------------

rfb_error apple_srp_serialize_packet2(
    const apple_srp_session *session,
    const char *options, size_t options_len,
    const uint8_t client_random[16],
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (session == NULL || out == NULL || out_len == NULL ||
        client_random == NULL || (options_len > 0u && options == NULL)) {
        return RFB_ERR_INTERNAL;
    }
    if (session->N_len != APPLE_SRP_N_BYTES ||
        session->A_len != session->N_len ||
        session->M1_len != APPLE_SRP_M1_BYTES) {
        return RFB_ERR_PROTOCOL;
    }

    size_t N_len = session->N_len;

    // Compute inner size:
    //   u16_be A_len + A(512)
    //   u8 M1_len + M1(64)
    //   u16_be opt_len + options
    //   u8 cr_len + client_random(16)
    size_t inner_len = (2 + N_len) + (1 + session->M1_len) +
                       (2 + options_len) + (1 + 16);

    // meaningful_body = preamble(2) + inner_len(2) + inner
    size_t meaningful_len = 4 + inner_len;

    // total = version(2) + "RSA1"(4) + authtype(2) + meaningful_len(2) + meaningful + tail(384)
    // total_len counts everything after the leading u32 (including the tail).
    size_t total_len = 2 + 4 + 2 + 2 + meaningful_len + 384;

    // full = total_len_field(4) + total
    size_t full_len = 4 + total_len;

    if (full_len > out_cap) {
        return RFB_ERR_LIMIT;
    }

    rfb_writer w = rfb_writer_make(out, out_cap);

    // u32_be total_len
    if (!rfb_write_u32(&w, (uint32_t)total_len)) return RFB_ERR_LIMIT;
    // u16_be version = 0x0100
    if (!rfb_write_u16(&w, 0x0100)) return RFB_ERR_LIMIT;
    // "RSA1"
    if (!rfb_write_bytes(&w, "RSA1", 4)) return RFB_ERR_LIMIT;
    // u16_be authtype = 2
    if (!rfb_write_u16(&w, 2)) return RFB_ERR_LIMIT;
    // u16_be meaningful_body_len
    if (!rfb_write_u16(&w, (uint16_t)meaningful_len)) return RFB_ERR_LIMIT;
    // u16_be preamble = 0
    if (!rfb_write_u16(&w, 0)) return RFB_ERR_LIMIT;
    // u16_be inner_len
    if (!rfb_write_u16(&w, (uint16_t)inner_len)) return RFB_ERR_LIMIT;

    // Inner: %m A
    if (!rfb_write_u16(&w, (uint16_t)session->A_len)) return RFB_ERR_LIMIT;
    if (!rfb_write_bytes(&w, session->A, session->A_len)) return RFB_ERR_LIMIT;
    // %o M1
    if (!rfb_write_u8(&w, (uint8_t)session->M1_len)) return RFB_ERR_LIMIT;
    if (!rfb_write_bytes(&w, session->M1, session->M1_len)) return RFB_ERR_LIMIT;
    // %s options (exact echo)
    if (!rfb_write_u16(&w, (uint16_t)options_len)) return RFB_ERR_LIMIT;
    if (options_len > 0 && !rfb_write_bytes(&w, options, options_len)) {
        return RFB_ERR_LIMIT;
    }
    // %o client_random (16 bytes)
    if (!rfb_write_u8(&w, 16)) return RFB_ERR_LIMIT;
    if (!rfb_write_bytes(&w, client_random, 16)) return RFB_ERR_LIMIT;

    // 384-byte compatibility tail (zero-initialized)
    static const uint8_t tail[384];
    if (!rfb_write_bytes(&w, tail, sizeof tail)) return RFB_ERR_LIMIT;

    *out_len = w.length;
    return RFB_OK;
}

rfb_error apple_srp_serialize_type36_packet2(
    const apple_srp_session *session,
    const char *options, size_t options_len,
    const uint8_t client_random[16],
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (session == NULL || out == NULL || out_len == NULL ||
        client_random == NULL || (options_len > 0u && options == NULL)) {
        return RFB_ERR_INTERNAL;
    }
    if (session->N_len != APPLE_SRP_N_BYTES ||
        session->A_len != session->N_len ||
        session->M1_len != APPLE_SRP_M1_BYTES) {
        return RFB_ERR_PROTOCOL;
    }
    if (options_len > UINT16_MAX) {
        return RFB_ERR_LIMIT;
    }

    const size_t inner_len = (2u + session->A_len) +
                             (1u + session->M1_len) +
                             (2u + options_len) + (1u + 16u);
    const size_t total_len = 4u + inner_len;
    const size_t full_len = 4u + total_len;
    if (full_len > out_cap || inner_len > UINT32_MAX) {
        return RFB_ERR_LIMIT;
    }

    rfb_writer w = rfb_writer_make(out, out_cap);
    if (!rfb_write_u32(&w, (uint32_t)total_len) ||
        !rfb_write_u32(&w, (uint32_t)inner_len) ||
        !rfb_write_u16(&w, (uint16_t)session->A_len) ||
        !rfb_write_bytes(&w, session->A, session->A_len) ||
        !rfb_write_u8(&w, (uint8_t)session->M1_len) ||
        !rfb_write_bytes(&w, session->M1, session->M1_len) ||
        !rfb_write_u16(&w, (uint16_t)options_len) ||
        (options_len > 0u && !rfb_write_bytes(&w, options, options_len)) ||
        !rfb_write_u8(&w, 16u) ||
        !rfb_write_bytes(&w, client_random, 16u)) {
        return RFB_ERR_LIMIT;
    }

    *out_len = w.length;
    return RFB_OK;
}

// ---- Server response parser (RSA1 envelope + SecurityResult) --------------

rfb_error apple_srp_parse_auth_response(const uint8_t *data, size_t len,
                                        apple_srp_auth_response *out)
{
    if (data == NULL || out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    memset(out, 0, sizeof *out);

    rfb_reader r = rfb_reader_make(data, len);

    // RSA1 envelope header: u32_be total_len, u16_be version, u16_be authtype,
    // u16_be meaningful_body_len
    if (!rfb_read_u32(&r, &out->total_len)) return RFB_ERR_PROTOCOL;
    if (!rfb_read_u16(&r, &out->version)) return RFB_ERR_PROTOCOL;
    if (!rfb_read_u16(&r, &out->authtype)) return RFB_ERR_PROTOCOL;
    if (!rfb_read_u16(&r, &out->meaningful_len)) return RFB_ERR_PROTOCOL;

    // The envelope payload is total_len - 6 bytes (after the 6-byte fixed header
    // of version + authtype + meaningful_len).
    if (out->total_len < 6u) return RFB_ERR_PROTOCOL;
    size_t body_len = out->total_len - 6u;
    if (out->version != 0u || out->authtype != 2u ||
        out->meaningful_len != body_len) {
        return RFB_ERR_PROTOCOL;
    }

    // Read the body if non-empty.
    if (body_len > 0) {
        // Success case: body contains preamble(2) + inner_len(2) + inner
        if (body_len < 4u) return RFB_ERR_PROTOCOL;
        uint16_t preamble = 0, inner_len = 0;
        if (!rfb_read_u16(&r, &preamble)) return RFB_ERR_PROTOCOL;
        if (!rfb_read_u16(&r, &inner_len)) return RFB_ERR_PROTOCOL;
        if (preamble != 0u) return RFB_ERR_PROTOCOL;

        // Inner: %o M2 (u8 len + data) | %o server_random (u8 len + data)
        // M2
        uint8_t m2_len_byte = 0;
        if (!rfb_read_u8(&r, &m2_len_byte)) return RFB_ERR_PROTOCOL;
        if (m2_len_byte != APPLE_SRP_M1_BYTES) return RFB_ERR_PROTOCOL;
        out->M2_len = m2_len_byte;
        out->M2 = r.data + r.offset;
        if (!rfb_reader_skip(&r, m2_len_byte)) return RFB_ERR_PROTOCOL;

        // server_random
        uint8_t sr_len_byte = 0;
        if (!rfb_read_u8(&r, &sr_len_byte)) return RFB_ERR_PROTOCOL;
        if (sr_len_byte != 16u) return RFB_ERR_PROTOCOL;
        out->server_random_len = sr_len_byte;
        out->server_random = r.data + r.offset;
        if (!rfb_reader_skip(&r, sr_len_byte)) return RFB_ERR_PROTOCOL;

        // Skip any remaining inner bytes (trailing zeros etc.)
        size_t consumed_inner = 1u + m2_len_byte + 1u + sr_len_byte;
        if (inner_len < consumed_inner) return RFB_ERR_PROTOCOL;
        size_t trailing_inner = inner_len - consumed_inner;
        if (!rfb_reader_skip(&r, trailing_inner)) return RFB_ERR_PROTOCOL;
    }

    // After the envelope: u32_be SecurityResult
    if (!rfb_read_u32(&r, &out->security_result)) {
        return RFB_ERR_PROTOCOL;  // truncated: envelope without result
    }

    // Full consumption
    if (rfb_reader_remaining(&r) != 0u) {
        return RFB_ERR_PROTOCOL;
    }

    return RFB_OK;
}

rfb_error apple_srp_parse_type36_auth_response(
    const uint8_t *data, size_t len, apple_srp_auth_response *out)
{
    if (data == NULL || out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    memset(out, 0, sizeof *out);

    rfb_reader r = rfb_reader_make(data, len);
    if (len == 4u) {
        if (!rfb_read_u32(&r, &out->security_result) ||
            out->security_result != 1u) {
            return RFB_ERR_PROTOCOL;
        }
        return RFB_OK;
    }

    uint32_t inner_len = 0u;
    if (len < 100u || !rfb_read_u32(&r, &out->total_len) ||
        out->total_len != len - 8u || out->total_len < 4u ||
        !rfb_read_u32(&r, &inner_len) || inner_len > UINT16_MAX ||
        inner_len != out->total_len - 4u) {
        return RFB_ERR_PROTOCOL;
    }
    out->meaningful_len = (uint16_t)inner_len;

    uint8_t m2_len = 0u;
    if (!rfb_read_u8(&r, &m2_len) || m2_len != APPLE_SRP_M1_BYTES) {
        return RFB_ERR_PROTOCOL;
    }
    out->M2 = r.data + r.offset;
    out->M2_len = m2_len;
    if (!rfb_reader_skip(&r, m2_len)) {
        return RFB_ERR_PROTOCOL;
    }

    uint8_t random_len = 0u;
    if (!rfb_read_u8(&r, &random_len) || random_len != 16u) {
        return RFB_ERR_PROTOCOL;
    }
    out->server_random = r.data + r.offset;
    out->server_random_len = random_len;
    if (!rfb_reader_skip(&r, random_len)) {
        return RFB_ERR_PROTOCOL;
    }

    uint8_t compatibility[6];
    if (!rfb_read_bytes(&r, compatibility, sizeof compatibility) ||
        !srp_bytes_all_zero(compatibility, sizeof compatibility) ||
        !rfb_read_u32(&r, &out->security_result) ||
        rfb_reader_remaining(&r) != 0u) {
        return RFB_ERR_PROTOCOL;
    }
    return RFB_OK;
}
