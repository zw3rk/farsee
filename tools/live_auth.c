// SPDX-License-Identifier: Apache-2.0
//
// G26 live VM authentication probe.
// Connects to a macOS Screen Sharing server, performs the full RSA1 + SRP
// type-33 authentication, and reports whether M2/SecurityResult succeed.
//
// Password is read from a file descriptor (never argv).
// No secrets are printed to stdout/stderr.
//
// Build:
//   cc -std=c11 -Wall -Wextra -Werror -Iinclude -Isrc \
//     tools/live_auth.c \
//     src/rfb/apple_srp.c src/rfb/apple_rsa1.c \
//     src/crypto/apple_crypto.c src/core/bytes.c \
//     src/io/outbound.c src/core/buffer.c src/core/secret.c \
//     -lcrypto -o build/live_auth
//
// Usage:
//   build/live_auth <host> <port> <username> <password-fd>
//
// Example:
//   printf 'admin' > /tmp/vncpw && build/live_auth 192.168.64.3 5900 admin 3 3< /tmp/vncpw

#include "farsee/apple_srp.h"
#include "farsee/apple_rsa1.h"
#include "farsee/apple_crypto.h"
#include "farsee/secret.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static int connect_to(const char *host, uint16_t port)
{
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof port_str, "%u", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }
    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static bool recv_exact(int fd, void *buf, size_t n)
{
    uint8_t *p = (uint8_t *)buf;
    while (n > 0) {
        ssize_t r = recv(fd, p, n, 0);
        if (r <= 0) return false;
        p += r;
        n -= (size_t)r;
    }
    return true;
}

static bool send_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        ssize_t w = send(fd, p, n, 0);
        if (w <= 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += w;
        n -= (size_t)w;
    }
    return true;
}

int main(int argc, char *argv[])
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s <host> <port> <username> <password-fd>\n", argv[0]);
        return 2;
    }

    const char *host = argv[1];
    uint16_t port = (uint16_t)atoi(argv[2]);
    const char *username = argv[3];
    int pw_fd = atoi(argv[4]);

    // Read password from fd (max 256 bytes)
    uint8_t password[256];
    ssize_t pw_len = read(pw_fd, password, sizeof password - 1);
    if (pw_len <= 0) {
        fprintf(stderr, "auth: failed to read password from fd %d\n", pw_fd);
        return 1;
    }
    // Strip trailing newline if present
    while (pw_len > 0 && (password[pw_len-1] == '\n' || password[pw_len-1] == '\r')) {
        pw_len--;
    }

    // Connect
    int fd = connect_to(host, port);
    if (fd < 0) {
        fprintf(stderr, "auth: connect failed\n");
        rfb_secret_zero(password, sizeof password);
        return 1;
    }
    fprintf(stderr, "auth: connected to %s:%u\n", host, port);

    // Banner exchange
    uint8_t server_banner[12];
    if (!recv_exact(fd, server_banner, 12)) {
        fprintf(stderr, "auth: banner recv failed\n");
        goto fail;
    }
    fprintf(stderr, "auth: banner=%.12s\n", server_banner);
    // Send RFB 003.889
    if (!send_all(fd, "RFB 003.889\n", 12)) goto fail;

    // Security types
    uint8_t sec_count;
    if (!recv_exact(fd, &sec_count, 1)) goto fail;
    uint8_t sec_types[16];
    if (!recv_exact(fd, sec_types, sec_count)) goto fail;
    fprintf(stderr, "auth: security types (%u):", sec_count);
    for (int i = 0; i < sec_count; i++) fprintf(stderr, " %u", sec_types[i]);
    fprintf(stderr, "\n");

    // Select type 33
    uint8_t sel = 33;
    if (!send_all(fd, &sel, 1)) goto fail;

    // Send key request (§3)
    uint8_t key_req[15];
    size_t kr_len = 0;
    if (apple_rsa1_serialize_key_request(key_req, sizeof key_req, &kr_len) != RFB_OK) {
        fprintf(stderr, "auth: key request serialize failed\n");
        goto fail;
    }
    if (!send_all(fd, key_req, kr_len)) goto fail;
    fprintf(stderr, "auth: sent key request (%zu bytes)\n", kr_len);

    // Receive key response
    // Read enough for the header first, then the full response
    uint8_t kr_hdr[10];
    if (!recv_exact(fd, kr_hdr, 10)) goto fail;
    uint32_t kr_total = ((uint32_t)kr_hdr[0] << 24) | ((uint32_t)kr_hdr[1] << 16) |
                        ((uint32_t)kr_hdr[2] << 8) | kr_hdr[3];
    uint16_t der_len = ((uint16_t)kr_hdr[8] << 8) | kr_hdr[9];
    size_t resp_len = 4 + kr_total;  // total_len field + payload
    fprintf(stderr, "auth: key response total=%u der_len=%u resp_len=%zu\n",
            kr_total, der_len, resp_len);

    // Read the rest of the key response
    uint8_t *key_resp = (uint8_t *)malloc(resp_len);
    if (key_resp == NULL) goto fail;
    memcpy(key_resp, kr_hdr, 10);
    if (!recv_exact(fd, key_resp + 10, resp_len - 10)) {
        free(key_resp);
        goto fail;
    }

    // Parse key response
    apple_rsa1_key_response kresp;
    if (apple_rsa1_parse_key_response(key_resp, resp_len, &kresp) != RFB_OK) {
        fprintf(stderr, "auth: key response parse failed\n");
        free(key_resp);
        goto fail;
    }
    fprintf(stderr, "auth: key response OK (der_len=%zu)\n", kresp.spki_len);

    // Build identity plaintext and encrypt
    uint8_t identity[256];
    size_t id_len = 0;
    size_t ulen = strlen(username);
    if (apple_rsa1_serialize_identity((const uint8_t *)username, ulen,
                                       identity, sizeof identity, &id_len) != RFB_OK) {
        fprintf(stderr, "auth: identity serialize failed\n");
        free(key_resp);
        goto fail;
    }

    uint8_t ciphertext[256];
    if (!apple_rsa1_encrypt_identity(kresp.spki_der, kresp.spki_len,
                                      identity, id_len, ciphertext)) {
        fprintf(stderr, "auth: RSA encrypt failed\n");
        rfb_secret_zero(identity, sizeof identity);
        free(key_resp);
        goto fail;
    }
    rfb_secret_zero(identity, sizeof identity);

    // Serialize and send packet 1
    uint8_t packet1[654];
    size_t p1_len = 0;
    if (apple_rsa1_serialize_packet1(ciphertext, packet1, sizeof packet1, &p1_len) != RFB_OK) {
        fprintf(stderr, "auth: packet1 serialize failed\n");
        free(key_resp);
        goto fail;
    }
    if (!send_all(fd, packet1, p1_len)) {
        free(key_resp);
        goto fail;
    }
    fprintf(stderr, "auth: sent packet 1 (%zu bytes)\n", p1_len);
    free(key_resp);

    // Receive SRP challenge
    // Read incrementally — first 4 bytes for total_len
    uint8_t ch_hdr[4];
    if (!recv_exact(fd, ch_hdr, 4)) goto fail;
    uint32_t ch_total = ((uint32_t)ch_hdr[0] << 24) | ((uint32_t)ch_hdr[1] << 16) |
                        ((uint32_t)ch_hdr[2] << 8) | ch_hdr[3];
    size_t ch_full = 4 + ch_total;
    fprintf(stderr, "auth: challenge total=%u full=%zu\n", ch_total, ch_full);

    uint8_t *challenge = (uint8_t *)malloc(ch_full);
    if (challenge == NULL) goto fail;
    memcpy(challenge, ch_hdr, 4);
    if (!recv_exact(fd, challenge + 4, ch_full - 4)) {
        free(challenge);
        goto fail;
    }
    fprintf(stderr, "auth: received challenge (%zu bytes)\n", ch_full);

    // Parse challenge
    apple_srp_challenge ch;
    if (apple_srp_parse_challenge(challenge, ch_full, &ch) != RFB_OK) {
        fprintf(stderr, "auth: challenge parse failed\n");
        free(challenge);
        goto fail;
    }
    fprintf(stderr, "auth: challenge OK (N=%zu g=%u iters=%u opt_len=%zu)\n",
            ch.N_len, ch.g[0], ch.iterations, ch.options_len);

    // Generate random private exponent 'a' (32 bytes, 256 bits)
    uint8_t a_secret[32];
    if (!rfb_crypto_random_bytes(a_secret, sizeof a_secret)) {
        fprintf(stderr, "auth: RNG failed\n");
        free(challenge);
        goto fail;
    }

    // Compute SRP client
    apple_srp_session sess;
    rfb_error e = apple_srp_compute_client(&ch,
        (const uint8_t *)username, strlen(username),
        password, (size_t)pw_len,
        a_secret, sizeof a_secret,
        &sess);
    if (e != RFB_OK) {
        fprintf(stderr, "auth: SRP compute failed: %d\n", e);
        rfb_secret_zero(a_secret, sizeof a_secret);
        free(challenge);
        goto fail;
    }
    fprintf(stderr, "auth: SRP computed (A=%zu M1=%zu)\n", sess.A_len, sess.M1_len);

    // Generate client_random
    uint8_t client_random[16];
    rfb_crypto_random_bytes(client_random, sizeof client_random);

    // Serialize packet 2
    uint8_t packet2[2048];
    size_t p2_len = 0;
    e = apple_srp_serialize_packet2(&sess,
        (const char *)ch.options, ch.options_len,
        client_random,
        packet2, sizeof packet2, &p2_len);
    if (e != RFB_OK) {
        fprintf(stderr, "auth: packet2 serialize failed: %d\n", e);
        apple_srp_session_destroy(&sess);
        rfb_secret_zero(a_secret, sizeof a_secret);
        free(challenge);
        goto fail;
    }

    // Send packet 2
    if (!send_all(fd, packet2, p2_len)) {
        apple_srp_session_destroy(&sess);
        rfb_secret_zero(a_secret, sizeof a_secret);
        free(challenge);
        goto fail;
    }
    fprintf(stderr, "auth: sent packet 2 (%zu bytes)\n", p2_len);

    // Zeroize secrets immediately after sending
    rfb_secret_zero(a_secret, sizeof a_secret);
    apple_srp_session_destroy(&sess);

    // Receive server response (M2 envelope + SecurityResult, or FIN/RST)
    // The response may arrive in multiple TCP segments. Read the envelope
    // header first, then read the remaining bytes based on total_len.
    uint8_t resp_hdr[10];  // u32 total_len + u16 ver + u16 authtype + u16 body_len
    if (!recv_exact(fd, resp_hdr, 10)) {
        fprintf(stderr, "auth: FIN/RST or timeout reading response header\n");
        free(challenge);
        goto fail;
    }
    uint32_t resp_total = ((uint32_t)resp_hdr[0] << 24) | ((uint32_t)resp_hdr[1] << 16) |
                          ((uint32_t)resp_hdr[2] << 8) | resp_hdr[3];
    // total_len is the bytes after the u32 itself.
    size_t resp_full = 4u + resp_total + 4u;  // u32 + envelope + SecurityResult
    fprintf(stderr, "auth: response total_len=%u, expecting %zu bytes\n",
            resp_total, resp_full);

    uint8_t resp[8192];
    memcpy(resp, resp_hdr, 10);
    if (!recv_exact(fd, resp + 10, resp_full - 10)) {
        fprintf(stderr, "auth: FIN/RST reading response body\n");
        free(challenge);
        goto fail;
    }
    fprintf(stderr, "auth: received %zu bytes (complete response)\n", resp_full);

    // Parse the response using the proper parser
    apple_srp_auth_response auth_resp;
    rfb_error parse_err = apple_srp_parse_auth_response(resp, resp_full, &auth_resp);
    if (parse_err != RFB_OK) {
        fprintf(stderr, "auth: response parse failed: %d\n", parse_err);
        free(challenge);
        goto fail;
    }

    fprintf(stderr, "auth: SecurityResult=%u\n", auth_resp.security_result);
    if (auth_resp.security_result == 0) {
        fprintf(stderr, "auth: *** AUTHENTICATION SUCCEEDED ***\n");
        if (auth_resp.M2 != NULL && auth_resp.M2_len > 0) {
            fprintf(stderr, "auth: M2 received (%zu bytes)\n", auth_resp.M2_len);
        }
        if (auth_resp.server_random != NULL) {
            fprintf(stderr, "auth: server_random received (%zu bytes)\n",
                    auth_resp.server_random_len);
        }
    } else {
        fprintf(stderr, "auth: AUTHENTICATION REJECTED (result=%u)\n",
                auth_resp.security_result);
        free(challenge);
        goto fail;
    }

    free(challenge);
    close(fd);
    rfb_secret_zero(password, sizeof password);
    fprintf(stderr, "auth: done\n");
    return 0;

fail:
    rfb_secret_zero(password, sizeof password);
    close(fd);
    fprintf(stderr, "auth: FAILED\n");
    return 1;
}
