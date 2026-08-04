// SPDX-License-Identifier: Apache-2.0
//
// Type-33 post-auth wire probe.
//
// Continues past RSA1+SRP authentication and dumps the first server bytes
// after ServerInit + SetEncodings + full-screen FBUR so we can see whether
// the peer still speaks cleartext FramebufferUpdate (type 0) or opaque
// post-auth framing (possible AEAD).
//
// Build (via Makefile):
//   nix develop --command make type33-probe
//
// Usage:
//   build/dev/bin/type33_postauth_probe <host> <port> <username> <password-fd>
//
// Example:
//   printf 'admin' > /tmp/vncpw
//   build/dev/bin/type33_postauth_probe 127.0.0.1 5900 admin 3 3</tmp/vncpw
//
// Secrets: password is read from a file descriptor (never argv). No
// secrets are printed. wrap_key is zeroized before exit.

#include "farsee/apple_postauth.h"
#include "farsee/apple_type33_live.h"
#include "farsee/bytes.h"
#include "farsee/encoding.h"
#include "farsee/error.h"
#include "farsee/input.h"
#include "farsee/limits.h"
#include "farsee/secret.h"
#include "farsee/server_init.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Prefer ZRLE then Raw (matches the diagnostic intent; no pseudo-encodings).
static const int32_t k_probe_encodings[] = {
    RFB_ENCODING_ZRLE,
    RFB_ENCODING_RAW,
};

typedef struct probe_io_ctx {
    int fd;
} probe_io_ctx;

static int connect_to(const char *host, uint16_t port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *rp = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    (void)snprintf(port_str, sizeof port_str, "%u", (unsigned)port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }
    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static rfb_error probe_send_all(void *ctx, const uint8_t *data, size_t n)
{
    probe_io_ctx *c = (probe_io_ctx *)ctx;
    const uint8_t *p = data;
    while (n > 0u) {
        ssize_t w = send(c->fd, p, n, 0);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return RFB_ERR_IO;
        }
        if (w == 0) {
            return RFB_ERR_EOF;
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
    return RFB_OK;
}

static rfb_error probe_recv_exact(void *ctx, uint8_t *data, size_t n)
{
    probe_io_ctx *c = (probe_io_ctx *)ctx;
    uint8_t *p = data;
    while (n > 0u) {
        ssize_t r = recv(c->fd, p, n, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return RFB_ERR_IO;
        }
        if (r == 0) {
            return RFB_ERR_EOF;
        }
        p += (size_t)r;
        n -= (size_t)r;
    }
    return RFB_OK;
}

static void hexdump(const char *tag, const uint8_t *data, size_t len,
                    size_t max_dump)
{
    size_t n = len < max_dump ? len : max_dump;
    fprintf(stderr, "probe: %s len=%zu dump=%zu:",
            tag != NULL ? tag : "bytes", len, n);
    for (size_t i = 0; i < n; i++) {
        fprintf(stderr, " %02x", data[i]);
    }
    if (n < len) {
        fprintf(stderr, " ...");
    }
    fputc('\n', stderr);
}

static rfb_error read_server_init_blocking(probe_io_ctx *io, rfb_server_init *si)
{
    uint8_t hdr[24];
    rfb_error e = probe_recv_exact(io, hdr, sizeof hdr);
    if (e != RFB_OK) {
        return e;
    }
    uint32_t name_len = ((uint32_t)hdr[20] << 24) | ((uint32_t)hdr[21] << 16) |
                        ((uint32_t)hdr[22] << 8) | (uint32_t)hdr[23];
    if ((size_t)name_len > RFB_LIMIT_DESKTOP_NAME_BYTES) {
        return RFB_ERR_LIMIT;
    }
    size_t need = 24u + (size_t)name_len;
    uint8_t *buf = (uint8_t *)malloc(need);
    if (buf == NULL) {
        return RFB_ERR_NOMEM;
    }
    memcpy(buf, hdr, 24u);
    if (name_len > 0u) {
        e = probe_recv_exact(io, buf + 24u, (size_t)name_len);
        if (e != RFB_OK) {
            free(buf);
            return e;
        }
    }
    e = rfb_parse_server_init(buf, need, si, RFB_LIMIT_DESKTOP_NAME_BYTES);
    free(buf);
    return e;
}

// Accumulating non-blocking-ish recv with poll for up to timeout_ms.
// Returns number of bytes collected into buf (0 on timeout with no data).
static size_t recv_for_ms(int fd, uint8_t *buf, size_t cap, int timeout_ms)
{
    size_t got = 0;
    int remaining = timeout_ms;
    while (got < cap && remaining > 0) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int slice = remaining > 250 ? 250 : remaining;
        int pr = poll(&pfd, 1, slice);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (pr == 0) {
            remaining -= slice;
            continue;
        }
        if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            break;
        }
        if ((pfd.revents & POLLIN) == 0) {
            remaining -= slice;
            continue;
        }
        ssize_t r = recv(fd, buf + got, cap - got, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (r == 0) {
            break;  // peer closed
        }
        got += (size_t)r;
        remaining -= slice;
    }
    return got;
}

int main(int argc, char *argv[])
{
    if (argc != 5) {
        fprintf(stderr,
                "usage: %s <host> <port> <username> <password-fd>\n",
                argv[0]);
        return 2;
    }

    const char *host = argv[1];
    uint16_t port = (uint16_t)atoi(argv[2]);
    const char *username = argv[3];
    int pw_fd = atoi(argv[4]);

    uint8_t password[256];
    ssize_t pw_len = read(pw_fd, password, sizeof password - 1u);
    if (pw_len <= 0) {
        fprintf(stderr, "probe: failed to read password from fd %d\n", pw_fd);
        return 1;
    }
    while (pw_len > 0 &&
           (password[pw_len - 1] == (uint8_t)'\n' ||
            password[pw_len - 1] == (uint8_t)'\r')) {
        pw_len--;
    }

    int fd = connect_to(host, port);
    if (fd < 0) {
        fprintf(stderr, "probe: connect to %s:%u failed\n", host,
                (unsigned)port);
        rfb_secret_zero(password, sizeof password);
        return 1;
    }
    fprintf(stderr, "probe: connected to %s:%u\n", host, (unsigned)port);

    probe_io_ctx io_ctx;
    io_ctx.fd = fd;

    // Server banner (12 bytes), then client RFB 003.889.
    uint8_t server_banner[12];
    rfb_error e = probe_recv_exact(&io_ctx, server_banner, sizeof server_banner);
    if (e != RFB_OK) {
        fprintf(stderr, "probe: banner recv failed (%s)\n", rfb_strerror(e));
        goto fail;
    }
    fprintf(stderr, "probe: server banner=%.12s\n", (const char *)server_banner);

    static const uint8_t k_client_banner[12] = {
        'R', 'F', 'B', ' ', '0', '0', '3', '.', '8', '8', '9', '\n'
    };
    e = probe_send_all(&io_ctx, k_client_banner, sizeof k_client_banner);
    if (e != RFB_OK) {
        fprintf(stderr, "probe: client banner send failed\n");
        goto fail;
    }

    // Security types: u8 count + types.
    uint8_t sec_count = 0;
    e = probe_recv_exact(&io_ctx, &sec_count, 1u);
    if (e != RFB_OK || sec_count == 0u || sec_count > 64u) {
        fprintf(stderr, "probe: bad security type list\n");
        goto fail;
    }
    uint8_t offered[64];
    e = probe_recv_exact(&io_ctx, offered, (size_t)sec_count);
    if (e != RFB_OK) {
        fprintf(stderr, "probe: security types recv failed\n");
        goto fail;
    }
    fprintf(stderr, "probe: security types (%u):", (unsigned)sec_count);
    bool has_33 = false;
    for (uint8_t i = 0; i < sec_count; i++) {
        fprintf(stderr, " %u", (unsigned)offered[i]);
        if (offered[i] == 33u) {
            has_33 = true;
        }
    }
    fputc('\n', stderr);
    if (!has_33) {
        fprintf(stderr, "probe: type 33 not offered\n");
        goto fail;
    }

    // Type-33 auth (sends selector+key request as one frame).
    apple_type33_io t33;
    t33.send_all = probe_send_all;
    t33.recv_exact = probe_recv_exact;
    t33.ctx = &io_ctx;

    uint8_t wrap_key[16];
    memset(wrap_key, 0, sizeof wrap_key);
    e = apple_type33_authenticate(
        &t33,
        (const uint8_t *)username, strlen(username),
        password, (size_t)pw_len,
        wrap_key, NULL, 0, NULL);
    rfb_secret_zero(password, sizeof password);
    if (e != RFB_OK) {
        fprintf(stderr, "probe: type-33 auth failed: %s\n", rfb_strerror(e));
        rfb_secret_zero(wrap_key, sizeof wrap_key);
        goto fail_no_pw;
    }
    fprintf(stderr, "probe: type-33 AUTH OK (wrap_key derived, not printed)\n");
    rfb_secret_zero(wrap_key, sizeof wrap_key);

    // CAPTURED E8: live ClientInit byte 0xc1 (shared).
    {
        uint8_t ci = 0;
        size_t ci_len = 0;
        e = apple_postauth_serialize_client_init_live(true, &ci, 1u, &ci_len);
        if (e != RFB_OK) {
            fprintf(stderr, "probe: live ClientInit serialize failed\n");
            goto fail_no_pw;
        }
        e = probe_send_all(&io_ctx, &ci, ci_len);
        if (e != RFB_OK) {
            fprintf(stderr, "probe: ClientInit send failed\n");
            goto fail_no_pw;
        }
        fprintf(stderr, "probe: sent live ClientInit 0x%02x\n", (unsigned)ci);
    }

    rfb_server_init si;
    memset(&si, 0, sizeof si);
    e = read_server_init_blocking(&io_ctx, &si);
    if (e != RFB_OK) {
        fprintf(stderr, "probe: ServerInit failed: %s\n", rfb_strerror(e));
        goto fail_no_pw;
    }
    fprintf(stderr, "probe: ServerInit %ux%u name=\"%s\" (name_len=%u)\n",
            (unsigned)si.width, (unsigned)si.height,
            si.name != NULL ? si.name : "",
            (unsigned)si.name_length);

    // CAPTURED E8 ViewerInfo (74-byte live layout).
    {
        apple_viewer_info vi;
        memset(&vi, 0, sizeof vi);
        static const char k_dev[] = "farsee-probe";
        memcpy(vi.device_name, k_dev, sizeof k_dev - 1u);
        vi.name_len = sizeof k_dev - 1u;
        uint8_t vi_msg[APPLE_VIEWER_INFO_LIVE_LEN];
        size_t vi_len = 0;
        e = apple_postauth_serialize_viewer_info_live(&vi, vi_msg,
                                                      sizeof vi_msg, &vi_len);
        if (e != RFB_OK) {
            fprintf(stderr, "probe: ViewerInfo serialize failed\n");
            rfb_server_init_destroy(&si);
            goto fail_no_pw;
        }
        e = probe_send_all(&io_ctx, vi_msg, vi_len);
        if (e != RFB_OK) {
            fprintf(stderr, "probe: ViewerInfo send failed\n");
            rfb_server_init_destroy(&si);
            goto fail_no_pw;
        }
        fprintf(stderr, "probe: sent live ViewerInfo (%zu bytes)\n", vi_len);

        // Length-prefixed ack: u16be body_len + body (E8: 0x50; probe: 0x4a).
        uint8_t hdr[2];
        size_t nh = recv_for_ms(fd, hdr, 2u, 2000);
        if (nh < 2u) {
            fprintf(stderr, "probe: ViewerInfo ack header bytes=%zu\n", nh);
            fprintf(stderr, "probe: classify ack: silent/partial\n");
        } else {
            uint16_t body_len =
                (uint16_t)(((uint16_t)hdr[0] << 8) | (uint16_t)hdr[1]);
            fprintf(stderr, "probe: ViewerInfo ack body_len=%u (hdr=%02x%02x)\n",
                    (unsigned)body_len, hdr[0], hdr[1]);
            if (body_len > 0u && body_len <= APPLE_VIEWER_INFO_LIVE_ACK_BODY_MAX &&
                !(hdr[0] == 0x00u && hdr[1] == 0x00u)) {
                uint8_t body[APPLE_VIEWER_INFO_LIVE_ACK_BODY_MAX];
                size_t nb = recv_for_ms(fd, body, (size_t)body_len, 2000);
                fprintf(stderr, "probe: ViewerInfo ack body got=%zu/%u\n",
                        nb, (unsigned)body_len);
                fprintf(stderr,
                        "probe: classify ack: length-prefixed ViewerInfo reply\n");
            } else if (hdr[0] == 0x00u && hdr[1] == 0x00u) {
                fprintf(stderr,
                        "probe: classify ack: looks like cleartext FBU header\n");
                // Leave bytes unconsumed is impossible after read — note only.
            } else {
                fprintf(stderr, "probe: classify ack: unexpected length\n");
            }
        }
    }

    // SetEncodings (ZRLE, Raw).
    {
        uint8_t msg[4u + 2u * 4u];
        rfb_writer w = rfb_writer_make(msg, sizeof msg);
        e = rfb_format_set_encodings(
            &w, k_probe_encodings,
            (uint16_t)(sizeof k_probe_encodings / sizeof k_probe_encodings[0]));
        if (e != RFB_OK) {
            fprintf(stderr, "probe: SetEncodings format failed\n");
            rfb_server_init_destroy(&si);
            goto fail_no_pw;
        }
        e = probe_send_all(&io_ctx, msg, w.length);
        if (e != RFB_OK) {
            fprintf(stderr, "probe: SetEncodings send failed\n");
            rfb_server_init_destroy(&si);
            goto fail_no_pw;
        }
        fprintf(stderr, "probe: sent SetEncodings (ZRLE, Raw)\n");
    }

    // Full-screen non-incremental FBUR.
    {
        uint8_t msg[10];
        rfb_writer w = rfb_writer_make(msg, sizeof msg);
        e = rfb_format_framebuffer_update_request(
            &w, false, 0, 0, si.width, si.height);
        if (e != RFB_OK) {
            fprintf(stderr, "probe: FBUR format failed\n");
            rfb_server_init_destroy(&si);
            goto fail_no_pw;
        }
        e = probe_send_all(&io_ctx, msg, w.length);
        if (e != RFB_OK) {
            fprintf(stderr, "probe: FBUR send failed\n");
            rfb_server_init_destroy(&si);
            goto fail_no_pw;
        }
        fprintf(stderr, "probe: sent full-screen FBUR (%ux%u)\n",
                (unsigned)si.width, (unsigned)si.height);
    }
    rfb_server_init_destroy(&si);

    // Collect ~3 seconds of post-setup server bytes.
    uint8_t post[256];
    size_t got = recv_for_ms(fd, post, sizeof post, 3000);
    fprintf(stderr, "probe: post-auth server bytes received: %zu\n", got);
    if (got == 0u) {
        fprintf(stderr, "probe: no post-auth data in 3s (peer silent or waiting)\n");
        fprintf(stderr, "probe: classify: none\n");
        close(fd);
        return 0;
    }

    hexdump("post-auth first bytes", post, got, 256u);

    if (post[0] == 0u) {
        fprintf(stderr,
                "probe: classify: looks like cleartext FBU (byte0==0)\n");
        if (got >= 4u) {
            uint16_t nrects = (uint16_t)(((uint16_t)post[2] << 8) | post[3]);
            fprintf(stderr, "probe: FBU pad=%u nrects=%u\n",
                    (unsigned)post[1], (unsigned)nrects);
        }
    } else {
        fprintf(stderr,
                "probe: classify: unknown/maybe AEAD (byte0=0x%02x)\n",
                (unsigned)post[0]);
    }

    close(fd);
    fprintf(stderr, "probe: done\n");
    return 0;

fail:
    rfb_secret_zero(password, sizeof password);
fail_no_pw:
    close(fd);
    fprintf(stderr, "probe: FAILED\n");
    return 1;
}
