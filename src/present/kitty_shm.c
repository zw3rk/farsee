// SPDX-License-Identifier: Apache-2.0
//
// farsee — Kitty POSIX shared-memory presenter (plan.md §G10, ADR-0005).
//
// Creates a one-shot POSIX shm object, writes raw pixel bytes into it,
// and emits the Kitty t=s command. The image bytes do NOT traverse the
// PTY — only the shm object name is base64-encoded into the command.

#include "farsee/kitty_shm.h"
#include "farsee/apple_crypto.h"
#include "farsee/base64.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

bool rfb_shm_generate_name(char *out, size_t out_cap)
{
    // Name format: /farsee-<16 hex chars>. Total = 1 + 7 + 16 + 1 = 25.
    // CSPRNG only (T15): never srand/rand — names must be unguessable and
    // thread-safe without clobbering process-global RNG state.
    if (out == NULL || out_cap < 25) {
        return false;
    }
    uint8_t rnd[8];
    if (!rfb_crypto_random_bytes(rnd, sizeof rnd)) {
        return false;
    }
    static const char hex[] = "0123456789abcdef";
    out[0] = '/';
    memcpy(out + 1, "farsee-", 7);
    for (int i = 0; i < 8; i++) {
        out[8 + 2 * i] = hex[(rnd[i] >> 4) & 0x0F];
        out[8 + 2 * i + 1] = hex[rnd[i] & 0x0F];
    }
    out[24] = '\0';
    return true;
}

rfb_error rfb_shm_transfer(rfb_buffer *out,
                           const uint8_t *rgba,
                           uint32_t width, uint32_t height,
                           kitty_format fmt,
                           uint32_t image_id,
                           uint32_t placement_id,
                           bool request_ack,
                           rfb_shm_table *table,
                           uint32_t place_cols,
                           uint32_t place_rows)
{
    if (out == NULL || rgba == NULL || width == 0 || height == 0) {
        return RFB_ERR_INTERNAL;
    }
    // Check the in-flight table: if full, fall back to direct (plan.md §G10).
    if (table != NULL && rfb_shm_table_full(table)) {
        return RFB_ERR_IO;  // caller falls back to direct transfer
    }
    // Determine bytes per pixel and total image size.
    uint32_t bpp = (fmt == KITTY_FMT_RGBA32) ? 4u : 3u;
    size_t total = (size_t)width * height * bpp;
    if (total == 0) {
        return RFB_ERR_INTERNAL;
    }
    // Generate an unpredictable shm name.
    char name[64];
    if (!rfb_shm_generate_name(name, sizeof name)) {
        return RFB_ERR_INTERNAL;
    }
    // Create the shm object with O_CREAT | O_EXCL, mode 0600.
    int fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) {
        return RFB_ERR_IO;  // caller falls back to direct
    }
    // ftruncate to the image size.
    if (ftruncate(fd, (off_t)total) != 0) {
        close(fd);
        shm_unlink(name);
        return RFB_ERR_IO;
    }
    // mmap, write pixel bytes, munmap.
    void *mapped = mmap(NULL, total, PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED) {
        close(fd);
        shm_unlink(name);
        return RFB_ERR_IO;
    }
    memcpy(mapped, rgba, total);
    munmap(mapped, total);
    close(fd);
    // Emit the Kitty t=s command: only the name is base64-encoded.
    // Control fields: f=<bpp>,s=<w>,v=<h>,t=s,i=<id>,p=<pid>,C=1,q=<ack>
    // optional c/r placement cells; payload is base64 shm name.
    char name_b64[128];
    size_t name_b64_len = rfb_base64_encode((const uint8_t *)name,
                                            strlen(name), name_b64, sizeof name_b64);
    // a=T required; C=1 keeps the cursor put. Placement is at the current
    // cursor (CLI homes before drain). ';' separates control from payload.
    char ctrl[224];
    int cn;
    if (place_cols > 0u && place_rows > 0u) {
        cn = snprintf(ctrl, sizeof ctrl,
                      "a=T,f=%u,s=%u,v=%u,t=s,i=%u,p=%u,C=1,q=%u,c=%u,r=%u,m=0",
                      (unsigned)fmt, (unsigned)width, (unsigned)height,
                      (unsigned)image_id, (unsigned)placement_id,
                      request_ack ? 0u : 2u,
                      (unsigned)place_cols, (unsigned)place_rows);
    } else if (place_rows > 0u) {
        cn = snprintf(ctrl, sizeof ctrl,
                      "a=T,f=%u,s=%u,v=%u,t=s,i=%u,p=%u,C=1,q=%u,r=%u,m=0",
                      (unsigned)fmt, (unsigned)width, (unsigned)height,
                      (unsigned)image_id, (unsigned)placement_id,
                      request_ack ? 0u : 2u, (unsigned)place_rows);
    } else if (place_cols > 0u) {
        cn = snprintf(ctrl, sizeof ctrl,
                      "a=T,f=%u,s=%u,v=%u,t=s,i=%u,p=%u,C=1,q=%u,c=%u,m=0",
                      (unsigned)fmt, (unsigned)width, (unsigned)height,
                      (unsigned)image_id, (unsigned)placement_id,
                      request_ack ? 0u : 2u, (unsigned)place_cols);
    } else {
        cn = snprintf(ctrl, sizeof ctrl,
                      "a=T,f=%u,s=%u,v=%u,t=s,i=%u,p=%u,C=1,q=%u,m=0",
                      (unsigned)fmt, (unsigned)width, (unsigned)height,
                      (unsigned)image_id, (unsigned)placement_id,
                      request_ack ? 0u : 2u);
    }
    if (cn <= 0 || (size_t)cn >= sizeof ctrl) {
        shm_unlink(name);
        return RFB_ERR_INTERNAL;
    }
    // Build the APC escape sequence: ESC_G <control>;<b64 name> ESC\.
    // Snapshot length so LIMIT/error rolls back only this APC suffix (loop
    // 68264760 r1: same contract as kitty_encode_direct truncate-to-mark).
    const size_t mark = rfb_buffer_length(out);
    static const uint8_t APC_START[] = { 0x1B, '_' };
    static const uint8_t APC_END[]   = { 0x1B, '\\' };
    rfb_error e = rfb_buffer_append(out, APC_START, sizeof APC_START);
    if (e != RFB_OK) {
        shm_unlink(name);
        rfb_buffer_truncate(out, mark);
        return e;
    }
    uint8_t g = 'G';
    e = rfb_buffer_append(out, &g, 1);
    if (e != RFB_OK) {
        shm_unlink(name);
        rfb_buffer_truncate(out, mark);
        return e;
    }
    e = rfb_buffer_append(out, ctrl, (size_t)cn);
    if (e != RFB_OK) {
        shm_unlink(name);
        rfb_buffer_truncate(out, mark);
        return e;
    }
    static const uint8_t sep = (uint8_t)';';
    e = rfb_buffer_append(out, &sep, 1);
    if (e != RFB_OK) {
        shm_unlink(name);
        rfb_buffer_truncate(out, mark);
        return e;
    }
    e = rfb_buffer_append(out, name_b64, name_b64_len);
    if (e != RFB_OK) {
        shm_unlink(name);
        rfb_buffer_truncate(out, mark);
        return e;
    }
    e = rfb_buffer_append(out, APC_END, sizeof APC_END);
    if (e != RFB_OK) {
        shm_unlink(name);
        rfb_buffer_truncate(out, mark);
        return e;
    }
    // Register in the in-flight table (for ack correlation + bounded tracking).
    if (table != NULL) {
        rfb_shm_table_add(table, name, image_id);
        // When a table is provided, defer the unlink to the session loop
        // (which unlinks after the terminal acknowledges or times out).
        // The table entry holds the name for deferred cleanup.
    } else {
        // No table: immediate unlink (the terminal reads bytes before
        // processing the command in the one-shot model).
        shm_unlink(name);
    }
    return RFB_OK;
}
