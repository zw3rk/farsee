// SPDX-License-Identifier: Apache-2.0
//
// farsee — bounded big-endian byte reader/writer (plan.md §10.1, §G1).
//
// Implementation rules:
//   - every access is bounds-checked;
//   - a failed atomic read leaves the offset unchanged (transactional);
//   - no wire buffer is ever cast to a packed struct (plan.md §15.3).

#include "farsee/bytes.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// ---- reader -------------------------------------------------------------

size_t rfb_reader_remaining(const rfb_reader *r)
{
    if (r == NULL || r->offset > r->length) {
        return 0;
    }
    return r->length - r->offset;
}

bool rfb_read_u8(rfb_reader *r, uint8_t *out)
{
    if (r == NULL || out == NULL) {
        return false;
    }
    if (rfb_reader_remaining(r) < 1) {
        return false;
    }
    *out = r->data[r->offset];
    r->offset += 1;
    return true;
}

bool rfb_read_u16(rfb_reader *r, uint16_t *out)
{
    if (r == NULL || out == NULL) {
        return false;
    }
    if (rfb_reader_remaining(r) < 2) {
        return false;
    }
    size_t o = r->offset;
    // Big-endian: high byte first (RFC 6143 §6.4.1).
    uint16_t v = (uint16_t)(((uint16_t)r->data[o] << 8) | (uint16_t)r->data[o + 1]);
    *out = v;
    r->offset = o + 2;
    return true;
}

bool rfb_read_u32(rfb_reader *r, uint32_t *out)
{
    if (r == NULL || out == NULL) {
        return false;
    }
    if (rfb_reader_remaining(r) < 4) {
        return false;
    }
    size_t o = r->offset;
    uint32_t v = ((uint32_t)r->data[o] << 24)
               | ((uint32_t)r->data[o + 1] << 16)
               | ((uint32_t)r->data[o + 2] << 8)
               | (uint32_t)r->data[o + 3];
    *out = v;
    r->offset = o + 4;
    return true;
}

bool rfb_read_bytes(rfb_reader *r, void *dst, size_t n)
{
    if (r == NULL || dst == NULL) {
        return false;
    }
    if (n == 0) {
        return true;  // reading zero bytes is trivially successful
    }
    if (rfb_reader_remaining(r) < n) {
        return false;  // transactional: do not partial-fill dst
    }
    memcpy(dst, r->data + r->offset, n);
    r->offset += n;
    return true;
}

bool rfb_peek_u8(const rfb_reader *r, size_t at, uint8_t *out)
{
    if (r == NULL || out == NULL) {
        return false;
    }
    if (at >= r->length) {
        return false;
    }
    *out = r->data[at];
    return true;
}

bool rfb_peek_u16(const rfb_reader *r, size_t at, uint16_t *out)
{
    if (r == NULL || out == NULL) {
        return false;
    }
    if (r->length - at < 2) {
        return false;
    }
    *out = (uint16_t)(((uint16_t)r->data[at] << 8) | (uint16_t)r->data[at + 1]);
    return true;
}

bool rfb_peek_u32(const rfb_reader *r, size_t at, uint32_t *out)
{
    if (r == NULL || out == NULL) {
        return false;
    }
    if (r->length - at < 4) {
        return false;
    }
    *out = ((uint32_t)r->data[at] << 24)
         | ((uint32_t)r->data[at + 1] << 16)
         | ((uint32_t)r->data[at + 2] << 8)
         | (uint32_t)r->data[at + 3];
    return true;
}

bool rfb_reader_skip(rfb_reader *r, size_t n)
{
    if (r == NULL) {
        return false;
    }
    if (rfb_reader_remaining(r) < n) {
        return false;
    }
    r->offset += n;
    return true;
}

void rfb_reader_reset(rfb_reader *r)
{
    if (r != NULL) {
        r->offset = 0;
    }
}

// ---- writer -------------------------------------------------------------

bool rfb_write_u8(rfb_writer *w, uint8_t v)
{
    if (w == NULL) {
        return false;
    }
    if (w->length + 1 > w->capacity) {
        return false;
    }
    w->data[w->length] = v;
    w->length += 1;
    return true;
}

bool rfb_write_u16(rfb_writer *w, uint16_t v)
{
    if (w == NULL) {
        return false;
    }
    if (w->length + 2 > w->capacity) {
        return false;  // transactional: do not write half a field
    }
    size_t o = w->length;
    w->data[o]     = (uint8_t)(v >> 8);
    w->data[o + 1] = (uint8_t)(v & 0xFFu);
    w->length = o + 2;
    return true;
}

bool rfb_write_u32(rfb_writer *w, uint32_t v)
{
    if (w == NULL) {
        return false;
    }
    if (w->length + 4 > w->capacity) {
        return false;
    }
    size_t o = w->length;
    w->data[o]     = (uint8_t)((v >> 24) & 0xFFu);
    w->data[o + 1] = (uint8_t)((v >> 16) & 0xFFu);
    w->data[o + 2] = (uint8_t)((v >> 8) & 0xFFu);
    w->data[o + 3] = (uint8_t)(v & 0xFFu);
    w->length = o + 4;
    return true;
}

bool rfb_write_bytes(rfb_writer *w, const void *src, size_t n)
{
    if (w == NULL) {
        return false;
    }
    if (n == 0) {
        return true;
    }
    if (src == NULL) {
        return false;
    }
    if (w->length + n > w->capacity) {
        return false;
    }
    memcpy(w->data + w->length, src, n);
    w->length += n;
    return true;
}
