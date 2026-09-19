// SPDX-License-Identifier: Apache-2.0
//
// farsee — bounded big-endian byte reader/writer (plan.md §10.1).
//
// Reader operations bounds-check each access and never read past the end.
// A failed atomic read leaves the offset unchanged, so callers can probe
// for a complete field and retry after more input arrives.
//
// These helpers decode the fixed-width big-endian fields that call them.

#ifndef FARSEE_INCLUDE_FARSEE_BYTES_H
#define FARSEE_INCLUDE_FARSEE_BYTES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// A reader over a bounded byte slice. The reader does not own the data;
// the caller must keep it alive for the reader's lifetime.
typedef struct rfb_reader {
    const uint8_t *data;
    size_t length;
    size_t offset;
} rfb_reader;

// Initialize a reader over the given byte slice.
static inline rfb_reader rfb_reader_make(const void *data, size_t length)
{
    rfb_reader r;
    r.data = (const uint8_t *)data;
    r.length = length;
    r.offset = 0;
    return r;
}

// Bytes remaining between the current offset and the end.
size_t rfb_reader_remaining(const rfb_reader *r);

// Atomic reads. On failure they return false and leave the offset
// unchanged, so a caller can probe for a complete message and retry
// after more input arrives.
bool rfb_read_u8(rfb_reader *r, uint8_t *out);
bool rfb_read_u16(rfb_reader *r, uint16_t *out);   // big-endian
bool rfb_read_u32(rfb_reader *r, uint32_t *out);   // big-endian
bool rfb_read_bytes(rfb_reader *r, void *dst, size_t n);

// Peek without advancing (for header dispatch). Same atomicity contract.
bool rfb_peek_u8(const rfb_reader *r, size_t at, uint8_t *out);
bool rfb_peek_u16(const rfb_reader *r, size_t at, uint16_t *out);
bool rfb_peek_u32(const rfb_reader *r, size_t at, uint32_t *out);

// Skip n bytes without reading them. Returns false if n exceeds remaining.
bool rfb_reader_skip(rfb_reader *r, size_t n);

// Reset the offset to zero (used when reusing a reader on a fresh buffer).
void rfb_reader_reset(rfb_reader *r);

// ---- Writer --------------------------------------------------------------
// A writer appends big-endian fields into a caller-owned fixed buffer.
// Every append is bounds-checked; on failure the writer's state is left
// unchanged (no partial field is written) so callers can detect overflow
// without tearing.

typedef struct rfb_writer {
    uint8_t *data;
    size_t capacity;
    size_t length;
} rfb_writer;

static inline rfb_writer rfb_writer_make(void *data, size_t capacity)
{
    rfb_writer w;
    w.data = (uint8_t *)data;
    w.capacity = capacity;
    w.length = 0;
    return w;
}

bool rfb_write_u8(rfb_writer *w, uint8_t v);
bool rfb_write_u16(rfb_writer *w, uint16_t v);   // big-endian
bool rfb_write_u32(rfb_writer *w, uint32_t v);   // big-endian
bool rfb_write_bytes(rfb_writer *w, const void *src, size_t n);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_BYTES_H
