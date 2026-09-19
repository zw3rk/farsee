// SPDX-License-Identifier: Apache-2.0
//
// farsee — shared hard-limit constants.
//
// These constants cover framebuffer geometry and bytes, server-controlled data,
// queues, rectangle counts, terminal replies, and timeouts. Callers select
// which constants they enforce; some interfaces accept stricter runtime policy
// values.

#ifndef FARSEE_INCLUDE_FARSEE_LIMITS_H
#define FARSEE_INCLUDE_FARSEE_LIMITS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// framebuffer geometry
#define RFB_LIMIT_FB_WIDTH_MAX       ((uint32_t)16384u)
#define RFB_LIMIT_FB_HEIGHT_MAX      ((uint32_t)16384u)
// Framebuffer byte constants: absolute ceiling and lower policy default.
#define RFB_LIMIT_FB_BYTES_ABSOLUTE  ((size_t)1024u * 1024u * 1024u)  // 1 GiB
#define RFB_LIMIT_FB_BYTES_POLICY    ((size_t)256u  * 1024u * 1024u)  // 256 MiB

// server-controlled string lengths
#define RFB_LIMIT_DESKTOP_NAME_BYTES ((size_t)1024u * 1024u)          // 1 MiB
#define RFB_LIMIT_CLIPBOARD_BYTES    ((size_t)16u * 1024u * 1024u)    // 16 MiB
#define RFB_LIMIT_COMPRESSED_RECT_BYTES ((size_t)256u * 1024u * 1024u)// 256 MiB

// queue bounds
#define RFB_LIMIT_OUTBOUND_BYTES     ((size_t)8u * 1024u * 1024u)     // 8 MiB
#define RFB_LIMIT_PRESENTATION_BYTES ((size_t)128u * 1024u * 1024u)   // 128 MiB

// rectangle count per FramebufferUpdate (the protocol field is uint16)
#define RFB_LIMIT_RECTS_PER_UPDATE   ((uint16_t)0xFFFFu)

// terminal reply byte-cap constant
#define RFB_LIMIT_TERMINAL_REPLY_BYTES ((size_t)4096u)

// timeout constants (milliseconds)
#define RFB_LIMIT_CONNECT_TIMEOUT_MS ((uint32_t)15000u)
#define RFB_LIMIT_IO_TIMEOUT_MS      ((uint32_t)30000u)

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_LIMITS_H
