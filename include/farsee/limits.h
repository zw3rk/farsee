// SPDX-License-Identifier: Apache-2.0
//
// farsee — configurable hard limits (plan.md §6.4 "Default hard limits").
//
// These are conservative defaults for hostile-input defenses. Every limit
// is configurable at runtime through the session/config objects; these
// macros are the documented defaults and the values the boundary tests
// exercise at limit-1, limit, limit+1.

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
// Absolute ceiling on framebuffer bytes; a lower policy default applies.
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

// terminal reply cap
#define RFB_LIMIT_TERMINAL_REPLY_BYTES ((size_t)4096u)

// Configurable timeouts (milliseconds). Defaults chosen for LAN use.
#define RFB_LIMIT_CONNECT_TIMEOUT_MS ((uint32_t)15000u)
#define RFB_LIMIT_IO_TIMEOUT_MS      ((uint32_t)30000u)

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_LIMITS_H
