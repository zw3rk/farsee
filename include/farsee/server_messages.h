// SPDX-License-Identifier: Apache-2.0
//
// farsee — server→client message parsers (plan.md §G6, RFC 6143 §7.6).
//
// Bell (§7.6.3) and ServerCutText (§7.6.4). These are message-type 2 and
// 3 respectively; they arrive interleaved with FramebufferUpdate (type 0).

#ifndef FARSEE_INCLUDE_FARSEE_SERVER_MESSAGES_H
#define FARSEE_INCLUDE_FARSEE_SERVER_MESSAGES_H

#include "farsee/buffer.h"
#include "farsee/bytes.h"
#include "farsee/error.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Bell: message-type 2, no payload. The reader has already consumed the
// type byte. Returns RFB_OK (the caller rings the terminal bell).
rfb_error rfb_parse_bell(rfb_reader *r);

// ServerCutText: message-type 3, u8 pad[3], u32 length, then length bytes.
// The text is stored into `out` (caller-allocated buffer); `cap` bounds it.
// `*out_len` receives the actual length. Returns RFB_ERR_LIMIT if the
// server's length exceeds the clipboard cap (plan.md §6.4: 16 MiB).
rfb_error rfb_parse_server_cut_text(rfb_reader *r,
                                    uint8_t *out, size_t cap, size_t *out_len,
                                    size_t hard_limit);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_SERVER_MESSAGES_H
