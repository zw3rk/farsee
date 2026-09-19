// SPDX-License-Identifier: Apache-2.0
//
// RFB server→client buffer demux and decode engine.
//
// Buffer in → progress out. No file descriptor or environment access.
// Owns incomplete FramebufferUpdate state. The caller supplies decode
// resources and optional side-effect hooks.

#ifndef FARSEE_INCLUDE_FARSEE_RFB_SERVER_ENGINE_H
#define FARSEE_INCLUDE_FARSEE_RFB_SERVER_ENGINE_H

#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/encoding.h"
#include "farsee/error.h"
#include "farsee/framebuffer.h"
#include "farsee/pacing.h"
#include "farsee/pixel_format.h"
#include "farsee/rfb_session.h"
#include "farsee/zlib_adapter.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Incremental demux state for one server→client stream. Zero-initialization is
// a valid clear state; rfb_server_engine_init performs that initialization.
typedef struct rfb_server_engine {
    bool in_fbupdate;
    uint16_t rects_remaining;
    uint16_t rects_total;
    uint16_t rects_decoded;
    // First unknown server message type (0 = none). Diagnostic only.
    uint8_t last_unexpected_type;
} rfb_server_engine;

void rfb_server_engine_init(rfb_server_engine *eng);

// Optional side-effect hooks. NULL hooks are no-ops (except decode still
// writes the framebuffer). hook_ctx is passed through unchanged. A non-OK
// error from an rfb_error-returning hook is propagated immediately.
typedef struct rfb_server_engine_hooks {
    void *hook_ctx;
    // Complete FBU (nrects fully decoded, or nrects==0).
    rfb_error (*on_publish)(void *hook_ctx);
    // Bell (RFC 6143 §7.6.3). May be NULL.
    void (*on_bell)(void *hook_ctx);
    // ServerCutText body (may be empty). text is borrowed from the input
    // buffer for the duration of the call only. May be NULL.
    void (*on_cut_text)(void *hook_ctx, const uint8_t *text, size_t len);
    // After FBU header accepted (nrects known). Optional CPU-probe seam.
    rfb_error (*on_fbu_begin)(void *hook_ctx, uint16_t nrects);
    // After a complete rectangle decodes, before its wire bytes are consumed.
    // payload is the borrowed byte range passed to the decoder and is valid
    // only during the call. Capture users must derive bounded metadata
    // synchronously and must not retain or log the bytes.
    rfb_error (*on_rect_decoded)(void *hook_ctx,
                                 const rfb_rect_header *rect,
                                 const uint8_t *payload, size_t payload_len);
    // After DesktopSize decode success. May be NULL (engine still resizes
    // the framebuffer via rfb_decode_desktopsize).
    void (*on_desktop_size)(void *hook_ctx, uint16_t width, uint16_t height);
} rfb_server_engine_hooks;

// Decode resources for one process_in call. All required pointers must be
// non-NULL. eng and in mutate. Decoders and hooks can update other resources.
typedef struct rfb_server_engine_ctx {
    rfb_server_engine *eng;
    rfb_buffer *in;
    rfb_framebuffer *fb;
    const rfb_pixel_format *pf;
    // Persistent ZRLE stream; required when a ZRLE rect arrives. May be
    // NULL if only Raw/CopyRect/Cursor/DesktopSize are expected.
    rfb_zlib_stream *zstream;
    rfb_cursor *cursor;
    rfb_allocator *alloc;
    // When non-NULL: update_received on FBU header; force_full_refresh
    // after DesktopSize.
    rfb_pacing *pacing;
    // Select classic or Apple-cleartext u16be control-record demux.
    rfb_session_dialect dialect;
    // Optional mirrored geometry (session desktop size). Updated on
    // DesktopSize when non-NULL.
    uint16_t *fb_width;
    uint16_t *fb_height;

    // skip_unknown affects only unrecognized Apple MultiVariant envelopes.
    // Malformed recognized type-0 bodies fail; the solid-black sample paints.
    bool mvs_skip_unknown;

    // Optional MVS quantization tables (from typed 0x03f3 QT message).
    // When non-NULL, both point to a 64-byte QT (luma / chroma) in RASTER
    // order: index = vertical frequency * 8 + horizontal frequency.
    const uint8_t *mvs_qt0;
    const uint8_t *mvs_qt1;

    // Optional coefficient-store argument forwarded to Apple MultiVariant decode.
    // The current type-0 entry point accepts but does not use it.
    struct apple_mvs_coeff_store *mvs_coeff_store;

    rfb_server_engine_hooks hooks;
} rfb_server_engine_ctx;

// Process complete server messages / rectangles currently in ctx->in.
//
// Returns:
//   RFB_OK     — progress made and/or more input needed (not a failure)
//   RFB_ERR_*  — hard protocol/limit/unsupported failure (fail closed)
//
// Sets *progress true when any input bytes were consumed.
// Fail-closed on unknown message types (records eng->last_unexpected_type).
rfb_error rfb_server_engine_process_in(rfb_server_engine_ctx *ctx,
                                       bool *progress);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_RFB_SERVER_ENGINE_H
