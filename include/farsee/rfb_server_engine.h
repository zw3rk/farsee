// SPDX-License-Identifier: Apache-2.0
//
// farsee — pure RFB server→client demux/decode engine.
//
// Buffer in → progress out. No fd, no getenv, no product essays.
// Owns incomplete FramebufferUpdate state; the session supplies the
// input buffer, framebuffer, pixel format, and optional hooks
// (publish / bell / cut text). Extracted from rfb_session (Q3).

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

// Incremental demux state for one server→client stream. Session embeds
// this (or owns one alongside the socket). Zero-init is a valid clear
// state; prefer rfb_server_engine_init for clarity.
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
// writes the framebuffer). hook_ctx is passed through unchanged.
typedef struct rfb_server_engine_hooks {
    void *hook_ctx;
    // Complete FBU (nrects fully decoded, or nrects==0).
    void (*on_publish)(void *hook_ctx);
    // Bell (RFC 6143 §7.6.3). May be NULL.
    void (*on_bell)(void *hook_ctx);
    // ServerCutText body (may be empty). text is borrowed from the input
    // buffer for the duration of the call only. May be NULL.
    void (*on_cut_text)(void *hook_ctx, const uint8_t *text, size_t len);
    // After FBU header accepted (nrects known). Optional CPU-probe seam.
    void (*on_fbu_begin)(void *hook_ctx, uint16_t nrects);
    // After DesktopSize decode success. May be NULL (engine still resizes
    // the framebuffer via rfb_decode_desktopsize).
    void (*on_desktop_size)(void *hook_ctx, uint16_t width, uint16_t height);
} rfb_server_engine_hooks;

// Decode resources for one process_in call. All non-optional pointers
// must be non-NULL. eng and in are mutated; fb/cursor may be written.
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
    // CLASSIC vs Apple cleartext control-record demux (u16be skip).
    rfb_session_dialect dialect;
    // Optional mirrored geometry (session desktop size). Updated on
    // DesktopSize when non-NULL.
    uint16_t *fb_width;
    uint16_t *fb_height;

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
