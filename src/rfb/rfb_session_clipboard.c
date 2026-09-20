// SPDX-License-Identifier: Apache-2.0
//
// Live RFB clipboard bridge. The protocol thread owns host polling, text
// conversion, policy enforcement, and ClientCutText queueing.

#include "rfb/rfb_session_internal.h"

#include "farsee/bytes.h"
#include "farsee/apple_wire_record.h"
#include "farsee/clipboard.h"
#include "farsee/input.h"
#include "farsee/limits.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define RFB_CLIPBOARD_POLL_MS 250u
// session_queue_bytes currently seals into a 4096-byte Apple record staging
// buffer. The first assertion proves the boundary fits; the second proves one
// additional text byte crosses it after 16-byte CBC padding.
#define RFB_CLIPBOARD_RECORD_WIRE_BYTES(text_bytes) \
    (2u + ((((text_bytes) + 8u + 2u + APPLE_WIRE_SHA1_LEN + 15u) / 16u) * 16u))
_Static_assert(
    RFB_CLIPBOARD_RECORD_WIRE_BYTES(
        RFB_SESSION_APPLE_CLIPBOARD_MAX_BYTES) <= 4096u,
    "Apple clipboard record boundary must fit staging");
_Static_assert(
    RFB_CLIPBOARD_RECORD_WIRE_BYTES(
        RFB_SESSION_APPLE_CLIPBOARD_MAX_BYTES + 1u) > 4096u,
    "Apple clipboard record boundary must be maximal");

static bool clipboard_active(const rfb_session *session)
{
    return session != NULL && session->cfg.clipboard_enabled &&
           !session->cfg.view_only &&
           session->cfg.clipboard_read_utf8 != NULL &&
           session->cfg.clipboard_write_utf8 != NULL;
}

static size_t clipboard_limit(const rfb_session *session)
{
    size_t limit = session->cfg.clipboard_max_bytes;
    if (limit == 0u) {
        limit = RFB_CLIP_DEFAULT_MAX_BYTES;
    }
    if (limit > RFB_LIMIT_CLIPBOARD_BYTES) {
        limit = RFB_LIMIT_CLIPBOARD_BYTES;
    }
    if (session->apple_records_active &&
        limit > RFB_SESSION_APPLE_CLIPBOARD_MAX_BYTES) {
        limit = RFB_SESSION_APPLE_CLIPBOARD_MAX_BYTES;
    }
    return limit;
}

static void *clipboard_alloc(rfb_session *session, size_t size)
{
    if (session == NULL || session->alloc == NULL ||
        session->alloc->alloc == NULL) {
        return NULL;
    }
    return session->alloc->alloc(session->alloc, size);
}

static void clipboard_free(rfb_session *session, void *pointer)
{
    if (session != NULL && session->alloc != NULL &&
        session->alloc->free != NULL && pointer != NULL) {
        session->alloc->free(session->alloc, pointer);
    }
}

static bool classic_latin1_to_utf8(rfb_session *session,
                                   const uint8_t *text, size_t length,
                                   uint8_t **out, size_t *out_length)
{
    if (out == NULL || out_length == NULL ||
        (text == NULL && length > 0u) ||
        length > (SIZE_MAX - 1u) / 2u) {
        return false;
    }
    *out = NULL;
    *out_length = 0u;
    uint8_t *converted = clipboard_alloc(session, length * 2u + 1u);
    if (converted == NULL) {
        return false;
    }
    size_t written = 0u;
    for (size_t i = 0u; i < length; i++) {
        const uint8_t byte = text[i];
        if (byte < 0x80u) {
            converted[written++] = byte;
        } else {
            converted[written++] = (uint8_t)(0xc0u | (byte >> 6u));
            converted[written++] = (uint8_t)(0x80u | (byte & 0x3fu));
        }
    }
    converted[written] = 0u;
    *out = converted;
    *out_length = written;
    return true;
}

static bool classic_utf8_to_latin1(rfb_session *session,
                                   const uint8_t *text, size_t length,
                                   uint8_t **out, size_t *out_length)
{
    if (out == NULL || out_length == NULL ||
        (text == NULL && length > 0u)) {
        return false;
    }
    *out = NULL;
    *out_length = 0u;
    uint8_t *converted = clipboard_alloc(session, length + 1u);
    if (converted == NULL) {
        return false;
    }
    size_t read_at = 0u;
    size_t written = 0u;
    while (read_at < length) {
        const uint8_t first = text[read_at];
        if (first < 0x80u) {
            converted[written++] = first;
            read_at++;
            continue;
        }
        // U+0080..U+00FF are exactly the valid C2/C3 two-byte forms.
        if ((first != 0xc2u && first != 0xc3u) ||
            read_at + 1u >= length || text[read_at + 1u] < 0x80u ||
            text[read_at + 1u] > 0xbfu) {
            clipboard_free(session, converted);
            return false;
        }
        converted[written++] = (uint8_t)(((first & 0x03u) << 6u) |
                                         (text[read_at + 1u] & 0x3fu));
        read_at += 2u;
    }
    converted[written] = 0u;
    *out = converted;
    *out_length = written;
    return true;
}

static bool apple_utf8_repair(rfb_session *session, const uint8_t *text,
                              size_t length, uint8_t **out,
                              size_t *out_length)
{
    if (out == NULL || out_length == NULL ||
        (text == NULL && length > 0u) ||
        length > (SIZE_MAX - 1u) / 3u) {
        return false;
    }
    *out = NULL;
    *out_length = 0u;
    const size_t capacity = length * 3u + 1u;
    uint8_t *repaired = clipboard_alloc(session, capacity);
    if (repaired == NULL) {
        return false;
    }
    size_t repaired_length = 0u;
    if (!rfb_clip_utf8_repair(text, length, repaired, capacity - 1u,
                              &repaired_length)) {
        clipboard_free(session, repaired);
        return false;
    }
    repaired[repaired_length] = 0u;
    *out = repaired;
    *out_length = repaired_length;
    return true;
}

void rfb_session_internal_receive_clipboard(rfb_session *session,
                                            const uint8_t *text,
                                            size_t length)
{
    if (!clipboard_active(session) || (text == NULL && length > 0u) ||
        length > clipboard_limit(session)) {
        return;
    }

    uint8_t *host_text = NULL;
    size_t host_length = 0u;
    const bool converted =
        session->dialect == RFB_SESSION_DIALECT_CLASSIC
            ? classic_latin1_to_utf8(session, text, length, &host_text,
                                     &host_length)
            : apple_utf8_repair(session, text, length, &host_text,
                                &host_length);
    if (!converted || host_text == NULL ||
        host_length > clipboard_limit(session)) {
        clipboard_free(session, host_text);
        return;
    }
    size_t sanitized_length = 0u;
    if (!rfb_clip_sanitize(host_text, host_length, host_text, host_length,
                           &sanitized_length)) {
        clipboard_free(session, host_text);
        return;
    }
    host_text[sanitized_length] = 0u;
    if (session->cfg.clipboard_write_utf8(
            session->cfg.clipboard_ctx, (const char *)host_text,
            sanitized_length)) {
        rfb_clip_loop_record_inbound(&session->clipboard_loop, host_text,
                                     sanitized_length);
    }
    clipboard_free(session, host_text);
}

static bool ensure_host_buffer(rfb_session *session, size_t limit)
{
    if (session->clipboard_host != NULL &&
        session->clipboard_host_cap >= limit + 1u) {
        return true;
    }
    uint8_t *replacement = clipboard_alloc(session, limit + 1u);
    if (replacement == NULL) {
        return false;
    }
    clipboard_free(session, session->clipboard_host);
    session->clipboard_host = replacement;
    session->clipboard_host_cap = limit + 1u;
    return true;
}

static rfb_error queue_client_cut_text(rfb_session *session,
                                       const uint8_t *text, size_t length)
{
    if (length > UINT32_MAX || length > SIZE_MAX - 8u) {
        return RFB_ERR_LIMIT;
    }
    const size_t message_length = length + 8u;
    uint8_t *message = clipboard_alloc(session, message_length);
    if (message == NULL) {
        return RFB_ERR_NOMEM;
    }
    rfb_writer writer = rfb_writer_make(message, message_length);
    rfb_error error = rfb_format_client_cut_text(
        &writer, text, (uint32_t)length);
    if (error == RFB_OK) {
        error = session_queue_bytes(session, message, writer.length);
    }
    clipboard_free(session, message);
    return error;
}

rfb_error rfb_session_internal_poll_clipboard(rfb_session *session,
                                              uint64_t now_ms)
{
    if (!clipboard_active(session) || now_ms < session->clipboard_next_poll_ms) {
        return RFB_OK;
    }
    session->clipboard_next_poll_ms =
        now_ms > UINT64_MAX - RFB_CLIPBOARD_POLL_MS
            ? UINT64_MAX
            : now_ms + RFB_CLIPBOARD_POLL_MS;

    const size_t limit = clipboard_limit(session);
    if (!ensure_host_buffer(session, limit)) {
        return RFB_ERR_NOMEM;
    }
    const long host_result = session->cfg.clipboard_read_utf8(
        session->cfg.clipboard_ctx, (char *)session->clipboard_host,
        session->clipboard_host_cap);
    if (host_result <= 0 || (size_t)host_result > limit) {
        return RFB_OK;
    }
    size_t host_length = (size_t)host_result;
    if (!rfb_clip_utf8_valid(session->clipboard_host, host_length)) {
        return RFB_OK;
    }
    size_t sanitized_length = 0u;
    if (!rfb_clip_sanitize(session->clipboard_host, host_length,
                           session->clipboard_host, limit,
                           &sanitized_length) || sanitized_length == 0u) {
        return RFB_OK;
    }

    const uint32_t local_hash = rfb_clip_fnv1a32(
        session->clipboard_host, sanitized_length);
    if (rfb_clip_loop_is_echo(&session->clipboard_loop,
                              session->clipboard_host, sanitized_length) ||
        (session->clipboard_has_last_local &&
         session->clipboard_last_local_hash == local_hash)) {
        return RFB_OK;
    }

    uint8_t *wire_text = session->clipboard_host;
    size_t wire_length = sanitized_length;
    bool wire_allocated = false;
    if (session->dialect == RFB_SESSION_DIALECT_CLASSIC) {
        if (!classic_utf8_to_latin1(session, session->clipboard_host,
                                    sanitized_length, &wire_text,
                                    &wire_length)) {
            return RFB_OK;
        }
        wire_allocated = true;
    }
    const rfb_error error =
        queue_client_cut_text(session, wire_text, wire_length);
    if (wire_allocated) {
        clipboard_free(session, wire_text);
    }
    if (error == RFB_OK) {
        session->clipboard_last_local_hash = local_hash;
        session->clipboard_has_last_local = true;
    }
    return error;
}
