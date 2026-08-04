// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP cliprdr client wiring (R6 plain-text clipboard, §15.13).
//
// Text-only cliprdr against FreeRDP 3.x. Policy via rdp_clipboard_bridge;
// host pasteboard via rdp_host_clipboard. FreeRDP/WinPR types confined
// to this file. Single-worker model matches rdp_callbacks.c.

#include "rdp_cliprdr.h"
#include "rdp_clipboard_bridge.h"
#include "rdp_host_clipboard.h"

#include <freerdp/addin.h>
#include <freerdp/channels/cliprdr.h>
#include <freerdp/client/channels.h>
#include <freerdp/client/cliprdr.h>
#include <freerdp/client.h>
#include <freerdp/event.h>
#include <freerdp/freerdp.h>

#include <winpr/crt.h>
#include <winpr/string.h>
#include <winpr/user.h>
#include <winpr/wtsapi.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Max host pasteboard read for outbound offers (matches F5 default 1 MiB).
#define RDP_CLIPRDR_HOST_CAP (1024u * 1024u)

// Single-worker cliprdr state (policy process-local; presenters live on
// FreeRDP custom context — see rdp_callbacks.c P5).
static farsee_clip_policy g_policy;
static bool g_policy_valid = false;
static bool g_enabled = false;
static bool g_addin_registered = false;
static bool g_pubsub_subscribed = false;

// Preferred format announced by the last ServerFormatList (for request).
static UINT32 g_server_format_id = 0;
static bool g_server_has_text = false;

bool rdp_cliprdr_is_enabled(void)
{
    return g_enabled;
}

// --- helpers ---------------------------------------------------------------

static UINT rdp_cliprdr_send_fail(CliprdrClientContext *clip)
{
    CLIPRDR_FORMAT_DATA_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));
    resp.common.msgFlags = CB_RESPONSE_FAIL;
    resp.common.dataLen = 0;
    resp.requestedFormatData = NULL;
    if (clip == NULL || clip->ClientFormatDataResponse == NULL) {
        return CHANNEL_RC_BAD_PROC;
    }
    return clip->ClientFormatDataResponse(clip, &resp);
}

// Convert host UTF-8 to a CF_UNICODETEXT payload (UTF-16LE + terminating
// double-NUL). On success *out_data is malloc'd and *out_len is the byte
// length including the 2-byte NUL. Caller frees *out_data.
static bool rdp_cliprdr_utf8_to_utf16le(const char *utf8, size_t utf8_len,
                                        BYTE **out_data, UINT32 *out_len)
{
    if (out_data == NULL || out_len == NULL) {
        return false;
    }
    *out_data = NULL;
    *out_len = 0;
    if (utf8 == NULL) {
        utf8 = "";
        utf8_len = 0;
    }
    size_t wlen = 0;
    WCHAR *w = ConvertUtf8NToWCharAlloc(utf8, utf8_len, &wlen);
    if (w == NULL) {
        return false;
    }
    // Payload is wlen WCHARs + 1 terminating L'\0' already present in w.
    // ConvertUtf8NToWCharAlloc returns zero-terminated; byte size is
    // (wlen + 1) * sizeof(WCHAR).
    size_t bytes = (wlen + 1u) * sizeof(WCHAR);
    if (bytes > UINT32_MAX) {
        free(w);
        return false;
    }
    *out_data = (BYTE *)w;
    *out_len = (UINT32)bytes;
    return true;
}

// Convert CF_UNICODETEXT / CF_TEXT payload to a freshly malloc'd UTF-8
// string (NUL-terminated). Returns length excluding NUL, or -1.
// Caller frees *out_utf8.
static long rdp_cliprdr_payload_to_utf8(UINT32 format_id,
                                        const BYTE *data, UINT32 data_len,
                                        char **out_utf8)
{
    if (out_utf8 == NULL) {
        return -1;
    }
    *out_utf8 = NULL;
    if (data == NULL || data_len == 0) {
        char *empty = (char *)calloc(1, 1);
        if (empty == NULL) {
            return -1;
        }
        *out_utf8 = empty;
        return 0;
    }

    if (format_id == CF_UNICODETEXT) {
        // data_len may or may not include the terminating double-NUL.
        size_t wchars = data_len / sizeof(WCHAR);
        const WCHAR *w = (const WCHAR *)(const void *)data;
        // Exclude trailing NULs from the character count for conversion.
        while (wchars > 0 && w[wchars - 1] == 0) {
            wchars--;
        }
        size_t ulen = 0;
        char *u = ConvertWCharNToUtf8Alloc(w, wchars, &ulen);
        if (u == NULL) {
            return -1;
        }
        *out_utf8 = u;
        return (long)ulen;
    }

    if (format_id == CF_TEXT) {
        // CF_TEXT is Windows ANSI/Latin-1 family: expand to UTF-8 so bare
        // C1 (0x80–0x9F) becomes C2 8x/9x and farsee_clip_sanitize_text
        // can neutralize them (reaudit T3). Never raw-memcpy as UTF-8.
        char *u = NULL;
        size_t n = farsee_latin1_to_utf8_alloc(data, data_len, &u);
        if (n == (size_t)-1 || u == NULL) {
            return -1;
        }
        *out_utf8 = u;
        return (long)n;
    }
    return -1;
}

// --- cliprdr callbacks -----------------------------------------------------

static UINT rdp_cliprdr_monitor_ready(CliprdrClientContext *context,
                                      const CLIPRDR_MONITOR_READY *monitorReady)
{
    (void)monitorReady;
    if (context == NULL) {
        return CHANNEL_RC_BAD_PROC;
    }

    // ClientCapabilities: long format names, no file-clipboard flags.
    CLIPRDR_GENERAL_CAPABILITY_SET general;
    memset(&general, 0, sizeof(general));
    general.capabilitySetType = CB_CAPSTYPE_GENERAL;
    general.capabilitySetLength = CB_CAPSTYPE_GENERAL_LEN;
    general.version = CB_CAPS_VERSION_2;
    general.generalFlags = CB_USE_LONG_FORMAT_NAMES;

    CLIPRDR_CAPABILITIES caps;
    memset(&caps, 0, sizeof(caps));
    caps.cCapabilitiesSets = 1;
    caps.capabilitySets = (CLIPRDR_CAPABILITY_SET *)&general;

    if (context->ClientCapabilities != NULL) {
        UINT rc = context->ClientCapabilities(context, &caps);
        if (rc != CHANNEL_RC_OK) {
            return rc;
        }
    }

    // ClientFormatList: advertise CF_UNICODETEXT when outbound is allowed
    // and the host pasteboard currently has text; else empty list.
    CLIPRDR_FORMAT formats[1];
    memset(formats, 0, sizeof(formats));
    UINT32 num = 0;

    if (g_policy_valid &&
        rdp_clip_allows_outbound(&g_policy, /*bytes=*/1)) {
        // Heap: RDP_CLIPRDR_HOST_CAP is 1 MiB; FreeRDP worker stacks on
        // macOS are often 512 KiB (T22).
        char *host = (char *)malloc((size_t)RDP_CLIPRDR_HOST_CAP + 1u);
        if (host != NULL) {
            long n = rdp_host_clipboard_get_utf8(host,
                                                 (size_t)RDP_CLIPRDR_HOST_CAP +
                                                     1u);
            if (n > 0) {
                formats[0].formatId = CF_UNICODETEXT;
                formats[0].formatName = NULL;
                num = 1;
            }
            free(host);
        }
    }

    CLIPRDR_FORMAT_LIST list;
    memset(&list, 0, sizeof(list));
    list.common.msgType = CB_FORMAT_LIST;
    list.numFormats = num;
    list.formats = (num > 0) ? formats : NULL;

    if (context->ClientFormatList == NULL) {
        return CHANNEL_RC_BAD_PROC;
    }
    return context->ClientFormatList(context, &list);
}

static UINT rdp_cliprdr_server_capabilities(
    CliprdrClientContext *context, const CLIPRDR_CAPABILITIES *capabilities)
{
    (void)context;
    (void)capabilities;
    // Server caps are informational for the text-only path; file flags
    // are ignored (we never advertise file support).
    return CHANNEL_RC_OK;
}

static UINT rdp_cliprdr_server_format_list(
    CliprdrClientContext *context, const CLIPRDR_FORMAT_LIST *formatList)
{
    if (context == NULL || formatList == NULL) {
        return CHANNEL_RC_BAD_PROC;
    }

    // Acknowledge the list.
    if (context->ClientFormatListResponse != NULL) {
        CLIPRDR_FORMAT_LIST_RESPONSE resp;
        memset(&resp, 0, sizeof(resp));
        resp.common.msgType = CB_FORMAT_LIST_RESPONSE;
        resp.common.msgFlags = CB_RESPONSE_OK;
        (void)context->ClientFormatListResponse(context, &resp);
    }

    g_server_has_text = false;
    g_server_format_id = 0;

    // Prefer CF_UNICODETEXT, fall back to CF_TEXT.
    UINT32 prefer = 0;
    bool found_uni = false;
    bool found_text = false;
    for (UINT32 i = 0; i < formatList->numFormats; i++) {
        const CLIPRDR_FORMAT *f = &formatList->formats[i];
        if (f == NULL) {
            continue;
        }
        if (f->formatId == CF_UNICODETEXT) {
            found_uni = true;
            prefer = CF_UNICODETEXT;
        } else if (f->formatId == CF_TEXT) {
            found_text = true;
            if (!found_uni) {
                prefer = CF_TEXT;
            }
        }
    }
    (void)found_text;

    if (prefer == 0) {
        return CHANNEL_RC_OK;  // no plain text offered
    }

    // Only request if inbound is allowed under policy.
    if (!g_policy_valid ||
        !farsee_clip_policy_allows(&g_policy,
                                   FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL)) {
        return CHANNEL_RC_OK;
    }

    g_server_has_text = true;
    g_server_format_id = prefer;
    context->lastRequestedFormatId = prefer;

    if (context->ClientFormatDataRequest == NULL) {
        return CHANNEL_RC_BAD_PROC;
    }
    CLIPRDR_FORMAT_DATA_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.requestedFormatId = prefer;
    return context->ClientFormatDataRequest(context, &req);
}

static UINT rdp_cliprdr_server_format_data_response(
    CliprdrClientContext *context,
    const CLIPRDR_FORMAT_DATA_RESPONSE *formatDataResponse)
{
    (void)context;
    if (formatDataResponse == NULL) {
        return CHANNEL_RC_BAD_PROC;
    }
    if ((formatDataResponse->common.msgFlags & CB_RESPONSE_FAIL) != 0) {
        return CHANNEL_RC_OK;
    }

    const BYTE *data = formatDataResponse->requestedFormatData;
    const UINT32 data_len = formatDataResponse->common.dataLen;
    const UINT32 format_id =
        g_server_format_id != 0 ? g_server_format_id : CF_UNICODETEXT;

    // Reject oversized wire payloads *before* UTF conversion allocates
    // (full2 T12): max_bytes bounds host pasteboard and heap.
    if (g_policy_valid && g_policy.max_bytes > 0u) {
        size_t rough = (size_t)data_len;
        if (format_id == CF_UNICODETEXT) {
            rough = (size_t)data_len / 2u; // UTF-16 lower bound → UTF-8
        }
        if (rough > g_policy.max_bytes) {
            return CHANNEL_RC_OK; // drop; keep session
        }
    }

    char *utf8 = NULL;
    long n = rdp_cliprdr_payload_to_utf8(format_id, data, data_len, &utf8);
    if (n < 0 || utf8 == NULL) {
        free(utf8);
        return CHANNEL_RC_OK;  // drop bad payload; keep session
    }

    // Policy gate (direction + size + plain-text format).
    rdp_clip_inbound_result ir =
        rdp_clip_check_inbound(g_policy_valid ? &g_policy : NULL,
                               (size_t)n, FARSEE_CLIP_FORMAT_UTF8_TEXT);
    if (ir != RDP_CLIP_ALLOW) {
        free(utf8);
        return CHANNEL_RC_OK;
    }

    // Sanitize terminal escapes before placing on the host pasteboard.
    char *sanitized = NULL;
    size_t san_len = 0;
    if (g_policy_valid && g_policy.sanitize_escapes) {
        sanitized = (char *)malloc((size_t)n + 1u);
        if (sanitized == NULL) {
            free(utf8);
            return CHANNEL_RC_NO_MEMORY;
        }
        san_len = farsee_clip_sanitize_text(sanitized, (size_t)n + 1u,
                                            utf8, (size_t)n);
        free(utf8);
        utf8 = sanitized;
        n = (long)san_len;
    }

    (void)rdp_host_clipboard_set_utf8(utf8, (size_t)n);
    free(utf8);
    return CHANNEL_RC_OK;
}

static UINT rdp_cliprdr_server_format_data_request(
    CliprdrClientContext *context,
    const CLIPRDR_FORMAT_DATA_REQUEST *formatDataRequest)
{
    if (context == NULL || formatDataRequest == NULL) {
        return CHANNEL_RC_BAD_PROC;
    }

    const UINT32 want = formatDataRequest->requestedFormatId;
    if (want != CF_UNICODETEXT && want != CF_TEXT) {
        return rdp_cliprdr_send_fail(context);
    }

    // Outbound policy check — fail closed when disabled or oversized.
    // Heap: 1 MiB pasteboard buffer (T22; avoid 512 KiB worker stack overflow).
    char *host = (char *)malloc((size_t)RDP_CLIPRDR_HOST_CAP + 1u);
    if (host == NULL) {
        return rdp_cliprdr_send_fail(context);
    }
    long n = rdp_host_clipboard_get_utf8(host,
                                         (size_t)RDP_CLIPRDR_HOST_CAP + 1u);
    if (n < 0) {
        n = 0;
        host[0] = '\0';
    }
    if (!g_policy_valid ||
        !rdp_clip_allows_outbound(&g_policy, (size_t)n)) {
        free(host);
        return rdp_cliprdr_send_fail(context);
    }

    BYTE *payload = NULL;
    UINT32 payload_len = 0;

    if (want == CF_UNICODETEXT) {
        if (!rdp_cliprdr_utf8_to_utf16le(host, (size_t)n, &payload,
                                         &payload_len)) {
            free(host);
            return rdp_cliprdr_send_fail(context);
        }
    } else {
        // CF_TEXT: send UTF-8 bytes as a best-effort ANSI payload with NUL.
        // (Servers that only offer CF_TEXT are rare; still fail-closed on OOM.)
        size_t bytes = (size_t)n + 1u;
        if (bytes > UINT32_MAX) {
            free(host);
            return rdp_cliprdr_send_fail(context);
        }
        payload = (BYTE *)malloc(bytes);
        if (payload == NULL) {
            free(host);
            return rdp_cliprdr_send_fail(context);
        }
        if (n > 0) {
            memcpy(payload, host, (size_t)n);
        }
        payload[n] = 0;
        payload_len = (UINT32)bytes;
    }
    free(host);

    CLIPRDR_FORMAT_DATA_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));
    resp.common.msgFlags = CB_RESPONSE_OK;
    resp.common.dataLen = payload_len;
    resp.requestedFormatData = payload;

    UINT rc = CHANNEL_RC_BAD_PROC;
    if (context->ClientFormatDataResponse != NULL) {
        rc = context->ClientFormatDataResponse(context, &resp);
    }
    free(payload);
    return rc;
}

// File-content / lock handlers: always refuse (text-only scope, §13.3).
static UINT rdp_cliprdr_server_file_contents_request(
    CliprdrClientContext *context,
    const CLIPRDR_FILE_CONTENTS_REQUEST *fileContentsRequest)
{
    (void)fileContentsRequest;
    if (context == NULL || context->ClientFileContentsResponse == NULL) {
        return CHANNEL_RC_OK;
    }
    CLIPRDR_FILE_CONTENTS_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));
    resp.common.msgFlags = CB_RESPONSE_FAIL;
    return context->ClientFileContentsResponse(context, &resp);
}

static UINT rdp_cliprdr_server_lock(
    CliprdrClientContext *context,
    const CLIPRDR_LOCK_CLIPBOARD_DATA *lockClipboardData)
{
    (void)context;
    (void)lockClipboardData;
    return CHANNEL_RC_OK;
}

static UINT rdp_cliprdr_server_unlock(
    CliprdrClientContext *context,
    const CLIPRDR_UNLOCK_CLIPBOARD_DATA *unlockClipboardData)
{
    (void)context;
    (void)unlockClipboardData;
    return CHANNEL_RC_OK;
}

// --- ChannelConnected / prepare -------------------------------------------

static void rdp_cliprdr_on_channel_connected(void *context,
                                             const ChannelConnectedEventArgs *e)
{
    (void)context;
    if (e == NULL || e->name == NULL || e->pInterface == NULL) {
        return;
    }
    if (strcmp(e->name, CLIPRDR_SVC_CHANNEL_NAME) != 0) {
        return;
    }
    // Only install when the operator enabled text clipboard.
    if (!g_enabled) {
        return;
    }

    CliprdrClientContext *clip = (CliprdrClientContext *)e->pInterface;
    clip->custom = (void *)(uintptr_t)1;  // non-NULL marker for "owned"

    clip->MonitorReady = rdp_cliprdr_monitor_ready;
    clip->ServerCapabilities = rdp_cliprdr_server_capabilities;
    clip->ServerFormatList = rdp_cliprdr_server_format_list;
    clip->ServerFormatDataRequest = rdp_cliprdr_server_format_data_request;
    clip->ServerFormatDataResponse = rdp_cliprdr_server_format_data_response;
    clip->ServerFileContentsRequest = rdp_cliprdr_server_file_contents_request;
    // Explicit no-ops for lock paths we never use (text-only scope).
    clip->ServerLockClipboardData = rdp_cliprdr_server_lock;
    clip->ServerUnlockClipboardData = rdp_cliprdr_server_unlock;
}

static void rdp_cliprdr_on_channel_disconnected(
    void *context, const ChannelDisconnectedEventArgs *e)
{
    (void)context;
    if (e == NULL || e->name == NULL || e->pInterface == NULL) {
        return;
    }
    if (strcmp(e->name, CLIPRDR_SVC_CHANNEL_NAME) != 0) {
        return;
    }
    CliprdrClientContext *clip = (CliprdrClientContext *)e->pInterface;
    clip->custom = NULL;
    clip->MonitorReady = NULL;
    clip->ServerCapabilities = NULL;
    clip->ServerFormatList = NULL;
    clip->ServerFormatDataRequest = NULL;
    clip->ServerFormatDataResponse = NULL;
    clip->ServerFileContentsRequest = NULL;
    g_server_has_text = false;
    g_server_format_id = 0;
}

bool rdp_cliprdr_prepare_instance(rdp_freerdp_ctx *ctx)
{
    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    if (inst == NULL || inst->context == NULL) {
        return false;
    }

    // Register the static channel addin provider once per process.
    if (!g_addin_registered) {
        if (freerdp_register_addin_provider(
                freerdp_channels_load_static_addin_entry, 0) !=
            CHANNEL_RC_OK) {
            return false;
        }
        g_addin_registered = true;
    }

    // freerdp_connect invokes LoadChannels before channel attach. Point it
    // at the FreeRDP-client helper that loads settings-selected addins
    // (cliprdr when FreeRDP_RedirectClipboard is true).
    if (inst->LoadChannels == NULL) {
        inst->LoadChannels = freerdp_client_load_channels;
    }

    // Subscribe PubSub once per process (handlers are process-global in the
    // single-worker model; re-prepare on a new instance still works because
    // pubSub is per-context — so always re-subscribe for this instance).
    if (inst->context->pubSub != NULL) {
        // Unsubscribe first so repeated prepare is idempotent on the same
        // context without stacking handlers.
        if (g_pubsub_subscribed) {
            (void)PubSub_UnsubscribeChannelConnected(
                inst->context->pubSub, rdp_cliprdr_on_channel_connected);
            (void)PubSub_UnsubscribeChannelDisconnected(
                inst->context->pubSub, rdp_cliprdr_on_channel_disconnected);
        }
        if (PubSub_SubscribeChannelConnected(
                inst->context->pubSub, rdp_cliprdr_on_channel_connected) != 0) {
            return false;
        }
        if (PubSub_SubscribeChannelDisconnected(
                inst->context->pubSub,
                rdp_cliprdr_on_channel_disconnected) != 0) {
            (void)PubSub_UnsubscribeChannelConnected(
                inst->context->pubSub, rdp_cliprdr_on_channel_connected);
            return false;
        }
        g_pubsub_subscribed = true;
    }
    return true;
}

void rdp_cliprdr_configure(rdp_freerdp_ctx *ctx,
                           const farsee_clip_policy *policy,
                           bool enabled)
{
    (void)ctx;
    // Reset per-connect negotiation state so sequential sessions cannot
    // inherit a previous peer's format id / text offer (process-global
    // policy is accepted debt; see multi-review T16).
    g_server_format_id = 0;
    g_server_has_text = false;
    if (policy != NULL) {
        g_policy = *policy;
        g_policy_valid = true;
    } else {
        g_policy = farsee_clip_policy_default();
        g_policy_valid = false;
        enabled = false;
    }
    g_enabled = enabled;
}
