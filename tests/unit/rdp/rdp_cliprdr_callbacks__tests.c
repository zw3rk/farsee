// SPDX-License-Identifier: Apache-2.0
//
// Deterministic FreeRDP CLIPRDR callback wiring tests.
//
// The callbacks are private to rdp_cliprdr.c. Exercise them through the
// installed PubSub channel boundary, as a real FreeRDP connection does.

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_callbacks.h"
#include "protocol/rdp/rdp_cliprdr.h"
#include "protocol/rdp/rdp_freerdp_facade.h"
#include "protocol/rdp/rdp_settings.h"
#include "farsee/farsee_security.h"
#include "tests/test_framework/rfb_test.h"

#include <freerdp/channels/cliprdr.h>
#include <freerdp/client/cliprdr.h>
#include <freerdp/event.h>
#include <freerdp/freerdp.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { CLIPRDR_CAPTURE_CAP = 256 };

typedef struct cliprdr_client_capture {
    size_t capabilities_calls;
    UINT capabilities_result;
    UINT16 capability_type;
    UINT16 capability_length;
    UINT32 capability_version;
    UINT32 capability_flags;

    size_t format_list_calls;
    UINT format_list_result;
    UINT32 format_count;
    UINT32 format_id;

    size_t list_response_calls;
    UINT list_response_result;
    UINT16 list_response_flags;

    size_t data_request_calls;
    UINT data_request_result;
    UINT32 requested_format_id;

    size_t data_response_calls;
    UINT data_response_result;
    UINT16 data_response_flags;
    UINT32 data_response_length;
    BYTE data_response[CLIPRDR_CAPTURE_CAP];

    size_t file_response_calls;
    UINT file_response_result;
    UINT16 file_response_flags;
} cliprdr_client_capture;

typedef struct cliprdr_callback_fixture {
    rdp_freerdp_ctx *ctx;
    freerdp *instance;
    farsee_rdp_settings settings;
    farsee_credential_response credentials;
    farsee_security_policy security;
    rdp_callback_context callbacks;
    CliprdrClientContext clip;
    cliprdr_client_capture capture;
} cliprdr_callback_fixture;

static cliprdr_client_capture *cliprdr_capture_from_context(
    CliprdrClientContext *context)
{
    return context != NULL
               ? (cliprdr_client_capture *)context->handle
               : NULL;
}

static UINT cliprdr_capture_capabilities(
    CliprdrClientContext *context, const CLIPRDR_CAPABILITIES *capabilities)
{
    cliprdr_client_capture *capture = cliprdr_capture_from_context(context);
    if (capture == NULL) {
        return CHANNEL_RC_BAD_PROC;
    }
    capture->capabilities_calls++;
    if (capabilities != NULL && capabilities->cCapabilitiesSets > 0u &&
        capabilities->capabilitySets != NULL) {
        const CLIPRDR_GENERAL_CAPABILITY_SET *general =
            (const CLIPRDR_GENERAL_CAPABILITY_SET *)(const void *)
                capabilities->capabilitySets;
        capture->capability_type = general->capabilitySetType;
        capture->capability_length = general->capabilitySetLength;
        capture->capability_version = general->version;
        capture->capability_flags = general->generalFlags;
    }
    return capture->capabilities_result;
}

static UINT cliprdr_capture_format_list(
    CliprdrClientContext *context, const CLIPRDR_FORMAT_LIST *format_list)
{
    cliprdr_client_capture *capture = cliprdr_capture_from_context(context);
    if (capture == NULL) {
        return CHANNEL_RC_BAD_PROC;
    }
    capture->format_list_calls++;
    if (format_list != NULL) {
        capture->format_count = format_list->numFormats;
        if (format_list->numFormats > 0u && format_list->formats != NULL) {
            capture->format_id = format_list->formats[0].formatId;
        }
    }
    return capture->format_list_result;
}

static UINT cliprdr_capture_list_response(
    CliprdrClientContext *context,
    const CLIPRDR_FORMAT_LIST_RESPONSE *format_list_response)
{
    cliprdr_client_capture *capture = cliprdr_capture_from_context(context);
    if (capture == NULL) {
        return CHANNEL_RC_BAD_PROC;
    }
    capture->list_response_calls++;
    if (format_list_response != NULL) {
        capture->list_response_flags = format_list_response->common.msgFlags;
    }
    return capture->list_response_result;
}

static UINT cliprdr_capture_data_request(
    CliprdrClientContext *context,
    const CLIPRDR_FORMAT_DATA_REQUEST *format_data_request)
{
    cliprdr_client_capture *capture = cliprdr_capture_from_context(context);
    if (capture == NULL) {
        return CHANNEL_RC_BAD_PROC;
    }
    capture->data_request_calls++;
    if (format_data_request != NULL) {
        capture->requested_format_id =
            format_data_request->requestedFormatId;
    }
    return capture->data_request_result;
}

static UINT cliprdr_capture_data_response(
    CliprdrClientContext *context,
    const CLIPRDR_FORMAT_DATA_RESPONSE *format_data_response)
{
    cliprdr_client_capture *capture = cliprdr_capture_from_context(context);
    if (capture == NULL) {
        return CHANNEL_RC_BAD_PROC;
    }
    capture->data_response_calls++;
    if (format_data_response != NULL) {
        capture->data_response_flags = format_data_response->common.msgFlags;
        capture->data_response_length = format_data_response->common.dataLen;
        size_t copied = (size_t)format_data_response->common.dataLen;
        if (copied > sizeof(capture->data_response)) {
            copied = sizeof(capture->data_response);
        }
        if (copied > 0u && format_data_response->requestedFormatData != NULL) {
            memcpy(capture->data_response,
                   format_data_response->requestedFormatData, copied);
        }
    }
    return capture->data_response_result;
}

static UINT cliprdr_capture_file_response(
    CliprdrClientContext *context,
    const CLIPRDR_FILE_CONTENTS_RESPONSE *file_contents_response)
{
    cliprdr_client_capture *capture = cliprdr_capture_from_context(context);
    if (capture == NULL) {
        return CHANNEL_RC_BAD_PROC;
    }
    capture->file_response_calls++;
    if (file_contents_response != NULL) {
        capture->file_response_flags =
            file_contents_response->common.msgFlags;
    }
    return capture->file_response_result;
}

static void cliprdr_callback_fixture_bind_client(
    cliprdr_callback_fixture *fixture)
{
    fixture->clip.handle = &fixture->capture;
    fixture->clip.ClientCapabilities = cliprdr_capture_capabilities;
    fixture->clip.ClientFormatList = cliprdr_capture_format_list;
    fixture->clip.ClientFormatListResponse = cliprdr_capture_list_response;
    fixture->clip.ClientFormatDataRequest = cliprdr_capture_data_request;
    fixture->clip.ClientFormatDataResponse = cliprdr_capture_data_response;
    fixture->clip.ClientFileContentsResponse = cliprdr_capture_file_response;
}

static bool cliprdr_callback_fixture_init(cliprdr_callback_fixture *fixture)
{
    if (fixture == NULL) {
        return false;
    }
    memset(fixture, 0, sizeof(*fixture));
    fixture->ctx = rdp_freerdp_create();
    if (fixture->ctx == NULL) {
        return false;
    }

    farsee_rdp_settings_init_for_host(&fixture->settings, "host", 3389u,
                                      "user", NULL);
    fixture->settings.desktop_width = 800u;
    fixture->settings.desktop_height = 600u;
    fixture->settings.channels.clipboard_text = true;
    farsee_credential_response_init(&fixture->credentials);
    fixture->credentials.username = "user";
    fixture->security = farsee_security_policy_default_rdp();

    fixture->callbacks.settings = &fixture->settings;
    fixture->callbacks.credentials = &fixture->credentials;
    fixture->callbacks.policy = &fixture->security;
    fixture->callbacks.trust = FARSEE_TRUST_DECISION_APPROVE_ONCE;
    fixture->callbacks.peer_cert_decided = true;

    if (!rdp_callbacks_install(fixture->ctx, &fixture->callbacks)) {
        rdp_freerdp_destroy(&fixture->ctx);
        return false;
    }
    fixture->instance =
        (freerdp *)rdp_freerdp_instance_opaque(fixture->ctx);
    cliprdr_callback_fixture_bind_client(fixture);
    return fixture->instance != NULL && fixture->instance->context != NULL &&
           fixture->instance->context->pubSub != NULL;
}

static void cliprdr_callback_fixture_publish_connected(
    cliprdr_callback_fixture *fixture, const char *name, void *interface)
{
    ChannelConnectedEventArgs event;
    EventArgsInit(&event, "farsee-test");
    event.name = name;
    event.pInterface = interface;
    (void)PubSub_OnChannelConnected(fixture->instance->context->pubSub,
                                    fixture->instance->context, &event);
}

static void cliprdr_callback_fixture_publish_disconnected(
    cliprdr_callback_fixture *fixture, const char *name, void *interface)
{
    ChannelDisconnectedEventArgs event;
    EventArgsInit(&event, "farsee-test");
    event.name = name;
    event.pInterface = interface;
    (void)PubSub_OnChannelDisconnected(fixture->instance->context->pubSub,
                                       fixture->instance->context, &event);
}

static bool cliprdr_callback_fixture_attach(
    cliprdr_callback_fixture *fixture)
{
    cliprdr_callback_fixture_publish_connected(
        fixture, CLIPRDR_SVC_CHANNEL_NAME, &fixture->clip);
    return fixture->clip.custom ==
               rdp_freerdp_cliprdr_state(fixture->ctx) &&
           fixture->clip.MonitorReady != NULL &&
           fixture->clip.ServerFormatList != NULL &&
           fixture->clip.ServerFormatDataRequest != NULL &&
           fixture->clip.ServerFormatDataResponse != NULL;
}

static void cliprdr_callback_fixture_set_policy(
    cliprdr_callback_fixture *fixture, farsee_clip_direction direction,
    size_t max_bytes, bool sanitize)
{
    farsee_clip_policy policy = farsee_clip_policy_default();
    policy.direction = direction;
    policy.max_bytes = max_bytes;
    policy.sanitize_escapes = sanitize;
    rdp_cliprdr_configure(fixture->ctx, &policy, true);
}

typedef struct cliprdr_fault_allocator {
    size_t calls;
    size_t fail_at;
    size_t frees;
} cliprdr_fault_allocator;

static void *cliprdr_fault_alloc(rfb_allocator *allocator, size_t size)
{
    cliprdr_fault_allocator *fault =
        (cliprdr_fault_allocator *)allocator->user;
    fault->calls++;
    if (fault->fail_at != 0u && fault->calls == fault->fail_at) {
        return NULL;
    }
    return malloc(size);
}

static void cliprdr_fault_free(rfb_allocator *allocator, void *pointer)
{
    cliprdr_fault_allocator *fault =
        (cliprdr_fault_allocator *)allocator->user;
    fault->frees++;
    free(pointer);
}

static rfb_allocator cliprdr_fault_allocator_make(
    cliprdr_fault_allocator *fault, size_t fail_at)
{
    fault->calls = 0u;
    fault->fail_at = fail_at;
    fault->frees = 0u;
    rfb_allocator allocator = {
        .alloc = cliprdr_fault_alloc,
        .free = cliprdr_fault_free,
        .user = fault,
    };
    return allocator;
}

static char *cliprdr_hide_host_tools(void)
{
    const char *path = getenv("PATH");
    char *saved = NULL;
    if (path != NULL) {
        size_t length = strlen(path);
        saved = (char *)malloc(length + 1u);
        if (saved == NULL) {
            return NULL;
        }
        memcpy(saved, path, length + 1u);
    }
    if (setenv("PATH", "/nonexistent", 1) != 0) {
        free(saved);
        return NULL;
    }
    return saved;
}

static void cliprdr_restore_host_tools(char *saved_path)
{
    if (saved_path != NULL) {
        (void)setenv("PATH", saved_path, 1);
    } else {
        (void)unsetenv("PATH");
    }
    free(saved_path);
}

typedef struct cliprdr_fake_host_tools {
    char directory[128];
    char paste_path[160];
    char copy_path[160];
    char wayland_paste_path[160];
    char wayland_copy_path[160];
    char xclip_path[160];
    char output_path[160];
    char *saved_path;
    bool had_path;
    bool path_overridden;
} cliprdr_fake_host_tools;

static bool cliprdr_write_tool(const char *path, const char *body)
{
    FILE *stream = fopen(path, "wb");
    if (stream == NULL) {
        return false;
    }
    bool ok = fputs(body, stream) >= 0;
    if (fclose(stream) != 0) {
        ok = false;
    }
    return ok && chmod(path, 0700) == 0;
}

static void cliprdr_fake_host_tools_stop(cliprdr_fake_host_tools *tools)
{
    if (tools == NULL) {
        return;
    }
    if (tools->path_overridden) {
        if (tools->had_path) {
            (void)setenv("PATH", tools->saved_path, 1);
        } else {
            (void)unsetenv("PATH");
        }
    }
    free(tools->saved_path);
    tools->saved_path = NULL;
    tools->had_path = false;
    tools->path_overridden = false;
    (void)unsetenv("FARSEE_TEST_CLIP_OUTPUT");
    (void)unlink(tools->paste_path);
    (void)unlink(tools->copy_path);
    (void)unlink(tools->wayland_paste_path);
    (void)unlink(tools->wayland_copy_path);
    (void)unlink(tools->xclip_path);
    (void)unlink(tools->output_path);
    (void)rmdir(tools->directory);
}

static bool cliprdr_fake_host_tools_start(cliprdr_fake_host_tools *tools)
{
    if (tools == NULL) {
        return false;
    }
    memset(tools, 0, sizeof(*tools));
    int written = snprintf(tools->directory, sizeof tools->directory,
                           "/tmp/farsee-cliprdr-tools-XXXXXX");
    if (written <= 0 || (size_t)written >= sizeof tools->directory ||
        mkdtemp(tools->directory) == NULL) {
        return false;
    }
    written = snprintf(tools->paste_path, sizeof tools->paste_path,
                       "%s/pbpaste", tools->directory);
    if (written <= 0 || (size_t)written >= sizeof tools->paste_path) {
        cliprdr_fake_host_tools_stop(tools);
        return false;
    }
    written = snprintf(tools->copy_path, sizeof tools->copy_path,
                       "%s/pbcopy", tools->directory);
    if (written <= 0 || (size_t)written >= sizeof tools->copy_path) {
        cliprdr_fake_host_tools_stop(tools);
        return false;
    }
    written = snprintf(tools->wayland_paste_path,
                       sizeof tools->wayland_paste_path,
                       "%s/wl-paste", tools->directory);
    if (written <= 0 ||
        (size_t)written >= sizeof tools->wayland_paste_path) {
        cliprdr_fake_host_tools_stop(tools);
        return false;
    }
    written = snprintf(tools->wayland_copy_path,
                       sizeof tools->wayland_copy_path,
                       "%s/wl-copy", tools->directory);
    if (written <= 0 ||
        (size_t)written >= sizeof tools->wayland_copy_path) {
        cliprdr_fake_host_tools_stop(tools);
        return false;
    }
    written = snprintf(tools->xclip_path, sizeof tools->xclip_path,
                       "%s/xclip", tools->directory);
    if (written <= 0 || (size_t)written >= sizeof tools->xclip_path) {
        cliprdr_fake_host_tools_stop(tools);
        return false;
    }
    written = snprintf(tools->output_path, sizeof tools->output_path,
                       "%s/output", tools->directory);
    if (written <= 0 || (size_t)written >= sizeof tools->output_path) {
        cliprdr_fake_host_tools_stop(tools);
        return false;
    }
    if (!cliprdr_write_tool(tools->paste_path,
                            "#!/bin/sh\nprintf 'hello'\n") ||
        !cliprdr_write_tool(
            tools->copy_path,
            "#!/bin/sh\ncat > \"$FARSEE_TEST_CLIP_OUTPUT\"\n") ||
        !cliprdr_write_tool(tools->wayland_paste_path,
                            "#!/bin/sh\nprintf 'hello'\n") ||
        !cliprdr_write_tool(
            tools->wayland_copy_path,
            "#!/bin/sh\ncat > \"$FARSEE_TEST_CLIP_OUTPUT\"\n") ||
        !cliprdr_write_tool(
            tools->xclip_path,
            "#!/bin/sh\ncase \"$*\" in *-o*) printf 'hello' ;; "
            "*) cat > \"$FARSEE_TEST_CLIP_OUTPUT\" ;; esac\n")) {
        cliprdr_fake_host_tools_stop(tools);
        return false;
    }
    const char *current_path = getenv("PATH");
    if (current_path != NULL) {
        const size_t path_length = strlen(current_path);
        tools->saved_path = (char *)malloc(path_length + 1u);
        if (tools->saved_path == NULL) {
            cliprdr_fake_host_tools_stop(tools);
            return false;
        }
        memcpy(tools->saved_path, current_path, path_length + 1u);
        tools->had_path = true;
    }
    const size_t directory_length = strlen(tools->directory);
    char *combined_path = NULL;
    const char *test_path = tools->directory;
    if (tools->had_path) {
        const size_t path_length = strlen(tools->saved_path);
        if (path_length > SIZE_MAX - directory_length - 2u) {
            cliprdr_fake_host_tools_stop(tools);
            return false;
        }
        combined_path =
            (char *)malloc(directory_length + 1u + path_length + 1u);
        if (combined_path == NULL) {
            cliprdr_fake_host_tools_stop(tools);
            return false;
        }
        memcpy(combined_path, tools->directory, directory_length);
        combined_path[directory_length] = ':';
        memcpy(combined_path + directory_length + 1u, tools->saved_path,
               path_length + 1u);
        test_path = combined_path;
    }
    if (setenv("PATH", test_path, 1) != 0) {
        free(combined_path);
        cliprdr_fake_host_tools_stop(tools);
        return false;
    }
    free(combined_path);
    tools->path_overridden = true;
    if (setenv("FARSEE_TEST_CLIP_OUTPUT", tools->output_path, 1) != 0) {
        cliprdr_fake_host_tools_stop(tools);
        return false;
    }
    return true;
}

static bool cliprdr_read_file(const char *path, char *buffer,
                              size_t capacity, size_t *out_size)
{
    if (path == NULL || buffer == NULL || capacity == 0u ||
        out_size == NULL) {
        return false;
    }
    *out_size = 0u;
    FILE *stream = fopen(path, "rb");
    if (stream == NULL) {
        return false;
    }
    const size_t count = fread(buffer, 1u, capacity, stream);
    bool ok = !ferror(stream);
    if (fclose(stream) != 0) {
        ok = false;
    }
    *out_size = count;
    return ok;
}

static void cliprdr_callback_fixture_destroy(
    cliprdr_callback_fixture *fixture)
{
    if (fixture == NULL) {
        return;
    }
    if (fixture->ctx != NULL && fixture->clip.custom != NULL) {
        cliprdr_callback_fixture_publish_disconnected(
            fixture, CLIPRDR_SVC_CHANNEL_NAME, &fixture->clip);
    }
    rdp_freerdp_destroy(&fixture->ctx);
}

RFB_TEST(rdp_cliprdr_callbacks,
         channel_events__filter_install_and_reset_per_instance_state)
{
    cliprdr_callback_fixture fixture;
    RFB_CHECK(cliprdr_callback_fixture_init(&fixture));
    if (fixture.ctx == NULL) {
        return;
    }

    cliprdr_callback_fixture_publish_connected(&fixture, NULL, &fixture.clip);
    cliprdr_callback_fixture_publish_connected(&fixture, "rdpsnd",
                                               &fixture.clip);
    cliprdr_callback_fixture_publish_connected(
        &fixture, CLIPRDR_SVC_CHANNEL_NAME, NULL);
    RFB_CHECK(fixture.clip.custom == NULL);

    rdp_cliprdr_configure(fixture.ctx, NULL, false);
    cliprdr_callback_fixture_publish_connected(
        &fixture, CLIPRDR_SVC_CHANNEL_NAME, &fixture.clip);
    RFB_CHECK(fixture.clip.custom == NULL);

    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_BIDIRECTIONAL, 64u, true);
    RFB_CHECK(cliprdr_callback_fixture_attach(&fixture));
    RFB_CHECK(fixture.clip.ServerCapabilities != NULL);
    RFB_CHECK(fixture.clip.ServerFileContentsRequest != NULL);
    RFB_CHECK(fixture.clip.ServerLockClipboardData != NULL);
    RFB_CHECK(fixture.clip.ServerUnlockClipboardData != NULL);

    rdp_cliprdr_state *state = rdp_freerdp_cliprdr_state(fixture.ctx);
    RFB_CHECK(state != NULL);
    state->server_has_text = true;
    state->server_format_id = CF_TEXT;
    cliprdr_callback_fixture_publish_disconnected(&fixture, "rdpsnd",
                                                  &fixture.clip);
    RFB_CHECK(fixture.clip.custom == state);
    cliprdr_callback_fixture_publish_disconnected(
        &fixture, CLIPRDR_SVC_CHANNEL_NAME, &fixture.clip);
    RFB_CHECK(fixture.clip.custom == NULL);
    RFB_CHECK(!state->server_has_text);
    RFB_CHECK_EQ_UINT(state->server_format_id, 0u);

    cliprdr_callback_fixture_destroy(&fixture);
}

RFB_TEST(rdp_cliprdr_callbacks,
         monitor_ready__advertises_text_only_capability_and_propagates_errors)
{
    cliprdr_callback_fixture fixture;
    RFB_CHECK(cliprdr_callback_fixture_init(&fixture));
    if (fixture.ctx == NULL) {
        return;
    }
    RFB_CHECK(cliprdr_callback_fixture_attach(&fixture));
    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL, 64u, true);

    CLIPRDR_MONITOR_READY ready;
    memset(&ready, 0, sizeof(ready));
    RFB_CHECK_EQ_UINT(fixture.clip.MonitorReady(NULL, &ready),
                      CHANNEL_RC_BAD_PROC);
    RFB_CHECK_EQ_UINT(fixture.clip.MonitorReady(&fixture.clip, &ready),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.capabilities_calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.capture.capability_type,
                      CB_CAPSTYPE_GENERAL);
    RFB_CHECK_EQ_UINT(fixture.capture.capability_length,
                      CB_CAPSTYPE_GENERAL_LEN);
    RFB_CHECK_EQ_UINT(fixture.capture.capability_version,
                      CB_CAPS_VERSION_2);
    RFB_CHECK_EQ_UINT(fixture.capture.capability_flags,
                      CB_USE_LONG_FORMAT_NAMES);
    RFB_CHECK_EQ_UINT(fixture.capture.format_list_calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.capture.format_count, 0u);

    fixture.capture.capabilities_result = CHANNEL_RC_BAD_PROC;
    RFB_CHECK_EQ_UINT(fixture.clip.MonitorReady(&fixture.clip, &ready),
                      CHANNEL_RC_BAD_PROC);
    RFB_CHECK_EQ_UINT(fixture.capture.format_list_calls, 1u);

    fixture.capture.capabilities_result = CHANNEL_RC_OK;
    fixture.clip.ClientCapabilities = NULL;
    fixture.clip.ClientFormatList = NULL;
    RFB_CHECK_EQ_UINT(fixture.clip.MonitorReady(&fixture.clip, &ready),
                      CHANNEL_RC_BAD_PROC);

    RFB_CHECK_EQ_UINT(fixture.clip.ServerCapabilities(NULL, NULL),
                      CHANNEL_RC_OK);
    cliprdr_callback_fixture_destroy(&fixture);
}

RFB_TEST(rdp_cliprdr_callbacks,
         server_format_list__prefers_unicode_and_obeys_inbound_policy)
{
    cliprdr_callback_fixture fixture;
    RFB_CHECK(cliprdr_callback_fixture_init(&fixture));
    if (fixture.ctx == NULL) {
        return;
    }
    RFB_CHECK(cliprdr_callback_fixture_attach(&fixture));
    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL, 64u, true);

    CLIPRDR_FORMAT formats[2];
    memset(formats, 0, sizeof(formats));
    formats[0].formatId = CF_TEXT;
    formats[1].formatId = CF_UNICODETEXT;
    CLIPRDR_FORMAT_LIST list;
    memset(&list, 0, sizeof(list));
    list.numFormats = 2u;
    list.formats = formats;

    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatList(NULL, &list),
                      CHANNEL_RC_BAD_PROC);
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatList(&fixture.clip, NULL),
                      CHANNEL_RC_BAD_PROC);
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatList(&fixture.clip, &list),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.list_response_calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.capture.list_response_flags, CB_RESPONSE_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.data_request_calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.capture.requested_format_id, CF_UNICODETEXT);
    RFB_CHECK_EQ_UINT(fixture.clip.lastRequestedFormatId, CF_UNICODETEXT);

    fixture.capture.data_request_result = CHANNEL_RC_BAD_PROC;
    formats[0].formatId = CF_TEXT;
    list.numFormats = 1u;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatList(&fixture.clip, &list),
                      CHANNEL_RC_BAD_PROC);
    RFB_CHECK_EQ_UINT(fixture.capture.requested_format_id, CF_TEXT);

    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_LOCAL_TO_REMOTE, 64u, true);
    fixture.capture.data_request_calls = 0u;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatList(&fixture.clip, &list),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.data_request_calls, 0u);

    list.numFormats = 0u;
    list.formats = NULL;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatList(&fixture.clip, &list),
                      CHANNEL_RC_OK);

    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL, 64u, true);
    fixture.clip.ClientFormatDataRequest = NULL;
    list.numFormats = 1u;
    list.formats = formats;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatList(&fixture.clip, &list),
                      CHANNEL_RC_BAD_PROC);

    cliprdr_callback_fixture_destroy(&fixture);
}

RFB_TEST(rdp_cliprdr_callbacks,
         server_format_list__rejects_missing_format_array)
{
    cliprdr_callback_fixture fixture;
    RFB_CHECK(cliprdr_callback_fixture_init(&fixture));
    if (fixture.ctx == NULL) {
        return;
    }
    RFB_CHECK(cliprdr_callback_fixture_attach(&fixture));

    CLIPRDR_FORMAT_LIST list;
    memset(&list, 0, sizeof(list));
    list.numFormats = 1u;
    list.formats = NULL;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatList(&fixture.clip, &list),
                      CHANNEL_RC_BAD_PROC);

    cliprdr_callback_fixture_destroy(&fixture);
}

RFB_TEST(rdp_cliprdr_callbacks,
         data_callbacks__reject_invalid_oversize_and_allocation_failure)
{
    cliprdr_callback_fixture fixture;
    RFB_CHECK(cliprdr_callback_fixture_init(&fixture));
    if (fixture.ctx == NULL) {
        return;
    }
    RFB_CHECK(cliprdr_callback_fixture_attach(&fixture));
    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_BIDIRECTIONAL, 3u, true);
    rdp_cliprdr_state *state = rdp_freerdp_cliprdr_state(fixture.ctx);
    RFB_CHECK(state != NULL);

    CLIPRDR_FORMAT_DATA_RESPONSE incoming;
    memset(&incoming, 0, sizeof(incoming));
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          NULL, &incoming),
                      CHANNEL_RC_BAD_PROC);
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, NULL),
                      CHANNEL_RC_BAD_PROC);
    incoming.common.msgFlags = CB_RESPONSE_FAIL;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_OK);

    static const BYTE oversized[] = { 'a', 'b', 'c', 'd' };
    incoming.common.msgFlags = CB_RESPONSE_OK;
    incoming.common.dataLen = (UINT32)sizeof(oversized);
    incoming.requestedFormatData = oversized;
    state->server_format_id = CF_TEXT;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_OK);

    CLIPRDR_FORMAT_DATA_REQUEST outgoing;
    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.requestedFormatId = 999u;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataRequest(
                          NULL, &outgoing),
                      CHANNEL_RC_BAD_PROC);
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataRequest(
                          &fixture.clip, NULL),
                      CHANNEL_RC_BAD_PROC);
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataRequest(
                          &fixture.clip, &outgoing),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.data_response_calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.capture.data_response_flags, CB_RESPONSE_FAIL);

    cliprdr_fault_allocator fault;
    rfb_allocator allocator = cliprdr_fault_allocator_make(&fault, 1u);
    state->allocator = &allocator;
    outgoing.requestedFormatId = CF_TEXT;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataRequest(
                          &fixture.clip, &outgoing),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.data_response_calls, 2u);
    RFB_CHECK_EQ_UINT(fixture.capture.data_response_flags, CB_RESPONSE_FAIL);
    RFB_CHECK_EQ_UINT(fault.calls, 1u);

    cliprdr_callback_fixture_destroy(&fixture);
}

RFB_TEST(rdp_cliprdr_callbacks,
         inbound_text__converts_sanitizes_and_handles_allocator_failures)
{
    char *saved_path = cliprdr_hide_host_tools();
    RFB_CHECK(saved_path != NULL);
    if (saved_path == NULL) {
        return;
    }
    cliprdr_callback_fixture fixture;
    RFB_CHECK(cliprdr_callback_fixture_init(&fixture));
    if (fixture.ctx == NULL) {
        cliprdr_restore_host_tools(saved_path);
        return;
    }
    RFB_CHECK(cliprdr_callback_fixture_attach(&fixture));
    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL, 64u, true);
    rdp_cliprdr_state *state = rdp_freerdp_cliprdr_state(fixture.ctx);
    RFB_CHECK(state != NULL);

    static const BYTE latin1[] = { 'A', 0x1Bu, 0xE9u, 0u };
    CLIPRDR_FORMAT_DATA_RESPONSE incoming;
    memset(&incoming, 0, sizeof(incoming));
    incoming.common.msgFlags = CB_RESPONSE_OK;
    incoming.common.dataLen = (UINT32)sizeof(latin1);
    incoming.requestedFormatData = latin1;
    state->server_format_id = CF_TEXT;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_OK);

    WCHAR unicode[] = { (WCHAR)'o', (WCHAR)'k', 0u };
    incoming.common.dataLen = (UINT32)sizeof(unicode);
    incoming.requestedFormatData = (const BYTE *)(const void *)unicode;
    state->server_format_id = CF_UNICODETEXT;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_OK);

    state->server_format_id = 999u;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_OK);

    cliprdr_fault_allocator fault;
    rfb_allocator allocator = cliprdr_fault_allocator_make(&fault, 2u);
    state->allocator = &allocator;
    state->server_format_id = CF_TEXT;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_NO_MEMORY);
    RFB_CHECK_EQ_UINT(fault.calls, 2u);
    RFB_CHECK_EQ_UINT(fault.frees, 1u);

    cliprdr_callback_fixture_destroy(&fixture);
    cliprdr_restore_host_tools(saved_path);
}

RFB_TEST(rdp_cliprdr_callbacks,
         host_tools__exercise_outbound_and_unsanitized_inbound_text)
{
    cliprdr_fake_host_tools tools;
    const bool tools_ready = cliprdr_fake_host_tools_start(&tools);
    RFB_CHECK(tools_ready);
    if (!tools_ready) {
        return;
    }
    cliprdr_callback_fixture fixture;
    RFB_CHECK(cliprdr_callback_fixture_init(&fixture));
    if (fixture.ctx == NULL) {
        cliprdr_fake_host_tools_stop(&tools);
        return;
    }
    RFB_CHECK(cliprdr_callback_fixture_attach(&fixture));
    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_BIDIRECTIONAL, 64u, false);
    rdp_cliprdr_state *state = rdp_freerdp_cliprdr_state(fixture.ctx);
    RFB_CHECK(state != NULL);

    CLIPRDR_MONITOR_READY ready;
    memset(&ready, 0, sizeof(ready));
    RFB_CHECK_EQ_UINT(fixture.clip.MonitorReady(&fixture.clip, &ready),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.format_count, 1u);
    RFB_CHECK_EQ_UINT(fixture.capture.format_id, CF_UNICODETEXT);

    CLIPRDR_FORMAT_DATA_REQUEST outgoing;
    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.requestedFormatId = CF_TEXT;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataRequest(
                          &fixture.clip, &outgoing),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.data_response_flags, CB_RESPONSE_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.data_response_length, 6u);
    static const BYTE expected_text[] = {'h', 'e', 'l', 'l', 'o', 0u};
    RFB_CHECK_MEM_EQ(fixture.capture.data_response, expected_text,
                     sizeof expected_text);

    outgoing.requestedFormatId = CF_UNICODETEXT;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataRequest(
                          &fixture.clip, &outgoing),
                      CHANNEL_RC_OK);
    RFB_CHECK(fixture.capture.data_response_length >= 12u);
    RFB_CHECK_EQ_UINT(fixture.capture.data_response[0], (BYTE)'h');

    fixture.capture.data_response_result = CHANNEL_RC_BAD_PROC;
    outgoing.requestedFormatId = CF_TEXT;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataRequest(
                          &fixture.clip, &outgoing),
                      CHANNEL_RC_BAD_PROC);
    fixture.capture.data_response_result = CHANNEL_RC_OK;

    static const BYTE remote[] = {'r', 'e', 'm', 'o', 't', 'e'};
    CLIPRDR_FORMAT_DATA_RESPONSE incoming;
    memset(&incoming, 0, sizeof(incoming));
    incoming.common.msgFlags = CB_RESPONSE_OK;
    incoming.common.dataLen = (UINT32)sizeof remote;
    incoming.requestedFormatData = remote;
    state->server_format_id = CF_TEXT;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_OK);
    char copied[16];
    size_t copied_size = 0u;
    RFB_CHECK(cliprdr_read_file(tools.output_path, copied, sizeof copied,
                                &copied_size));
    RFB_CHECK_EQ_UINT(copied_size, sizeof remote);
    RFB_CHECK_MEM_EQ(copied, remote, sizeof remote);

    incoming.common.dataLen = 0u;
    incoming.requestedFormatData = NULL;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_OK);
    RFB_CHECK(cliprdr_read_file(tools.output_path, copied, sizeof copied,
                                &copied_size));
    RFB_CHECK_EQ_UINT(copied_size, 0u);

    cliprdr_fault_allocator fault;
    rfb_allocator allocator = cliprdr_fault_allocator_make(&fault, 1u);
    state->allocator = &allocator;
    incoming.common.dataLen = (UINT32)sizeof remote;
    incoming.requestedFormatData = remote;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fault.calls, 1u);

    allocator = cliprdr_fault_allocator_make(&fault, 2u);
    state->allocator = &allocator;
    outgoing.requestedFormatId = CF_TEXT;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataRequest(
                          &fixture.clip, &outgoing),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.data_response_flags, CB_RESPONSE_FAIL);
    RFB_CHECK_EQ_UINT(fault.calls, 2u);

    state->allocator = NULL;
    state->policy_valid = false;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataRequest(
                          &fixture.clip, &outgoing),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.data_response_flags, CB_RESPONSE_FAIL);

    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_BIDIRECTIONAL, 64u, false);
    fixture.clip.ClientFormatDataResponse = NULL;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataRequest(
                          &fixture.clip, &outgoing),
                      CHANNEL_RC_BAD_PROC);

    cliprdr_callback_fixture_destroy(&fixture);
    cliprdr_fake_host_tools_stop(&tools);
}

RFB_TEST(rdp_cliprdr_callbacks,
         file_and_lock_callbacks__refuse_files_and_accept_noop_locks)
{
    cliprdr_callback_fixture fixture;
    RFB_CHECK(cliprdr_callback_fixture_init(&fixture));
    if (fixture.ctx == NULL) {
        return;
    }
    RFB_CHECK(cliprdr_callback_fixture_attach(&fixture));

    CLIPRDR_FILE_CONTENTS_REQUEST file_request;
    CLIPRDR_LOCK_CLIPBOARD_DATA lock;
    CLIPRDR_UNLOCK_CLIPBOARD_DATA unlock;
    memset(&file_request, 0, sizeof(file_request));
    memset(&lock, 0, sizeof(lock));
    memset(&unlock, 0, sizeof(unlock));
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFileContentsRequest(
                          NULL, &file_request),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFileContentsRequest(
                          &fixture.clip, &file_request),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.file_response_calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.capture.file_response_flags, CB_RESPONSE_FAIL);
    RFB_CHECK_EQ_UINT(fixture.clip.ServerLockClipboardData(
                          &fixture.clip, &lock),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.clip.ServerUnlockClipboardData(
                          &fixture.clip, &unlock),
                      CHANNEL_RC_OK);

    fixture.clip.ClientFileContentsResponse = NULL;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFileContentsRequest(
                          &fixture.clip, &file_request),
                      CHANNEL_RC_OK);
    cliprdr_callback_fixture_destroy(&fixture);
}

RFB_TEST(rdp_cliprdr_callbacks,
         disconnect__removes_every_installed_callback)
{
    cliprdr_callback_fixture fixture;
    RFB_CHECK(cliprdr_callback_fixture_init(&fixture));
    if (fixture.ctx == NULL) {
        return;
    }

    cliprdr_callback_fixture_publish_connected(
        &fixture, CLIPRDR_SVC_CHANNEL_NAME, &fixture.clip);
    RFB_CHECK(fixture.clip.ServerLockClipboardData != NULL);
    RFB_CHECK(fixture.clip.ServerUnlockClipboardData != NULL);

    cliprdr_callback_fixture_publish_disconnected(
        &fixture, CLIPRDR_SVC_CHANNEL_NAME, &fixture.clip);
    RFB_CHECK(fixture.clip.custom == NULL);
    RFB_CHECK(fixture.clip.ServerLockClipboardData == NULL);
    RFB_CHECK(fixture.clip.ServerUnlockClipboardData == NULL);

    cliprdr_callback_fixture_destroy(&fixture);
}

RFB_TEST(rdp_cliprdr_callbacks,
         format_negotiation__covers_absent_state_order_and_policy_edges)
{
    cliprdr_callback_fixture fixture;
    RFB_CHECK(cliprdr_callback_fixture_init(&fixture));
    if (fixture.ctx == NULL) {
        return;
    }
    RFB_CHECK(cliprdr_callback_fixture_attach(&fixture));
    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL, 64u, true);
    rdp_cliprdr_state *state = rdp_freerdp_cliprdr_state(fixture.ctx);
    RFB_CHECK(state != NULL);

    CLIPRDR_FORMAT_LIST list;
    memset(&list, 0, sizeof(list));
    fixture.clip.ClientFormatListResponse = NULL;
    fixture.clip.custom = NULL;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatList(&fixture.clip, &list),
                      CHANNEL_RC_BAD_PROC);
    fixture.clip.custom = state;

    CLIPRDR_FORMAT formats[2];
    memset(formats, 0, sizeof(formats));
    formats[0].formatId = 999u;
    list.numFormats = 1u;
    list.formats = formats;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatList(&fixture.clip, &list),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.data_request_calls, 0u);

    formats[0].formatId = CF_UNICODETEXT;
    formats[1].formatId = CF_TEXT;
    list.numFormats = 2u;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatList(&fixture.clip, &list),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.data_request_calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.capture.requested_format_id, CF_UNICODETEXT);

    rdp_cliprdr_configure(fixture.ctx, NULL, true);
    fixture.capture.data_request_calls = 0u;
    formats[0].formatId = CF_TEXT;
    list.numFormats = 1u;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatList(&fixture.clip, &list),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.data_request_calls, 0u);

    cliprdr_callback_fixture_publish_disconnected(&fixture, NULL,
                                                  &fixture.clip);
    RFB_CHECK(fixture.clip.custom == state);
    cliprdr_callback_fixture_publish_disconnected(
        &fixture, CLIPRDR_SVC_CHANNEL_NAME, NULL);
    RFB_CHECK(fixture.clip.custom == state);
    fixture.clip.custom = NULL;
    cliprdr_callback_fixture_publish_disconnected(
        &fixture, CLIPRDR_SVC_CHANNEL_NAME, &fixture.clip);
    RFB_CHECK(fixture.clip.ServerFormatList == NULL);
    RFB_CHECK(fixture.clip.ServerFormatDataResponse == NULL);

    cliprdr_callback_fixture_destroy(&fixture);
}

RFB_TEST(rdp_cliprdr_callbacks,
         inbound_text__covers_unicode_bounds_policy_and_empty_failures)
{
    char *saved_path = cliprdr_hide_host_tools();
    RFB_CHECK(saved_path != NULL);
    if (saved_path == NULL) {
        return;
    }
    cliprdr_callback_fixture fixture;
    RFB_CHECK(cliprdr_callback_fixture_init(&fixture));
    if (fixture.ctx == NULL) {
        cliprdr_restore_host_tools(saved_path);
        return;
    }
    RFB_CHECK(cliprdr_callback_fixture_attach(&fixture));
    rdp_cliprdr_state *state = rdp_freerdp_cliprdr_state(fixture.ctx);
    RFB_CHECK(state != NULL);

    WCHAR unicode[] = {
        (WCHAR)'t', (WCHAR)'e', (WCHAR)'x', (WCHAR)'t', 0u,
    };
    CLIPRDR_FORMAT_DATA_RESPONSE incoming;
    memset(&incoming, 0, sizeof(incoming));
    incoming.common.msgFlags = CB_RESPONSE_OK;
    incoming.common.dataLen = (UINT32)sizeof(unicode);
    incoming.requestedFormatData = (const BYTE *)(const void *)unicode;

    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL, 3u, false);
    state->server_format_id = CF_UNICODETEXT;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_OK);

    static const BYTE remote[] = { 'o', 'k' };
    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_LOCAL_TO_REMOTE, 64u, false);
    state->server_format_id = CF_TEXT;
    incoming.common.dataLen = (UINT32)sizeof(remote);
    incoming.requestedFormatData = remote;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_OK);

    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL, 0u, false);
    incoming.common.dataLen = 0u;
    incoming.requestedFormatData = NULL;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_OK);

    cliprdr_fault_allocator fault;
    rfb_allocator allocator = cliprdr_fault_allocator_make(&fault, 1u);
    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL, 64u, false);
    state->allocator = &allocator;
    state->server_format_id = CF_UNICODETEXT;
    incoming.common.dataLen = (UINT32)sizeof(unicode);
    incoming.requestedFormatData = (const BYTE *)(const void *)unicode;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fault.calls, 1u);

    allocator = cliprdr_fault_allocator_make(&fault, 1u);
    state->allocator = &allocator;
    state->server_format_id = CF_TEXT;
    incoming.common.dataLen = 0u;
    incoming.requestedFormatData = NULL;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fault.calls, 1u);

    state->allocator = NULL;
    fixture.clip.custom = NULL;
    incoming.common.dataLen = (UINT32)sizeof(unicode);
    incoming.requestedFormatData = (const BYTE *)(const void *)unicode;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataResponse(
                          &fixture.clip, &incoming),
                      CHANNEL_RC_OK);
    fixture.clip.custom = state;

    cliprdr_callback_fixture_destroy(&fixture);
    cliprdr_restore_host_tools(saved_path);
}

RFB_TEST(rdp_cliprdr_callbacks,
         outbound_text__covers_empty_host_and_response_failures)
{
    char *saved_path = cliprdr_hide_host_tools();
    RFB_CHECK(saved_path != NULL);
    if (saved_path == NULL) {
        return;
    }
    cliprdr_callback_fixture fixture;
    RFB_CHECK(cliprdr_callback_fixture_init(&fixture));
    if (fixture.ctx == NULL) {
        cliprdr_restore_host_tools(saved_path);
        return;
    }
    RFB_CHECK(cliprdr_callback_fixture_attach(&fixture));
    cliprdr_callback_fixture_set_policy(
        &fixture, FARSEE_CLIP_DIRECTION_BIDIRECTIONAL, 64u, false);
    rdp_cliprdr_state *state = rdp_freerdp_cliprdr_state(fixture.ctx);
    RFB_CHECK(state != NULL);

    cliprdr_fault_allocator fault;
    rfb_allocator allocator = cliprdr_fault_allocator_make(&fault, 1u);
    state->allocator = &allocator;
    CLIPRDR_MONITOR_READY ready;
    memset(&ready, 0, sizeof(ready));
    RFB_CHECK_EQ_UINT(fixture.clip.MonitorReady(&fixture.clip, &ready),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fault.calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.capture.format_count, 0u);

    state->allocator = NULL;
    fixture.clip.custom = NULL;
    RFB_CHECK_EQ_UINT(fixture.clip.MonitorReady(&fixture.clip, &ready),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.format_count, 0u);
    fixture.clip.custom = state;

    CLIPRDR_FORMAT_DATA_REQUEST outgoing;
    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.requestedFormatId = CF_TEXT;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataRequest(
                          &fixture.clip, &outgoing),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.data_response_flags, CB_RESPONSE_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.data_response_length, 1u);
    RFB_CHECK_EQ_UINT(fixture.capture.data_response[0], 0u);

    fixture.clip.ClientFormatDataResponse = NULL;
    outgoing.requestedFormatId = 999u;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataRequest(
                          &fixture.clip, &outgoing),
                      CHANNEL_RC_BAD_PROC);
    fixture.clip.ClientFormatDataResponse = cliprdr_capture_data_response;

    allocator = cliprdr_fault_allocator_make(&fault, 2u);
    state->allocator = &allocator;
    outgoing.requestedFormatId = CF_UNICODETEXT;
    RFB_CHECK_EQ_UINT(fixture.clip.ServerFormatDataRequest(
                          &fixture.clip, &outgoing),
                      CHANNEL_RC_OK);
    RFB_CHECK_EQ_UINT(fixture.capture.data_response_flags, CB_RESPONSE_FAIL);
    RFB_CHECK_EQ_UINT(fault.calls, 2u);
    RFB_CHECK_EQ_UINT(fault.frees, 1u);

    state->allocator = NULL;
    cliprdr_callback_fixture_destroy(&fixture);
    cliprdr_restore_host_tools(saved_path);
}

#endif  // FARSEE_WITH_RDP
