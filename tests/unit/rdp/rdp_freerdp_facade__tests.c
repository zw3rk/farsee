// SPDX-License-Identifier: Apache-2.0
//
// R0 — FreeRDP facade smoke test (§22/R0 exit criterion).
//
// "A minimal test program creates and destroys a FreeRDP context through
// the Farsee-private facade under sanitizers." This is that test. It is
// compiled ONLY under FARSEE_WITH_RDP=1; in the no-RDP build the file is
// empty: the no-RDP build has no registered tests from this file.
//
// SANITIZER NOTE (ADR-0006): on macOS 26, loading FreeRDP's dynamic library
// under AddressSanitizer deadlocks during dyld initialization (same class
// of issue as the documented nix-LLVM ASan deadlock). Apple Clang's ASan
// is affected too for this particular complex dylib. Therefore the tests
// that exercise FreeRDP at runtime skip themselves on darwin under a
// sanitizer; the version check (no runtime FreeRDP call) still runs. The
// Linux sanitizer CI covers the full create/destroy path.

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_callbacks.h"
#include "protocol/rdp/rdp_freerdp_facade.h"
#include "protocol/rdp/rdp_freerdp_facade_internal.h"
#include "farsee/farsee_thread.h"
#include "tests/test_framework/rfb_test.h"

#include <freerdp/error.h>
#include <freerdp/freerdp.h>
#include <winpr/synch.h>
#include <winpr/wlog.h>

#include <poll.h>
#include <string.h>

static bool pinned_loggers_have_level(DWORD level)
{
    static const char *const loggers[] = {
        "com.freerdp",
        "com.freerdp.core",
        "com.freerdp.core.rdp",
        "com.freerdp.core.connection",
        "com.freerdp.core.license",
        "com.freerdp.codec",
        "com.freerdp.codec.nsc",
        "com.freerdp.channels",
        "com.winpr",
        "com.winpr.sspi",
        "com.winpr.sspi.Kerberos",
        "com.winpr.thread",
    };
    wLog *root = WLog_GetRoot();
    if (root == NULL || WLog_GetLogLevel(root) != level) {
        return false;
    }
    for (size_t i = 0u; i < sizeof loggers / sizeof loggers[0]; i++) {
        wLog *log = WLog_Get(loggers[i]);
        if (log == NULL || WLog_GetLogLevel(log) != level) {
            return false;
        }
    }
    return true;
}

RFB_TEST(rdp_facade, freerdp_version__is_pinned_3x)
{
    // §15.3: fail configuration when the pinned API version is not present.
    RFB_CHECK(rdp_freerdp_version_ok());
    const char *v = rdp_freerdp_version_string();
    RFB_CHECK(v != NULL);
    RFB_CHECK(v[0] == '3');
}

RFB_TEST(rdp_facade, wlog_policy__all_levels_and_invalid_enum)
{
    static const struct {
        rdp_liblog_level level;
        DWORD wlevel;
    } levels[] = {
        {RDP_LIBLOG_ERROR, WLOG_ERROR},
        {RDP_LIBLOG_WARN, WLOG_WARN},
        {RDP_LIBLOG_INFO, WLOG_INFO},
        {RDP_LIBLOG_DEBUG, WLOG_DEBUG},
        {RDP_LIBLOG_TRACE, WLOG_TRACE},
    };

    RFB_CHECK(rdp_freerdp_set_library_log_level(RDP_LIBLOG_OFF));
    RFB_CHECK(pinned_loggers_have_level(WLOG_OFF));
    for (size_t i = 0u; i < sizeof levels / sizeof levels[0]; i++) {
#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
        RFB_CHECK(rdp_freerdp_set_library_log_level(levels[i].level));
        RFB_CHECK(pinned_loggers_have_level(levels[i].wlevel));
#else
        RFB_CHECK(!rdp_freerdp_set_library_log_level(levels[i].level));
        RFB_CHECK(pinned_loggers_have_level(WLOG_OFF));
#endif
    }
    RFB_CHECK(!rdp_freerdp_set_library_log_level((rdp_liblog_level)999));
    RFB_CHECK(pinned_loggers_have_level(WLOG_OFF));

    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    rdp_freerdp_destroy(&ctx);
    RFB_CHECK(rdp_freerdp_set_library_log_level(RDP_LIBLOG_OFF));
}

RFB_TEST(rdp_facade, create_destroy__no_leak_under_sanitizers)
{
    // The R0 exit-criterion object: create + destroy must be clean.
    // (Built into the RDP-enabled test binary; the macOS ASan row builds
    // without FARSEE_WITH_RDP because FreeRDP's dylib deadlocks under
    // macOS ASan at dyld init — ADR-0006 class. The dev build and the
    // Linux ASan row exercise this path.)
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    rdp_freerdp_destroy(&ctx);
    RFB_CHECK(ctx == NULL);
}

RFB_TEST(rdp_facade, destroy_null__safe)
{
    rdp_freerdp_ctx *ctx = NULL;
    rdp_freerdp_destroy(&ctx);
    RFB_CHECK(ctx == NULL);
    rdp_freerdp_destroy(&ctx);  // double-destroy safe
    RFB_CHECK(ctx == NULL);
}

RFB_TEST(rdp_facade, create_many__no_resource_growth)
{
    // Create+destroy in a loop; any FreeRDP instance/context leak would
    // trip ASan leak detection at process exit.
    for (int i = 0; i < 64; ++i) {
        rdp_freerdp_ctx *ctx = rdp_freerdp_create();
        RFB_CHECK(ctx != NULL);
        rdp_freerdp_destroy(&ctx);
    }
}

typedef struct facade_concurrent_arg {
    rdp_liblog_level level;
    bool ok;
} facade_concurrent_arg;

static void *configure_and_create_facades(void *opaque)
{
    facade_concurrent_arg *arg = (facade_concurrent_arg *)opaque;
    arg->ok = true;
    for (size_t i = 0u; i < 16u; i++) {
#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
        const bool expected = true;
#else
        const bool expected = arg->level == RDP_LIBLOG_OFF;
#endif
        if (rdp_freerdp_set_library_log_level(arg->level) != expected) {
            arg->ok = false;
            break;
        }
        rdp_freerdp_ctx *ctx = rdp_freerdp_create();
        if (ctx == NULL) {
            arg->ok = false;
            break;
        }
        rdp_freerdp_destroy(&ctx);
    }
    return NULL;
}

RFB_TEST(rdp_facade, wlog_policy__concurrent_create_and_configuration_safe)
{
    facade_concurrent_arg a = { .level = RDP_LIBLOG_OFF, .ok = false };
    facade_concurrent_arg b = { .level = RDP_LIBLOG_ERROR, .ok = false };
    farsee_thread *ta = farsee_thread_create(configure_and_create_facades, &a);
    farsee_thread *tb = farsee_thread_create(configure_and_create_facades, &b);
    RFB_CHECK(ta != NULL);
    RFB_CHECK(tb != NULL);
    farsee_thread_join(&ta, NULL);
    farsee_thread_join(&tb, NULL);
    RFB_CHECK(a.ok);
    RFB_CHECK(b.ok);
    RFB_CHECK(rdp_freerdp_set_library_log_level(RDP_LIBLOG_OFF));
}

RFB_TEST(rdp_facade, peer_disconnect__classifies_only_documented_clean_codes)
{
    static const UINT32 clean_codes[] = {
        FREERDP_ERROR_SUCCESS,
        FREERDP_ERROR_NONE,
        FREERDP_ERROR_LOGOFF_BY_USER,
        FREERDP_ERROR_RPC_INITIATED_LOGOFF,
        FREERDP_ERROR_RPC_INITIATED_DISCONNECT,
        FREERDP_ERROR_RPC_INITIATED_DISCONNECT_BY_USER,
        FREERDP_ERROR_DISCONNECTED_BY_OTHER_CONNECTION,
        FREERDP_ERROR_IDLE_TIMEOUT,
    };
    static const UINT32 failure_codes[] = {
        FREERDP_ERROR_LOGON_TIMEOUT,
        FREERDP_ERROR_SERVER_DENIED_CONNECTION,
        FREERDP_ERROR_CONNECT_TRANSPORT_FAILED,
    };

    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    freerdp *instance = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    RFB_CHECK(instance != NULL);
    RFB_CHECK(instance->context != NULL);

    for (size_t i = 0u; i < sizeof clean_codes / sizeof clean_codes[0]; i++) {
        freerdp_set_last_error(instance->context, clean_codes[i]);
        RFB_CHECK_EQ_UINT(rdp_freerdp_last_error(ctx), clean_codes[i]);
        RFB_CHECK(rdp_freerdp_is_clean_peer_disconnect(ctx));
    }
    for (size_t i = 0u; i < sizeof failure_codes / sizeof failure_codes[0];
         i++) {
        freerdp_set_last_error(instance->context, failure_codes[i]);
        RFB_CHECK_EQ_UINT(rdp_freerdp_last_error(ctx), failure_codes[i]);
        RFB_CHECK(!rdp_freerdp_is_clean_peer_disconnect(ctx));
    }
    rdp_freerdp_destroy(&ctx);
}

static BOOL wait_for_connect_watcher_then_reject(freerdp *instance)
{
    (void)instance;
    (void)poll(NULL, 0, 100);
    return FALSE;
}

RFB_TEST(rdp_facade, connect_stop__wakes_a_blocked_preconnect)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    freerdp *instance = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    RFB_CHECK(instance != NULL);
    RFB_CHECK(instance->context != NULL);
    instance->PreConnect = wait_for_connect_watcher_then_reject;

    farsee_atomic_int stop = 1;
    RFB_CHECK(!rdp_freerdp_connect_with_stop(ctx, &stop));
    HANDLE abort_event = freerdp_abort_event(instance->context);
    RFB_CHECK(abort_event != NULL);
    RFB_CHECK_EQ_UINT(WaitForSingleObject(abort_event, 0), WAIT_OBJECT_0);

    rdp_freerdp_destroy(&ctx);
}

static BOOL reject_preconnect_immediately(freerdp *instance)
{
    (void)instance;
    return FALSE;
}

RFB_TEST(rdp_facade, connect__rejection_joins_optional_watcher)
{
    rdp_freerdp_ctx *watched = rdp_freerdp_create();
    RFB_CHECK(watched != NULL);
    freerdp *watched_instance =
        (freerdp *)rdp_freerdp_instance_opaque(watched);
    RFB_CHECK(watched_instance != NULL);
    watched_instance->PreConnect = reject_preconnect_immediately;
    farsee_atomic_int stop = 0;
    RFB_CHECK(!rdp_freerdp_connect_with_stop(watched, &stop));
    RFB_CHECK(!farsee_atomic_int_load_nonzero(&stop));
    rdp_freerdp_destroy(&watched);

    rdp_freerdp_ctx *unwatched = rdp_freerdp_create();
    RFB_CHECK(unwatched != NULL);
    freerdp *unwatched_instance =
        (freerdp *)rdp_freerdp_instance_opaque(unwatched);
    RFB_CHECK(unwatched_instance != NULL);
    unwatched_instance->PreConnect = reject_preconnect_immediately;
    RFB_CHECK(!rdp_freerdp_connect(unwatched));
    rdp_freerdp_destroy(&unwatched);
}

RFB_TEST(rdp_facade, nested_context_guards__fail_closed_and_reset_output)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    freerdp *instance = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    RFB_CHECK(instance != NULL);
    RFB_CHECK(instance->context != NULL);

    farsee_atomic_int stop = 1;
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    budget.stop_flag = &stop;
    RFB_CHECK_EQ_INT(rdp_freerdp_run_until(ctx, &budget, NULL).code,
                     FARSEE_E_OK);

    rdpContext *saved_context = instance->context;
    instance->context = NULL;
    uint64_t in_bytes = 11u;
    uint64_t out_bytes = 22u;
    RFB_CHECK(!rdp_freerdp_wire_stats(ctx, &in_bytes, &out_bytes));
    RFB_CHECK_EQ_UINT(in_bytes, 11u);
    RFB_CHECK_EQ_UINT(out_bytes, 22u);
    RFB_CHECK_EQ_INT(rdp_freerdp_wire_fd(ctx), -1);

    bool got_frame = true;
    farsee_error error = rdp_freerdp_run_until(ctx, &budget, &got_frame);
    RFB_CHECK_EQ_INT(error.code, FARSEE_ERR_STATE);
    RFB_CHECK_EQ_INT(error.subsystem, FARSEE_SUB_RDP);
    RFB_CHECK(!got_frame);
    rdp_freerdp_request_stop(ctx);
    RFB_CHECK_EQ_UINT(rdp_freerdp_last_error(ctx), 0u);
    RFB_CHECK(strcmp(rdp_freerdp_last_error_name(ctx),
                     "FREERDP_ERROR_SUCCESS") == 0);
    RFB_CHECK(!rdp_freerdp_is_clean_peer_disconnect(ctx));
    instance->context = saved_context;

    void *saved_rdp = saved_context->rdp;
    saved_context->rdp = NULL;
    RFB_CHECK(!rdp_freerdp_wire_stats(ctx, &in_bytes, &out_bytes));
    RFB_CHECK_EQ_UINT(in_bytes, 11u);
    RFB_CHECK_EQ_UINT(out_bytes, 22u);
    saved_context->rdp = saved_rdp;

    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_facade, partial_context__missing_instance_fails_closed)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    freerdp *saved_instance =
        (freerdp *)rdp_freerdp_instance_opaque(ctx);
    RFB_CHECK(saved_instance != NULL);

    // The private facade starts with a NULL instance during construction.
    // Recreate that documented partial state through object representation so
    // every public defensive guard can be checked without exposing the type.
    freerdp *missing_instance = NULL;
    memcpy(ctx, &missing_instance, sizeof missing_instance);
    RFB_CHECK(rdp_freerdp_instance_opaque(ctx) == NULL);

    uint64_t in_bytes = 11u;
    uint64_t out_bytes = 22u;
    RFB_CHECK(!rdp_freerdp_wire_stats(ctx, &in_bytes, &out_bytes));
    RFB_CHECK_EQ_UINT(in_bytes, 11u);
    RFB_CHECK_EQ_UINT(out_bytes, 22u);
    RFB_CHECK_EQ_INT(rdp_freerdp_wire_fd(ctx), -1);
    RFB_CHECK(!rdp_freerdp_connect(ctx));

    farsee_atomic_int stop = 1;
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    budget.stop_flag = &stop;
    bool got_frame = true;
    farsee_error error = rdp_freerdp_run_until(ctx, &budget, &got_frame);
    RFB_CHECK_EQ_INT(error.code, FARSEE_ERR_STATE);
    RFB_CHECK(!got_frame);

    rdp_freerdp_request_stop(ctx);
    rdp_freerdp_disconnect(ctx);
    RFB_CHECK_EQ_UINT(rdp_freerdp_last_error(ctx), 0u);
    RFB_CHECK(strcmp(rdp_freerdp_last_error_name(ctx),
                     "FREERDP_ERROR_SUCCESS") == 0);
    RFB_CHECK(!rdp_freerdp_is_clean_peer_disconnect(ctx));

    memcpy(ctx, &saved_instance, sizeof saved_instance);
    RFB_CHECK(rdp_freerdp_instance_opaque(ctx) == saved_instance);
    rdp_freerdp_destroy(&ctx);
}

typedef struct facade_run_edge {
    size_t iterations;
    size_t handle_count;
    bool abort_event_present;
    bool check_ok;
    rdp_freerdp_wait_result wait_result;
    uint64_t now_ms;
    uint32_t last_error;
    unsigned shall_calls;
    unsigned abort_calls;
    unsigned wait_calls;
    unsigned check_calls;
    unsigned last_error_calls;
    unsigned char handle_token;
    unsigned char abort_token;
} facade_run_edge;

static void facade_run_edge_init(facade_run_edge *edge)
{
    memset(edge, 0, sizeof *edge);
    edge->iterations = 1u;
    edge->handle_count = 1u;
    edge->abort_event_present = true;
    edge->check_ok = true;
    edge->wait_result = RDP_FREERDP_WAIT_TIMEOUT;
    edge->last_error = FREERDP_ERROR_SUCCESS;
}

static bool facade_edge_shall_disconnect(void *user, void *context)
{
    facade_run_edge *edge = (facade_run_edge *)user;
    RFB_CHECK(context == edge);
    edge->shall_calls++;
    return (size_t)edge->shall_calls > edge->iterations;
}

static void facade_edge_abort(void *user, void *context)
{
    facade_run_edge *edge = (facade_run_edge *)user;
    RFB_CHECK(context == edge);
    edge->abort_calls++;
}

static size_t facade_edge_handles(void *user, void *context,
                                  rdp_freerdp_wait_handle *handles,
                                  size_t capacity)
{
    facade_run_edge *edge = (facade_run_edge *)user;
    RFB_CHECK(context == edge);
    if (edge->handle_count != 0u && capacity != 0u) {
        handles[0] = &edge->handle_token;
    }
    return edge->handle_count;
}

static rdp_freerdp_wait_handle facade_edge_abort_event(void *user,
                                                        void *context)
{
    facade_run_edge *edge = (facade_run_edge *)user;
    RFB_CHECK(context == edge);
    return edge->abort_event_present ? &edge->abort_token : NULL;
}

static rdp_freerdp_wait_result facade_edge_wait(
    void *user, const rdp_freerdp_wait_handle *handles,
    size_t handle_count, uint32_t timeout_ms)
{
    facade_run_edge *edge = (facade_run_edge *)user;
    RFB_CHECK(handles != NULL);
    RFB_CHECK(handle_count != 0u);
    RFB_CHECK_EQ_UINT(timeout_ms, 10u);
    edge->wait_calls++;
    return edge->wait_result;
}

static bool facade_edge_check(void *user, void *context)
{
    facade_run_edge *edge = (facade_run_edge *)user;
    RFB_CHECK(context == edge);
    edge->check_calls++;
    return edge->check_ok;
}

static uint64_t facade_edge_now(void *user)
{
    facade_run_edge *edge = (facade_run_edge *)user;
    return edge->now_ms;
}

static uint32_t facade_edge_last_error(void *user, void *context)
{
    facade_run_edge *edge = (facade_run_edge *)user;
    RFB_CHECK(context == edge);
    edge->last_error_calls++;
    return edge->last_error;
}

static rdp_freerdp_run_ops facade_edge_ops(facade_run_edge *edge)
{
    const rdp_freerdp_run_ops ops = {
        .user = edge,
        .shall_disconnect = facade_edge_shall_disconnect,
        .abort_connect = facade_edge_abort,
        .get_event_handles = facade_edge_handles,
        .abort_event = facade_edge_abort_event,
        .wait = facade_edge_wait,
        .check_event_handles = facade_edge_check,
        .monotonic_ms = facade_edge_now,
        .last_error = facade_edge_last_error,
    };
    return ops;
}

RFB_TEST(rdp_facade, run_context__covers_sink_and_deadline_boundaries)
{
    facade_run_edge edge;
    rdp_display_sink sink;
    rdp_run_budget budget;
    bool got_frame;
    farsee_error error;

    facade_run_edge_init(&edge);
    rdp_freerdp_run_ops ops = facade_edge_ops(&edge);
    rdp_display_sink_init(&sink);
    memset(&budget, 0, sizeof budget);
    budget.sink = &sink;
    budget.deadline_monotonic_ms = 10u;
    edge.now_ms = 5u;
    got_frame = true;
    error = rdp_freerdp_run_context_until(&edge, &budget, &got_frame, &ops);
    RFB_CHECK_EQ_INT(error.code, FARSEE_E_OK);
    RFB_CHECK(!got_frame);
    RFB_CHECK_EQ_UINT(edge.wait_calls, 1u);
    RFB_CHECK_EQ_UINT(edge.last_error_calls, 1u);

    facade_run_edge_init(&edge);
    ops = facade_edge_ops(&edge);
    rdp_display_sink_init(&sink);
    farsee_atomic_int_store(&sink.first_frame_delivered, 1);
    memset(&budget, 0, sizeof budget);
    budget.sink = &sink;
    error = rdp_freerdp_run_context_until(&edge, &budget, NULL, &ops);
    RFB_CHECK_EQ_INT(error.code, FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(edge.wait_calls, 1u);
    RFB_CHECK_EQ_UINT(edge.last_error_calls, 1u);

    facade_run_edge_init(&edge);
    ops = facade_edge_ops(&edge);
    rdp_display_sink_init(&sink);
    farsee_atomic_int_store(&sink.first_frame_delivered, 1);
    memset(&budget, 0, sizeof budget);
    budget.sink = &sink;
    budget.deadline_monotonic_ms = 5u;
    edge.now_ms = 5u;
    error = rdp_freerdp_run_context_until(&edge, &budget, NULL, &ops);
    RFB_CHECK_EQ_INT(error.code, FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(edge.last_error_calls, 0u);

    facade_run_edge_init(&edge);
    ops = facade_edge_ops(&edge);
    rdp_display_sink_init(&sink);
    memset(&budget, 0, sizeof budget);
    budget.sink = &sink;
    budget.deadline_monotonic_ms = 5u;
    edge.now_ms = 5u;
    got_frame = true;
    error = rdp_freerdp_run_context_until(&edge, &budget, &got_frame, &ops);
    RFB_CHECK_EQ_INT(error.code, FARSEE_ERR_TIMEOUT);
    RFB_CHECK(!got_frame);
    RFB_CHECK_EQ_UINT(edge.last_error_calls, 0u);
}

#endif  // FARSEE_WITH_RDP
