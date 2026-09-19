// SPDX-License-Identifier: Apache-2.0
//
// Farsee-private FreeRDP facade implementation (R0/R1 gate, §15.2; R6 connect).
//
// Wraps the minimal FreeRDP instance/context lifecycle and the connect/run/
// disconnect sequence. FreeRDP/WinPR headers are confined to this file; the
// facade exposes only Farsee-owned opaque types. Compiled only under
// FARSEE_WITH_RDP=1.

#include "rdp_freerdp_facade_internal.h"
#include "rdp_callbacks.h"
#include "farsee/farsee_thread.h"  // farsee_thread_monotonic_ms

#if (defined(NDEBUG) || defined(FARSEE_RELEASE_BUILD)) && \
    defined(FARSEE_ENABLE_WLOG_DIAGNOSTICS)
#error "FARSEE_ENABLE_WLOG_DIAGNOSTICS cannot be enabled in release builds"
#endif

#include <freerdp/error.h>
#include <freerdp/freerdp.h>
#include <freerdp/version.h>
#include <winpr/synch.h>
#include <winpr/thread.h>  // HANDLE type + WaitForMultipleObjects
#include <winpr/wlog.h>    // WLog_* — developer-only library log gate

#include <poll.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

// True after the first explicit or default set_library_log_level call so
// create() does not clobber a caller that already raised verbosity.
static atomic_flag g_rdp_liblog_lock = ATOMIC_FLAG_INIT;
static bool g_rdp_liblog_configured;

static void rdp_liblog_lock(void)
{
    while (atomic_flag_test_and_set_explicit(&g_rdp_liblog_lock,
                                             memory_order_acquire)) {
        // WLog configuration is short and happens only during setup.
    }
}

static void rdp_liblog_unlock(void)
{
    atomic_flag_clear_explicit(&g_rdp_liblog_lock, memory_order_release);
}

// The wrapped state. FreeRDP types never appear in the header. The
// callback_context is stored here (not as a stack local) so the installed
// callbacks keep a stable pointer for the whole connection lifetime —
// rdp_callbacks_install copies a pointer to this into the FreeRDP custom
// context (per-instance), which PreConnect/auth/cert callbacks read.
struct rdp_freerdp_ctx {
    freerdp *instance;            // NULL until created; freed in reverse order
    rdp_callback_context cbctx;   // stable storage for the installed callbacks
    rdp_cliprdr_state cliprdr;    // per-instance clipboard state
};

rdp_cliprdr_state *rdp_freerdp_cliprdr_state(rdp_freerdp_ctx *ctx)
{
    return (ctx != NULL) ? &ctx->cliprdr : NULL;
}

bool rdp_freerdp_version_ok(void)
{
    return FREERDP_VERSION_MAJOR == 3;
}

const char *rdp_freerdp_version_string(void)
{
    return FREERDP_VERSION;
}

static bool rdp_library_log_level(rdp_liblog_level level, DWORD *wlevel)
{
    if (wlevel == NULL) {
        return false;
    }
    *wlevel = WLOG_OFF;
    switch (level) {
    case RDP_LIBLOG_OFF:
        *wlevel = WLOG_OFF;
        break;
    case RDP_LIBLOG_ERROR:
        *wlevel = WLOG_ERROR;
        break;
    case RDP_LIBLOG_WARN:
        *wlevel = WLOG_WARN;
        break;
    case RDP_LIBLOG_INFO:
        *wlevel = WLOG_INFO;
        break;
    case RDP_LIBLOG_DEBUG:
        *wlevel = WLOG_DEBUG;
        break;
    case RDP_LIBLOG_TRACE:
        *wlevel = WLOG_TRACE;
        break;
    default:
        return false;
    }
#ifndef FARSEE_ENABLE_WLOG_DIAGNOSTICS
    if (level != RDP_LIBLOG_OFF) {
        *wlevel = WLOG_OFF;
        return false;
    }
#endif
    return true;
}

static void rdp_apply_library_log_level(DWORD wlevel)
{
    wLog *root = WLog_GetRoot();
    if (root != NULL) {
        (void)WLog_SetLogLevel(root, wlevel);
    }
    // Also pin the common FreeRDP/WinPR channels so inheritance quirks
    // cannot re-enable noisy WARN spam under a quiet root.
    static const char *const k_loggers[] = {
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
    for (size_t i = 0; i < sizeof k_loggers / sizeof k_loggers[0]; i++) {
        wLog *log = WLog_Get(k_loggers[i]);
        if (log != NULL) {
            (void)WLog_SetLogLevel(log, wlevel);
        }
    }
}

bool rdp_freerdp_set_library_log_level(rdp_liblog_level level)
{
    DWORD wlevel = WLOG_OFF;
    const bool accepted = rdp_library_log_level(level, &wlevel);
    rdp_liblog_lock();
    rdp_apply_library_log_level(wlevel);
    g_rdp_liblog_configured = true;
    rdp_liblog_unlock();
    return accepted;
}

rdp_freerdp_ctx *rdp_freerdp_create(void)
{
    // Quiet FreeRDP library logs by default (neon stubs, kerberos realm,
    // license blob, runtime-check banners). Caller may raise via
    // rdp_freerdp_set_library_log_level before create.
    rdp_liblog_lock();
    if (!g_rdp_liblog_configured) {
        rdp_apply_library_log_level(WLOG_OFF);
        g_rdp_liblog_configured = true;
    }
    rdp_liblog_unlock();

    rdp_freerdp_ctx *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->instance = freerdp_new();
    if (ctx->instance == NULL) {
        free(ctx);
        return NULL;
    }
    // Farsee custom context (rdpContext + presenter/sink/cbctx). Must set
    // ContextSize before freerdp_context_new allocates the block.
    rdp_callbacks_prepare_instance(ctx->instance);
    // Allocate the rdpContext. Per FreeRDP discipline, context is freed
    // (freerdp_context_free) before the instance (freerdp_free).
    if (!freerdp_context_new(ctx->instance)) {
        freerdp_free(ctx->instance);
        free(ctx);
        return NULL;
    }
    return ctx;
}

void rdp_freerdp_destroy(rdp_freerdp_ctx **ctxp)
{
    if (ctxp == NULL || *ctxp == NULL) {
        return;
    }
    rdp_freerdp_ctx *ctx = *ctxp;
    if (ctx->instance != NULL) {
        // Context first, then instance — reverse order of creation.
        freerdp_context_free(ctx->instance);
        freerdp_free(ctx->instance);
        ctx->instance = NULL;
    }
    free(ctx);
    *ctxp = NULL;
}

void *rdp_freerdp_instance_opaque(const rdp_freerdp_ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    return ctx->instance;
}

static bool rdp_default_stats_active(void *user, void *context)
{
    (void)user;
    return freerdp_is_active_state((rdpContext *)context) != FALSE;
}

static bool rdp_default_get_stats(void *user, void *context,
                                  uint64_t *out_in_bytes,
                                  uint64_t *out_out_bytes)
{
    (void)user;
    rdpContext *rdp_context = (rdpContext *)context;
    UINT64 in_b = 0;
    UINT64 out_b = 0;
    UINT64 in_p = 0;
    UINT64 out_p = 0;
    if (!freerdp_get_stats(rdp_context->rdp, &in_b, &out_b, &in_p, &out_p)) {
        return false;
    }
    *out_in_bytes = (uint64_t)in_b;
    *out_out_bytes = (uint64_t)out_b;
    return true;
}

static const rdp_freerdp_stats_ops rdp_default_stats_ops = {
    .user = NULL,
    .is_active = rdp_default_stats_active,
    .get_stats = rdp_default_get_stats,
};

bool rdp_freerdp_wire_stats_context(
    void *context, uint64_t *out_in_bytes, uint64_t *out_out_bytes,
    const rdp_freerdp_stats_ops *ops)
{
    if (context == NULL || ops == NULL || ops->is_active == NULL ||
        ops->get_stats == NULL || !ops->is_active(ops->user, context)) {
        return false;
    }
    uint64_t in_bytes = 0u;
    uint64_t out_bytes = 0u;
    if (!ops->get_stats(ops->user, context, &in_bytes, &out_bytes)) {
        return false;
    }
    if (out_in_bytes != NULL) {
        *out_in_bytes = in_bytes;
    }
    if (out_out_bytes != NULL) {
        *out_out_bytes = out_bytes;
    }
    return true;
}

bool rdp_freerdp_wire_stats(const rdp_freerdp_ctx *ctx, uint64_t *out_in_bytes,
                            uint64_t *out_out_bytes)
{
    if (ctx == NULL || ctx->instance == NULL || ctx->instance->context == NULL ||
        ctx->instance->context->rdp == NULL) {
        return false;
    }
    return rdp_freerdp_wire_stats_context(
        ctx->instance->context, out_in_bytes, out_out_bytes,
        &rdp_default_stats_ops);
}

int rdp_freerdp_wire_fd(const rdp_freerdp_ctx *ctx)
{
    if (ctx == NULL || ctx->instance == NULL ||
        ctx->instance->context == NULL) {
        return -1;
    }
    // Public FreeRDP 3 path: map event handles to file descriptors.
    HANDLE handles[64];
    const DWORD n =
        freerdp_get_event_handles(ctx->instance->context, handles, 64);
    if (n == 0) {
        return -1;
    }
    for (DWORD i = 0; i < n; i++) {
        if (handles[i] == NULL) {
            continue;
        }
        const int fd = GetEventFileDescriptor(handles[i]);
        if (fd < 0) {
            continue;
        }
        int typ = 0;
        socklen_t tl = (socklen_t)sizeof typ;
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &typ, &tl) == 0 &&
            typ == SOCK_STREAM) {
            return fd;
        }
    }
    return -1;
}

// --- Connect / run / disconnect (R6, §15.5) --------------------------------

bool rdp_freerdp_apply_settings(rdp_freerdp_ctx *ctx,
                                const farsee_rdp_settings *settings,
                                const farsee_security_policy *policy,
                                const farsee_credential_response *credentials,
                                farsee_trust_decision trust,
                                const char *known_hosts_path)
{
    return rdp_freerdp_apply_settings_with_memory_budget(
        ctx, settings, policy, credentials, trust, known_hosts_path, NULL);
}

bool rdp_freerdp_apply_settings_with_memory_budget(
    rdp_freerdp_ctx *ctx, const farsee_rdp_settings *settings,
    const farsee_security_policy *policy,
    const farsee_credential_response *credentials,
    farsee_trust_decision trust, const char *known_hosts_path,
    farsee_memory_budget *memory_budget)
{
    if (ctx == NULL || settings == NULL || policy == NULL) {
        return false;
    }
    // Store the callback context in the facade (stable storage) so the
    // installed callbacks keep a valid pointer for the connection lifetime.
    // The settings/policy/credentials/known_hosts_path pointers are borrowed
    // from the caller (the CLI), which must keep them alive until disconnect.
    // Start at REJECT; peer_cert_decided=false. Outside pin mode, a
    // system-CA trusted peer can skip VerifyX509 and Authenticate promotes it.
    // Pin mode requires VerifyX509 for every peer. Whenever it runs, only its
    // decision applies.
    ctx->cbctx.trust = trust;
    ctx->cbctx.memory_budget = memory_budget;
    ctx->cbctx.allocator = memory_budget != NULL
                               ? farsee_memory_budget_allocator(memory_budget)
                               : rfb_default_allocator();
    ctx->cbctx.peer_cert_decided = false;
    ctx->cbctx.credentials = credentials;
    ctx->cbctx.policy = policy;
    ctx->cbctx.settings = settings;
    ctx->cbctx.known_hosts_path = known_hosts_path;
    return rdp_callbacks_install(ctx, &ctx->cbctx);
}

// Optional cooperative stop during blocking freerdp_connect.
// Signal handler only stores an atomic; this watcher thread calls abort.
typedef struct rdp_connect_watch {
    rdp_freerdp_ctx *ctx;
    farsee_atomic_int *stop;
    farsee_atomic_int done;
} rdp_connect_watch;

static void *rdp_connect_watch_fn(void *arg)
{
    rdp_connect_watch *w = (rdp_connect_watch *)arg;
    if (w == NULL) {
        return NULL;
    }
    while (!farsee_atomic_int_load_nonzero(&w->done)) {
        if (farsee_atomic_int_load_nonzero(w->stop)) {
            if (w->ctx != NULL && w->ctx->instance != NULL &&
                w->ctx->instance->context != NULL) {
                freerdp_abort_connect_context(w->ctx->instance->context);
            }
            break;
        }
        (void)poll(NULL, 0, 50); // 50ms poll
    }
    return NULL;
}

bool rdp_freerdp_connect(rdp_freerdp_ctx *ctx)
{
    return rdp_freerdp_connect_with_stop(ctx, NULL);
}

bool rdp_freerdp_connect_with_stop(rdp_freerdp_ctx *ctx, farsee_atomic_int *stop)
{
    if (ctx == NULL || ctx->instance == NULL) {
        return false;
    }
    rdp_connect_watch watch;
    memset(&watch, 0, sizeof watch);
    watch.ctx = ctx;
    watch.stop = stop;
    farsee_atomic_int_store(&watch.done, 0);
    farsee_thread *th = NULL;
    if (stop != NULL) {
        th = farsee_thread_create(rdp_connect_watch_fn, &watch);
    }
    const bool ok = freerdp_connect(ctx->instance) ? true : false;
    farsee_atomic_int_store(&watch.done, 1);
    if (th != NULL) {
        farsee_thread_join(&th, NULL);
    }
    return ok;
}

// Max FreeRDP event handles we wait on at once (plus one for the abort event).
#define RDP_MAX_HANDLES 64

static bool rdp_default_shall_disconnect(void *user, void *context)
{
    (void)user;
    return freerdp_shall_disconnect_context((rdpContext *)context) != FALSE;
}

static void rdp_default_abort_connect(void *user, void *context)
{
    (void)user;
    freerdp_abort_connect_context((rdpContext *)context);
}

static size_t rdp_default_get_event_handles(
    void *user, void *context, rdp_freerdp_wait_handle *handles,
    size_t capacity)
{
    (void)user;
    if (handles == NULL || capacity > RDP_MAX_HANDLES) {
        return 0u;
    }
    HANDLE native_handles[RDP_MAX_HANDLES];
    const DWORD count = freerdp_get_event_handles(
        (rdpContext *)context, native_handles, (DWORD)capacity);
    for (DWORD i = 0u; i < count && i < (DWORD)capacity; i++) {
        handles[i] = native_handles[i];
    }
    return (size_t)count;
}

static rdp_freerdp_wait_handle rdp_default_abort_event(void *user,
                                                        void *context)
{
    (void)user;
    return freerdp_abort_event((rdpContext *)context);
}

static rdp_freerdp_wait_result rdp_default_wait(
    void *user, const rdp_freerdp_wait_handle *handles,
    size_t handle_count, uint32_t timeout_ms)
{
    (void)user;
    if (handles == NULL || handle_count == 0u ||
        handle_count > RDP_MAX_HANDLES) {
        return RDP_FREERDP_WAIT_FAILED;
    }
    HANDLE native_handles[RDP_MAX_HANDLES];
    for (size_t i = 0u; i < handle_count; i++) {
        native_handles[i] = handles[i];
    }
    const DWORD result = WaitForMultipleObjects(
        (DWORD)handle_count, native_handles, FALSE, (DWORD)timeout_ms);
    if (result == WAIT_FAILED) {
        return RDP_FREERDP_WAIT_FAILED;
    }
    return result == WAIT_TIMEOUT ? RDP_FREERDP_WAIT_TIMEOUT
                                  : RDP_FREERDP_WAIT_SIGNALED;
}

static bool rdp_default_check_event_handles(void *user, void *context)
{
    (void)user;
    return freerdp_check_event_handles((rdpContext *)context) != FALSE;
}

static uint64_t rdp_default_monotonic_ms(void *user)
{
    (void)user;
    return farsee_thread_monotonic_ms();
}

static uint32_t rdp_default_last_error(void *user, void *context)
{
    (void)user;
    return (uint32_t)freerdp_get_last_error((rdpContext *)context);
}

static const rdp_freerdp_run_ops rdp_default_run_ops = {
    .user = NULL,
    .shall_disconnect = rdp_default_shall_disconnect,
    .abort_connect = rdp_default_abort_connect,
    .get_event_handles = rdp_default_get_event_handles,
    .abort_event = rdp_default_abort_event,
    .wait = rdp_default_wait,
    .check_event_handles = rdp_default_check_event_handles,
    .monotonic_ms = rdp_default_monotonic_ms,
    .last_error = rdp_default_last_error,
};

static bool rdp_run_ops_complete(const rdp_freerdp_run_ops *ops)
{
    return ops != NULL &&
           ops->shall_disconnect != NULL &&
           ops->abort_connect != NULL &&
           ops->get_event_handles != NULL &&
           ops->abort_event != NULL &&
           ops->wait != NULL &&
           ops->check_event_handles != NULL &&
           ops->monotonic_ms != NULL &&
           ops->last_error != NULL;
}

static bool rdp_run_error_is_clean(uint32_t last)
{
    switch (last) {
    case FREERDP_ERROR_SUCCESS:
    case FREERDP_ERROR_NONE:
    case FREERDP_ERROR_LOGOFF_BY_USER:
    case FREERDP_ERROR_RPC_INITIATED_LOGOFF:
    case FREERDP_ERROR_RPC_INITIATED_DISCONNECT:
    case FREERDP_ERROR_RPC_INITIATED_DISCONNECT_BY_USER:
    case FREERDP_ERROR_DISCONNECTED_BY_OTHER_CONNECTION:
    case FREERDP_ERROR_IDLE_TIMEOUT:
        return true;
    default:
        return false;
    }
}

farsee_error rdp_freerdp_run_context_until(
    void *context, const rdp_run_budget *budget, bool *out_first_frame,
    const rdp_freerdp_run_ops *ops)
{
    if (out_first_frame != NULL) {
        *out_first_frame = false;
    }
    if (context == NULL || budget == NULL || !rdp_run_ops_complete(ops)) {
        return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_RDP,
                                 FARSEE_PHASE_ACTIVE);
    }

    // Merge the abort event into the wait set so a future cancel wakes us.
    rdp_freerdp_wait_handle handles[RDP_MAX_HANDLES];
    const rdp_freerdp_wait_handle abort_event =
        ops->abort_event(ops->user, context);
    uint64_t first_frame_at_ms = 0;
    bool first_frame_seen = false;

    while (!ops->shall_disconnect(ops->user, context)) {
        // Cooperative stop (SIGINT path): leave cleanly.
        if (farsee_atomic_int_load_nonzero(budget->stop_flag)) {
            ops->abort_connect(ops->user, context);
            break;
        }

        const size_t n = ops->get_event_handles(
            ops->user, context, handles, RDP_MAX_HANDLES - 1u);
        if (n == 0) {
            // No handles to pump: nothing more to do.
            break;
        }
        if (n > RDP_MAX_HANDLES - 1u) {
            return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_RDP,
                                     FARSEE_PHASE_ACTIVE);
        }
        size_t wait_count = n;
        // get_event_handles receives a 63-handle capacity, so the final
        // array slot is always reserved for the cooperative abort event.
        if (abort_event != NULL) {
            handles[wait_count++] = abort_event;
        }

        // Pump TTY input BEFORE waiting/painting so keyboard/mouse never
        // sit behind FreeRDP or Kitty present work.
        if (budget->on_tick != NULL) {
            budget->on_tick(budget->on_tick_user);
        }

        // Short wait (10 ms): responsive input without spinning.
        const uint32_t wait_ms = 10u;

        const rdp_freerdp_wait_result wait_result = ops->wait(
            ops->user, handles, wait_count, wait_ms);
        if (wait_result == RDP_FREERDP_WAIT_FAILED) {
            break;
        }
        if (wait_result != RDP_FREERDP_WAIT_TIMEOUT) {
            if (!ops->check_event_handles(ops->user, context)) {
                // Peer closed the transport (logoff / other session / error).
                // Leave the loop; classification happens below.
                break;
            }
        }

        // Again after FreeRDP: input first, then deferred present inside tick.
        if (budget->on_tick != NULL) {
            budget->on_tick(budget->on_tick_user);
        }

        const uint64_t now_ms = ops->monotonic_ms(ops->user);

        // Track first real frame, then optionally settle for progressive paint.
        if (budget->sink != NULL &&
            farsee_atomic_int_load_nonzero(
                &budget->sink->first_frame_delivered)) {
            if (out_first_frame != NULL) {
                *out_first_frame = true;
            }
            if (!first_frame_seen) {
                first_frame_at_ms = now_ms;
                first_frame_seen = true;
            }
            if (budget->stop_on_first_frame) {
                const uint64_t settle = budget->settle_ms_after_first;
                if (settle == 0u || now_ms - first_frame_at_ms >= settle) {
                    return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE,
                                             FARSEE_PHASE_ACTIVE);
                }
            }
        }

        // Deadline check against the project monotonic clock.
        if (budget->deadline_monotonic_ms != 0 &&
            now_ms >= budget->deadline_monotonic_ms) {
            if (budget->sink != NULL &&
                farsee_atomic_int_load_nonzero(
                    &budget->sink->first_frame_delivered)) {
                // Deadline hit after we already had a frame (settle path).
                if (out_first_frame != NULL) {
                    *out_first_frame = true;
                }
                return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE,
                                         FARSEE_PHASE_ACTIVE);
            }
            return farsee_error_make(FARSEE_ERR_TIMEOUT, FARSEE_SUB_RDP,
                                     FARSEE_PHASE_ACTIVE);
        }
    }

    if (budget->sink != NULL &&
        farsee_atomic_int_load_nonzero(&budget->sink->first_frame_delivered) &&
        out_first_frame != NULL) {
        *out_first_frame = true;
    }
    // Cooperative stop without a frame is still a clean exit (user abort).
    if (farsee_atomic_int_load_nonzero(budget->stop_flag)) {
        return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE,
                                 FARSEE_PHASE_ACTIVE);
    }
    // Peer logoff / session takeover / idle timeout: clean end of session.
    // Do NOT surface these as CONNECT_FAILURE — the session ran successfully
    // until the server ended it (e.g. another user signed in on Windows).
    if (rdp_run_error_is_clean(ops->last_error(ops->user, context))) {
        return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE,
                                 FARSEE_PHASE_ACTIVE);
    }
    // Genuine transport / protocol failure.
    return farsee_error_make(FARSEE_ERR_CONNECT_FAILURE, FARSEE_SUB_RDP,
                             FARSEE_PHASE_ACTIVE);
}

farsee_error rdp_freerdp_run_until(rdp_freerdp_ctx *ctx,
                                   const rdp_run_budget *budget,
                                   bool *out_first_frame)
{
    if (out_first_frame != NULL) {
        *out_first_frame = false;
    }
    if (ctx == NULL || ctx->instance == NULL || ctx->instance->context == NULL ||
        budget == NULL) {
        return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_RDP,
                                 FARSEE_PHASE_ACTIVE);
    }
    return rdp_freerdp_run_context_until(
        ctx->instance->context, budget, out_first_frame, &rdp_default_run_ops);
}

void rdp_freerdp_clear_credentials(rdp_freerdp_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->cbctx.credentials = NULL;
}

void rdp_freerdp_request_stop(rdp_freerdp_ctx *ctx)
{
    if (ctx == NULL || ctx->instance == NULL || ctx->instance->context == NULL) {
        return;
    }
    freerdp_abort_connect_context(ctx->instance->context);
}

void rdp_freerdp_disconnect(rdp_freerdp_ctx *ctx)
{
    if (ctx == NULL || ctx->instance == NULL) {
        return;
    }
    freerdp_disconnect(ctx->instance);
}

uint32_t rdp_freerdp_last_error(const rdp_freerdp_ctx *ctx)
{
    if (ctx == NULL || ctx->instance == NULL || ctx->instance->context == NULL) {
        return 0;
    }
    return (uint32_t)freerdp_get_last_error(ctx->instance->context);
}

const char *rdp_freerdp_last_error_name(const rdp_freerdp_ctx *ctx)
{
    uint32_t code = rdp_freerdp_last_error(ctx);
    if (code == 0) {
        return "FREERDP_ERROR_SUCCESS";
    }
    return freerdp_get_last_error_name(code);
}

bool rdp_freerdp_is_clean_peer_disconnect(const rdp_freerdp_ctx *ctx)
{
    if (ctx == NULL || ctx->instance == NULL || ctx->instance->context == NULL) {
        return false;
    }
    const UINT32 last = freerdp_get_last_error(ctx->instance->context);
    switch (last) {
    case FREERDP_ERROR_SUCCESS:
    case FREERDP_ERROR_NONE:
    case FREERDP_ERROR_LOGOFF_BY_USER:
    case FREERDP_ERROR_RPC_INITIATED_LOGOFF:
    case FREERDP_ERROR_RPC_INITIATED_DISCONNECT:
    case FREERDP_ERROR_RPC_INITIATED_DISCONNECT_BY_USER:
    case FREERDP_ERROR_DISCONNECTED_BY_OTHER_CONNECTION:
    case FREERDP_ERROR_IDLE_TIMEOUT:
        return true;
    default:
        break;
    }
    // Name fallback for FreeRDP builds that renumber classes.
    const char *name = freerdp_get_last_error_name(last);
    if (name == NULL) {
        return false;
    }
    return strstr(name, "LOGOFF") != NULL ||
           strstr(name, "DISCONNECTED_BY_OTHER") != NULL ||
           strstr(name, "RPC_INITIATED_DISCONNECT") != NULL ||
           strstr(name, "IDLE_TIMEOUT") != NULL;
}
