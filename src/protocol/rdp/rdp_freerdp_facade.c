// SPDX-License-Identifier: Apache-2.0
//
// Farsee-private FreeRDP facade implementation (R0/R1 gate, §15.2; R6 connect).
//
// Wraps the minimal FreeRDP instance/context lifecycle and the connect/run/
// disconnect sequence. FreeRDP/WinPR headers are confined to this file; the
// facade exposes only Farsee-owned opaque types. Compiled only under
// FARSEE_WITH_RDP=1.

#include "rdp_freerdp_facade.h"
#include "rdp_callbacks.h"
#include "farsee/farsee_thread.h"  // farsee_thread_monotonic_ms

#include <freerdp/error.h>
#include <freerdp/freerdp.h>
#include <freerdp/version.h>
#include <winpr/synch.h>
#include <winpr/thread.h>  // HANDLE type + WaitForMultipleObjects
#include <winpr/wlog.h>    // WLog_* — library log gate (--verbose)

#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

// True after the first explicit or default set_library_log_level call so
// create() does not clobber a caller that already raised verbosity.
static bool g_rdp_liblog_configured = false;

// The wrapped state. FreeRDP types never appear in the header. The
// callback_context is stored here (not as a stack local) so the installed
// callbacks keep a stable pointer for the whole connection lifetime —
// rdp_callbacks_install copies a pointer to this into the FreeRDP custom
// context (per-instance), which PreConnect/auth/cert callbacks read.
struct rdp_freerdp_ctx {
    freerdp *instance;            // NULL until created; freed in reverse order
    rdp_callback_context cbctx;   // stable storage for the installed callbacks
};

bool rdp_freerdp_version_ok(void)
{
    return FREERDP_VERSION_MAJOR == 3;
}

const char *rdp_freerdp_version_string(void)
{
    return FREERDP_VERSION;
}

void rdp_freerdp_set_library_log_level(rdp_liblog_level level)
{
    DWORD wlevel = WLOG_OFF;
    switch (level) {
    case RDP_LIBLOG_OFF:
        wlevel = WLOG_OFF;
        break;
    case RDP_LIBLOG_ERROR:
        wlevel = WLOG_ERROR;
        break;
    case RDP_LIBLOG_WARN:
        wlevel = WLOG_WARN;
        break;
    case RDP_LIBLOG_INFO:
        wlevel = WLOG_INFO;
        break;
    case RDP_LIBLOG_DEBUG:
        wlevel = WLOG_DEBUG;
        break;
    case RDP_LIBLOG_TRACE:
        wlevel = WLOG_TRACE;
        break;
    default:
        wlevel = WLOG_OFF;
        break;
    }
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
    g_rdp_liblog_configured = true;
}

rdp_freerdp_ctx *rdp_freerdp_create(void)
{
    // Quiet FreeRDP library logs by default (neon stubs, kerberos realm,
    // license blob, runtime-check banners). Caller may raise via
    // rdp_freerdp_set_library_log_level before create.
    if (!g_rdp_liblog_configured) {
        rdp_freerdp_set_library_log_level(RDP_LIBLOG_OFF);
    }

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

bool rdp_freerdp_wire_stats(const rdp_freerdp_ctx *ctx, uint64_t *out_in_bytes,
                            uint64_t *out_out_bytes)
{
    if (ctx == NULL || ctx->instance == NULL || ctx->instance->context == NULL ||
        ctx->instance->context->rdp == NULL) {
        return false;
    }
    UINT64 in_b = 0;
    UINT64 out_b = 0;
    UINT64 in_p = 0;
    UINT64 out_p = 0;
    if (!freerdp_get_stats(ctx->instance->context->rdp, &in_b, &out_b, &in_p,
                           &out_p)) {
        return false;
    }
    if (out_in_bytes != NULL) {
        *out_in_bytes = (uint64_t)in_b;
    }
    if (out_out_bytes != NULL) {
        *out_out_bytes = (uint64_t)out_b;
    }
    return true;
}

int rdp_freerdp_wire_fd(const rdp_freerdp_ctx *ctx)
{
    if (ctx == NULL || ctx->instance == NULL ||
        ctx->instance->context == NULL) {
        return -1;
    }
    // Public FreeRDP 3 path: event handles → file descriptor (T4).
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
    if (ctx == NULL || settings == NULL || policy == NULL) {
        return false;
    }
    // Store the callback context in the facade (stable storage) so the
    // installed callbacks keep a valid pointer for the connection lifetime.
    // The settings/policy/credentials/known_hosts_path pointers are borrowed
    // from the caller (the CLI), which must keep them alive until disconnect.
    // Start at REJECT; peer_cert_decided=false. If FreeRDP never calls
    // VerifyX509 (system-CA trusted peer), Authenticate promotes to approve.
    // If it does call VerifyX509 (untrusted), only that decision applies.
    ctx->cbctx.trust = trust;
    ctx->cbctx.peer_cert_decided = false;
    ctx->cbctx.credentials = credentials;
    ctx->cbctx.policy = policy;
    ctx->cbctx.settings = settings;
    ctx->cbctx.known_hosts_path = known_hosts_path;
    return rdp_callbacks_install(ctx, &ctx->cbctx);
}

// Optional cooperative stop during blocking freerdp_connect (full2 T5).
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
    rdpContext *context = ctx->instance->context;

    // Merge the abort event into the wait set so a future cancel wakes us.
    HANDLE handles[RDP_MAX_HANDLES];
    const HANDLE abortEvt = freerdp_abort_event(context);
    uint64_t first_frame_at_ms = 0;

    while (!freerdp_shall_disconnect_context(context)) {
        // Cooperative stop (SIGINT path): leave cleanly.
        if (farsee_atomic_int_load_nonzero(budget->stop_flag)) {
            freerdp_abort_connect_context(context);
            break;
        }

        DWORD n = freerdp_get_event_handles(context, handles,
                                            RDP_MAX_HANDLES - 1);
        if (n == 0) {
            // No handles to pump: nothing more to do.
            break;
        }
        DWORD waitCount = n;
        if (abortEvt != NULL && n < RDP_MAX_HANDLES - 1) {
            handles[waitCount++] = abortEvt;
        }

        // Pump TTY input BEFORE waiting/painting so keyboard/mouse never
        // sit behind FreeRDP or Kitty present work.
        if (budget->on_tick != NULL) {
            budget->on_tick(budget->on_tick_user);
        }

        // Short wait (10 ms): responsive input without spinning.
        const DWORD waitMs = 10;

        DWORD wr = WaitForMultipleObjects(waitCount, handles, FALSE, waitMs);
        if (wr == WAIT_FAILED) {
            break;
        }
        if (wr != WAIT_TIMEOUT) {
            if (!freerdp_check_event_handles(context)) {
                // Peer closed the transport (logoff / other session / error).
                // Leave the loop; classification happens below.
                break;
            }
        }

        // Again after FreeRDP: input first, then deferred present inside tick.
        if (budget->on_tick != NULL) {
            budget->on_tick(budget->on_tick_user);
        }

        const uint64_t nowMs = farsee_thread_monotonic_ms();

        // Track first real frame, then optionally settle for progressive paint.
        if (budget->sink != NULL &&
            farsee_atomic_int_load_nonzero(
                &budget->sink->first_frame_delivered)) {
            if (out_first_frame != NULL) {
                *out_first_frame = true;
            }
            if (first_frame_at_ms == 0) {
                first_frame_at_ms = nowMs;
            }
            if (budget->stop_on_first_frame) {
                const uint64_t settle = budget->settle_ms_after_first;
                if (settle == 0 || nowMs >= first_frame_at_ms + settle) {
                    return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE,
                                             FARSEE_PHASE_ACTIVE);
                }
            }
        }

        // Deadline check against the project monotonic clock.
        if (budget->deadline_monotonic_ms != 0 &&
            nowMs >= budget->deadline_monotonic_ms) {
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
    {
        const UINT32 last = freerdp_get_last_error(context);
        if (last == FREERDP_ERROR_SUCCESS ||
            last == FREERDP_ERROR_NONE ||
            last == FREERDP_ERROR_LOGOFF_BY_USER ||
            last == FREERDP_ERROR_RPC_INITIATED_LOGOFF ||
            last == FREERDP_ERROR_RPC_INITIATED_DISCONNECT ||
            last == FREERDP_ERROR_RPC_INITIATED_DISCONNECT_BY_USER ||
            last == FREERDP_ERROR_DISCONNECTED_BY_OTHER_CONNECTION ||
            last == FREERDP_ERROR_IDLE_TIMEOUT) {
            return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE,
                                     FARSEE_PHASE_ACTIVE);
        }
    }
    // Genuine transport / protocol failure.
    return farsee_error_make(FARSEE_ERR_CONNECT_FAILURE, FARSEE_SUB_RDP,
                             FARSEE_PHASE_ACTIVE);
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
