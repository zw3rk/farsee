// SPDX-License-Identifier: Apache-2.0
//
// Farsee-private FreeRDP facade (R0/R1 gate, §15.2).
//
// PRIVATE to src/protocol/rdp/. No FreeRDP or WinPR type may cross this
// directory's boundary (§15.2, §4.2). This facade wraps the minimal FreeRDP
// instance/context lifecycle behind Farsee-owned types so the rest of the
// engine adapter never sees FreeRDP headers.
//
// Only compiled when FARSEE_WITH_RDP=1. The compile-time version check
// (rdp_freerdp_version_ok) fails configuration if the pinned API is not
// FreeRDP 3.x (§15.3).

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_FREERDP_FACADE_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_FREERDP_FACADE_H

#include "farsee/farsee_atomic.h"
#include "farsee/farsee_error.h"
#include "farsee/farsee_security.h"
#include "rdp_settings.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque FreeRDP instance/context handle, Farsee-owned.
typedef struct rdp_freerdp_ctx rdp_freerdp_ctx;

// Forward decl (full type is in rdp_callbacks.h): the display sink the
// connect/run path cooperates with to stop on the first delivered frame.
struct rdp_display_sink;

// Optional per-tick hook (e.g. drain Kitty output to the TTY). Called after
// each event-handle pump. Must not block for long; may be NULL.
typedef void (*rdp_run_tick_fn)(void *user);

// Run-loop budget for rdp_freerdp_run_until. The caller sets a deadline and
// optionally asks the loop to return once the sink has delivered its first
// desktop frame (headless capture) — optionally after a settle window so
// progressive paint can finish. Live sessions leave stop_on_first_frame
// false and set stop_flag for SIGINT.
typedef struct rdp_run_budget {
    uint64_t deadline_monotonic_ms;     // absolute monotonic-ms cutoff; 0=none
    bool stop_on_first_frame;           // return after first_frame + settle
    uint64_t settle_ms_after_first;     // keep pumping this long after first
    const struct rdp_display_sink *sink;
    // Optional cooperative stop (e.g. SIGINT). Non-NULL and non-zero
    // ends the loop cleanly. Atomic so a signal handler can set it.
    farsee_atomic_int *stop_flag;
    rdp_run_tick_fn on_tick;            // optional post-pump hook
    void *on_tick_user;
} rdp_run_budget;

// Compile-time + runtime check that the linked FreeRDP is the pinned 3.x
// API (§15.3). Returns true iff FREERDP_VERSION_MAJOR == 3. Compiled into
// the test binary so a wrong-API link fails the R0 test, not just a build.
bool rdp_freerdp_version_ok(void);

// The exact pinned version string (e.g. "3.15.0"), for --build-info (§18.4).
const char *rdp_freerdp_version_string(void);

// FreeRDP/WinPR library log verbosity (WLog). Default is OFF so routine
// WARN/ERROR chatter (neon stubs, kerberos realm, license blob, etc.) does
// not pollute the TTY. Use --verbose / --log-level to raise.
typedef enum {
    RDP_LIBLOG_OFF = 0,  // suppress FreeRDP library logs entirely
    RDP_LIBLOG_ERROR,
    RDP_LIBLOG_WARN,
    RDP_LIBLOG_INFO,
    RDP_LIBLOG_DEBUG,
    RDP_LIBLOG_TRACE,
} rdp_liblog_level;

// Set the FreeRDP/WinPR root WLog level. Safe to call before create.
// Idempotent. Does not affect Farsee's own fprintf diagnostics.
void rdp_freerdp_set_library_log_level(rdp_liblog_level level);

// Create a minimal FreeRDP instance + context (no connection, no channels).
// Returns NULL on allocation/init failure. This is the R0 exit-criterion
// object: create + destroy must be leak-free under sanitizers.
// Applies RDP_LIBLOG_OFF if the caller has not set a library log level yet
// for this process (first create establishes quiet default).
rdp_freerdp_ctx *rdp_freerdp_create(void);

// Destroy the context and the underlying FreeRDP instance/context. Safe on
// NULL. Must never invoke callbacks after return.
void rdp_freerdp_destroy(rdp_freerdp_ctx **ctx);

// PRIVATE accessor for sibling modules in src/protocol/rdp/: the underlying
// FreeRDP instance as an opaque pointer (caller casts to freerdp*). Returns
// NULL if ctx is NULL. NOT for use outside this directory.
void *rdp_freerdp_instance_opaque(const rdp_freerdp_ctx *ctx);

// Cumulative FreeRDP wire totals for live status (downlink / uplink).
// Returns false if ctx is not connected or stats are unavailable.
bool rdp_freerdp_wire_stats(const rdp_freerdp_ctx *ctx, uint64_t *out_in_bytes,
                            uint64_t *out_out_bytes);

// Best-effort TCP fd for kernel RTT (status band). -1 if unknown.
// Uses freerdp_get_event_handles + GetEventFileDescriptor; validates
// SOCK_STREAM via getsockopt. Protocol thread only (T4/T6).
int rdp_freerdp_wire_fd(const rdp_freerdp_ctx *ctx);

// --- Connect / run / disconnect (R6 live path, §15.5) ---------------------
//
// These wrap the FreeRDP connect sequence + event pump behind Farsee-owned
// types. The CLI drives them synchronously on the main thread (the staged
// execution model, ADR-0008); the worker-thread+F3-queue production path
// will call the same primitives from a worker.

// Install callbacks (VerifyX509Certificate/Authenticate/PreConnect/PostConnect/
// PostDisconnect + display updates) and apply the settings bundle. Builds the
// internal callback context from the supplied trust/credentials/policy.
// Returns false if the facade/context is invalid or settings are unsafe.
// known_hosts_path: TOFU store for RDP peer cert fingerprints (SHA-256 of
// DER). Non-NULL enables known_hosts_check in VerifyX509Certificate.
// Pass NULL only in unit tests that do not exercise TOFU.
bool rdp_freerdp_apply_settings(rdp_freerdp_ctx *ctx,
                                const farsee_rdp_settings *settings,
                                const farsee_security_policy *policy,
                                const farsee_credential_response *credentials,
                                farsee_trust_decision trust,
                                const char *known_hosts_path);

// Blocking connect: runs TCP -> TLS -> NLA -> licensing -> PostConnect
// (which initializes the software-GDI framebuffer). Returns true on success.
// On failure the caller can read the FreeRDP last error via
// rdp_freerdp_last_error.
bool rdp_freerdp_connect(rdp_freerdp_ctx *ctx);

// Same as rdp_freerdp_connect, but polls `stop` (when non-NULL) on a helper
// thread and calls freerdp_abort_connect_context so SIGINT can cancel a
// stuck TLS/NLA connect (full2 T5). Signal handlers must only store stop.
bool rdp_freerdp_connect_with_stop(rdp_freerdp_ctx *ctx, farsee_atomic_int *stop);

// Pump FreeRDP event handles until the budget is exhausted or the peer
// disconnects. Returns FARSEE_E_OK on a clean stop (first frame delivered
// or peer-initiated disconnect), or a typed error on transport failure /
// timeout. Sets *out_first_frame if non-NULL and a frame was delivered.
farsee_error rdp_freerdp_run_until(rdp_freerdp_ctx *ctx,
                                   const rdp_run_budget *budget,
                                   bool *out_first_frame);

// Cooperative abort: wake WaitForMultipleObjects and mark the session for
// disconnect. Safe to call from a signal handler's deferred path (not
// async-signal-safe itself — only call from the run loop / main thread
// after a stop_flag is observed, or from a non-signal context).
void rdp_freerdp_request_stop(rdp_freerdp_ctx *ctx);

// Null the borrowed credentials pointer after Farsee wiped its copy.
void rdp_freerdp_clear_credentials(rdp_freerdp_ctx *ctx);

// Disconnect the transport (idempotent). Safe before connect or after a
// failed connect.
void rdp_freerdp_disconnect(rdp_freerdp_ctx *ctx);

// The FreeRDP last-error code (0 == success) and its human-readable name,
// for diagnostics after a failed connect/run. NULL-safe.
uint32_t rdp_freerdp_last_error(const rdp_freerdp_ctx *ctx);
const char *rdp_freerdp_last_error_name(const rdp_freerdp_ctx *ctx);

// True when the last FreeRDP error is a clean peer-initiated disconnect
// (user logoff, another connection took the session, idle timeout, etc.).
// Used so the CLI can report "session ended" instead of a hard failure.
bool rdp_freerdp_is_clean_peer_disconnect(const rdp_freerdp_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_PROTOCOL_RDP_RDP_FREERDP_FACADE_H
