// SPDX-License-Identifier: Apache-2.0
//
// farsee — fail-closed CLI option parsing.
//
// The parser is pure: no I/O, getenv, or sockets. It writes argv data into a
// bounded options struct. Unknown options, missing values, and invalid enums
// return exit-style code 2 with a message in errbuf. The print functions below
// write operator text to a supplied FILE.
//
// main applies process guards, parses, handles early text actions, and
// dispatches the selected live path.

#ifndef FARSEE_INCLUDE_FARSEE_CLI_ARGS_H
#define FARSEE_INCLUDE_FARSEE_CLI_ARGS_H

#if (defined(NDEBUG) || defined(FARSEE_RELEASE_BUILD)) && \
    defined(FARSEE_ENABLE_WLOG_DIAGNOSTICS)
#error "FARSEE_ENABLE_WLOG_DIAGNOSTICS cannot be enabled in release builds"
#endif

#include "farsee/cli_target.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// What the process should do after a successful parse.
typedef enum {
    FARSEE_CLI_ACTION_RUN = 0,
    FARSEE_CLI_ACTION_HELP,
    FARSEE_CLI_ACTION_VERSION,
    FARSEE_CLI_ACTION_CAPABILITIES,
} farsee_cli_action;

// Protocol selection (--protocol rfb|vnc|rdp|auto). DEFAULT means unset
// (auto-resolve from port / scheme in the dispatch path).
typedef enum {
    FARSEE_CLI_PROTOCOL_DEFAULT = 0,
    FARSEE_CLI_PROTOCOL_RFB,
    FARSEE_CLI_PROTOCOL_RDP,
    FARSEE_CLI_PROTOCOL_AUTO,
} farsee_cli_protocol;

// Auth-mode selection (--auth apple|vnc|auto). DEFAULT means unset → AUTO.
typedef enum {
    FARSEE_CLI_AUTH_DEFAULT = 0,
    FARSEE_CLI_AUTH_VNC,
    FARSEE_CLI_AUTH_APPLE,
    FARSEE_CLI_AUTH_AUTO,
} farsee_cli_auth;

typedef enum {
    FARSEE_CLI_APPLE_POSTAUTH_CLEARTEXT = 0,
    FARSEE_CLI_APPLE_POSTAUTH_RECORDS,
    FARSEE_CLI_APPLE_POSTAUTH_PRIVATE_ENCODINGS,
} farsee_cli_apple_postauth;

// FreeRDP diagnostic library log level. Numeric values match rdp_liblog_level
// when RDP is compiled in. Release builds keep this at OFF and reject the
// developer-only --log-level / --verbose controls.
typedef enum {
    FARSEE_CLI_LOG_OFF = 0,
    FARSEE_CLI_LOG_ERROR,
    FARSEE_CLI_LOG_WARN,
    FARSEE_CLI_LOG_INFO,
    FARSEE_CLI_LOG_DEBUG,
    FARSEE_CLI_LOG_TRACE,
} farsee_cli_log_level;

// Fully-owned parse result. String fields are always NUL-terminated when
// present; has_* flags mark which optional fields were set.
typedef struct farsee_cli_options {
    farsee_cli_action   action;
    farsee_cli_protocol protocol;
    farsee_cli_auth     auth;

    char     host[256];
    bool     has_host;
    uint16_t port;              // 0 = default per protocol

    char user[128];
    bool has_user;
    char domain[128];
    bool has_domain;
    char cert_policy[32];       // "ignore" or "pin"; default is fail-closed
    bool has_cert_policy;
    char presenter[64];
    bool has_presenter;

    int      password_fd;       // -1 = none
    uint32_t desk_w;            // 0 = default
    uint32_t desk_h;            // 0 = default
    uint64_t connect_timeout_ms;
    bool     view_only;
    bool     clipboard_on;      // default true
    bool     accept_new_host;   // default false (fail closed on first use)
    bool     apple_require_type_36; // default false (auto prefers type 33)
    bool     allow_none_auth;
    bool     shared_session;    // default true
    uint8_t  apple_attach;      // 0=ask, 1=share, 2=login
    farsee_cli_apple_postauth apple_postauth;
    bool     apple_send_viewer_info;
    bool     apple_disable_wake_keys;
    uint32_t max_fps;           // default 30; 0 = unlimited
    uint32_t view_scale_pct;    // 0 → RFB default
    farsee_cli_log_level log_level;
    bool     log_level_set;     // true if a WLog control appeared on argv
    farsee_cli_leader    leader;
    bool     leader_set;        // true if --leader appeared on argv
} farsee_cli_options;

// Zero *out and apply production defaults (clipboard on, shared, etc.).
void farsee_cli_options_init(farsee_cli_options *out);

// Parse argv[1..argc-1] into *out. Returns 0 on success, 2 on failure.
// On failure writes a short operator message into errbuf (when non-NULL
// and errbuf_cap > 0). Does not print. Does not call getenv.
//
// Early actions (--help / --version / --protocol-capabilities) succeed
// without a host. FARSEE_CLI_ACTION_RUN may also succeed without a host;
// the dispatch path reports the missing host.
int farsee_cli_parse_args(int argc, char **argv, farsee_cli_options *out,
                          char *errbuf, size_t errbuf_cap);

// Operator-facing help / version / capabilities. These write to FILE; tests
// capture the help and capability output with memory streams.
void farsee_cli_print_help(FILE *out, const char *argv0);
void farsee_cli_print_version(FILE *out);
void farsee_cli_print_capabilities(FILE *out);

// Resolve DEFAULT/AUTO protocol from port (3389/13390 → RDP, else RFB).
// Leaves RFB/RDP unchanged. Mutates *p in place.
void farsee_cli_resolve_protocol(farsee_cli_protocol *p, uint16_t port);

// Validate option combinations that depend on the resolved protocol. Call
// after farsee_cli_resolve_protocol. In particular, WLog controls require an
// RDP target. Returns false and writes an operator message on failure.
bool farsee_cli_validate_resolved_options(const farsee_cli_options *options,
                                          char *errbuf, size_t errbuf_cap);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_CLI_ARGS_H */
