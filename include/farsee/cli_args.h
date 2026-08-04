// SPDX-License-Identifier: Apache-2.0
//
// farsee — fail-closed CLI option parse (Q4).
//
// Pure: no I/O, no getenv, no sockets. Parses argv into a bounded options
// struct. Unknown options, missing values, and invalid enums fail with
// exit-style return code 2 and a message in errbuf.
//
// main stays thin: parse → print error / help / version → dispatch live.

#ifndef FARSEE_INCLUDE_FARSEE_CLI_ARGS_H
#define FARSEE_INCLUDE_FARSEE_CLI_ARGS_H

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

// FreeRDP / diagnostic library log level (--log-level / --verbose).
// Numeric values match rdp_liblog_level when RDP is compiled in.
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
    char cert_policy[32];       // e.g. "ignore" (prompt removed until TOFU UI)
    bool has_cert_policy;
    char presenter[64];
    bool has_presenter;
    char dump_frame[512];
    bool has_dump_frame;

    int      password_fd;       // -1 = none
    uint32_t desk_w;            // 0 = default
    uint32_t desk_h;            // 0 = default
    uint64_t connect_timeout_ms;
    bool     view_only;
    bool     clipboard_on;      // default true
    bool     allow_none_auth;
    bool     shared_session;    // default true
    uint8_t  apple_attach;      // 0=ask, 1=share, 2=login
    uint32_t max_fps;           // default 30; 0 = unlimited
    uint32_t view_scale_pct;    // 0 → RFB default
    farsee_cli_log_level log_level;
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

// Operator-facing help / version / capabilities (I/O; not used by tests).
void farsee_cli_print_help(FILE *out, const char *argv0);
void farsee_cli_print_version(FILE *out);
void farsee_cli_print_capabilities(FILE *out);

// Resolve DEFAULT/AUTO protocol from port (3389/13390 → RDP, else RFB).
// Leaves RFB/RDP unchanged. Mutates *p in place.
void farsee_cli_resolve_protocol(farsee_cli_protocol *p, uint16_t port);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_CLI_ARGS_H */
