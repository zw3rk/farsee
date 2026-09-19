// SPDX-License-Identifier: Apache-2.0
//
// Fail-closed CLI option parsing. See farsee/cli_args.h.

#include "farsee/cli_args.h"
#include "farsee/cli_parse.h"
#include "farsee/cli_target.h"
#include "farsee/encoding.h"
#include "farsee/term_mouse_map.h" /* FARSEE_VIEW_SCALE_DEFAULT_PCT */
#include "farsee/version.h"
#include "farsee/binary_id.h"

#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Defaults / helpers
// ---------------------------------------------------------------------------

void farsee_cli_options_init(farsee_cli_options *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->action = FARSEE_CLI_ACTION_RUN;
    out->protocol = FARSEE_CLI_PROTOCOL_DEFAULT;
    out->auth = FARSEE_CLI_AUTH_DEFAULT;
    out->password_fd = -1;
    out->connect_timeout_ms = 30000ull;
    out->clipboard_on = true;   /* USAGE / RDP path: default on */
    out->shared_session = true;
    out->apple_attach = 0u;     /* ask */
    out->max_fps = 30u;
    out->log_level = FARSEE_CLI_LOG_OFF;
    farsee_cli_leader_default(&out->leader);
    out->leader_set = false;
}

void farsee_cli_resolve_protocol(farsee_cli_protocol *p, uint16_t port)
{
    if (p == NULL) {
        return;
    }
    if (*p == FARSEE_CLI_PROTOCOL_AUTO || *p == FARSEE_CLI_PROTOCOL_DEFAULT) {
        if (port == 3389u || port == 13390u) {
            *p = FARSEE_CLI_PROTOCOL_RDP;
        } else {
            *p = FARSEE_CLI_PROTOCOL_RFB;
        }
    }
}

static void set_err(char *errbuf, size_t errbuf_cap, const char *msg)
{
    if (errbuf == NULL || errbuf_cap == 0) {
        return;
    }
    if (msg == NULL) {
        errbuf[0] = '\0';
        return;
    }
    (void)snprintf(errbuf, errbuf_cap, "%s", msg);
}

bool farsee_cli_validate_resolved_options(const farsee_cli_options *options,
                                          char *errbuf, size_t errbuf_cap)
{
    if (options == NULL) {
        set_err(errbuf, errbuf_cap, "farsee: internal error (null options)");
        return false;
    }
    switch (options->log_level) {
    case FARSEE_CLI_LOG_OFF:
        break;
    case FARSEE_CLI_LOG_ERROR:
    case FARSEE_CLI_LOG_WARN:
    case FARSEE_CLI_LOG_INFO:
    case FARSEE_CLI_LOG_DEBUG:
    case FARSEE_CLI_LOG_TRACE:
        break;
    default:
        set_err(errbuf, errbuf_cap,
                "farsee: invalid FreeRDP/WinPR log level");
        return false;
    }
    if (!options->log_level_set &&
        options->log_level == FARSEE_CLI_LOG_OFF) {
        return true;
    }
    if (options->protocol == FARSEE_CLI_PROTOCOL_RDP) {
        return true;
    }
    if (options->protocol == FARSEE_CLI_PROTOCOL_DEFAULT ||
        options->protocol == FARSEE_CLI_PROTOCOL_AUTO) {
        set_err(errbuf, errbuf_cap,
                "farsee: WLog validation requires a resolved protocol");
        return false;
    }
    set_err(errbuf, errbuf_cap,
            "farsee: FreeRDP/WinPR log controls require an RDP target");
    return false;
}

// Fixed formats only (no nonliteral format strings under -Wformat-nonliteral).
static void set_err_opt_value(char *errbuf, size_t errbuf_cap, const char *opt)
{
    if (errbuf == NULL || errbuf_cap == 0) {
        return;
    }
    (void)snprintf(errbuf, errbuf_cap, "farsee: %s requires a value",
                   opt != NULL ? opt : "option");
}

static void set_err_unknown_opt(char *errbuf, size_t errbuf_cap, const char *a)
{
    if (errbuf == NULL || errbuf_cap == 0) {
        return;
    }
    (void)snprintf(errbuf, errbuf_cap, "farsee: unknown option '%s'",
                   a != NULL ? a : "");
}

static void set_err_got(char *errbuf, size_t errbuf_cap, const char *what,
                        const char *expect, const char *got)
{
    if (errbuf == NULL || errbuf_cap == 0) {
        return;
    }
    (void)snprintf(errbuf, errbuf_cap, "farsee: %s expects %s; got '%s'",
                   what != NULL ? what : "option",
                   expect != NULL ? expect : "",
                   got != NULL ? got : "");
}

static void set_err_invalid_target(char *errbuf, size_t errbuf_cap,
                                   const char *a)
{
    if (errbuf == NULL || errbuf_cap == 0) {
        return;
    }
    (void)snprintf(errbuf, errbuf_cap, "farsee: invalid target '%s'",
                   a != NULL ? a : "");
}

static void set_err_invalid_leader(char *errbuf, size_t errbuf_cap,
                                   const char *spec)
{
    if (errbuf == NULL || errbuf_cap == 0) {
        return;
    }
    (void)snprintf(errbuf, errbuf_cap,
                   "farsee: invalid --leader '%s' "
                   "(want C-x, ctrl-x, or bare x; Control only)",
                   spec != NULL ? spec : "");
}

#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
static void set_err_log_level(char *errbuf, size_t errbuf_cap, const char *lv)
{
    if (errbuf == NULL || errbuf_cap == 0) {
        return;
    }
    (void)snprintf(errbuf, errbuf_cap,
                   "farsee: unknown --log-level '%s' "
                   "(off|error|warn|info|debug|trace)",
                   lv != NULL ? lv : "");
}
#else
static void set_err_wlog_disabled(char *errbuf, size_t errbuf_cap)
{
#ifdef FARSEE_RELEASE_BUILD
    set_err(errbuf, errbuf_cap,
            "farsee: FreeRDP/WinPR log controls are available only in "
            "developer builds");
#else
    set_err(errbuf, errbuf_cap,
            "farsee: FreeRDP/WinPR log controls are unavailable without "
            "RDP support");
#endif
}

static bool is_wlog_control(const char *arg)
{
    return arg != NULL &&
           (strcmp(arg, "--verbose") == 0 || strcmp(arg, "-v") == 0 ||
            strcmp(arg, "--log-level") == 0 ||
            strncmp(arg, "--log-level=", 12) == 0);
}
#endif

// Copy src into dst[cap] (including NUL). Returns false if src is NULL or
// does not fit.
static bool copy_field(char *dst, size_t cap, const char *src)
{
    size_t n;
    if (dst == NULL || cap == 0u || src == NULL) {
        return false;
    }
    n = strlen(src);
    if (n + 1u > cap) {
        return false;
    }
    memcpy(dst, src, n + 1u);
    return true;
}

// Consume a value for --opt / --opt=VALUE. Advances *ip past the value.
// Returns the value string, or NULL on missing value (sets err).
static const char *take_value(int argc, char **argv, int *ip,
                              const char *opt_name, const char *inline_val,
                              char *errbuf, size_t errbuf_cap)
{
    if (inline_val != NULL) {
        return inline_val;
    }
    if (*ip + 1 >= argc) {
        set_err_opt_value(errbuf, errbuf_cap, opt_name);
        return NULL;
    }
    (*ip)++;
    return argv[*ip];
}

static bool parse_auth(const char *s, farsee_cli_auth *out)
{
    if (s == NULL || out == NULL) {
        return false;
    }
    if (strcmp(s, "apple") == 0) {
        *out = FARSEE_CLI_AUTH_APPLE;
        return true;
    }
    if (strcmp(s, "vnc") == 0) {
        *out = FARSEE_CLI_AUTH_VNC;
        return true;
    }
    if (strcmp(s, "auto") == 0) {
        *out = FARSEE_CLI_AUTH_AUTO;
        return true;
    }
    return false;
}

static bool parse_protocol(const char *s, farsee_cli_protocol *out)
{
    if (s == NULL || out == NULL) {
        return false;
    }
    if (strcmp(s, "rfb") == 0 || strcmp(s, "vnc") == 0) {
        *out = FARSEE_CLI_PROTOCOL_RFB;
        return true;
    }
    if (strcmp(s, "rdp") == 0) {
        *out = FARSEE_CLI_PROTOCOL_RDP;
        return true;
    }
    if (strcmp(s, "auto") == 0) {
        *out = FARSEE_CLI_PROTOCOL_AUTO;
        return true;
    }
    return false;
}

static bool parse_clipboard(const char *s, bool *on)
{
    if (s == NULL || on == NULL) {
        return false;
    }
    if (strcmp(s, "on") == 0 || strcmp(s, "1") == 0 ||
        strcmp(s, "true") == 0) {
        *on = true;
        return true;
    }
    if (strcmp(s, "off") == 0 || strcmp(s, "0") == 0 ||
        strcmp(s, "false") == 0) {
        *on = false;
        return true;
    }
    return false;
}

static bool parse_apple_attach(const char *s, uint8_t *out)
{
    if (s == NULL || out == NULL) {
        return false;
    }
    if (strcmp(s, "share") == 0 || strcmp(s, "display") == 0) {
        *out = 1u;
        return true;
    }
    if (strcmp(s, "login") == 0 || strcmp(s, "user") == 0) {
        *out = 2u;
        return true;
    }
    if (strcmp(s, "ask") == 0 || strcmp(s, "prompt") == 0) {
        *out = 0u;
        return true;
    }
    return false;
}

static bool parse_apple_postauth(const char *s,
                                 farsee_cli_apple_postauth *out)
{
    if (s == NULL || out == NULL) {
        return false;
    }
    if (strcmp(s, "cleartext") == 0 || strcmp(s, "compat") == 0) {
        *out = FARSEE_CLI_APPLE_POSTAUTH_CLEARTEXT;
        return true;
    }
    if (strcmp(s, "records") == 0 || strcmp(s, "protected") == 0) {
        *out = FARSEE_CLI_APPLE_POSTAUTH_RECORDS;
        return true;
    }
    if (strcmp(s, "private") == 0) {
        *out = FARSEE_CLI_APPLE_POSTAUTH_PRIVATE_ENCODINGS;
        return true;
    }
    return false;
}

#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
static bool parse_log_level(const char *s, farsee_cli_log_level *out)
{
    if (s == NULL || out == NULL) {
        return false;
    }
    if (strcmp(s, "off") == 0 || strcmp(s, "none") == 0) {
        *out = FARSEE_CLI_LOG_OFF;
        return true;
    }
    if (strcmp(s, "error") == 0) {
        *out = FARSEE_CLI_LOG_ERROR;
        return true;
    }
    if (strcmp(s, "warn") == 0 || strcmp(s, "warning") == 0) {
        *out = FARSEE_CLI_LOG_WARN;
        return true;
    }
    if (strcmp(s, "info") == 0) {
        *out = FARSEE_CLI_LOG_INFO;
        return true;
    }
    if (strcmp(s, "debug") == 0) {
        *out = FARSEE_CLI_LOG_DEBUG;
        return true;
    }
    if (strcmp(s, "trace") == 0) {
        *out = FARSEE_CLI_LOG_TRACE;
        return true;
    }
    return false;
}
#endif

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

int farsee_cli_parse_args(int argc, char **argv, farsee_cli_options *out,
                          char *errbuf, size_t errbuf_cap)
{
    if (out == NULL) {
        set_err(errbuf, errbuf_cap, "farsee: internal error (null options)");
        return 2;
    }
    farsee_cli_options_init(out);
    if (argc < 1 || argv == NULL) {
        set_err(errbuf, errbuf_cap, "farsee: missing argv");
        return 2;
    }

#ifndef FARSEE_ENABLE_WLOG_DIAGNOSTICS
    // Output actions return immediately below. Scan first so a disabled WLog
    // control cannot hide after --help, --version, or capability output.
    for (int i = 1; i < argc; i++) {
        if (argv[i] == NULL) {
            set_err(errbuf, errbuf_cap, "farsee: null argument");
            return 2;
        }
        if (is_wlog_control(argv[i])) {
            set_err_wlog_disabled(errbuf, errbuf_cap);
            return 2;
        }
    }
#endif

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *val;
        char opt_eq_buf[64];

        if (a == NULL) {
            set_err(errbuf, errbuf_cap, "farsee: null argument");
            return 2;
        }

        if (strcmp(a, "--version") == 0) {
            out->action = FARSEE_CLI_ACTION_VERSION;
            return 0;
        }
        if (strcmp(a, "--protocol-capabilities") == 0) {
            out->action = FARSEE_CLI_ACTION_CAPABILITIES;
            return 0;
        }
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            out->action = FARSEE_CLI_ACTION_HELP;
            return 0;
        }

        // --auth VALUE / --auth=VALUE
        if (strcmp(a, "--auth") == 0 || strncmp(a, "--auth=", 7) == 0) {
            val = take_value(argc, argv, &i, "--auth",
                             (a[6] == '=') ? a + 7 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!parse_auth(val, &out->auth)) {
                set_err_got(errbuf, errbuf_cap, "--auth", "apple|vnc|auto",
                            val);
                return 2;
            }
            continue;
        }

        // --protocol VALUE / --protocol=VALUE
        if (strcmp(a, "--protocol") == 0 || strncmp(a, "--protocol=", 11) == 0) {
            val = take_value(argc, argv, &i, "--protocol",
                             (a[10] == '=') ? a + 11 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!parse_protocol(val, &out->protocol)) {
                set_err_got(errbuf, errbuf_cap, "--protocol", "rfb|vnc|rdp|auto",
                            val);
                return 2;
            }
            continue;
        }

        // --port N / --port=N
        if (strcmp(a, "--port") == 0 || strncmp(a, "--port=", 7) == 0) {
            int32_t p = 0;
            val = take_value(argc, argv, &i, "--port",
                             (a[6] == '=') ? a + 7 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!farsee_parse_i32(val, &p) || p <= 0 || p >= 65536) {
                set_err(errbuf, errbuf_cap, "farsee: --port expects 1..65535");
                return 2;
            }
            out->port = (uint16_t)p;
            continue;
        }

        // --user NAME
        if (strcmp(a, "--user") == 0 || strncmp(a, "--user=", 7) == 0) {
            val = take_value(argc, argv, &i, "--user",
                             (a[6] == '=') ? a + 7 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!copy_field(out->user, sizeof out->user, val)) {
                set_err(errbuf, errbuf_cap, "farsee: --user value too long");
                return 2;
            }
            out->has_user = true;
            continue;
        }

        // --domain DOM
        if (strcmp(a, "--domain") == 0 || strncmp(a, "--domain=", 9) == 0) {
            val = take_value(argc, argv, &i, "--domain",
                             (a[8] == '=') ? a + 9 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!copy_field(out->domain, sizeof out->domain, val)) {
                set_err(errbuf, errbuf_cap, "farsee: --domain value too long");
                return 2;
            }
            out->has_domain = true;
            continue;
        }

        // --cert POLICY
        if (strcmp(a, "--cert") == 0 || strncmp(a, "--cert=", 7) == 0) {
            val = take_value(argc, argv, &i, "--cert",
                             (a[6] == '=') ? a + 7 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            // ignore = session-only (no TOFU write); pin = store first use.
            // Default is fail-closed. "prompt" deferred (no interactive UI).
            if (strcmp(val, "ignore") != 0 && strcmp(val, "pin") != 0) {
                set_err_got(errbuf, errbuf_cap, "--cert", "ignore|pin", val);
                return 2;
            }
            if (!copy_field(out->cert_policy, sizeof out->cert_policy, val)) {
                set_err(errbuf, errbuf_cap, "farsee: --cert value too long");
                return 2;
            }
            out->has_cert_policy = true;
            continue;
        }

        // --password-fd N
        if (strcmp(a, "--password-fd") == 0 ||
            strncmp(a, "--password-fd=", 14) == 0) {
            int32_t fd = 0;
            val = take_value(argc, argv, &i, "--password-fd",
                             (a[13] == '=') ? a + 14 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!farsee_parse_i32(val, &fd) || fd < 0) {
                set_err(errbuf, errbuf_cap,
                        "farsee: --password-fd expects a non-negative integer");
                return 2;
            }
            out->password_fd = (int)fd;
            continue;
        }

        // --presenter NAME
        if (strcmp(a, "--presenter") == 0 ||
            strncmp(a, "--presenter=", 12) == 0) {
            val = take_value(argc, argv, &i, "--presenter",
                             (a[11] == '=') ? a + 12 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (strcmp(val, "auto") != 0 && strcmp(val, "kitty") != 0 &&
                strcmp(val, "kitty-shm") != 0 &&
                strcmp(val, "kitty-direct") != 0 &&
                strcmp(val, "null") != 0) {
                set_err_got(errbuf, errbuf_cap, "--presenter",
                            "auto|kitty|kitty-direct|kitty-shm|null", val);
                return 2;
            }
            if (!copy_field(out->presenter, sizeof out->presenter, val)) {
                set_err(errbuf, errbuf_cap,
                        "farsee: --presenter value too long");
                return 2;
            }
            out->has_presenter = true;
            continue;
        }

        // --desktop-w N
        if (strcmp(a, "--desktop-w") == 0 ||
            strncmp(a, "--desktop-w=", 12) == 0) {
            uint32_t w = 0;
            val = take_value(argc, argv, &i, "--desktop-w",
                             (a[11] == '=') ? a + 12 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!farsee_parse_u32(val, &w)) {
                set_err(errbuf, errbuf_cap,
                        "farsee: --desktop-w expects a non-negative integer");
                return 2;
            }
            out->desk_w = w;
            continue;
        }

        // --desktop-h N
        if (strcmp(a, "--desktop-h") == 0 ||
            strncmp(a, "--desktop-h=", 12) == 0) {
            uint32_t h = 0;
            val = take_value(argc, argv, &i, "--desktop-h",
                             (a[11] == '=') ? a + 12 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!farsee_parse_u32(val, &h)) {
                set_err(errbuf, errbuf_cap,
                        "farsee: --desktop-h expects a non-negative integer");
                return 2;
            }
            out->desk_h = h;
            continue;
        }

        // --connect-timeout MS
        if (strcmp(a, "--connect-timeout") == 0 ||
            strncmp(a, "--connect-timeout=", 18) == 0) {
            uint64_t ms = 0;
            val = take_value(argc, argv, &i, "--connect-timeout",
                             (a[17] == '=') ? a + 18 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!farsee_parse_u64(val, &ms) || ms > 0xFFFFFFFFull) {
                // Stored as uint32 downstream, so reject values that cannot
                // be represented without truncation.
                set_err(errbuf, errbuf_cap,
                        "farsee: --connect-timeout expects a non-negative "
                        "integer (ms, <= 4294967295)");
                return 2;
            }
            out->connect_timeout_ms = ms;
            continue;
        }

        // --view-only
        if (strcmp(a, "--view-only") == 0) {
            out->view_only = true;
            continue;
        }

        // --accept-new-host: first-use TOFU policy for Apple type-33 host
        // keys (default: fail closed and print the fingerprint). Parsing
        // only; the session wiring consumes the field.
        if (strcmp(a, "--accept-new-host") == 0 ||
            strcmp(a, "--accept-new-host=1") == 0) {
            out->accept_new_host = true;
            continue;
        }
        if (strcmp(a, "--accept-new-host=0") == 0) {
            out->accept_new_host = false;
            continue;
        }

        // --view-scale N
        if (strcmp(a, "--view-scale") == 0 ||
            strncmp(a, "--view-scale=", 13) == 0) {
            int32_t s = 0;
            val = take_value(argc, argv, &i, "--view-scale",
                             (a[12] == '=') ? a + 13 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            // Enforce the documented 20..100 range at the CLI boundary.
            if (!farsee_parse_i32(val, &s) ||
                s < (int32_t)FARSEE_VIEW_SCALE_MIN_PCT ||
                s > (int32_t)FARSEE_VIEW_SCALE_MAX_PCT) {
                char msg[96];
                (void)snprintf(msg, sizeof msg,
                               "farsee: --view-scale expects %u..%u "
                               "(percent of max fit)",
                               (unsigned)FARSEE_VIEW_SCALE_MIN_PCT,
                               (unsigned)FARSEE_VIEW_SCALE_MAX_PCT);
                set_err(errbuf, errbuf_cap, msg);
                return 2;
            }
            out->view_scale_pct = (uint32_t)s;
            continue;
        }

        // --allow-none-auth
        if (strcmp(a, "--allow-none-auth") == 0) {
            out->allow_none_auth = true;
            continue;
        }

        // --shared / --exclusive
        if (strcmp(a, "--shared") == 0) {
            out->shared_session = true;
            continue;
        }
        if (strcmp(a, "--exclusive") == 0) {
            out->shared_session = false;
            continue;
        }

        // --apple-attach MODE
        if (strcmp(a, "--apple-attach") == 0 ||
            strncmp(a, "--apple-attach=", 15) == 0) {
            val = take_value(argc, argv, &i, "--apple-attach",
                             (a[14] == '=') ? a + 15 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!parse_apple_attach(val, &out->apple_attach)) {
                set_err_got(errbuf, errbuf_cap, "--apple-attach",
                            "share|login|ask", val);
                return 2;
            }
            continue;
        }

        // --apple-security MODE
        if (strcmp(a, "--apple-security") == 0 ||
            strncmp(a, "--apple-security=", 17) == 0) {
            val = take_value(argc, argv, &i, "--apple-security",
                             (a[16] == '=') ? a + 17 : NULL,
                             errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (strcmp(val, "auto") == 0) {
                out->apple_require_type_36 = false;
            } else if (strcmp(val, "36") == 0) {
                out->apple_require_type_36 = true;
            } else {
                set_err_got(errbuf, errbuf_cap, "--apple-security",
                            "auto|36", val);
                return 2;
            }
            continue;
        }

        // --apple-postauth MODE
        if (strcmp(a, "--apple-postauth") == 0 ||
            strncmp(a, "--apple-postauth=", 17) == 0) {
            val = take_value(argc, argv, &i, "--apple-postauth",
                             (a[16] == '=') ? a + 17 : NULL,
                             errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!parse_apple_postauth(val, &out->apple_postauth)) {
                set_err_got(errbuf, errbuf_cap, "--apple-postauth",
                            "cleartext|records|private", val);
                return 2;
            }
            continue;
        }

        // --apple-viewer-info
        if (strcmp(a, "--apple-viewer-info") == 0) {
            out->apple_send_viewer_info = true;
            continue;
        }

        // --apple-wake-keys on|off
        if (strcmp(a, "--apple-wake-keys") == 0 ||
            strncmp(a, "--apple-wake-keys=", 18) == 0) {
            bool enabled = false;
            val = take_value(argc, argv, &i, "--apple-wake-keys",
                             (a[17] == '=') ? a + 18 : NULL,
                             errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!parse_clipboard(val, &enabled)) {
                set_err_got(errbuf, errbuf_cap, "--apple-wake-keys",
                            "on|off", val);
                return 2;
            }
            out->apple_disable_wake_keys = !enabled;
            continue;
        }

        // --max-fps N
        if (strcmp(a, "--max-fps") == 0 || strncmp(a, "--max-fps=", 10) == 0) {
            uint32_t f = 0;
            val = take_value(argc, argv, &i, "--max-fps",
                             (a[9] == '=') ? a + 10 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!farsee_parse_u32(val, &f) || f > 240u) {
                set_err(errbuf, errbuf_cap,
                        "farsee: --max-fps expects 0..240 (0 = unlimited)");
                return 2;
            }
            out->max_fps = f;
            continue;
        }

        // --verbose / -v
        if (strcmp(a, "--verbose") == 0 || strcmp(a, "-v") == 0) {
#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
            if (out->log_level < FARSEE_CLI_LOG_INFO) {
                out->log_level = FARSEE_CLI_LOG_INFO;
            }
            out->log_level_set = true;
            continue;
#else
            set_err_wlog_disabled(errbuf, errbuf_cap);
            return 2;
#endif
        }

        // --log-level LEVEL
        if (strcmp(a, "--log-level") == 0 ||
            strncmp(a, "--log-level=", 12) == 0) {
#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
            val = take_value(argc, argv, &i, "--log-level",
                             (a[11] == '=') ? a + 12 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!parse_log_level(val, &out->log_level)) {
                set_err_log_level(errbuf, errbuf_cap, val);
                return 2;
            }
            out->log_level_set = true;
            continue;
#else
            set_err_wlog_disabled(errbuf, errbuf_cap);
            return 2;
#endif
        }

        // --clipboard on|off
        if (strcmp(a, "--clipboard") == 0 ||
            strncmp(a, "--clipboard=", 12) == 0) {
            val = take_value(argc, argv, &i, "--clipboard",
                             (a[11] == '=') ? a + 12 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!parse_clipboard(val, &out->clipboard_on)) {
                set_err_got(errbuf, errbuf_cap, "--clipboard", "on|off", val);
                return 2;
            }
            continue;
        }

        // --leader SPEC
        if (strcmp(a, "--leader") == 0 || strncmp(a, "--leader=", 9) == 0) {
            farsee_cli_leader tmp;
            val = take_value(argc, argv, &i, "--leader",
                             (a[8] == '=') ? a + 9 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!farsee_cli_leader_parse(val, &tmp)) {
                set_err_invalid_leader(errbuf, errbuf_cap, val);
                return 2;
            }
            out->leader = tmp;
            out->leader_set = true;
            continue;
        }

        // Positional target (must not start with '-').
        if (a[0] != '-') {
            farsee_cli_target tgt;
            const char *pw_err;
            if (!farsee_cli_target_parse(a, &tgt)) {
                set_err_invalid_target(errbuf, errbuf_cap, a);
                return 2;
            }
            pw_err = farsee_cli_url_password_policy_error(&tgt);
            if (pw_err != NULL) {
                set_err(errbuf, errbuf_cap, pw_err);
                return 2;
            }
            if (tgt.proto == FARSEE_CLI_PROTO_RDP) {
                out->protocol = FARSEE_CLI_PROTOCOL_RDP;
            } else if (tgt.proto == FARSEE_CLI_PROTO_RFB) {
                out->protocol = FARSEE_CLI_PROTOCOL_RFB;
            }
            if (!copy_field(out->host, sizeof out->host, tgt.host)) {
                set_err(errbuf, errbuf_cap, "farsee: host too long");
                return 2;
            }
            out->has_host = true;
            if (tgt.port != 0u && out->port == 0u) {
                out->port = tgt.port;
            }
            if (tgt.has_user && !out->has_user) {
                if (!copy_field(out->user, sizeof out->user, tgt.user)) {
                    set_err(errbuf, errbuf_cap, "farsee: user too long");
                    return 2;
                }
                out->has_user = true;
            }
            continue;
        }

        // Unknown option — fail closed (do not silently ignore).
        // Truncate very long argv for the error message.
        if (strlen(a) >= sizeof opt_eq_buf) {
            (void)snprintf(opt_eq_buf, sizeof opt_eq_buf, "%.48s...", a);
            set_err_unknown_opt(errbuf, errbuf_cap, opt_eq_buf);
        } else {
            set_err_unknown_opt(errbuf, errbuf_cap, a);
        }
        return 2;
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Operator-facing text (help and capability output is captured by unit tests)
// ---------------------------------------------------------------------------

void farsee_cli_print_version(FILE *out)
{
    if (out == NULL) {
        return;
    }
    fprintf(out, "%s %s git=%s built=%s\n", farsee_project_name(),
            farsee_version_string(), farsee_binary_id_git(),
            farsee_binary_id_build_time());
    fprintf(out, "C11 RFB/VNC terminal client\n");
    fprintf(out, "License: Apache-2.0\n");
}

void farsee_cli_print_capabilities(FILE *out)
{
    if (out == NULL) {
        return;
    }
    fprintf(out, "farsee protocol capabilities:\n");
    fprintf(out, "  Versions: RFB 3.3, 3.7, 3.8\n");
    fprintf(out, "  Security: VNC Authentication (type 2), None (type 1, opt-in)\n");
    fprintf(out, "  Apple dialect: 003.889, security types 33 and 36 live; "
                 "type 36 can be required\n");
    fprintf(out, "  Encodings:\n");
    fprintf(out, "    Raw (%d)\n", RFB_ENCODING_RAW);
    fprintf(out, "    CopyRect (%d)\n", RFB_ENCODING_COPYRECT);
    fprintf(out, "    ZRLE (%d)\n", RFB_ENCODING_ZRLE);
    fprintf(out, "    Apple MultiVariant (0x03f3; type-0 paint)\n");
    fprintf(out, "    Apple private 0x0450 (composited alpha cursor)\n");
    fprintf(out, "    Cursor (%d)\n", RFB_ENCODING_CURSOR);
    fprintf(out, "    DesktopSize (%d)\n", RFB_ENCODING_DESKTOPSIZE);
    fprintf(out, "  Canonical framebuffer: RGBA8 (32bpp, depth 24)\n");
    fprintf(out, "  Presenters: null, kitty-direct, kitty-shm\n");
    fprintf(out, "  Crypto providers:\n");
    fprintf(out, "    OpenSSL 3.x: Apple auth on macOS and Linux; "
                 "classic VNC auth on Linux\n");
    fprintf(out, "    CommonCrypto: classic VNC auth on macOS\n");
    fprintf(out, "  Apple protected-record mode: AES-128-CBC records after "
                 "0x044f rekey (modern Screen Sharing path)\n");
    fprintf(out, "  Apple High Performance/Adaptive (HEVC): NOT ENABLED\n");
    fprintf(out, "  RDP connect timeout: --connect-timeout MS "
                 "(FreeRDP TcpConnectTimeout)\n");
    fprintf(out, "  RFB connect: --connect-timeout MS sets handshake/recv "
                 "monotonic deadline (default 30000)\n");
}

void farsee_cli_print_help(FILE *out, const char *argv0)
{
    const char *prog = (argv0 != NULL && argv0[0] != '\0') ? argv0 : "farsee";
    if (out == NULL) {
        return;
    }
    fprintf(out, "usage: %s [options] <target>\n\n", prog);
    fprintf(out, "Target (positional):\n");
    fprintf(out, "  host[:port]\n");
    fprintf(out, "  <proto>://host[:port]\n");
    fprintf(out, "  <proto>://user@host[:port]\n");
    fprintf(out, "  proto is rdp, vnc, or rfb. user@host is allowed; passwords in\n");
    fprintf(out, "  URL userinfo (user:password@host) are REJECTED (visible to ps).\n");
    fprintf(out, "  Use --password-fd N or the interactive TTY prompt for secrets.\n\n");
    fprintf(out, "Options:\n");
    fprintf(out, "  --protocol rfb|rdp|auto  protocol (default: auto; rdp if port 3389\n");
    fprintf(out, "                        or rdp:// scheme)\n");
    fprintf(out, "  --port N              TCP port (default 5900 rfb, 3389 rdp)\n");
    fprintf(out, "  --auth apple|vnc|auto authentication mode (default: auto)\n");
    fprintf(out, "  --user NAME           username (RDP / Apple login name;\n");
    fprintf(out, "                        overrides URL user)\n");
    fprintf(out, "  --domain DOM          RDP domain\n");
    fprintf(out, "  --cert ignore|pin     RDP peer cert: ignore=session-only\n");
    fprintf(out, "                        (never write TOFU); pin=store fingerprint\n");
    fprintf(out, "                        on first use under ~/.farsee/rdp_known_hosts.\n");
    fprintf(out, "                        Default: fail-closed (TOFU match still ok)\n");
    fprintf(out, "  --desktop-w N         RDP desktop width (default 1280)\n");
    fprintf(out, "  --desktop-h N         RDP desktop height (default 800)\n");
    fprintf(out, "  --shared | --exclusive  shared or exclusive session\n");
    fprintf(out, "  --apple-attach share|login|ask\n");
    fprintf(out, "                        Apple SRP attach (default: ask after ServerInit;\n");
    fprintf(out, "                        shows who owns the display when known).\n");
    fprintf(out, "                        Enter/L=login, s=share. Non-interactive\n");
    fprintf(out, "                        ask → login. share=console; login=virtual\n");
    fprintf(out, "                        session as --user\n");
    fprintf(out, "  --apple-postauth cleartext|records|private\n");
    fprintf(out, "                        Apple post-auth path (default: cleartext);\n");
    fprintf(out, "                        records enables protected 0x044f records;\n");
    fprintf(out, "                        private also requests Apple 0x03f3/0x0450\n");
    fprintf(out, "  --apple-security auto|36\n");
    fprintf(out, "                        auto prefers type 33; 36 requires type 36\n");
    fprintf(out, "  --apple-viewer-info  send the optional Apple ViewerInfo prelude\n");
    fprintf(out, "  --apple-wake-keys on|off\n");
    fprintf(out, "                        allow automatic wake click/keys (default: on)\n");
    fprintf(out,
            "  --presenter auto|kitty|kitty-direct|kitty-shm|null\n");
    fprintf(out, "                        RDP local: auto/kitty = kitty-shm (POSIX shm;\n");
    fprintf(out, "                        pixels do not cross the TTY). Use kitty-direct\n");
    fprintf(out, "                        only if you need base64-over-TTY (slow).\n");
    fprintf(out, "                        RDP live: status bar under the image;\n");
    fprintf(out, "                        leader C-] then q=quit, z=suspend\n");
    fprintf(out, "                        (C-] C-] sends prefix to remote)\n");
    fprintf(out, "  --leader SPEC         live prefix: C-x | ctrl-x | x  (default C-])\n");
    fprintf(out, "                        tmux-style (modifier included)\n");
    fprintf(out, "  --allow-none-auth     permit security type None (default: refused)\n");
    fprintf(out, "  --password-fd N       read password from file descriptor N\n");
    fprintf(out, "                        (preferred non-interactive secret path)\n");
    fprintf(out, "  --max-fps N           maximum presentation frame rate (default 30)\n");
    fprintf(out, "  --view-only           prevent all input and clipboard\n");
    fprintf(out, "  --view-scale N        RFB live: Kitty place size as %% of max fit\n");
    fprintf(out, "                        (20..100, default %u). Live: C-] + / -\n",
            (unsigned)FARSEE_VIEW_SCALE_DEFAULT_PCT);
    fprintf(out, "  --clipboard on|off    clipboard forwarding (default: on; "
                 "RDP only today)\n");
#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
    fprintf(out, "  --verbose, -v         FreeRDP logs (INFO; developer RDP target)\n");
    fprintf(out, "  --log-level off|error|warn|info|debug|trace\n");
    fprintf(out, "                        FreeRDP/WinPR WLog for RDP (default: off)\n");
#else
#ifdef FARSEE_RELEASE_BUILD
    fprintf(out, "  FreeRDP/WinPR WLog diagnostics are disabled in release builds.\n");
#else
    fprintf(out, "  FreeRDP/WinPR WLog diagnostics are unavailable without RDP support.\n");
#endif
#endif
    fprintf(out, "  --connect-timeout MS  connection timeout (default 30000)\n");
    fprintf(out, "  --version             print version and exit\n");
    fprintf(out, "  --protocol-capabilities  print protocol support and exit\n");
    fprintf(out, "  --help                print this help and exit\n");
    fprintf(out, "\nSecurity: traditional VNC Authentication does not encrypt the\n");
    fprintf(out, "session. Use over a trusted LAN or a user-managed SSH tunnel.\n");
    fprintf(out, "\nApple auth supports security types 33 and 36. Auto prefers 33.\n");
    fprintf(out, "Protected post-auth enables AES-128-CBC records after\n");
    fprintf(out, "the server 0x044f setup and rekey.\n");
    fprintf(out, "High Performance/Adaptive (HEVC) media is NOT enabled.\n");
    fprintf(out, "\nUnknown options and missing/invalid values exit with status 2.\n");
    fprintf(out, "See plan.md, docs/protocol-support.md, SECURITY.md, USAGE.md.\n");
}
