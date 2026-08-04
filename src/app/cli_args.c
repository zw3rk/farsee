// SPDX-License-Identifier: Apache-2.0
//
// Fail-closed CLI option parse (Q4). See farsee/cli_args.h.

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
            if (!copy_field(out->presenter, sizeof out->presenter, val)) {
                set_err(errbuf, errbuf_cap,
                        "farsee: --presenter value too long");
                return 2;
            }
            out->has_presenter = true;
            continue;
        }

        // --dump-frame FILE
        if (strcmp(a, "--dump-frame") == 0 ||
            strncmp(a, "--dump-frame=", 13) == 0) {
            val = take_value(argc, argv, &i, "--dump-frame",
                             (a[12] == '=') ? a + 13 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!copy_field(out->dump_frame, sizeof out->dump_frame, val)) {
                set_err(errbuf, errbuf_cap,
                        "farsee: --dump-frame path too long");
                return 2;
            }
            out->has_dump_frame = true;
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
            if (!farsee_parse_u64(val, &ms)) {
                set_err(errbuf, errbuf_cap,
                        "farsee: --connect-timeout expects a non-negative "
                        "integer (ms)");
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

        // --view-scale N
        if (strcmp(a, "--view-scale") == 0 ||
            strncmp(a, "--view-scale=", 13) == 0) {
            int32_t s = 0;
            val = take_value(argc, argv, &i, "--view-scale",
                             (a[12] == '=') ? a + 13 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!farsee_parse_i32(val, &s) || s < 1 || s > 100) {
                set_err(errbuf, errbuf_cap,
                        "farsee: --view-scale expects 1..100 (percent of max "
                        "fit)");
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
            if (out->log_level < FARSEE_CLI_LOG_INFO) {
                out->log_level = FARSEE_CLI_LOG_INFO;
            }
            continue;
        }

        // --log-level LEVEL
        if (strcmp(a, "--log-level") == 0 ||
            strncmp(a, "--log-level=", 12) == 0) {
            val = take_value(argc, argv, &i, "--log-level",
                             (a[11] == '=') ? a + 12 : NULL, errbuf, errbuf_cap);
            if (val == NULL) {
                return 2;
            }
            if (!parse_log_level(val, &out->log_level)) {
                set_err_log_level(errbuf, errbuf_cap, val);
                return 2;
            }
            continue;
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
// Operator-facing text (not used by pure unit tests)
// ---------------------------------------------------------------------------

void farsee_cli_print_version(FILE *out)
{
    if (out == NULL) {
        return;
    }
    fprintf(out, "%s %s git=%s built=%s\n", farsee_project_name(),
            farsee_version_string(), farsee_binary_id_git(),
            farsee_binary_id_build_time());
    fprintf(out, "clean-room C11 RFB/VNC terminal client\n");
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
    fprintf(out, "  Apple dialect: 003.889, security type 33 (RSA/SRP local-user)\n");
    fprintf(out, "  Encodings:\n");
    fprintf(out, "    Raw (%d)\n", RFB_ENCODING_RAW);
    fprintf(out, "    CopyRect (%d)\n", RFB_ENCODING_COPYRECT);
    fprintf(out, "    ZRLE (%d)\n", RFB_ENCODING_ZRLE);
    fprintf(out, "    Cursor (%d)\n", RFB_ENCODING_CURSOR);
    fprintf(out, "    DesktopSize (%d)\n", RFB_ENCODING_DESKTOPSIZE);
    fprintf(out, "  Canonical framebuffer: RGBA8 (32bpp, depth 24)\n");
    fprintf(out, "  Presenters: null, dump, kitty-direct, kitty-shm\n");
    fprintf(out, "  Crypto providers: CommonCrypto (macOS), OpenSSL 3.x (Linux)\n");
    fprintf(out, "  Apple Full-Quality session: cleartext MVP "
                 "(NOT encrypted on the wire after auth; AEAD not enabled)\n");
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
    fprintf(out, "  --user NAME           username (RDP login / Apple type-33 macOS\n");
    fprintf(out, "                        account; overrides URL user)\n");
    fprintf(out, "  --domain DOM          RDP domain\n");
    fprintf(out, "  --cert ignore|pin     RDP peer cert: ignore=session-only\n");
    fprintf(out, "                        (never write TOFU); pin=store fingerprint\n");
    fprintf(out, "                        on first use under ~/.farsee/rdp_known_hosts.\n");
    fprintf(out, "                        Default: fail-closed (TOFU match still ok)\n");
    fprintf(out, "  --desktop-w N         RDP desktop width (default 1280)\n");
    fprintf(out, "  --desktop-h N         RDP desktop height (default 800)\n");
    fprintf(out, "  --shared | --exclusive  shared or exclusive session\n");
    fprintf(out, "  --apple-attach share|login|ask\n");
    fprintf(out, "                        type-33 attach (default: ask after ServerInit;\n");
    fprintf(out, "                        shows who owns the display when known).\n");
    fprintf(out, "                        Enter/L=login, s=share. Non-interactive\n");
    fprintf(out, "                        ask → login. share=console; login=virtual\n");
    fprintf(out, "                        session as --user\n");
    fprintf(out, "  --presenter auto|kitty-shm|kitty-direct|dump|null\n");
    fprintf(out, "                        RDP local: auto/kitty = kitty-shm (POSIX shm;\n");
    fprintf(out, "                        pixels do not cross the TTY). Use kitty-direct\n");
    fprintf(out, "                        only if you need base64-over-TTY (slow).\n");
    fprintf(out, "                        RDP live: status bar under the image;\n");
    fprintf(out, "                        leader C-] then q=quit, z=suspend\n");
    fprintf(out, "                        (C-] C-] sends prefix to remote)\n");
    fprintf(out, "  --leader SPEC         live prefix: C-x | ctrl-x | x  (default C-])\n");
    fprintf(out, "                        also FARSEE_LEADER; tmux-style (modifier included)\n");
    fprintf(out, "  --allow-none-auth     permit security type None (default: refused)\n");
    fprintf(out, "  --password-fd N       read password from file descriptor N\n");
    fprintf(out, "                        (preferred non-interactive secret path)\n");
    fprintf(out, "  --max-fps N           maximum presentation frame rate (default 30)\n");
    fprintf(out, "  --view-only           prevent all input and clipboard\n");
    fprintf(out, "  --view-scale N        RFB live: Kitty place size as %% of max fit\n");
    fprintf(out, "                        (20..100, default %u). Live: C-] + / -\n",
            (unsigned)FARSEE_VIEW_SCALE_DEFAULT_PCT);
    fprintf(out, "  --clipboard on|off    clipboard forwarding (default: on)\n");
    fprintf(out, "  --verbose, -v         FreeRDP library logs (INFO)\n");
    fprintf(out, "  --log-level off|error|warn|info|debug|trace\n");
    fprintf(out, "                        FreeRDP/WinPR WLog level (default: off)\n");
    fprintf(out, "  --dump-frame FILE     dump RGBA to FILE on each frame\n");
    fprintf(out, "  --connect-timeout MS  connection timeout (default 30000)\n");
    fprintf(out, "  --version             print version and exit\n");
    fprintf(out, "  --protocol-capabilities  print protocol support and exit\n");
    fprintf(out, "  --help                print this help and exit\n");
    fprintf(out, "\nSecurity: traditional VNC Authentication does not encrypt the\n");
    fprintf(out, "session. Use over a trusted LAN or a user-managed SSH tunnel.\n");
    fprintf(out, "\nApple auth (--auth=apple): selects security type 33 (RSA/SRP\n");
    fprintf(out, "local-user). Full-Quality post-auth is a cleartext MVP today\n");
    fprintf(out, "(NOT encrypted on the wire; AEAD record layer not enabled).\n");
    fprintf(out, "High Performance/Adaptive (HEVC) media is NOT enabled.\n");
    fprintf(out, "\nUnknown options and missing/invalid values exit with status 2.\n");
    fprintf(out, "See plan.md, docs/protocol-support.md, SECURITY.md, USAGE.md.\n");
}
