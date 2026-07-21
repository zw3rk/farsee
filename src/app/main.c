// SPDX-License-Identifier: Apache-2.0
//
// farsee CLI entry (plan.md §17, Q4). Parse → dispatch only.
// Option table lives in farsee_cli_parse_args (cli_args.c).

#include "farsee/binary_id.h"
#include "farsee/cli_args.h"
#include "farsee/cli_target.h"
#include "farsee/handshake.h"
#include "app/rfb_live.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef FARSEE_WITH_RDP
#include "app/rdp_live.h"
#endif

// Apple capability phases — diagnostic only (FARSEE_RFB_DEBUG=1).
static void print_apple_phase(const char *phase)
{
    const char *e = getenv("FARSEE_RFB_DEBUG");
    if (e == NULL || e[0] == '\0') {
        return;
    }
    fprintf(stderr, "farsee: apple session phase: %s\n", phase);
}

int main(int argc, char **argv)
{
    farsee_cli_options opt;
    char err[256];
    int rc;

    // Peer close during write must not SIGPIPE-kill us (full2 T3): atexit
    // TTY restore would never run. Socket path also uses MSG_NOSIGNAL.
    (void)signal(SIGPIPE, SIG_IGN);

    farsee_binary_id_init(argc > 0 ? argv[0] : NULL);

    rc = farsee_cli_parse_args(argc, argv, &opt, err, sizeof err);
    if (rc != 0) {
        if (err[0] != '\0') {
            fprintf(stderr, "%s\n", err);
        }
        return 2;
    }

    // Env default for leader when --leader was not given.
    if (!opt.leader_set) {
        const char *env = getenv("FARSEE_LEADER");
        if (env != NULL && env[0] != '\0') {
            farsee_cli_leader tmp;
            if (farsee_cli_leader_parse(env, &tmp)) {
                opt.leader = tmp;
            } else {
                fprintf(stderr,
                        "farsee: warning: ignoring invalid FARSEE_LEADER='%s' "
                        "(want C-x / ctrl-x / x)\n",
                        env);
            }
        }
    }

    switch (opt.action) {
    case FARSEE_CLI_ACTION_HELP:
        farsee_cli_print_help(stdout, argc > 0 ? argv[0] : "farsee");
        return 0;
    case FARSEE_CLI_ACTION_VERSION:
        farsee_cli_print_version(stdout);
        return 0;
    case FARSEE_CLI_ACTION_CAPABILITIES:
        farsee_cli_print_capabilities(stdout);
        return 0;
    case FARSEE_CLI_ACTION_RUN:
        break;
    }

    if (opt.auth == FARSEE_CLI_AUTH_APPLE) {
        print_apple_phase("apple-auth-selected (type 33 RSA/SRP)");
        print_apple_phase("live-type33-path");
        print_apple_phase("post-auth-aead-kitty-may-be-incomplete");
        print_apple_phase("high-performance-adaptive-not-enabled");
    }

    farsee_cli_resolve_protocol(&opt.protocol, opt.port);

#ifdef FARSEE_WITH_RDP
    if (opt.protocol == FARSEE_CLI_PROTOCOL_RDP) {
        rdp_liblog_level liblog = (rdp_liblog_level)opt.log_level;
        if (!opt.has_host) {
            fprintf(stderr, "farsee rdp: missing host argument\n");
            return 2;
        }
        return farsee_run_rdp(
            opt.host, opt.port,
            opt.has_user ? opt.user : NULL,
            opt.has_domain ? opt.domain : NULL,
            opt.has_cert_policy ? opt.cert_policy : NULL, opt.password_fd,
            NULL /* password never from URL */, opt.desk_w, opt.desk_h,
            opt.has_presenter ? opt.presenter : NULL,
            opt.has_dump_frame ? opt.dump_frame : NULL, opt.connect_timeout_ms,
            opt.view_only, opt.clipboard_on, liblog, &opt.leader);
    }
#else
    if (opt.protocol == FARSEE_CLI_PROTOCOL_RDP) {
        fprintf(stderr,
                "farsee: RDP support not compiled in "
                "(build with FARSEE_WITH_RDP=1)\n");
        return 2;
    }
#endif

    if (!opt.has_host) {
        fprintf(stderr, "farsee: missing host argument\n");
        farsee_cli_print_help(stdout, argc > 0 ? argv[0] : "farsee");
        return 2;
    }

    {
        farsee_rfb_auth_mode rfb_auth = FARSEE_AUTH_MODE_AUTO;
        if (opt.auth == FARSEE_CLI_AUTH_VNC) {
            rfb_auth = FARSEE_AUTH_MODE_VNC;
        } else if (opt.auth == FARSEE_CLI_AUTH_APPLE) {
            rfb_auth = FARSEE_AUTH_MODE_APPLE;
        }

        return farsee_run_rfb(
            opt.host, opt.port, opt.has_user ? opt.user : NULL, opt.password_fd,
            NULL /* password only via --password-fd or TTY */,
            opt.allow_none_auth, opt.shared_session, opt.apple_attach, rfb_auth,
            opt.has_presenter ? opt.presenter : NULL,
            opt.has_dump_frame ? opt.dump_frame : NULL, opt.max_fps,
            opt.view_only, &opt.leader, opt.view_scale_pct,
            (uint32_t)opt.connect_timeout_ms);
    }
}
