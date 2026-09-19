// SPDX-License-Identifier: Apache-2.0
//
// farsee CLI entry (plan.md §17). Apply process guards, parse, handle early
// output, then dispatch. The option table is in farsee_cli_parse_args.

#include "farsee/binary_id.h"
#include "farsee/cli_args.h"
#include "farsee/cli_target.h"
#include "farsee/credential_acquire.h"
#include "farsee/handshake.h"
#include "app/core_dump_guard.h"
#include "app/rfb_live.h"

#include <signal.h>
#include <stdio.h>

#ifdef FARSEE_WITH_RDP
#include "app/rdp_live.h"
#endif

typedef struct farsee_entry_context {
    int argc;
    char **argv;
} farsee_entry_context;

static bool farsee_disable_core_dumps(void *context)
{
    (void)context;
    return farsee_core_dump_guard_disable();
}

static int farsee_main_after_core_dump_guard(void *context)
{
    farsee_entry_context *entry = (farsee_entry_context *)context;
    const int argc = entry->argc;
    char **argv = entry->argv;
    farsee_cli_options opt;
    char err[256];
    int rc;

    farsee_binary_id_init(argc > 0 ? argv[0] : NULL);

    rc = farsee_cli_parse_args(argc, argv, &opt, err, sizeof err);
    if (rc != 0) {
        if (err[0] != '\0') {
            fprintf(stderr, "%s\n", err);
        }
        return 2;
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

    farsee_cli_resolve_protocol(&opt.protocol, opt.port);
    if (!farsee_cli_validate_resolved_options(&opt, err, sizeof err)) {
        if (err[0] != '\0') {
            fprintf(stderr, "%s\n", err);
        }
        (void)farsee_credential_close_password_fd(opt.password_fd);
        return 2;
    }

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
            opt.desk_w, opt.desk_h,
            opt.has_presenter ? opt.presenter : NULL,
            opt.connect_timeout_ms, opt.view_only, opt.clipboard_on, liblog,
            &opt.leader);
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
            opt.allow_none_auth, opt.shared_session, opt.apple_attach, rfb_auth,
            (rfb_apple_postauth_mode)opt.apple_postauth,
            opt.apple_send_viewer_info, opt.apple_disable_wake_keys,
            opt.has_presenter ? opt.presenter : NULL, opt.max_fps,
            opt.view_only, &opt.leader, opt.view_scale_pct,
            (uint32_t)opt.connect_timeout_ms, opt.accept_new_host,
            opt.apple_require_type_36);
    }
}

int main(int argc, char **argv)
{
    // A peer close during write must not terminate the process with SIGPIPE;
    // TTY restore would never run. Socket path also uses MSG_NOSIGNAL.
    (void)signal(SIGPIPE, SIG_IGN);

    // Process memory can contain authentication and transport secrets. Refuse
    // to parse or acquire credentials unless core dumps are disabled and the
    // resulting platform state has been verified.
    farsee_entry_context context = {
        .argc = argc,
        .argv = argv,
    };
    return farsee_core_dump_guarded_entry(
        farsee_disable_core_dumps, farsee_main_after_core_dump_guard,
        &context, stderr);
}
