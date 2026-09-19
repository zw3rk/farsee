// SPDX-License-Identifier: Apache-2.0
//
// CLI parser and operator-text unit tests.
//
// Parser cases cover valid and invalid option forms without getenv or sockets.
// Output cases capture help and capability text with memory streams.

#include "rfb_test.h"
#include "farsee/cli_args.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

RFB_TEST(cli_args, parse__unknown_option__fails)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--foo";
    char a2[] = "host.example";
    char *argv[] = {a0, a1, a2};
    int rc = farsee_cli_parse_args(3, argv, &opt, err, sizeof err);
    RFB_CHECK_EQ_INT(rc, 2);
    RFB_CHECK(strstr(err, "--foo") != NULL);
}

RFB_TEST(cli_args, wlog_controls__conditional_parse_default_and_help)
{
    farsee_cli_options opt;
    char err[192];
    char a0[] = "farsee";
    char host[] = "host.example";
    char verbose_short[] = "-v";
    char verbose_long[] = "--verbose";
    char *verbose_forms[] = {verbose_short, verbose_long};
#ifndef FARSEE_ENABLE_WLOG_DIAGNOSTICS
#ifdef FARSEE_RELEASE_BUILD
    const char *const disabled_reason = "developer build";
#else
    const char *const disabled_reason = "without RDP support";
#endif
#endif

    farsee_cli_options_init(&opt);
    RFB_CHECK_EQ_INT(opt.log_level, FARSEE_CLI_LOG_OFF);

    for (size_t i = 0u;
         i < sizeof verbose_forms / sizeof verbose_forms[0]; i++) {
        char *argv[] = {a0, verbose_forms[i], host};
        err[0] = '\0';
        const int rc = farsee_cli_parse_args(3, argv, &opt, err, sizeof err);
#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
        RFB_CHECK_EQ_INT(rc, 0);
        RFB_CHECK_EQ_INT(opt.log_level, FARSEE_CLI_LOG_INFO);
        RFB_CHECK(opt.log_level_set);
#else
        RFB_CHECK_EQ_INT(rc, 2);
        RFB_CHECK(strstr(err, disabled_reason) != NULL);
#endif
    }

    struct log_level_case {
        const char *name;
        farsee_cli_log_level level;
    } levels[] = {
        {"off", FARSEE_CLI_LOG_OFF},
        {"error", FARSEE_CLI_LOG_ERROR},
        {"warn", FARSEE_CLI_LOG_WARN},
        {"info", FARSEE_CLI_LOG_INFO},
        {"debug", FARSEE_CLI_LOG_DEBUG},
        {"trace", FARSEE_CLI_LOG_TRACE},
    };
    for (size_t i = 0u; i < sizeof levels / sizeof levels[0]; i++) {
        char option[48];
        const int written = snprintf(option, sizeof option, "--log-level=%s",
                                     levels[i].name);
        RFB_CHECK(written > 0 && (size_t)written < sizeof option);
        char *equals_argv[] = {a0, option, host};
        err[0] = '\0';
        int rc = farsee_cli_parse_args(3, equals_argv, &opt, err, sizeof err);
#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
        RFB_CHECK_EQ_INT(rc, 0);
        RFB_CHECK_EQ_INT(opt.log_level, levels[i].level);
        RFB_CHECK(opt.log_level_set);
#else
        RFB_CHECK_EQ_INT(rc, 2);
        RFB_CHECK(strstr(err, disabled_reason) != NULL);
#endif

        char log_level[] = "--log-level";
        char level_value[16];
        const int copied = snprintf(level_value, sizeof level_value, "%s",
                                    levels[i].name);
        RFB_CHECK(copied > 0 && (size_t)copied < sizeof level_value);
        char *split_argv[] = {a0, log_level, level_value, host};
        err[0] = '\0';
        rc = farsee_cli_parse_args(4, split_argv, &opt, err, sizeof err);
#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
        RFB_CHECK_EQ_INT(rc, 0);
        RFB_CHECK_EQ_INT(opt.log_level, levels[i].level);
        RFB_CHECK(opt.log_level_set);
#else
        RFB_CHECK_EQ_INT(rc, 2);
        RFB_CHECK(strstr(err, disabled_reason) != NULL);
#endif
    }

    char log_level_missing[] = "--log-level";
    char *missing_argv[] = {a0, log_level_missing};
    err[0] = '\0';
    RFB_CHECK_EQ_INT(
        farsee_cli_parse_args(2, missing_argv, &opt, err, sizeof err), 2);
#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
    RFB_CHECK(strstr(err, "requires a value") != NULL);
#else
    RFB_CHECK(strstr(err, disabled_reason) != NULL);
#endif

    char *help = NULL;
    size_t help_size = 0u;
    FILE *mem = open_memstream(&help, &help_size);
    RFB_CHECK(mem != NULL);
    farsee_cli_print_help(mem, "farsee");
    RFB_CHECK(fflush(mem) == 0);
    RFB_CHECK(help != NULL);
#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
    RFB_CHECK(strstr(help, "--verbose") != NULL);
    RFB_CHECK(strstr(help, "--log-level") != NULL);
    RFB_CHECK(strstr(help, "disabled in release builds") == NULL);
#else
    RFB_CHECK(strstr(help, "--verbose") == NULL);
    RFB_CHECK(strstr(help, "--log-level") == NULL);
#ifdef FARSEE_RELEASE_BUILD
    RFB_CHECK(strstr(help, "disabled in release builds") != NULL);
#else
    RFB_CHECK(strstr(help, "unavailable without RDP support") != NULL);
#endif
#endif
    (void)fclose(mem);
    free(help);

    char help_arg[] = "--help";
    char version_arg[] = "--version";
    char capabilities_arg[] = "--protocol-capabilities";
    struct early_action_case {
        char *arg;
        farsee_cli_action action;
    } early_actions[] = {
        {help_arg, FARSEE_CLI_ACTION_HELP},
        {version_arg, FARSEE_CLI_ACTION_VERSION},
        {capabilities_arg, FARSEE_CLI_ACTION_CAPABILITIES},
    };
    for (size_t i = 0u;
         i < sizeof early_actions / sizeof early_actions[0]; i++) {
        char *argv[] = {a0, early_actions[i].arg};
        err[0] = '\0';
        RFB_CHECK_EQ_INT(
            farsee_cli_parse_args(2, argv, &opt, err, sizeof err), 0);
        RFB_CHECK_EQ_INT(opt.action, early_actions[i].action);
    }

#ifndef FARSEE_ENABLE_WLOG_DIAGNOSTICS
    char log_trace[] = "--log-level=trace";
    struct disabled_after_early_case {
        char *early;
        char *disabled;
    } disabled_after_early[] = {
        {help_arg, verbose_long},
        {version_arg, log_trace},
        {capabilities_arg, verbose_short},
    };
    for (size_t i = 0u;
         i < sizeof disabled_after_early / sizeof disabled_after_early[0]; i++) {
        char *argv[] = {a0, disabled_after_early[i].early,
                        disabled_after_early[i].disabled};
        err[0] = '\0';
        RFB_CHECK_EQ_INT(
            farsee_cli_parse_args(3, argv, &opt, err, sizeof err), 2);
        RFB_CHECK(strstr(err, disabled_reason) != NULL);
    }

    char unrelated[] = "--verbose-output";
    char *unrelated_argv[] = {a0, help_arg, unrelated};
    err[0] = '\0';
    RFB_CHECK_EQ_INT(
        farsee_cli_parse_args(3, unrelated_argv, &opt, err, sizeof err), 0);
    RFB_CHECK_EQ_INT(opt.action, FARSEE_CLI_ACTION_HELP);
#endif
}

RFB_TEST(cli_args, wlog_controls__resolved_protocol_must_be_rdp)
{
    farsee_cli_options opt;
    char err[192];

    farsee_cli_options_init(&opt);
    opt.log_level = FARSEE_CLI_LOG_INFO;
    opt.log_level_set = true;

    opt.protocol = FARSEE_CLI_PROTOCOL_RFB;
    err[0] = '\0';
    RFB_CHECK(!farsee_cli_validate_resolved_options(&opt, err, sizeof err));
    RFB_CHECK(strstr(err, "RDP target") != NULL);

    opt.protocol = FARSEE_CLI_PROTOCOL_DEFAULT;
    err[0] = '\0';
    RFB_CHECK(!farsee_cli_validate_resolved_options(&opt, err, sizeof err));
    RFB_CHECK(strstr(err, "resolved protocol") != NULL);

    opt.protocol = FARSEE_CLI_PROTOCOL_RDP;
    err[0] = '\0';
    RFB_CHECK(farsee_cli_validate_resolved_options(&opt, err, sizeof err));

    opt.protocol = FARSEE_CLI_PROTOCOL_RFB;
    opt.log_level = FARSEE_CLI_LOG_OFF;
    err[0] = '\0';
    RFB_CHECK(!farsee_cli_validate_resolved_options(&opt, err, sizeof err));
    RFB_CHECK(strstr(err, "RDP target") != NULL);

    opt.log_level_set = false;
    err[0] = '\0';
    RFB_CHECK(farsee_cli_validate_resolved_options(&opt, err, sizeof err));
}

RFB_TEST(cli_args, parse__removed_dump_options__fail_closed)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char host[] = "host.example";
    char dump_frame[] = "--dump-frame=/tmp/frame.rgba";
    char presenter_dump[] = "--presenter=dump";
    char *dump_argv[] = {a0, dump_frame, host};
    char *presenter_argv[] = {a0, presenter_dump, host};

    RFB_CHECK_EQ_INT(farsee_cli_parse_args(
                         3, dump_argv, &opt, err, sizeof err),
                     2);
    RFB_CHECK(strstr(err, "--dump-frame") != NULL);
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(
                         3, presenter_argv, &opt, err, sizeof err),
                     2);
    RFB_CHECK(strstr(err, "--presenter") != NULL);
    RFB_CHECK(strstr(err, "auto|kitty|kitty-direct|kitty-shm|null") != NULL);
}

RFB_TEST(cli_args, parse__all_presenter_values__accepted)
{
    const char *values[] = {
        "auto",
        "null",
        "kitty",
        "kitty-direct",
        "kitty-shm",
    };
    char a0[] = "farsee";
    char host[] = "host.example";

    for (size_t i = 0u; i < sizeof values / sizeof values[0]; i++) {
        farsee_cli_options opt;
        char err[128];
        char option[64];
        const int length = snprintf(
            option, sizeof option, "--presenter=%s", values[i]);
        RFB_CHECK(length > 0 && (size_t)length < sizeof option);
        char *argv[] = {a0, option, host};
        RFB_CHECK_EQ_INT(
            farsee_cli_parse_args(3, argv, &opt, err, sizeof err), 0);
        RFB_CHECK(opt.has_presenter);
        RFB_CHECK(strcmp(opt.presenter, values[i]) == 0);
    }
}

RFB_TEST(cli_args, parse__port_missing_value__fails)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--port";
    char *argv[] = {a0, a1};
    int rc = farsee_cli_parse_args(2, argv, &opt, err, sizeof err);
    RFB_CHECK_EQ_INT(rc, 2);
    RFB_CHECK(strstr(err, "--port") != NULL);
}

RFB_TEST(cli_args, parse__auth_bogus__fails)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--auth=bogus";
    char a2[] = "host.example";
    char *argv[] = {a0, a1, a2};
    int rc = farsee_cli_parse_args(3, argv, &opt, err, sizeof err);
    RFB_CHECK_EQ_INT(rc, 2);
    RFB_CHECK(strstr(err, "auth") != NULL || strstr(err, "bogus") != NULL);
}

RFB_TEST(cli_args, parse__protocol_bogus__fails)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--protocol";
    char a2[] = "ftp";
    char a3[] = "host.example";
    char *argv[] = {a0, a1, a2, a3};
    int rc = farsee_cli_parse_args(4, argv, &opt, err, sizeof err);
    RFB_CHECK_EQ_INT(rc, 2);
    RFB_CHECK(strstr(err, "protocol") != NULL || strstr(err, "ftp") != NULL);
}

RFB_TEST(cli_args, parse__clipboard_bogus__fails)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--clipboard";
    char a2[] = "maybe";
    char a3[] = "host.example";
    char *argv[] = {a0, a1, a2, a3};
    int rc = farsee_cli_parse_args(4, argv, &opt, err, sizeof err);
    RFB_CHECK_EQ_INT(rc, 2);
    RFB_CHECK(strstr(err, "clipboard") != NULL);
}

RFB_TEST(cli_args, parse__host_and_port__ok)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--port";
    char a2[] = "5901";
    char a3[] = "192.0.2.10";
    char *argv[] = {a0, a1, a2, a3};
    int rc = farsee_cli_parse_args(4, argv, &opt, err, sizeof err);
    RFB_CHECK_EQ_INT(rc, 0);
    RFB_CHECK(opt.has_host);
    RFB_CHECK(strcmp(opt.host, "192.0.2.10") == 0);
    RFB_CHECK_EQ_UINT(opt.port, 5901u);
    RFB_CHECK_EQ_INT(opt.action, FARSEE_CLI_ACTION_RUN);
    /* Clipboard defaults on when flag absent. */
    RFB_CHECK(opt.clipboard_on);
}

RFB_TEST(cli_args, parse__auth_equals_vnc__ok)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--auth=vnc";
    char a2[] = "h";
    char *argv[] = {a0, a1, a2};
    int rc = farsee_cli_parse_args(3, argv, &opt, err, sizeof err);
    RFB_CHECK_EQ_INT(rc, 0);
    RFB_CHECK_EQ_INT(opt.auth, FARSEE_CLI_AUTH_VNC);
}

RFB_TEST(cli_args, parse__apple_postauth_defaults_to_cleartext)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "host.example";
    char *argv[] = {a0, a1};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(2, argv, &opt, err, sizeof err), 0);
    RFB_CHECK_EQ_INT(opt.apple_postauth,
                     FARSEE_CLI_APPLE_POSTAUTH_CLEARTEXT);
    RFB_CHECK(!opt.apple_send_viewer_info);
    RFB_CHECK(!opt.apple_disable_wake_keys);
}

RFB_TEST(cli_args, parse__apple_postauth_records_and_private__ok)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--apple-postauth=records";
    char a2[] = "--apple-viewer-info";
    char a3[] = "--apple-wake-keys=off";
    char a4[] = "host.example";
    char *records_argv[] = {a0, a1, a2, a3, a4};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(5, records_argv, &opt, err,
                                           sizeof err), 0);
    RFB_CHECK_EQ_INT(opt.apple_postauth,
                     FARSEE_CLI_APPLE_POSTAUTH_RECORDS);
    RFB_CHECK(opt.apple_send_viewer_info);
    RFB_CHECK(opt.apple_disable_wake_keys);

    char b1[] = "--apple-postauth";
    char b2[] = "private";
    char b3[] = "--apple-wake-keys=on";
    char *private_argv[] = {a0, b1, b2, b3, a4};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(5, private_argv, &opt, err,
                                           sizeof err), 0);
    RFB_CHECK_EQ_INT(opt.apple_postauth,
                     FARSEE_CLI_APPLE_POSTAUTH_PRIVATE_ENCODINGS);
    RFB_CHECK(!opt.apple_send_viewer_info);
    RFB_CHECK(!opt.apple_disable_wake_keys);
}

RFB_TEST(cli_args, parse__apple_security_auto_and_36__ok)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--apple-security=36";
    char a2[] = "host.example";
    char *type36_argv[] = {a0, a1, a2};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(3, type36_argv, &opt, err,
                                           sizeof err), 0);
    RFB_CHECK(opt.apple_require_type_36);

    char b1[] = "--apple-security";
    char b2[] = "auto";
    char *auto_argv[] = {a0, b1, b2, a2};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(4, auto_argv, &opt, err,
                                           sizeof err), 0);
    RFB_CHECK(!opt.apple_require_type_36);
}

RFB_TEST(cli_args, parse__apple_security_invalid__fails)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--apple-security=33";
    char a2[] = "host.example";
    char *argv[] = {a0, a1, a2};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(3, argv, &opt, err, sizeof err), 2);
    RFB_CHECK(strstr(err, "--apple-security") != NULL);
}

RFB_TEST(cli_args, parse__apple_postauth_and_wake_invalid__fail)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--apple-postauth=unknown";
    char a2[] = "host.example";
    char *postauth_argv[] = {a0, a1, a2};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(3, postauth_argv, &opt, err,
                                           sizeof err), 2);
    RFB_CHECK(strstr(err, "--apple-postauth") != NULL);

    char b1[] = "--apple-wake-keys=maybe";
    char *wake_argv[] = {a0, b1, a2};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(3, wake_argv, &opt, err,
                                           sizeof err), 2);
    RFB_CHECK(strstr(err, "--apple-wake-keys") != NULL);
}

RFB_TEST(cli_args, parse__help__action)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--help";
    char *argv[] = {a0, a1};
    int rc = farsee_cli_parse_args(2, argv, &opt, err, sizeof err);
    RFB_CHECK_EQ_INT(rc, 0);
    RFB_CHECK_EQ_INT(opt.action, FARSEE_CLI_ACTION_HELP);
}

RFB_TEST(cli_args, parse__url_password_rejected)
{
    farsee_cli_options opt;
    char err[256];
    char a0[] = "farsee";
    char a1[] = "vnc://u:secret@host:5900";
    char *argv[] = {a0, a1};
    int rc = farsee_cli_parse_args(2, argv, &opt, err, sizeof err);
    RFB_CHECK_EQ_INT(rc, 2);
    RFB_CHECK(err[0] != '\0');
}

RFB_TEST(cli_args, parse__null_out__fails)
{
    char err[64];
    char a0[] = "farsee";
    char *argv[] = {a0};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(1, argv, NULL, err, sizeof err), 2);
}

// Despite the legacy registry label, this checks only the AES/0x044f and HEVC
// markers in the capability text. It does not exercise either protocol path.
RFB_TEST(cli_args, print_capabilities__apple_record_honesty)
{
    char *buf = NULL;
    size_t buf_sz = 0;
    FILE *mem = open_memstream(&buf, &buf_sz);
    RFB_CHECK(mem != NULL);
    farsee_cli_print_capabilities(mem);
    RFB_CHECK(fflush(mem) == 0);
    RFB_CHECK(buf != NULL);
    RFB_CHECK(strstr(buf, "AES-128-CBC") != NULL ||
              strstr(buf, "AES-CBC") != NULL ||
              strstr(buf, "0x044f") != NULL);
    RFB_CHECK(strstr(buf, "HEVC") != NULL);
    RFB_CHECK(strstr(buf, "NOT ENABLED") != NULL);
    (void)fclose(mem);
    free(buf);
}

// These output-contract cases check policy/type and private-encoding markers.
RFB_TEST(cli_args, print_capabilities__apple_scope_is_complete)
{
    char *buf = NULL;
    size_t buf_sz = 0u;
    FILE *mem = open_memstream(&buf, &buf_sz);
    RFB_CHECK(mem != NULL);
    farsee_cli_print_capabilities(mem);
    RFB_CHECK(fflush(mem) == 0);
    RFB_CHECK(buf != NULL);
    RFB_CHECK(strstr(buf, "types 33 and 36 live") != NULL);
    RFB_CHECK(strstr(buf, "type 36") != NULL);
    RFB_CHECK(strstr(buf, "rejected before authentication") == NULL);
    RFB_CHECK(strstr(buf, "0x03f3") != NULL);
    RFB_CHECK(strstr(buf, "0x0450") != NULL);
    RFB_CHECK(strstr(buf, "OpenSSL 3.x: Apple auth on macOS and Linux") !=
              NULL);
    RFB_CHECK(strstr(buf, "OpenSSL 3.x (Linux)") == NULL);
    (void)fclose(mem);
    free(buf);
}

RFB_TEST(cli_args, print_help__apple_auth_scope_is_complete)
{
    char *buf = NULL;
    size_t buf_sz = 0u;
    FILE *mem = open_memstream(&buf, &buf_sz);
    RFB_CHECK(mem != NULL);
    farsee_cli_print_help(mem, "farsee");
    RFB_CHECK(fflush(mem) == 0);
    RFB_CHECK(buf != NULL);
    RFB_CHECK(strstr(buf, "types 33 and 36") != NULL);
    RFB_CHECK(strstr(buf, "--apple-security auto|36") != NULL);
    RFB_CHECK(strstr(buf, "rejected before authentication") == NULL);
    RFB_CHECK(strstr(buf, "0x03f3") != NULL);
    RFB_CHECK(strstr(buf, "G17") == NULL);
    (void)fclose(mem);
    free(buf);
}

RFB_TEST(cli_args, print_help__does_not_claim_apple_account_authentication)
{
    char *buf = NULL;
    size_t buf_sz = 0u;
    FILE *mem = open_memstream(&buf, &buf_sz);
    RFB_CHECK(mem != NULL);
    farsee_cli_print_help(mem, "farsee");
    RFB_CHECK(fflush(mem) == 0);
    RFB_CHECK(buf != NULL);
    RFB_CHECK(strstr(buf, "Apple account") == NULL);
    RFB_CHECK(strstr(buf, "Apple login name") != NULL);
    (void)fclose(mem);
    free(buf);
}

RFB_TEST(cli_args, print_help__removed_dump_surface_is_absent)
{
    char *buf = NULL;
    size_t buf_sz = 0u;
    FILE *mem = open_memstream(&buf, &buf_sz);
    RFB_CHECK(mem != NULL);
    farsee_cli_print_help(mem, "farsee");
    RFB_CHECK(fflush(mem) == 0);
    RFB_CHECK(buf != NULL);
    RFB_CHECK(strstr(buf, "dump") == NULL);
    RFB_CHECK(strstr(
                  buf, "--presenter auto|kitty|kitty-direct|kitty-shm|null") !=
              NULL);
    (void)fclose(mem);
    free(buf);
}

// The --cert prompt is not implemented; the parser rejects it.
RFB_TEST(cli_args, parse__cert_prompt__rejected)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--cert";
    char a2[] = "prompt";
    char a3[] = "host.example";
    char *argv[] = {a0, a1, a2, a3};
    int rc = farsee_cli_parse_args(4, argv, &opt, err, sizeof err);
    RFB_CHECK_EQ_INT(rc, 2);
    RFB_CHECK(strstr(err, "cert") != NULL || strstr(err, "prompt") != NULL ||
              strstr(err, "ignore") != NULL);
}

RFB_TEST(cli_args, parse__cert_ignore__ok)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--cert";
    char a2[] = "ignore";
    char a3[] = "host.example";
    char *argv[] = {a0, a1, a2, a3};
    int rc = farsee_cli_parse_args(4, argv, &opt, err, sizeof err);
    RFB_CHECK_EQ_INT(rc, 0);
    RFB_CHECK(strcmp(opt.cert_policy, "ignore") == 0);
}

// --- Parse-boundary regressions -------------------------------------------

RFB_TEST(cli_args, parse__view_scale_below_min__fails)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--view-scale=19";
    char a2[] = "host.example";
    char *argv[] = {a0, a1, a2};
    int rc = farsee_cli_parse_args(3, argv, &opt, err, sizeof err);
    RFB_CHECK_EQ_INT(rc, 2);
    RFB_CHECK(strstr(err, "--view-scale") != NULL);
}

RFB_TEST(cli_args, parse__view_scale_min_and_max__ok)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--view-scale";
    char a2[] = "20";
    char a3[] = "--view-scale=100";
    char a4[] = "host.example";
    char *argv[] = {a0, a1, a2, a4};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(4, argv, &opt, err, sizeof err), 0);
    RFB_CHECK_EQ_UINT(opt.view_scale_pct, 20u);
    char *argv2[] = {a0, a3, a4};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(3, argv2, &opt, err,
                                           sizeof err), 0);
    RFB_CHECK_EQ_UINT(opt.view_scale_pct, 100u);
}

RFB_TEST(cli_args, parse__connect_timeout_over_u32__fails)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--connect-timeout=4294967296";
    char a2[] = "host.example";
    char *argv[] = {a0, a1, a2};
    int rc = farsee_cli_parse_args(3, argv, &opt, err, sizeof err);
    RFB_CHECK_EQ_INT(rc, 2);
    RFB_CHECK(strstr(err, "--connect-timeout") != NULL);
}

RFB_TEST(cli_args, parse__connect_timeout_u32_max__ok)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--connect-timeout=4294967295";
    char a2[] = "host.example";
    char *argv[] = {a0, a1, a2};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(3, argv, &opt, err,
                                           sizeof err), 0);
    RFB_CHECK_EQ_UINT((uint32_t)opt.connect_timeout_ms, 4294967295u);
}

RFB_TEST(cli_args, parse__accept_new_host_flag__parses_default_off)
{
    farsee_cli_options opt;
    char err[128];
    char a0[] = "farsee";
    char a1[] = "--accept-new-host";
    char a2[] = "host.example";
    char *argv[] = {a0, a2};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(2, argv, &opt, err,
                                           sizeof err), 0);
    RFB_CHECK(!opt.accept_new_host);
    char *argv2[] = {a0, a1, a2};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(3, argv2, &opt, err,
                                           sizeof err), 0);
    RFB_CHECK(opt.accept_new_host);
    char a3[] = "--accept-new-host=0";
    char *argv3[] = {a0, a3, a2};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(3, argv3, &opt, err,
                                           sizeof err), 0);
    RFB_CHECK(!opt.accept_new_host);
}

RFB_TEST(cli_args, public_guards__fail_closed_without_error_storage)
{
    farsee_cli_options options;
    char program[] = "farsee";
    char unknown[] = "--unknown";
    char port[] = "--port";
    char bad_auth[] = "--auth=bogus";
    char bad_leader[] = "--leader=shift-x";
    char bad_target[] = "rfb://";
    char *unknown_argv[] = {program, unknown};
    char *port_argv[] = {program, port};
    char *auth_argv[] = {program, bad_auth};
    char *leader_argv[] = {program, bad_leader};
    char *target_argv[] = {program, bad_target};
    char *null_argv[] = {program, NULL};

    farsee_cli_options_init(NULL);
    farsee_cli_resolve_protocol(NULL, 3389u);

    RFB_CHECK_EQ_INT(
        farsee_cli_parse_args(2, unknown_argv, &options, NULL, 0u), 2);
    RFB_CHECK_EQ_INT(
        farsee_cli_parse_args(2, port_argv, &options, NULL, 0u), 2);
    RFB_CHECK_EQ_INT(
        farsee_cli_parse_args(2, auth_argv, &options, NULL, 0u), 2);
    RFB_CHECK_EQ_INT(
        farsee_cli_parse_args(2, leader_argv, &options, NULL, 0u), 2);
    RFB_CHECK_EQ_INT(
        farsee_cli_parse_args(2, target_argv, &options, NULL, 0u), 2);
    RFB_CHECK_EQ_INT(
        farsee_cli_parse_args(2, null_argv, &options, NULL, 0u), 2);
    RFB_CHECK_EQ_INT(
        farsee_cli_parse_args(0, unknown_argv, &options, NULL, 0u), 2);
    RFB_CHECK_EQ_INT(
        farsee_cli_parse_args(1, NULL, &options, NULL, 0u), 2);
    RFB_CHECK_EQ_INT(
        farsee_cli_parse_args(1, unknown_argv, NULL, NULL, 0u), 2);

    RFB_CHECK(!farsee_cli_validate_resolved_options(NULL, NULL, 0u));
}

RFB_TEST(cli_args, resolved_options__cover_protocol_and_log_boundaries)
{
    farsee_cli_options options;
    char error[128];

    farsee_cli_options_init(&options);
    farsee_cli_resolve_protocol(&options.protocol, 13390u);
    RFB_CHECK_EQ_INT(options.protocol, FARSEE_CLI_PROTOCOL_RDP);

    options.protocol = FARSEE_CLI_PROTOCOL_RFB;
    farsee_cli_resolve_protocol(&options.protocol, 3389u);
    RFB_CHECK_EQ_INT(options.protocol, FARSEE_CLI_PROTOCOL_RFB);

    options.log_level = (farsee_cli_log_level)99;
    options.log_level_set = true;
    RFB_CHECK(!farsee_cli_validate_resolved_options(
        &options, error, sizeof error));
    RFB_CHECK(strstr(error, "invalid") != NULL);

    options.log_level = FARSEE_CLI_LOG_INFO;
    options.protocol = FARSEE_CLI_PROTOCOL_AUTO;
    RFB_CHECK(!farsee_cli_validate_resolved_options(
        &options, error, sizeof error));
    RFB_CHECK(strstr(error, "resolved protocol") != NULL);
}

RFB_TEST(cli_args, parser_edges__cover_long_and_split_option_forms)
{
    farsee_cli_options options;
    char error[128];
    char program[] = "farsee";
    char long_unknown[] =
        "--this-option-name-is-deliberately-longer-than-sixty-four-characters"
        "-and-must-be-truncated";
    char cert[] = "--cert";
    char pin[] = "pin";
    char host[] = "host.example";
    char *unknown_argv[] = {program, long_unknown};
    char *cert_argv[] = {program, cert, pin, host};

    RFB_CHECK_EQ_INT(farsee_cli_parse_args(
                         2, unknown_argv, &options, error, sizeof error),
                     2);
    RFB_CHECK(strstr(error, "...") != NULL);

    RFB_CHECK_EQ_INT(farsee_cli_parse_args(
                         4, cert_argv, &options, error, sizeof error),
                     0);
    RFB_CHECK(options.has_cert_policy);
    RFB_CHECK(strcmp(options.cert_policy, "pin") == 0);
}
