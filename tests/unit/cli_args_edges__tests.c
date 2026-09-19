// SPDX-License-Identifier: Apache-2.0
//
// CLI option composition, aliases, and fail-closed edge contracts.

#include "rfb_test.h"
#include "farsee/cli_args.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_single_option(const char *option, farsee_cli_options *out,
                               char *error, size_t error_capacity)
{
    char program[] = "farsee";
    char argument[384];
    char host[] = "host.example";
    const int written = snprintf(argument, sizeof argument, "%s", option);
    if (written < 0 || (size_t)written >= sizeof argument) {
        return -1;
    }
    char *argv[] = {program, argument, host};
    return farsee_cli_parse_args(3, argv, out, error, error_capacity);
}

RFB_TEST(cli_args_edges, full_option_set__preserves_every_selected_value)
{
    char a0[] = "farsee";
    char a1[] = "--auth";
    char a2[] = "apple";
    char a3[] = "--protocol";
    char a4[] = "auto";
    char a5[] = "--port";
    char a6[] = "5901";
    char a7[] = "--user";
    char a8[] = "alice";
    char a9[] = "--domain";
    char a10[] = "lab";
    char a11[] = "--cert";
    char a12[] = "pin";
    char a13[] = "--password-fd";
    char a14[] = "7";
    char a15[] = "--presenter";
    char a16[] = "kitty";
    char a17[] = "--desktop-w";
    char a18[] = "1920";
    char a19[] = "--desktop-h";
    char a20[] = "1080";
    char a21[] = "--connect-timeout";
    char a22[] = "1234";
    char a23[] = "--view-only";
    char a24[] = "--allow-none-auth";
    char a25[] = "--exclusive";
    char a26[] = "--apple-attach";
    char a27[] = "login";
    char a28[] = "--apple-postauth";
    char a29[] = "records";
    char a30[] = "--apple-viewer-info";
    char a31[] = "--apple-wake-keys";
    char a32[] = "off";
    char a33[] = "--max-fps";
    char a34[] = "60";
    char a35[] = "--clipboard";
    char a36[] = "off";
    char a37[] = "--leader";
    char a38[] = "C-a";
    char a39[] = "vnc://bob@host.example:5902";
    char *argv[] = {
        a0,  a1,  a2,  a3,  a4,  a5,  a6,  a7,  a8,  a9,
        a10, a11, a12, a13, a14, a15, a16, a17, a18, a19,
        a20, a21, a22, a23, a24, a25, a26, a27, a28, a29,
        a30, a31, a32, a33, a34, a35, a36, a37, a38, a39,
    };
    farsee_cli_options options;
    char error[192];

    RFB_CHECK_EQ_INT(farsee_cli_parse_args(
                         (int)(sizeof argv / sizeof argv[0]), argv,
                         &options, error, sizeof error), 0);
    RFB_CHECK_EQ_INT(options.auth, FARSEE_CLI_AUTH_APPLE);
    RFB_CHECK_EQ_INT(options.protocol, FARSEE_CLI_PROTOCOL_RFB);
    RFB_CHECK_EQ_UINT(options.port, 5901u);
    RFB_CHECK(options.has_user);
    RFB_CHECK(strcmp(options.user, "alice") == 0);
    RFB_CHECK(options.has_domain);
    RFB_CHECK(strcmp(options.domain, "lab") == 0);
    RFB_CHECK(options.has_cert_policy);
    RFB_CHECK(strcmp(options.cert_policy, "pin") == 0);
    RFB_CHECK_EQ_INT(options.password_fd, 7);
    RFB_CHECK(options.has_presenter);
    RFB_CHECK(strcmp(options.presenter, "kitty") == 0);
    RFB_CHECK_EQ_UINT(options.desk_w, 1920u);
    RFB_CHECK_EQ_UINT(options.desk_h, 1080u);
    RFB_CHECK_EQ_UINT(options.connect_timeout_ms, 1234u);
    RFB_CHECK(options.view_only);
    RFB_CHECK(options.allow_none_auth);
    RFB_CHECK(!options.shared_session);
    RFB_CHECK_EQ_UINT(options.apple_attach, 2u);
    RFB_CHECK_EQ_INT(options.apple_postauth,
                     FARSEE_CLI_APPLE_POSTAUTH_RECORDS);
    RFB_CHECK(options.apple_send_viewer_info);
    RFB_CHECK(options.apple_disable_wake_keys);
    RFB_CHECK_EQ_UINT(options.max_fps, 60u);
    RFB_CHECK(!options.clipboard_on);
    RFB_CHECK(options.leader_set);
    RFB_CHECK(options.has_host);
    RFB_CHECK(strcmp(options.host, "host.example") == 0);
}

RFB_TEST(cli_args_edges, value_options__missing_value__fail_closed)
{
    static const char *const option_names[] = {
        "--auth", "--protocol", "--user", "--domain", "--cert",
        "--password-fd", "--presenter", "--desktop-w", "--desktop-h",
        "--connect-timeout", "--view-scale", "--apple-attach",
        "--apple-postauth", "--apple-wake-keys", "--max-fps",
        "--clipboard", "--leader",
    };
    char program[] = "farsee";

    for (size_t i = 0u;
         i < sizeof option_names / sizeof option_names[0]; i++) {
        char option[32];
        char error[192];
        farsee_cli_options options;
        const int written = snprintf(option, sizeof option, "%s",
                                     option_names[i]);
        RFB_CHECK(written > 0 && (size_t)written < sizeof option);
        char *argv[] = {program, option};
        RFB_CHECK_EQ_INT(farsee_cli_parse_args(2, argv, &options,
                                               error, sizeof error), 2);
        RFB_CHECK(strstr(error, "requires a value") != NULL);
    }
}

RFB_TEST(cli_args_edges, invalid_option_values__report_the_rejected_option)
{
    struct invalid_case {
        const char *argument;
        const char *diagnostic;
    } cases[] = {
        {"--port=0", "--port"},
        {"--port=65536", "--port"},
        {"--password-fd=-1", "--password-fd"},
        {"--desktop-w=-1", "--desktop-w"},
        {"--desktop-h=no", "--desktop-h"},
        {"--connect-timeout=-1", "--connect-timeout"},
        {"--view-scale=19", "--view-scale"},
        {"--view-scale=101", "--view-scale"},
        {"--apple-attach=no", "--apple-attach"},
        {"--apple-postauth=no", "--apple-postauth"},
        {"--apple-wake-keys=no", "--apple-wake-keys"},
        {"--max-fps=241", "--max-fps"},
        {"--clipboard=no", "--clipboard"},
        {"--leader=alt-x", "--leader"},
        {"--presenter=other", "--presenter"},
    };

    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        farsee_cli_options options;
        char error[192];
        RFB_CHECK_EQ_INT(parse_single_option(cases[i].argument, &options,
                                             error, sizeof error), 2);
        RFB_CHECK(strstr(error, cases[i].diagnostic) != NULL);
    }
}

RFB_TEST(cli_args_edges, documented_aliases__map_to_canonical_values)
{
    struct alias_case {
        const char *argument;
        int expected;
        int field;
    } cases[] = {
        {"--auth=auto", FARSEE_CLI_AUTH_AUTO, 0},
        {"--protocol=rdp", FARSEE_CLI_PROTOCOL_RDP, 1},
        {"--protocol=vnc", FARSEE_CLI_PROTOCOL_RFB, 1},
        {"--apple-attach=display", 1, 2},
        {"--apple-attach=user", 2, 2},
        {"--apple-attach=prompt", 0, 2},
        {"--apple-postauth=compat", FARSEE_CLI_APPLE_POSTAUTH_CLEARTEXT, 3},
        {"--apple-postauth=protected", FARSEE_CLI_APPLE_POSTAUTH_RECORDS, 3},
        {"--apple-postauth=private",
         FARSEE_CLI_APPLE_POSTAUTH_PRIVATE_ENCODINGS, 3},
        {"--clipboard=1", 1, 4},
        {"--clipboard=true", 1, 4},
        {"--clipboard=0", 0, 4},
        {"--clipboard=false", 0, 4},
    };

    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        farsee_cli_options options;
        char error[192];
        RFB_CHECK_EQ_INT(parse_single_option(cases[i].argument, &options,
                                             error, sizeof error), 0);
        switch (cases[i].field) {
        case 0:
            RFB_CHECK_EQ_INT(options.auth, cases[i].expected);
            break;
        case 1:
            RFB_CHECK_EQ_INT(options.protocol, cases[i].expected);
            break;
        case 2:
            RFB_CHECK_EQ_INT(options.apple_attach, cases[i].expected);
            break;
        case 3:
            RFB_CHECK_EQ_INT(options.apple_postauth, cases[i].expected);
            break;
        case 4:
            RFB_CHECK_EQ_INT(options.clipboard_on, cases[i].expected);
            break;
        default:
            RFB_CHECK(false);
            break;
        }
    }
}

RFB_TEST(cli_args_edges, protocol_resolution__covers_auto_and_explicit_modes)
{
    farsee_cli_protocol protocol = FARSEE_CLI_PROTOCOL_DEFAULT;
    farsee_cli_resolve_protocol(NULL, 3389u);
    farsee_cli_resolve_protocol(&protocol, 3389u);
    RFB_CHECK_EQ_INT(protocol, FARSEE_CLI_PROTOCOL_RDP);

    protocol = FARSEE_CLI_PROTOCOL_AUTO;
    farsee_cli_resolve_protocol(&protocol, 13390u);
    RFB_CHECK_EQ_INT(protocol, FARSEE_CLI_PROTOCOL_RDP);

    protocol = FARSEE_CLI_PROTOCOL_AUTO;
    farsee_cli_resolve_protocol(&protocol, 5900u);
    RFB_CHECK_EQ_INT(protocol, FARSEE_CLI_PROTOCOL_RFB);

    protocol = FARSEE_CLI_PROTOCOL_RDP;
    farsee_cli_resolve_protocol(&protocol, 5900u);
    RFB_CHECK_EQ_INT(protocol, FARSEE_CLI_PROTOCOL_RDP);
}

RFB_TEST(cli_args_edges, resolved_validation__rejects_invalid_and_unresolved_logging)
{
    farsee_cli_options options;
    char error[192];

    farsee_cli_options_init(NULL);
    RFB_CHECK(!farsee_cli_validate_resolved_options(NULL,
                                                     error, sizeof error));
    RFB_CHECK(strstr(error, "null options") != NULL);

    farsee_cli_options_init(&options);
    options.log_level = (farsee_cli_log_level)99;
    RFB_CHECK(!farsee_cli_validate_resolved_options(&options,
                                                     error, sizeof error));
    RFB_CHECK(strstr(error, "invalid") != NULL);

    farsee_cli_options_init(&options);
    options.log_level = FARSEE_CLI_LOG_INFO;
    options.log_level_set = true;
    RFB_CHECK(!farsee_cli_validate_resolved_options(&options,
                                                     error, sizeof error));
    RFB_CHECK(strstr(error, "resolved protocol") != NULL);

    options.protocol = FARSEE_CLI_PROTOCOL_RFB;
    RFB_CHECK(!farsee_cli_validate_resolved_options(&options,
                                                     error, sizeof error));
    RFB_CHECK(strstr(error, "RDP target") != NULL);

    options.protocol = FARSEE_CLI_PROTOCOL_RDP;
    RFB_CHECK(farsee_cli_validate_resolved_options(&options,
                                                    error, sizeof error));
}

RFB_TEST(cli_args_edges, output_helpers__null_is_safe_and_version_is_complete)
{
    char *output = NULL;
    size_t output_size = 0u;
    FILE *stream = open_memstream(&output, &output_size);
    RFB_CHECK(stream != NULL);

    farsee_cli_print_help(NULL, NULL);
    farsee_cli_print_version(NULL);
    farsee_cli_print_capabilities(NULL);
    farsee_cli_print_version(stream);
    RFB_CHECK(fflush(stream) == 0);
    RFB_CHECK(output != NULL);
    RFB_CHECK(strstr(output, "farsee 0.1") != NULL);
    RFB_CHECK(strstr(output, "C11 RFB/VNC terminal client") != NULL);
    RFB_CHECK(strstr(output, "License: Apache-2.0") != NULL);
    RFB_CHECK(fclose(stream) == 0);
    free(output);
}

RFB_TEST(cli_args_edges,
         suppressed_diagnostics_and_rare_values__remain_fail_closed)
{
    char program[] = "farsee";
    farsee_cli_options options;

    RFB_CHECK_EQ_INT(farsee_cli_parse_args(0, NULL, &options, NULL, 0u), 2);
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(0, NULL, NULL, NULL, 0u), 2);

    char auth[] = "--auth";
    char *missing_value[] = {program, auth};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(2, missing_value, &options,
                                           NULL, 0u), 2);
    char invalid_auth[] = "--auth=invalid";
    char host[] = "host.example";
    char *invalid_value[] = {program, invalid_auth, host};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(3, invalid_value, &options,
                                           NULL, 0u), 2);
    char invalid_leader[] = "--leader=alt-x";
    char *bad_leader[] = {program, invalid_leader, host};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(3, bad_leader, &options,
                                           NULL, 0u), 2);
    char invalid_target[] = "user@";
    char *bad_target[] = {program, invalid_target};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(2, bad_target, &options,
                                           NULL, 0u), 2);

    char long_value[160];
    memset(long_value, 'u', sizeof long_value - 1u);
    long_value[sizeof long_value - 1u] = '\0';
    char long_option[180];
    int written = snprintf(long_option, sizeof long_option, "--user=%s",
                           long_value);
    RFB_CHECK(written > 0 && (size_t)written < sizeof long_option);
    char *long_user[] = {program, long_option, host};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(3, long_user, &options,
                                           NULL, 0u), 2);
    written = snprintf(long_option, sizeof long_option, "--domain=%s",
                       long_value);
    RFB_CHECK(written > 0 && (size_t)written < sizeof long_option);
    char *long_domain[] = {program, long_option, host};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(3, long_domain, &options,
                                           NULL, 0u), 2);

    char long_unknown[96];
    long_unknown[0] = '-';
    long_unknown[1] = '-';
    memset(long_unknown + 2, 'x', sizeof long_unknown - 3u);
    long_unknown[sizeof long_unknown - 1u] = '\0';
    char error[192];
    char *unknown_argv[] = {program, long_unknown, host};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(3, unknown_argv, &options,
                                           error, sizeof error), 2);
    RFB_CHECK(strstr(error, "...") != NULL);

    char shared[] = "--shared";
    char *shared_argv[] = {program, shared, host};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(3, shared_argv, &options,
                                           error, sizeof error), 0);
    RFB_CHECK(options.shared_session);

    char rdp_target[] = "rdp://bob@rdp.example:3390";
    char *target_argv[] = {program, rdp_target};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(2, target_argv, &options,
                                           error, sizeof error), 0);
    RFB_CHECK_EQ_INT(options.protocol, FARSEE_CLI_PROTOCOL_RDP);
    RFB_CHECK_EQ_UINT(options.port, 3390u);
    RFB_CHECK(options.has_user);
    RFB_CHECK(strcmp(options.user, "bob") == 0);
}

RFB_TEST(cli_args_edges,
         branch_distinguishing_aliases__preserve_canonical_values)
{
    farsee_cli_options options;
    char error[192];

    RFB_CHECK_EQ_INT(parse_single_option("--protocol=rfb", &options,
                                         error, sizeof error), 0);
    RFB_CHECK_EQ_INT(options.protocol, FARSEE_CLI_PROTOCOL_RFB);

    RFB_CHECK_EQ_INT(parse_single_option("--apple-attach=share", &options,
                                         error, sizeof error), 0);
    RFB_CHECK_EQ_UINT(options.apple_attach, 1u);
    RFB_CHECK_EQ_INT(parse_single_option("--apple-attach=ask", &options,
                                         error, sizeof error), 0);
    RFB_CHECK_EQ_UINT(options.apple_attach, 0u);

    RFB_CHECK_EQ_INT(parse_single_option("--apple-postauth=cleartext",
                                         &options, error, sizeof error), 0);
    RFB_CHECK_EQ_INT(options.apple_postauth,
                     FARSEE_CLI_APPLE_POSTAUTH_CLEARTEXT);

    RFB_CHECK_EQ_INT(parse_single_option("--clipboard=on", &options,
                                         error, sizeof error), 0);
    RFB_CHECK(options.clipboard_on);
    RFB_CHECK_EQ_INT(parse_single_option("--apple-wake-keys=true", &options,
                                         error, sizeof error), 0);
    RFB_CHECK(!options.apple_disable_wake_keys);
    RFB_CHECK_EQ_INT(parse_single_option("--apple-wake-keys=false", &options,
                                         error, sizeof error), 0);
    RFB_CHECK(options.apple_disable_wake_keys);

    RFB_CHECK_EQ_INT(parse_single_option("--accept-new-host=1", &options,
                                         error, sizeof error), 0);
    RFB_CHECK(options.accept_new_host);

    char program[] = "farsee";
    char short_help[] = "-h";
    char *help_argv[] = {program, short_help};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(2, help_argv, &options,
                                           error, sizeof error), 0);
    RFB_CHECK_EQ_INT(options.action, FARSEE_CLI_ACTION_HELP);

#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
    RFB_CHECK_EQ_INT(parse_single_option("--log-level=none", &options,
                                         error, sizeof error), 0);
    RFB_CHECK_EQ_INT(options.log_level, FARSEE_CLI_LOG_OFF);
    RFB_CHECK_EQ_INT(parse_single_option("--log-level=warning", &options,
                                         error, sizeof error), 0);
    RFB_CHECK_EQ_INT(options.log_level, FARSEE_CLI_LOG_WARN);

    char trace[] = "--log-level=trace";
    char verbose[] = "--verbose";
    char host[] = "host.example";
    char *verbose_argv[] = {program, trace, verbose, host};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(4, verbose_argv, &options,
                                           error, sizeof error), 0);
    RFB_CHECK_EQ_INT(options.log_level, FARSEE_CLI_LOG_TRACE);
#endif
}

RFB_TEST(cli_args_edges,
         parser_failure_causes_and_suppressed_buffers__stay_distinct)
{
    static const char *const nonnumeric_options[] = {
        "--port=no",
        "--password-fd=no",
        "--view-scale=no",
        "--max-fps=no",
    };
    farsee_cli_options options;
    char error[192];

    for (size_t i = 0u;
         i < sizeof nonnumeric_options / sizeof nonnumeric_options[0]; i++) {
        RFB_CHECK_EQ_INT(parse_single_option(nonnumeric_options[i], &options,
                                             error, sizeof error), 2);
    }

    char program[] = "farsee";
    char host[] = "host.example";
    char missing[] = "--auth";
    char invalid[] = "--auth=invalid";
    char leader[] = "--leader=alt-x";
    char target[] = "user@";
    char unknown[] = "--unknown";
    char one_byte_error[1] = {'x'};
    char *missing_argv[] = {program, missing};
    char *invalid_argv[] = {program, invalid, host};
    char *leader_argv[] = {program, leader, host};
    char *target_argv[] = {program, target};
    char *unknown_argv[] = {program, unknown, host};
    char *null_argv[] = {program, NULL};
    char *program_argv[] = {program};

    RFB_CHECK(!farsee_cli_validate_resolved_options(
        NULL, one_byte_error, 0u));
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(
                         1, program_argv, NULL, one_byte_error, 0u), 2);
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(
                         2, missing_argv, &options, one_byte_error, 0u), 2);
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(
                         3, invalid_argv, &options, one_byte_error, 0u), 2);
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(
                         3, leader_argv, &options, one_byte_error, 0u), 2);
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(
                         2, target_argv, &options, one_byte_error, 0u), 2);
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(
                         3, unknown_argv, &options, one_byte_error, 0u), 2);
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(
                         2, null_argv, &options, one_byte_error, 0u), 2);

#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
    char bad_log[] = "--log-level=invalid";
    char *bad_log_argv[] = {program, bad_log, host};
    RFB_CHECK_EQ_INT(farsee_cli_parse_args(
                         3, bad_log_argv, &options, one_byte_error, 0u), 2);
#endif

    char *help_output = NULL;
    size_t help_size = 0u;
    FILE *help = open_memstream(&help_output, &help_size);
    RFB_CHECK(help != NULL);
    farsee_cli_print_help(help, "");
    RFB_CHECK(fflush(help) == 0);
    RFB_CHECK(strstr(help_output, "usage: farsee") != NULL);
    RFB_CHECK(fclose(help) == 0);
    free(help_output);
}
