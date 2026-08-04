// SPDX-License-Identifier: Apache-2.0
//
// Fail-closed CLI option parser (Q4). Pure: no I/O, no getenv.
//
// Positive: valid host + port (and common option forms).
// Negative: unknown options, missing values, invalid auth/protocol/clipboard.

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

// T6: capabilities text must honestly state Apple Full-Quality is cleartext
// MVP / NOT encrypted, and HEVC is not enabled.
RFB_TEST(cli_args, print_capabilities__apple_cleartext_honesty)
{
    char *buf = NULL;
    size_t buf_sz = 0;
    FILE *mem = open_memstream(&buf, &buf_sz);
    RFB_CHECK(mem != NULL);
    farsee_cli_print_capabilities(mem);
    RFB_CHECK(fflush(mem) == 0);
    RFB_CHECK(buf != NULL);
    RFB_CHECK(strstr(buf, "cleartext") != NULL);
    RFB_CHECK(strstr(buf, "NOT encrypted") != NULL ||
              strstr(buf, "not encrypted") != NULL);
    RFB_CHECK(strstr(buf, "HEVC") != NULL);
    RFB_CHECK(strstr(buf, "NOT ENABLED") != NULL);
    (void)fclose(mem);
    free(buf);
}

// Residual T3: --cert prompt is not implemented; parser rejects it.
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
