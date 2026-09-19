// SPDX-License-Identifier: Apache-2.0
//
// Target URL and leader boundary contracts.

#include "rfb_test.h"
#include "farsee/cli_target.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

RFB_TEST(cli_target_edges, percent_decode__validates_inputs_and_hex_forms)
{
    char output[32];
    RFB_CHECK(!farsee_cli_percent_decode(NULL, output, sizeof output));
    RFB_CHECK(!farsee_cli_percent_decode("value", NULL, sizeof output));
    RFB_CHECK(!farsee_cli_percent_decode("value", output, 0u));

    RFB_CHECK(farsee_cli_percent_decode("%30%61%41+z", output,
                                         sizeof output));
    RFB_CHECK(strcmp(output, "0aA z") == 0);
    RFB_CHECK(farsee_cli_percent_decode("trailing%", output,
                                         sizeof output));
    RFB_CHECK(strcmp(output, "trailing%") == 0);
    RFB_CHECK(farsee_cli_percent_decode("trailing%0", output,
                                         sizeof output));
    RFB_CHECK(strcmp(output, "trailing%0") == 0);
    RFB_CHECK(!farsee_cli_percent_decode("%g0", output, sizeof output));
    RFB_CHECK(output[0] == '\0');
    RFB_CHECK(!farsee_cli_percent_decode("%0g", output, sizeof output));
    RFB_CHECK(output[0] == '\0');
}

RFB_TEST(cli_target_edges, schemes__accept_documented_case_variants)
{
    struct scheme_case {
        const char *target;
        farsee_cli_proto protocol;
    } cases[] = {
        {"RDP://host", FARSEE_CLI_PROTO_RDP},
        {"VNC://host", FARSEE_CLI_PROTO_RFB},
        {"rfb://host", FARSEE_CLI_PROTO_RFB},
        {"RFB://host", FARSEE_CLI_PROTO_RFB},
    };

    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        farsee_cli_target target;
        RFB_CHECK(farsee_cli_target_parse(cases[i].target, &target));
        RFB_CHECK_EQ_INT(target.proto, cases[i].protocol);
        RFB_CHECK(strcmp(target.host, "host") == 0);
    }
}

RFB_TEST(cli_target_edges, malformed_authority_and_port__clear_the_result)
{
    static const char *const rejected[] = {
        "user@",
        ":value@host",
        "host:0",
        ":1",
    };

    for (size_t i = 0u; i < sizeof rejected / sizeof rejected[0]; i++) {
        farsee_cli_target target;
        memset(&target, 0xA5, sizeof target);
        RFB_CHECK(!farsee_cli_target_parse(rejected[i], &target));
        RFB_CHECK_EQ_INT(target.proto, FARSEE_CLI_PROTO_NONE);
        RFB_CHECK(target.host[0] == '\0');
        RFB_CHECK(!target.has_user);
        RFB_CHECK(!target.has_password);
    }
}

RFB_TEST(cli_target_edges, oversized_authority_fields__fail_closed)
{
    char target_text[700];
    farsee_cli_target target;

    memset(target_text, 'u', 128u);
    (void)snprintf(target_text + 128u, sizeof target_text - 128u, "@host");
    RFB_CHECK(!farsee_cli_target_parse(target_text, &target));
    RFB_CHECK(target.host[0] == '\0');

    target_text[0] = 'u';
    target_text[1] = ':';
    memset(target_text + 2, 'p', 256u);
    (void)snprintf(target_text + 258u, sizeof target_text - 258u, "@host");
    RFB_CHECK(!farsee_cli_target_parse(target_text, &target));
    RFB_CHECK(target.host[0] == '\0');

    memset(target_text, 'h', 256u);
    target_text[256] = '\0';
    RFB_CHECK(!farsee_cli_target_parse(target_text, &target));
    RFB_CHECK(target.host[0] == '\0');

    memset(target_text, 'u', 128u);
    target_text[128] = ':';
    (void)snprintf(target_text + 129u, sizeof target_text - 129u, "p@host");
    RFB_CHECK(!farsee_cli_target_parse(target_text, &target));
    RFB_CHECK(target.host[0] == '\0');

    memset(target_text, 'h', 256u);
    (void)snprintf(target_text + 256u, sizeof target_text - 256u, ":1");
    RFB_CHECK(!farsee_cli_target_parse(target_text, &target));
    RFB_CHECK(target.host[0] == '\0');
}

RFB_TEST(cli_target_edges, malformed_percent_encoded_userinfo__fails_closed)
{
    static const char *const rejected[] = {
        "vnc://%gg@host",
        "vnc://user:%gg@host",
    };
    for (size_t i = 0u; i < sizeof rejected / sizeof rejected[0]; i++) {
        farsee_cli_target target;
        memset(&target, 0xA5, sizeof target);
        RFB_CHECK(!farsee_cli_target_parse(rejected[i], &target));
        RFB_CHECK(target.host[0] == '\0');
        RFB_CHECK(!target.has_user);
        RFB_CHECK(!target.has_password);
    }
}

RFB_TEST(cli_target_edges, nonnumeric_port_suffix__remains_part_of_host)
{
    farsee_cli_target target;
    RFB_CHECK(farsee_cli_target_parse("host:service", &target));
    RFB_CHECK(strcmp(target.host, "host:service") == 0);
    RFB_CHECK_EQ_UINT(target.port, 0u);

    RFB_CHECK(farsee_cli_target_parse("host:", &target));
    RFB_CHECK(strcmp(target.host, "host:") == 0);
    RFB_CHECK_EQ_UINT(target.port, 0u);
}

RFB_TEST(cli_target_edges, leader__trims_and_accepts_control_spelling)
{
    farsee_cli_leader leader;
    farsee_cli_leader_default(NULL);

    RFB_CHECK(farsee_cli_leader_parse("  control-B\t", &leader));
    RFB_CHECK_EQ_UINT(leader.keysym, (uint32_t)'b');
    RFB_CHECK_EQ_UINT(leader.c0_byte, 0x02u);
    RFB_CHECK(strcmp(leader.display, "C-b") == 0);

    RFB_CHECK(farsee_cli_leader_parse("C-\\", &leader));
    RFB_CHECK_EQ_UINT(leader.c0_byte, 0x1Cu);
    RFB_CHECK(strcmp(leader.display, "C-\\\\") == 0);

    RFB_CHECK(farsee_cli_leader_parse("CTRL-B", &leader));
    RFB_CHECK_EQ_UINT(leader.c0_byte, 0x02u);
    RFB_CHECK(farsee_cli_leader_parse("CONTROL-B", &leader));
    RFB_CHECK_EQ_UINT(leader.c0_byte, 0x02u);
    RFB_CHECK(farsee_cli_leader_parse("c-B", &leader));
    RFB_CHECK_EQ_UINT(leader.keysym, (uint32_t)'b');
}

RFB_TEST(cli_target_edges, leader__maps_c0_punctuation_and_plain_symbols)
{
    struct leader_case {
        const char *text;
        uint8_t c0;
        bool has_c0;
    } cases[] = {
        {"C-@", 0x00u, true},
        {"C-[", 0x1Bu, true},
        {"C-^", 0x1Eu, true},
        {"C-_", 0x1Fu, true},
        {"C-7", 0x00u, false},
    };

    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        farsee_cli_leader leader;
        RFB_CHECK(farsee_cli_leader_parse(cases[i].text, &leader));
        RFB_CHECK_EQ_INT(leader.has_c0, cases[i].has_c0);
        RFB_CHECK_EQ_UINT(leader.c0_byte, cases[i].c0);
    }
}

RFB_TEST(cli_target_edges, leader__rejects_whitespace_meta_and_control_bytes)
{
    static const char *const rejected[] = {
        "   ",
        "Meta-x",
        "META-x",
        "meta-x",
        "mEtA-x",
        "Alt-x",
        "ALT-x",
        "control-ab",
        "C- ",
        "\x1f",
        "\x7f",
    };

    for (size_t i = 0u; i < sizeof rejected / sizeof rejected[0]; i++) {
        farsee_cli_leader leader;
        RFB_CHECK(!farsee_cli_leader_parse(rejected[i], &leader));
    }
}
