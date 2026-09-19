// SPDX-License-Identifier: Apache-2.0
//
// CLI target URL parser tests.

#include "rfb_test.h"
#include "farsee/cli_target.h"
#include "farsee/normalized_input.h"

#include <string.h>

RFB_TEST(cli_target, parse__bare_host)
{
    farsee_cli_target t;
    RFB_CHECK(farsee_cli_target_parse("example.com", &t));
    RFB_CHECK_EQ_INT(t.proto, FARSEE_CLI_PROTO_NONE);
    RFB_CHECK(strcmp(t.host, "example.com") == 0);
    RFB_CHECK_EQ_UINT(t.port, 0u);
    RFB_CHECK(!t.has_user);
    RFB_CHECK(!t.has_password);
}

RFB_TEST(cli_target, parse__host_port)
{
    farsee_cli_target t;
    RFB_CHECK(farsee_cli_target_parse("127.0.0.1:13390", &t));
    RFB_CHECK(strcmp(t.host, "127.0.0.1") == 0);
    RFB_CHECK_EQ_UINT(t.port, 13390u);
}

RFB_TEST(cli_target, parse__rdp_user_pass_host_port)
{
    farsee_cli_target t;
    RFB_CHECK(farsee_cli_target_parse(
        "rdp://TestAdmin:test-password@127.0.0.1:13390", &t));
    RFB_CHECK_EQ_INT(t.proto, FARSEE_CLI_PROTO_RDP);
    RFB_CHECK(strcmp(t.host, "127.0.0.1") == 0);
    RFB_CHECK_EQ_UINT(t.port, 13390u);
    RFB_CHECK(t.has_user);
    RFB_CHECK(t.has_password);
    RFB_CHECK(strcmp(t.user, "TestAdmin") == 0);
    RFB_CHECK(strcmp(t.password, "test-password") == 0);
}

RFB_TEST(cli_target, parse__vnc_user_at_host)
{
    farsee_cli_target t;
    RFB_CHECK(farsee_cli_target_parse("vnc://alice@host", &t));
    RFB_CHECK_EQ_INT(t.proto, FARSEE_CLI_PROTO_RFB);
    RFB_CHECK(strcmp(t.host, "host") == 0);
    RFB_CHECK(t.has_user);
    RFB_CHECK(!t.has_password);
    RFB_CHECK(strcmp(t.user, "alice") == 0);
}

RFB_TEST(cli_target, parse__password_with_colon)
{
    farsee_cli_target t;
    RFB_CHECK(farsee_cli_target_parse("rdp://u:p:w:d@h:1", &t));
    RFB_CHECK(strcmp(t.user, "u") == 0);
    RFB_CHECK(strcmp(t.password, "p:w:d") == 0);
    RFB_CHECK(strcmp(t.host, "h") == 0);
    RFB_CHECK_EQ_UINT(t.port, 1u);
}

RFB_TEST(cli_target, parse__percent_encoded_password)
{
    farsee_cli_target t;
    // password "a@b" as a%40b
    RFB_CHECK(farsee_cli_target_parse("rdp://u:a%40b@host:3389", &t));
    RFB_CHECK(strcmp(t.password, "a@b") == 0);
    RFB_CHECK(strcmp(t.host, "host") == 0);
    RFB_CHECK_EQ_UINT(t.port, 3389u);
}

RFB_TEST(cli_target, parse__negatives)
{
    farsee_cli_target t;
    RFB_CHECK(!farsee_cli_target_parse(NULL, &t));
    RFB_CHECK(!farsee_cli_target_parse("", &t));
    RFB_CHECK(!farsee_cli_target_parse("rdp://", &t));
    RFB_CHECK(!farsee_cli_target_parse("rdp://@host", &t));
    RFB_CHECK(!farsee_cli_target_parse("host:99999", &t));
    RFB_CHECK(!farsee_cli_target_parse("host", NULL));
}

RFB_TEST(cli_target, percent_decode__basic)
{
    char out[32];
    RFB_CHECK(farsee_cli_percent_decode("a%20b", out, sizeof out));
    RFB_CHECK(strcmp(out, "a b") == 0);
    RFB_CHECK(!farsee_cli_percent_decode("a%zz", out, sizeof out));
    RFB_CHECK(!farsee_cli_percent_decode("x", out, 1));  // no room for NUL
}

// ---------------------------------------------------------------------------
// Production URL-password policy (threat model: no secrets in argv/ps)
// Parser may still parse user:pass@host; production entry must refuse it.
// ---------------------------------------------------------------------------

RFB_TEST(cli_target, url_password_policy__rejects_has_password)
{
    farsee_cli_target t;
    RFB_CHECK(farsee_cli_target_parse(
        "rdp://alice:not-a-secret@127.0.0.1:13390", &t));
    RFB_CHECK(t.has_password);
    RFB_CHECK(!farsee_cli_url_password_allowed(&t));
    RFB_CHECK(farsee_cli_url_password_policy_error(&t) != NULL);
}

RFB_TEST(cli_target, url_password_policy__allows_user_without_password)
{
    farsee_cli_target t;
    RFB_CHECK(farsee_cli_target_parse("vnc://alice@host", &t));
    RFB_CHECK(t.has_user);
    RFB_CHECK(!t.has_password);
    RFB_CHECK(farsee_cli_url_password_allowed(&t));
    RFB_CHECK(farsee_cli_url_password_policy_error(&t) == NULL);
}

RFB_TEST(cli_target, url_password_policy__allows_host_only)
{
    farsee_cli_target t;
    RFB_CHECK(farsee_cli_target_parse("example.com:5900", &t));
    RFB_CHECK(!t.has_user);
    RFB_CHECK(!t.has_password);
    RFB_CHECK(farsee_cli_url_password_allowed(&t));
    RFB_CHECK(farsee_cli_url_password_policy_error(&t) == NULL);
}

RFB_TEST(cli_target, url_password_policy__null_target_allowed)
{
    // No target ⇒ no password field ⇒ allowed (defensive NULL handling).
    RFB_CHECK(farsee_cli_url_password_allowed(NULL));
    RFB_CHECK(farsee_cli_url_password_policy_error(NULL) == NULL);
}

RFB_TEST(cli_target, url_password_policy__error_message_mentions_password_fd)
{
    farsee_cli_target t;
    RFB_CHECK(farsee_cli_target_parse("vnc://u:secret@h", &t));
    const char *msg = farsee_cli_url_password_policy_error(&t);
    RFB_CHECK(msg != NULL);
    // Direct operator toward safe credential paths.
    RFB_CHECK(strstr(msg, "--password-fd") != NULL);
}

// ---------------------------------------------------------------------------
// Leader parse (tmux-style C-x / ctrl-x / bare x)
// ---------------------------------------------------------------------------

RFB_TEST(cli_leader, leader_default__is_ctrl_bracket)
{
    farsee_cli_leader L;
    farsee_cli_leader_default(&L);
    RFB_CHECK_EQ_UINT(L.keysym, (uint32_t)']');
    RFB_CHECK_EQ_UINT(L.mods, RFB_MOD_CONTROL);
    RFB_CHECK(L.has_c0);
    RFB_CHECK_EQ_UINT(L.c0_byte, 0x1Du);
    RFB_CHECK(strcmp(L.display, "C-]") == 0);
}

RFB_TEST(cli_leader, leader_parse__emacs_and_ctrl_forms)
{
    farsee_cli_leader L;
    RFB_CHECK(farsee_cli_leader_parse("C-]", &L));
    RFB_CHECK_EQ_UINT(L.keysym, (uint32_t)']');
    RFB_CHECK(L.has_c0 && L.c0_byte == 0x1Du);
    RFB_CHECK(strcmp(L.display, "C-]") == 0);

    RFB_CHECK(farsee_cli_leader_parse("ctrl-b", &L));
    RFB_CHECK_EQ_UINT(L.keysym, (uint32_t)'b');
    RFB_CHECK(L.has_c0 && L.c0_byte == 0x02u);
    RFB_CHECK(strcmp(L.display, "C-b") == 0);

    RFB_CHECK(farsee_cli_leader_parse("C-B", &L));  // case-fold
    RFB_CHECK_EQ_UINT(L.keysym, (uint32_t)'b');

    RFB_CHECK(farsee_cli_leader_parse("b", &L));  // bare ⇒ Control
    RFB_CHECK_EQ_UINT(L.keysym, (uint32_t)'b');
    RFB_CHECK_EQ_UINT(L.mods, RFB_MOD_CONTROL);
}

RFB_TEST(cli_leader, leader_parse__negatives)
{
    farsee_cli_leader L;
    RFB_CHECK(!farsee_cli_leader_parse(NULL, &L));
    RFB_CHECK(!farsee_cli_leader_parse("", &L));
    RFB_CHECK(!farsee_cli_leader_parse("C-", &L));
    RFB_CHECK(!farsee_cli_leader_parse("C-ab", &L));
    RFB_CHECK(!farsee_cli_leader_parse("M-x", &L));   // meta not supported
    RFB_CHECK(!farsee_cli_leader_parse("alt-x", &L));
    RFB_CHECK(!farsee_cli_leader_parse("C-]", NULL));
}

RFB_TEST(cli_leader, leader_matches__configured_chord)
{
    farsee_cli_leader L;
    RFB_CHECK(farsee_cli_leader_parse("C-b", &L));
    rfb_norm_key k;
    memset(&k, 0, sizeof(k));
    k.down = true;
    k.keysym = (uint32_t)'b';
    k.modifiers = RFB_MOD_CONTROL;
    RFB_CHECK(rfb_norm_key_matches_leader(&k, L.keysym, L.mods));
    RFB_CHECK(rfb_byte_matches_leader(0x02u, L.c0_byte, L.has_c0));
    RFB_CHECK(!rfb_byte_matches_leader(0x1Du, L.c0_byte, L.has_c0));
    RFB_CHECK_EQ_INT(rfb_leader_cmd_from_key(&k, L.keysym, L.mods),
                     RFB_LEADER_CMD_PASS);
}
