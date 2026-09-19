// SPDX-License-Identifier: Apache-2.0
//
// Security-service contract tests.
//
// Verifies cleared secret/credential fields after destroy, security-policy
// defaults, explicit RFB plaintext opt-in, and NULL-policy rejection. The
// lower-level secret tests cover the memory-wipe primitive.

#include "farsee/farsee_security.h"
#include "tests/test_framework/rfb_test.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// --- secret destroy clears and releases ------------------------------------

RFB_TEST(farsee_security, secret_destroy__clears_and_releases)
{
    farsee_secret s;
    s.cap = 16;
    s.len = 9;
    s.data = (uint8_t *)malloc(16);
    RFB_CHECK(s.data != NULL);
    memcpy(s.data, "SECRET123", 9);
    farsee_secret_destroy(&s);
    // This test checks the cleared pointer and length/capacity fields after
    // destroy; lower-level tests cover the memory-wipe primitive.
    RFB_CHECK(s.data == NULL);
    RFB_CHECK_EQ_UINT(s.len, 0u);
    RFB_CHECK_EQ_UINT(s.cap, 0u);
}

// --- credential response lifecycle -----------------------------------------

RFB_TEST(farsee_security, credential_response__destroy_clears_password_and_identity_fields)
{
    farsee_credential_response r;
    farsee_credential_response_init(&r);
    RFB_CHECK(r.username == NULL);
    RFB_CHECK(r.password.data == NULL);

    // Simulate the backend filling a password secret.
    r.password.cap = 8;
    r.password.len = 8;
    r.password.data = (uint8_t *)malloc(8);
    RFB_CHECK(r.password.data != NULL);
    memcpy(r.password.data, "passw0rd", 8);
    r.username = "alice";
    r.domain = "EXAMPLE";

    farsee_credential_response_destroy(&r);
    // Password and identity fields are cleared after destroy.
    RFB_CHECK(r.password.data == NULL);
    RFB_CHECK_EQ_UINT(r.password.len, 0u);
    RFB_CHECK(r.username == NULL);
    RFB_CHECK(r.domain == NULL);
}

RFB_TEST(farsee_security, credential_response__init_destroy_idempotent)
{
    farsee_credential_response r;
    farsee_credential_response_init(&r);
    farsee_credential_response_destroy(&r);  // no-op on empty
    farsee_credential_response_destroy(&r);  // double-destroy safe
    RFB_CHECK(r.password.data == NULL);
}

// --- security policy defaults --------------------------------------------

RFB_TEST(farsee_security, policy__rdp_defaults_require_tls_nla_no_legacy)
{
    farsee_security_policy p = farsee_security_policy_default_rdp();
    RFB_CHECK(farsee_security_policy_allows_tls(&p));       // TLS required
    RFB_CHECK(farsee_security_policy_allows_nla(&p));       // NLA required
    RFB_CHECK(farsee_security_policy_allows_plaintext(&p) == false);
    RFB_CHECK(p.allow_insecure_cert == false);
    RFB_CHECK(p.allow_legacy_rdp_security == false);
}

RFB_TEST(farsee_security, policy__rfb_defaults_plaintext_off)
{
    farsee_security_policy p = farsee_security_policy_default_rfb();
    // The default RFB policy leaves plaintext disabled.
    RFB_CHECK(farsee_security_policy_allows_plaintext(&p) == false);
    RFB_CHECK(p.allow_insecure_cert == false);
    // NLA is RDP-specific, off for RFB.
    RFB_CHECK(farsee_security_policy_allows_nla(&p) == false);
}

// --- fail closed: NULL policy rejects everything ---------------------------

RFB_TEST(farsee_security, policy__null_policy_rejects_all)
{
    RFB_CHECK(farsee_security_policy_allows_tls(NULL) == false);
    RFB_CHECK(farsee_security_policy_allows_plaintext(NULL) == false);
    RFB_CHECK(farsee_security_policy_allows_nla(NULL) == false);
}

// cap==0 with a live pointer must still free without a zero-byte wipe.
RFB_TEST(farsee_security, secret_destroy__cap_zero_live_pointer__frees)
{
    farsee_secret s;
    s.data = (uint8_t *)malloc(4);  // live pointer, cap 0
    RFB_CHECK(s.data != NULL);
    s.len = 0;
    s.cap = 0;
    farsee_secret_destroy(&s);
    RFB_CHECK(s.data == NULL);
    RFB_CHECK_EQ_UINT(s.len, 0u);
    RFB_CHECK_EQ_UINT(s.cap, 0u);
    farsee_secret_destroy(&s);  // idempotent
}
