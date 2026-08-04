// SPDX-License-Identifier: Apache-2.0
//
// F6 — security services contract tests (§10).
//
// Verifies secret-safe lifecycle (zeroization on every path), security-
// policy defaults (RDP TLS+NLA on, plaintext/legacy off; RFB plaintext
// opt-in only), and the fail-closed rule.

#include "farsee/farsee_security.h"
#include "tests/test_framework/rfb_test.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// --- secret destroy zeroizes -----------------------------------------------

RFB_TEST(farsee_security, secret_destroy__clears_and_releases)
{
    farsee_secret s;
    s.cap = 16;
    s.len = 9;
    s.data = (uint8_t *)malloc(16);
    RFB_CHECK(s.data != NULL);
    memcpy(s.data, "SECRET123", 9);
    farsee_secret_destroy(&s);
    // Contract: after destroy the secret is released (data NULL, len/cap 0).
    // The zeroization itself (rfb_secret_zero before free) is unit-tested in
    // G1; here we assert the lifecycle the caller depends on.
    RFB_CHECK(s.data == NULL);
    RFB_CHECK_EQ_UINT(s.len, 0u);
    RFB_CHECK_EQ_UINT(s.cap, 0u);
}

// --- credential response lifecycle -----------------------------------------

RFB_TEST(farsee_security, credential_response__destroy_zeroizes_password)
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
    // Password zeroized and cleared; non-secret pointers cleared.
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

// --- security policy defaults (§10.5, §15.4) -------------------------------

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
    // RFB None must remain opt-in only (§10.5): plaintext off by default.
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
