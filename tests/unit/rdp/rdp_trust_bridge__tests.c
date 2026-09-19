// SPDX-License-Identifier: Apache-2.0
//
// R2 — RDP trust + credential bridge tests (§15.7, §10.3, §10.4).
//
// Deterministic: the trust classification, evaluation, and credential gate
// are pure functions. The independent-endpoint callback path is the
// PASS_INTEROP gate (NEEDS_HARDWARE).

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_trust_bridge.h"
#include "tests/test_framework/rfb_test.h"
#include <string.h>

// --- trust request building (sanitized, no raw cert blob) -------------------

RFB_TEST(rdp_trust, build_request__sanitized_no_secrets)
{
    farsee_trust_request r;
    rdp_trust_build_request(&r, "ABCD1234", "win.example:3389",
                            "CN=win.example", true, RDP_TRUST_FIRST_USE);
    RFB_CHECK(r.identity_type == FARSEE_IDENTITY_X509_CERTIFICATE_CHAIN);
    RFB_CHECK(strcmp(r.fingerprint, "ABCD1234") == 0);
    RFB_CHECK(strcmp(r.host, "win.example:3389") == 0);
    RFB_CHECK(strcmp(r.subject_name, "CN=win.example") == 0);
    RFB_CHECK(r.ca_hostname_ok);
    RFB_CHECK(r.first_use);
}

RFB_TEST(rdp_trust, build_request__long_strings_truncated_not_overflowed)
{
    farsee_trust_request r;
    // A fingerprint far longer than the buffer must be truncated safely.
    rdp_trust_build_request(&r,
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "h", "s", false, RDP_TRUST_FIRST_USE);
    // The buffer is 64 bytes; the string must be NUL-terminated within it.
    RFB_CHECK(r.fingerprint[sizeof(r.fingerprint) - 1] == '\0');
}

// --- trust evaluation (§15.7) ----------------------------------------------

RFB_TEST(rdp_trust, evaluate__changed_defaults_reject)
{
    RFB_CHECK(rdp_trust_evaluate_classified(RDP_TRUST_CHANGED, true) ==
              FARSEE_TRUST_DECISION_REJECT);
    RFB_CHECK(rdp_trust_evaluate_classified(RDP_TRUST_CHANGED, false) ==
              FARSEE_TRUST_DECISION_REJECT);
}

RFB_TEST(rdp_trust, evaluate__first_use_ca_ok_approves_self_signed_rejects)
{
    // CA-valid first use -> approve once.
    RFB_CHECK(rdp_trust_evaluate_classified(RDP_TRUST_FIRST_USE, true) ==
              FARSEE_TRUST_DECISION_APPROVE_ONCE);
    // Self-signed first use (CA/hostname failed) -> reject; requires
    // explicit user approval, never auto-approved (§15.7).
    RFB_CHECK(rdp_trust_evaluate_classified(RDP_TRUST_FIRST_USE, false) ==
              FARSEE_TRUST_DECISION_REJECT);
}

RFB_TEST(rdp_trust, evaluate__unchanged_approves_once)
{
    RFB_CHECK(rdp_trust_evaluate_classified(RDP_TRUST_UNCHANGED, true) ==
              FARSEE_TRUST_DECISION_APPROVE_ONCE);
    RFB_CHECK(rdp_trust_evaluate_classified(RDP_TRUST_UNCHANGED, false) ==
              FARSEE_TRUST_DECISION_APPROVE_ONCE);
}

RFB_TEST(rdp_trust, evaluate__null_request_rejects)
{
    RFB_CHECK(rdp_trust_evaluate(NULL) == FARSEE_TRUST_DECISION_REJECT);
}

// --- credential gate (§10.4: no creds to a rejected peer) -------------------

RFB_TEST(rdp_trust, allows_credentials__only_on_approval)
{
    RFB_CHECK(rdp_trust_allows_credentials(FARSEE_TRUST_DECISION_APPROVE_ONCE));
    RFB_CHECK(rdp_trust_allows_credentials(FARSEE_TRUST_DECISION_APPROVE_PERMANENT));
    RFB_CHECK(rdp_trust_allows_credentials(FARSEE_TRUST_DECISION_REJECT) == false);
}

// The FreeRDP callback return is session-only (2),
// never permanent store (1), for every allow path.
RFB_TEST(rdp_trust, verify_x509_return__approve_once_is_session_only)
{
    RFB_CHECK_EQ_INT(rdp_verify_x509_freerdp_return(FARSEE_TRUST_DECISION_APPROVE_ONCE),
                     2);
    RFB_CHECK_EQ_INT(
        rdp_verify_x509_freerdp_return(FARSEE_TRUST_DECISION_APPROVE_PERMANENT),
        2);
    RFB_CHECK_EQ_INT(rdp_verify_x509_freerdp_return(FARSEE_TRUST_DECISION_REJECT),
                     0);
}

RFB_TEST(rdp_credential, may_apply__rejected_trust_blocks_credentials)
{
    farsee_security_policy p = farsee_security_policy_default_rdp();
    farsee_credential_response resp;
    farsee_credential_response_init(&resp);
    // Even with a password present, a rejected peer gets no credentials.
    RFB_CHECK(rdp_credential_may_apply(FARSEE_TRUST_DECISION_REJECT, &p, &resp) == false);
}

RFB_TEST(rdp_credential, may_apply__nla_requires_password)
{
    farsee_security_policy p = farsee_security_policy_default_rdp();
    farsee_credential_response resp;
    farsee_credential_response_init(&resp);
    // Approved trust but empty password under NLA -> rejected (§15.4).
    RFB_CHECK(rdp_credential_may_apply(FARSEE_TRUST_DECISION_APPROVE_ONCE, &p, &resp) == false);
}

RFB_TEST(rdp_credential, may_apply__approved_with_password_succeeds)
{
    farsee_security_policy p = farsee_security_policy_default_rdp();
    farsee_credential_response resp;
    farsee_credential_response_init(&resp);
    // Simulate a filled password secret (writable test buffer).
    static uint8_t pw[] = {'s','e','c','r','e','t'};
    resp.password.data = pw;
    resp.password.len = 6;
    resp.password.cap = 6;
    RFB_CHECK(rdp_credential_may_apply(FARSEE_TRUST_DECISION_APPROVE_ONCE, &p, &resp));
    // Do NOT call destroy (we didn't allocate the password).
    resp.password.data = NULL;
    resp.password.len = 0;
    resp.password.cap = 0;
}

// --- Product decision path (reject versus --cert ignore) -----------------

RFB_TEST(rdp_trust, decide__first_use_self_signed_rejects_by_default)
{
    // Default policy: self-signed first use (ca_hostname_ok=false) rejects.
    RFB_CHECK(rdp_trust_decide(RDP_TRUST_FIRST_USE, false, false) ==
              FARSEE_TRUST_DECISION_REJECT);
}

RFB_TEST(rdp_trust, decide__allow_insecure_approves_self_signed)
{
    // --cert ignore: approve even without CA/hostname and even CHANGED.
    RFB_CHECK(rdp_trust_decide(RDP_TRUST_FIRST_USE, false, true) ==
              FARSEE_TRUST_DECISION_APPROVE_ONCE);
    RFB_CHECK(rdp_trust_decide(RDP_TRUST_CHANGED, false, true) ==
              FARSEE_TRUST_DECISION_APPROVE_ONCE);
}

RFB_TEST(rdp_trust, decide__changed_rejects_without_ignore)
{
    RFB_CHECK(rdp_trust_decide(RDP_TRUST_CHANGED, true, false) ==
              FARSEE_TRUST_DECISION_REJECT);
    RFB_CHECK(rdp_trust_decide(RDP_TRUST_CHANGED, false, false) ==
              FARSEE_TRUST_DECISION_REJECT);
}

RFB_TEST(rdp_trust, flags__verify_x509_never_ca_hostname_ok)
{
    // FreeRDP only calls VerifyX509Certificate for untrusted peers.
    // flags==0 is first-use self-signed / unknown CA — NOT ca_hostname_ok.
    RFB_CHECK(rdp_trust_ca_hostname_ok_from_flags(0u) == false);
    RFB_CHECK(rdp_trust_ca_hostname_ok_from_flags(
                  RDP_VERIFY_CERT_FLAG_MISMATCH) == false);
    RFB_CHECK(rdp_trust_ca_hostname_ok_from_flags(
                  RDP_VERIFY_CERT_FLAG_CHANGED) == false);
    RFB_CHECK(rdp_trust_classify_from_flags(0u) == RDP_TRUST_FIRST_USE);
    RFB_CHECK(rdp_trust_classify_from_flags(RDP_VERIFY_CERT_FLAG_CHANGED) ==
              RDP_TRUST_CHANGED);
    // Hostname MISMATCH is classified CHANGED (not first-use).
    RFB_CHECK(rdp_trust_classify_from_flags(RDP_VERIFY_CERT_FLAG_MISMATCH) ==
              RDP_TRUST_CHANGED);

    // Product path: flags==0 (VERIFY_CERT_FLAG_NONE) without --cert ignore
    // must REJECT — this is the FreeRDP untrusted-first-use call pattern.
    RFB_CHECK(rdp_trust_decide(
                  rdp_trust_classify_from_flags(0u),
                  rdp_trust_ca_hostname_ok_from_flags(0u),
                  false) == FARSEE_TRUST_DECISION_REJECT);

    // Product path: MISMATCH without ignore -> REJECT.
    RFB_CHECK(rdp_trust_decide(
                  rdp_trust_classify_from_flags(RDP_VERIFY_CERT_FLAG_MISMATCH),
                  rdp_trust_ca_hostname_ok_from_flags(
                      RDP_VERIFY_CERT_FLAG_MISMATCH),
                  false) == FARSEE_TRUST_DECISION_REJECT);

    // --cert ignore still approves flags==0 untrusted first use.
    RFB_CHECK(rdp_trust_decide(
                  rdp_trust_classify_from_flags(0u),
                  rdp_trust_ca_hostname_ok_from_flags(0u),
                  true) == FARSEE_TRUST_DECISION_APPROVE_ONCE);
}

// Simulate the FreeRDP VerifyX509 product decision path (fingerprint TOFU
// classification + decide) without a live peer.
RFB_TEST(rdp_trust, product_path__flags_zero_without_ignore__rejects)
{
    // Mirrors rdp_cb_verify_x509 when FreeRDP passes flags=0 for an unknown
    // self-signed cert and no known_hosts match exists.
    const uint32_t flags = 0u; // VERIFY_CERT_FLAG_NONE
    const bool ca_ok = rdp_trust_ca_hostname_ok_from_flags(flags);
    const rdp_trust_classification c = rdp_trust_classify_from_flags(flags);
    RFB_CHECK(ca_ok == false);
    RFB_CHECK(c == RDP_TRUST_FIRST_USE);
    RFB_CHECK(rdp_trust_decide(c, ca_ok, /*allow_insecure=*/false) ==
              FARSEE_TRUST_DECISION_REJECT);
    RFB_CHECK(rdp_trust_allows_credentials(FARSEE_TRUST_DECISION_REJECT) ==
              false);
}

RFB_TEST(rdp_trust, product_path__known_hosts_match__approves_unchanged)
{
    // TOFU match maps to UNCHANGED → APPROVE_ONCE even without CA.
    RFB_CHECK(rdp_trust_decide(RDP_TRUST_UNCHANGED, false, false) ==
              FARSEE_TRUST_DECISION_APPROVE_ONCE);
    RFB_CHECK(rdp_trust_allows_credentials(FARSEE_TRUST_DECISION_APPROVE_ONCE));
}

#endif  // FARSEE_WITH_RDP
