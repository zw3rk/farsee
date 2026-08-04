// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP trust + credential bridge implementation (R2 gate).

#include "rdp_trust_bridge.h"

#include <stddef.h>
#include <string.h>

static void copy_bounded(char *dst, size_t cap, const char *src)
{
    if (dst == NULL || cap == 0) {
        return;
    }
    dst[0] = '\0';
    if (src == NULL) {
        return;
    }
    size_t n = strlen(src);
    if (n >= cap) {
        n = cap - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void rdp_trust_build_request(farsee_trust_request *out,
                             const char *fingerprint_hex,
                             const char *host,
                             const char *subject,
                             bool ca_hostname_ok,
                             rdp_trust_classification classification)
{
    if (out == NULL) {
        return;
    }
    // Zero the request first so every field is well-defined.
    memset(out, 0, sizeof(*out));
    out->identity_type = FARSEE_IDENTITY_X509_CERTIFICATE_CHAIN;
    copy_bounded(out->fingerprint, sizeof(out->fingerprint), fingerprint_hex);
    copy_bounded(out->host, sizeof(out->host), host);
    copy_bounded(out->subject_name, sizeof(out->subject_name), subject);
    out->ca_hostname_ok = ca_hostname_ok;
    out->first_use = (classification == RDP_TRUST_FIRST_USE);
}

farsee_trust_decision rdp_trust_evaluate(const farsee_trust_request *req)
{
    if (req == NULL) {
        return FARSEE_TRUST_DECISION_REJECT;  // fail closed
    }
    // §15.7: a changed certificate defaults to rejection.
    // first_use==false && the caller classified it CHANGED => reject.
    // We cannot see "changed" directly from the request struct (it only has
    // first_use), so the bridge passes classification explicitly via the
    // caller; here we encode: not-first-use is UNCHANGED unless the caller
    // already routed CHANGED to a reject upstream. For a clean contract,
    // treat not-first-use as already-trusted (UNCHANGED -> approve once).
    if (req->first_use) {
        // First use: only auto-approve if CA + hostname validation passed.
        // A self-signed first use requires explicit user approval.
        return req->ca_hostname_ok ? FARSEE_TRUST_DECISION_APPROVE_ONCE
                                   : FARSEE_TRUST_DECISION_REJECT;
    }
    // Unchanged (previously approved) -> proceed for this session.
    return FARSEE_TRUST_DECISION_APPROVE_ONCE;
}

// Variant that takes the explicit classification (used by the live callback
// path which knows whether the cert differs from the stored record).
farsee_trust_decision rdp_trust_evaluate_classified(
    rdp_trust_classification c, bool ca_hostname_ok)
{
    switch (c) {
    case RDP_TRUST_CHANGED:
        return FARSEE_TRUST_DECISION_REJECT;  // §15.7 default
    case RDP_TRUST_UNCHANGED:
        return FARSEE_TRUST_DECISION_APPROVE_ONCE;
    case RDP_TRUST_FIRST_USE:
        return ca_hostname_ok ? FARSEE_TRUST_DECISION_APPROVE_ONCE
                              : FARSEE_TRUST_DECISION_REJECT;
    }
    return FARSEE_TRUST_DECISION_REJECT;
}

bool rdp_trust_ca_hostname_ok_from_flags(uint32_t freerdp_flags)
{
    // FreeRDP only calls VerifyX509Certificate when the cert is not already
    // trusted by the TLS stack / system store. flags==0 is the common
    // first-use untrusted case (self-signed, unknown CA) — that is NOT
    // ca_hostname_ok. CHANGED/MISMATCH are also not OK. Never auto-approve
    // solely because no error bits are set.
    (void)freerdp_flags;
    return false;
}

rdp_trust_classification rdp_trust_classify_from_flags(uint32_t freerdp_flags)
{
    // FreeRDP sets MISMATCH for hostname mismatch; treat like CHANGED so
    // diagnostics and future CA-ok paths do not label MITM as "first use".
    if ((freerdp_flags & (RDP_VERIFY_CERT_FLAG_CHANGED |
                          RDP_VERIFY_CERT_FLAG_MISMATCH)) != 0u) {
        return RDP_TRUST_CHANGED;
    }
    return RDP_TRUST_FIRST_USE;
}

farsee_trust_decision rdp_trust_decide(rdp_trust_classification c,
                                       bool ca_hostname_ok,
                                       bool allow_insecure_cert)
{
    // Backward-compatible wrapper: no pin-store flag.
    return rdp_trust_decide_ex(c, ca_hostname_ok, allow_insecure_cert,
                               /*tofu_pin_store=*/false);
}

farsee_trust_decision rdp_trust_decide_ex(rdp_trust_classification c,
                                          bool ca_hostname_ok,
                                          bool allow_insecure_cert,
                                          bool tofu_pin_store)
{
    // CHANGED: only --cert ignore (session-only) may approve; never pin-store.
    if (c == RDP_TRUST_CHANGED && !allow_insecure_cert) {
        return FARSEE_TRUST_DECISION_REJECT;
    }
    if (c == RDP_TRUST_CHANGED && allow_insecure_cert) {
        return FARSEE_TRUST_DECISION_APPROVE_ONCE;
    }
    // FIRST_USE / other: ignore or pin both approve once; pin stores later.
    if (allow_insecure_cert || tofu_pin_store) {
        return FARSEE_TRUST_DECISION_APPROVE_ONCE;
    }
    return rdp_trust_evaluate_classified(c, ca_hostname_ok);
}

bool rdp_trust_allows_credentials(farsee_trust_decision d)
{
    // §10.4: never send credentials to a rejected peer.
    return d == FARSEE_TRUST_DECISION_APPROVE_ONCE ||
           d == FARSEE_TRUST_DECISION_APPROVE_PERMANENT;
}

int rdp_verify_x509_freerdp_return(farsee_trust_decision d)
{
    // FreeRDP: 0 reject, 1 accept+store, 2 accept session-only.
    // Always session-only for allow so FreeRDP's store cannot outrank TOFU.
    if (rdp_trust_allows_credentials(d)) {
        return 2;
    }
    return 0;
}

bool rdp_credential_may_apply(farsee_trust_decision trust,
                              const farsee_security_policy *policy,
                              const farsee_credential_response *resp)
{
    // §10.4 gate first.
    if (!rdp_trust_allows_credentials(trust)) {
        return false;
    }
    if (policy == NULL || resp == NULL) {
        return false;
    }
    // NLA/CredSSP requires a password (§15.4). An empty secret under NLA
    // is rejected — credentials MUST NOT be delegated without the secret.
    if (policy->require_nla) {
        if (resp->password.data == NULL || resp->password.len == 0) {
            return false;
        }
    }
    // Legacy RDP security is never allowed by default (§15.4).
    if (policy->allow_legacy_rdp_security == false &&
        policy->require_tls == false) {
        return false;
    }
    return true;
}
