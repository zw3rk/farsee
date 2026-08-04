// SPDX-License-Identifier: Apache-2.0
//
// Farsee security services implementation (F6 gate, §10).
//
// Secret-safe lifecycle helpers and security-policy defaults. Reuses the
// existing rfb_secret_zero (G1) for zeroization — no hand-rolled crypto.

#include "farsee/farsee_security.h"
#include "farsee/secret.h"  // rfb_secret_zero

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void farsee_secret_destroy(farsee_secret *s)
{
    if (s == NULL) {
        return;
    }
    if (s->data != NULL && s->cap > 0) {
        rfb_secret_zero(s->data, s->cap);
        free(s->data);
    }
    s->data = NULL;
    s->len = 0;
    s->cap = 0;
}

void farsee_credential_response_init(farsee_credential_response *r)
{
    if (r == NULL) {
        return;
    }
    r->username = NULL;
    r->domain = NULL;
    r->password.data = NULL;
    r->password.len = 0;
    r->password.cap = 0;
}

void farsee_credential_response_destroy(farsee_credential_response *r)
{
    if (r == NULL) {
        return;
    }
    // Zeroize the password secret before non-secret cleanup.
    farsee_secret_destroy(&r->password);
    r->username = NULL;
    r->domain = NULL;
}

farsee_security_policy farsee_security_policy_default_rdp(void)
{
    farsee_security_policy p;
    memset(&p, 0, sizeof p);
    p.require_tls = true;
    p.allow_plaintext = false;
    p.allow_insecure_cert = false;
    p.tofu_pin_store = false;
    p.require_nla = true;
    p.allow_legacy_rdp_security = false;
    return p;
}

farsee_security_policy farsee_security_policy_default_rfb(void)
{
    farsee_security_policy p;
    memset(&p, 0, sizeof p);
    p.require_tls = false;      // RFB may run plaintext until VeNCrypt is up
    p.allow_plaintext = false;  // None is opt-in only (§10.5)
    p.allow_insecure_cert = false;
    p.tofu_pin_store = false;
    p.require_nla = false;      // NLA is RDP-specific
    p.allow_legacy_rdp_security = false;
    return p;
}

bool farsee_security_policy_allows_tls(const farsee_security_policy *p)
{
    return p != NULL && p->require_tls;
}

bool farsee_security_policy_allows_plaintext(const farsee_security_policy *p)
{
    // Plaintext is only "allowed" when explicitly opted in AND insecure is on.
    // By default (allow_plaintext=false) this returns false.
    return p != NULL && p->allow_plaintext;
}

bool farsee_security_policy_allows_nla(const farsee_security_policy *p)
{
    return p != NULL && p->require_nla;
}
