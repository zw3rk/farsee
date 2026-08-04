// SPDX-License-Identifier: Apache-2.0
//
// farsee — pure RFB security-type selection for --auth auto|vnc|apple.
//
// Derives a single chosen type from the server's offered list and a
// product policy. No I/O, no session state, no crypto. Rank among
// eligible types: 33 > 36 > 35 > 30 > 2 > 1
//
// Eligibility is mode-gated:
//   AUTO  — classic + Apple candidates (subject to allow_* flags)
//   VNC   — classic only (2, and 1 with allow_none)
//   APPLE — Apple only (33/36/35/30)

#include "farsee/handshake.h"

#include <stddef.h>
#include <stdint.h>

// Known security-type codes we may select.
#define SEC_NONE  1u
#define SEC_VNC   2u
#define SEC_30    30u
#define SEC_33    33u
#define SEC_35    35u
#define SEC_36    36u

farsee_rfb_security_policy farsee_rfb_security_policy_default(void)
{
    farsee_rfb_security_policy p;
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    p.allow_none = false;
    p.allow_legacy_apple = false;
    p.allow_type_33 = true;
    p.allow_type_36 = false;
    p.allow_type_35 = false;
    p.allow_vnc = true;
    return p;
}

rfb_error farsee_rfb_select_security(const uint8_t *offered, size_t count,
                                     const farsee_rfb_security_policy *policy,
                                     uint8_t *out_type)
{
    if (out_type == NULL) {
        return RFB_ERR_INTERNAL;
    }
    *out_type = 0;

    if (offered == NULL || count == 0) {
        return RFB_ERR_UNSUPPORTED;
    }

    farsee_rfb_security_policy pol =
        (policy != NULL) ? *policy : farsee_rfb_security_policy_default();

    // Presence of each candidate type in the offered list.
    bool have_1 = false;
    bool have_2 = false;
    bool have_30 = false;
    bool have_33 = false;
    bool have_35 = false;
    bool have_36 = false;
    for (size_t i = 0; i < count; i++) {
        switch (offered[i]) {
        case SEC_NONE: have_1 = true; break;
        case SEC_VNC:  have_2 = true; break;
        case SEC_30:   have_30 = true; break;
        case SEC_33:   have_33 = true; break;
        case SEC_35:   have_35 = true; break;
        case SEC_36:   have_36 = true; break;
        default: break;
        }
    }

    const bool want_classic =
        (pol.auth_mode == FARSEE_AUTH_MODE_AUTO ||
         pol.auth_mode == FARSEE_AUTH_MODE_VNC);
    const bool want_apple =
        (pol.auth_mode == FARSEE_AUTH_MODE_AUTO ||
         pol.auth_mode == FARSEE_AUTH_MODE_APPLE);

    // Eligible candidates (must also be present in offered).
    const bool elig_33 = want_apple && pol.allow_type_33 && have_33;
    const bool elig_36 = want_apple && pol.allow_type_36 && have_36;
    const bool elig_35 = want_apple && pol.allow_type_35 && have_35;
    const bool elig_30 = want_apple && pol.allow_legacy_apple && have_30;
    const bool elig_2  = want_classic && pol.allow_vnc && have_2;
    const bool elig_1  = want_classic && pol.allow_none && have_1;

    // Rank: 33 > 36 > 35 > 30 > 2 > 1
    if (elig_33) {
        *out_type = SEC_33;
        return RFB_OK;
    }
    if (elig_36) {
        *out_type = SEC_36;
        return RFB_OK;
    }
    if (elig_35) {
        *out_type = SEC_35;
        return RFB_OK;
    }
    if (elig_30) {
        *out_type = SEC_30;
        return RFB_OK;
    }
    if (elig_2) {
        *out_type = SEC_VNC;
        return RFB_OK;
    }
    if (elig_1) {
        *out_type = SEC_NONE;
        return RFB_OK;
    }

    return RFB_ERR_UNSUPPORTED;
}
