// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple dialect and authentication state-machine framework.

#include "farsee/apple_auth.h"
#include "farsee/handshake.h"

#include <string.h>

// --- Dialect detection ---------------------------------------------------

bool apple_is_dialect_003_889(const uint8_t *banner, size_t len)
{
    if (banner == NULL || len < 12) return false;
    // Apple uses RFB 003.889\n (12 bytes).
    static const uint8_t apple_banner[12] = {
        'R','F','B',' ','0','0','3','.','8','8','9','\n'
    };
    return memcmp(banner, apple_banner, 12) == 0;
}

// --- Security type selection policy --------------------------------------

int apple_select_security_type(const uint8_t *offered, size_t count,
                               bool allow_legacy)
{
    // Single pure policy: farsee_rfb_select_security. This Apple-only helper
    // admits types 36 and 35 for selection tests and fuzzing. The live connect
    // policy supports type 36. Generic product defaults keep types 36 and 35
    // disabled until the Apple path supplies its explicit policy.
    farsee_rfb_security_policy pol = farsee_rfb_security_policy_default();
    pol.auth_mode = FARSEE_AUTH_MODE_APPLE;
    pol.allow_type_33 = true;
    pol.allow_type_36 = true;
    pol.allow_type_35 = true;
    pol.allow_legacy_apple = allow_legacy;
    pol.allow_vnc = false;
    pol.allow_none = false;
    uint8_t selected = 0;
    if (farsee_rfb_select_security(offered, count, &pol, &selected) != RFB_OK) {
        return 0;
    }
    return (int)selected;
}
