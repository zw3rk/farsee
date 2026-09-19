// SPDX-License-Identifier: Apache-2.0
//
// Pure connect-path selection: --auth=vnc never forces type 33
// solely because the peer banner is RFB 003.889.

#include "rfb_test.h"
#include "farsee/rfb_session.h"
#include "farsee/handshake.h"

RFB_TEST(session_path, prefer_apple__auto_with_banner__true)
{
    RFB_CHECK(rfb_session_prefer_apple_path(true, FARSEE_AUTH_MODE_AUTO));
}

RFB_TEST(session_path, prefer_apple__auto_without_banner__false)
{
    RFB_CHECK(!rfb_session_prefer_apple_path(false, FARSEE_AUTH_MODE_AUTO));
}

// − Apple banner + VNC mode → classic (not type-33)
RFB_TEST(session_path, prefer_apple__vnc_mode_with_apple_banner__false)
{
    RFB_CHECK(!rfb_session_prefer_apple_path(true, FARSEE_AUTH_MODE_VNC));
    RFB_CHECK(!rfb_session_prefer_apple_path(false, FARSEE_AUTH_MODE_VNC));
}

// + explicit APPLE mode always type-33 path
RFB_TEST(session_path, prefer_apple__apple_mode__always_true)
{
    RFB_CHECK(rfb_session_prefer_apple_path(true, FARSEE_AUTH_MODE_APPLE));
    RFB_CHECK(rfb_session_prefer_apple_path(false, FARSEE_AUTH_MODE_APPLE));
}

// Cross-check: security selector under VNC mode still picks type 2 when
// both 2 and 33 are offered (banner policy is independent of list policy).
RFB_TEST(session_path, security_select__vnc_mode_offered_2_and_33__selects_2)
{
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_VNC;
    static const uint8_t offered[] = { 2, 33 };
    uint8_t got = 0;
    RFB_CHECK_EQ_INT(farsee_rfb_select_security(offered, 2, &p, &got), RFB_OK);
    RFB_CHECK_EQ_UINT(got, 2u);
}

RFB_TEST(session_path, security_select__auto_offered_2_and_33__selects_33)
{
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    static const uint8_t offered[] = { 2, 33 };
    uint8_t got = 0;
    RFB_CHECK_EQ_INT(farsee_rfb_select_security(offered, 2, &p, &got), RFB_OK);
    RFB_CHECK_EQ_UINT(got, 33u);
}
