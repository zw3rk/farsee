// SPDX-License-Identifier: Apache-2.0
//
// wheel_notches(INT32_MIN) performs negation in int64_t to avoid signed
// overflow.

#include "rfb_test.h"
#include "rfb/rfb_session_math.h"

#include <stdint.h>

RFB_TEST(wheel_notches, int32_min__truncates_toward_zero_no_ub)
{
    // 2147483648 / 120 = 17895697 remainder 8 -> -17895697.
    RFB_CHECK_EQ_INT(rfb_session_wheel_notches(INT32_MIN), -17895697);
}

RFB_TEST(wheel_notches, boundaries__truncate_toward_zero)
{
    RFB_CHECK_EQ_INT(rfb_session_wheel_notches(0), 0);
    RFB_CHECK_EQ_INT(rfb_session_wheel_notches(119), 0);
    RFB_CHECK_EQ_INT(rfb_session_wheel_notches(120), 1);
    RFB_CHECK_EQ_INT(rfb_session_wheel_notches(-119), 0);
    RFB_CHECK_EQ_INT(rfb_session_wheel_notches(-120), -1);
    RFB_CHECK_EQ_INT(rfb_session_wheel_notches(-239), -1);
    RFB_CHECK_EQ_INT(rfb_session_wheel_notches(240), 2);
    // 120 * 17895697 = 2147483640 <= INT32_MAX < 120 * 17895698.
    RFB_CHECK_EQ_INT(rfb_session_wheel_notches(INT32_MAX), 17895697);
}
