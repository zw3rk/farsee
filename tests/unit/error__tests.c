// SPDX-License-Identifier: Apache-2.0
//
// Typed error-code stability tests.

#include "rfb_test.h"
#include "farsee/error.h"

RFB_TEST(error, error__ok_is_zero__and_not_failed) {
    RFB_CHECK_EQ_INT(RFB_OK, 0);
    RFB_CHECK(!rfb_failed(RFB_OK));
}

RFB_TEST(error, error__every_failure_code__is_failed) {
    RFB_CHECK(rfb_failed(RFB_ERR_NOMEM));
    RFB_CHECK(rfb_failed(RFB_ERR_OVERFLOW));
    RFB_CHECK(rfb_failed(RFB_ERR_LIMIT));
    RFB_CHECK(rfb_failed(RFB_ERR_EOF));
    RFB_CHECK(rfb_failed(RFB_ERR_IO));
    RFB_CHECK(rfb_failed(RFB_ERR_PROTOCOL));
    RFB_CHECK(rfb_failed(RFB_ERR_STATE));
    RFB_CHECK(rfb_failed(RFB_ERR_UNSUPPORTED));
    RFB_CHECK(rfb_failed(RFB_ERR_AUTH));
    RFB_CHECK(rfb_failed(RFB_ERR_CANCELLED));
    RFB_CHECK(rfb_failed(RFB_ERR_TIMEOUT));
    RFB_CHECK(rfb_failed(RFB_ERR_INTERNAL));
}

RFB_TEST(error, error__strerror__returns_nonnull_for_every_code) {
    for (int i = 0; i <= 12; i++) {
        RFB_CHECK(rfb_strerror((rfb_error)i) != NULL);
    }
}

RFB_TEST(error, error__strerror__ok_says_ok) {
    const char *s = rfb_strerror(RFB_OK);
    RFB_CHECK(s != NULL);
    // Non-empty, static literal.
    RFB_CHECK(s[0] != '\0');
}
