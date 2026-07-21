// SPDX-License-Identifier: Apache-2.0
//
// G0 — build-system smoke test (plan.md §G0: "build-system smoke test
// that links a C11 library and executable").
//
// This test exercises that:
//   (a) a library symbol from src/app/version.c is reachable at link
//       time (the library is part of the link line);
//   (b) the symbol returns the documented value;
//   (c) C11/C99 constructs used elsewhere in the project compile
//       (designated initializers, // comments, stdint, stdbool) so a
//       silent regression of the -std=c11 flag would be caught.

#include "rfb_test.h"
#include "farsee/version.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

RFB_TEST(build, build__links_library_symbol__returns_version_string) {
    const char *v = farsee_version_string();
    RFB_CHECK(v != NULL);
    RFB_CHECK_MSG(strstr(v, "0.1") != NULL,
                  "version string should contain the major.minor prefix");
}

RFB_TEST(build, build__project_name__is_farsee) {
    RFB_CHECK_MSG(strcmp(farsee_project_name(), "farsee") == 0,
                  "project name must be 'farsee'");
}

// A C99 construct (retained in C11) that would fail under -std=c89
// (designated initializer for an array). If the -std=c11 flag regresses
// to c89, this fails to compile.
RFB_TEST(build, build__c11_designated_initializer__compiles) {
    static const int arr[3] = { [0] = 10, [2] = 30 };
    RFB_CHECK_EQ_INT(arr[0], 10);
    RFB_CHECK_EQ_INT(arr[1], 0);   // implicit zero-init is C99/C11
    RFB_CHECK_EQ_INT(arr[2], 30);
}

// C99/C11 `bool` from <stdbool.h> must be available.
RFB_TEST(build, build__stdbool_bool_type__compiles) {
    bool flag = (5 > 3);
    RFB_CHECK(flag);
}

// Exact-width integer types from <stdint.h>.
RFB_TEST(build, build__stdint_exact_width__compiles) {
    uint32_t u = 0x01020304UL;
    RFB_CHECK_EQ_UINT(u & 0xFFUL, 0x04UL);
}
