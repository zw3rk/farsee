// SPDX-License-Identifier: Apache-2.0
//
// farsee — project version and name accessors.
//
// Both functions return compile-time string literals.

#include "farsee/version.h"

const char *farsee_version_string(void)
{
    return FARSEE_VERSION_STRING;
}

const char *farsee_project_name(void)
{
    return "farsee";
}
