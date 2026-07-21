// SPDX-License-Identifier: Apache-2.0
//
// farsee version string implementation. Linked into the library and
// the CLI so `--version` and the protocol-capabilities output share one
// source of truth.

#include "farsee/version.h"

const char *farsee_version_string(void)
{
    return FARSEE_VERSION_STRING;
}

const char *farsee_project_name(void)
{
    return "farsee";
}
