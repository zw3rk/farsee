// SPDX-License-Identifier: Apache-2.0
//
// Farsee TLS-provider default accessor.
//
// No Farsee-owned TLS provider is registered in this implementation. The
// default accessor returns NULL; callers must treat that as unavailable.

#include "farsee/farsee_tls.h"

#include <stddef.h>

const farsee_tls_provider *farsee_tls_provider_default(void)
{
    // No concrete provider is registered.
    return NULL;
}
