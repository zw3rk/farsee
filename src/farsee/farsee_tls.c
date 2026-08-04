// SPDX-License-Identifier: Apache-2.0
//
// Farsee TLS provider — default accessor (F7 gate, §9.5).
//
// The concrete TLS backend (OpenSSL for Farsee-owned transports) is a
// focused subgate of F7 that wires the ops table to a real handshake/record
// implementation. Until that backend is registered, the default accessor
// returns NULL, which means "no Farsee-owned TLS yet — engines must use
// engine-owned TLS (e.g. FreeRDP)". This is an honest, fail-closed state,
// not a stub that pretends to provide security.

#include "farsee/farsee_tls.h"

#include <stddef.h>

const farsee_tls_provider *farsee_tls_provider_default(void)
{
    // No concrete backend registered yet. The OpenSSL backend lands when
    // VeNCrypt/TLS interop work begins (a hardware-gated F7 subgate).
    return NULL;
}
