// SPDX-License-Identifier: Apache-2.0
//
// Farsee protocol-neutral TLS provider contract.
// (FARSEE_ARCHITECTURE_IMPROVEMENT_PLAN.md §9.5 — F7 gate.)
//
// Client-mode TLS with SNI, hostname verification, CA validation, version
// and cipher policy, and typed peer-identity extraction. The contract is a
// backend-agnostic ops table; concrete backends (OpenSSL for Farsee-owned
// transports, FreeRDP-bridged for RDP) implement it. No OpenSSL/CommonCrypto
// types appear here (§4.2) — backends map to farsee_identity_type.
//
// §9.5: clear distinction between TLS success and peer AUTHORIZATION. TLS
// establishing a chain is necessary but not sufficient; the trust service
// (F6) makes the authorization decision.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_TLS_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_TLS_H

#include "farsee/farsee_error.h"
#include "farsee/farsee_security.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// TLS version policy (minimum). Backends enforce >= the selected floor.
typedef enum {
    FARSEE_TLS_VERSION_1_2 = 0,
    FARSEE_TLS_VERSION_1_3 = 1,
} farsee_tls_version_floor;

// Opaque TLS session handle (backend-defined).
typedef struct farsee_tls_session farsee_tls_session;

// A TLS provider is a backend vtable. The backend binds a session to a
// Farsee-owned transport lane (identified by its pollable descriptor) and
// drives the handshake. Peer authorization is returned via the trust
// service, not decided here.
typedef struct farsee_tls_provider {
    // Create a client TLS session bound to hostname (for SNI + verification).
    farsee_error_code (*create_client)(const char *hostname,
                                       farsee_tls_version_floor floor,
                                       farsee_tls_session **out);
    // Drive the handshake. Returns OK on completion, STATE if more I/O is
    // needed (caller polls the lane descriptor), or a TLS/auth error.
    farsee_error_code (*handshake_step)(farsee_tls_session *s);
    // Extract the peer identity type + fingerprint for the trust service.
    farsee_error_code (*peer_identity)(farsee_tls_session *s,
                                       farsee_identity_type *out_type,
                                       char *out_fingerprint, size_t fp_cap);
    // Read/write application data through the TLS record layer.
    farsee_error_code (*read)(farsee_tls_session *s, uint8_t *buf, size_t cap,
                              size_t *out_n);
    farsee_error_code (*write)(farsee_tls_session *s, const uint8_t *buf,
                               size_t len, size_t *out_n);
    void (*destroy)(farsee_tls_session **s);
} farsee_tls_provider;

// The default OpenSSL-backed provider for Farsee-owned transports. Returns
// NULL if OpenSSL is unavailable at runtime. Registered when FARSEE_WITH_OPENSSL.
const farsee_tls_provider *farsee_tls_provider_default(void);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_TLS_H
