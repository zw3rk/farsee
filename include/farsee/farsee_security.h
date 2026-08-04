// SPDX-License-Identifier: Apache-2.0
//
// Farsee common security services contracts.
// (FARSEE_ARCHITECTURE_IMPROVEMENT_PLAN.md §10 — F6 gate.)
//
// §10.1 separates FOUR concerns that Farsee MUST NOT collapse into one
// "crypto" interface:
//   1. cryptographic primitive provider (hashes/ciphers/signatures/RNG) —
//      satisfied by the existing rfb_crypto_* provider interface (G1/G16);
//   2. TLS provider — handshake, record protection, cert-chain extraction;
//   3. credential provider — passwords/usernames/domains/certs/agents;
//   4. peer trust provider — persisted authorization for the remote identity.
//
// This header introduces the common contracts for (2), (3), and (4) as
// opaque, protocol-neutral types. The existing crypto provider and
// known_hosts store are preserved; these common contracts sit above them.
//
// Secret safety (§7.3, §10.2): secrets use farsee_secret and are zeroized
// on every path, never enter a general log, have a single owner, and are
// released immediately after the backend has consumed them.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_SECURITY_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_SECURITY_H

#include "farsee/farsee_error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- Secret (§10.2) --------------------------------------------------------
// A length-prefixed secret buffer with a single owner. The owner zeroizes
// it (farsee_secret_zero) on every release path. Avoid immutable string
// literals; secrets live in writable, owned storage.
typedef struct farsee_secret {
    uint8_t *data;
    size_t   len;       // bytes used
    size_t   cap;       // bytes allocated
} farsee_secret;

// Zeroize and free a secret's backing storage. Sets data=NULL, len=cap=0.
// Safe on NULL or already-released secrets.
void farsee_secret_destroy(farsee_secret *s);

// --- Credential provider (§10.2) ------------------------------------------

typedef enum {
    FARSEE_CRED_USERNAME  = 1u << 0,
    FARSEE_CRED_DOMAIN    = 1u << 1,
    FARSEE_CRED_PASSWORD  = 1u << 2,   // secret
    FARSEE_CRED_PIN       = 1u << 3,   // secret (deferred)
} farsee_credential_field;

typedef enum {
    FARSEE_CRED_PROTOCOL_RFB   = 1,
    FARSEE_CRED_PROTOCOL_RDP   = 2,
    FARSEE_CRED_PROTOCOL_SPICE = 3,
    FARSEE_CRED_PROTOCOL_AHPSS = 4,
} farsee_credential_protocol;

// A credential request (§10.2). Contains NO secret material — only the
// description of what is needed and why. The response carries secrets.
typedef struct farsee_credential_request {
    farsee_credential_protocol protocol;
    unsigned requested_fields;     // farsee_credential_field bitmask
    farsee_phase phase;            // reason / protocol phase
    char profile_id[64];           // host/profile binding (NUL-terminated)
    bool retry_allowed;
    uint64_t request_id;           // opaque, unique within a session
    uint64_t deadline_monotonic_ms;
} farsee_credential_request;

// A credential response. Secret fields (password) live in farsee_secret;
// the caller owns and must destroy them. Non-secret fields are borrowed
// caller-owned NUL-terminated strings.
typedef struct farsee_credential_response {
    const char *username;   // may be NULL
    const char *domain;     // may be NULL
    farsee_secret password; // zeroized by the owner after use
} farsee_credential_response;

// Initialize an empty response (password zero-initialized).
void farsee_credential_response_init(farsee_credential_response *r);
// Destroy a response: zeroizes the password secret, clears pointers.
void farsee_credential_response_destroy(farsee_credential_response *r);

// --- Typed peer identity (§10.3) ------------------------------------------

typedef enum {
    FARSEE_IDENTITY_X509_CERTIFICATE_CHAIN = 1,
    FARSEE_IDENTITY_X509_SPKI_PIN          = 2,
    FARSEE_IDENTITY_RFB_APPLE_IDENTITY_KEY = 3,
    FARSEE_IDENTITY_RFB_VENCRYPT_CERTIFICATE = 4,
    FARSEE_IDENTITY_SPICE_CERTIFICATE      = 5,
    FARSEE_IDENTITY_AHPSS_IDENTITY         = 6,  // exact form TBD by evidence
} farsee_identity_type;

typedef enum {
    FARSEE_TRUST_MODE_CA                = 1,
    FARSEE_TRUST_MODE_PIN               = 2,
    FARSEE_TRUST_MODE_TOFU              = 3,  // trust-on-first-use
    FARSEE_TRUST_MODE_USER_APPROVED_ONCE = 4,
} farsee_trust_mode;

// A trust decision request surfaced to the user (§10.3, §15.7). Carries
// no raw certificate blob by default — only sanitized metadata + the
// fingerprint of an approved digest.
typedef struct farsee_trust_request {
    farsee_identity_type identity_type;
    char fingerprint[64];   // hex of an approved digest (e.g. SHA-256), NUL-terminated
    char host[64];          // canonical host:port binding
    bool first_use;         // true = never seen; false = identity CHANGED
    bool ca_hostname_ok;    // true = normal CA + hostname validation succeeded
    char subject_name[96];  // sanitized certificate subject (NUL-terminated)
} farsee_trust_request;

typedef enum {
    FARSEE_TRUST_DECISION_REJECT = 0,
    FARSEE_TRUST_DECISION_APPROVE_ONCE = 1,
    FARSEE_TRUST_DECISION_APPROVE_PERMANENT = 2,
} farsee_trust_decision;

// --- Security policy (§10.5) ----------------------------------------------
// Declares the allowed security posture per protocol profile. The engine
// MUST fail closed when the server selects an unapproved method. Farsee
// MUST NOT retry with a weaker security method after a failure (§6.2/§10.5).
typedef struct farsee_security_policy {
    bool require_tls;            // TLS mandatory
    bool allow_plaintext;        // opt-in only (RFB None); never default
    bool allow_insecure_cert;    // --cert ignore: session-only approve (no store)
    bool tofu_pin_store;         // --cert pin: store TOFU on FIRST_USE only
    bool require_nla;            // RDP: CredSSP/NLA mandatory
    bool allow_legacy_rdp_security;  // RDP legacy; never default
} farsee_security_policy;

// Safe defaults: TLS required, plaintext off, insecure off, NLA required,
// legacy off. (§15.4: RDP defaults to TLS+NLA, no legacy fallback.)
farsee_security_policy farsee_security_policy_default_rdp(void);
farsee_security_policy farsee_security_policy_default_rfb(void);

// Validate that a server-selected method is permitted by the policy. Fail
// closed: anything not explicitly allowed is rejected.
bool farsee_security_policy_allows_tls(const farsee_security_policy *p);
bool farsee_security_policy_allows_plaintext(const farsee_security_policy *p);
bool farsee_security_policy_allows_nla(const farsee_security_policy *p);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_SECURITY_H
