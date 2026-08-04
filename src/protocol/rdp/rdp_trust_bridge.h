// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP trust + credential bridge (R2 gate, §15.7, §10.3, §10.4).
//
// Maps FreeRDP certificate-verification callbacks into the F6 typed trust
// service, and credential requests into FreeRDP settings. The bridge logic
// is pure and deterministic (testable without a live server): the live
// callback wiring runs against an independent RDP endpoint for PASS_INTEROP.
//
// §10.4: credentials MUST NOT be sent to a peer whose identity was rejected.
// §15.7: a changed certificate defaults to rejection.
//
// PRIVATE to src/protocol/rdp/.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_TRUST_BRIDGE_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_TRUST_BRIDGE_H

#include "farsee/farsee_security.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Classification of a certificate observation relative to a prior trust
// record (§15.7). first_use = never seen; unchanged = matches the record;
// changed = the identity differs from the prior record (defaults reject).
typedef enum {
    RDP_TRUST_FIRST_USE = 0,
    RDP_TRUST_UNCHANGED = 1,
    RDP_TRUST_CHANGED   = 2,
} rdp_trust_classification;

// Build a sanitized farsee_trust_request from a certificate observation.
// `fingerprint_hex` is the approved-digest hex of the peer cert; `host`
// is the canonical host:port; `subject` is a sanitized subject string;
// `ca_hostname_ok` is whether normal CA + hostname validation succeeded.
// The request carries NO raw certificate blob (§10.3).
void rdp_trust_build_request(farsee_trust_request *out,
                             const char *fingerprint_hex,
                             const char *host,
                             const char *subject,
                             bool ca_hostname_ok,
                             rdp_trust_classification classification);

// Evaluate a trust decision per §15.7 / §10.5.
//   - CHANGED  -> REJECT (a changed identity defaults to rejection; the
//                user must explicitly approve, which is a separate action).
//   - UNCHANGED -> APPROVE_ONCE (already trusted; proceed this session).
//   - FIRST_USE with ca_hostname_ok -> APPROVE_ONCE (CA-valid first use).
//   - FIRST_USE without ca_hostname_ok -> REJECT (self-signed first use
//                requires explicit user approval; do not auto-approve).
farsee_trust_decision rdp_trust_evaluate(const farsee_trust_request *req);

// Evaluate with the explicit classification (the live callback path knows
// whether the observed cert differs from the stored record). Encodes §15.7:
// CHANGED -> REJECT; UNCHANGED -> APPROVE_ONCE; FIRST_USE -> APPROVE_ONCE
// only if CA+hostname validation passed, else REJECT (self-signed first use
// needs explicit user approval).
farsee_trust_decision rdp_trust_evaluate_classified(
    rdp_trust_classification c, bool ca_hostname_ok);

// FreeRDP VERIFY_CERT_FLAG_* bit values (mirrored so this header stays free
// of FreeRDP includes). Keep in sync with freerdp/freerdp.h.
// FreeRDP only invokes VerifyX509Certificate when the peer is NOT already
// system-CA trusted — so the callback is "user must accept", not "CA ok".
// flags==0 is the common first-use untrusted/self-signed case.
#define RDP_VERIFY_CERT_FLAG_CHANGED  0x40u
#define RDP_VERIFY_CERT_FLAG_MISMATCH 0x80u

// Always false for FreeRDP VerifyX509Certificate flags: being asked means
// the peer is not system-CA trusted. Never treat flags==0 as ca_hostname_ok.
bool rdp_trust_ca_hostname_ok_from_flags(uint32_t freerdp_flags);

// Seed classification from FreeRDP flags alone (before known_hosts).
// CHANGED flag -> RDP_TRUST_CHANGED; otherwise FIRST_USE (includes flags==0).
rdp_trust_classification rdp_trust_classify_from_flags(uint32_t freerdp_flags);

// Full product decision for a cert observation: if allow_insecure_cert,
// APPROVE_ONCE; else rdp_trust_evaluate_classified(c, ca_hostname_ok).
// Used by rdp_cb_verify_x509 and unit tests (reject vs --cert ignore).
farsee_trust_decision rdp_trust_decide(rdp_trust_classification c,
                                       bool ca_hostname_ok,
                                       bool allow_insecure_cert);

// Extended: tofu_pin_store (--cert pin) approves FIRST_USE without
// allow_insecure; CHANGED still requires allow_insecure (session-only).
farsee_trust_decision rdp_trust_decide_ex(rdp_trust_classification c,
                                          bool ca_hostname_ok,
                                          bool allow_insecure_cert,
                                          bool tofu_pin_store);

// §10.4 gate: may credentials be sent to this peer? Returns false if the
// trust decision is REJECT. Credentials MUST NOT be delegated to a peer
// whose identity was rejected, even if the backend asks for them first.
bool rdp_trust_allows_credentials(farsee_trust_decision d);

// FreeRDP 3.x VerifyX509Certificate return code for a farsee trust decision.
// 0 = reject; 2 = accept this session only. Never returns 1 (accept+store):
// farsee pins via known_hosts; FreeRDP permanent store would skip our
// callback on later connects (multi-review 2026-07-31 T2).
int rdp_verify_x509_freerdp_return(farsee_trust_decision d);

// --- Credential bridge (§15.6) ---------------------------------------------
// Decide whether a credential response may be applied given the trust
// decision and the security policy. Returns false if the response is
// rejected (trust failed, or NLA required but the secret is empty).
bool rdp_credential_may_apply(farsee_trust_decision trust,
                              const farsee_security_policy *policy,
                              const farsee_credential_response *resp);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_PROTOCOL_RDP_RDP_TRUST_BRIDGE_H
