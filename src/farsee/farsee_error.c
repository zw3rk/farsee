// SPDX-License-Identifier: Apache-2.0
//
// Farsee common structured error implementation (F1 gate, §7).

#include "farsee/farsee_error.h"

#include <stddef.h>

// --- Retryability classification (§7.2). -----------------------------------
// Transient/network categories may be retried (same operation). Trust,
// auth, cancel, and internal-bug categories MUST NOT be retried — and
// retrying NEVER means "try a weaker security method or another protocol"
// (§6.2, §10.5).
static bool code_is_retryable(farsee_error_code code)
{
    switch (code) {
    case FARSEE_ERR_TIMEOUT:
    case FARSEE_ERR_DNS_FAILURE:
    case FARSEE_ERR_CONNECT_FAILURE:
    case FARSEE_ERR_TRANSPORT_CLOSED:
    case FARSEE_ERR_TLS_FAILURE:
    case FARSEE_ERR_RESOURCE_LIMIT:
    case FARSEE_ERR_CHANNEL_FAILURE:
    case FARSEE_ERR_THIRD_PARTY_BACKEND_FAILURE:
        return true;
    case FARSEE_E_OK:
    case FARSEE_ERR_CONFIGURATION:
    case FARSEE_ERR_UNSUPPORTED_FEATURE:
    case FARSEE_ERR_OUT_OF_MEMORY:
    case FARSEE_ERR_CANCELLED:
    case FARSEE_ERR_PEER_IDENTITY_UNTRUSTED:
    case FARSEE_ERR_PEER_IDENTITY_CHANGED:
    case FARSEE_ERR_AUTHENTICATION_REJECTED:
    case FARSEE_ERR_AUTHENTICATION_UNAVAILABLE:
    case FARSEE_ERR_PROTOCOL_VIOLATION:
    case FARSEE_ERR_CODEC_FAILURE:
    case FARSEE_ERR_PRESENTER_FAILURE:
    case FARSEE_ERR_LOCAL_IO_FAILURE:
    case FARSEE_ERR_STATE:
    case FARSEE_ERR_INTERNAL:
        return false;
    }
    return false;
}

static bool code_requires_user_action(farsee_error_code code)
{
    switch (code) {
    case FARSEE_ERR_CONFIGURATION:
    case FARSEE_ERR_PEER_IDENTITY_UNTRUSTED:
    case FARSEE_ERR_PEER_IDENTITY_CHANGED:
    case FARSEE_ERR_AUTHENTICATION_REJECTED:
    case FARSEE_ERR_AUTHENTICATION_UNAVAILABLE:
    case FARSEE_ERR_UNSUPPORTED_FEATURE:
        return true;
    case FARSEE_E_OK:
    case FARSEE_ERR_RESOURCE_LIMIT:
    case FARSEE_ERR_OUT_OF_MEMORY:
    case FARSEE_ERR_CANCELLED:
    case FARSEE_ERR_TIMEOUT:
    case FARSEE_ERR_DNS_FAILURE:
    case FARSEE_ERR_CONNECT_FAILURE:
    case FARSEE_ERR_TRANSPORT_CLOSED:
    case FARSEE_ERR_TLS_FAILURE:
    case FARSEE_ERR_PROTOCOL_VIOLATION:
    case FARSEE_ERR_CODEC_FAILURE:
    case FARSEE_ERR_CHANNEL_FAILURE:
    case FARSEE_ERR_PRESENTER_FAILURE:
    case FARSEE_ERR_LOCAL_IO_FAILURE:
    case FARSEE_ERR_THIRD_PARTY_BACKEND_FAILURE:
    case FARSEE_ERR_STATE:
    case FARSEE_ERR_INTERNAL:
        return false;
    }
    return false;
}

// --- Constructors -----------------------------------------------------------

farsee_error farsee_error_make(farsee_error_code code,
                               farsee_subsystem subsystem,
                               farsee_phase phase)
{
    farsee_error e;
    e.code = code;
    e.subsystem = subsystem;
    e.phase = phase;
    e.message = NULL;
    e.cause = NULL;
    return e;
}

farsee_error farsee_error_make_with_msg(farsee_error_code code,
                                        farsee_subsystem subsystem,
                                        farsee_phase phase,
                                        const char *msg)
{
    farsee_error e = farsee_error_make(code, subsystem, phase);
    e.message = msg;
    return e;
}

// Compute the depth of a causal chain (1 + recursive length).
static int chain_depth(const farsee_error *e)
{
    int depth = 1;
    const farsee_error *c = e->cause;
    while (c != NULL) {
        ++depth;
        c = c->cause;
    }
    return depth;
}

farsee_error farsee_error_make_with_cause(farsee_error_code code,
                                          farsee_subsystem subsystem,
                                          farsee_phase phase,
                                          const farsee_error *parent)
{
    farsee_error e = farsee_error_make(code, subsystem, phase);
    // Clamp the chain: if attaching `parent` would exceed the declared
    // maximum depth, drop the cause rather than overflow. The test
    // farsee_error__bounded_chain verifies the clamp keeps total length
    // at exactly MAX_CAUSE_DEPTH + 1.
    if (parent != NULL && chain_depth(parent) < FARSEE_ERROR_MAX_CAUSE_DEPTH) {
        e.cause = parent;
    } else {
        e.cause = NULL;
    }
    return e;
}

// --- Accessors --------------------------------------------------------------

bool farsee_error_failed(farsee_error e)
{
    return e.code != FARSEE_E_OK;
}

bool farsee_error_is_retryable(farsee_error e)
{
    return code_is_retryable(e.code);
}

bool farsee_error_requires_user_action(farsee_error e)
{
    return code_requires_user_action(e.code);
}

const char *farsee_error_code_name(farsee_error_code code)
{
    switch (code) {
    case FARSEE_E_OK:                           return "FARSEE_E_OK";
    case FARSEE_ERR_CONFIGURATION:              return "FARSEE_ERR_CONFIGURATION";
    case FARSEE_ERR_UNSUPPORTED_FEATURE:        return "FARSEE_ERR_UNSUPPORTED_FEATURE";
    case FARSEE_ERR_RESOURCE_LIMIT:             return "FARSEE_ERR_RESOURCE_LIMIT";
    case FARSEE_ERR_OUT_OF_MEMORY:              return "FARSEE_ERR_OUT_OF_MEMORY";
    case FARSEE_ERR_CANCELLED:                  return "FARSEE_ERR_CANCELLED";
    case FARSEE_ERR_TIMEOUT:                    return "FARSEE_ERR_TIMEOUT";
    case FARSEE_ERR_DNS_FAILURE:                return "FARSEE_ERR_DNS_FAILURE";
    case FARSEE_ERR_CONNECT_FAILURE:            return "FARSEE_ERR_CONNECT_FAILURE";
    case FARSEE_ERR_TRANSPORT_CLOSED:           return "FARSEE_ERR_TRANSPORT_CLOSED";
    case FARSEE_ERR_TLS_FAILURE:                return "FARSEE_ERR_TLS_FAILURE";
    case FARSEE_ERR_PEER_IDENTITY_UNTRUSTED:    return "FARSEE_ERR_PEER_IDENTITY_UNTRUSTED";
    case FARSEE_ERR_PEER_IDENTITY_CHANGED:      return "FARSEE_ERR_PEER_IDENTITY_CHANGED";
    case FARSEE_ERR_AUTHENTICATION_REJECTED:    return "FARSEE_ERR_AUTHENTICATION_REJECTED";
    case FARSEE_ERR_AUTHENTICATION_UNAVAILABLE: return "FARSEE_ERR_AUTHENTICATION_UNAVAILABLE";
    case FARSEE_ERR_PROTOCOL_VIOLATION:         return "FARSEE_ERR_PROTOCOL_VIOLATION";
    case FARSEE_ERR_CODEC_FAILURE:              return "FARSEE_ERR_CODEC_FAILURE";
    case FARSEE_ERR_CHANNEL_FAILURE:            return "FARSEE_ERR_CHANNEL_FAILURE";
    case FARSEE_ERR_PRESENTER_FAILURE:          return "FARSEE_ERR_PRESENTER_FAILURE";
    case FARSEE_ERR_LOCAL_IO_FAILURE:           return "FARSEE_ERR_LOCAL_IO_FAILURE";
    case FARSEE_ERR_THIRD_PARTY_BACKEND_FAILURE:return "FARSEE_ERR_THIRD_PARTY_BACKEND_FAILURE";
    case FARSEE_ERR_STATE:                      return "FARSEE_ERR_STATE";
    case FARSEE_ERR_INTERNAL:                   return "FARSEE_ERR_INTERNAL";
    }
    return "FARSEE_E_UNKNOWN";
}

const char *farsee_error_message_or_default(farsee_error e)
{
    if (e.message != NULL) {
        return e.message;
    }
    // Stable, sanitized fallback per code. No paths, no secrets, no
    // platform/errno strings.
    switch (e.code) {
    case FARSEE_E_OK:                           return "ok";
    case FARSEE_ERR_CONFIGURATION:              return "configuration error";
    case FARSEE_ERR_UNSUPPORTED_FEATURE:        return "unsupported feature";
    case FARSEE_ERR_RESOURCE_LIMIT:             return "resource limit exceeded";
    case FARSEE_ERR_OUT_OF_MEMORY:              return "out of memory";
    case FARSEE_ERR_CANCELLED:                  return "operation cancelled";
    case FARSEE_ERR_TIMEOUT:                    return "operation timed out";
    case FARSEE_ERR_DNS_FAILURE:                return "name resolution failed";
    case FARSEE_ERR_CONNECT_FAILURE:            return "connection failed";
    case FARSEE_ERR_TRANSPORT_CLOSED:           return "connection closed";
    case FARSEE_ERR_TLS_FAILURE:                return "TLS handshake or record error";
    case FARSEE_ERR_PEER_IDENTITY_UNTRUSTED:    return "peer identity not trusted";
    case FARSEE_ERR_PEER_IDENTITY_CHANGED:      return "peer identity changed";
    case FARSEE_ERR_AUTHENTICATION_REJECTED:    return "authentication rejected";
    case FARSEE_ERR_AUTHENTICATION_UNAVAILABLE: return "authentication unavailable";
    case FARSEE_ERR_PROTOCOL_VIOLATION:         return "protocol violation";
    case FARSEE_ERR_CODEC_FAILURE:              return "codec failure";
    case FARSEE_ERR_CHANNEL_FAILURE:            return "channel failure";
    case FARSEE_ERR_PRESENTER_FAILURE:          return "presenter failure";
    case FARSEE_ERR_LOCAL_IO_FAILURE:           return "local I/O failure";
    case FARSEE_ERR_THIRD_PARTY_BACKEND_FAILURE:return "backend failure";
    case FARSEE_ERR_STATE:                      return "invalid state for operation";
    case FARSEE_ERR_INTERNAL:                   return "internal error";
    }
    return "unknown error";
}
