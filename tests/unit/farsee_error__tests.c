// SPDX-License-Identifier: Apache-2.0
//
// F1 — structured error contract tests (FARSEE_ARCHITECTURE_IMPROVEMENT_PLAN.md §7).
//
// The common farsee_error is a *structured* error, distinct from the
// existing flat rfb_error enum (include/farsee/error.h). It carries a
// subsystem, lifecycle phase, retryability classification, user-action
// flag, a sanitized message, and a bounded causal chain. It must never
// carry secret material.

#include "farsee/farsee_error.h"
#include "tests/test_framework/rfb_test.h"
#include <string.h>

RFB_TEST(farsee_error, farsee_error_init__zeroed_is_ok)
{
    farsee_error e = farsee_error_make(FARSEE_E_OK, FARSEE_SUB_CORE,
                                       FARSEE_PHASE_NONE);
    RFB_CHECK(e.code == FARSEE_E_OK);
    RFB_CHECK(e.subsystem == FARSEE_SUB_CORE);
    RFB_CHECK(e.phase == FARSEE_PHASE_NONE);
    RFB_CHECK_MSG(farsee_error_failed(e) == false,
                  "OK must not report as failed");
}

RFB_TEST(farsee_error, farsee_error_make__populates_fields)
{
    farsee_error e = farsee_error_make(FARSEE_ERR_AUTHENTICATION_REJECTED,
                                       FARSEE_SUB_RDP, FARSEE_PHASE_AUTHENTICATING);
    RFB_CHECK(e.code == FARSEE_ERR_AUTHENTICATION_REJECTED);
    RFB_CHECK(e.subsystem == FARSEE_SUB_RDP);
    RFB_CHECK(e.phase == FARSEE_PHASE_AUTHENTICATING);
    RFB_CHECK(farsee_error_failed(e) == true);
    // Default retryability must be derived from the code (auth reject = not retryable).
    RFB_CHECK_MSG(farsee_error_is_retryable(e) == false,
                  "auth rejection must NOT be retryable");
    RFB_CHECK_MSG(farsee_error_requires_user_action(e) == true,
                  "auth rejection requires user action");
}

RFB_TEST(farsee_error, farsee_error_retryability__per_category)
{
    // Transient/network failures are retryable.
    farsee_error transient = farsee_error_make(FARSEE_ERR_TIMEOUT,
        FARSEE_SUB_TRANSPORT, FARSEE_PHASE_CONNECTING);
    RFB_CHECK(farsee_error_is_retryable(transient) == true);

    // Trust failure is terminal for this host identity — never retryable
    // (§6.2 / §10.5: never retry a weaker method or another protocol after
    // trust/auth failure).
    farsee_error trust = farsee_error_make(FARSEE_ERR_PEER_IDENTITY_UNTRUSTED,
        FARSEE_SUB_TRUST, FARSEE_PHASE_NEGOTIATING_SECURITY);
    RFB_CHECK(farsee_error_is_retryable(trust) == false);

    // Cancelled is not retryable.
    farsee_error cancelled = farsee_error_make(FARSEE_ERR_CANCELLED,
        FARSEE_SUB_CORE, FARSEE_PHASE_CONNECTING);
    RFB_CHECK(farsee_error_is_retryable(cancelled) == false);
}

RFB_TEST(farsee_error, farsee_error_message__sanitized_no_secret)
{
    // A sanitized message must never echo attacker-controlled or secret
    // text. The builder takes a printf-style format but the contract is
    // that callers pass only safe descriptions.
    farsee_error e = farsee_error_make_with_msg(FARSEE_ERR_PROTOCOL_VIOLATION,
        FARSEE_SUB_RFB, FARSEE_PHASE_ESTABLISHING_SESSION,
        "invalid rectangle header");
    RFB_CHECK(e.message != NULL);
    RFB_CHECK(strcmp(e.message, "invalid rectangle header") == 0);
}

RFB_TEST(farsee_error, farsee_error_cause__bounded_chain)
{
    // The cause chain points to a PARENT that must outlive the child. We
    // build the chain in a stable array so each link's cause address
    // remains valid.
    farsee_error root = farsee_error_make(FARSEE_ERR_TRANSPORT_CLOSED,
        FARSEE_SUB_TRANSPORT, FARSEE_PHASE_CONNECTING);
    farsee_error leaf = farsee_error_make_with_cause(
        FARSEE_ERR_CONNECT_FAILURE, FARSEE_SUB_TRANSPORT,
        FARSEE_PHASE_CONNECTING, &root);
    RFB_CHECK(leaf.cause != NULL);
    RFB_CHECK(leaf.cause->code == FARSEE_ERR_TRANSPORT_CLOSED);
    RFB_CHECK(leaf.cause->cause == NULL);

    // Build a chain beyond the declared depth limit in stable storage so
    // the clamp can be observed. Each node's cause points at the previous
    // node's address (a stable array slot).
    enum { CHAIN_CAP = FARSEE_ERROR_MAX_CAUSE_DEPTH + 4 };
    farsee_error chain[CHAIN_CAP];
    chain[0] = root;
    int last = 0;
    for (int i = 1; i < CHAIN_CAP; ++i) {
        chain[i] = farsee_error_make_with_cause(FARSEE_ERR_TRANSPORT_CLOSED,
                                                FARSEE_SUB_TRANSPORT,
                                                FARSEE_PHASE_CONNECTING,
                                                &chain[last]);
        last = i;
    }
    // Walk the final link's chain; it MUST be clamped to at most
    // MAX_CAUSE_DEPTH + 1 nodes and never cycle or exceed the bound.
    int depth = 0;
    for (const farsee_error *c = &chain[last]; c != NULL; c = c->cause) {
        ++depth;
        RFB_CHECK_MSG(depth <= FARSEE_ERROR_MAX_CAUSE_DEPTH + 1,
                      "causal chain exceeded declared bound");
    }
    RFB_CHECK_MSG(depth <= FARSEE_ERROR_MAX_CAUSE_DEPTH + 1,
                  "chain should be clamped to the declared bound");
}

// Negative: secret content must never appear in the produced message even
// if a buggy caller tries to embed it via the format string. This test
// documents that the message field is caller-controlled prose; the secret
// guarantee is enforced by *never* passing secrets to the builder. We
// verify the builder does not itself append platform/errno strings that
// could leak environment or path information.
RFB_TEST(farsee_error, farsee_error_message__no_platform_leak)
{
    farsee_error e = farsee_error_make(FARSEE_ERR_TLS_FAILURE,
        FARSEE_SUB_TLS, FARSEE_PHASE_NEGOTIATING_SECURITY);
    // No message set: accessor must return a stable static literal, never
    // NULL, never containing a path or env-derived text.
    const char *m = farsee_error_message_or_default(e);
    RFB_CHECK(m != NULL);
    RFB_CHECK(strchr(m, '/') == NULL);
    RFB_CHECK(strstr(m, "password") == NULL);
}
