// SPDX-License-Identifier: Apache-2.0
//
// F7 — transport set + TLS provider contract tests (§9).
//
// Verifies the transport-set container (bounded lanes, engine-owned
// registration, metrics) and the TLS provider contract (the backend vtable
// shape). Concrete TCP/UDP/TLS backends are later subgates; interop
// (VeNCrypt against independent VNC servers, §14.4) is a hardware gate.

#include "farsee/farsee_transport.h"
#include "farsee/farsee_tls.h"
#include "tests/test_framework/rfb_test.h"

// --- transport set lifecycle -----------------------------------------------

RFB_TEST(farsee_transport, set__create_destroy)
{
    farsee_transport_set *s = farsee_transport_set_create(4);
    RFB_CHECK(s != NULL);
    RFB_CHECK_EQ_UINT(farsee_transport_set_count(s), 0u);
    farsee_transport_set_destroy(&s);
    RFB_CHECK(s == NULL);
    // bad config
    RFB_CHECK(farsee_transport_set_create(0) == NULL);
}

RFB_TEST(farsee_transport, set__add_engine_owned_lane)
{
    farsee_transport_set *s = farsee_transport_set_create(2);
    size_t a = farsee_transport_set_add_engine_owned(s);
    size_t b = farsee_transport_set_add_engine_owned(s);
    RFB_CHECK(a != SIZE_MAX);
    RFB_CHECK(b != SIZE_MAX);
    RFB_CHECK(a != b);
    RFB_CHECK_EQ_UINT(farsee_transport_set_count(s), 2u);
    RFB_CHECK(farsee_transport_lane_semantics(s, a) == FARSEE_LANE_ENGINE_OWNED);
    RFB_CHECK(farsee_transport_lane_semantics(s, b) == FARSEE_LANE_ENGINE_OWNED);
    // Cap enforced: third add fails.
    RFB_CHECK(farsee_transport_set_add_engine_owned(s) == SIZE_MAX);
    // Out-of-range / missing lane queries are safe.
    RFB_CHECK(farsee_transport_lane_metrics(s, 99) == NULL);
    farsee_transport_set_destroy(&s);
}

RFB_TEST(farsee_transport, set__metrics_storage_zero_initialized)
{
    farsee_transport_set *s = farsee_transport_set_create(2);
    size_t a = farsee_transport_set_add_engine_owned(s);
    const farsee_transport_metrics *m = farsee_transport_lane_metrics(s, a);
    RFB_CHECK(m != NULL);
    RFB_CHECK_EQ_UINT(m->bytes_in, 0u);
    RFB_CHECK_EQ_UINT(m->bytes_out, 0u);
    farsee_transport_set_destroy(&s);
}

// --- TLS provider contract -------------------------------------------------

// The contract is a vtable; verify the default provider accessor exists
// and (when OpenSSL is present) returns a non-NULL provider with all ops.
// When OpenSSL is absent it may return NULL — that is an acceptable
// "engine-owned TLS only" state, not a failure.
RFB_TEST(farsee_tls, provider__default_accessor_present)
{
    const farsee_tls_provider *p = farsee_tls_provider_default();
    if (p != NULL) {
        // A registered backend MUST provide every op (no NULL ops).
        RFB_CHECK(p->create_client != NULL);
        RFB_CHECK(p->handshake_step != NULL);
        RFB_CHECK(p->peer_identity != NULL);
        RFB_CHECK(p->read != NULL);
        RFB_CHECK(p->write != NULL);
        RFB_CHECK(p->destroy != NULL);
    }
    // If p == NULL, the build is no-OpenSSL; acceptable for engine-owned TLS.
}
