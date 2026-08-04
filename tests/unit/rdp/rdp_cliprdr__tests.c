// SPDX-License-Identifier: Apache-2.0
//
// R6 — cliprdr prepare/configure null-safety and enable-flag tests.
// No live RDP server: create/destroy FreeRDP instance through the facade.

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_cliprdr.h"
#include "protocol/rdp/rdp_freerdp_facade.h"
#include "tests/test_framework/rfb_test.h"

#include <freerdp/freerdp.h>

#include <string.h>

RFB_TEST(rdp_cliprdr, prepare__null_safe)
{
    RFB_CHECK(rdp_cliprdr_prepare_instance(NULL) == false);
}

RFB_TEST(rdp_cliprdr, prepare__on_fresh_instance)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    RFB_CHECK(rdp_cliprdr_prepare_instance(ctx));

    // LoadChannels must be installed so freerdp_connect can load cliprdr.
    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    RFB_CHECK(inst != NULL);
    RFB_CHECK(inst->LoadChannels != NULL);

    // Idempotent prepare on the same instance.
    RFB_CHECK(rdp_cliprdr_prepare_instance(ctx));

    rdp_freerdp_destroy(&ctx);
    RFB_CHECK(ctx == NULL);
}

RFB_TEST(rdp_cliprdr, configure__enable_and_disable)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    RFB_CHECK(rdp_cliprdr_prepare_instance(ctx));

    farsee_clip_policy pol = farsee_clip_policy_default();
    pol.direction = FARSEE_CLIP_DIRECTION_BIDIRECTIONAL;

    // Sequential configure must be safe (T16: reset negotiation state).
    rdp_cliprdr_configure(ctx, &pol, true);
    RFB_CHECK(rdp_cliprdr_is_enabled());
    rdp_cliprdr_configure(ctx, &pol, true);
    RFB_CHECK(rdp_cliprdr_is_enabled());

    rdp_cliprdr_configure(ctx, &pol, false);
    RFB_CHECK(rdp_cliprdr_is_enabled() == false);

    // NULL policy forces disabled.
    rdp_cliprdr_configure(ctx, NULL, true);
    RFB_CHECK(rdp_cliprdr_is_enabled() == false);

    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_cliprdr, configure__null_ctx_safe)
{
    // configure must not crash on a NULL facade handle.
    farsee_clip_policy pol = farsee_clip_policy_default();
    pol.direction = FARSEE_CLIP_DIRECTION_LOCAL_TO_REMOTE;
    rdp_cliprdr_configure(NULL, &pol, true);
    RFB_CHECK(rdp_cliprdr_is_enabled());
    rdp_cliprdr_configure(NULL, NULL, false);
    RFB_CHECK(rdp_cliprdr_is_enabled() == false);
}

#endif  // FARSEE_WITH_RDP
