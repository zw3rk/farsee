// SPDX-License-Identifier: Apache-2.0
//
// R6 — cliprdr prepare/configure null-safety and enable-flag tests.
// No live RDP server: create/destroy FreeRDP instance through the facade.

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_cliprdr.h"
#include "protocol/rdp/rdp_freerdp_facade.h"
#include "farsee/farsee_thread.h"
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

typedef struct prepare_arg {
    rdp_freerdp_ctx *ctx;
    bool ok;
} prepare_arg;

static void *prepare_instance_concurrently(void *opaque)
{
    prepare_arg *arg = (prepare_arg *)opaque;
    arg->ok = rdp_cliprdr_prepare_instance(arg->ctx);
    return NULL;
}

RFB_TEST(rdp_cliprdr, prepare__concurrent_instances_are_safe)
{
    rdp_freerdp_ctx *a = rdp_freerdp_create();
    rdp_freerdp_ctx *b = rdp_freerdp_create();
    RFB_CHECK(a != NULL);
    RFB_CHECK(b != NULL);
    prepare_arg aa = { .ctx = a, .ok = false };
    prepare_arg bb = { .ctx = b, .ok = false };
    farsee_thread *ta = farsee_thread_create(prepare_instance_concurrently,
                                              &aa);
    farsee_thread *tb = farsee_thread_create(prepare_instance_concurrently,
                                              &bb);
    RFB_CHECK(ta != NULL);
    RFB_CHECK(tb != NULL);
    farsee_thread_join(&ta, NULL);
    farsee_thread_join(&tb, NULL);
    RFB_CHECK(aa.ok);
    RFB_CHECK(bb.ok);
    rdp_freerdp_destroy(&a);
    rdp_freerdp_destroy(&b);
}

RFB_TEST(rdp_cliprdr, configure__enable_and_disable)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    RFB_CHECK(rdp_cliprdr_prepare_instance(ctx));

    farsee_clip_policy pol = farsee_clip_policy_default();
    pol.direction = FARSEE_CLIP_DIRECTION_BIDIRECTIONAL;

    // Sequential configuration must safely reset negotiation state.
    rdp_cliprdr_configure(ctx, &pol, true);
    RFB_CHECK(rdp_cliprdr_is_enabled(ctx));
    rdp_cliprdr_configure(ctx, &pol, true);
    RFB_CHECK(rdp_cliprdr_is_enabled(ctx));

    rdp_cliprdr_configure(ctx, &pol, false);
    RFB_CHECK(rdp_cliprdr_is_enabled(ctx) == false);

    // NULL policy forces disabled.
    rdp_cliprdr_configure(ctx, NULL, true);
    RFB_CHECK(rdp_cliprdr_is_enabled(ctx) == false);

    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_cliprdr, configure__null_ctx_safe)
{
    // configure must not crash on a NULL facade handle (no-op), and a
    // NULL handle never reports enabled.
    farsee_clip_policy pol = farsee_clip_policy_default();
    pol.direction = FARSEE_CLIP_DIRECTION_LOCAL_TO_REMOTE;
    rdp_cliprdr_configure(NULL, &pol, true);
    RFB_CHECK(rdp_cliprdr_is_enabled(NULL) == false);
    rdp_cliprdr_configure(NULL, NULL, false);
    RFB_CHECK(rdp_cliprdr_is_enabled(NULL) == false);
}

// Clipboard state is per-instance, so two sessions can use different policy.
RFB_TEST(rdp_cliprdr, two_contexts__state_is_independent)
{
    rdp_freerdp_ctx *a = rdp_freerdp_create();
    rdp_freerdp_ctx *b = rdp_freerdp_create();
    RFB_CHECK(a != NULL);
    RFB_CHECK(b != NULL);
    RFB_CHECK(a != b);

    farsee_clip_policy pol = farsee_clip_policy_default();
    pol.direction = FARSEE_CLIP_DIRECTION_BIDIRECTIONAL;

    rdp_cliprdr_configure(a, &pol, true);
    rdp_cliprdr_configure(b, &pol, false);

    // Each context reports its own enabled state.
    RFB_CHECK(rdp_cliprdr_is_enabled(a));
    RFB_CHECK(rdp_cliprdr_is_enabled(b) == false);

    // Flipping B must not disturb A.
    rdp_cliprdr_configure(b, NULL, true);
    RFB_CHECK(rdp_cliprdr_is_enabled(a));
    RFB_CHECK(rdp_cliprdr_is_enabled(b) == false);

    // Per-instance negotiation state (server_format_id) is also isolated:
    // configure resets it per instance only.
    rdp_cliprdr_configure(b, &pol, true);
    RFB_CHECK(rdp_cliprdr_is_enabled(a));
    RFB_CHECK(rdp_cliprdr_is_enabled(b));

    rdp_freerdp_destroy(&a);
    rdp_freerdp_destroy(&b);
    RFB_CHECK(a == NULL);
    RFB_CHECK(b == NULL);
}

#endif  // FARSEE_WITH_RDP
