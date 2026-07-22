// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple dialect and authentication state-machine framework
// (goals.md G15). Clean-room derived from RFC 6143 and Apple public docs.

#include "farsee/apple_auth.h"
#include "farsee/handshake.h"
#include "farsee/secret.h"

#include <string.h>

// --- Fake deterministic provider -----------------------------------------

static apple_auth_result_t fake_process(
    apple_auth_ctx *ctx,
    const uint8_t *in, size_t in_len,
    uint8_t *out_bytes, size_t out_cap, size_t *out_len,
    uint8_t wrap_key[16])
{
    (void)in; (void)in_len; (void)out_bytes; (void)out_cap;
    apple_auth_fake *f = (apple_auth_fake *)ctx->impl;
    if (f == NULL) return APPLE_AUTH_FATAL;
    f->messages_consumed++;
    if (f->messages_consumed < f->messages_needed) {
        // Simulate sending a response.
        *out_len = 0;
        return APPLE_AUTH_NEED_MORE;
    }
    // Authenticated: copy the wrap key.
    memcpy(wrap_key, f->wrap_key, 16);
    *out_len = 0;
    return APPLE_AUTH_AUTHENTICATED;
}

static void fake_destroy(apple_auth_ctx *ctx)
{
    if (ctx == NULL || ctx->impl == NULL) return;
    apple_auth_fake *f = (apple_auth_fake *)ctx->impl;
    rfb_secret_zero(f->wrap_key, sizeof f->wrap_key);
}

static const apple_auth_provider_ops fake_ops = {
    .process = fake_process,
    .destroy = fake_destroy,
};

void apple_auth_fake_init(apple_auth_fake *f, int messages_needed,
                          const uint8_t wrap_key[16])
{
    if (f == NULL) return;
    f->messages_consumed = 0;
    f->messages_needed = messages_needed;
    if (wrap_key != NULL) {
        memcpy(f->wrap_key, wrap_key, 16);
    } else {
        memset(f->wrap_key, 0, 16);
    }
}

apple_auth_ctx apple_auth_fake_ctx(apple_auth_fake *f)
{
    apple_auth_ctx ctx;
    ctx.ops = &fake_ops;
    ctx.impl = f;
    return ctx;
}

// --- Dialect detection ---------------------------------------------------

bool apple_is_dialect_003_889(const uint8_t *banner, size_t len)
{
    if (banner == NULL || len < 12) return false;
    // Apple uses RFB 003.889\n (12 bytes).
    static const uint8_t apple_banner[12] = {
        'R','F','B',' ','0','0','3','.','8','8','9','\n'
    };
    return memcmp(banner, apple_banner, 12) == 0;
}

// --- Security type selection policy --------------------------------------

int apple_select_security_type(const uint8_t *offered, size_t count,
                               bool allow_legacy)
{
    // Single pure policy: farsee_rfb_select_security. Historical Apple helper
    // tests/fuzz expect APPLE-only mode with 36/35 eligible when offered
    // (product defaults keep 36/35 off until their gates land).
    farsee_rfb_security_policy pol = farsee_rfb_security_policy_default();
    pol.auth_mode = FARSEE_AUTH_MODE_APPLE;
    pol.allow_type_33 = true;
    pol.allow_type_36 = true;
    pol.allow_type_35 = true;
    pol.allow_legacy_apple = allow_legacy;
    pol.allow_vnc = false;
    pol.allow_none = false;
    uint8_t selected = 0;
    if (farsee_rfb_select_security(offered, count, &pol, &selected) != RFB_OK) {
        return 0;
    }
    return (int)selected;
}
