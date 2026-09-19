// SPDX-License-Identifier: Apache-2.0

#include "fakes/apple_auth_fake.h"

#include "farsee/secret.h"

#include <stddef.h>
#include <string.h>

static apple_auth_result_t fake_process(
    apple_auth_ctx *ctx,
    const uint8_t *in, size_t in_len,
    uint8_t *out_bytes, size_t out_cap, size_t *out_len,
    uint8_t wrap_key[16])
{
    apple_auth_fake *fake = (apple_auth_fake *)ctx->impl;
    (void)in;
    (void)in_len;
    (void)out_bytes;
    (void)out_cap;
    if (fake == NULL) {
        return APPLE_AUTH_FATAL;
    }
    fake->messages_consumed++;
    *out_len = 0;
    if (fake->messages_consumed < fake->messages_needed) {
        return APPLE_AUTH_NEED_MORE;
    }
    memcpy(wrap_key, fake->wrap_key, sizeof fake->wrap_key);
    return APPLE_AUTH_AUTHENTICATED;
}

static void fake_destroy(apple_auth_ctx *ctx)
{
    apple_auth_fake *fake;
    if (ctx == NULL || ctx->impl == NULL) {
        return;
    }
    fake = (apple_auth_fake *)ctx->impl;
    rfb_secret_zero(fake->wrap_key, sizeof fake->wrap_key);
}

static const apple_auth_provider_ops fake_ops = {
    .process = fake_process,
    .destroy = fake_destroy,
};

void apple_auth_fake_init(apple_auth_fake *fake, int messages_needed,
                          const uint8_t wrap_key[16])
{
    if (fake == NULL) {
        return;
    }
    fake->messages_consumed = 0;
    fake->messages_needed = messages_needed;
    if (wrap_key != NULL) {
        memcpy(fake->wrap_key, wrap_key, sizeof fake->wrap_key);
    } else {
        memset(fake->wrap_key, 0, sizeof fake->wrap_key);
    }
}

apple_auth_ctx apple_auth_fake_ctx(apple_auth_fake *fake)
{
    apple_auth_ctx ctx;
    ctx.ops = &fake_ops;
    ctx.impl = fake;
    return ctx;
}
