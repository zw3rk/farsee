// SPDX-License-Identifier: Apache-2.0
//
// Private dependency seam for the Apple type-33 live authenticator.

#ifndef FARSEE_SRC_RFB_APPLE_TYPE33_LIVE_INTERNAL_H
#define FARSEE_SRC_RFB_APPLE_TYPE33_LIVE_INTERNAL_H

#include "farsee/apple_type33_live.h"

typedef bool (*apple_type33_live_random_fn)(void *ctx, uint8_t *out,
                                            size_t len);

typedef struct apple_type33_live_ops {
    void *ctx;
    apple_type33_live_random_fn random_bytes;
} apple_type33_live_ops;

rfb_error apple_type33_authenticate_ex_with_allocator_and_ops(
    const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16], apple_type33_kdf_material *kdf_out,
    const char *host, uint16_t port, const char *known_hosts_path,
    bool accept_new_host, rfb_allocator *allocator,
    const apple_type33_live_ops *ops);

rfb_error apple_type36_authenticate_ex_with_allocator_and_ops(
    const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16], apple_type33_kdf_material *kdf_out,
    rfb_allocator *allocator, const apple_type33_live_ops *ops);

#endif  // FARSEE_SRC_RFB_APPLE_TYPE33_LIVE_INTERNAL_H
