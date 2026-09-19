// SPDX-License-Identifier: Apache-2.0
//
// Private dependency seam for the Apple type-33 connect state machine.

#ifndef FARSEE_SRC_RFB_APPLE_TYPE33_CONNECT_INTERNAL_H
#define FARSEE_SRC_RFB_APPLE_TYPE33_CONNECT_INTERNAL_H

#include "farsee/apple_type33_connect.h"
#include "farsee/apple_type33_live.h"

typedef rfb_error (*apple_type33_connect_authenticate_fn)(
    void *ctx, uint8_t selected_type, const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16], apple_type33_kdf_material *kdf_out,
    const char *host, uint16_t port, const char *known_hosts_path,
    bool accept_new_host, rfb_allocator *allocator);

typedef bool (*apple_type33_connect_random_fn)(void *ctx, uint8_t *out,
                                               size_t len);

typedef struct apple_type33_connect_ops {
    void *ctx;
    apple_type33_connect_authenticate_fn authenticate;
    apple_type33_connect_random_fn random_bytes;
} apple_type33_connect_ops;

rfb_error apple_type33_connect_with_ops(
    rfb_io_pump *pump, rfb_session_config *cfg,
    const apple_type33_connect_hooks *hooks,
    uint8_t wrap_key_out[16], bool *has_wrap_key_out,
    rfb_session_dialect *dialect_out, uint8_t *sk32_out,
    const apple_type33_connect_ops *ops);

#endif  // FARSEE_SRC_RFB_APPLE_TYPE33_CONNECT_INTERNAL_H
