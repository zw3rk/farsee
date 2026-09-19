// SPDX-License-Identifier: Apache-2.0
//
// farsee — blocking Apple security-type 36 authentication.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_TYPE36_LIVE_H
#define FARSEE_INCLUDE_FARSEE_APPLE_TYPE36_LIVE_H

#include "farsee/apple_type33_live.h"

#ifdef __cplusplus
extern "C" {
#endif

// Run the type-36 identity + SRP exchange. The function sends the security
// selector and identity frame as one branch-entry write, verifies the server
// proof, and publishes the same post-authentication key material as type 33.
rfb_error apple_type36_authenticate_ex_with_allocator(
    const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16], apple_type33_kdf_material *kdf_out,
    rfb_allocator *allocator);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_TYPE36_LIVE_H
