// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple encrypted record layer.
//
// Independent of sockets and presenters. Driven only by bounded byte spans.
// Accepts caller-supplied wrap keys, including fixed keys in unit tests.
// Supports AES-128-CBC record encryption and decryption, wrap-key rotation,
// sequence counters, bounded record lengths, and zeroization.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_RECORD_H
#define FARSEE_INCLUDE_FARSEE_APPLE_RECORD_H

#include "farsee/apple_crypto.h"
#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum record body size (plan.md §6.4: 256 MiB compressed-rect cap).
#define APPLE_RECORD_MAX_BODY (256u * 1024u * 1024u)

// AES-128 block size.
#define APPLE_BLOCK_SIZE 16u

// Record direction.
typedef enum {
    APPLE_DIR_DECRYPT = 0,  // server → client
    APPLE_DIR_ENCRYPT = 1,  // client → server
} apple_record_dir;

// Record-layer state for one direction. Each direction has its own
// key, IV, CBC context, and sequence counter.
typedef struct apple_record_direction {
    uint8_t content_key[APPLE_BLOCK_SIZE];
    uint8_t iv[APPLE_BLOCK_SIZE];
    rfb_crypto_cbc_ctx *cbc;
    uint64_t sequence;
    bool active;
} apple_record_direction;

// Full record-layer state (both directions).
typedef struct apple_record_layer {
    apple_record_direction decrypt;  // server → client
    apple_record_direction encrypt;  // client → server
    uint8_t wrap_key[APPLE_BLOCK_SIZE];  // current wrap key (AES-128-ECB unwrap)
    uint8_t next_wrap_key[APPLE_BLOCK_SIZE];  // set by rekey
    bool initialized;
} apple_record_layer;

// Initialize the record layer with a caller-supplied wrap key.
void apple_record_init(apple_record_layer *rl, const uint8_t wrap_key[APPLE_BLOCK_SIZE]);

// Set the content key and IV for a direction (derived from the wrap key
// by the caller or by the rekey process).
bool apple_record_set_direction(apple_record_layer *rl, apple_record_dir dir,
                                const uint8_t key[APPLE_BLOCK_SIZE],
                                const uint8_t iv[APPLE_BLOCK_SIZE]);

// First enable from a cleartext 0x044f setup payload:
// unwrap two 16-byte blocks via AES-128-ECB with the current wrap key
// (block0 → content key, block1 → IV) and install them for `dir`.
// Does **not** rotate wrap_key (unlike rekey). Works when the direction
// is still inactive — this is the initial post-auth key install.
bool apple_record_enable_wrapped(apple_record_layer *rl, apple_record_dir dir,
                                 const uint8_t wrapped_key[APPLE_BLOCK_SIZE],
                                 const uint8_t wrapped_iv[APPLE_BLOCK_SIZE]);

// Rekey: unwrap two 16-byte blocks via AES-128-ECB using the current
// wrap key. Block 0 → new content key; Block 1 → new IV. Atomically
// install the new key/IV and rotate the wrap key to next_wrap_key.
// Returns false if the direction is not active (never partially activates).
bool apple_record_rekey(apple_record_layer *rl, apple_record_dir dir,
                        const uint8_t wrapped_key[APPLE_BLOCK_SIZE],
                        const uint8_t wrapped_iv[APPLE_BLOCK_SIZE],
                        const uint8_t new_wrap_key[APPLE_BLOCK_SIZE]);

// Decrypt one nonempty record whose length is a multiple of 16 bytes.
// The provider processes complete blocks with padding disabled.
// Returns RFB_ERR_PROTOCOL for invalid length or provider failure, and
// RFB_ERR_LIMIT for oversize input or an undersized output buffer.
rfb_error apple_record_decrypt(apple_record_layer *rl,
                               const uint8_t *ciphertext, size_t ct_len,
                               uint8_t *plaintext, size_t pt_cap, size_t *pt_len);

// Encrypt one record. Input must be padded to 16-byte boundary by caller.
// Returns RFB_OK or an error.
rfb_error apple_record_encrypt(apple_record_layer *rl,
                               const uint8_t *plaintext, size_t pt_len,
                               uint8_t *ciphertext, size_t ct_cap, size_t *ct_len);

// Release all resources. Zeroizes all keys, IVs, and CBC contexts.
void apple_record_destroy(apple_record_layer *rl);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_RECORD_H
