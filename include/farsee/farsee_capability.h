// SPDX-License-Identifier: Apache-2.0
//
// Farsee common capability set.
//
// Capabilities are a versioned set with typed fields, not a single
// bitmask. Unsupported capabilities MUST be absent (off), never
// represented as callbacks that silently do nothing.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_CAPABILITY_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_CAPABILITY_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Typed capability identifiers. Append-only; never renumber. The set is
// sized to hold FARSEE_CAP_COUNT bits in a small fixed array (see .c).
typedef enum {
    FARSEE_CAP_DISPLAY_COUNT       = 0,
    FARSEE_CAP_MULTI_MONITOR       = 1,
    FARSEE_CAP_REMOTE_RESIZE       = 2,
    FARSEE_CAP_ABSOLUTE_POINTER    = 3,
    FARSEE_CAP_RELATIVE_POINTER    = 4,
    FARSEE_CAP_HIGH_RESOLUTION_WHEEL = 5,
    FARSEE_CAP_UNICODE_INPUT       = 6,
    FARSEE_CAP_PHYSICAL_SCANCODE_INPUT = 7,
    FARSEE_CAP_CLIPBOARD_TEXT      = 8,
    FARSEE_CAP_CLIPBOARD_RICH_FORMATS = 9,
    FARSEE_CAP_CLIPBOARD_FILES     = 10,
    FARSEE_CAP_AUDIO_PLAYBACK      = 11,
    FARSEE_CAP_AUDIO_CAPTURE       = 12,
    FARSEE_CAP_VIRTUAL_DISPLAY     = 13,
    FARSEE_CAP_HDR                 = 14,
    FARSEE_CAP_COLOR_444           = 15,
    FARSEE_CAP_REMOTE_APP          = 16,
    FARSEE_CAP_DRIVE_REDIRECTION   = 17,
    FARSEE_CAP_PRINTER_REDIRECTION = 18,
    FARSEE_CAP_SMARTCARD_REDIRECTION = 19,
    FARSEE_CAP_UDP_TRANSPORT       = 20,
    FARSEE_CAP_RECONNECT           = 21,
    FARSEE_CAP_COUNT               = 22,  // sentinel; not a capability
} farsee_capability_id;

// Fixed-size bitset. Stored as a small byte array so it has no heap
// dependency and is trivially destructible from any partial state.
typedef struct farsee_capability_set {
    unsigned char bits[(FARSEE_CAP_COUNT + 7) / 8];
} farsee_capability_set;

// Zero-initialize (all capabilities absent). Must be called once before use.
void farsee_capability_set_init(farsee_capability_set *caps);

// Get/set a capability. Out-of-range ids are rejected (return false / no-op).
bool farsee_capability_get(const farsee_capability_set *caps,
                           farsee_capability_id id);
void farsee_capability_set_set(farsee_capability_set *caps,
                               farsee_capability_id id, bool present);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_CAPABILITY_H
