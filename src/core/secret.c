// SPDX-License-Identifier: Apache-2.0
//
// farsee — compiler-resistant secret zeroization (plan.md §G1, §6.3).
//
// The trick: assign through a pointer-to-volatile so the compiler cannot
// prove the store is dead (it must assume an external observer can read
// the volatile target). We also use a non-inline function boundary so the
// optimizer does not propagate "this was about to be freed anyway" into
// eliding the zeroing.

#include "farsee/secret.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// The sink function is deliberately non-inline and uses volatile.
static void zero_impl(volatile uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        p[i] = 0;
    }
}

void rfb_secret_zero(void *buf, size_t n)
{
    if (buf == NULL || n == 0) {
        return;
    }
    // Also use memset_explicit-like behavior through a volatile barrier.
    // The volatile cast ensures the byte writes happen even if the
    // compiler would otherwise remove them as dead stores.
    zero_impl((volatile uint8_t *)buf, n);
}

// Note: handshake set_password uses rfb_secret_zero (not memset).

size_t rfb_secret_trunc_vnc8(void *buf, size_t len, size_t buf_cap)
{
    if (buf == NULL || buf_cap == 0u) {
        return 0u;
    }
    if (len <= 8u) {
        return len;
    }
    // Zero everything past the first 8 bytes (including any trailing NUL
    // region) so a later free of the allocation cannot leak the tail.
    if (buf_cap > 8u) {
        rfb_secret_zero((uint8_t *)buf + 8u, buf_cap - 8u);
    }
    // Re-NUL-terminate at the new logical end when capacity allows.
    if (buf_cap > 8u) {
        ((uint8_t *)buf)[8] = 0u;
    }
    return 8u;
}

void rfb_secret_wipe_free(void *buf, size_t buf_cap)
{
    if (buf == NULL) {
        return;
    }
    if (buf_cap > 0u) {
        rfb_secret_zero(buf, buf_cap);
    }
    free(buf);
}
