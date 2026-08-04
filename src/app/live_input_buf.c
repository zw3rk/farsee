// SPDX-License-Identifier: Apache-2.0
//
// Pure residual+chunk fill for live demux (ADR-0011 / quality aggregate).

#include "farsee/live_input_buf.h"

#include <string.h>

bool farsee_live_input_fill(uint8_t *work, size_t work_cap,
                            const uint8_t *residual, size_t residual_len,
                            const uint8_t *data, size_t data_len,
                            size_t data_off, size_t *out_work_len,
                            size_t *out_data_used)
{
    if (work == NULL || work_cap == 0u || out_work_len == NULL ||
        out_data_used == NULL) {
        return false;
    }
    *out_work_len = 0;
    *out_data_used = 0;

    size_t wlen = 0;
    if (residual != NULL && residual_len > 0u) {
        size_t copy = residual_len;
        if (copy > work_cap) {
            copy = work_cap;
        }
        memcpy(work, residual, copy);
        wlen = copy;
    }

    if (data != NULL && data_off < data_len && wlen < work_cap) {
        size_t avail = data_len - data_off;
        size_t space = work_cap - wlen;
        size_t take = avail < space ? avail : space;
        memcpy(work + wlen, data + data_off, take);
        wlen += take;
        *out_data_used = take;
    }

    *out_work_len = wlen;
    return true;
}
