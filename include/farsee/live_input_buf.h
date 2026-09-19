// SPDX-License-Identifier: Apache-2.0
//
// farsee — pure live-input work-buffer fill (no drop of unread bytes).
//
// Used by the RDP and shared live_shell demultiplexers: merge residual with
// a new chunk into a fixed work buffer without silently discarding the
// excess of `data`. Caller advances through `data` using the returned
// consumption count until all input is processed or residual is full.

#ifndef FARSEE_INCLUDE_FARSEE_LIVE_INPUT_BUF_H
#define FARSEE_INCLUDE_FARSEE_LIVE_INPUT_BUF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Fill `work` (capacity `work_cap`) from residual then from data[data_off..).
// On entry residual_len is the valid residual length; may be truncated to
// work_cap. On success:
//   *out_work_len   — bytes placed in work
//   *out_data_used  — how many bytes of data were copied (from data_off)
// Returns false on NULL work/out params or work_cap == 0.
bool farsee_live_input_fill(uint8_t *work, size_t work_cap,
                            const uint8_t *residual, size_t residual_len,
                            const uint8_t *data, size_t data_len,
                            size_t data_off, size_t *out_work_len,
                            size_t *out_data_used);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_LIVE_INPUT_BUF_H */
