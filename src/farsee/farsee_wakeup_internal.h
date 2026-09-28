// SPDX-License-Identifier: Apache-2.0
//
// Private dependency seam for deterministic wakeup write tests.

#ifndef FARSEE_SRC_FARSEE_FARSEE_WAKEUP_INTERNAL_H
#define FARSEE_SRC_FARSEE_FARSEE_WAKEUP_INTERNAL_H

#include "farsee/farsee_wakeup.h"

#include <stddef.h>
#include <sys/types.h>

typedef ssize_t (*farsee_wakeup_write_fn)(void *context, int fd,
                                          const void *buffer, size_t length);

bool farsee_wakeup_signal_with_writer(farsee_wakeup *w,
                                      farsee_wakeup_write_fn write_fn,
                                      void *context);

#endif  // FARSEE_SRC_FARSEE_FARSEE_WAKEUP_INTERNAL_H
