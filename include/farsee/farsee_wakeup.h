// SPDX-License-Identifier: Apache-2.0
//
// Farsee wakeup primitive.
//
// A reactor wakeup lets another thread (e.g. a confined worker, §8.3)
// interrupt a reactor blocked in farsee_reactor_tick without exposing a
// raw fd to callers. On POSIX it is a self-pipe (portable) or eventfd
// (Linux); the chosen mechanism is private to the implementation.
//
// Opaque: callers hold a farsee_wakeup pointer, never the underlying fd.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_WAKEUP_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_WAKEUP_H

#include "farsee/farsee_reactor.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque wakeup primitive.
typedef struct farsee_wakeup farsee_wakeup;

// Create a wakeup. The caller registers it with a reactor via
// farsee_wakeup_register to receive callbacks when signaled. Returns NULL
// on allocation/init failure.
farsee_wakeup *farsee_wakeup_create(void);

// Destroy the wakeup. Safe on NULL. Closes underlying resources.
void farsee_wakeup_destroy(farsee_wakeup **w);

// Register the wakeup with a reactor. When signaled, `cb` fires with
// FARSEE_REACTOR_READ. Returns a reactor token or INVALID on failure.
farsee_reactor_token farsee_wakeup_register(farsee_wakeup *w,
                                            farsee_reactor *r,
                                            farsee_reactor_cb cb,
                                            void *user);

// Signal the wakeup from any thread. Safe to call concurrently with the
// reactor tick on another thread. Returns false on I/O failure. Repeated
// signals coalesce.
bool farsee_wakeup_signal(farsee_wakeup *w);

// Acknowledge/consume a pending wakeup. Called from within the reactor
// callback before re-arming. Returns false if nothing was pending.
bool farsee_wakeup_consume(farsee_wakeup *w);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_WAKEUP_H
