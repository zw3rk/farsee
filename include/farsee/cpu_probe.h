// SPDX-License-Identifier: Apache-2.0
//
// farsee — env-gated per-thread CPU / loop probe (type-33 live peg diagnosis).
//
// Enable with FARSEE_CPU_PROBE=1. Each thread that attaches a probe emits a
// single stderr line every ~2 s with:
//   - thread CPU fraction of a core (CLOCK_THREAD_CPUTIME_ID / wall)
//   - loop iterations/s (spin: 1e5–1e6; paced: ~30–60)
//   - poll calls/s, poll timeouts (pr==0), poll ready (pr>0)
//   - protocol: recv B/s, FBU headers/s, FBU complete/s, publishes/s
//   - present: ok/s, fail/s
//   - process: ru_minflt delta/s (page faults — 4K SHM path)
//
// No behaviour change when the env var is unset/empty/"0".

#ifndef FARSEE_CPU_PROBE_H
#define FARSEE_CPU_PROBE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct farsee_cpu_probe farsee_cpu_probe;

// True iff FARSEE_CPU_PROBE is set to a non-empty value other than "0".
bool farsee_cpu_probe_enabled(void);

// Zero `p` and set name (not copied — must outlive the probe). No-op if
// probing is disabled; still safe to call the record helpers.
void farsee_cpu_probe_begin(farsee_cpu_probe *p, const char *name);

// Attach/detach as the current thread's probe so deep call sites
// (session_read_some, publish) can record without plumbing a pointer.
void farsee_cpu_probe_attach(farsee_cpu_probe *p);
void farsee_cpu_probe_detach(void);
farsee_cpu_probe *farsee_cpu_probe_current(void);

// Call once per loop iteration; may emit a report line.
void farsee_cpu_probe_loop(farsee_cpu_probe *p);

// Record a poll() result (pr is the poll return value; <0 ignored for ready).
void farsee_cpu_probe_poll(farsee_cpu_probe *p, int pr);

// Protocol-side counters (no-op if p or current is NULL / disabled).
void farsee_cpu_probe_recv(farsee_cpu_probe *p, size_t n);
void farsee_cpu_probe_fbu_header(farsee_cpu_probe *p);
void farsee_cpu_probe_fbu_complete(farsee_cpu_probe *p);
void farsee_cpu_probe_publish(farsee_cpu_probe *p);

// Present-side counters.
void farsee_cpu_probe_present_ok(farsee_cpu_probe *p);
void farsee_cpu_probe_present_fail(farsee_cpu_probe *p);
// Same generation re-acquired (intentional skip, not a failure/spin).
void farsee_cpu_probe_present_skip(farsee_cpu_probe *p);

// Convenience: record on the attached TLS probe if any.
void farsee_cpu_probe_recv_cur(size_t n);
void farsee_cpu_probe_fbu_header_cur(void);
void farsee_cpu_probe_fbu_complete_cur(void);
void farsee_cpu_probe_publish_cur(void);
void farsee_cpu_probe_poll_cur(int pr);

// Opaque storage (stack-allocatable). Size is ABI-stable for this file.
struct farsee_cpu_probe {
    const char *name;
    uint64_t wall0_ms;
    double cpu0_ms;
    uint64_t last_report_ms;
    uint64_t loops;
    uint64_t poll_calls;
    uint64_t poll_timeout;  // pr == 0
    uint64_t poll_ready;    // pr > 0
    uint64_t bytes_recv;
    uint64_t fbu_headers;
    uint64_t fbu_complete;
    uint64_t publishes;
    uint64_t present_ok;
    uint64_t present_fail;
    uint64_t present_skip;
    // Snapshot at last report (for deltas).
    uint64_t prev_loops;
    uint64_t prev_poll_calls;
    uint64_t prev_poll_timeout;
    uint64_t prev_poll_ready;
    uint64_t prev_bytes_recv;
    uint64_t prev_fbu_headers;
    uint64_t prev_fbu_complete;
    uint64_t prev_publishes;
    uint64_t prev_present_ok;
    uint64_t prev_present_fail;
    uint64_t prev_present_skip;
    long prev_minflt;
    double prev_cpu_ms;  // thread CPU at last report (for window fraction)
    // Process-wide (RUSAGE_SELF) — distinguishes "farsee busy" from "kitty".
    double prev_proc_u_ms;
    double prev_proc_s_ms;
    bool active;
    bool have_prev_rusage;
};

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_CPU_PROBE_H */
