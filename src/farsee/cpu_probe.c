// SPDX-License-Identifier: Apache-2.0
//
// farsee — env-gated per-thread CPU / loop probe.

#include "farsee/cpu_probe.h"
#include "farsee/binary_id.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#ifndef FARSEE_CPU_PROBE_INTERVAL_MS
#define FARSEE_CPU_PROBE_INTERVAL_MS 2000u
#endif

static _Thread_local farsee_cpu_probe *tls_probe = NULL;

static uint64_t wall_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static double thread_cpu_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t) != 0) {
        return -1.0;
    }
    return (double)t.tv_sec * 1000.0 + (double)t.tv_nsec / 1.0e6;
}

bool farsee_cpu_probe_enabled(void)
{
    const char *e = getenv("FARSEE_CPU_PROBE");
    if (e == NULL || e[0] == '\0') {
        return false;
    }
    if (e[0] == '0' && e[1] == '\0') {
        return false;
    }
    return true;
}

void farsee_cpu_probe_begin(farsee_cpu_probe *p, const char *name)
{
    if (p == NULL) {
        return;
    }
    memset(p, 0, sizeof(*p));
    p->name = (name != NULL) ? name : "?";
    p->active = farsee_cpu_probe_enabled();
    if (!p->active) {
        return;
    }
    p->wall0_ms = wall_ms();
    p->cpu0_ms = thread_cpu_ms();
    p->prev_cpu_ms = p->cpu0_ms;
    p->last_report_ms = p->wall0_ms;
    p->prev_minflt = 0;
    p->have_prev_rusage = false;
}

void farsee_cpu_probe_attach(farsee_cpu_probe *p)
{
    tls_probe = p;
}

void farsee_cpu_probe_detach(void)
{
    tls_probe = NULL;
}

farsee_cpu_probe *farsee_cpu_probe_current(void)
{
    return tls_probe;
}

static void probe_maybe_report(farsee_cpu_probe *p)
{
    if (p == NULL || !p->active) {
        return;
    }
    const uint64_t now = wall_ms();
    if (now < p->last_report_ms + (uint64_t)FARSEE_CPU_PROBE_INTERVAL_MS) {
        return;
    }
    const uint64_t dwall = now - p->last_report_ms;
    if (dwall == 0u) {
        return;
    }
    const double cpu_now = thread_cpu_ms();
    double dcpu_win = -1.0;
    if (cpu_now >= 0.0 && p->prev_cpu_ms >= 0.0) {
        dcpu_win = cpu_now - p->prev_cpu_ms;
    }
    if (cpu_now >= 0.0) {
        p->prev_cpu_ms = cpu_now;
    }

    const double sec = (double)dwall / 1000.0;
    // core=1.0 means this thread used 100% of one core over the window.
    const double core_frac =
        (dcpu_win >= 0.0 && sec > 0.0) ? (dcpu_win / (sec * 1000.0)) : -1.0;

    const uint64_t d_loops = p->loops - p->prev_loops;
    const uint64_t d_poll = p->poll_calls - p->prev_poll_calls;
    const uint64_t d_pto = p->poll_timeout - p->prev_poll_timeout;
    const uint64_t d_prdy = p->poll_ready - p->prev_poll_ready;
    const uint64_t d_rx = p->bytes_recv - p->prev_bytes_recv;
    const uint64_t d_hdr = p->fbu_headers - p->prev_fbu_headers;
    const uint64_t d_fbu = p->fbu_complete - p->prev_fbu_complete;
    const uint64_t d_pub = p->publishes - p->prev_publishes;
    const uint64_t d_pok = p->present_ok - p->prev_present_ok;
    const uint64_t d_pfl = p->present_fail - p->prev_present_fail;
    const uint64_t d_psk = p->present_skip - p->prev_present_skip;

    long minflt = 0;
    long d_minflt = 0;
    double proc_core = -1.0;
    double proc_sys = -1.0;
    struct rusage ru;
    memset(&ru, 0, sizeof(ru));
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        minflt = ru.ru_minflt;
        const double u_ms = (double)ru.ru_utime.tv_sec * 1000.0 +
                            (double)ru.ru_utime.tv_usec / 1000.0;
        const double s_ms = (double)ru.ru_stime.tv_sec * 1000.0 +
                            (double)ru.ru_stime.tv_usec / 1000.0;
        if (p->have_prev_rusage) {
            d_minflt = minflt - p->prev_minflt;
            if (sec > 0.0) {
                const double du = u_ms - p->prev_proc_u_ms;
                const double ds = s_ms - p->prev_proc_s_ms;
                proc_core = (du + ds) / (sec * 1000.0);
                proc_sys = ds / (sec * 1000.0);
            }
        }
        p->prev_minflt = minflt;
        p->prev_proc_u_ms = u_ms;
        p->prev_proc_s_ms = s_ms;
        p->have_prev_rusage = true;
    }

    fprintf(stderr,
            "farsee.cpu_probe name=%s wall_ms=%llu core=%.3f "
            "proc_core=%.3f proc_sys=%.3f "
            "loops/s=%.0f poll/s=%.0f pto/s=%.0f prdy/s=%.0f "
            "rx_B/s=%.0f fbu_hdr/s=%.1f fbu_done/s=%.1f pub/s=%.1f "
            "pres_ok/s=%.1f pres_fail/s=%.1f pres_skip/s=%.1f minflt/s=%.0f\n",
            p->name != NULL ? p->name : "?",
            (unsigned long long)dwall, core_frac, proc_core, proc_sys,
            (double)d_loops / sec, (double)d_poll / sec, (double)d_pto / sec,
            (double)d_prdy / sec, (double)d_rx / sec, (double)d_hdr / sec,
            (double)d_fbu / sec, (double)d_pub / sec, (double)d_pok / sec,
            (double)d_pfl / sec, (double)d_psk / sec, (double)d_minflt / sec);
    (void)fflush(stderr);
    // Catch rebuild-while-running (disk inode/mtime changed under our feet).
    (void)farsee_binary_id_warn_if_stale();

    p->prev_loops = p->loops;
    p->prev_poll_calls = p->poll_calls;
    p->prev_poll_timeout = p->poll_timeout;
    p->prev_poll_ready = p->poll_ready;
    p->prev_bytes_recv = p->bytes_recv;
    p->prev_fbu_headers = p->fbu_headers;
    p->prev_fbu_complete = p->fbu_complete;
    p->prev_publishes = p->publishes;
    p->prev_present_ok = p->present_ok;
    p->prev_present_fail = p->present_fail;
    p->prev_present_skip = p->present_skip;
    p->last_report_ms = now;
}

void farsee_cpu_probe_loop(farsee_cpu_probe *p)
{
    if (p == NULL || !p->active) {
        return;
    }
    p->loops++;
    probe_maybe_report(p);
}

void farsee_cpu_probe_poll(farsee_cpu_probe *p, int pr)
{
    if (p == NULL || !p->active) {
        return;
    }
    p->poll_calls++;
    if (pr == 0) {
        p->poll_timeout++;
    } else if (pr > 0) {
        p->poll_ready++;
    }
}

void farsee_cpu_probe_recv(farsee_cpu_probe *p, size_t n)
{
    if (p == NULL || !p->active || n == 0u) {
        return;
    }
    p->bytes_recv += (uint64_t)n;
}

void farsee_cpu_probe_fbu_header(farsee_cpu_probe *p)
{
    if (p == NULL || !p->active) {
        return;
    }
    p->fbu_headers++;
}

void farsee_cpu_probe_fbu_complete(farsee_cpu_probe *p)
{
    if (p == NULL || !p->active) {
        return;
    }
    p->fbu_complete++;
}

void farsee_cpu_probe_publish(farsee_cpu_probe *p)
{
    if (p == NULL || !p->active) {
        return;
    }
    p->publishes++;
}

void farsee_cpu_probe_present_ok(farsee_cpu_probe *p)
{
    if (p == NULL || !p->active) {
        return;
    }
    p->present_ok++;
}

void farsee_cpu_probe_present_fail(farsee_cpu_probe *p)
{
    if (p == NULL || !p->active) {
        return;
    }
    p->present_fail++;
}

void farsee_cpu_probe_present_skip(farsee_cpu_probe *p)
{
    if (p == NULL || !p->active) {
        return;
    }
    p->present_skip++;
}

void farsee_cpu_probe_recv_cur(size_t n)
{
    farsee_cpu_probe_recv(tls_probe, n);
}

void farsee_cpu_probe_fbu_header_cur(void)
{
    farsee_cpu_probe_fbu_header(tls_probe);
}

void farsee_cpu_probe_fbu_complete_cur(void)
{
    farsee_cpu_probe_fbu_complete(tls_probe);
}

void farsee_cpu_probe_publish_cur(void)
{
    farsee_cpu_probe_publish(tls_probe);
}

void farsee_cpu_probe_poll_cur(int pr)
{
    farsee_cpu_probe_poll(tls_probe, pr);
}
