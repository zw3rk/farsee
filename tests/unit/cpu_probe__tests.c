// SPDX-License-Identifier: Apache-2.0
//
// FARSEE_CPU_PROBE unit tests — env gate + counter no-ops when disabled.

#include "rfb_test.h"
#include "farsee/cpu_probe.h"

#include <stdlib.h>
#include <string.h>

RFB_TEST(cpu_probe, cpu_probe__disabled_by_default_or_zero)
{
    // Ensure a clean env for this process (parent may export FARSEE_CPU_PROBE).
    (void)unsetenv("FARSEE_CPU_PROBE");
    RFB_CHECK(!farsee_cpu_probe_enabled());

    farsee_cpu_probe *p = (farsee_cpu_probe *)calloc(1, sizeof(*p));
    RFB_CHECK(p != NULL);
    farsee_cpu_probe_begin(p, "t");
    RFB_CHECK(!p->active);
    farsee_cpu_probe_loop(p);
    farsee_cpu_probe_poll(p, 0);
    farsee_cpu_probe_recv(p, 100);
    RFB_CHECK(p->loops == 0);
    RFB_CHECK(p->poll_calls == 0);
    RFB_CHECK(p->bytes_recv == 0);

    (void)setenv("FARSEE_CPU_PROBE", "0", 1);
    RFB_CHECK(!farsee_cpu_probe_enabled());
    (void)unsetenv("FARSEE_CPU_PROBE");
    free(p);
}

RFB_TEST(cpu_probe, cpu_probe__enabled_counts_events)
{
    (void)setenv("FARSEE_CPU_PROBE", "1", 1);
    RFB_CHECK(farsee_cpu_probe_enabled());

    farsee_cpu_probe *p = (farsee_cpu_probe *)calloc(1, sizeof(*p));
    RFB_CHECK(p != NULL);
    farsee_cpu_probe_begin(p, "unit");
    RFB_CHECK(p->active);
    farsee_cpu_probe_attach(p);

    farsee_cpu_probe_loop(p);
    farsee_cpu_probe_loop(p);
    farsee_cpu_probe_poll(p, 0);
    farsee_cpu_probe_poll(p, 1);
    farsee_cpu_probe_poll(p, -1);
    farsee_cpu_probe_recv_cur(4096);
    farsee_cpu_probe_fbu_header_cur();
    farsee_cpu_probe_fbu_complete_cur();
    farsee_cpu_probe_publish_cur();
    farsee_cpu_probe_present_ok(p);
    farsee_cpu_probe_present_fail(p);
    farsee_cpu_probe_present_skip(p);

    RFB_CHECK(p->loops == 2);
    RFB_CHECK(p->poll_calls == 3);
    RFB_CHECK(p->poll_timeout == 1);
    RFB_CHECK(p->poll_ready == 1);
    RFB_CHECK(p->bytes_recv == 4096);
    RFB_CHECK(p->fbu_headers == 1);
    RFB_CHECK(p->fbu_complete == 1);
    RFB_CHECK(p->publishes == 1);
    RFB_CHECK(p->present_ok == 1);
    RFB_CHECK(p->present_fail == 1);
    RFB_CHECK(p->present_skip == 1);

    farsee_cpu_probe_detach();
    RFB_CHECK(farsee_cpu_probe_current() == NULL);

    (void)unsetenv("FARSEE_CPU_PROBE");
    free(p);
}
