// SPDX-License-Identifier: Apache-2.0
//
// G25 fuzz target for known-hosts lookup.
//
// Writes bounded arbitrary bytes to a process-specific temporary pathname,
// then calls known_hosts_check with fixed fingerprints and host/port values.
// It also calls the lookup on a nonexistent pathname. The harness ignores all
// lookup results and relies on sanitizer instrumentation.

#include "farsee/known_hosts.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define FUZZ_MAX_INPUT 4096u

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > FUZZ_MAX_INPUT) {
        size = FUZZ_MAX_INPUT;
    }

    // Write the fuzzer bytes to a pathname derived from the process ID.
    char path[256];
    snprintf(path, sizeof path, "/tmp/farsee_fuzz_kh_%ld.txt", (long)getpid());
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return 0;
    }
    if (size > 0) {
        (void)fwrite(data, 1, size, f);
    }
    fclose(f);

    // Probe the generated file with a fixed all-0xAA fingerprint and fixed
    // host/port. The result is not classified.
    static const uint8_t probe_fp[32] = {
        0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
        0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
        0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
        0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    };
    known_hosts_result r = known_hosts_check("probehost", 5900, probe_fp, path);
    (void)r;  // any of the three results is acceptable; we only check no crash.

    // Probe a second host/port; ignore the result.
    (void)known_hosts_check("otherhost", 5901, probe_fp, path);

    // Probe a nonexistent pathname; ignore the result.
    (void)known_hosts_check("probehost", 5900, probe_fp, "/nonexistent/path/xyz");

    (void)remove(path);
    return 0;
}
