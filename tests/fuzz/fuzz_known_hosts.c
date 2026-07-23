// SPDX-License-Identifier: Apache-2.0
//
// G25 fuzz target: known-hosts file parsing (threat-model T12).
//
// Writes the fuzzer input as a known-hosts file, then exercises
// known_hosts_check against it with a fixed probe fingerprint/host/port.
// The parser (fgets + sscanf + hex_to_fingerprint) must:
//   - never crash or read out of bounds on malformed lines;
//   - tolerate any byte content (NULs, overlong lines, bad hex, missing
//     fields, embedded spaces) without undefined behavior;
//   - never accept a malformed fingerprint as a match.

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

    // Write the fuzzer bytes to a temp file (unique name per process).
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

    // Probe with a fixed fingerprint (all 0xAA) and host/port. Any line
    // in the file whose hex matches all-0xAA and host matches "probehost"
    // port 5900 should yield MATCH; anything else is NOT_FOUND or MISMATCH.
    static const uint8_t probe_fp[32] = {
        0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
        0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
        0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
        0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    };
    known_hosts_result r = known_hosts_check("probehost", 5900, probe_fp, path);
    (void)r;  // any of the three results is acceptable; we only check no crash.

    // Also probe a different host to exercise the NOT_FOUND path.
    (void)known_hosts_check("otherhost", 5901, probe_fp, path);

    // Probe a nonexistent file path — must return NOT_FOUND, not crash.
    (void)known_hosts_check("probehost", 5900, probe_fp, "/nonexistent/path/xyz");

    (void)remove(path);
    return 0;
}
