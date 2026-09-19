// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple known-hosts trust.
// Stores SHA-256 SPKI fingerprints in a 0600 file scoped by host:port.
// Interactive first-use must display the fingerprint and require confirmation.
// Noninteractive mode must fail unless accept-new policy is supplied.
// A changed key must abort before credentials are sent.

#ifndef FARSEE_INCLUDE_FARSEE_KNOWN_HOSTS_H
#define FARSEE_INCLUDE_FARSEE_KNOWN_HOSTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Result of a known-hosts lookup.
typedef enum {
    KNOWN_HOSTS_NOT_FOUND = 0,   // first use — ask the user
    KNOWN_HOSTS_MATCH = 1,       // fingerprint matches — proceed
    KNOWN_HOSTS_MISMATCH = 2,    // fingerprint changed — abort!
} known_hosts_result;

// Check a server's SPKI fingerprint against the known-hosts file.
// `host` and `port` identify the connection. `fingerprint` is the
// SHA-256 of the server's DER SPKI (32 bytes).
// Returns KNOWN_HOSTS_MATCH if the fingerprint is already known and matches.
// Returns KNOWN_HOSTS_NOT_FOUND if this host is not in the file.
// Returns KNOWN_HOSTS_MISMATCH if the host is known but the fingerprint differs.
known_hosts_result known_hosts_check(
    const char *host, uint16_t port,
    const uint8_t fingerprint[32],
    const char *known_hosts_path);

// Add or update a host's fingerprint in the known-hosts file.
// Creates the file with mode 0600 if it does not exist.
// Returns true on success.
bool known_hosts_add(
    const char *host, uint16_t port,
    const uint8_t fingerprint[32],
    const char *known_hosts_path);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_KNOWN_HOSTS_H
