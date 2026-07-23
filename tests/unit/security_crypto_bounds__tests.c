// SPDX-License-Identifier: Apache-2.0
//
// G25 — crypto-bound security regression tests: PBKDF2 DoS cap, SRP parameter
// abuse, and host-key TOFU defense (goals.md G25, threat-model T3, T4, T12).
//
// Proves:
//   - PBKDF2 iteration cap rejects a malicious server's huge iteration count;
//   - the RSA SPKI fingerprint is deterministic (TOFU relies on it);
//   - known-hosts first-use returns NOT_FOUND, match returns MATCH, changed
//     key returns MISMATCH (the abort-before-credentials defense);
//   - the known_hosts file is created with mode 0600;
//   - constant-time compare agrees on equal and disagrees on unequal.

#include "rfb_test.h"
#include "farsee/apple_type33.h"
#include "farsee/apple_crypto.h"
#include "farsee/known_hosts.h"
#include "farsee/secret.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static const char *kh_path_g25 = "/tmp/farsee_g25_known_hosts";

static void kh_cleanup_g25(void)
{
    unlink(kh_path_g25);
}

// --- PBKDF2 iteration cap (DoS defense, T3) ------------------------------

RFB_TEST(g25_crypto, pbkdf2__iteration_cap_rejects_malicious_server) {
    static const uint8_t secret[16] = {
        's','e','c','r','e','t','-','v','a','l','u','e','-','x','x','x' };
    static const uint8_t salt[16] = {
        's','a','l','t','-','v','a','l','u','e','-','y','y','y','y','y' };
    uint8_t out[APPLE33_KEY_SIZE];

    // A reasonable iteration count succeeds.
    RFB_CHECK(apple33_derive_session_key(secret, sizeof secret,
                                         salt, sizeof salt, 1000, out));

    // A count at exactly the cap is still allowed.
    RFB_CHECK(apple33_derive_session_key(secret, sizeof secret,
                                         salt, sizeof salt,
                                         APPLE33_PBKDF2_MAX_ITERATIONS, out));

    // One above the cap must be rejected (DoS defense).
    RFB_CHECK(!apple33_derive_session_key(secret, sizeof secret,
                                          salt, sizeof salt,
                                          APPLE33_PBKDF2_MAX_ITERATIONS + 1u, out));

    // A truly hostile value (e.g. UINT32_MAX) must be rejected.
    RFB_CHECK(!apple33_derive_session_key(secret, sizeof secret,
                                          salt, sizeof salt, 0xFFFFFFFFu, out));
}

// --- SPKI fingerprint determinism (TOFU relies on this, T12) ------------

RFB_TEST(g25_crypto, fingerprint__deterministic_for_same_spki) {
    static const uint8_t spki[64] = { 0x30, 0x3e, 0x01 };  // synthetic
    uint8_t fp1[32], fp2[32];
    rfb_crypto_spki_fingerprint(spki, sizeof spki, fp1);
    rfb_crypto_spki_fingerprint(spki, sizeof spki, fp2);
    RFB_CHECK_MEM_EQ(fp1, fp2, 32);

    // Different SPKI → different fingerprint (overwhelmingly likely).
    uint8_t spki2[64];
    memcpy(spki2, spki, sizeof spki);
    spki2[0] ^= 0xFF;
    uint8_t fp3[32];
    rfb_crypto_spki_fingerprint(spki2, sizeof spki2, fp3);
    // At least one byte differs.
    bool diff = false;
    for (int i = 0; i < 32; i++) {
        if (fp1[i] != fp3[i]) { diff = true; break; }
    }
    RFB_CHECK(diff);
}

// --- Constant-time compare (cryptographic equality) ---------------------

RFB_TEST(g25_crypto, ct_eq__equal_bytes_true_unequal_false) {
    static const uint8_t a[16] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                                   0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00 };
    static const uint8_t b[16] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                                   0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00 };
    RFB_CHECK(rfb_crypto_ct_eq(a, b, 16));
    uint8_t c[16];
    memcpy(c, b, 16);
    c[15] ^= 0x01;
    RFB_CHECK(!rfb_crypto_ct_eq(a, c, 16));
    // Single-byte equal.
    RFB_CHECK(rfb_crypto_ct_eq(a, a, 1));
}

// --- Known-hosts TOFU lifecycle (T12) -----------------------------------

RFB_TEST(g25_crypto, hostkey__first_use_returns_not_found) {
    kh_cleanup_g25();
    static const uint8_t fp[32] = { 0xAA };
    RFB_CHECK_EQ_INT(
        known_hosts_check("g25host", 5900, fp, kh_path_g25),
        KNOWN_HOSTS_NOT_FOUND);
    kh_cleanup_g25();
}

RFB_TEST(g25_crypto, hostkey__add_then_match) {
    kh_cleanup_g25();
    static const uint8_t fp[32] = { 0xBB };
    RFB_CHECK(known_hosts_add("g25host", 5900, fp, kh_path_g25));
    RFB_CHECK_EQ_INT(
        known_hosts_check("g25host", 5900, fp, kh_path_g25),
        KNOWN_HOSTS_MATCH);
    kh_cleanup_g25();
}

RFB_TEST(g25_crypto, hostkey__changed_key_returns_mismatch) {
    // This is the core TOFU defense: a changed fingerprint must NOT match,
    // so the client aborts before sending credentials.
    kh_cleanup_g25();
    static const uint8_t fp_orig[32] = { 0xCC };
    static const uint8_t fp_evil[32] = { 0xDD };
    RFB_CHECK(known_hosts_add("g25host2", 5900, fp_orig, kh_path_g25));
    RFB_CHECK_EQ_INT(
        known_hosts_check("g25host2", 5900, fp_evil, kh_path_g25),
        KNOWN_HOSTS_MISMATCH);
    kh_cleanup_g25();
}

RFB_TEST(g25_crypto, hostkey__different_port_is_distinct) {
    kh_cleanup_g25();
    static const uint8_t fp[32] = { 0xEE };
    RFB_CHECK(known_hosts_add("g25host3", 5900, fp, kh_path_g25));
    // Same host, different port → NOT_FOUND (distinct trust scoping).
    RFB_CHECK_EQ_INT(
        known_hosts_check("g25host3", 5901, fp, kh_path_g25),
        KNOWN_HOSTS_NOT_FOUND);
    kh_cleanup_g25();
}

RFB_TEST(g25_crypto, hostkey__file_created_with_mode_0600) {
    kh_cleanup_g25();
    static const uint8_t fp[32] = { 0x12 };
    RFB_CHECK(known_hosts_add("g25mode", 5900, fp, kh_path_g25));

    struct stat st;
    RFB_CHECK_EQ_INT(stat(kh_path_g25, &st), 0);
    // Mode must be 0600 (owner read/write only) — the file holds fingerprints.
    RFB_CHECK_EQ_UINT(st.st_mode & 0777, 0600u);
    kh_cleanup_g25();
}

RFB_TEST(g25_crypto, hostkey__null_inputs_fail_closed) {
    kh_cleanup_g25();
    static const uint8_t fp[32] = { 0x00 };
    // NULL host/path/fingerprint must fail closed (MISMATCH, never silently
    // NOT_FOUND which could be misread as "safe to proceed"). This is the
    // defense: a programming error must never authorize credential send.
    known_hosts_result r1 = known_hosts_check(NULL, 5900, fp, kh_path_g25);
    known_hosts_result r2 = known_hosts_check("h", 5900, fp, NULL);
    known_hosts_result r3 = known_hosts_check("h", 5900, NULL, kh_path_g25);
    RFB_CHECK_EQ_INT(r1, KNOWN_HOSTS_MISMATCH);
    RFB_CHECK_EQ_INT(r2, KNOWN_HOSTS_MISMATCH);
    RFB_CHECK_EQ_INT(r3, KNOWN_HOSTS_MISMATCH);
    kh_cleanup_g25();
}
