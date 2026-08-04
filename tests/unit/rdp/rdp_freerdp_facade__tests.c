// SPDX-License-Identifier: Apache-2.0
//
// R0 — FreeRDP facade smoke test (§22/R0 exit criterion).
//
// "A minimal test program creates and destroys a FreeRDP context through
// the Farsee-private facade under sanitizers." This is that test. It is
// compiled ONLY under FARSEE_WITH_RDP=1; in the no-RDP build the file is
// empty (no RFB_TEST entries), so the no-RDP CI row stays green.
//
// SANITIZER NOTE (ADR-0006): on macOS 26, loading FreeRDP's dynamic library
// under AddressSanitizer deadlocks during dyld initialization (same class
// of issue as the documented nix-LLVM ASan deadlock). Apple Clang's ASan
// is affected too for this particular complex dylib. Therefore the tests
// that exercise FreeRDP at runtime skip themselves on darwin under a
// sanitizer; the version check (no runtime FreeRDP call) still runs. The
// full create/destroy-under-sanitizers evidence is produced on the Linux
// sanitizer CI row, where FreeRDP loads cleanly.

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_freerdp_facade.h"
#include "tests/test_framework/rfb_test.h"

RFB_TEST(rdp_facade, freerdp_version__is_pinned_3x)
{
    // §15.3: fail configuration when the pinned API version is not present.
    RFB_CHECK(rdp_freerdp_version_ok());
    const char *v = rdp_freerdp_version_string();
    RFB_CHECK(v != NULL);
    RFB_CHECK(v[0] == '3');
}

RFB_TEST(rdp_facade, library_log_level__set_all_levels_no_crash)
{
    // Quiet default + every explicit level must be safe before/after create.
    rdp_freerdp_set_library_log_level(RDP_LIBLOG_OFF);
    rdp_freerdp_set_library_log_level(RDP_LIBLOG_ERROR);
    rdp_freerdp_set_library_log_level(RDP_LIBLOG_WARN);
    rdp_freerdp_set_library_log_level(RDP_LIBLOG_INFO);
    rdp_freerdp_set_library_log_level(RDP_LIBLOG_DEBUG);
    rdp_freerdp_set_library_log_level(RDP_LIBLOG_TRACE);
    rdp_freerdp_set_library_log_level(RDP_LIBLOG_OFF);
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    rdp_freerdp_set_library_log_level(RDP_LIBLOG_DEBUG);
    rdp_freerdp_destroy(&ctx);
    rdp_freerdp_set_library_log_level(RDP_LIBLOG_OFF);
}

RFB_TEST(rdp_facade, create_destroy__no_leak_under_sanitizers)
{
    // The R0 exit-criterion object: create + destroy must be clean.
    // (Built into the RDP-enabled test binary; the macOS ASan row builds
    // without FARSEE_WITH_RDP because FreeRDP's dylib deadlocks under
    // macOS ASan at dyld init — ADR-0006 class. The dev build and the
    // Linux ASan row exercise this path.)
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    rdp_freerdp_destroy(&ctx);
    RFB_CHECK(ctx == NULL);
}

RFB_TEST(rdp_facade, destroy_null__safe)
{
    rdp_freerdp_ctx *ctx = NULL;
    rdp_freerdp_destroy(&ctx);
    RFB_CHECK(ctx == NULL);
    rdp_freerdp_destroy(&ctx);  // double-destroy safe
    RFB_CHECK(ctx == NULL);
}

RFB_TEST(rdp_facade, create_many__no_resource_growth)
{
    // Create+destroy in a loop; any FreeRDP instance/context leak would
    // trip ASan leak detection at process exit.
    for (int i = 0; i < 64; ++i) {
        rdp_freerdp_ctx *ctx = rdp_freerdp_create();
        RFB_CHECK(ctx != NULL);
        rdp_freerdp_destroy(&ctx);
    }
}

#endif  // FARSEE_WITH_RDP
