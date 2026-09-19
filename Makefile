# SPDX-License-Identifier: Apache-2.0
#
# farsee — self-documenting primary build driver (ADR-0006).
#
# The toolchain is provisioned by `nix develop` (see flake.nix). This
# Makefile is the single entry point for every build/test/coverage/fuzz/
# release action. Run `make help` to see the full target catalogue.
#
# Build configurations (plan.md §15.4 / ADR-0006):
#   BUILD=dev          strict-warnings dev build          (default)
#   BUILD=release      optimized release build
#   BUILD=asan-ubsan   AddressSanitizer + UBSan
#   BUILD=tsan         ThreadSanitizer (Linux acceptance only)
#   BUILD=coverage     coverage instrumentation
#   BUILD=fuzz         fuzz build (libFuzzer-style entry points)
#
# Compilers:
#   CC=clang           default on macOS (Apple Clang) and Linux (nix clang)
#   CC=gcc             real GCC via nix (Apple's gcc is an alias for clang)

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Toolchain and paths
# ---------------------------------------------------------------------------
ifeq ($(origin CC),default)
  CC          := clang
endif
AR            ?= ar
PKG_CONFIG    ?= pkg-config
PYTHON        ?= python3
GITLEAKS      ?= gitleaks

ROOT_DIR      := $(CURDIR)
SRC_DIR       := $(ROOT_DIR)/src
TEST_DIR      := $(ROOT_DIR)/tests
INCLUDE_DIR   := $(ROOT_DIR)/include
BUILD_DIR     ?= $(ROOT_DIR)/build
TOOLS_DIR     := $(ROOT_DIR)/tools

# Out-of-tree layout per build mode.
BUILD         ?= dev
BUILD_ROOT    := $(BUILD_DIR)/$(BUILD)
OBJ_DIR       := $(BUILD_ROOT)/obj
BIN_DIR       := $(BUILD_ROOT)/bin
LIB_DIR       := $(BUILD_ROOT)/lib
COVERAGE_DIR  := $(BUILD_DIR)/coverage
REPORT_DIR    := $(BUILD_ROOT)/report

INSTALL_PREFIX ?= /usr/local
INSTALL_BINDIR ?= $(INSTALL_PREFIX)/bin
INSTALL_DOCDIR ?= $(INSTALL_PREFIX)/share/doc/farsee
VERSION        ?= 0.1.0-dev
RELEASE_GATE_DIR     ?= $(BUILD_DIR)/release-gate
TSAN_GATE_DIR        ?= $(BUILD_DIR)/tsan-gate
RELEASE_STAGE        ?= $(BUILD_DIR)/release-stage/farsee-$(VERSION)
RELEASE_ARTIFACT_DIR ?= $(BUILD_DIR)/release-artifacts
RELEASE_PLATFORM     ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')-$(shell uname -m)
RELEASE_ARCHIVE      := $(RELEASE_ARTIFACT_DIR)/farsee-$(VERSION)-$(RELEASE_PLATFORM).tar.gz
RELEASE_SBOM         := $(RELEASE_ARTIFACT_DIR)/farsee-$(VERSION)-$(RELEASE_PLATFORM).spdx.json
RELEASE_NOTES        := $(RELEASE_ARTIFACT_DIR)/farsee-$(VERSION)-release-notes.md
RELEASE_CHECKSUMS    := $(RELEASE_ARTIFACT_DIR)/SHA256SUMS
HISTORY_TRACE_TIMEOUT ?= 120
SECRET_SCAN_TIMEOUT    ?= 300

# Pass release paths through Make's environment, not shell interpolation. The
# release path guard validates these values before any directory is cleared.
export FARSEE_GUARD_BUILD_DIR := $(BUILD_DIR)
export FARSEE_GUARD_RELEASE_STAGE := $(RELEASE_STAGE)
export FARSEE_GUARD_ARTIFACT_DIR := $(RELEASE_ARTIFACT_DIR)
export FARSEE_GUARD_ARCHIVE := $(RELEASE_ARCHIVE)
export FARSEE_GUARD_VERSION := $(VERSION)
export FARSEE_GUARD_PLATFORM := $(RELEASE_PLATFORM)

# ---------------------------------------------------------------------------
# Language policy: the "Curated C11" subset, no extensions (AGENTS.md
# "C programming guidelines"; plan.md §15.1, §15.3). C11 is the sole
# language target; -Werror=vla hard-enforces the VLA ban.
# ---------------------------------------------------------------------------
STD_FLAGS     := -std=c11 -pedantic

# Strict warnings (plan.md §15.2). The full set is treated as errors.
# A deliberate warning in `tests/configure/` must fail the build (G0).
STRICT_WARN   := -Wall -Wextra -Wpedantic -Werror \
                 -Wconversion -Wsign-conversion \
                 -Wshadow -Wstrict-prototypes -Wmissing-prototypes \
                 -Wold-style-definition -Wundef \
                 -Wformat=2 -Wformat-security \
                 -Wcast-align -Wcast-qual \
                 -Wwrite-strings -Wpointer-arith \
                 -Wswitch-enum -Werror=vla \
                 -fno-common

# Build-mode flags.
DEV_FLAGS     :=
RELEASE_FLAGS := -O2 -DNDEBUG
ASAN_FLAGS    := -fsanitize=address,undefined -fno-omit-frame-pointer \
                 -fno-sanitize-recover=all
TSAN_FLAGS    := -O1 -g -fsanitize=thread -fno-omit-frame-pointer
# -O1: glibc _FORTIFY_SOURCE (injected by distros/nix) requires optimization
# under -Werror; pure -O0 fails on Linux CI.
COVERAGE_FLAGS := --coverage -O1 -g -U_FORTIFY_SOURCE
# Fuzz builds must carry sanitizers: without them the harnesses could
# not observe the "no sanitizer finding" contract. On macOS the set is
# UBSan-only: nix LLVM's ASan runtime deadlocks before main on recent
# macOS (ADR-0006) and Apple
# clang ships no libFuzzer runtime — the full ASan+UBSan fuzz set runs on
# the Linux CI matrix where the runtime works.
ifeq ($(shell uname -s 2>/dev/null),Darwin)
  FUZZ_SAN := undefined
else
  FUZZ_SAN := address,undefined
endif
FUZZ_FLAGS    := -O1 -g -fsanitize=$(FUZZ_SAN) \
                 -fno-omit-frame-pointer -fno-sanitize-recover=all

# Pick the flag set for the current BUILD.
BUILD_CFLAGS  :=
BUILD_LDFLAGS :=
WLOG_DIAGNOSTIC_DEFS :=
RELEASE_POLICY_DEFS :=
WLOG_DIAGNOSTICS_BUILD :=
CAPTURE_DIAGNOSTIC_DEFS :=
CAPTURE_DIAGNOSTICS_BUILD :=
ifeq ($(BUILD),dev)
  BUILD_CFLAGS := $(DEV_FLAGS)
  WLOG_DIAGNOSTICS_BUILD := 1
  CAPTURE_DIAGNOSTICS_BUILD := 1
else ifeq ($(BUILD),release)
  ifneq ($(filter command line,$(origin WLOG_DIAGNOSTIC_DEFS)),)
    $(error WLOG_DIAGNOSTIC_DEFS cannot be overridden in release builds)
  endif
  ifneq ($(filter command line,$(origin RELEASE_POLICY_DEFS)),)
    $(error RELEASE_POLICY_DEFS cannot be overridden in release builds)
  endif
  ifneq ($(filter command line,$(origin CAPTURE_DIAGNOSTIC_DEFS)),)
    $(error CAPTURE_DIAGNOSTIC_DEFS cannot be overridden in release builds)
  endif
  ifneq ($(filter command line,$(origin CAPTURE_DIAGNOSTICS_BUILD)),)
    $(error CAPTURE_DIAGNOSTICS_BUILD cannot be overridden in release builds)
  endif
  BUILD_CFLAGS := $(RELEASE_FLAGS)
  override RELEASE_POLICY_DEFS := -DFARSEE_RELEASE_BUILD=1
else ifeq ($(BUILD),asan-ubsan)
  BUILD_CFLAGS := $(ASAN_FLAGS)
  BUILD_LDFLAGS := $(ASAN_FLAGS)
  WLOG_DIAGNOSTICS_BUILD := 1
  CAPTURE_DIAGNOSTICS_BUILD := 1
else ifeq ($(BUILD),tsan)
  BUILD_CFLAGS := $(TSAN_FLAGS)
  BUILD_LDFLAGS := $(TSAN_FLAGS)
  WLOG_DIAGNOSTICS_BUILD := 1
  CAPTURE_DIAGNOSTICS_BUILD := 1
else ifeq ($(BUILD),coverage)
  BUILD_CFLAGS := $(COVERAGE_FLAGS)
  BUILD_LDFLAGS := $(COVERAGE_FLAGS)
  WLOG_DIAGNOSTICS_BUILD := 1
  CAPTURE_DIAGNOSTICS_BUILD := 1
else ifeq ($(BUILD),fuzz)
  BUILD_CFLAGS := $(FUZZ_FLAGS)
  WLOG_DIAGNOSTICS_BUILD := 1
  CAPTURE_DIAGNOSTICS_BUILD := 1
else
  $(error Unknown BUILD='$(BUILD)'. Use one of: dev, release, asan-ubsan, tsan, coverage, fuzz.)
endif

# When CC is Apple's command-line clang (used for the macOS sanitizer
# build — see ADR-0006), it needs an explicit -isysroot to find system
# headers. The nix-wrapped compilers handle this themselves. We detect
# Apple clang by checking that CC is not the nix clang (i.e. it does not
# live under /nix/store) AND we're on Darwin.
PLATFORM_CFLAGS :=
ifeq ($(shell uname -s 2>/dev/null),Darwin)
  ifneq ($(findstring /nix/store,$(CC)),/nix/store)
    # CC is a system compiler on macOS (Apple clang via $MACOS_ASAN_CC).
    ifeq ($(findstring xcrun,$(CC)),xcrun)
      PLATFORM_CFLAGS := -isysroot $(shell xcrun --show-sdk-path 2>/dev/null)
    else ifneq ($(CC),clang)
      PLATFORM_CFLAGS := -isysroot $(shell xcrun --show-sdk-path 2>/dev/null)
    endif
  endif
endif
# Linux: expose POSIX.1-2008 (clock_gettime, etc.) under -std=c11 -pedantic.
# Without this, glibc hides CLOCK_MONOTONIC / clock_gettime as undeclared.
# struct tcp_info: file-local _DEFAULT_SOURCE in socket_posix.c only (avoid
# project-wide symbol-namespace widen under -Wshadow -Werror).
ifeq ($(shell uname -s 2>/dev/null),Linux)
  PLATFORM_CFLAGS += -D_POSIX_C_SOURCE=200809L
endif

# zlib and OpenSSL locations (filled by the nix devShell env vars; empty
# defaults let the build host's compiler find them on macOS via the SDK).
ZLIB_CFLAGS  ?=
ZLIB_LIBS    ?= -lz

# --- Crypto provider selection (ADR-0002) ---------------------------------
# macOS links CommonCrypto (always present in the SDK). Linux/cross links
# OpenSSL 3.x via RFB_USE_OPENSSL + -lcrypto. The provider TU selection is
# automatic based on the host OS so callers never choose.
UNAME_S := $(shell uname -s 2>/dev/null)
ifeq ($(UNAME_S),Darwin)
  CRYPTO_DEFS  :=
  # CommonCrypto is part of libSystem on macOS. OpenSSL remains in
  # OPENSSL_LIBS because the Apple authentication path uses it.
  CRYPTO_LIBS  :=
else
  CRYPTO_DEFS  := -DRFB_USE_OPENSSL
  CRYPTO_LIBS  := $(OPENSSL_LIBS) -lcrypto
endif

# --- RDP engine feature switch (ADR-0008) ---------------------------------
# Default ON: compile src/protocol/rdp/*.c and link FreeRDP 3.x (freerdp3
# pkg-config). The nix devShell exports FREERDP_CFLAGS / FREERDP_LIBS.
# The CI matrix covers the no-RDP binary: FARSEE_WITH_RDP=0.
FARSEE_WITH_RDP ?= 1
ifeq ($(FARSEE_WITH_RDP),1)
  RDP_SRCS    := $(wildcard $(SRC_DIR)/protocol/rdp/*.c)
  # Treat FreeRDP/WinPR include dirs as system headers so third-party
  # -Wconversion / deprecation noise does not fail our -Werror build
  # (GCC on Linux is stricter about these than Apple Clang).
  RDP_DEFS    := -DFARSEE_WITH_RDP=1 $(subst -I,$(empty)-isystem ,$(FREERDP_CFLAGS))
  RDP_LIBS    := $(FREERDP_LIBS)
else
  RDP_SRCS    :=
  RDP_DEFS    :=
  RDP_LIBS    :=
endif
empty :=

# WLog diagnostics have no effect without FreeRDP. Keep the positive define
# absent from no-RDP and release builds, even if a caller supplies the Make
# variable on the command line.
override WLOG_DIAGNOSTIC_DEFS :=
ifeq ($(WLOG_DIAGNOSTICS_BUILD),1)
  ifeq ($(FARSEE_WITH_RDP),1)
    override WLOG_DIAGNOSTIC_DEFS := -DFARSEE_ENABLE_WLOG_DIAGNOSTICS=1
  endif
endif

# Private capture schedule/control artifacts are available only in diagnostic
# build modes. The policy is independent of the optional RDP engine.
override CAPTURE_DIAGNOSTIC_DEFS :=
ifeq ($(CAPTURE_DIAGNOSTICS_BUILD),1)
  override CAPTURE_DIAGNOSTIC_DEFS := -DFARSEE_ENABLE_CAPTURE_DIAGNOSTICS=1
endif

# Aggregate flags. Defined AFTER crypto + RDP feature blocks so all the
# *_DEFS/*_LIBS variables above are already expanded (immediate :=).
# Git/build stamp for binary identity banner (stale-inode detection).
# Regenerated every build so only app/binary_id.o needs to recompile for a
# new stamp (see gen-build-id).
BUILD_ID_H := $(OBJ_DIR)/generated/build_id.h
GEN_VERSION_H := $(OBJ_DIR)/generated/farsee_build_version.h
FARSEE_SOURCE_REV ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
SOURCE_DATE_EPOCH ?= 1
export FARSEE_AUDIT_SOURCE_REV := $(FARSEE_SOURCE_REV)
export FARSEE_AUDIT_SOURCE_DATE_EPOCH := $(SOURCE_DATE_EPOCH)

COMMAND_LINE_CFLAGS := $(if $(filter command line,$(origin CFLAGS)),$(CFLAGS))
PROJECT_CFLAGS := $(STD_FLAGS) $(STRICT_WARN) $(BUILD_CFLAGS) \
                  -include $(GEN_VERSION_H) \
                  -I$(INCLUDE_DIR) -I$(SRC_DIR) -I$(TEST_DIR) \
                  -I$(TEST_DIR)/test_framework -I$(OBJ_DIR)/generated \
                  -I$(ROOT_DIR) $(PLATFORM_CFLAGS) $(CRYPTO_DEFS) \
                  $(ZLIB_CFLAGS) $(OPENSSL_CFLAGS) $(RDP_DEFS) \
                  $(WLOG_DIAGNOSTIC_DEFS) $(CAPTURE_DIAGNOSTIC_DEFS)
override CFLAGS := $(PROJECT_CFLAGS) $(COMMAND_LINE_CFLAGS) $(RELEASE_POLICY_DEFS)
override SA_CFLAGS := $(STD_FLAGS) -include $(GEN_VERSION_H) \
                      -I$(INCLUDE_DIR) -I$(SRC_DIR) \
                      $(PLATFORM_CFLAGS) $(RDP_DEFS) $(ZLIB_CFLAGS) \
                      $(WLOG_DIAGNOSTIC_DEFS) $(CAPTURE_DIAGNOSTIC_DEFS) \
                      $(RELEASE_POLICY_DEFS)
LDFLAGS := $(BUILD_LDFLAGS)
LDLIBS  := $(CRYPTO_LIBS) $(ZLIB_LIBS) $(OPENSSL_LIBS) $(RDP_LIBS) -lpthread

# ---------------------------------------------------------------------------
# Discover sources. (G0 has only the test framework + smoke test; more
# directories are added by later gates.)
# ---------------------------------------------------------------------------
CORE_SRCS     := $(wildcard $(SRC_DIR)/core/*.c)
# Farsee common layer (ADR-0010 SHARED-MT + live helpers). Full wildcard is
# the *test* link set. Product binary excludes scaffold modules (ADR-0011).
FARSEE_SRCS   := $(wildcard $(SRC_DIR)/farsee/*.c)
RFB_SRCS      := $(wildcard $(SRC_DIR)/rfb/*.c)
FB_SRCS       := $(wildcard $(SRC_DIR)/fb/*.c)
IO_SRCS       := $(wildcard $(SRC_DIR)/io/*.c)
INPUT_SRCS    := $(wildcard $(SRC_DIR)/input/*.c)
CRYPTO_SRCS   := $(wildcard $(SRC_DIR)/crypto/*.c)
TTY_SRCS      := $(wildcard $(SRC_DIR)/tty/*.c)
PRESENT_SRCS  := $(wildcard $(SRC_DIR)/present/*.c)
# APP_SRCS holds the library-grade app sources (version, config); the CLI
# entry point main.c is listed separately so it is linked only into the
# farsee binary, not the test runner.
APP_LIB_SRCS  := $(filter-out $(SRC_DIR)/app/main.c,$(wildcard $(SRC_DIR)/app/*.c))
APP_MAIN_SRC  := $(SRC_DIR)/app/main.c

# Scaffold / non-product (ADR-0011): linked into tests and fuzzers, never the
# farsee CLI. Keep this denylist as a readable cross-check for the closed
# product allowlist below.
SCAFFOLD_SRCS := \
	$(SRC_DIR)/farsee/farsee_engine.c \
	$(SRC_DIR)/farsee/farsee_reactor.c \
	$(SRC_DIR)/farsee/farsee_queue.c \
	$(SRC_DIR)/farsee/farsee_transport.c \
	$(SRC_DIR)/farsee/farsee_tls.c \
	$(SRC_DIR)/farsee/farsee_wakeup.c \
	$(SRC_DIR)/farsee/rfb_engine_adapter.c \
	$(SRC_DIR)/farsee/farsee_lifecycle.c \
	$(SRC_DIR)/farsee/farsee_capability.c \
	$(SRC_DIR)/rfb/apple_session.c \
	$(SRC_DIR)/protocol/rdp/rdp_worker.c

LIB_SRCS      := $(CORE_SRCS) $(FARSEE_SRCS) $(RFB_SRCS) $(RDP_SRCS) $(FB_SRCS) $(IO_SRCS) $(INPUT_SRCS) \
                 $(CRYPTO_SRCS) $(TTY_SRCS) $(PRESENT_SRCS) $(APP_LIB_SRCS)
LIB_OBJS      := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(LIB_SRCS))

# Optimized release tests retain private capture-control coverage through two
# test-only object variants. The release product links the ordinary objects,
# which compile without either diagnostic define.
TEST_LIB_OBJS := $(LIB_OBJS)
ifeq ($(BUILD),release)
  TEST_CAPTURE_DIAGNOSTIC_SRCS := \
	$(SRC_DIR)/rfb/rfb_session_capture.c \
	$(SRC_DIR)/rfb/rfb_session_connect.c
  TEST_CAPTURE_DIAGNOSTIC_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/test-lib/%.o,$(TEST_CAPTURE_DIAGNOSTIC_SRCS))
  TEST_LIB_OBJS := \
	$(filter-out $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(TEST_CAPTURE_DIAGNOSTIC_SRCS)),$(LIB_OBJS)) \
	$(TEST_CAPTURE_DIAGNOSTIC_OBJS)
endif

# BEGIN PRODUCT SOURCE ALLOWLIST
# Product link set: closed by default. Adding any production translation unit
# requires an explicit entry here. Test discovery remains pattern-based above
# so an unreviewed new source can be tested without silently entering farsee.
PRODUCT_CORE_SRCS := \
	$(SRC_DIR)/core/allocator.c \
	$(SRC_DIR)/core/buffer.c \
	$(SRC_DIR)/core/bytes.c \
	$(SRC_DIR)/core/checked.c \
	$(SRC_DIR)/core/error.c \
	$(SRC_DIR)/core/log.c \
	$(SRC_DIR)/core/memory_budget.c \
	$(SRC_DIR)/core/secret.c

PRODUCT_FARSEE_SRCS := \
	$(SRC_DIR)/farsee/farsee_clipboard.c \
	$(SRC_DIR)/farsee/farsee_cmd_queue.c \
	$(SRC_DIR)/farsee/farsee_display.c \
	$(SRC_DIR)/farsee/farsee_error.c \
	$(SRC_DIR)/farsee/farsee_frame_slot.c \
	$(SRC_DIR)/farsee/farsee_input.c \
	$(SRC_DIR)/farsee/farsee_mt_session.c \
	$(SRC_DIR)/farsee/farsee_presenter_v2.c \
	$(SRC_DIR)/farsee/farsee_security.c \
	$(SRC_DIR)/farsee/farsee_thread.c \
	$(SRC_DIR)/farsee/presenter_v1_adapter.c

override PRODUCT_RFB_DIAGNOSTIC_SRCS :=
ifeq ($(CAPTURE_DIAGNOSTICS_BUILD),1)
  override PRODUCT_RFB_DIAGNOSTIC_SRCS := \
	$(SRC_DIR)/rfb/rfb_capture_artifact.c \
	$(SRC_DIR)/rfb/rfb_capture_control.c
endif

# Apple support is intentional. apple_session.c is the test-only
# deterministic scaffold; the live product path is rfb_session.c.
PRODUCT_RFB_SRCS := \
	$(SRC_DIR)/rfb/apple_auth.c \
	$(SRC_DIR)/rfb/apple_input.c \
	$(SRC_DIR)/rfb/apple_mvs_bits.c \
	$(SRC_DIR)/rfb/apple_mvs_dct.c \
	$(SRC_DIR)/rfb/apple_mvs_image.c \
	$(SRC_DIR)/rfb/apple_mvs_mag.c \
	$(SRC_DIR)/rfb/apple_mvs_stream.c \
	$(SRC_DIR)/rfb/apple_postauth.c \
	$(SRC_DIR)/rfb/apple_record.c \
	$(SRC_DIR)/rfb/apple_rsa1.c \
	$(SRC_DIR)/rfb/apple_srp.c \
	$(SRC_DIR)/rfb/apple_type33.c \
	$(SRC_DIR)/rfb/apple_type33_connect.c \
	$(SRC_DIR)/rfb/apple_type33_live.c \
	$(SRC_DIR)/rfb/apple_wire_decode.c \
	$(SRC_DIR)/rfb/apple_wire_record.c \
	$(SRC_DIR)/rfb/encoding_apple_0450.c \
	$(SRC_DIR)/rfb/encoding_apple_mvs.c \
	$(SRC_DIR)/rfb/encoding_copyrect.c \
	$(SRC_DIR)/rfb/encoding_cursor_desktopsize.c \
	$(SRC_DIR)/rfb/encoding_raw.c \
	$(SRC_DIR)/rfb/encoding_zrle.c \
	$(SRC_DIR)/rfb/fbupdate.c \
	$(SRC_DIR)/rfb/handshake.c \
	$(SRC_DIR)/rfb/input.c \
	$(SRC_DIR)/rfb/pixel_convert.c \
	$(SRC_DIR)/rfb/pixel_format.c \
	$(SRC_DIR)/rfb/rfb_capture_scheduler.c \
	$(SRC_DIR)/rfb/rfb_capture_scheduler_lifecycle.c \
	$(SRC_DIR)/rfb/rfb_io_pump.c \
	$(SRC_DIR)/rfb/rfb_server_engine.c \
	$(SRC_DIR)/rfb/rfb_session.c \
	$(SRC_DIR)/rfb/rfb_session_capture.c \
	$(SRC_DIR)/rfb/rfb_session_connect.c \
	$(SRC_DIR)/rfb/rfb_session_frame.c \
	$(SRC_DIR)/rfb/rfb_session_input.c \
	$(SRC_DIR)/rfb/rfb_session_wire.c \
	$(SRC_DIR)/rfb/rsa1_envelope.c \
	$(SRC_DIR)/rfb/security_select.c \
	$(SRC_DIR)/rfb/server_init.c \
	$(SRC_DIR)/rfb/server_messages.c \
	$(SRC_DIR)/rfb/zlib_adapter.c

PRODUCT_RDP_SRCS :=
ifeq ($(FARSEE_WITH_RDP),1)
  PRODUCT_RDP_SRCS := \
	$(SRC_DIR)/protocol/rdp/rdp_callbacks.c \
	$(SRC_DIR)/protocol/rdp/rdp_callbacks_settings.c \
	$(SRC_DIR)/protocol/rdp/rdp_clipboard_bridge.c \
	$(SRC_DIR)/protocol/rdp/rdp_cliprdr.c \
	$(SRC_DIR)/protocol/rdp/rdp_display_bridge.c \
	$(SRC_DIR)/protocol/rdp/rdp_frame_slot.c \
	$(SRC_DIR)/protocol/rdp/rdp_freerdp_facade.c \
	$(SRC_DIR)/protocol/rdp/rdp_host_clipboard.c \
	$(SRC_DIR)/protocol/rdp/rdp_inj_queue.c \
	$(SRC_DIR)/protocol/rdp/rdp_input_bridge.c \
	$(SRC_DIR)/protocol/rdp/rdp_input_inject.c \
	$(SRC_DIR)/protocol/rdp/rdp_mt_session.c \
	$(SRC_DIR)/protocol/rdp/rdp_settings.c \
	$(SRC_DIR)/protocol/rdp/rdp_trust_bridge.c
endif

PRODUCT_FB_SRCS := \
	$(SRC_DIR)/fb/damage.c \
	$(SRC_DIR)/fb/framebuffer.c \
	$(SRC_DIR)/fb/pacing.c

PRODUCT_IO_SRCS := \
	$(SRC_DIR)/io/clipboard.c \
	$(SRC_DIR)/io/known_hosts.c \
	$(SRC_DIR)/io/outbound.c \
	$(SRC_DIR)/io/poller_posix.c \
	$(SRC_DIR)/io/socket_posix.c

PRODUCT_INPUT_SRCS := \
	$(SRC_DIR)/input/modifier_synth.c \
	$(SRC_DIR)/input/normalized_input.c \
	$(SRC_DIR)/input/sgr_mouse.c \
	$(SRC_DIR)/input/term_mouse_map.c

PRODUCT_CRYPTO_SRCS := \
	$(SRC_DIR)/crypto/apple_crypto.c \
	$(SRC_DIR)/crypto/crypto_commoncrypto.c \
	$(SRC_DIR)/crypto/crypto_openssl.c \
	$(SRC_DIR)/crypto/crypto_provider.c

PRODUCT_PRESENT_SRCS := \
	$(SRC_DIR)/present/base64.c \
	$(SRC_DIR)/present/kitty_protocol.c \
	$(SRC_DIR)/present/kitty_shm.c \
	$(SRC_DIR)/present/kitty_shm_table.c \
	$(SRC_DIR)/present/kitty_tile.c \
	$(SRC_DIR)/present/presenter_null.c

# Shared credential prompting is intentionally linked by both live protocols.
# Add future approved app TUs explicitly; do not restore app/*.c discovery.
PRODUCT_APP_SRCS := \
	$(SRC_DIR)/app/binary_id.c \
	$(SRC_DIR)/app/cli_args.c \
	$(SRC_DIR)/app/cli_parse.c \
	$(SRC_DIR)/app/cli_target.c \
	$(SRC_DIR)/app/core_dump_guard.c \
	$(SRC_DIR)/app/credential_acquire.c \
	$(SRC_DIR)/app/credential_prompt.c \
	$(SRC_DIR)/app/kitty_drain.c \
	$(SRC_DIR)/app/live_demux.c \
	$(SRC_DIR)/app/live_input_buf.c \
	$(SRC_DIR)/app/live_presenter.c \
	$(SRC_DIR)/app/live_signal_scope.c \
	$(SRC_DIR)/app/live_shell.c \
	$(SRC_DIR)/app/live_shell_tty_guard.c \
	$(SRC_DIR)/app/rdp_live.c \
	$(SRC_DIR)/app/rdp_live_input.c \
	$(SRC_DIR)/app/rfb_live.c \
	$(SRC_DIR)/app/rfb_live_ui.c \
	$(SRC_DIR)/app/secret_fd.c \
	$(SRC_DIR)/app/version.c

PRODUCT_LIB_SRCS := \
	$(PRODUCT_CORE_SRCS) \
	$(PRODUCT_FARSEE_SRCS) \
	$(PRODUCT_RFB_SRCS) \
	$(PRODUCT_RFB_DIAGNOSTIC_SRCS) \
	$(PRODUCT_RDP_SRCS) \
	$(PRODUCT_FB_SRCS) \
	$(PRODUCT_IO_SRCS) \
	$(PRODUCT_INPUT_SRCS) \
	$(PRODUCT_CRYPTO_SRCS) \
	$(PRODUCT_PRESENT_SRCS) \
	$(PRODUCT_APP_SRCS)
# END PRODUCT SOURCE ALLOWLIST
PRODUCT_LIB_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(PRODUCT_LIB_SRCS))

# Linux libc marks selected stdio/syscall results warn_unused_result. Keep the
# exception on the five best-effort diagnostic/output objects that
# intentionally discard them; every other object retains the global error.
ifeq ($(UNAME_S),Linux)
  UNUSED_RESULT_OK_OBJS := \
    $(OBJ_DIR)/app/rdp_live.o \
    $(OBJ_DIR)/app/rdp_live_input.o \
    $(OBJ_DIR)/app/rfb_live.o \
    $(OBJ_DIR)/app/rfb_live_ui.o \
    $(OBJ_DIR)/rfb/rfb_session.o
  $(UNUSED_RESULT_OK_OBJS): CFLAGS += -Wno-unused-result
endif

TEST_FRAMEWORK_SRCS := $(wildcard $(TEST_DIR)/test_framework/*.c)
# Unit/component sources compile independently. The generated registry holds
# their externally visible constant test records without constructors or
# linker sections, preserving deterministic discovery across platforms.
TEST_RUNNER_FRAMEWORK_OBJ := $(OBJ_DIR)/tests/test_framework/runner.o
TEST_HELPERS_OBJ := $(patsubst $(TEST_DIR)/%.c,$(OBJ_DIR)/tests/%.o,$(filter-out $(TEST_DIR)/test_framework/runner.c,$(TEST_FRAMEWORK_SRCS)))
# Test-only protocol fakes (e.g. fake_engine for F1 contract tests). Real
# helper implementations compiled as separate objects and linked into the
# runner. NOT first-party library code; never linked into the farsee binary.
TEST_FAKES_SRCS := $(wildcard $(TEST_DIR)/fakes/*.c)
TEST_FAKES_OBJ  := $(patsubst $(TEST_DIR)/%.c,$(OBJ_DIR)/tests/%.o,$(TEST_FAKES_SRCS))
TEST_CASE_SRCS  := $(wildcard $(TEST_DIR)/unit/*.c) $(wildcard $(TEST_DIR)/component/*.c)
ifeq ($(FARSEE_WITH_RDP),1)
  TEST_CASE_SRCS += $(wildcard $(TEST_DIR)/unit/rdp/*.c)
endif
TEST_CASE_OBJS := $(patsubst $(TEST_DIR)/%.c,$(OBJ_DIR)/tests/%.o,$(TEST_CASE_SRCS))

# Generated test registry (rebuilt whenever test sources change).
GEN_DIR              := $(OBJ_DIR)/generated
GEN_INCLUDE          := $(GEN_DIR)/test_includes.generated.h
GEN_REGISTRY         := $(GEN_DIR)/registry.generated.c
# The generator writes both files in one invocation. Only the registry is a
# Make target so parallel builds cannot run two writers against the same pair.
GEN_ARTIFACTS        := $(GEN_REGISTRY)
GEN_REGISTRY_OBJ     := $(GEN_DIR)/registry.generated.o

# Test runner binary.
TEST_RUNNER    := $(BIN_DIR)/farsee_tests
APP_BIN        := $(BIN_DIR)/farsee
# Integration drivers (standalone mains; not linked into the unit runner).
INTEGRATION_DRIVERS := $(BIN_DIR)/handshake_integration

# ---------------------------------------------------------------------------
# Pretty printing (respects NO_COLOR and "V=1")
# ---------------------------------------------------------------------------
ifeq ($(origin V),undefined)
  Q := @
  QUIET_CC   = @echo "  CC      $<";
  QUIET_LINK = @echo "  LINK    $@";
  QUIET_RUN  = @echo "  RUN     $@";
else
  Q :=
  QUIET_CC   :=
  QUIET_LINK :=
  QUIET_RUN  :=
endif

# ---------------------------------------------------------------------------
# Phony targets
# ---------------------------------------------------------------------------
.PHONY: help all build test test-unit test-tools cli-smoke check clean mostlyclean \
        dev release release-check release-cli no-rdp-check \
        no-rdp-release-check leak-check \
        tsan-check \
        coverage coverage-report coverage-release-report \
        fuzz fuzz-smoke fuzz-release check-license check-release-approval \
        check-release-platform \
        check-release-runtime-policy check-runtime-closure \
        check-nix-closure check-release-binary check-release-version \
        check-release-wlog-policy \
        check-secrets trace-current-check \
        trace-release-check trace-release-artifacts-check \
        history-trace-check apple-preservation-check \
        check-reproducible check-reproducible-no-rdp \
        release-stage release-artifacts release-sign \
        check-release-artifacts check-std-c11 check-warnings \
        check-static-analysis check-common-headers \
        integration \
        ci macos-acceptance rdp-interop install uninstall \
        gen-build-id gen-version-header \
        $(NULL)

# ===========================================================================
# `make help` — the self-documenting entry point
# ===========================================================================
help: ## Show this target catalogue
	@printf '\n\033[1mfarsee\033[0m — C11 RFB/VNC/RDP terminal client\n\n'
	@printf '\033[1mUsage:\033[0m\n'
	@printf '  make [target] [BUILD=<mode>] [CC=<compiler>] [V=1]\n\n'
	@printf '\033[1mBuild modes (BUILD=):\033[0m  dev (default) · release · asan-ubsan · tsan · coverage · fuzz\n'
	@printf '\033[1mCompilers (CC=):\033[0m      clang (default) · gcc\n\n'
	@printf '\033[1mTargets:\033[0m\n'
	@awk 'BEGIN {FS = ":.*?## "} \
	     /^[a-zA-Z0-9_-]+:.*?## / { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 } \
	     /^## / { sub(/^## /,""); printf "\n\033[1m%s\033[0m\n", $$0 }' $(MAKEFILE_LIST)
	@printf '\n\033[1mEnvironment:\033[0m  nix develop   (provides all compilers and libraries)\n\n'

# ===========================================================================
## Quickstart
## ---------------------------------------------------------------------------
all: build test ## Build then run the test suite (most common)

dev: ## Dev build (Clang, strict warnings) — same as plain `make build`
	$(MAKE) BUILD=dev build

release: ## Build the optimized release CLI and test runner
	$(MAKE) BUILD=release build

release-cli: ## Optimized CLI binary only (no tests) — nix packaging
	$(MAKE) BUILD=release $(BUILD_DIR)/release/bin/farsee

MACOS_ACCEPTANCE_HOST ?=
MACOS_ACCEPTANCE_BIN ?= $(BUILD_DIR)/release/bin/farsee
macos-acceptance: release-cli ## Run bounded Apple RFB checks on an authorized Mac
	@FARSEE_BIN='$(MACOS_ACCEPTANCE_BIN)' \
	  $(TOOLS_DIR)/macos_acceptance.sh '$(MACOS_ACCEPTANCE_HOST)'

RDP_INTEROP_EVIDENCE_DIR ?= $(BUILD_DIR)/rdp-interop-evidence
RDP_INTEROP_PHASE ?= baseline
rdp-interop: release-cli ## Run the authorized RDP endpoint acceptance matrix
	@FARSEE_BIN='$(BUILD_DIR)/release/bin/farsee' \
	  RDP_MATRIX_PHASE='$(RDP_INTEROP_PHASE)' \
	  $(TOOLS_DIR)/rdp_interop_matrix.sh '$(RDP_INTEROP_EVIDENCE_DIR)'

release-check: ## Build/test optimized code and apply host release policy
	$(MAKE) BUILD_DIR=$(RELEASE_GATE_DIR) BUILD=release CC=clang clean build test
	@$(RELEASE_GATE_DIR)/release/bin/farsee --version
	@$(RELEASE_GATE_DIR)/release/bin/farsee --help >/dev/null
	@$(RELEASE_GATE_DIR)/release/bin/farsee --protocol-capabilities >/dev/null
	@$(MAKE) BUILD_DIR=$(RELEASE_GATE_DIR) BUILD=release \
	  RELEASE_BINARY=$(RELEASE_GATE_DIR)/release/bin/farsee \
	  check-release-runtime-policy check-release-binary check-release-version \
	  check-release-wlog-policy trace-release-check \
	  apple-preservation-check history-trace-check

no-rdp-check: ## Build and test the supported no-FreeRDP configuration
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/no-rdp-gate BUILD=dev CC=clang \
	  FARSEE_WITH_RDP=0 clean build test

no-rdp-release-check: ## Run optimized release gates without FreeRDP
	$(MAKE) BUILD_DIR=$(BUILD_DIR) \
	  RELEASE_GATE_DIR=$(BUILD_DIR)/no-rdp-release-gate \
	  FARSEE_WITH_RDP=0 release-check

leak-check: ## Leak-enabled first-party sanitizer tests (Linux, no FreeRDP)
	@if [ "$(UNAME_S)" = "Darwin" ]; then \
	  echo "leak-check: skipped on macOS; Linux CI is authoritative"; \
	else \
	  ASAN_OPTIONS=detect_leaks=1 $(MAKE) BUILD_DIR=$(BUILD_DIR)/leak-gate \
	    BUILD=asan-ubsan CC=clang FARSEE_WITH_RDP=0 clean build test; \
	fi

tsan-check: ## ThreadSanitizer frame-slot publisher regression (Linux only)
	@if [ "$(UNAME_S)" = "Darwin" ]; then \
	  echo "tsan-check: skipped on macOS; Linux CI is authoritative"; \
	elif [ "$(UNAME_S)" != "Linux" ]; then \
	  echo "tsan-check: unsupported platform: $(UNAME_S)" >&2; \
	  exit 2; \
	else \
	  $(MAKE) BUILD_DIR=$(TSAN_GATE_DIR) BUILD=tsan CC=clang \
	    FARSEE_WITH_RDP=0 clean build && \
	  env TSAN_OPTIONS="$${TSAN_OPTIONS:+$$TSAN_OPTIONS:}halt_on_error=1:exitcode=66" \
	    $(TSAN_GATE_DIR)/tsan/bin/farsee_tests \
	      --filter farsee_slot_two_publishers__reserve_distinct_storage; \
	fi

asan-ubsan: ## Address + UBSan build and tests (Apple Clang on macOS; see ADR-0006)
	@# On macOS the nix LLVM 19/20 ASan runtime deadlocks during dyld
	@# initialization (see ADR-0006). Apple's matched runtime works. The
	@# devShell exports MACOS_ASAN_CC = absolute path to Apple's clang
	@# (discovered via xcrun with the nix PATH cleared, so xcrun does not
	@# resolve to nix's own clang). On Linux, nix clang's ASan is used.
	@# Like every other ci step, clean first so stale objects from other
	@# modes can never leak into the sanitizer run (L22).
	@if [ -n "$$MACOS_ASAN_CC" ] && [ -x "$$MACOS_ASAN_CC" ]; then \
	  echo "asan-ubsan: using Apple Clang ($$MACOS_ASAN_CC)"; \
	  $(MAKE) BUILD=asan-ubsan CC="$$MACOS_ASAN_CC" clean build test; \
	elif [ "$(shell uname -s 2>/dev/null)" = "Darwin" ]; then \
	  echo "asan-ubsan: WARNING: MACOS_ASAN_CC not set; falling back to nix clang (may hang on macOS 26)" >&2; \
	  $(MAKE) BUILD=asan-ubsan CC=clang clean build test; \
	else \
	  $(MAKE) BUILD=asan-ubsan CC=clang clean build test; \
	fi

# FreeRDP client may dlopen SDL3 at process start and abort if the library
# cannot initialize a video backend (headless CI / ASan). Prefer dummy drivers.
export SDL_VIDEODRIVER ?= dummy
export SDL_AUDIODRIVER ?= dummy

coverage: ## Coverage build
	$(MAKE) BUILD=coverage build

coverage-report: ## Aggregate gcov data and enforce tools/coverage-thresholds.tsv floors (requires BUILD=coverage)
	@if [ "$(BUILD)" != "coverage" ]; then \
	  echo "coverage-report: BUILD must be 'coverage' (got '$(BUILD)')" >&2; \
	  echo "  run: make BUILD=coverage coverage-report" >&2; \
	  exit 2; \
	fi
	@mkdir -p $(COVERAGE_DIR)
	@for source in $(sort $(PRODUCT_LIB_SRCS) $(APP_MAIN_SRC)); do \
	  printf '%s\n' "$$source"; \
	done > $(COVERAGE_DIR)/product-sources.txt
	@$(TOOLS_DIR)/coverage.sh $(BUILD_ROOT) $(COVERAGE_DIR) \
	  --sources $(COVERAGE_DIR)/product-sources.txt --enforce

coverage-release-report: ## Enforce the declared 85% line / 80% branch release policy
	@$(TOOLS_DIR)/coverage.sh --check-total \
	  $(COVERAGE_DIR)/farsee.filtered.info 85 80

# ===========================================================================
## Build
## ---------------------------------------------------------------------------
## Dev hygiene
## ---------------------------------------------------------------------------
# Always refresh git/build stamp so the next link of farsee embeds identity.
# (binary_id still prints path/inode/mtime so a long-lived process can be
# spotted as stale without blocking the rebuild.)
gen-build-id: ## Write reproducible source identity for binary_id.o
	@$(PYTHON) $(TOOLS_DIR)/gen_build_id.py $(BUILD_ID_H)

# binary_id.o must rebuild whenever the stamp is regenerated.
$(OBJ_DIR)/app/binary_id.o: gen-build-id

gen-version-header: ## Validate VERSION and generate compile-time constants
	@$(PYTHON) $(TOOLS_DIR)/gen_version_header.py $(GEN_VERSION_H)

# version.o is cheap and must rebuild when a caller changes VERSION in an
# existing build directory. Other objects wait for the forced-include header.
$(OBJ_DIR)/app/version.o: gen-version-header

build: $(APP_BIN) $(TEST_RUNNER) ## Build the CLI and the test runner

# Integration driver: standalone main that talks to a real socket.
$(BIN_DIR)/handshake_integration: $(LIB_OBJS) tests/integration/handshake_integration.c $(GEN_ARTIFACTS)
	@mkdir -p $(@D)
	$(QUIET_LINK)$(CC) $(STD_FLAGS) $(STRICT_WARN) $(BUILD_CFLAGS) \
	  -I$(INCLUDE_DIR) -I$(SRC_DIR) -I$(OBJ_DIR)/generated -I$(ROOT_DIR) \
	  $(PLATFORM_CFLAGS) $(CRYPTO_DEFS) \
	  -o $@ tests/integration/handshake_integration.c $(LIB_OBJS) $(LDLIBS)

# G5 lifecycle driver: handshake + ServerInit over the POSIX nonblocking
# adapter (the real socket path under test).
$(BIN_DIR)/lifecycle_integration: $(LIB_OBJS) tests/integration/lifecycle_integration.c $(GEN_ARTIFACTS)
	@mkdir -p $(@D)
	$(QUIET_LINK)$(CC) $(STD_FLAGS) $(STRICT_WARN) $(BUILD_CFLAGS) \
	  -I$(INCLUDE_DIR) -I$(SRC_DIR) -I$(OBJ_DIR)/generated -I$(ROOT_DIR) \
	  $(PLATFORM_CFLAGS) $(CRYPTO_DEFS) \
	  -o $@ tests/integration/lifecycle_integration.c $(LIB_OBJS) $(LDLIBS)

# Capture-only session driver: real classic RFB handshake plus the bounded
# exact-subrectangle scheduler over loopback TCP.
$(BIN_DIR)/capture_integration: $(LIB_OBJS) tests/integration/capture_integration.c $(GEN_ARTIFACTS)
	@mkdir -p $(@D)
	$(QUIET_LINK)$(CC) $(STD_FLAGS) $(STRICT_WARN) $(BUILD_CFLAGS) \
	  -I$(INCLUDE_DIR) -I$(SRC_DIR) -I$(OBJ_DIR)/generated -I$(ROOT_DIR) \
	  $(PLATFORM_CFLAGS) $(CRYPTO_DEFS) \
	  -o $@ tests/integration/capture_integration.c $(LIB_OBJS) $(LDLIBS)

# Generate the test registry before compiling the independent test objects.
#
# Feature stamp: the registry content depends on FARSEE_WITH_RDP,
# so the generated artifacts carry a stamp prerequisite that records the
# feature value. A FARSEE_WITH_RDP=0 build must not leave a feature-0
# registry behind and plain `make test` silently skipped the rdp tests.
#
# GNU make treats any prerequisite whose recipe RAN as newer than its
# dependents even when the file is untouched, so an always-running
# "write-if-changed" stamp recipe would force regeneration on every
# invocation. The comparison therefore happens at PARSE time: the stamp
# is a prerequisite of the generated artifacts (and the stale file is
# removed) ONLY when the recorded value differs. A toggle rebuilds the
# chain; an unchanged value leaves it completely untouched.
REGISTRY_STAMP      := $(GEN_DIR)/registry_features.stamp
REGISTRY_STAMP_WANT := FARSEE_WITH_RDP=$(FARSEE_WITH_RDP)
REGISTRY_STAMP_HAVE := $(shell cat $(REGISTRY_STAMP) 2>/dev/null)
REGISTRY_STAMP_PREREQ :=
ifneq ($(REGISTRY_STAMP_WANT),$(REGISTRY_STAMP_HAVE))
$(shell rm -f $(REGISTRY_STAMP))
REGISTRY_STAMP_PREREQ := $(REGISTRY_STAMP)
endif

$(REGISTRY_STAMP):
	@mkdir -p $(GEN_DIR)
	@printf '%s\n' '$(REGISTRY_STAMP_WANT)' > $@
	@echo "  GEN     registry feature stamp ($(REGISTRY_STAMP_WANT))"

gen-test-registry: $(GEN_ARTIFACTS)

$(GEN_ARTIFACTS): $(REGISTRY_STAMP_PREREQ) $(TEST_FRAMEWORK_SRCS) $(wildcard $(TEST_DIR)/unit/*.c) $(wildcard $(TEST_DIR)/unit/rdp/*.c) $(wildcard $(TEST_DIR)/component/*.c) tools/gen_test_registry.py
	@mkdir -p $(GEN_DIR)
	@echo "  GEN     test registry"
	@FARSEE_WITH_RDP=$(FARSEE_WITH_RDP) $(PYTHON) $(TOOLS_DIR)/gen_test_registry.py $(TEST_DIR) $(GEN_DIR)

$(APP_BIN): $(PRODUCT_LIB_OBJS) $(APP_MAIN_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
	@mkdir -p $(@D)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_RUNNER): $(TEST_LIB_OBJS) $(TEST_RUNNER_FRAMEWORK_OBJ) $(TEST_HELPERS_OBJ) $(TEST_FAKES_OBJ) $(TEST_CASE_OBJS) $(GEN_REGISTRY_OBJ)
	@mkdir -p $(@D)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(TEST_LIB_OBJS) $(TEST_RUNNER_FRAMEWORK_OBJ) $(TEST_HELPERS_OBJ) $(TEST_FAKES_OBJ) $(TEST_CASE_OBJS) $(GEN_REGISTRY_OBJ) $(LDLIBS)

$(GEN_REGISTRY_OBJ): $(GEN_REGISTRY) | gen-version-header
	@mkdir -p $(@D)
	$(QUIET_CC)$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Generic compile rule for src/ and tests/. The generated registry is an
# order prerequisite for test objects so discovery and feature state agree.
# -MMD -MP emit
# a make dependency fragment next to every object so editing any
# header rebuilds its dependents (included below).
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | gen-version-header
	@mkdir -p $(@D)
	$(QUIET_CC)$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(OBJ_DIR)/test-lib/%.o: $(SRC_DIR)/%.c | gen-version-header
	@mkdir -p $(@D)
	$(QUIET_CC)$(CC) $(CFLAGS) -DFARSEE_TEST_CAPTURE_DIAGNOSTICS=1 \
	  -MMD -MP -c -o $@ $<

$(OBJ_DIR)/tests/%.o: $(TEST_DIR)/%.c $(GEN_ARTIFACTS) | gen-version-header
	@mkdir -p $(@D)
	$(QUIET_CC)$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Compiler-emitted .d fragments cover every object dependency. Missing
# fragments from the first build are ignored.
DEP_OBJS := $(LIB_OBJS) $(TEST_CAPTURE_DIAGNOSTIC_OBJS) \
            $(APP_MAIN_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o) \
            $(TEST_RUNNER_FRAMEWORK_OBJ) $(TEST_HELPERS_OBJ) $(TEST_FAKES_OBJ) \
            $(TEST_CASE_OBJS) $(GEN_REGISTRY_OBJ)
-include $(DEP_OBJS:.o=.d)

# ===========================================================================
## Test
## ---------------------------------------------------------------------------
test-tools: ## Run repository tool self-tests (Python + shell)
	$(QUIET_RUN)PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s $(TEST_DIR)/tools -p 'test_*.py'
	@for t in $(TEST_DIR)/tools/test_*.sh; do \
	  echo "==> $$t"; \
	  sh "$$t" || exit 1; \
	done

cli-smoke: $(APP_BIN) ## Exercise successful and rejected CLI dispatch paths
	@$(APP_BIN) --help >/dev/null 2>&1
	@$(APP_BIN) --version >/dev/null 2>&1
	@$(APP_BIN) --protocol-capabilities >/dev/null 2>&1
	@expect_status_2() { \
	  $(APP_BIN) "$$@" >/dev/null 2>&1; status=$$?; \
	  if [ $$status -ne 2 ]; then \
	    echo "CLI rejection returned $$status: $$*" >&2; \
	    return 1; \
	  fi; \
	}; \
	expect_status_2 --farsee-invalid-option && \
	expect_status_2 && \
	expect_status_2 --protocol rdp && \
	expect_status_2 --protocol vnc --auth vnc && \
	expect_status_2 --protocol vnc --auth apple && \
	expect_status_2 --protocol vnc --cert ignore && \
	expect_status_2 --log-level info --protocol vnc && \
	expect_status_2 --protocol rdp --connect-timeout 1 127.0.0.1:1 && \
	expect_status_2 --protocol rdp --user smoke --domain local \
	  --cert ignore --presenter null --password-fd 3 \
	  --connect-timeout 1 127.0.0.1:1 3</dev/null && \
	expect_status_2 --protocol vnc --connect-timeout 1 127.0.0.1:1 && \
	expect_status_2 --protocol vnc --auth vnc --user smoke \
	  --presenter null --password-fd 3 --connect-timeout 1 \
	  127.0.0.1:1 3</dev/null && \
	expect_status_2 --protocol vnc --auth apple --password-fd 3 \
	  --connect-timeout 1 127.0.0.1:1 3</dev/null

test-unit: $(TEST_RUNNER) ## Run unit/component tests; use TEST_FILTER=name to focus
	@# FreeRDP/SDL leave third-party allocations at exit under ASan LSan;
	@# product code is still checked by ASan for UAF/OOB. Override with
	@# ASAN_OPTIONS=detect_leaks=1 for leak hunts.
	$(QUIET_RUN)env ASAN_OPTIONS="$${ASAN_OPTIONS:-detect_leaks=0}" \
	  $(TEST_RUNNER) $(TEST_ARGS)

test: build test-tools cli-smoke test-unit ## Build and run the test suite

check: test ## Alias for `test`

# Integration tests: run the Python-orchestrated scenarios that drive the
# C handshake driver against the scripted RFB server over real loopback TCP.
integration: $(BIN_DIR)/handshake_integration $(BIN_DIR)/lifecycle_integration $(BIN_DIR)/capture_integration ## Run the scripted-server integration tests
	@$(PYTHON) $(TEST_DIR)/integration/run_handshake_integration.py \
	    --driver $(BIN_DIR)/handshake_integration \
	    --server $(TEST_DIR)/integration/scripted_rfb_server.py
	@$(PYTHON) $(TEST_DIR)/integration/run_lifecycle_integration.py \
	    --driver $(BIN_DIR)/lifecycle_integration \
	    --server $(TEST_DIR)/integration/scripted_rfb_server.py
	@$(PYTHON) $(TEST_DIR)/integration/run_capture_integration.py \
	    --driver $(BIN_DIR)/capture_integration \
	    --server $(TEST_DIR)/integration/scripted_rfb_server.py

# Focused filter for the red-green-refactor loop (plan.md §13.1):
#   make test TEST_FILTER=checked
ifeq ($(strip $(TEST_FILTER)),)
TEST_ARGS :=
else
TEST_ARGS := --filter $(TEST_FILTER)
endif

# ===========================================================================
## Fuzz (G12 smoke; full campaign is `tools/fuzz_smoke.sh`)
## ---------------------------------------------------------------------------
# Each fuzz target is compiled standalone with -fsanitize=fuzzer and linked
# against the same library objects as the test runner. The list of targets
# is discovered from tests/fuzz/fuzz_*.c.
FUZZ_TARGETS := $(patsubst $(TEST_DIR)/fuzz/%.c,$(BUILD_DIR)/fuzz/bin/%,$(wildcard $(TEST_DIR)/fuzz/fuzz_*.c))

fuzz: $(FUZZ_TARGETS) ## Build fuzz targets
	@echo "Built fuzz targets: $(notdir $(FUZZ_TARGETS))"

# Compile each fuzz target standalone. -fsanitize=fuzzer supplies main();
# the library objects provide the project code under test.
# libFuzzer requires Clang (GCC does not accept -fsanitize=fuzzer).
# Plain nix clang: Apple clang has working ASan but NO libFuzzer runtime,
# and the fuzz sanitizer set is UBSan-only on macOS (see FUZZ_FLAGS), so
# the deadlock-prone nix ASan runtime is never linked into fuzz binaries.
FUZZ_CC ?= clang
# The static analyzer is a clang feature; pinned so a CC=gcc step leaking
# through MAKEFLAGS cannot reach gcc with clang-only flags.
ANALYZER_CC ?= clang
SA_JOBS ?= 4
SA_TIMEOUT ?= 120
SA_SHARD_INDEX ?= 0
SA_SHARD_COUNT ?= 1
$(BUILD_DIR)/fuzz/bin/%: $(TEST_DIR)/fuzz/%.c $(LIB_OBJS) $(GEN_ARTIFACTS)
	@mkdir -p $(@D)
	$(QUIET_LINK)$(FUZZ_CC) $(STD_FLAGS) $(STRICT_WARN) $(FUZZ_FLAGS) \
	  -fsanitize=fuzzer \
	  -I$(INCLUDE_DIR) -I$(SRC_DIR) -I$(ROOT_DIR) \
	  -o $@ $< $(LIB_OBJS) $(LDLIBS)

fuzz-smoke: ## Run each fuzz target briefly against its corpus (Clang)
	@$(MAKE) BUILD=fuzz CC=$(FUZZ_CC) fuzz
	@FUZZ_BIN=$(BUILD_DIR)/fuzz/bin FUZZ_LOG_DIR=$(BUILD_DIR)/fuzz/logs \
	  FUZZ_ARTIFACT_ROOT=$(BUILD_DIR)/fuzz/artifacts \
	  $(TOOLS_DIR)/fuzz_smoke.sh

RELEASE_FUZZ_DURATION ?= 60
fuzz-release: ## Run a sustained bounded campaign against copied corpora
	@mkdir -p $(BUILD_DIR)/fuzz-release/corpus \
	  $(BUILD_DIR)/fuzz-release/logs $(BUILD_DIR)/fuzz-release/artifacts
	@cp -R $(TEST_DIR)/fuzz/corpus/. $(BUILD_DIR)/fuzz-release/corpus/
	@$(MAKE) BUILD=fuzz CC=$(FUZZ_CC) fuzz
	@FUZZ_BIN=$(BUILD_DIR)/fuzz/bin \
	  FUZZ_CORPUS_ROOT=$(BUILD_DIR)/fuzz-release/corpus \
	  FUZZ_LOG_DIR=$(BUILD_DIR)/fuzz-release/logs \
	  FUZZ_ARTIFACT_ROOT=$(BUILD_DIR)/fuzz-release/artifacts \
	  FUZZ_DURATION=$(RELEASE_FUZZ_DURATION) $(TOOLS_DIR)/fuzz_smoke.sh

# ===========================================================================
## Static / hygiene
## ---------------------------------------------------------------------------
check-license: ## Verify SPDX headers and THIRD_PARTY_NOTICES.md
	@$(PYTHON) $(TOOLS_DIR)/check_license.py $(ROOT_DIR)

RELEASE_BINARY ?= $(BUILD_DIR)/release/bin/farsee
check-release-approval: ## Require recorded external release approvals
	@$(PYTHON) $(TOOLS_DIR)/check_release_approval.py release/approval.json \
	  --repo-root $(ROOT_DIR) --version $(VERSION)

check-release-platform: ## Require an approved release-artifact host
	@$(PYTHON) $(TOOLS_DIR)/check_release_platform.py \
	  release/dependencies.json

check-release-runtime-policy: ## Audit closure only on release-artifact hosts
	@status=0; \
	$(PYTHON) $(TOOLS_DIR)/check_release_platform.py \
	  release/dependencies.json --quiet || status=$$?; \
	case $$status in \
	  0) $(MAKE) RELEASE_BINARY=$(RELEASE_BINARY) check-runtime-closure ;; \
	  1) echo "runtime closure: skipped; this host does not publish release artifacts" ;; \
	  *) $(PYTHON) $(TOOLS_DIR)/check_release_platform.py \
	       release/dependencies.json; exit $$status ;; \
	esac

check-runtime-closure: ## Resolve and license-audit every release-linked library
	@test -x $(RELEASE_BINARY) || { echo "missing release binary: $(RELEASE_BINARY)" >&2; exit 2; }
	@mkdir -p $(REPORT_DIR)
	@$(PYTHON) $(TOOLS_DIR)/runtime_closure.py $(RELEASE_BINARY) \
	  $(REPORT_DIR)/runtime-closure.txt
	@FARSEE_RUNTIME_CLOSURE=$(REPORT_DIR)/runtime-closure.txt \
	  $(PYTHON) $(TOOLS_DIR)/check_license.py $(ROOT_DIR)

NIX_PACKAGE_PATH ?= result
check-nix-closure: ## Require an allowed declaration for every Nix closure path
	@test -e $(NIX_PACKAGE_PATH) || { echo "missing Nix package: $(NIX_PACKAGE_PATH)" >&2; exit 2; }
	@$(PYTHON) $(TOOLS_DIR)/nix_closure_audit.py $(NIX_PACKAGE_PATH) \
	  release/dependencies.json $(BUILD_DIR)/nix-closure.txt

check-release-binary: ## Reject lab-only symbols and debug controls from release
	@test -x $(RELEASE_BINARY) || { echo "missing release binary: $(RELEASE_BINARY)" >&2; exit 2; }
	@$(PYTHON) $(TOOLS_DIR)/release_binary_audit.py $(RELEASE_BINARY) \
	  release/binary-policy.json

check-release-wlog-policy: ## Reject developer-only WLog controls in release
	@test -x $(RELEASE_BINARY) || { echo "missing release binary: $(RELEASE_BINARY)" >&2; exit 2; }
	@check_rejected() { \
	  output=`$(RELEASE_BINARY) "$$@" 2>&1`; status=$$?; \
	  if [ $$status -ne 2 ]; then \
	    echo "release WLog control unexpectedly returned $$status: $$*" >&2; \
	    return 1; \
	  fi; \
	  case "$$output" in \
	    *"developer build"*) ;; \
	    *) echo "release WLog rejection lacks developer-build message: $$*" >&2; return 1 ;; \
	  esac; \
	}; \
	check_rejected -v && \
	check_rejected --verbose && \
	check_rejected --log-level && \
	check_rejected --log-level info && \
	check_rejected --log-level=info && \
	check_rejected --help --verbose && \
	check_rejected --version --log-level=trace && \
	check_rejected --protocol-capabilities -v

check-release-version: ## Require package and embedded binary versions to agree
	@test -x $(RELEASE_BINARY) || { echo "missing release binary: $(RELEASE_BINARY)" >&2; exit 2; }
	@actual=`$(RELEASE_BINARY) --version | awk 'NR == 1 { print $$2 }'`; \
	  test "$$actual" = "$$FARSEE_GUARD_VERSION" || { \
	    echo "release version mismatch: package=$$FARSEE_GUARD_VERSION, binary=$$actual" >&2; \
	    exit 1; \
	  }

trace-current-check: ## Reject forbidden residue in tracked, untracked, and staged content
	@$(PYTHON) $(TOOLS_DIR)/forbidden_trace_scan.py --root $(ROOT_DIR)

trace-release-check: ## Scan generated files and the release binary for forbidden residue
	@test -x $(RELEASE_BINARY) || { echo "missing release binary: $(RELEASE_BINARY)" >&2; exit 2; }
	@$(PYTHON) $(TOOLS_DIR)/forbidden_trace_scan.py --root $(ROOT_DIR) \
	  --generated-root $(BUILD_ID_H) --generated-root $(GEN_VERSION_H) \
	  --generated-root $(GEN_INCLUDE) \
	  --generated-root $(GEN_REGISTRY) --release-binary $(RELEASE_BINARY)

history-trace-check: ## Reject forbidden residue in all locally reachable Git refs
	@timeout $(HISTORY_TRACE_TIMEOUT) \
	  $(PYTHON) $(TOOLS_DIR)/history_trace_scan.py --root $(ROOT_DIR)

apple-preservation-check: ## Preserve Apple tests, fixtures, and product symbols
	@test -x $(RELEASE_BINARY) || { echo "missing release binary: $(RELEASE_BINARY)" >&2; exit 2; }
	@test -x $(TEST_RUNNER) || { echo "missing test runner: $(TEST_RUNNER)" >&2; exit 2; }
	@$(PYTHON) $(TOOLS_DIR)/apple_preservation_gate.py --root $(ROOT_DIR) \
	  --binary $(RELEASE_BINARY) --test-runner $(TEST_RUNNER) \
	  $(if $(filter 0,$(FARSEE_WITH_RDP)),--without-rdp,)

check-secrets: ## Scan current content and all reachable history with gitleaks
	@command -v $(GITLEAKS) >/dev/null 2>&1 || { echo "gitleaks is required" >&2; exit 2; }
	@timeout $(SECRET_SCAN_TIMEOUT) $(PYTHON) $(TOOLS_DIR)/check_secrets.py \
	  --root $(ROOT_DIR) --gitleaks $(GITLEAKS)

check-reproducible: ## Compare two complete release artifact sets byte-for-byte
	@$(TOOLS_DIR)/check_reproducible.sh $(ROOT_DIR) $(BUILD_DIR)

check-reproducible-no-rdp: ## Reproduce the complete no-FreeRDP artifact set
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/no-rdp-reproducible \
	  FARSEE_WITH_RDP=0 check-reproducible

## Configure-time self-tests (G0)
check-std-c11: ## Verify a GNU extension is rejected under -std=c11
	@$(TOOLS_DIR)/check_std_c11.sh

check-warnings: ## Verify a deliberate warning fails the build under -Werror
	@$(TOOLS_DIR)/check_warnings.sh

check-static-analysis: gen-version-header ## Run Clang static analyzer on all source files
	@SA_CFLAGS='$(SA_CFLAGS)' \
	  $(PYTHON) $(TOOLS_DIR)/static_analysis.py \
	    --root $(ROOT_DIR) --output $(REPORT_DIR)/static-analysis \
	    --compiler $(ANALYZER_CC) --jobs $(SA_JOBS) --timeout $(SA_TIMEOUT) \
	    --shard-index $(SA_SHARD_INDEX) --shard-count $(SA_SHARD_COUNT) \
	    $(if $(SA_FILES),$(SA_FILES),$(if $(filter 0,$(FARSEE_WITH_RDP)),$(filter-out $(SRC_DIR)/protocol/rdp/%,$(shell find $(SRC_DIR) -name '*.c' | sort))))

check-common-headers: ## F1 (§4.2): no protocol/platform types in common headers
	@$(PYTHON) $(TOOLS_DIR)/check_common_headers.py $(INCLUDE_DIR)

# ===========================================================================
## CI / release gate (plan.md §15.4)
## ---------------------------------------------------------------------------
ci: ## Full release-candidate gate sequence (Clang/GCC + sanitizers + coverage + fuzz + license)
	@echo "==> Clang dev build + tests"
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/ci-clang BUILD=dev CC=clang clean build test
	@echo "==> GCC dev build + tests (verifies GCC warning/standard compliance)"
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/ci-gcc BUILD=dev CC=gcc clean build test
	@echo "==> Optimized release build + tests + CLI/closure smoke"
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/ci-release release-check
	@echo "==> No-RDP configuration"
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/ci-no-rdp no-rdp-check
	@echo "==> Optimized no-RDP release gates"
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/ci-no-rdp-release no-rdp-release-check
	@echo "==> ASan/UBSan build + tests"
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/ci-sanitizer asan-ubsan
	@echo "==> Leak-enabled first-party sanitizer tests"
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/ci-leak leak-check
	@echo "==> Linux ThreadSanitizer frame-slot publisher regression"
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/ci-tsan tsan-check
	@echo "==> Coverage build + tests + report"
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/ci-coverage BUILD=coverage CC=clang clean build test
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/ci-coverage BUILD=coverage coverage-report
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/ci-coverage BUILD=coverage coverage-release-report
	@echo "==> Fuzz smoke"
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/ci-fuzz fuzz-smoke
	@echo "==> License check"
	$(MAKE) check-license
	@echo "==> Current-tree and reachable-history trace checks"
	$(MAKE) trace-current-check history-trace-check
	@echo "==> Current-content and reachable-history secret scan"
	$(MAKE) check-secrets
	@echo "==> Integration tests (loopback TCP)"
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/ci-integration BUILD=dev CC=clang integration
	@echo "==> Static / configure checks"
	$(MAKE) check-std-c11 check-warnings check-static-analysis check-common-headers
	@echo "CI gate sequence complete."

# ===========================================================================
## Packaging and install
## ---------------------------------------------------------------------------
.NOTPARALLEL: release-stage release-artifacts

release-stage: check-release-platform release ## Stage binary, legal notices, and dependency manifest
	@$(PYTHON) $(TOOLS_DIR)/release_path_guard.py --prepare stage
	@install -d -m755 '$(RELEASE_STAGE)/bin' \
	  '$(RELEASE_STAGE)/share/doc/farsee'
	@install -m755 '$(BUILD_DIR)/release/bin/farsee' '$(RELEASE_STAGE)/bin/farsee'
	@install -m644 LICENSE NOTICE THIRD_PARTY_NOTICES.md release/dependencies.json \
	  '$(RELEASE_STAGE)/share/doc/farsee/'
	@$(PYTHON) $(TOOLS_DIR)/gen_release_metadata.py \
	  '$(RELEASE_STAGE)/share/doc/farsee/release-metadata.json' \
	  --platform '$(RELEASE_PLATFORM)'

release-artifacts: release-stage ## Generate SBOM, reproducible archive, and checksums
	@command -v syft >/dev/null 2>&1 || { echo "syft is required" >&2; exit 2; }
	@$(MAKE) BUILD=release \
	  RELEASE_BINARY=$(BUILD_DIR)/release/bin/farsee \
	  check-runtime-closure check-release-binary check-release-version \
	  check-release-wlog-policy trace-release-check \
	  apple-preservation-check
	@install -m644 '$(BUILD_DIR)/release/report/runtime-closure.txt' \
	  '$(RELEASE_STAGE)/share/doc/farsee/'
	@$(PYTHON) $(TOOLS_DIR)/release_path_guard.py --prepare artifacts
	@syft scan 'dir:$(RELEASE_STAGE)' \
	  --source-name farsee --source-version $(VERSION) \
	  '-o' 'spdx-json=$(RELEASE_SBOM)'
	@$(PYTHON) $(TOOLS_DIR)/release_sbom.py '$(RELEASE_SBOM)' \
	  --manifest '$(RELEASE_STAGE)/share/doc/farsee/dependencies.json' \
	  --runtime-closure '$(RELEASE_STAGE)/share/doc/farsee/runtime-closure.txt' \
	  --binary '$(RELEASE_STAGE)/bin/farsee'
	@tar --sort=name --mtime="@$$FARSEE_AUDIT_SOURCE_DATE_EPOCH" \
	  --owner=0 --group=0 --numeric-owner -czf '$(RELEASE_ARCHIVE)' \
	  -C '$(dir $(RELEASE_STAGE))' '$(notdir $(RELEASE_STAGE))'
	@$(PYTHON) $(TOOLS_DIR)/gen_release_notes.py CHANGELOG.md \
	  '$(RELEASE_NOTES)'
	@cd '$(RELEASE_ARTIFACT_DIR)' && sha256sum \
	  '$(notdir $(RELEASE_ARCHIVE))' \
	  '$(notdir $(RELEASE_SBOM))' \
	  '$(notdir $(RELEASE_NOTES))' > '$(notdir $(RELEASE_CHECKSUMS))'
	@$(MAKE) trace-release-artifacts-check check-release-artifacts

trace-release-artifacts-check: ## Scan staged documents and final release metadata
	@test -d '$(RELEASE_STAGE)/share/doc/farsee' || { echo "missing staged documents" >&2; exit 2; }
	@test -f '$(RELEASE_SBOM)' -a -f '$(RELEASE_NOTES)' -a -f '$(RELEASE_CHECKSUMS)' || { echo "missing release metadata" >&2; exit 2; }
	@$(PYTHON) $(TOOLS_DIR)/forbidden_trace_scan.py --root $(ROOT_DIR) \
	  '$(RELEASE_STAGE)/share/doc/farsee' \
	  '$(RELEASE_SBOM)' '$(RELEASE_NOTES)' '$(RELEASE_CHECKSUMS)'

check-release-artifacts: ## Verify package layout, SPDX SBOM, and checksums
	@$(PYTHON) $(TOOLS_DIR)/check_release_artifacts.py

release-sign: check-release-approval release-artifacts ## Sign checksums with cosign (set COSIGN_KEY)
	@test -n "$(COSIGN_KEY)" || { echo "set COSIGN_KEY to an approved cosign key URI" >&2; exit 2; }
	@cosign sign-blob --yes --key "$(COSIGN_KEY)" \
	  --bundle $(RELEASE_ARTIFACT_DIR)/SHA256SUMS.sigstore.json \
	  $(RELEASE_ARTIFACT_DIR)/SHA256SUMS

install: ## Install release binary and legal notices under INSTALL_PREFIX
	@# Always ship the optimized release build, never the dev binary (L22).
	$(MAKE) BUILD=release $(BUILD_DIR)/release/bin/farsee
	@mkdir -p $(INSTALL_BINDIR) $(INSTALL_DOCDIR)
	@cp $(BUILD_DIR)/release/bin/farsee $(INSTALL_BINDIR)/
	@cp LICENSE NOTICE THIRD_PARTY_NOTICES.md release/dependencies.json $(INSTALL_DOCDIR)/
	@echo "Installed $(BUILD_DIR)/release/bin/farsee -> $(INSTALL_BINDIR)"

uninstall: ## Remove farsee from INSTALL_PREFIX
	@rm -f $(INSTALL_BINDIR)/farsee
	@rm -f $(INSTALL_DOCDIR)/LICENSE $(INSTALL_DOCDIR)/NOTICE \
	  $(INSTALL_DOCDIR)/THIRD_PARTY_NOTICES.md $(INSTALL_DOCDIR)/dependencies.json
	@echo "Removed $(INSTALL_BINDIR)/farsee"

# ===========================================================================
## Clean
## ---------------------------------------------------------------------------
clean: ## Remove the entire build/ tree
	@rm -rf $(BUILD_DIR)

mostlyclean: ## Remove object files, keep built binaries
	@rm -rf $(BUILD_DIR)/$(BUILD)/obj
