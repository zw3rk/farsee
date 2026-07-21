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
CC            ?= clang
AR            ?= ar
PKG_CONFIG    ?= pkg-config
PYTHON        ?= python3

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

# ---------------------------------------------------------------------------
# Language policy: the "Curated C11" subset, no extensions (AGENTS.md
# "C programming guidelines"; plan.md §15.1, §15.3). C11 supersedes the
# earlier C99 target; -Werror=vla hard-enforces the VLA ban.
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
# -O1: glibc _FORTIFY_SOURCE (injected by distros/nix) requires optimization
# under -Werror; pure -O0 fails on Linux CI.
COVERAGE_FLAGS := --coverage -O1 -g -U_FORTIFY_SOURCE
FUZZ_FLAGS    := -O1 -g

# Pick the flag set for the current BUILD.
BUILD_CFLAGS  :=
BUILD_LDFLAGS :=
ifeq ($(BUILD),dev)
  BUILD_CFLAGS := $(DEV_FLAGS)
else ifeq ($(BUILD),release)
  BUILD_CFLAGS := $(RELEASE_FLAGS)
else ifeq ($(BUILD),asan-ubsan)
  BUILD_CFLAGS := $(ASAN_FLAGS)
  BUILD_LDFLAGS := $(ASAN_FLAGS)
else ifeq ($(BUILD),coverage)
  BUILD_CFLAGS := $(COVERAGE_FLAGS)
  BUILD_LDFLAGS := $(COVERAGE_FLAGS)
else ifeq ($(BUILD),fuzz)
  BUILD_CFLAGS := $(FUZZ_FLAGS)
else
  $(error Unknown BUILD='$(BUILD)'. Use one of: dev, release, asan-ubsan, coverage, fuzz.)
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
# glibc marks write() with warn_unused_result; best-effort TTY/escape
# writes intentionally ignore short writes / EPIPE under -Werror.
ifeq ($(shell uname -s 2>/dev/null),Linux)
  PLATFORM_CFLAGS += -D_POSIX_C_SOURCE=200809L -Wno-unused-result
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
  CRYPTO_LIBS  := -framework SECURITY_FRAMEWORK  # placeholder; CC is in libSystem
  # CommonCrypto is part of libSystem on macOS; no extra link flag needed.
  CRYPTO_LIBS  :=
else
  CRYPTO_DEFS  := -DRFB_USE_OPENSSL
  CRYPTO_LIBS  := $(OPENSSL_LIBS) -lcrypto
endif

# --- RDP engine feature switch (ADR-RDP-001) -------------------------------
# Default ON: compile src/protocol/rdp/*.c and link FreeRDP 3.x (freerdp3
# pkg-config). The nix devShell exports FREERDP_CFLAGS / FREERDP_LIBS.
# Opt out for a no-RDP binary (still must stay green): FARSEE_WITH_RDP=0.
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

# Aggregate flags. Defined AFTER crypto + RDP feature blocks so all the
# *_DEFS/*_LIBS variables above are already expanded (immediate :=).
# Git/build stamp for binary identity banner (stale-inode detection).
# Regenerated every build so only app/binary_id.o needs to recompile for a
# new stamp (see gen-build-id).
BUILD_ID_H := $(OBJ_DIR)/generated/build_id.h

CFLAGS  := $(STD_FLAGS) $(STRICT_WARN) $(BUILD_CFLAGS) -I$(INCLUDE_DIR) -I$(SRC_DIR) \
           -I$(TEST_DIR) -I$(TEST_DIR)/test_framework -I$(OBJ_DIR)/generated \
           -I$(ROOT_DIR) $(PLATFORM_CFLAGS) $(CRYPTO_DEFS) $(ZLIB_CFLAGS) $(OPENSSL_CFLAGS) \
           $(RDP_DEFS)
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

# Scaffold / non-product (ADR-0011): F-engine museum, G17/fake Apple, R1 stub.
# Linked into farsee_tests + fuzz + tools; NOT into the farsee CLI binary.
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
	$(SRC_DIR)/rfb/fake_apple_server.c \
	$(SRC_DIR)/rfb/apple_session.c \
	$(SRC_DIR)/protocol/rdp/rdp_worker.c

LIB_SRCS      := $(CORE_SRCS) $(FARSEE_SRCS) $(RFB_SRCS) $(RDP_SRCS) $(FB_SRCS) $(IO_SRCS) $(INPUT_SRCS) \
                 $(CRYPTO_SRCS) $(TTY_SRCS) $(PRESENT_SRCS) $(APP_LIB_SRCS)
LIB_OBJS      := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(LIB_SRCS))

# Product link set: full library minus scaffold (tests keep full LIB_OBJS).
PRODUCT_LIB_SRCS := $(filter-out $(SCAFFOLD_SRCS),$(LIB_SRCS))
PRODUCT_LIB_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(PRODUCT_LIB_SRCS))

TEST_FRAMEWORK_SRCS := $(wildcard $(TEST_DIR)/test_framework/*.c)
# Note: unit/component test sources are NOT compiled directly. They are
# #include'd into runner.c via a generated header (see gen-test-registry)
# so the whole suite is one translation unit — portable and ASan-safe.
# runner.c is the single TU main; other test_framework/*.c files (e.g.
# fake_io.c) are real helper implementations compiled as separate objects
# and linked into the runner.
TEST_RUNNER_FRAMEWORK_OBJ := $(OBJ_DIR)/tests/test_framework/runner.o
TEST_HELPERS_OBJ := $(patsubst $(TEST_DIR)/%.c,$(OBJ_DIR)/tests/%.o,$(filter-out $(TEST_DIR)/test_framework/runner.c,$(TEST_FRAMEWORK_SRCS)))
# Test-only protocol fakes (e.g. fake_engine for F1 contract tests). Real
# helper implementations compiled as separate objects and linked into the
# runner. NOT first-party library code; never linked into the farsee binary.
TEST_FAKES_SRCS := $(wildcard $(TEST_DIR)/fakes/*.c)
TEST_FAKES_OBJ  := $(patsubst $(TEST_DIR)/%.c,$(OBJ_DIR)/tests/%.o,$(TEST_FAKES_SRCS))

# Generated test registry (rebuilt whenever test sources change).
GEN_DIR              := $(OBJ_DIR)/generated
GEN_INCLUDE          := $(GEN_DIR)/test_includes.generated.h
GEN_REGISTRY         := $(GEN_DIR)/registry.generated.c
GEN_ARTIFACTS        := $(GEN_INCLUDE) $(GEN_REGISTRY)

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
.PHONY: help all build test check clean mostlyclean \
        dev release asan-ubsan coverage coverage-report \
        fuzz fuzz-smoke check-license check-std-c11 check-warnings \
        check-static-analysis check-common-headers \
        type33-probe \
        ci install uninstall \
        gen-build-id \
        $(NULL)

# ===========================================================================
# `make help` — the self-documenting entry point
# ===========================================================================
help: ## Show this target catalogue
	@printf '\n\033[1mfarsee\033[0m — clean-room C99 RFB/VNC terminal client\n\n'
	@printf '\033[1mUsage:\033[0m\n'
	@printf '  make [target] [BUILD=<mode>] [CC=<compiler>] [V=1]\n\n'
	@printf '\033[1mBuild modes (BUILD=):\033[0m  dev (default) · release · asan-ubsan · coverage · fuzz\n'
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

release: ## Optimized release build of the CLI
	$(MAKE) BUILD=release build

release-cli: ## Optimized CLI binary only (no tests) — nix packaging
	$(MAKE) BUILD=release $(BUILD_DIR)/release/bin/farsee

asan-ubsan: ## Address + UBSan build and tests (Apple Clang on macOS; see ADR-0006)
	@# On macOS the nix LLVM 19/20 ASan runtime deadlocks during dyld
	@# initialization (see ADR-0006). Apple's matched runtime works. The
	@# devShell exports MACOS_ASAN_CC = absolute path to Apple's clang
	@# (discovered via xcrun with the nix PATH cleared, so xcrun does not
	@# resolve to nix's own clang). On Linux, nix clang's ASan is used.
	@if [ -n "$$MACOS_ASAN_CC" ] && [ -x "$$MACOS_ASAN_CC" ]; then \
	  echo "asan-ubsan: using Apple Clang ($$MACOS_ASAN_CC)"; \
	  $(MAKE) BUILD=asan-ubsan CC="$$MACOS_ASAN_CC" all; \
	elif [ "$(shell uname -s 2>/dev/null)" = "Darwin" ]; then \
	  echo "asan-ubsan: WARNING: MACOS_ASAN_CC not set; falling back to nix clang (may hang on macOS 26)" >&2; \
	  $(MAKE) BUILD=asan-ubsan CC=clang all; \
	else \
	  $(MAKE) BUILD=asan-ubsan CC=clang all; \
	fi

# FreeRDP client may dlopen SDL3 at process start and abort if the library
# cannot initialize a video backend (headless CI / ASan). Prefer dummy drivers.
export SDL_VIDEODRIVER ?= dummy
export SDL_AUDIODRIVER ?= dummy

coverage: ## Coverage build
	$(MAKE) BUILD=coverage build

coverage-report: ## Aggregate gcov data and enforce plan.md thresholds (requires BUILD=coverage)
	@if [ "$(BUILD)" != "coverage" ]; then \
	  echo "coverage-report: BUILD must be 'coverage' (got '$(BUILD)')" >&2; \
	  echo "  run: make BUILD=coverage coverage-report" >&2; \
	  exit 2; \
	fi
	@$(TOOLS_DIR)/coverage.sh $(BUILD_ROOT) $(COVERAGE_DIR) --enforce

# ===========================================================================
## Build
## ---------------------------------------------------------------------------
## Dev hygiene
## ---------------------------------------------------------------------------
# Always refresh git/build stamp so the next link of farsee embeds identity.
# (binary_id still prints path/inode/mtime so a long-lived process can be
# spotted as stale without blocking the rebuild.)
gen-build-id: ## Write build_id.h (git rev + UTC time) for binary_id.o
	@mkdir -p $(OBJ_DIR)/generated
	@printf '%s\n' \
	  '/* AUTO-GENERATED by make gen-build-id — do not edit */' \
	  '#ifndef FARSEE_BUILD_ID_H' \
	  '#define FARSEE_BUILD_ID_H' \
	  '#define FARSEE_GIT_REV "$(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"' \
	  '#define FARSEE_BUILD_TIME "$(shell date -u +%Y-%m-%dT%H:%M:%SZ)"' \
	  '#endif' > $(BUILD_ID_H)

# binary_id.o must rebuild whenever the stamp is regenerated.
$(OBJ_DIR)/app/binary_id.o: gen-build-id

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

# Generate the test registry before compiling the runner. The runner
# #include's both generated files.
gen-test-registry: $(GEN_ARTIFACTS)

$(GEN_ARTIFACTS): $(TEST_FRAMEWORK_SRCS) $(wildcard $(TEST_DIR)/unit/*.c) $(wildcard $(TEST_DIR)/unit/rdp/*.c) $(wildcard $(TEST_DIR)/component/*.c) tools/gen_test_registry.py
	@mkdir -p $(GEN_DIR)
	@echo "  GEN     test registry"
	@FARSEE_WITH_RDP=$(FARSEE_WITH_RDP) $(PYTHON) $(TOOLS_DIR)/gen_test_registry.py $(TEST_DIR) $(GEN_DIR)

$(APP_BIN): $(PRODUCT_LIB_OBJS) $(APP_MAIN_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
	@mkdir -p $(@D)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_RUNNER): $(LIB_OBJS) $(TEST_RUNNER_FRAMEWORK_OBJ) $(TEST_HELPERS_OBJ) $(TEST_FAKES_OBJ) $(GEN_REGISTRY)
	@mkdir -p $(@D)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(LIB_OBJS) $(TEST_RUNNER_FRAMEWORK_OBJ) $(TEST_HELPERS_OBJ) $(TEST_FAKES_OBJ) $(LDLIBS)

# Generic compile rule for src/ and tests/. Note: the test runner object
# depends on the generated artifacts (they are #include'd).
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(QUIET_CC)$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/tests/%.o: $(TEST_DIR)/%.c $(GEN_ARTIFACTS)
	@mkdir -p $(@D)
	$(QUIET_CC)$(CC) $(CFLAGS) -c -o $@ $<

# ===========================================================================
## Test
## ---------------------------------------------------------------------------
test: build ## Build and run the test suite
	@# FreeRDP/SDL leave third-party allocations at exit under ASan LSan;
	@# product code is still checked by ASan for UAF/OOB. Override with
	@# ASAN_OPTIONS=detect_leaks=1 for leak hunts.
	$(QUIET_RUN)env ASAN_OPTIONS="$${ASAN_OPTIONS:-detect_leaks=0}" \
	  $(TEST_RUNNER) $(TEST_ARGS)

check: test ## Alias for `test`

# Integration tests: run the Python-orchestrated scenarios that drive the
# C handshake driver against the scripted RFB server over real loopback TCP.
integration: $(BIN_DIR)/handshake_integration $(BIN_DIR)/lifecycle_integration ## Run the scripted-server integration tests
	@$(PYTHON) $(TEST_DIR)/integration/run_handshake_integration.py \
	    --driver $(BIN_DIR)/handshake_integration \
	    --server $(TEST_DIR)/integration/scripted_rfb_server.py
	@$(PYTHON) $(TEST_DIR)/integration/run_lifecycle_integration.py \
	    --driver $(BIN_DIR)/lifecycle_integration \
	    --server $(TEST_DIR)/integration/scripted_rfb_server.py

# Focused filter for the red-green-refactor loop (plan.md §13.1):
#   make test TEST_FILTER=checked
ifeq ($(strip $(TEST_FILTER)),)
TEST_ARGS :=
else
TEST_ARGS := --filter $(TEST_FILTER)
endif

# ===========================================================================
## Diagnostic tools (optional; not part of `make ci`)
## ---------------------------------------------------------------------------
# Type-33 post-auth wire probe: auth → ServerInit → SetEncodings + FBUR,
# then dump the first server bytes (cleartext FBU vs opaque/AEAD).
# Usage:
#   nix develop --command make type33-probe
#   build/dev/bin/type33_postauth_probe <host> <port> <user> <password-fd>
type33-probe: $(BIN_DIR)/type33_postauth_probe ## Build type-33 post-auth wire probe

$(BIN_DIR)/type33_postauth_probe: $(LIB_OBJS) $(TOOLS_DIR)/type33_postauth_probe.c
	@mkdir -p $(@D)
	$(QUIET_LINK)$(CC) $(STD_FLAGS) $(STRICT_WARN) $(BUILD_CFLAGS) \
	  -I$(INCLUDE_DIR) -I$(SRC_DIR) -I$(ROOT_DIR) \
	  $(PLATFORM_CFLAGS) $(CRYPTO_DEFS) \
	  -o $@ $(TOOLS_DIR)/type33_postauth_probe.c $(LIB_OBJS) $(LDLIBS)

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
FUZZ_CC ?= clang
$(BUILD_DIR)/fuzz/bin/%: $(TEST_DIR)/fuzz/%.c $(LIB_OBJS) $(GEN_ARTIFACTS)
	@mkdir -p $(@D)
	$(QUIET_LINK)$(FUZZ_CC) $(STD_FLAGS) $(STRICT_WARN) $(FUZZ_FLAGS) \
	  -fsanitize=fuzzer \
	  -I$(INCLUDE_DIR) -I$(SRC_DIR) -I$(ROOT_DIR) \
	  -o $@ $< $(LIB_OBJS) $(LDLIBS)

fuzz-smoke: ## Run each fuzz target briefly against its corpus (Clang)
	@$(MAKE) BUILD=fuzz CC=$(FUZZ_CC) fuzz
	@$(TOOLS_DIR)/fuzz_smoke.sh

# ===========================================================================
## Static / hygiene
## ---------------------------------------------------------------------------
check-license: ## Verify SPDX headers and THIRD_PARTY_NOTICES.md
	@$(PYTHON) $(TOOLS_DIR)/check_license.py $(ROOT_DIR)

## Configure-time self-tests (G0)
check-std-c11: ## Verify a GNU extension is rejected under -std=c11
	@$(TOOLS_DIR)/check_std_c11.sh

check-warnings: ## Verify a deliberate warning fails the build under -Werror
	@$(TOOLS_DIR)/check_warnings.sh

check-static-analysis: ## Run Clang static analyzer on all source files
	@SDK="$$(xcrun --show-sdk-path 2>/dev/null)"; \
	SRCS=$$(find $(SRC_DIR) -name '*.c' | sort); \
	STATUS=0; \
	for f in $$SRCS; do \
	  case "$$f" in \
	    */protocol/rdp/*) if [ "$(FARSEE_WITH_RDP)" != "1" ]; then continue; fi ;; \
	  esac; \
	  result=$$($(CC) --analyze "$$f" \
	    -std=c11 -isysroot "$$SDK" -I$(INCLUDE_DIR) -I$(SRC_DIR) \
	    $(RDP_DEFS) \
	    $$(echo $(ZLIB_CFLAGS) | sed 's/-L[^ ]*//g') 2>&1); \
	  real=$$(echo "$$result" | grep -v 'unused-command-line-argument' | grep -v '^$$' | grep -v '^clang:'); \
	  if [ -n "$$real" ]; then \
	    echo "FINDING in $$f:"; echo "$$real"; \
	    STATUS=1; \
	  fi; \
	done; \
	if [ "$$STATUS" = "0" ]; then \
	  echo "ok: Clang static analyzer clean ($$(echo $$SRCS | wc -w) files)."; \
	fi; \
	exit $$STATUS

check-common-headers: ## F1 (§4.2): no protocol/platform types in common headers
	@$(PYTHON) $(TOOLS_DIR)/check_common_headers.py $(INCLUDE_DIR)

# ===========================================================================
## CI / release gate (plan.md §15.4)
## ---------------------------------------------------------------------------
ci: ## Full release-candidate gate sequence (Clang dev + GCC dev + sanitizer + coverage + fuzz + license)
	@echo "==> Clang dev build + tests"
	$(MAKE) BUILD=dev CC=clang clean build test
	@echo "==> GCC dev build + tests (verifies GCC warning/standard compliance)"
	$(MAKE) BUILD=dev CC=gcc clean build test
	@echo "==> ASan/UBSan build + tests"
	$(MAKE) asan-ubsan
	@echo "==> Coverage build + tests + report"
	$(MAKE) BUILD=coverage CC=clang clean build test
	$(MAKE) BUILD=coverage coverage-report
	@echo "==> Fuzz smoke"
	$(MAKE) fuzz-smoke
	@echo "==> License check"
	$(MAKE) check-license
	@echo "==> Integration tests (loopback TCP)"
	$(MAKE) BUILD=dev CC=clang integration
	@echo "==> Static / configure checks"
	$(MAKE) check-std-c11 check-warnings check-static-analysis check-common-headers
	@echo "CI gate sequence complete."

# ===========================================================================
## Install (deferred until CLI exists; targets declared for symmetry)
## ---------------------------------------------------------------------------
install: build ## Install farsee under INSTALL_PREFIX (default /usr/local)
	@mkdir -p $(INSTALL_BINDIR)
	@cp $(APP_BIN) $(INSTALL_BINDIR)/
	@echo "Installed $(APP_BIN) -> $(INSTALL_BINDIR)"

uninstall: ## Remove farsee from INSTALL_PREFIX
	@rm -f $(INSTALL_BINDIR)/farsee
	@echo "Removed $(INSTALL_BINDIR)/farsee"

# ===========================================================================
## Clean
## ---------------------------------------------------------------------------
clean: ## Remove the entire build/ tree
	@rm -rf $(BUILD_DIR)

mostlyclean: ## Remove object files, keep built binaries
	@rm -rf $(BUILD_DIR)/$(BUILD)/obj
