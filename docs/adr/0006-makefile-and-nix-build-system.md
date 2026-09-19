# ADR-0006: Makefile + Nix build system

- **Status:** Accepted · **Date:** 2026-07-21

## Context

plan.md originally sketched CMake presets. Operator directive: Nix for
toolchain, self-documenting Makefile as the sole driver.

## Decision

1. **`flake.nix`** provisions Clang/GCC, zlib, OpenSSL, FreeRDP (optional),
   coverage/fuzz tools, Python.  
2. **`Makefile`** exposes `dev`, `release`, `asan-ubsan`, `coverage`, `fuzz`,
   `ci`, license checks (`make help`).  
3. **macOS ASan:** Apple Clang via `MACOS_ASAN_CC` (nix LLVM ASan deadlocks
   on recent macOS). Linux uses nix clang ASan.  
4. Warning set and C11/`-Werror=vla` as in plan.md §15 / Makefile.

## Consequences

No CMake. No bare system package installs for the project toolchain.
`make ci` is the full release-candidate gate.
