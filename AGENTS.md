# AGENTS.md — farsee

> **Spec:** `plan.md` · **Driver:** `nix develop --command make <target>`
> (`make help`)

## Standing directives

1. Use Nix only for the environment (`flake.nix` / ADR-0006).
2. Use the Makefile as the only build and test interface.
3. Commit complete verified units. Ask before any push or merge.

## Platform notes

- On macOS, use Apple Clang through `MACOS_ASAN_CC` for `make asan-ubsan`.
  The Nix LLVM ASan runtime deadlocks on recent macOS releases. Linux uses
  Nix Clang ASan.
- In PTY tests, use a raw slave and ensure that the master receives EOF.
  Prefer pipes for Kitty byte contracts. ESC in cooked mode can block.

## TDD

Use red → green → refactor. Add positive and negative tests before or with
production changes. Every defect needs a permanent regression when a test
seam exists. The harness is in `tests/test_framework/`; registry generation is
in `tools/gen_test_registry.py`.

## Clean-room policy — LOCKED

Use only the sources allowed by ADR-0001: RFC 6143 and errata, IANA RFB,
the Kitty graphics specification, POSIX and platform documentation, Apple
public Screen Sharing documentation, and project-generated wire vectors.
Do not use source code from implementations outside that allowlist.

## Dependencies and cryptography — LOCKED

- A new dependency needs an ADR, approval under `plan.md` section 5.4, and an
  entry in `THIRD_PARTY_NOTICES.md`.
- Do not implement cryptographic primitives. Use CommonCrypto or OpenSSL
  through `src/crypto/`. The VNC key-schedule bit permutation is specified by
  RFC 6143 section 7.2.2 and is not a primitive.

## Curated C11

- Use the supported C11 subset. Do not use VLAs, Annex K, `<threads.h>`, or
  `_Generic`.
- Do not use `sprintf`, `strcpy`, or `strcat`. Use checked `snprintf` calls.
  Check allocations and fail closed.
- The required flags and build modes are in the Makefile and `plan.md`
  section 15.2. The full gate is `make ci`.

## Architecture

- Keep the protocol core pure and parsers incremental. Use canonical RGBA8
  framebuffer data (ADR-0003).
- SHARED-MT is the product seam (ADR-0010): protocol, presentation, and input.
  Sessions publish frames and the application presents them.
- The F-engine/reactor remains scaffold until it has a vertical slice
  (ADR-0011). Fail closed and avoid hidden global state.

## Commits

Use an imperative subject of at most 72 characters. Explain why and cite the
specification in the body. Do not add attribution, signature, or automation
trailers. Never force-push.

## Definition of done

Complete red → green → refactor, positive and negative tests, regression tests
for defects, Apache-2.0 SPDX tags, behavior documentation, and
`docs/implementation-status.md` updates when a gate changes. Finish with a
green `make ci`.

## Escalation

For a trigger in `SENIOR-ESCALATION.md`, prepare an evidence packet and get an
independent senior review before speculative production changes. The worker
keeps ownership.
