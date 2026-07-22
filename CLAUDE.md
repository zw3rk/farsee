# CLAUDE.md — farsee

On top of global `~/.claude/CLAUDE.md`. Stricter rule wins.

> **Spec:** `plan.md` · **Driver:** `nix develop --command make <target>` (`make help`)

## Standing directives

1. **Nix only** for the environment (`flake.nix` / ADR-0006).
2. **Makefile only** as the build/test interface.
3. **Commit** complete verified units along the way (push/merge still needs ask).

## Platform notes

- **macOS ASan:** use Apple Clang via `MACOS_ASAN_CC` (`make asan-ubsan`); nix LLVM ASan deadlocks on recent macOS. Linux uses nix clang ASan.
- **PTY in tests:** never `openpty` without raw slave + master EOF. Prefer pipes for Kitty byte contracts. ESC in cooked mode blocks forever.

## TDD (non-negotiable)

Red → green → refactor. Positive **and** negative tests before production code.  
Every bug ⇒ permanent −/+ regression first. Harness: `tests/test_framework/` + `tools/gen_test_registry.py`.

## Clean-room — LOCKED

Derive only from: RFC 6143 + errata, IANA RFB, Kitty graphics spec, POSIX/platform docs, Apple public Screen Sharing docs, project-owned captures/vectors.  
**No** GPL/AGPL/LGPL VNC sources (LibVNC, TigerVNC, termvnc, …). ADR-0001.

## Dependencies & crypto — LOCKED

- New dep: ADR + plan.md §5.4 license allowlist + `THIRD_PARTY_NOTICES.md`.
- **Never hand-roll crypto.** DES/VNC via CommonCrypto or OpenSSL through `src/crypto/`. VNC key schedule bit-permutation is RFC 6143 §7.2.2, not a primitive.

## Curated C11

- C11 subset; **no** VLAs (`-Werror=vla`), Annex K `_s`, `<threads.h>`, `_Generic`.
- **No** `sprintf` / `strcpy` / `strcat` — `snprintf` + bounds. NULL-check allocations; fail closed.
- Flags: see Makefile / plan.md §15.2. Modes: `dev`, `release`, `asan-ubsan`, `coverage`, `fuzz`. Full gate: `make ci`.

## Architecture (live)

- Pure protocol core; incremental parsers; canonical RGBA8 framebuffer (ADR-0003).
- **SHARED-MT** is the product seam (ADR-0010): protocol / present / input; session publishes, app presents.
- F-engine/reactor = scaffold only until a vertical slice (ADR-0011). Fail closed; no hidden globals.

## Commits

Imperative ≤72-char subject, scoped. Why + spec in body.  
**Banned trailers:** Co-authored-by, Signed-off-by, Generated-by/AI. Never force-push.

## Definition of Done

red→green→refactor · +/− tests · regression if bug · Apache-2.0 SPDX · docs if behaviour changed · `docs/implementation-status.md` if gate status changed · `make ci` green.

## Escalation

On triggers in `SENIOR-ESCALATION.md`: evidence packet + independent senior consult before speculative production changes. Worker keeps ownership.
