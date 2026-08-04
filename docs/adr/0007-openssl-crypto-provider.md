# ADR-0007: OpenSSL 3.x as the Apple-auth crypto provider

- **Status:** Accepted
- **Date:** 2026-07-22
- **Supersedes:** Extends ADR-0002 (which selected CommonCrypto/OpenSSL for VNC auth only)

## Context

G16 (goals.md) requires a permissively-licensed crypto provider for Apple authentication primitives: SHA-1/256/512, MD5, PBKDF2-HMAC-SHA512, RSA-2048 PKCS#1 v1.5, AES-128-ECB unwrap, AES-128-CBC contexts, DER SPKI parsing, constant-time compare, secure random, and zeroization. The existing VNC-auth provider (ADR-0002) uses CommonCrypto on macOS and OpenSSL on Linux. For Apple auth, we need more primitives (RSA, PBKDF2, AES-128-CBC, SHA-512) and cross-platform consistency. CommonCrypto lacks some of these (no PBKDF2-HMAC-SHA512, no BN/modexp).

## Decision

1. **OpenSSL 3.x** is the primary provider for all Apple-auth crypto primitives, on both macOS and Linux. The nix devShell provides `openssl-3.4.3` via `OPENSSL_CFLAGS`/`OPENSSL_LIBS`.
2. The existing **VNC-auth DES provider** (CommonCrypto/OpenSSL split) remains unchanged — it is not affected by this ADR.
3. The crypto APIs are narrow internal wrappers in `src/crypto/`, never exposing OpenSSL types in public headers.
4. OpenSSL is Apache-2.0 licensed — on the plan.md §5.4 allowlist.

## Consequences

- macOS builds link `-lcrypto` (from the nix devShell). - No CommonCrypto dependency for Apple-auth primitives (removes a macOS-only code path). - FIPS-mode limitations: OpenSSL FIPS provider lacks MD5; if FIPS mode is detected, type-30 (legacy) auth reports unsupported rather than weakening the provider policy.
