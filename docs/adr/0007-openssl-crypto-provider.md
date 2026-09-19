# ADR-0007: OpenSSL 3.x as the Apple-auth crypto provider

- **Status:** Accepted
- **Date:** 2026-07-22
- **Supersedes:** Extends ADR-0002 (which selected CommonCrypto/OpenSSL for VNC auth only)

## Context

Apple authentication requires a permissively licensed crypto provider for
SHA-1, SHA-256, SHA-512, MD5, PBKDF2-HMAC-SHA512, RSA-2048 PKCS#1 v1.5,
AES-128-ECB unwrap, AES-128-CBC contexts, DER SPKI parsing, constant-time
comparison, secure random data, and zeroization. The VNC-auth provider from
ADR-0002 uses CommonCrypto on macOS and OpenSSL on Linux. Apple authentication
needs additional primitives and one cross-platform provider. CommonCrypto does
not provide every required primitive.

## Decision

1. **OpenSSL 3.x** is the primary provider for all Apple-auth crypto
   primitives on macOS and Linux. The Nix development environment provides
   `openssl-3.4.3` through `OPENSSL_CFLAGS` and `OPENSSL_LIBS`.
2. The existing **VNC-auth DES provider** keeps its CommonCrypto/OpenSSL split.
3. The crypto APIs are narrow internal wrappers in `src/crypto/`, never exposing OpenSSL types in public headers.
4. OpenSSL is Apache-2.0 licensed — on the plan.md §5.4 allowlist.

## Consequences

- macOS builds link `-lcrypto` from the Nix development environment.
- Apple-auth primitives have no CommonCrypto-specific code path.
- The OpenSSL FIPS provider does not provide MD5. In FIPS mode, legacy
  type-30 authentication reports unsupported instead of weakening provider
  policy.
