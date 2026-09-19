# ADR-0002: VNC Authentication crypto provider

- **Status:** Accepted (provider selection); individual providers land in G2.
- **Date:** 2026-07-21

## Context

VNC Authentication (RFC 6143 §7.2.2, security type 2) requires:

- taking the first 8 bytes of the password, with zero-padding when shorter;
- applying the specified bit permutation to form the 64-bit DES key; and
- DES-ECB encrypting the 16-byte server challenge in two 8-byte blocks.

`plan.md` §5.5 requires a provider interface instead of one platform-specific
crypto library:

- macOS uses CommonCrypto, which is an Apple system framework;
- Linux and other supported platforms use OpenSSL 3.x; and
- the RFB core does not expose a provider-specific type.

RFC 6143 specifies both the DES operation and the VNC key-schedule bit
permutation.

## Decision

1. **Provider interface** in `include/farsee/` declares only opaque handles and
   pure-C entry points. It exposes no OpenSSL or CommonCrypto type.
2. **macOS provider** uses `CCCrypt` (CommonCrypto) for DES-ECB and the
   project-owned RFC 6143 key-schedule implementation.
3. **Linux and cross-platform provider** uses the OpenSSL 3.x `EVP_*` API for
   DES-ECB and the same key-schedule implementation.
4. **Key schedule** is implemented once in `src/crypto/`, in plain C, with
   known-answer tests. Its bit permutation follows the RFC 6143 table.
5. **Password handling** follows `plan.md` §6.3 and §15.3:
   - never accept a password as a CLI argument;
   - read it from a TTY with echo disabled or from `--password-fd`; and
   - keep it in one owned buffer and zeroize the full allocation with the
     compiler-resistant helper on every release path.

## Consequences

- Two provider `.c` files are selected at compile time, and the core links
  against the provider interface.
- Each provider has known-answer tests.
- Adding a third provider requires a new ADR and license check. The provider
  boundary keeps that change local.
