# ADR-0002: VNC Authentication crypto provider

- **Status:** Accepted (provider selection); individual providers land in G2.
- **Date:** 2026-07-21

## Context

VNC Authentication (RFC 6143 §7.2.2, security type 2) requires: - taking the first 8 bytes of the password (zero-padded if shorter); - bit-permuting them into a 64-bit DES key (the well-known "VNC key schedule"); - DES-ECB encrypting the 16-byte server challenge in two 8-byte blocks. plan.md §5.5 mandates a **provider interface**, not a single crypto library, so that: - macOS uses CommonCrypto (Apple system framework, always available); - Linux/cross-platform uses OpenSSL 3.x (Apache-2.0); - the RFB core never sees a provider-specific type. Both DES and the VNC key schedule are described by RF

## Decision

1. **Provider interface** in `include/farsee/` declares only opaque handles and pure-C entry points; no OpenSSL or CommonCrypto type appears there.
2. **macOS provider** uses `CCCrypt` (CommonCrypto) for DES-ECB and a project-owned key-schedule implementation derived from RFC 6143.
3. **Linux / cross provider** uses OpenSSL 3.x `EVP_*` API for DES-ECB and the same project-owned key-schedule implementation.
4. **Key schedule** is implemented once, in `src/crypto/`, in plain C with full known-answer tests. It is derived from the RFC table, not from any implementation.
5. **Password handling** (plan.md §6.3, §15.3): - never accepted as a CLI argument; - read from a tty (echo disabled) or `--password-fd`; - held in a single locked buffer and zeroized through a compiler-resistant helper on ever

## Consequences

- Two provider `.c` files compile-select via platform `#ifdef`; the core links against an abstract symbol. - Each provider has its own known-answer test; both must pass. - Adding a third provider (e.g. mbedTLS, BoringSSL) is a new ADR + license check; the interface makes that local.
