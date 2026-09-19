# G2 — RFB version negotiation and security handshake

- **Status:** ✅ PASS
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Reach authenticated state without framebuffer processing: exact 12-byte banner parser; 3.3/3.7/3.8 negotiation; security type list + selection policy; explicit opt-in for None; VNC Authentication provider interface with CommonCrypto and OpenSSL backends; password handling; DES/VNC response known-answer vectors; security result and failure-reason parsing; ClientInit (deferred to G3 — it follows DONE); disconnect/EOF at every handshake state.


## Key paths

- `docs/provenance.md`
- `src/crypto/crypto_commoncrypto.c`
- `src/crypto/crypto_openssl.c`
- `src/crypto/crypto_provider.c`
- `src/rfb/handshake.c`
- `tests/integration/scripted_rfb_server.py`
## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
