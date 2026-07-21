# Provenance

Clean-room sources (plan.md §5). Update when a new external fact influences code.

## Public specs

| Source | Use |
|--------|-----|
| [RFC 6143](https://datatracker.ietf.org/doc/html/rfc6143) + [errata](https://www.rfc-editor.org/errata/rfc6143) | RFB |
| [IANA RFB](https://www.iana.org/assignments/rfb/rfb.xhtml) | types, encodings, keysyms |
| [Kitty graphics](https://sw.kovidgoyal.net/kitty/graphics-protocol/) | direct + SHM present |
| POSIX / platform man pages | sockets, poll, termios, shm |
| Apple public Screen Sharing / Remote Desktop docs | dialect overview only |
| OpenSSL / CommonCrypto docs | crypto providers (not algorithms from scratch) |

## Project-owned

| Artifact | Use |
|----------|-----|
| `docs/apple/apple-wire-spec.md` | type-33 wire fields |
| `RSA1-UNBLOCK.md` | RSA1 branch-entry / packet layouts |
| `docs/apple/srp-challenge-offsets.md` | SRP challenge layout |
| `docs/gates/interop-evidence/` | R6 / post-auth fixtures (minimal) |
| Synthetic tests under `tests/` | regression oracles |

## Prohibited

GPL/AGPL/LGPL VNC implementations (LibVNCClient, TigerVNC, termvnc, …) —
no read, copy, translate, or test reuse. ADR-0001.

Label non-obvious fields: **CAPTURED** · **INFERRED** · **UNKNOWN** · **CONFLICTING**.
