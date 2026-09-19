# farsee — usage

C11 RFB/VNC (and RDP) client for Kitty graphics (KGP) terminals.
See `README.md` for a short list of terminals that implement KGP.

## Quick start

```sh
nix develop
make release
./build/release/bin/farsee --version
./build/release/bin/farsee 192.0.2.50            # VNC, prompts for password
./build/release/bin/farsee rdp://user@host       # RDP
```

**Never** put a password on argv or in a URL (`user:pass@host`). Production
entry rejects URL userinfo passwords (exit 2). Use the TTY prompt or
`--password-fd N`.

```sh
nix develop --command make install INSTALL_PREFIX=$HOME/.local
```

The project build workflow uses Nix flakes. It needs no system-wide package
install.

## Target forms

| Form | Notes |
|------|--------|
| `host[:port]` | Default port 5900 (RFB) or 3389 (RDP) by protocol |
| `vnc://` / `rfb://` / `rdp://host[:port]` | Explicit protocol |
| `…://user@host` | Username OK; password in URL **rejected** |

## Common options

| Flag | Meaning |
|------|---------|
| `--password-fd N` | Read password from FD N (preferred automation) |
| `--user NAME` | Username (RDP / Apple) |
| `--auth auto\|vnc\|apple` | RFB security selection policy |
| `--view-scale PCT` | Live view scale percent |
| `-v` / `--verbose` | FreeRDP/WinPR INFO logs for RDP targets in developer builds only |
| `--log-level off\|error\|warn\|info\|debug\|trace` | Select FreeRDP/WinPR logs for RDP targets in developer builds only |
| `--version` | Build id / version |
| `--protocol-capabilities` | Print the operator capability summary |

Full flag list: `farsee --help` (source of truth may grow; keep this table
as the operator summary).

Optimized release builds keep FreeRDP/WinPR WLog at `off`. They reject `-v`,
`--verbose`, and every `--log-level` form with exit status 2. Use an
RDP-enabled `dev`, `asan-ubsan`, `coverage`, or `fuzz` build for library
diagnostics. These builds reject the controls for RFB targets. Builds without
RDP also reject and omit the controls.

## Live status band

During Kitty sessions the status line shows host/port help plus:

- **scale %** — view scale  
- **RTT ms** — TCP RTT when the kernel reports a sample on an established
  socket (omitted = no sample)  
- **KiB/s** — downlink over a 250 ms latched window (`link_rate_pub`)

Protocol thread latches rate; present/input only load atomics. See ADR-0010.

## Apple security types 33 and 36

The selection policy supports types 33 and 36 and prefers type 33 by default.
Use `--apple-security=36` to require type 36 and fail closed when it is absent.
Type 33 uses RSA1 followed by SRP. Type 36 enters the SRP exchange directly.
Both paths verify the server proof before using the derived wrap key.

These Apple capabilities are present in the retained implementation but are
not approved for release. Release requires the governance decision and any
required counsel review recorded in
`docs/adr/0013-apple-provenance-release-status.md`.

| Mode | Effect |
|------|--------|
| (default) | Cleartext compatibility paint after Apple authentication (ZRLE+Raw + FBUR) |
| `--apple-postauth=records` | Protected records after `0x044f`: AES-CBC + SHA-1 checksum, sealed FBUR, ZRLE paint |
| `--apple-postauth=private` | Protected records with the private Apple encoding list (MVS `0x03f3` first) |
| `--apple-viewer-info` | Send the optional ViewerInfo prelude |
| `--apple-wake-keys=on|off` | Permit or suppress automatic wake click/key input |
| `--apple-security=auto|36` | Prefer type 33, or require type 36 |

Apple MultiVariant (`0x03f3`) type-0 rectangles paint. No flag turns this on:
the client uses the quantisation tables the server sends in its own `0x03f3`
control message. A rectangle is consumed without painting — never painted
wrongly — when those tables have not arrived, when the quality pair is not one
of the supported quality profiles, when a tile class is not recognized, or when
the image plane does not parse.

Apple `0x0450` carries an alpha cursor. Farsee decodes its premultiplied
negotiated-format pixels and separate alpha plane into a straight RGBA8 cursor
sprite. The presentation copy composites the sprite at the local pointer
position. The cursor remains separate from the authoritative framebuffer.

See `docs/known-limitations.md` and `docs/apple/apple-wire-spec.md`.

### Authorized macOS acceptance

Run the bounded type-36 protected-session check through the Makefile. Open a
password descriptor without putting the password in argv or the environment:

```sh
exec 3<path-to-private-password-file
FARSEE_USER=account FARSEE_PASSWORD_FD=3 \
  nix develop --command make macos-acceptance \
  MACOS_ACCEPTANCE_HOST=mac.example
exec 3<&-
```

Set `MACOS_ACCEPTANCE_BIN=/absolute/path/to/farsee` to run the gate against a
prebuilt, signed candidate. The target still prepares the release build, but
the acceptance runner executes the selected candidate binary.

The target requests attachment to the active shared desktop by default. Set
`FARSEE_APPLE_ATTACH=login` to qualify the login-window path. The result omits
the host, account, password, child log, and descriptor. A pass proves
authentication, protected-record activation, and bounded session entry. It
does not replace the manual fidelity and input matrix.

## Secrets

- Password: TTY or `--password-fd` only; required empty passwords are refused;
  the owned allocation is zeroized after use
- Classic VNC Authentication uses the first eight acquired password bytes;
  RDP and Apple authentication receive the complete acquired password
- Known-hosts / TOFU: fail-closed on change (see SECURITY.md)

## Build targets

`make help` · `make test` · `make no-rdp-release-check` ·
`make check-reproducible` · `make asan-ubsan` · `make ci`
Always: `nix develop --command make <target>`.

`release/dependencies.json` is the release-platform authority. It currently
permits complete release artifacts on Apple silicon and Intel macOS. Linux
remains in the build and test matrix, but `make release-artifacts` rejects a
Linux host until its runtime license policy is approved.
