# farsee

Apache-2.0 C11 RFB/VNC + RDP client that draws the remote desktop in a
[Kitty graphics](https://sw.kovidgoyal.net/kitty/graphics-protocol/) terminal.

This is **not** Apple High Performance Screen Sharing (AHPSS). Classic VNC
Authentication proves password knowledge only — it is **not** session
encryption. See [`SECURITY.md`](SECURITY.md).

## Install / run

```sh
nix run github:zw3rk/farsee -- --version
nix run github:zw3rk/farsee -- vnc://host.example:5900
nix run github:zw3rk/farsee -- rdp://user@host.example
```

Password is never taken from argv or a URL. Use the TTY prompt (echo off) or
`--password-fd N`. Production rejects URL userinfo passwords.

## Terminals (Kitty graphics)

Live graphics use the
[Kitty graphics protocol](https://sw.kovidgoyal.net/kitty/graphics-protocol/)
(KGP). Without a supporting terminal, use `--dump-frame` for a single-frame
RGBA/PPM dump.

Terminals that implement KGP (per the protocol docs; feature depth varies):

| Terminal | Notes |
| -------- | ----- |
| [Kitty](https://sw.kovidgoyal.net/kitty/) | Reference implementation |
| [Ghostty](https://ghostty.org) | |
| [WezTerm](https://wezfurlong.org/wezterm/) | |
| [Konsole](https://konsole.kde.org/) | |
| [Warp](https://www.warp.dev/) | |
| [iTerm2](https://iterm2.com/) | |
| [wayst](https://github.com/91861/wayst) | |
| [st](https://st.suckless.org/patches/kitty-graphics-protocol/) | With the KGP patch |
| [xterm.js](https://xtermjs.org/) | Embeddable / web |

Farsee is developed and manually accepted primarily against **Kitty**. Other
entries may work for basic placement; SHM transfer, APC drain timing, and
cursor overlay can differ. Nested multiplexers (tmux, screen) often need
passthrough configuration.

## Develop

```sh
nix develop
make help
make test
make ci
```

Hermetic toolchain via the flake (`flake.nix`); all work goes through the
Makefile (`make help`).

## Common targets

| Target | What it does |
| ------ | ------------ |
| `make help` | Full target catalogue |
| `make` / `make build` | Dev build (Clang, strict warnings) |
| `make test` | Build and run the unit suite |
| `make ci` | Full release-candidate gate |
| `make asan-ubsan` | Address + UBSan build and tests |
| `make release` | Optimized release binary |
| `make coverage` / `make coverage-report` | Coverage build + report |
| `make fuzz-smoke` | Brief corpus run per fuzz target |
| `make check-license` | SPDX + third-party notices |
| `make clean` | Remove build outputs |

## Scope

- **Classic VNC** (RFB 3.3/3.7/3.8): VNC Auth, Raw / CopyRect / ZRLE, Cursor,
  DesktopSize, input, clipboard, Bell
- **Apple Screen Sharing type-33** MVP (cleartext post-auth path)
- **RDP** via FreeRDP
- **Live graphics** need a KGP-capable terminal (or `--dump-frame`)

## Known limitations

No VNC TLS/VeNCrypt; type-33 ships as a cleartext MVP. Details:
[`docs/known-limitations.md`](docs/known-limitations.md).

## Documentation

| Doc | Role |
| --- | ---- |
| [`USAGE.md`](USAGE.md) | CLI, flags, runtime paths |
| [`plan.md`](plan.md) | Controlling requirements |
| [`docs/implementation-status.md`](docs/implementation-status.md) | Gate status |
| [`SECURITY.md`](SECURITY.md) | Secure-use guide |
| [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) | Dependencies & licenses |

## License

Apache-2.0 — see [`LICENSE`](LICENSE). The RFB stack is written from public
specs (RFC 6143, IANA, platform docs); it does not incorporate GPL/AGPL/LGPL
VNC client sources (see ADR-0001).
