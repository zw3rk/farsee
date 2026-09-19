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
(KGP). Use `--presenter null` when the client must receive frames without
displaying them.

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
| `make no-rdp-release-check` | Optimized release gates without FreeRDP |
| `make check-reproducible` | Reproduce and compare complete artifacts |
| `make coverage` / `make coverage-report` | Coverage build + report |
| `make fuzz-smoke` | Brief corpus run per fuzz target |
| `make check-license` | SPDX + third-party notices |
| `make clean` | Remove build outputs |

The build and test matrix supports macOS and Linux. Published release
artifacts are currently limited to `aarch64-darwin` and `x86_64-darwin` by
`release/dependencies.json`. Linux release packaging fails closed because its
runtime libraries are not approved by the locked release-license policy.

## Scope

- **Classic VNC** (RFB 3.3/3.7/3.8): VNC Auth, Raw / CopyRect / ZRLE, Cursor,
  DesktopSize, input, clipboard, Bell
- **Apple Screen Sharing:** security types 33 and 36 are live. The default
  policy prefers 33; `--apple-security=36` requires 36. These features are
  present in the retained implementation but are not approved for release; see
  [ADR-0013](docs/adr/0013-apple-provenance-release-status.md).
- **Apple encodings:** `0x03f3` supported type-0 image planes paint;
  `0x0450` decodes to a separate RGBA8 alpha cursor and composites into the
  copied presentation frame.
- **RDP** via FreeRDP
- **Live graphics** need a KGP-capable terminal

## Known limitations

No VNC TLS/VeNCrypt. The default Apple post-auth mode is the cleartext
compatibility path; protected records and the private Apple encoding list are
explicit options. Apple `0x0450` supports the profile-1000 cursor;
other profiles fail closed. Details:
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

Apache-2.0 — see [`LICENSE`](LICENSE). Source and dependency rules are in
ADR-0001. ADR-0013 and [`docs/provenance.md`](docs/provenance.md) record the
separate Apple feature release block.
