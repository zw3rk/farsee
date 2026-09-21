# Known limitations

## Intentional non-goals

- TLS and VeNCrypt for RFB
- Apple High Performance Screen Sharing and HEVC media
- Tight/JPEG, Hextile, HDR, audio, Sixel, and tmux passthrough
- ExtendedDesktopSize and extended clipboard formats
- A Windows-hosted farsee binary

Use a trusted network or SSH/VPN when the selected RFB path has no encrypted
transport.

## Apple paths

- The Apple connect policy admits security types 33 and 36. It prefers type 33
  by default. `--apple-security=36` requires type 36.
- The post-auth record suite is AES-128-CBC for setup52 type `0x044f`, method 1.
  Unsupported suites fail closed.
- Apple `0x03f3` validates type-0 command planes and decodes supported image
  planes for painting. The DCT path accepts the observed full-DC, DC-reuse,
  and luma-only selectors; reserved selectors and unmeasured forms consume
  with no damage.
- Apple `0x0450` decodes the supported profile-1000 alpha cursor and composites
  it into the presentation copy. Other profile values and non-canonical
  negotiated pixel formats fail closed.
- An authenticated peer can still provide an all-black framebuffer. The client
  detects sustained black output but cannot distinguish every remote desktop or
  login-state cause.
- Full Apple desktop parity and sustained hardware matrices remain open.

## Other gaps

- Manual PTY edge-case coverage remains incomplete.
- The full Windows RDP interoperability matrix is incomplete beyond the tested
  first-frame and xrdp cases.
- The separate engine/reactor architecture remains scaffold code. The live path
  uses SHARED-MT.

Do not claim HDR/audio/HEVC, guaranteed 4K60 via PTY, or full Apple desktop
parity.
