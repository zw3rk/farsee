<!-- SPDX-License-Identifier: Apache-2.0 -->

# captures/ — developer-only local frame output (gitignored)

Only developer, sanitizer, coverage, and fuzz products can link the private
capture-artifact interface. Production and release products cannot write
framebuffer dumps. Diagnostic framebuffer output can contain private screen
content. Git ignores everything in this directory except this README. Never
commit its contents.

## Sidecar format (`*.meta`)

When an enabled diagnostic path writes capture `N`, it also writes a sidecar
`N.meta` with one line of `key=value` fields:

- `w`, `h`, `stride` — framebuffer geometry and row stride in bytes.
- `gen` — framebuffer generation at capture time.
- `present_nz` — sampled pixels whose RGB channels are not all zero.
- `samples` — total sampled pixels.
- `nonblack` — `yes` exactly when `present_nz` is greater than 200.

The sampler examines pixels at 16-pixel intervals in each direction.
