# Architecture

Decisions are recorded in `docs/adr/`.  
**Live product path (normative):** SHARED-MT — ADR-0010 / ADR-0011.

## Principles

1. Pure protocol core (no Kitty/socket knowledge in RFB parsers).  
2. Incremental, resumable parsers.  
3. Canonical persistent RGBA8 framebuffer (ADR-0003).  
4. Presenter abstraction (null / Kitty direct / Kitty SHM).
5. Interactive live = **SHARED-MT** (`farsee_mt_run`: protocol · present ·
   input). Session **publishes** frames; app owns present.  
6. Explicit ownership; fail closed; no hidden globals.  
7. Engine/reactor modules = unit-tested scaffold only until a vertical slice.

## Live dataflow

```
CLI → connect/auth (main) → farsee_mt_run
        protocol: RFB session / FreeRDP pump → frame_slot publish
        present:  latest-wins → Kitty / null
        input:    TTY demux → cmd / inject queue → protocol
```

| Path | Entry |
|------|--------|
| VNC / Apple security types 33 and 36 | `farsee_run_rfb` (`rfb_live.c`) |
| RDP | `farsee_run_rdp` (`rdp_live.c`) → `rdp_mt_run` |


## Layout

`include/farsee/` · `src/{core,rfb,fb,io,crypto,present,farsee,protocol/rdp,app}/` ·
`tests/` · `docs/` · `tools/` · `Makefile` + `flake.nix`

Build: `nix develop --command make help` · full gate `make ci`.
