# ADR-0012: Presenter generation freeze + public header honesty

- **Status:** Accepted
- **Date:** 2026-07-30
- **Related:** ADR-0010, ADR-0011, quality-remaining Q5/Q6

## Context

1. `include/farsee/` remains the monorepo public include root for agents and tests (~86 headers). Product install surface is not a separate tree yet. 2. **Product-facing** (CLI/session/MT): e.g. `rfb_session.h`, `cli_args.h`, `cli_target.h`, `farsee_mt_session.h`, `farsee_frame_slot.h`, `farsee_cmd_queue.h`, `live_shell.h`, `live_demux.h`, `secret_fd.h`, `error.h`, `handshake.h` (security select). 3. **Internal / dialect / test-only** (not a separate install set, but agents should treat as non-API): `fake_apple_server.h`, Apple crypto/session/record internals, `rdp_*` under `src/protocol/rdp/*

## Decision

1. **Live RFB** uses **v1** `rfb_presenter_ops` / kitty_tile directly (RGBA publish path).
2. **Live RDP** keeps **v1 Kitty/dump/null** wrapped once through `farsee_presenter_v1_adapter` so FreeRDP callbacks can use the **v2** `farsee_presenter` API and `accepts_bgra8888` capability. This is **not** a second product presenter implementation — it is a format/capability bridge on the FreeRDP boundary. 3. Do **not** grow a third presenter generation. Future native BGRA Kitty path may delete the adapter; until then freeze dual stack as: v1 widgets + one adapter at RDP edge. 4. `rdp_worker` remains **test/scaffold only** (ADR-0011 product link exclude).

## Consequences

- Quality-remaining Q5/Q6 documented complete without mass header moves or RDP present rewrite risk. - Next presenter work: optional native BGRA present ops, then drop adapter.
