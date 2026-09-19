# ADR-0012: Presenter generation freeze + public header honesty

- **Status:** Accepted
- **Date:** 2026-07-30
- **Related:** ADR-0010, ADR-0011

## Context

1. `include/farsee/` remains the monorepo public include root for source and
   tests. The product install surface is not a separate tree.
2. Product-facing headers cover CLI, session, and SHARED-MT interfaces. Examples
   include `rfb_session.h`, `cli_args.h`, `cli_target.h`,
   `farsee_mt_session.h`, `farsee_frame_slot.h`, `farsee_cmd_queue.h`,
   `live_shell.h`, `live_demux.h`, `secret_fd.h`, `error.h`, and `handshake.h`.
3. Internal, dialect, and test-only headers remain in the same include root but
   are not product APIs. Examples include `fake_apple_server.h`, Apple crypto,
   session, and record internals, and RDP-private headers under
   `src/protocol/rdp/`.

## Decision

1. **Live RFB** uses **v1** `rfb_presenter_ops` / kitty_tile directly (RGBA publish path).
2. **Live RDP** keeps **v1 Kitty/null** wrapped once through
   `farsee_presenter_v1_adapter` so FreeRDP callbacks can use the **v2**
   `farsee_presenter` API and its `accepts_bgra8888` capability. This is a
   format and capability bridge at the FreeRDP boundary, not a second product
   presenter implementation.
3. Do **not** add a third presenter generation. A future native BGRA Kitty path
   can remove the adapter. Until then, keep v1 presenters and one adapter at
   the RDP edge.
4. Live RFB and RDP share one private application owner for presenter
   selection, construction, and teardown. The owner preserves the distinct v1
   and v2 frontend contracts above. It is not a presenter generation.
5. `rdp_worker` remains test and scaffold code only under ADR-0011.

## Consequences

- Product and internal headers remain in one include tree with documented API
  intent.
- The presenter boundary avoids mass header moves and an RDP presentation
  rewrite.
- One owner now enforces the live presenter lifecycle and keeps teardown
  output alive for each frontend's final Kitty drain.
- A native BGRA presenter can replace the v1 adapter in a later change.
