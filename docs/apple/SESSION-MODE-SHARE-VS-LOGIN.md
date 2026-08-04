# Share display vs log in (Apple attach mode)

**Status:** cleartext difference CAPTURED (E9) · trailer keying UNKNOWN  
**Evidence:** `docs/gates/interop-evidence/e9-session-mode/`

When another session owns the console, Screen Sharing offers share-display
vs login-as-yourself. Captures show distinct post-auth cleartext; product
path must not assume a single attach mode.

Details and fixtures stay under the gate interop evidence; product wiring
is `rfb_session` attach/session mode (see `include/farsee/rfb_session.h`).
