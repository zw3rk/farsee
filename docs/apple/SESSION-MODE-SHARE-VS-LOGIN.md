# Share display vs log in (Apple attach mode)

**Status:** multi-session and modern single-session paths are supported.

When another session owns the console, Screen Sharing offers share-display
vs login-as-yourself. The two modes use distinct post-auth cleartext
ViewerInfo sizes (share 74 B / login 202 B). The product path must not assume
a single attach mode for that dialog.

**Modern single-session:** the client does not send ViewerInfo after
ServerInit. It sends cfg21, msg12-part, and SetEncodings before switching to
`0x044f` AES-128-CBC records. The cleartext product path therefore omits
ViewerInfo by default.

Product wiring is in the `rfb_session` attach/session mode contract. See
`include/farsee/rfb_session.h`.
