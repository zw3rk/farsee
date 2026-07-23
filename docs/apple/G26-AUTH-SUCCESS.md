# Type-33 auth — PASS (G26)

**VM:** macos-ssh · macOS 15.7.7 · loopback (`127.0.0.1:5900`)

## Result

Full type-33 login: SecurityResult=0, M2 verified, wrap_key derived,
ServerInit (e.g. 2048×1536).

**Loopback vs remote:** external connects can get SecurityResult=2; localhost
uses the standard RSA1/SRP path. Prefer loopback for auth proof.

## Flow (proven)

1. Banner `RFB 003.889\n` → select type 33  
2. RSA1 key request (15 B) → key response  
3. Packet 1 identity (654 B) → SRP challenge (~1169 B)  
4. SRP: parse N/g/salt/B/iters/opts → A, M1 → packet 2  
5. M2 + SecurityResult=0 → ClientInit → ServerInit  

Wire layouts: `RSA1-UNBLOCK.md`, `docs/apple/srp-challenge-offsets.md`,
`docs/apple/apple-wire-spec.md`.
