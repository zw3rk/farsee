<!-- SPDX-License-Identifier: Apache-2.0 -->

# Apple type-33 RSA1 wire format

This document defines the byte-level contract implemented by the RSA1 parser
and serializer.

## Branch entry and public-key request

After `RFB 003.889\n`, when the server offers security type `33` (`0x21`) and
the key is not cached, the client sends one contiguous buffer:

```text
u8      selector       = 0x21
u32_be  total_len      = 10
u16_be  version        = 0x0100
byte[4] algorithm      = "RSA1"
u16_be  authtype       = 0
u16_be  inner_len      = 0
```

Exact bytes: `21 00 00 00 0a 01 00 52 53 41 31 00 00 00 00`

The key response is:

```text
u32_be  total_len      = der_len + 7
u32_le  version        = 0x00000100
u16_be  der_len
byte[]  DER SubjectPublicKeyInfo
u8      trailing_zero  = 0
```

The parser requires `total_len == der_len + 7`, a policy-bounded DER value,
an RSA-2048 modulus, no trailing bytes, and host-key approval before identity
data is sent.

## Packet 1

The identity plaintext before RSA PKCS#1 v1.5 encryption is:

```text
u32_be  payload_len        = username_len + 7
u32_be  username_len
byte[]  username_utf8
u16_be  empty_string_len   = 0
u8      empty_opaque_len   = 0
```

Its length is `username_len + 11`. Overlong usernames are rejected.

```text
u32_be  total_len      = 650
u16_be  version        = 0x0100
byte[4] algorithm      = "RSA1"
u16_be  authtype       = 2
u16_be  inner_len      = 256
byte[256] rsa_ciphertext
byte[384] zero_tail
```

The packet is 654 bytes. Without a prior key request, the client concatenates
the selector and packet 1 into one 655-byte transport write.

## Packet 2

After the SRP challenge, with `A` and `M1`:

```text
inner =
    u16_be len(A)             || A
 || u8     len(M1)            || M1
 || u16_be len(options)       || options
 || u8     len(client_random) || client_random

meaningful_body = u16_be 0 || u16_be inner_len || inner

packet =
    u32_be total_len
 || u16_be version = 0x0100
 || "RSA1"
 || u16_be authtype = 2
 || u16_be meaningful_body_len
 || meaningful_body
 || trailing
```

The supported profile uses A=512, M1=64, options=80, and client_random=16.
Thus `inner_len=678`, meaningful length is 682, and `total_len=1076`.

## Validation traps

- Keep the selector and first envelope in one write.
- Encode the version bytes as `01 00`.
- Exclude the leading length field from `total_len`.
- Keep the 384-byte zero tail in packet 1.
- Use PKCS#1 v1.5, not OAEP.
- Keep the identity fields in the specified order.
- Apply host-key policy before sending identity data.
