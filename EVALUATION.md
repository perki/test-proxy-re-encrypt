# Proxy Re-Encryption Implementations — Comparative Evaluation

## Overview

| | **ironcore-0** | **aldenml-ecc-0** | **recrypt-js-0** | **umbral-pre-0** |
|---|---|---|---|---|
| Package | `@ironcorelabs/recrypt-node-binding` | `@aldenml/ecc` | `recrypt-js` | `@nucypher/umbral-pre` |
| Runtime | Rust native (Node) / WASM (browser) | WASM | Pure JS (elliptic) | Rust → WASM |
| Curve | Curve25519-256 | Ristretto255 | secp256k1 | secp256k1 |
| License | **AGPL-3.0** | MIT | MIT | **GPL-3.0** |
| Version | 0.10.1 | 1.1.0 | 1.1.2 | 0.10.0 |

## Cryptographic Design

| | **ironcore-0** | **aldenml-ecc-0** | **recrypt-js-0** | **umbral-pre-0** |
|---|---|---|---|---|
| PRE scheme | Custom (IronCore) | BBS98 (Schema 1) | AFGH (simplified) | Umbral (threshold) |
| Separate signing keys | Yes (Ed25519) | Yes (Schnorr) | No | No |
| Supports public encryption | Yes | **No** | Yes | Yes |
| Re-encryption levels | Multi-hop | **1 hop only** (level check) | Multi-hop | 1 hop (by design) |
| Threshold support | No | No | No | **Yes** (t-of-n kfrags) |
| Transform needs proxy signing key | Yes | Yes | No | No |
| Ciphertext integrity | authHash + signature | signing verification | None (AES-CBC only) | Built-in AEAD |

### Notes

- **aldenml-ecc** explicitly tracks encryption "levels" (1=original, 2=re-encrypted) and rejects re-encrypting a level-2 ciphertext. The "Encrypt by Public" test is skipped because it requires a separate encryption key from the signing key, which this lib doesn't support.
- **recrypt-js** uses a KEM/DEM approach: the PRE operates on a symmetric key capsule, and the actual plaintext is encrypted with AES-256-CBC. No authentication or signatures are involved — the weakest integrity guarantees.
- **umbral-pre** is the only one with threshold support (configured as 1-of-1 here). In production you'd use t-of-n for split-trust re-encryption.
- **ironcore** has the richest ciphertext structure: ephemeral key, encrypted message, auth hash, signing key, signature, and transform blocks.

## Performance (Node.js, avg of 20 iterations)

| Operation | **ironcore-0** | **aldenml-ecc-0** | **recrypt-js-0** | **umbral-pre-0** |
|---|---|---|---|---|
| Key generation | 0.75 ms | 2.17 ms | 1.05 ms | **0.13 ms** |
| Encrypt | 6.35 ms | 8.45 ms | 4.80 ms | **0.48 ms** |
| Transform key gen | 13.61 ms | 13.72 ms | 3.17 ms | **1.17 ms** |
| Transform (re-encrypt) | 16.33 ms | 17.71 ms | 2.58 ms | **1.32 ms** |
| Decrypt (original) | 5.73 ms | 8.27 ms | 1.39 ms | **0.50 ms** |
| Decrypt (re-encrypted) | 21.77 ms | 27.10 ms | 2.51 ms | **2.10 ms** |

**umbral-pre** is the fastest across the board — 5-20x faster than ironcore/aldenml. This is expected: it's a Rust→WASM binary with optimized secp256k1 operations. **recrypt-js** is surprisingly fast for pure JS, likely because secp256k1 is well-optimized in the `elliptic` library and the scheme is simpler.

## Serialized Sizes (base64/hex encoded, in characters)

| | **ironcore-0** | **aldenml-ecc-0** | **recrypt-js-0** | **umbral-pre-0** |
|---|---|---|---|---|
| Private key | 44 | 44 | 64 | 44 |
| Public key | 89 | 64 | 130 | **44** |
| Encrypted payload | 796 | 1057 | **451** | 259 |
| Transform key | 1013 | 1206 | **201** | 561 |
| Re-encrypted payload | 2103 | 2849 | **586** | 911 |

**umbral-pre** has the smallest keys (compressed points). **recrypt-js** has the smallest encrypted/re-encrypted payloads because the PRE only wraps a 32-byte symmetric key capsule — the actual data goes in a separate AES ciphertext. **ironcore** and **aldenml** have the largest payloads because they embed signatures, auth hashes, and signing public keys.

## Package / Bundle Size

| | **ironcore** | **aldenml-ecc** | **recrypt-js** | **umbral-pre** |
|---|---|---|---|---|
| node_modules | 828K (native) + 1.1M (WASM) | 1.2M | **640K** | 1.1M |
| WASM binary | 1.1 MB | (embedded in JS) | **0** (pure JS) | 443 KB |
| Native binary | 771 KB (.node) | — | — | — |

**recrypt-js** is the lightest — pure JS, no WASM, no native binaries.

## Browser Compatibility

| | **ironcore-0** | **aldenml-ecc-0** | **recrypt-js-0** | **umbral-pre-0** |
|---|---|---|---|---|
| Browser support | WASM (async init) | WASM (async import) | Native JS | WASM (async import) |
| Webpack config needed | alias to wasm-binding | asyncWebAssembly | **Nothing** | asyncWebAssembly |
| Known browser issues | WASM aliasing bugs | None | None | None |

## Practical Tradeoffs Summary

- **ironcore-0**: Most mature/audited PRE implementation. Strongest integrity (signatures + auth hash). Separate signing keys allow distinct encryption and signing identities. But: AGPL license, largest payloads, slowest performance, WASM issues in browser.

- **aldenml-ecc-0**: Clean Ristretto255 implementation with level tracking. But: no public encryption support (signer must know target's encryption key), single-hop only, second slowest.

- **recrypt-js-0**: Lightest deployment — pure JS, no WASM, smallest bundle, smallest payloads. Decent performance. But: **no ciphertext authentication** (AES-CBC without HMAC), no signing, has a serialization bug requiring workarounds (`BN.toArray()` drops leading zeros), MIT license is friendly.

- **umbral-pre-0**: Best overall performance by a large margin, smallest keys, built-in threshold support, built-in AEAD. But: GPL license, and the WASM objects have strict lifecycle semantics (consumed after serialization, must reconstruct from bytes).

## Application: Healthcare Data Sharing with Historical Access Control

### Use Case

Healthcare data stored by context (medication, nutrition, activity...) where a user grants access to specific segments to different practitioners. For example:
- Dr. A gets access to **medication + nutrition**
- Dr. B gets access to **medication + activity**

Accesses can be granted and revoked at any time, but must allow reading data collected in the past.

### Why PRE Fits This Case

The server stores historical events encrypted per-user. When the user grants Dr. A access to "medication", the server must let Dr. A decrypt past medication events — without re-uploading or re-encrypting them, and without the server ever seeing plaintext.

The flow:
1. User's device encrypts each event with user's public key before storage
2. User grants access → generates a transform key (user → Dr. A) scoped to the data segment
3. Server applies transform key to matching historical ciphertexts on read
4. Dr. A decrypts with their own private key
5. User revokes → server deletes the transform key → Dr. A can no longer read (even past data)

### Why Simpler Alternatives Fall Short

- **Re-encrypt on grant**: Requires re-processing potentially years of historical data. With 10 doctors and 5 data segments, that's 50 copies. Every new event needs encryption to all current recipients.
- **Wrap symmetric key per recipient**: Same problem — every grant requires the user's device to be online to re-wrap keys for all historical data segments.
- **Server-side decryption + re-encryption**: Server sees plaintext. Fails healthcare compliance (HIPAA, GDPR health data).

**PRE advantage**: The user's device only needs to be online for the grant (to generate one transform key). The server handles all historical data access without ever seeing plaintext. Revocation is instant — delete the transform key.

### Architecture Sketch

```
Events stored per segment:
  { keyId: "user123:umbral-pre-0:aes-256-gcm-0",
    encryptedPassword: "...",    ← PRE-encrypted symmetric key
    encryptedData: "..." }       ← envelope-encrypted payload

On grant (user device):
  transformKey = getTransformKey(userKeys, drAKeys.public)
  → server stores: { from: "user123", to: "drA", segment: "medication", key: transformKey }

On read (server-side, no plaintext exposure):
  recrypted = transformPassword(event.encryptedPassword, transformKey, proxyKeys)
  → return { ...event, encryptedPassword: recrypted, keyId: "drA:..." }

On revoke:
  → server deletes transformKey → done
```

### Recommendation for This Use Case

**umbral-pre** is the strongest candidate:
- Fastest performance (matters for bulk historical re-encryption on read)
- Threshold support (split trust across multiple proxies — no single server sees the full transform key)
- Built-in AEAD (ciphertext integrity required for healthcare)
- Smallest keys and payloads (storage efficiency for long-term data)
- GPL license is acceptable for a backend service

**ironcore** would be second choice: most audited, strongest integrity guarantees (signatures verify the proxy didn't tamper), separate signing keys. But AGPL is more restrictive and performance is 10-20x worse for bulk reads.

**recrypt-js** and **aldenml-ecc** are less suitable: recrypt-js lacks ciphertext authentication (unacceptable for healthcare), aldenml-ecc doesn't support public encryption (a third-party device can't encrypt for the user).

### Open Design Question: Segment Scoping

PRE itself doesn't know about "medication" vs "activity". Two approaches:

- **Separate key pairs per segment**: The user has a medication keypair, a nutrition keypair, etc. Granting access to "medication" means generating a transform key from the medication keypair to Dr. A's keypair. Cleanest cryptographic guarantee — the server cannot grant access to segments the user didn't authorize. More keys to manage.
- **Single keypair + server-side filtering**: One user keypair, the server decides which events get transformed based on segment metadata. Simpler key management, but the server controls access scope (weaker guarantee — a compromised server could transform events from unauthorized segments).
