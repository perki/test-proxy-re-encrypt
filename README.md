# Proxy Re-Encryption Explorer

Explore and compare different **proxy re-encryption** mechanisms. Proxy re-encryption allows a proxy (e.g. a server) to transform ciphertext encrypted for one party so that another party can decrypt it — without the proxy ever seeing the plaintext.

## What it does

This project provides a unified API over two proxy re-encryption backends, combined with envelope encryption for the actual data:

**Re-encryption backends:**
- [IronCore Labs recrypt](https://github.com/IronCoreLabs/recrypt-node-binding) (`ironcore-0`) — Transform encryption based on BBS98
- [aldenml/ecc](https://github.com/aldenml/ecc) (`aldenml-ecc-0`) — ECC-based proxy re-encryption

**Envelope encryption:**
- AES-256-GCM (`aes-256-gcm-0`)
- AES-192 (`aes-192-0`)

All combinations are tested (2 backends x 2 envelopes).

## How proxy re-encryption works

```
1. Origin generates a key pair and encrypts data with their public key
2. Origin creates a "transform key" from their private key to Target's public key
3. A Proxy (server) re-encrypts the data using the transform key
   — the Proxy never sees the plaintext
4. Target decrypts the re-encrypted data with their own private key
```

## Example usage

```js
const lib = require('./src/lib');

// Generate keys for two parties
const originKeys = await lib.generateKeys('origin', { recrypt: 'ironcore-0' });
const targetKeys = await lib.generateKeys('target', { recrypt: 'ironcore-0' });
const proxyKeys  = await lib.generateKeys('proxy',  { recrypt: 'ironcore-0' });

// Origin encrypts data
const encrypted = await lib.encryptWithKeys(
  { message: 'secret data' },
  originKeys, originKeys.public,
  { recrypt: 'ironcore-0', envelope: 'aes-256-gcm-0' }
);

// Origin creates a transform key for Target
const transformKey = await lib.getTransformKey(originKeys, targetKeys.public);

// Proxy re-encrypts (without seeing the plaintext)
const reEncrypted = await lib.recryptForKeys(encrypted, transformKey, proxyKeys);

// Target decrypts with their own private key
const decrypted = await lib.decryptWithKeys(reEncrypted, targetKeys.privateKey);
// => { message: 'secret data' }
```

A mock server API (`src/server/API.js`) demonstrates the full flow with users, streams, events, and recipient sharing via proxy re-encryption.

## Setup

```
npm install
```

## Tests

```
npm test
```

## Browser Tests

```
npm run build
npm run web
```

Then open https://whatever.backloop.dev:8465/tests.html

Published at [https://perki.github.io/test-proxy-re-encrypt/](https://perki.github.io/test-proxy-re-encrypt/)
