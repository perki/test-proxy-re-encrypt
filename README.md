# Testing proxy re-encryption


Testing https://github.com/IronCoreLabs/recrypt-node-binding [IronCoreLabs](https://github.com/IronCoreLabs) proxy re-encryption

Everything starts in src/index.js

Object oriented implementation in src/oo-index.js

- `npm install` setup
- `npm run api` direct api example
- `npm run oo` Object Oriented example

Web:

- `npm run build` Build web based example
- `npm run web` Run webserver 
- Open https://l.backloop.dev:4443 to see web based example 

This page is published on [https://perki.github.io/test-proxy-re-encrypt/](https://perki.github.io/test-proxy-re-encrypt/)

**Investigating:**
- How to rotate keys: 
  - inspiration: https://github.com/IronCoreLabs/ironnode/blob/01df7123ee25ad3991c3158c1784b830f0d008d0/src/crypto/Recrypt.ts#L54

- Average simple encryption / decryption flow 15ms / char

**Todo** 
  - Find a better way to store type and size 
  - Implement streaming 
  - Check "sub access mechanism" 

Other implementation to look at: https://github.com/aldenml/ecc
https://www.npmjs.com/package/@aldenml/ecc

