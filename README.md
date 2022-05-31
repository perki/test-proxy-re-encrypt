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
- Open https://l.rec.la:4443 to see web based example 

This page is published on [https://perki.github.io/test-proxy-re-encrypt/](https://perki.github.io/test-proxy-re-encrypt/)

**Speed & buffering:**
Messages are limited to 384 chars so I quickly implemented a splitting logic see: `buffer_split.js`. 

Running the script shows that encryting / transforming / decrypting text is taking arrount 15ms / char .. !!! 



**Investigating:**
- How to rotate keys: 
  - inspiration: https://github.com/IronCoreLabs/ironnode/blob/01df7123ee25ad3991c3158c1784b830f0d008d0/src/crypto/Recrypt.ts#L54

- Average simple encryption / decryption flow 15ms / char

**Todo** 
  - Randomize unused data 
  - Find a better way to store type and size 
  - Implement streaming 
  - Check "sub access mechanism" 

Other implementation to look at: https://github.com/aldenml/ecc
https://www.npmjs.com/package/@aldenml/ecc

**Investigate on:** the following exchange snips (extracted from discord Ironcore)

BobWall: " if you want to encrypt arbitrary text, you need to find a way to map the text onto one of the points" and "

BobWall: "The Plaintext is a point on an extension of the elliptic curve. The transform crypto math only works on these points - if you want to encrypt arbitrary text, you need to find a way to map the text onto one of the points, and a way to reverse that mapping after you decrypt the point to recover the arbitrary text."

About "padding plain text with whiteshpace instead of using" =>

BobWall: You definitely do not want to do that , even if it looks like it works. Any time you want to encrypt something, you should generate a random Plaintext, encrypt that with recrypt,  derive a symmetric key from the Plaintext, and encrypt your message with that symmetric key and a random IV. The result would be the encrypted Plaintext plus the AES-encrypted message.


