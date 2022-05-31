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


**Current Approach is wrong**
- Plaintext cannot be arbitrary (see comments from BobWall bellow)
- The Plaintext should be generated before and eventually used a symetric key to encrypt content
  - Then Plaintext should be encrypted with the public key of the user and sent/stored alongside the data 

we exposed that in our public API. The only safe way to generate a plaintext is to use gen_plaintext. https://github.com/IronCoreLabs/recrypt-rs/blob/main/src/api.rs#L823 

If you want to use it as an encryption key for AES or something else you can use derive_symmetric_key -- https://github.com/IronCoreLabs/recrypt-rs/blob/main/src/api.rs#L823

**Investigate on:** the following exchange snips (extracted from discord Ironcore)

BobWall: " if you want to encrypt arbitrary text, you need to find a way to map the text onto one of the points" and "

BobWall: "The Plaintext is a point on an extension of the elliptic curve. The transform crypto math only works on these points - if you want to encrypt arbitrary text, you need to find a way to map the text onto one of the points, and a way to reverse that mapping after you decrypt the point to recover the arbitrary text."

About "padding plain text with whiteshpace instead of using" =>

BobWall: You definitely do not want to do that , even if it looks like it works. Any time you want to encrypt something, you should generate a random Plaintext, encrypt that with recrypt,  derive a symmetric key from the Plaintext, and encrypt your message with that symmetric key and a random IV. The result would be the encrypted Plaintext plus the AES-encrypted message.


===> 
BobWall: Our proxy reencryption algorithm requires as input a value that belongs to a set of points with special characteristics that are on the elliptic curve that the algorithm is built around. The algorithm cannot encrypt arbitrary data. You could possibly map arbitrary data to one of these points, encrypt that point, then after you decrypt the point, map it back to the arbitrary data. What we do instead is to randomly generate one of these points, then apply a hash function to it to generate a value that can be used as a key for encryption of the actual data (we use AES256-GCM for the data encryption). We can encrypt the point, transform it, decrypt it, then apply the hash function to retrieve the AES encryption key.
The discussion arose because we use the name Plaintext as the type for these special points on the elliptic curve.
This approach allows you to encrypt messages of any length without padding them - AES256-GCM handles inputs of arbitrary length. But it does require that you generate the point and derive the AES key before you encrypt the data.