
let ecc;

async function main () {

// client A setup public/private keys and signing keys
const keysA = await ecc.pre_schema1_KeyGen();
const signingA = await ecc.pre_schema1_SigningKeyGen();

// client B setup public/private keys (signing keys are not used here)
const keysB = await ecc.pre_schema1_KeyGen();

// proxy server setup signing keys
const signingProxy = await ecc.pre_schema1_SigningKeyGen();

// client A select a plaintext message, this message
// in itself is random, but can be used as a seed
// for symmetric encryption keys
const message = await ecc.pre_schema1_MessageGen();
const messageS = uintArrayToString(message);
const publicKeyAS = uintArrayToString(keysA.pk);
const signingSecretKeyA = uintArrayToString(signingA.ssk);
const signingPublicKeyA = uintArrayToString(signingA.spk);

console.log({messageS});

// client A encrypts the message to itself, making it
// possible to send this ciphertext to the proxy.
const ciphertextLevel1 = await ecc.pre_schema1_Encrypt(
  stringToUintArray(messageS), 
  stringToUintArray(publicKeyAS), 
  {spk: stringToUintArray(signingPublicKeyA), ssk: stringToUintArray(signingSecretKeyA)});

// client B is able to decrypt ciphertextLevel2 and the result
// is the original plaintext message
const messageDecrypted1 = await ecc.pre_schema1_DecryptLevel1(
  ciphertextLevel1,
  keysA.sk,
  signingA.spk
);

console.log({'B': uintArrayToString(messageDecrypted1)});

// client A sends ciphertextLevel1 to the proxy server and
// eventually client A allows client B to see the encrypted
// message, in this case the proxy needs to re-encrypt
// ciphertextLevel1 (without ever knowing the plaintext).
// In order to do that, the client A needs to create a re-encryption
// key that the proxy can use to perform such operation.

// client A creates a re-encryption key that the proxy can use
// to re-encrypt the ciphertext (ciphertextLevel1) in order for
// client B be able to recover the original message
const reEncKey = await ecc.pre_schema1_ReKeyGen(keysA.sk, keysB.pk, signingA);

// the proxy re-encrypt the ciphertext ciphertextLevel1 with such
// a key that allows client B to recover the original message
const ciphertextLevel2 = await ecc.pre_schema1_ReEncrypt(
    ciphertextLevel1,
    reEncKey,
    signingA.spk, keysB.pk,
    signingProxy
);

// client B is able to decrypt ciphertextLevel2 and the result
// is the original plaintext message
const messageDecrypted = await ecc.pre_schema1_DecryptLevel2(
    ciphertextLevel2,
    keysB.sk, signingProxy.spk
);

// now both client A and client B share the same plaintext message
// messageDecrypted is equal to message

console.log({'C': uintArrayToString(messageDecrypted)});

}


function uintArrayToString(u8) {
  return Buffer.from(u8).toString('base64');
}

function stringToUintArray(b64) {
  return new Uint8Array(Buffer.from(b64, 'base64'))
}


(async () => {
  ecc = await import('@aldenml/ecc');
  await main();
})();
