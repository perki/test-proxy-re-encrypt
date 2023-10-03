
let ecc;

async function main() {

  // client A setup public/private keys and signing keys
  const keysA = await ecc.pre_schema1_KeyGen();
  const signingA = await ecc.pre_schema1_SigningKeyGen();

  // client B setup public/private keys (signing keys are not used here)
  const keysB = await ecc.pre_schema1_KeyGen();

  // proxy server setup signing keys
  const signingProxy = await ecc.pre_schema1_SigningKeyGen();

  // client C is the origin encrypting party
  const signingC = await ecc.pre_schema1_SigningKeyGen();

  // client C select a plaintext message
  const message = await ecc.pre_schema1_MessageGen();
  const messageS = uintArrayToString(message);

  // proxy encrypts the message with A key
  const ciphertextLevel1 = await ecc.pre_schema1_Encrypt(
    message,
    keysA.pk,
    signingProxy);
    //signingC);

  // client A is able to decrypt ciphertextLevel1 
  const messageDecrypted1 = await ecc.pre_schema1_DecryptLevel1(
    ciphertextLevel1,
    keysA.sk,
    signingProxy.spk
    // signingC.spk
  );

  console.log(' Message decrypted == message ', (messageS == uintArrayToString(messageDecrypted1)));

  
  // client A allows client B to see the encrypted

  // client A creates a re-encryption key that the proxy can use
  // to re-encrypt the ciphertext (ciphertextLevel1) in order for
  // client B be able to recover the original message
  const reEncKey = await ecc.pre_schema1_ReKeyGen(
    keysA.sk, 
    keysB.pk, 
    // signingC // ⚠️ HERE I WOULD LIKE TO AVOID USING `C` signing Key
    signingProxy
  );

  // the proxy re-encrypt the ciphertext ciphertextLevel1 with such
  // a key that allows client B to recover the original message
  const ciphertextLevel2 = await ecc.pre_schema1_ReEncrypt(
    ciphertextLevel1,
    reEncKey,
    //signingC.spk, // ⚠️ HERE I WOULD LIKE TO AVOID USING `C` signing Key
    signingProxy.spk,
    keysB.pk, 
    signingProxy
  );

  // client B is able to decrypt ciphertextLevel2 and the result
  // is the original plaintext message
  const messageDecrypted2 = await ecc.pre_schema1_DecryptLevel2(
    ciphertextLevel2,
    keysB.sk, signingProxy.spk
  );

  // now both client A and client B share the same plaintext message
  // messageDecrypted is equal to message

  console.log(' Message recrypted/decrypted == message ', (messageS == uintArrayToString(messageDecrypted2)));

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
