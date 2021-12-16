let Api256 = null;
let utf8decoder = new TextDecoder(); // default 'utf-8' or 'utf8'

function encrypt(data, toPublicKey, fromSigningKey) {
  const plaintext = new Buffer.alloc(384);
  const msgBuff = new Buffer.from(data, 'utf8');
  plaintext.fill(msgBuff, 0, msgBuff.length);
  return Api256.encrypt(plaintext, toPublicKey, fromSigningKey);
}


function getTransformKey(userKeys, targetPublicKey) {
  return Api256.generateTransformKey(userKeys.privateKey, targetPublicKey, userKeys.signPrivateKey);
}

function generateKeys() {
  const keys = Api256.generateKeyPair();
  const signKeys = Api256.generateEd25519KeyPair();
  return {
    publicKey: keys.publicKey,
    privateKey: keys.privateKey,
    signPublicKey: signKeys.publicKey,
    signPrivateKey: signKeys.privateKey
  }
}

function decrypt(encryptedArray, privateKey) {
  const res = [];
  for (const data of encryptedArray) {
    const decrypted = utf8decoder.decode(Api256.decrypt(data, privateKey)).replace(/\0/g, '')
    res.push(decrypted);
  }
  return res;
}

function transform(data, toPublicKey, fromSigningKey) {
  return Api256.transform(data, toPublicKey, fromSigningKey);
}

module.exports = {
  encrypt,
  decrypt,
  generateKeys,
  getTransformKey,
  transform,
  init: (Recrypt) => {
    //Create a new Recrypt API instance
    Api256 = new Recrypt.Api256();
  }
}