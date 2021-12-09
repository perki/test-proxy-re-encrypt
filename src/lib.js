const Recrypt = require("@ironcorelabs/recrypt-node-binding");
//Create a new Recrypt API instance
const Api256 = new Recrypt.Api256();

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
    const decrypted = Api256.decrypt(data, privateKey).toString('utf-8').replace(/\0/g, '')
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
  transform
}