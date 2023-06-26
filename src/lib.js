let Api256 = null;
let utf8decoder = new TextDecoder(); // default 'utf-8' or 'utf8'

const ENCRYPTED_DATA_SIZE = 384;

function encrypt(data, toPublicKey, fromSigningKey) {
  const buff384 = new Buffer.alloc(ENCRYPTED_DATA_SIZE);
  const msgBuff = new Buffer.from(data, 'utf8');
  buff384.fill(msgBuff, 0, msgBuff.length);
  const encryptedData = encrypt384Buffer(buff384, toPublicKey, fromSigningKey);
  return encryptedData;
}

function encrypt384Buffer(data, toPublicKey, fromSigningKey) {
  const encryptedData = Api256.encrypt(data, toPublicKey, fromSigningKey);
  return encryptedData;
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


function decrypt384Buffer(data, privateKey) {
  return Api256.decrypt(data, privateKey);
}

function decrypt(data, privateKey) {
  return utf8decoder.decode(Api256.decrypt(data, privateKey)).replace(/\0/g, '');
}

function decryptArray(encryptedArray, privateKey) {
  const res = [];
  for (const data of encryptedArray) {
    res.push(decrypt(data, privateKey));
  }
  return res;
}

function transform(data, toPublicKey, fromSigningKey) {
  return Api256.transform(data, toPublicKey, fromSigningKey);
}

function get384PlaintText() {
  return Api256.generatePlaintext();
}

module.exports = {
  get384PlaintText,
  encrypt,
  encrypt384Buffer,
  decryptArray,
  decrypt,
  decrypt384Buffer,
  generateKeys,
  getTransformKey,
  transform,
  init: (Recrypt) => {
    //Create a new Recrypt API instance
    Api256 = new Recrypt.Api256();
  }
}