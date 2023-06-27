let Api256 = null;
let utf8decoder = new TextDecoder(); // default 'utf-8' or 'utf8'

const ENCRYPTED_DATA_SIZE = 384;

const aes256gcm = require('./aes-256-gcm');

function encrypt(data, toPublicKey, fromSigningKey) {
  const password = get384Password();
  const encryptedPassword = encryptedPasswordToString(Api256.encrypt(password, stringToPublicKey(toPublicKey), stringToKey(fromSigningKey)));
  const encryptedData = aes256gcm.encrypt(data, password);
  const encrypted = {encryptedPassword, encryptedData};
  return encrypted;
}

function encryptWithPassword(data, password ) {
  const encryptedData = aes256gcm.encrypt(data, password);
  const encrypted = { encryptedData };
  return encrypted;
}



function getTransformKey(userKeys, targetPublicKey) {
  return Api256.generateTransformKey(
      stringToKey(userKeys.privateKey), 
      stringToPublicKey(targetPublicKey), 
      stringToKey(userKeys.signPrivateKey));
}

function generateKeys(id) {
  const keys = Api256.generateKeyPair();
  const signKeys = Api256.generateEd25519KeyPair();
  const password = get384Password();
  const encryptedPassword = encryptedPasswordToString(Api256.encrypt(password, keys.publicKey, signKeys.privateKey));
  const key = {
    privateKey: keyToString(keys.privateKey),
    signPrivateKey: keyToString(signKeys.privateKey),
    public : {
      id: id || Math.random().toString(36).substring(2, 6),
      publicKey: publicKeyToString(keys.publicKey),
      signPublicKey: keyToString(signKeys.publicKey),
      encryptedPassword
    }
  }
  return key;
}

function decryptPassword(encryptedPassword, privateKey) {
  const password = Api256.decrypt(stringToEncryptedPassword(encryptedPassword), stringToKey(privateKey));
  return password;
}

function decrypt(data, privateKey) {
  const password = decryptPassword(data.encryptedPassword, privateKey);
  const decryptedData = decryptWithPassword(data, password);
  return decryptedData;
}

function decryptWithPassword(data, password) {
  const decryptedData = aes256gcm.decrypt(data.encryptedData, password);
  return decryptedData;
}

function decryptArray(encryptedArray, privateKey) {
  const res = [];
  for (const data of encryptedArray) {
    res.push(decrypt(data, privateKey));
  }
  return res;
}

function transform(data, toPublicKey, fromSigningKey) {
  const transformed = {
    encryptedPassword: Api256.transform(data.encryptedPassword, toPublicKey, fromSigningKey),
    encryptedData: data.encryptedData
  }
  return transformed;
}

function get384Password() {
  return Api256.generatePlaintext();
}

module.exports = {
  get384Password,
  encrypt,
  encryptWithPassword,
  decryptPassword,
  decryptArray,
  decryptWithPassword,
  decrypt,
  generateKeys,
  getTransformKey,
  transform,
  init: (Recrypt) => {
    //Create a new Recrypt API instance
    Api256 = new Recrypt.Api256();
  }
}

function keyToString(buffer) {
  return buffer.toString('base64');
}

function stringToKey(string) {
  return Buffer.from(string, 'base64');
}

function publicKeyToString(publicKey) {
  return publicKey.x.toString('base64') + ' ' + publicKey.y.toString('base64');
}

function stringToPublicKey(string) {
  const [x, y] = string.split(' ');
  return {
    x: Buffer.from(x, 'base64'),
    y: Buffer.from(y, 'base64'),
  }
}

function encryptedPasswordToString(data) {
  const res = [
    publicKeyToString(data.ephemeralPublicKey),
    data.encryptedMessage.toString('base64'),
    data.authHash.toString('base64'),
    data.publicSigningKey.toString('base64'),
    data.signature.toString('base64'),
    data.transformBlocks.map((b) => b.toString('base64'))
  ];
  return JSON.stringify(res);
}

function stringToEncryptedPassword(string) {
  const [ephemeralPublicKeyS, encryptedMessageS, authHashS, publicSigningKeyS, signatureS, transformBlocksS] = JSON.parse(string);
  const res = {
    ephemeralPublicKey: stringToPublicKey(ephemeralPublicKeyS),
    encryptedMessage: Buffer.from(encryptedMessageS, 'base64'),
    authHash: Buffer.from(authHashS, 'base64'),
    publicSigningKey: Buffer.from(publicSigningKeyS, 'base64'),
    signature: Buffer.from(signatureS, 'base64'),
    transformBlocks: transformBlocksS.map((s) => Buffer.from(s, 'base64'))
  }
  return res;
}