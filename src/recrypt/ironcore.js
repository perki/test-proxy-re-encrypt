const Recrypt = require('@ironcorelabs/recrypt-node-binding');
const Api256 = new Recrypt.Api256();

const TYPE = 'ironcore-0';

async function getTransformKey(originPrivateKeys, targetPublicKey) {
  const transformKey = Api256.generateTransformKey(
      stringToBuffer(originPrivateKeys.privateKey), 
      stringToPublicKey(targetPublicKey), 
      stringToBuffer(originPrivateKeys.signPrivateKey));
  return transformKeyToString(transformKey);
}

async function generateKeys(id) {
  const keys = Api256.generateKeyPair();
  const signKeys = Api256.generateEd25519KeyPair();
  const key = {
    privateKey: bufferToString(keys.privateKey),
    signPrivateKey: bufferToString(signKeys.privateKey),
    public : {
      type: TYPE,
      id: id || Math.random().toString(36).substring(2),
      publicKey: publicKeyToString(keys.publicKey),
      signPublicKey: bufferToString(signKeys.publicKey)
    }
  }
  return key;
}

async function decryptPassword(encryptedPassword, privateKey) {
  const password = bufferToString(Api256.decrypt(stringToEncryptedPassword(encryptedPassword), stringToBuffer(privateKey)));
  return password;
}


async function transformPassword(encryptedPassword, transformKey, fromSigningKey) {
  const transformedPassword = Api256.transform(
    stringToEncryptedPassword(encryptedPassword), 
    stringToTransformkey(transformKey), 
    stringToBuffer(fromSigningKey));
  return encryptedPasswordToString(transformedPassword);
}


async function getNewPassword() {
  return bufferToString(Api256.generatePlaintext());
}

async function encryptPassword(password, publicKey, signPrivateKey) {
  const encryptedPassword = Api256.encrypt(stringToBuffer(password), stringToPublicKey(publicKey), stringToBuffer(signPrivateKey));
  return encryptedPasswordToString(encryptedPassword);
}


module.exports = {
  type: TYPE,
  getNewPassword,
  encryptPassword,
  decryptPassword,
  generateKeys,
  getTransformKey,
  transformPassword,
  init: (Recrypt) => {
    //Create a new Recrypt API instance
    
  }
}

function bufferToString(buffer) {
  return buffer.toString('base64');
}

function stringToBuffer(string) {
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
    data.transformBlocks.map(transformBlockToObjectOfStrings)
  ];
  return JSON.stringify(res);
}

function transformBlockToObjectOfStrings(transformBlock) {
  const res = {
    publicKey: publicKeyToString(transformBlock.publicKey),
    encryptedTempKey: bufferToString(transformBlock.encryptedTempKey),
    randomTransformPublicKey: publicKeyToString(transformBlock.randomTransformPublicKey),
    randomTransformEncryptedTempKey: bufferToString(transformBlock.randomTransformEncryptedTempKey)
  }
  return res;
}

function objectOfStringsToTransformBlock(transformBlockS) {
  const res = {
    publicKey: stringToPublicKey(transformBlockS.publicKey),
    encryptedTempKey: stringToBuffer(transformBlockS.encryptedTempKey),
    randomTransformPublicKey: stringToPublicKey(transformBlockS.randomTransformPublicKey),
    randomTransformEncryptedTempKey: stringToBuffer(transformBlockS.randomTransformEncryptedTempKey)
  }
  return res;
}

function stringToEncryptedPassword(string) {
  const [ephemeralPublicKeyS, encryptedMessageS, authHashS, publicSigningKeyS, signatureS, transformBlocksS] = JSON.parse(string);
  const res = {
    ephemeralPublicKey: stringToPublicKey(ephemeralPublicKeyS),
    encryptedMessage: Buffer.from(encryptedMessageS, 'base64'),
    authHash: Buffer.from(authHashS, 'base64'),
    publicSigningKey: Buffer.from(publicSigningKeyS, 'base64'),
    signature: Buffer.from(signatureS, 'base64'),
    transformBlocks: transformBlocksS.map(objectOfStringsToTransformBlock)
  }
  return res;
}

function transformKeyToString(transfromKey) {
  const res = [
    publicKeyToString(transfromKey.toPublicKey),
    publicKeyToString(transfromKey.ephemeralPublicKey),
    transfromKey.encryptedTempKey.toString('base64'),
    transfromKey.hashedTempKey.toString('base64'),
    transfromKey.publicSigningKey.toString('base64'),
    transfromKey.signature.toString('base64')
  ];
  return JSON.stringify(res);
}

function stringToTransformkey(string) {
  const [toPublicKeyS, ephemeralPublicKeyS, encryptedTempKeyS, hashedTempKeyS, publicSigningKeyS, signatureS] = JSON.parse(string);
  const res = {
    toPublicKey: stringToPublicKey(toPublicKeyS),
    ephemeralPublicKey: stringToPublicKey(ephemeralPublicKeyS),
    encryptedTempKey: Buffer.from(encryptedTempKeyS, 'base64'),
    hashedTempKey: Buffer.from(hashedTempKeyS, 'base64'),
    publicSigningKey: Buffer.from(publicSigningKeyS, 'base64'),
    signature: Buffer.from(signatureS, 'base64')
  }
  return res;
}