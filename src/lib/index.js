
const envelope = require('../envelope')('aes-256-gcm-0');
const recrypt = require('../recrypt')('ironcore-0');

/**
 * @typedef {Object} EncryptedPayLoad
 * @property {String} encryptedPassword - Password to decrypt the payload
 * @property {String} encryptedData - The data
 */

/**
 * @param {*} data // must be a String or Support JSON.stringify
 * @param {string} publicKey 
 * @param {string} signingKey 
 * @returns {EncryptedPayLoad}
 */
function encryptWithKeys(data, publicKey, signingKey) {
  const password = recrypt.getNewPassword();
  const encryptedPassword = recrypt.encryptPassword(password, publicKey, signingKey);
  const encryptedData = envelope.encrypt(data, password);
  const encrypted = {encryptedPassword, encryptedData};
  return encrypted;
}

/**
 * Decrypt with the provided Key. 
 * @param {EncryptedPayLoad} data 
 * @param {string} privateKey 
 * @returns 
 */
function decryptWithKeys(data, privateKey) {
  if (data.encryptedPassword == null) {
    throw new Error('Cannot decrypt data with private key, if payload does not contain encrypted password');
  }
  const password = recrypt.decryptPassword(data.encryptedPassword, privateKey);
  const decryptedData = decryptWithPassword(data, password);
  return decryptedData;
}

function decryptWithPassword(data, password) {
  $$('decryptWithPassword', password);
  const decryptedData = envelope.decrypt(data.encryptedData, password);
  return decryptedData;
}

function decryptArrayWithKeys(encryptedArray, privateKey) {
  const res = [];
  for (const data of encryptedArray) {
    res.push(decryptWithKeys(data, privateKey));
  }
  return res;
}


function encryptWithPassword(data, password ) {
  const encryptedData = envelope.encrypt(data, password);
  const encrypted = { encryptedData };
  return encrypted;
}


module.exports = {
  encryptWithKeys,
  encryptWithPassword,
  decryptPassword: recrypt.decryptPassword,
  decryptArrayWithKeys,
  decryptWithPassword,
  decryptWithKeys,
  generateKeys: recrypt.generateKeys,
  getTransformKey: recrypt.generateKeys,
  transformPassword: recrypt.transformPassword,
  transform: recrypt.transform,
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