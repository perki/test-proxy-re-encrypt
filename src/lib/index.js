
const envelope = require('../envelope')('aes-256-gcm-0');
const recrypt = require('../recrypt')('ironcore-0');

/**
 * @typedef {Object} EncryptedPayLoad
 * @property {String} encryptedPassword - Password to decrypt the payload
 * @property {String} encryptedData - The data
 */

/**
 * @param {*} data // must be a String or Support JSON.stringify
 * @param {string} publicSet 
 * @param {string} signingKey 
 * @returns {EncryptedPayLoad}
 */
async function encryptWithKeys(data, publicSet, signingKey) {
  const password = await recrypt.getNewPassword();
  const encryptedPassword = await recrypt.encryptPassword(password, publicSet.publicKey, signingKey);
  const encryptedData = envelope.encrypt(data, password);
  const type = recrypt.type + ':' + envelope.type;
  const keyId = publicSet.id + ':' + type;
  const encrypted = {keyId, encryptedPassword, encryptedData};
  return encrypted;
}

/**
 * Decrypt with the provided Key. 
 * @param {EncryptedPayLoad} data 
 * @param {string} privateKey 
 * @returns 
 */
async function decryptWithKeys(data, privateKey) {
  if (data.encryptedPassword == null) {
    throw new Error('Cannot decrypt data with private key, if payload does not contain encrypted password');
  }
  const password = await recrypt.decryptPassword(data.encryptedPassword, privateKey);
  const decryptedData = decryptWithPassword(data, password);
  return decryptedData;
}

function decryptWithPassword(data, password) {
  const decryptedData = envelope.decrypt(data.encryptedData, password);
  return decryptedData;
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
  decryptWithPassword,
  decryptWithKeys,
  generateKeys: recrypt.generateKeys,
  getTransformKey: recrypt.generateKeys,
  transformPassword: recrypt.transformPassword,
  transform: recrypt.transform,
}
