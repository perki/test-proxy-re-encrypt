
const envelopes = require('../envelope');
const recrypts = require('../recrypt');

const defaults = {
  envelope: envelopes.list()[0],
  recrypt: recrypts.list()[0]
}

function getEnvelope(use = {}) {
  return envelopes.get(use.envelope || defaults.envelope);
}

async function getRecrypt(use = {}) {
  const recrypt = recrypts.get(use.recrypt || defaults.recrypt);
  await recrypt.init();
  return recrypt;
}

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
async function encryptWithKeys(data, keySet, use) {
  const recrypt = await getRecrypt(use);
  const envelope = getEnvelope(use);

  const password = await recrypt.getNewPassword();
  const encryptedPassword = await recrypt.encryptPassword(password, keySet);
  const encryptedData = envelope.encrypt(data, password);
  const type = recrypt.type + ':' + envelope.type;
  const keyId = keySet.public.id + ':' + type;
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
  const use = infosFromKeyId = useFromKeyId(data.keyId);
  const recrypt = recrypts.get(use.recrypt);
  const password = await recrypt.decryptPassword(data.encryptedPassword, privateKey);
  const decryptedData = decryptWithPassword(data, password);
  return decryptedData;
}

function useFromKeyId(key) {
  const [id, recrypt, envelope] = key.split(':');
  return {id, recrypt, envelope};
}

function decryptWithPassword(data, password) {
  const use = infosFromKeyId = useFromKeyId(data.keyId);
  const envelope = envelopes.get(use.envelope);
  const decryptedData = envelope.decrypt(data.encryptedData, password);
  return decryptedData;
}

function encryptWithPassword(data, password ) {
  $$(data);
  const encryptedData = envelope.encrypt(data, password);
  const encrypted = { encryptedData };
  return encrypted;
}

async function decryptPassword(encryptedPassword, privateKey) {
  $$(encryptedPassword);
  // recrypt.decryptPassword
}

async function generateKeys(id, use = {}) {
  const recrypt = await getRecrypt(use.recrypt);
  return recrypt.generateKeys(id);
}

async function getTransformKey(originKeys, targetPublicKey) {
  $$({originKeys});
  const recrypt = await getRecrypt(use.recrypt);
  return recrypt.generateKeys(originKeys, targetPublicKey);
}

async function transformPassword(encryptedPassword, transformKey, proxyKeySet) {
  $$(encryptedPassword);
  // : recrypt.transformPassword
}



module.exports = {
  encryptWithKeys,
  encryptWithPassword,
  decryptPassword,
  decryptWithPassword,
  decryptWithKeys,
  generateKeys,
  getTransformKey,
  transformPassword,
}
