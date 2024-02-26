
const envelopes = require('../envelope');
const recrypts = require('../recrypt');

const defaults = {
  envelope: envelopes.list()[0],
  recrypt: recrypts.list()[0]
}

function getEnvelope(envelopeId) {
  return envelopes.get(envelopeId || defaults.envelope);
}

async function getRecrypt(recryptId) {
  const recrypt = recrypts.get(recryptId || defaults.recrypt);
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
 * @param {*} keySet 
 * @param {*} use 
 * @returns {EncryptedPayLoad}
 */
async function encryptWithKeys(data, signKeySet, encryptingPublicKeySet, use = {}) {
  if (use.recrypt && encryptingPublicKeySet.type !== use.recrypt) {
    throw new Error(`Cannot use recryptType: ${use.recrypt} with this key of type: ${encryptingPublicKeySet.type}`);
  }
  if (encryptingPublicKeySet.type !== signKeySet.public.type) {
    throw new Error(`Cannot use sign with type: ${signKeySet.public.type} with this public key of type: ${encryptingPublicKeySet.type}`);
  }

  const recrypt = await getRecrypt(encryptingPublicKeySet.type);
  const envelope = getEnvelope(use.envelope);

  const password = await recrypt.getNewPassword();
  const encryptedPassword = await recrypt.encryptPassword(password, signKeySet, encryptingPublicKeySet.publicKey);
  const encryptedData = envelope.encrypt(data, password);
  const type = recrypt.type + ':' + envelope.type;
  const keyId = encryptingPublicKeySet.id + ':' + type;
  const encrypted = {keyId, encryptedPassword, encryptedData};
  return encrypted;
}

/**
 * @param {EncryptedPayLoad} encrypted
 * @param {*} keySet 
 * @param {*} use 
 * @returns {EncryptedPayLoad}
 */
async function recryptForKeys(encrypted, transformKey, proxyKeySet) {
  const use = useFromKeyId(encrypted.keyId);
  if (use.id != transformKey.fromId) {
    throw new Error(`Cannot recrypt content encrypted from  ${use.id} using a transform Key from ${transformKey.fromId}`)
  }

  const recrypt = await getRecrypt(use.recrypt);
  const transformedPassword = await recrypt.transformPassword(
    encrypted.encryptedPassword,
    transformKey.key,
    proxyKeySet);
  const recrypted = Object.assign({}, encrypted); // we can safely clone with Object.assign as long atheer is no nested properties
  recrypted.keyId = transformKey.toId + ':' + use.recrypt + ':' + use.envelope,
  recrypted.encryptedPassword = transformedPassword;
  return recrypted;
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

function decryptWithPassword(data, password) {
  const use = infosFromKeyId = useFromKeyId(data.keyId);
  const envelope = envelopes.get(use.envelope);
  const decryptedData = envelope.decrypt(data.encryptedData, password);
  return decryptedData;
}

function encryptWithPassword(data, password ) {
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

async function getTransformKey(originKeys, targetPublicKeySet, signingkeySet) {
  const signWith = signingkeySet || originKeys;
  if (originKeys.public.type != targetPublicKeySet.type) {
    throw new Error(`Mismatching types for transform get, origin: ${originKeys.public.type}, target: ${targetPublicKeySet.type}`)
  }
  if (signWith.public.type != targetPublicKeySet.type) {
    throw new Error(`Mismatching types for transform get, signing: ${signWith.public.type}, target: ${targetPublicKeySet.type}`)
  }
  const recrypt = await getRecrypt(originKeys.public.type);
  const key = await recrypt.getTransformKey(originKeys, targetPublicKeySet.publicKey, signWith);
  return {
    fromId: originKeys.public.id,
    toId: targetPublicKeySet.id,
    signId: signWith.public.id,
    type: originKeys.public.type,
    key
  }
}

async function transformPassword(encryptedPassword, transformKey, proxyKeySet) {
  $$(encryptedPassword);
  // : recrypt.transformPassword
}

function useFromKeyId(key) {
  const [id, recrypt, envelope] = key.split(':');
  return {id, recrypt, envelope};
}

function signingKeySetFromKeys (keySet) {
  return {
    signPrivateKey: keySet.signPrivateKey,
    public: {
      type: keySet.public.type,
      id: keySet.public.id,
      signPublicKey: keySet.public.signPublicKey
    }
  }
}

async function recryptSupportsPublicEncryption (type) {
  const recrypt = await getRecrypt(type);
  return recrypt.supportsPublicEncryption;
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
  recryptForKeys,
  signingKeySetFromKeys,
  recryptSupportsPublicEncryption,
  defaults,
  envelopeTypes: envelopes.list(),
  recryptTypes: recrypts.list()
}
