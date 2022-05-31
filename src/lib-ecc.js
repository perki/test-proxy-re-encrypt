// AT WORK!! not finalized 

// TESTing another lib!!

const ecc = require("fix-esm").require('@aldenml/ecc')

console.log(ecc);

(async () => {

  
  message = await ecc.pre_schema1_MessageGen();

  console.log(message);
})();

let utf8decoder = new TextDecoder(); // default 'utf-8' or 'utf8'

const ENCRYPTED_DATA_SIZE = 384;

async function encrypt(data, toPublicKey, fromSigningKey) {
  const buff384 = new Buffer.alloc(ENCRYPTED_DATA_SIZE);
  const msgBuff = new Buffer.from(data, 'utf8');
  buff384.fill(msgBuff, 0, msgBuff.length);
  const encryptedData = await encrypt384Buffer(buff384, toPublicKey, fromSigningKey);
  return encryptedData;
}

async function encrypt384Buffer(data, toPublicKey, fromSigningKey) {
  const encryptedData = await pre_schema1_Encrypt(data, toPublicKey, fromSigningKey);
  return encryptedData;
}


async function getTransformKey(userKeys, targetPublicKey) {
  return await pre_schema1_ReKeyGen(userKeys.privateKey, targetPublicKey, userKeys.signPrivateKey);
}

async function generateKeys() {
  const keys = await ecc.pre_schema1_KeyGen();
  const signKeys = await ecc.pre_schema1_SigningKeyGen();
  return {
    publicKey: keys.pk,
    privateKey: keys.sk,
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

module.exports = {
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