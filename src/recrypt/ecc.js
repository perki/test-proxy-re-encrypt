
let ecc;

const TYPE = 'aldenml-ecc-0';

module.exports = {
  type: TYPE,
  getNewPassword,
  encryptPassword,
  decryptPassword,
  generateKeys,
  getTransformKey,
  transformPassword,
  init
}

async function init() {
  if (ecc) return;
  ecc = await import('@aldenml/ecc');
}

async function getNewPassword() {
  return uintArrayToString(await ecc.pre_schema1_MessageGen());
}

async function generateKeys(id) {
  const keys = await ecc.pre_schema1_KeyGen();
  const signing = await ecc.pre_schema1_SigningKeyGen();
  const key = {
    privateKey: uintArrayToString(keys.sk),
    signPrivateKey: uintArrayToString(signing.ssk),
    public : {
      type: TYPE,
      id: id || Math.random().toString(36).substring(2),
      publicKey: uintArrayToString(keys.pk),
      signPublicKey: uintArrayToString(signing.spk)
    }
  }
  return key;
}

async function encryptPassword(password, keySet) {
  const encryptedPassword = await ecc.pre_schema1_Encrypt(stringToUintArray(password), stringToUintArray(keySet.public.publicKey), {spk: stringToUintArray(keySet.public.signPublicKey), ssk: stringToUintArray(keySet.signPrivateKey)});
  const pack = [
    uintArrayToString(encryptedPassword),
    keySet.public.signPublicKey,
    1
  ];
  return JSON.stringify(pack);
}

async function getTransformKey(originKeys, targetPublicKey) {
  const reEncKey = await ecc.pre_schema1_ReKeyGen(
    stringToUintArray(originKeys.privateKey), 
    stringToUintArray(targetPublicKey), 
    {ssk: stringToUintArray(originKeys.signPrivateKey), spk: stringToUintArray(originKeys.public.signPublicKey)});
   const pack = [
    uintArrayToString(reEncKey),
    originKeys.public.signPublicKey,
    targetPublicKey
   ];
  return JSON.stringify(pack);
}

async function transformPassword(encryptedPassword, transformKey, proxyKeys) {
  const [reEncKey, originKeySignPublicKey, targetPublicKey] = JSON.parse(transformKey);
  const [encryptedPasswordItem, signPublicKey, level] = JSON.parse(encryptedPassword);
  if (level !== 1) { throw new Error('Cannot Transform level 2 passwords'); }
  const transformedPassword = await ecc.pre_schema1_ReEncrypt(
    stringToUintArray(encryptedPasswordItem), 
    stringToUintArray(reEncKey), 
    stringToUintArray(originKeySignPublicKey),
    stringToUintArray(targetPublicKey),
    {spk: stringToUintArray(proxyKeys.public.signPublicKey), ssk: stringToUintArray(proxyKeys.signPrivateKey)});

  const pack = [
    uintArrayToString(transformedPassword),
    proxyKeys.public.signPublicKey,
    2
  ]
  return JSON.stringify(pack);
}

async function decryptPassword(encryptedPassword, readerKeys) {
  const [encryptedPasswordItem, signingPublicKey, level] = JSON.parse(encryptedPassword);
  if (level === 1) { // level 1 (self decrypt)
    const password = await ecc.pre_schema1_DecryptLevel1(
      stringToUintArray(encryptedPasswordItem),
      stringToUintArray(readerKeys),
      stringToUintArray(signingPublicKey)
    );
    return uintArrayToString(password);
  }  
  
  // level 2  
  const password = await ecc.pre_schema1_DecryptLevel2(
      stringToUintArray(encryptedPasswordItem),
      stringToUintArray(readerKeys),
      stringToUintArray(signingPublicKey)
    );
  return uintArrayToString(password);
}

function uintArrayToString(u8) {
  return Buffer.from(u8).toString('base64');
}

function stringToUintArray(b64) {
  return new Uint8Array(Buffer.from(b64, 'base64'))
}