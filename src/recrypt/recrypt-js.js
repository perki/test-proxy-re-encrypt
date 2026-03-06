const crypto = require('crypto');
const Proxy = require('recrypt-js/src/proxy');

const TYPE = 'recrypt-js-0';

module.exports = {
  type: TYPE,
  supportsPublicEncryption: true,
  getNewPassword,
  encryptPassword,
  decryptPassword,
  generateKeys,
  getTransformKey,
  transformPassword,
  init: async () => {},
}

async function getNewPassword() {
  return crypto.randomBytes(32).toString('base64');
}

async function generateKeys(id) {
  const kp = Proxy.generate_key_pair();
  const sk = kp.get_private_key();
  const pk = kp.get_public_key();
  return {
    privateKey: scalarToHex(sk),
    signPrivateKey: scalarToHex(sk),
    public: {
      type: TYPE,
      id: id || Math.random().toString(36).substring(2),
      publicKey: geToHex(pk),
      signPublicKey: geToHex(pk)
    }
  };
}

async function encryptPassword(password, signingkeySet, targetPublicKey) {
  const pubKey = Proxy.public_key_from_bytes(Proxy.from_hex(targetPublicKey));
  const cp = Proxy.encapsulate(pubKey);
  const symKeyBytes = scalarToBuffer(cp.symmetric_key);
  const capsuleStr = serializeCapsule(cp.capsule);
  const ciphertext = symEncrypt(symKeyBytes, password);
  return JSON.stringify({ key: capsuleStr, cipher: ciphertext });
}

async function decryptPassword(encryptedPassword, privateKey) {
  const { key, cipher } = JSON.parse(encryptedPassword);
  const capsule = deserializeCapsule(key);
  const priKey = Proxy.private_key_from_bytes(Proxy.from_hex(privateKey));
  let symKey;
  if (capsule.is_re_encrypted()) {
    symKey = Proxy.decapsulate_re_encrypted(capsule, priKey);
  } else {
    symKey = Proxy.decapsulate_original(capsule, priKey);
  }
  const symKeyBytes = scalarToBuffer(symKey);
  return symDecrypt(symKeyBytes, cipher);
}

async function getTransformKey(originKeys, targetPublicKey) {
  const priKey = Proxy.private_key_from_bytes(Proxy.from_hex(originKeys.privateKey));
  const pubKey = Proxy.public_key_from_bytes(Proxy.from_hex(targetPublicKey));
  const rk = Proxy.generate_re_encryption_key(priKey, pubKey);
  return JSON.stringify([scalarToHex(rk.get_re_key()), geToHex(rk.get_internal_public_key())]);
}

async function transformPassword(encryptedPassword, transformKey) {
  const { key, cipher } = JSON.parse(encryptedPassword);
  const capsule = deserializeCapsule(key);
  const [rkHex, ipcHex] = JSON.parse(transformKey);
  const rkBytes = [...Proxy.from_hex(rkHex), ...Proxy.from_hex(ipcHex)];
  const rk = Proxy.re_encryption_key_from_bytes(rkBytes);
  const reCapsule = Proxy.re_encrypt_capsule(capsule, rk);
  return JSON.stringify({ key: serializeCapsule(reCapsule), cipher });
}

// --- capsule serialization with properly padded components ---

function serializeCapsule(capsule) {
  const E = geToHex(capsule.get_E());
  const V = geToHex(capsule.get_V());
  const S = scalarToHex(capsule.get_S());
  if (capsule.is_re_encrypted()) {
    const XG = geToHex(capsule.get_XG());
    return JSON.stringify([E, V, S, XG]);
  }
  return JSON.stringify([E, V, S]);
}

function deserializeCapsule(str) {
  const parts = JSON.parse(str);
  const buf = parts.length > 3
    ? [...Proxy.from_hex(parts[0]), ...Proxy.from_hex(parts[1]), ...Proxy.from_hex(parts[2]), ...Proxy.from_hex(parts[3])]
    : [...Proxy.from_hex(parts[0]), ...Proxy.from_hex(parts[1]), ...Proxy.from_hex(parts[2])];
  const capsule = Proxy.capsule_from_bytes(buf);
  if (parts.length > 3) capsule.set_re_encrypted(true);
  return capsule;
}

// --- serialization helpers using BN.toArray('be', len) for proper zero-padding ---

function toBN(obj) {
  // Unwrap PrivateKey→Scalar→BN or Scalar→BN
  let v = obj;
  while (v.valueOf && v.valueOf() !== v) v = v.valueOf();
  return v;
}

function toPoint(obj) {
  // Unwrap PublicKey→GroupElement→Point or GroupElement→Point
  let v = obj;
  while (v.valueOf && v.valueOf() !== v && typeof v.valueOf().getX !== 'function') v = v.valueOf();
  if (typeof v.getX === 'function') return v;
  return v.valueOf();
}

function scalarToHex(scalar) {
  return Proxy.to_hex(scalarToArr(scalar));
}

function scalarToBuffer(scalar) {
  return Buffer.from(scalarToArr(scalar));
}

function scalarToArr(scalar) {
  const bn = toBN(scalar);
  const arr = bn.toArray('be');
  if (arr.length === 32) return arr;
  if (arr.length > 32) return arr.slice(arr.length - 32);
  const padded = new Array(32).fill(0);
  for (let i = 0; i < arr.length; i++) padded[32 - arr.length + i] = arr[i];
  return padded;
}

function geToHex(ge) {
  const point = toPoint(ge);
  const x = point.getX().toArray('be', 32);
  const y = point.getY().toArray('be', 32);
  return Proxy.to_hex([0x04, ...x, ...y]);
}

// --- symmetric encryption helpers using AES-256-CBC ---

function symEncrypt(keyBytes, plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', keyBytes, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return iv.toString('base64') + ':' + encrypted.toString('base64');
}

function symDecrypt(keyBytes, ciphertext) {
  const [ivB64, dataB64] = ciphertext.split(':');
  const iv = Buffer.from(ivB64, 'base64');
  const data = Buffer.from(dataB64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-cbc', keyBytes, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}
