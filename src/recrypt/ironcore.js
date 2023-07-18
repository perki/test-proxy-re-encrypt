let Api256 = null;

function getTransformKey(userKeys, targetPublicKey) {
  const transformKey = Api256.generateTransformKey(
      stringToKey(userKeys.privateKey), 
      stringToPublicKey(targetPublicKey), 
      stringToKey(userKeys.signPrivateKey));
  return transformKeyToString(transformKey);
}

function generateKeys(id) {
  const keys = Api256.generateKeyPair();
  const signKeys = Api256.generateEd25519KeyPair();
  const password = getNewPassword();
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


function transformPassword(encryptedPassword, transformKey, fromSigningKey) {
  const transformedPassword = Api256.transform(
    stringToEncryptedPassword(encryptedPassword), 
    stringToTransformkey(transformKey), 
    stringToKey(fromSigningKey));
  return encryptedPasswordToString(transformedPassword);
}


function getNewPassword() {
  return Api256.generatePlaintext();
}

function encryptPassword(password, publicKey, signingKey) {
  const encryptedPassword = Api256.encrypt(password, stringToPublicKey(publicKey), stringToKey(signingKey));
  return encryptedPasswordToString(encryptedPassword);
}


module.exports = {
  type: 'ironcore-0',
  getNewPassword,
  encryptPassword,
  decryptPassword,
  generateKeys,
  getTransformKey,
  transformPassword,
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
    data.transformBlocks.map(transformBlockToObjectOfStrings)
  ];
  return JSON.stringify(res);
}

function transformBlockToObjectOfStrings(transformBlock) {
  const res = {
    publicKey: publicKeyToString(transformBlock.publicKey),
    encryptedTempKey: keyToString(transformBlock.encryptedTempKey),
    randomTransformPublicKey: publicKeyToString(transformBlock.randomTransformPublicKey),
    randomTransformEncryptedTempKey: keyToString(transformBlock.randomTransformEncryptedTempKey)
  }
  return res;
}

function objectOfStringsToTransformBlock(transformBlockS) {
  const res = {
    publicKey: stringToPublicKey(transformBlockS.publicKey),
    encryptedTempKey: stringToKey(transformBlockS.encryptedTempKey),
    randomTransformPublicKey: stringToPublicKey(transformBlockS.randomTransformPublicKey),
    randomTransformEncryptedTempKey: stringToKey(transformBlockS.randomTransformEncryptedTempKey)
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