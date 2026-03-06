let umbral;

const TYPE = 'umbral-pre-0';

module.exports = {
  type: TYPE,
  supportsPublicEncryption: true,
  getNewPassword,
  encryptPassword,
  decryptPassword,
  generateKeys,
  getTransformKey,
  transformPassword,
  init,
}

async function init() {
  if (umbral) return;
  umbral = await import('@nucypher/umbral-pre');
}

async function getNewPassword() {
  const sk = umbral.SecretKey.random();
  return Buffer.from(sk.toBEBytes()).toString('base64');
}

async function generateKeys(id) {
  const sk = umbral.SecretKey.random();
  const pk = sk.publicKey();
  const skB64 = Buffer.from(sk.toBEBytes()).toString('base64');
  const pkB64 = Buffer.from(pk.toCompressedBytes()).toString('base64');
  return {
    privateKey: skB64,
    signPrivateKey: skB64, // same key used for signing
    public: {
      type: TYPE,
      id: id || Math.random().toString(36).substring(2),
      publicKey: pkB64,
      signPublicKey: pkB64
    }
  };
}

async function encryptPassword(password, signingkeySet, targetPublicKey) {
  const pk = umbral.PublicKey.fromCompressedBytes(Buffer.from(targetPublicKey, 'base64'));
  const plaintext = Buffer.from(password, 'utf8');
  const [capsule, ciphertext] = umbral.encrypt(pk, plaintext);
  return JSON.stringify([
    Buffer.from(capsule.toBytes()).toString('base64'),
    Buffer.from(ciphertext).toString('base64')
  ]);
}

async function decryptPassword(encryptedPassword, privateKey) {
  const parts = JSON.parse(encryptedPassword);
  const sk = umbral.SecretKey.fromBEBytes(Buffer.from(privateKey, 'base64'));
  const capsule = umbral.Capsule.fromBytes(Buffer.from(parts[0], 'base64'));
  const ciphertext = Buffer.from(parts[1], 'base64');

  if (parts.length === 2) {
    const plaintext = umbral.decryptOriginal(sk, capsule, ciphertext);
    return Buffer.from(plaintext).toString('utf8');
  }

  // Re-encrypted: [capsule, ciphertext, cfragB64, delegatingPkB64, signingPkB64, receivingPkB64]
  const cfrag = umbral.CapsuleFrag.fromBytes(Buffer.from(parts[2], 'base64'));
  const delegatingPk = umbral.PublicKey.fromCompressedBytes(Buffer.from(parts[3], 'base64'));
  const signingPk = umbral.PublicKey.fromCompressedBytes(Buffer.from(parts[4], 'base64'));
  const receivingPk = umbral.PublicKey.fromCompressedBytes(Buffer.from(parts[5], 'base64'));

  const vcfrag = cfrag.verify(capsule, signingPk, delegatingPk, receivingPk);
  const plaintext = umbral.decryptReencrypted(sk, delegatingPk, capsule, [vcfrag], ciphertext);
  return Buffer.from(plaintext).toString('utf8');
}

// Transform key format: [kfragB64, delegatingPkB64, signingPkB64, receivingPkB64]
async function getTransformKey(originKeys, targetPublicKey) {
  const sk = umbral.SecretKey.fromBEBytes(Buffer.from(originKeys.privateKey, 'base64'));
  const targetPk = umbral.PublicKey.fromCompressedBytes(Buffer.from(targetPublicKey, 'base64'));
  const signer = new umbral.Signer(sk);
  const kfrags = umbral.generateKFrags(sk, targetPk, signer, 1, 1, false, false);
  const originPk = sk.publicKey();
  const signingPk = signer.verifyingKey();
  return JSON.stringify([
    Buffer.from(kfrags[0].toBytes()).toString('base64'),
    Buffer.from(originPk.toCompressedBytes()).toString('base64'),
    Buffer.from(signingPk.toCompressedBytes()).toString('base64'),
    Buffer.from(targetPk.toCompressedBytes()).toString('base64')
  ]);
}

async function transformPassword(encryptedPassword, transformKey) {
  const [capsuleB64, ciphertextB64] = JSON.parse(encryptedPassword);
  const [kfragB64, delegatingPkB64, signingPkB64, receivingPkB64] = JSON.parse(transformKey);

  const capsule = umbral.Capsule.fromBytes(Buffer.from(capsuleB64, 'base64'));
  const kfrag = umbral.KeyFrag.fromBytes(Buffer.from(kfragB64, 'base64'));
  const signingPk = umbral.PublicKey.fromCompressedBytes(Buffer.from(signingPkB64, 'base64'));
  const delegatingPk = umbral.PublicKey.fromCompressedBytes(Buffer.from(delegatingPkB64, 'base64'));
  const receivingPk = umbral.PublicKey.fromCompressedBytes(Buffer.from(receivingPkB64, 'base64'));

  const vkfrag = kfrag.verify(signingPk, delegatingPk, receivingPk);
  const cfrag = umbral.reencrypt(capsule, vkfrag);

  return JSON.stringify([
    capsuleB64,
    ciphertextB64,
    Buffer.from(cfrag.toBytes()).toString('base64'),
    delegatingPkB64,
    signingPkB64,
    receivingPkB64
  ]);
}
