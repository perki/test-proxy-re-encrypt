require('./helpers');

const { assert } = require('chai');

const recrypts = require('../src/recrypt');


describe('recrypt', function () {

  it('Throw error on unsupported implementation', () => {
    try {
      recrypts.get('unsupported');
      throw new Error('Should throw an error');
    } catch (e) {
      assert.equal(e.message, 'Unsuported recrypt method :unsupported');
    }
    
  });

  for (const recryptType of recrypts.list()) {
    describe(`implementation ${recryptType}`, function () {
      let recrypt = recrypts.get(recryptType);

      before(async () => {
        await recrypt.init();
      });

      it('Has correct type code', () => {
        assert.equal(recrypt.type, recryptType);
      });

      it('Generate random password with getNewPassword', async () => {
        const password = await recrypt.getNewPassword();
        assert.isString(password);
      });

      it('Generate Keys with provided keyId', async () => {
        const keyId = 'myKeyId';
        const key = await recrypt.generateKeys(keyId);
        assert.isString(key.privateKey, 'privateKey should be a string');
        assert.isString(key.signPrivateKey, 'signPrivateKey should be a string');
        assert.isString(key.public.publicKey, 'publicKey should be a string');
        assert.isString(key.public.signPublicKey, 'signPublicKey should be a string');
        assert.equal(keyId, key.public.id, 'Assigned key is kept');
        assert.equal(recryptType, key.public.type, 'Type is stored in public segment');
      });

      it('Generate Ids when generateKeys does not provide one', async () => {
        const key = await recrypt.generateKeys();
        assert.isString(key.public.id, 'an id is auto assigned');
      });

      it('Simple crypt / decrypt flow with single key', async () => {
        const password = await recrypt.getNewPassword();
        const key = await recrypt.generateKeys();
        const encryptedPassword = await recrypt.encryptPassword(password, key, key.public.publicKey);
        assert.isString(encryptedPassword);
        const decryptedPassword = await recrypt.decryptPassword(encryptedPassword, key.privateKey);
        assert.equal(password, decryptedPassword, 'Decrypted password should match password');
      });

      it('Full crypt by Origin / transform / decrypt flow with two keys', async () => {
        const password = await recrypt.getNewPassword();
        const keyOrigin = await recrypt.generateKeys();
        const encryptedPassword = await recrypt.encryptPassword(password, keyOrigin, keyOrigin.public.publicKey);
        
        const keyRecipient = await recrypt.generateKeys();

        const transformKeyOriginToRecipient = await recrypt.getTransformKey(keyOrigin, keyRecipient.public.publicKey);
        assert.isString(transformKeyOriginToRecipient);

        const proxyKeys = await recrypt.generateKeys();
        const encryptedPasswordForRecipient = await recrypt.transformPassword(encryptedPassword, transformKeyOriginToRecipient, proxyKeys);

        const decryptedPassword = await recrypt.decryptPassword(encryptedPasswordForRecipient, keyRecipient.privateKey);
        assert.equal(password, decryptedPassword, 'Decrypted password should match password');
      });

      it('Full crypt by Proxy / transform / decrypt flow with two keys', async () => {
        const password = await recrypt.getNewPassword();
        const keyOrigin = await recrypt.generateKeys();
        const proxyKeys = await recrypt.generateKeys();

        // !! This implies that Origin knows the private and public signing keys of Proxy
        const proxySignKeys = {
          signPrivateKey: proxyKeys.signPrivateKey,
          public: {
            type: proxyKeys.public.type,
            id: proxyKeys.public.id,
            signPublicKey: proxyKeys.public.signPublicKey
          }
        }

        const encryptedPassword = await recrypt.encryptPassword(password, proxySignKeys, keyOrigin.public.publicKey);
        
        const keyRecipient = await recrypt.generateKeys();

        const transformKeyOriginToRecipient = await recrypt.getTransformKey(keyOrigin, keyRecipient.public.publicKey, proxySignKeys);
        assert.isString(transformKeyOriginToRecipient);

        const encryptedPasswordForRecipient = await recrypt.transformPassword(encryptedPassword, transformKeyOriginToRecipient, proxyKeys);

        const decryptedPassword = await recrypt.decryptPassword(encryptedPasswordForRecipient, keyRecipient.privateKey);
        assert.equal(password, decryptedPassword, 'Decrypted password should match password');
      });
    });
  }
});