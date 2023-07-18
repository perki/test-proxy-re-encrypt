require('./helpers');

const { assert } = require('chai');

const recryptLibrary = require('../src/recrypt');

// list supported recrypt methods
const recryptTypes = ['ironcore-0'];

describe('recrypt', function () {

  it('Throw error on unsupported implementation', () => {
    try {
      recryptLibrary('unsupported');
      throw new Error('Should throw an error');
    } catch (e) {
      assert.equal(e.message, 'Unsuported recrypt method :unsupported');
    }
    
  });

  for (const recryptType of recryptTypes) {
    describe(`implementation ${recryptType}`, function () {
      let recrypt = recryptLibrary(recryptType);

      it('Has correct type code', () => {
        assert.equal(recrypt.type, recryptType);
      });

      it('Generate random password with getNewPassword', () => {
        const password = recrypt.getNewPassword();
        assert.isString(password);
      });

      it('Generate Keys with provided keyId', () => {
        const keyId = 'myKeyId';
        const key = recrypt.generateKeys(keyId);
        assert.isString(key.privateKey, 'privateKey should be a string');
        assert.isString(key.signPrivateKey, 'signPrivateKey should be a string');
        assert.isString(key.public.publicKey, 'publicKey should be a string');
        assert.isString(key.public.signPublicKey, 'signPublicKey should be a string');
        assert.equal(keyId, key.public.id, 'Assigned key is kept');
        assert.equal(recryptType, key.public.type, 'Type is stored in public segment');
      });

      it('Generate Ids when generateKeys does not provide one', () => {
        const key = recrypt.generateKeys();
        assert.isString(key.public.id, 'an id is auto assigned');
      });

      it('Simple crypt / decrypt flow with single key', () => {
        const password = recrypt.getNewPassword();
        const key = recrypt.generateKeys();
        const encryptedPassword = recrypt.encryptPassword(password, key.public.publicKey, key.signPrivateKey);
        assert.isString(encryptedPassword);
        const decryptedPassword = recrypt.decryptPassword(encryptedPassword, key.privateKey);
        assert.equal(password, decryptedPassword, 'Decrypted password should match password');
      });


      

      it('Full crypt / transform / decrypt flow with two keys', () => {
        const password = recrypt.getNewPassword();
        const keyOrigin = recrypt.generateKeys();
        const encryptedPassword = recrypt.encryptPassword(password, keyOrigin.public.publicKey, keyOrigin.signPrivateKey);
        
        const keyRecipient = recrypt.generateKeys();

        const transformKeyOriginToRecipient = recrypt.getTransformKey(keyOrigin, keyRecipient.public.publicKey);
        assert.isString(transformKeyOriginToRecipient);

        const transformerKeys = recrypt.generateKeys();
        const encryptedPasswordForRecipient = recrypt.transformPassword(encryptedPassword, transformKeyOriginToRecipient, transformerKeys.signPrivateKey);

        const decryptedPassword = recrypt.decryptPassword(encryptedPasswordForRecipient, keyRecipient.privateKey);
        assert.equal(password, decryptedPassword, 'Decrypted password should match password');
      });

    });
  }
});