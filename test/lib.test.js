require('./helpers');

const { assert } = require('chai');
const lib = require('../src/lib');


for (const recryptType of lib.recryptTypes) {
  for (const envelopeType of lib.envelopeTypes) {
    const use = {
      envelope: envelopeType,
      recrypt: recryptType
    }
    describe(`lib recrypt: ${recryptType}, envelope: ${envelopeType}`, () => {
      const myData = {
        string: 'Hello 😃 !',
        int: 12, 
        float: 0.12,
        bool: true,
        nested: {
          array: ['a', 1, true]
        }
      };

      it('Encrypt / Decrypt object', async () => {
        const originKeys = await lib.generateKeys('origin', use);
        const encrypted = await lib.encryptWithKeys(myData, originKeys, originKeys.public, use);
        const infos = infoFromKeyId(encrypted.keyId);
        assert.equal(infos.id, 'origin', 'Orgin key is kept');
        assert.equal(infos.recrypt, recryptType, 'Recrypt type is correct');
        assert.equal(infos.envelope, envelopeType, 'Envelope type is correct');
        const decryptedData = await lib.decryptWithKeys(encrypted, originKeys.privateKey);
        assert.deepEqual(myData, decryptedData);
      });

      it('Encrypt by Third party / Decrypt object', async () => {
        const originKeys = await lib.generateKeys('origin', use);
        const partyKeys = await lib.generateKeys('party', use);
        const encrypted = await lib.encryptWithKeys(myData, partyKeys, originKeys.public, use);
        const infos = infoFromKeyId(encrypted.keyId);
        assert.equal(infos.id, 'origin', 'Orgin key is not kept');
        assert.equal(infos.recrypt, recryptType, 'Recrypt type is not correct');
        assert.equal(infos.envelope, envelopeType, 'Envelope type is not correct');
        const decryptedData = await lib.decryptWithKeys(encrypted, originKeys.privateKey);
        assert.deepEqual(myData, decryptedData);
      });
    

      it('Encrypt / Recrypt / Decrypt', async () => {
        const originKeys = await lib.generateKeys('origin', use);
        const proxyKeys = await lib.generateKeys('proxy', use);
        const recipientKeys = await lib.generateKeys('recipient', use);

        const encrypted = await lib.encryptWithKeys(myData, originKeys, originKeys.public, use);

        // Origin generate transform Key
        const transformKeyOriginToRecipient = await lib.getTransformKey(originKeys, recipientKeys.public);
        assert.equal(transformKeyOriginToRecipient.fromId, 'origin', 'From id is notcorrect');
        assert.equal(transformKeyOriginToRecipient.toId, 'recipient', 'Recipient id is not correct');
        assert.equal(transformKeyOriginToRecipient.signId, 'origin', 'signId is not correct');
        assert.equal(transformKeyOriginToRecipient.type, recryptType, 'Recrypt type is not correct');

        // Proxy transform encrypted Data
        const recrypted = await lib.recryptForKeys(encrypted, transformKeyOriginToRecipient, proxyKeys);
        const infos = infoFromKeyId(recrypted.keyId);
        assert.equal(infos.id, 'recipient', 'Recipient id is not correctly set');
        assert.equal(infos.recrypt, recryptType, 'Recrypt type is not correct');
        assert.equal(infos.envelope, envelopeType, 'Envelope type is not correct');

        // Recipient decrypt data 
        const decryptedData = await lib.decryptWithKeys(recrypted, recipientKeys.privateKey);

        assert.deepEqual(myData, decryptedData);
      });

      it('Encrypt by Proxy / Recrypt by Proxy / Decrypt by Third Party', async function () {
        const originKeys = await lib.generateKeys('origin', use);
        const proxyKeys = await lib.generateKeys('proxy', use);
        const proxySignKeys = lib.signingKeySetFromKeys(proxyKeys);

        const recipientKeys = await lib.generateKeys('recipient', use);

        const encrypted = await lib.encryptWithKeys(myData, proxySignKeys, originKeys.public, use);
  
        // Origin generate transform Key
        const transformKeyOriginToRecipient = await lib.getTransformKey(originKeys, recipientKeys.public, proxySignKeys);
        assert.equal(transformKeyOriginToRecipient.fromId, 'origin', 'fromId is not correctly set');
        assert.equal(transformKeyOriginToRecipient.toId, 'recipient', 'toId is not correct');
        assert.equal(transformKeyOriginToRecipient.signId, 'proxy', 'signId is not correct');
        assert.equal(transformKeyOriginToRecipient.type, recryptType, 'Recrypt type is not correct');

        // Proxy transform encrypted Data
        const recrypted = await lib.recryptForKeys(encrypted, transformKeyOriginToRecipient, proxyKeys);

        // Recipient decrypt data 
        const decryptedData = await lib.decryptWithKeys(recrypted, recipientKeys.privateKey);

        assert.deepEqual(myData, decryptedData);
      });


      it('Encrypt by Public / Recrypt by Proxy / Decrypt by Third Party', async function () {
        if (! await lib.recryptSupportsPublicEncryption(recryptType)) { this.skip(); }
        const originKeys = await lib.generateKeys('origin', use);
        const proxyKeys = await lib.generateKeys('proxy', use);
        const fourthPartyKeys = await lib.generateKeys('fourthParty', use);
        const fourthPartySigninKeys = lib.signingKeySetFromKeys(fourthPartyKeys);

        const recipientKeys = await lib.generateKeys('recipient', use);

        const encrypted = await lib.encryptWithKeys(myData, fourthPartySigninKeys, originKeys.public, use);
  
        // Origin generate transform Key
        const transformKeyOriginToRecipient = await lib.getTransformKey(originKeys, recipientKeys.public);
        assert.equal(transformKeyOriginToRecipient.fromId, 'origin', 'fromId is not correctly set');
        assert.equal(transformKeyOriginToRecipient.toId, 'recipient', 'toId is not correct');
        assert.equal(transformKeyOriginToRecipient.signId, 'origin', 'signId is not correct');
        assert.equal(transformKeyOriginToRecipient.type, recryptType, 'Recrypt type is not correct');

        // Proxy transform encrypted Data
        const recrypted = await lib.recryptForKeys(encrypted, transformKeyOriginToRecipient, proxyKeys);

        // Recipient decrypt data 
        const decryptedData = await lib.decryptWithKeys(recrypted, recipientKeys.privateKey);

        assert.deepEqual(myData, decryptedData);
      });

    });
  }
}


function infoFromKeyId(key) {
  const [id, recrypt, envelope] = key.split(':');
  return {id, recrypt, envelope};
}