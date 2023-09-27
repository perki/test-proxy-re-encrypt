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
        assert.equal(infos.id, 'origin', 'Orgin key is kept');
        assert.equal(infos.recrypt, recryptType, 'Recrypt type is correct');
        assert.equal(infos.envelope, envelopeType, 'Envelope type is correct');
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
 
        // Proxy transform encrypted Data
        const recrypted = await lib.recryptForKeys(encrypted, transformKeyOriginToRecipient, proxyKeys);

        // Recipient decrypt data 
        const decryptedData = await lib.decryptWithKeys(recrypted, recipientKeys.privateKey);

        assert.deepEqual(myData, decryptedData);
      });

      it('Encrypt by Proxy / Recrypt by Proxy / Decrypt by Third Party', async function () {
        if (use.recrypt === 'aldenml-ecc-0') {
          this.skip();
        }
        const originKeys = await lib.generateKeys('origin', use);
        const proxyKeys = await lib.generateKeys('proxy', use);
        const recipientKeys = await lib.generateKeys('recipient', use);

        const encrypted = await lib.encryptWithKeys(myData, proxyKeys, originKeys.public, use);
  
        // Origin generate transform Key
        const transformKeyOriginToRecipient = await lib.getTransformKey(originKeys, recipientKeys.public);

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