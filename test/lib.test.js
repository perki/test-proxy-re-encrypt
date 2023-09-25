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

      it('Encrypt / Decrypt object', async () => {
        const myData = {
          string: 'Hello 😃 !',
          int: 12, 
          float: 0.12,
          bool: true,
          nested: {
            array: ['a', 1, true]
          }
        };

        const originKeys = await lib.generateKeys('origin', use);
        const encrypted = await lib.encryptWithKeys(myData, originKeys, use);
        const infos = infoFromKeyId(encrypted.keyId);
        assert.equal(infos.id, 'origin', 'Orgin key is kept');
        assert.equal(infos.recrypt, recryptType, 'Recrypt type is correct');
        assert.equal(infos.envelope, envelopeType, 'Envelope type is correct');
        const decryptedData = await lib.decryptWithKeys(encrypted, originKeys.privateKey);
        assert.deepEqual(myData, decryptedData);
      });
    });
  }
}


function infoFromKeyId(key) {
  const [id, recrypt, envelope] = key.split(':');
  return {id, recrypt, envelope};
}