require('./helpers');

const { assert } = require('chai');
const lib = require('../src/lib');

describe('lib', () => {

  before(async () => {
    await lib.init();
  });

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

    const originKeys = await lib.generateKeys('origin');
    const encrypted = await lib.encryptWithKeys(myData, originKeys);
    const decryptedData = await lib.decryptWithKeys(encrypted, originKeys.privateKey);
    assert.deepEqual(myData, decryptedData);
  });
});