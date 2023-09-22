require('./helpers');

const { assert } = require('chai');
const lib = require('../src/lib');

describe('lib', () => {

  it('Encrypt / Decrypt object', () => {
    const myData = {
      string: 'Hello 😃 !',
      int: 12, 
      float: 0.12,
      bool: true,
      nested: {
        array: ['a', 1, true]
      }
    };

    const originKeys = lib.generateKeys('origin');
    const encrypted = lib.encryptWithKeys(myData, originKeys.public, originKeys.signPrivateKey);
    const decryptedData = lib.decryptWithKeys(encrypted, originKeys.privateKey);
    assert.deepEqual(myData, decryptedData);
  });
});