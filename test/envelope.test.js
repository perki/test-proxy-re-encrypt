require('./helpers');

const { assert } = require('chai');

function getPassword() {
  return Math.random().toString(36).substring(2);
}

// list all envelope types to use
const envelopeTypes = ['aes-256-gcm-0', 'aes-192-0'];

describe('envelope', function () {
  for (const envelopeType of envelopeTypes) {

    describe(`implementation ${envelopeType}`, function () {
      let enveloppe = require('../src/envelope')(envelopeType);

      it('Has correct type code', () => {
        assert.equal(enveloppe.type, envelopeType);
      });

      it('Encrypt / Decrypt string', () => {
        const password = getPassword();
        const myString = 'love "❤️" 😁';
        const encrypted = enveloppe.encrypt(myString, password);
        assert.isString(encrypted);
        assert.isTrue(encrypted.startsWith(envelopeType + '::'), `Should start with ${envelopeType}::`);
        const decrypted = enveloppe.decrypt(encrypted, password);
        assert.equal(myString, decrypted);
      });

      it('Encrypt / Decrypt object', () => {
        const password = getPassword();
        const myData = {
          string: 'Hello 😃 !',
          int: 12, 
          float: 0.12,
          bool: true,
          nested: {
            array: ['a', 1, true]
          }
        };
        const encrypted = enveloppe.encrypt(myData, password);
        assert.isString(encrypted);
        assert.isTrue(encrypted.startsWith(envelopeType + '::'), `Should start with ${envelopeType}::`);
        const decrypted = enveloppe.decrypt(encrypted, password);
        assert.deepEqual(myData, decrypted);
      });
    });
  }
});

