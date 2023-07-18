require('./helpers');

const { assert } = require('chai');

function getPassword() {
  return Math.random().toString(36).substring(2);
}

// list all envelope types to use
const envelopeTypes = ['aes-256-gcm-0'];

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
        assert.isTrue(encrypted.startsWith('enc::'), 'Should start with enc::');
        const decrypted = enveloppe.decrypt(encrypted, password);
        assert.equal(myString, decrypted);
      });
    });
  }
});

