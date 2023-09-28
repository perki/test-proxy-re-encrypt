
const lib = require('../src/lib/');

(async () => {
  for (const recryptType of lib.recryptTypes) {
    for (const envelopeType of lib.envelopeTypes) {
      const use = {
        envelope: envelopeType,
        recrypt: recryptType
      }
      console.log({use});
      const originKeys = await lib.generateKeys('origin', use);
      console.log({originKeys});
    }
  }
})();