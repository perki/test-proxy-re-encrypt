
const lib = require('../src/lib/');
const recrypts = require('../src/recrypt');

(async () => {
  for (const recryptType of lib.recryptTypes) {
    for (const envelopeType of lib.envelopeTypes) {
      const use = {
        envelope: envelopeType,
        recrypt: recryptType
      }
      clog({use});
      const originKeys = await lib.generateKeys('origin', use);
      clog({originKeys});
    }
  }
  for (const recryptType of recrypts.list()) {
    clog(`implementation ${recryptType}`);
    const recrypt = recrypts.get(recryptType);
    await recrypt.init();
    const password = await recrypt.getNewPassword();
    clog('password', password);
    const keyId = 'myKeyId';
    const key = await recrypt.generateKeys(keyId);
    clog('key', key);
    const encryptedPassword = await recrypt.encryptPassword(password, key, key.public.publicKey);
    clog('encryptedPassword', encryptedPassword);
    const decryptedPassword = await recrypt.decryptPassword(encryptedPassword, key.privateKey);
    clog('encryptedPassword', decryptedPassword);
  }
  

})();


function clog() {
  document.write(...arguments);
  console.log(...arguments);
  document.write('<br> > ');
}
