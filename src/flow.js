
const lib = require('./lib/recrypt');
const API = require('./api');

module.exports = function executeFlow(clog) {

  const api = new API();

  /**
   * We have two persons
   *  - "user" is an individual using and 'api' service
   *  - "target" is another individual who gets access to "user" data in r/w mode using the 'api' service
   * 
   *  The 'api' only holds encrypted data, 
   *      'user' only can decrypt the data.
   *      'target' can decrypt the data only when transformed by 'api' for him.
   * 
   *  The data is encrypted 'end' to 'end' with a central repository encrypted.
   * 
   *  An "attacker", should have either the private key of "user" or 
   *      the private key of "target" + the transform key hold on "api".
   */


  // 1- User creates his keyRing
  const userKeys = {};

  // 2- User communicates his public key to the server
  api.createUser('user1', { publicKey: userKeys.publicKey, signPublicKey: userKeys.signPublicKey });

  const keyForStreamA = lib.generateKeys('user1:streamA:0');
  userKeys[keyForStreamA.public.id] = keyForStreamA;

  // 2.1- Create a stream
  api.createStream('user1', {
    id: 'streamA', 
    clientData: { 
      encryption : { 
        'recrypt-aes-256-gcm-v1': keyForStreamA.public
      } 
    }
  });

  // 3- Someone post Data to the server (any one can send unencrypted data to the server)
  api.postUnencryptedEvent('user1', {id: 'e1', streamIds: ['streamA'], type: 'note/txt', content: 'Unencrypted from someone 😀'});

  
  // 4- User get his own data and decrypt it
  const userEvents = api.getData('user1');
  for (const event of userEvents) { // find a matching key 
    clog('user get encrypted>', event.content);
    const keyId = Object.keys(event.content)[0];
    const userKey = userKeys[keyId];
    const decryptedData = lib.decrypt(event.content[keyId], userKey.privateKey);
    Object.assign(event, decryptedData);
    clog('user get decrypted>', event);
  }

  /** 
  // 5- A target send a request to access user data 
  const targetKeys = lib.generateKeys();
  // 5.1 target communicates his public key to the user
  const requestFromTargetToUser = { publicKey: targetKeys.publicKey, signPublicKey: targetKeys.signPublicKey };
  // 5.2 user creates a transform key from his private key to the target public key
  const userToTargetTransfromKey = lib.getTransformKey(userKeys, requestFromTargetToUser.publicKey);
  // 5.3 user register the target as an authorized recipient on the server
  api.postRecipient('user1', 'target1', { transformKey: userToTargetTransfromKey, publicKeys: requestFromTargetToUser });

  // 6- Target Get Data from the server
  clog('target get>', lib.decryptArray(api.getData('user1', 'target1'), targetKeys.privateKey));

  // 7- User sends encrypted data
  api.postData('user1', lib.encrypt('Encrypted from user', userKeys.publicKey, userKeys.signPrivateKey));

  // 8- Target sends encrypted data
  api.postData('user1', lib.encrypt('Encrypted from target', api.getPublicKeys('user1').publicKey, targetKeys.signPrivateKey));

  // 9- User get his data
  clog('user get>', lib.decryptArray(api.getData('user1'), userKeys.privateKey));

  // 10- Target get user's data
  clog('target get>', lib.decryptArray(api.getData('user1', 'target1'), targetKeys.privateKey));

  // 11- User rotates his keys
  const newUserKeys = lib.generateKeys();
  // 11.1 Generate a trasform key for API
  const apiTransformRotateKey = lib.getTransformKey(userKeys, newUserKeys.publicKey);
  // 11.1 Generate new transform keys for recipients
  const newRecipientTransformKeys = [];
  for (const recipient of api.getRecipientsPublicKeys('user1')) {
    newRecipientTransformKeys.push({
      transformKey: lib.getTransformKey(newUserKeys, recipient.publicKey),
      recipientid: recipient.recipientid
    });
  };
  // 11.2 Update keys on api
  api.rotateKeys('user1', 
    { keys: { publicKey: newUserKeys.publicKey, signPublicKey: newUserKeys.signPublicKey }, 
      transformKey: apiTransformRotateKey,
      newRecipientTransformKeys: newRecipientTransformKeys
    });

  
  // 12- User get his data
  clog('user get>', lib.decryptArray(api.getData('user1'), newUserKeys.privateKey));

  // 13- Target get user's data
  clog('target get>', lib.decryptArray(api.getData('user1', 'target1'), targetKeys.privateKey));

  // 14- Target rotates his keys
  const newTargetKeys = lib.generateKeys();
  */
}