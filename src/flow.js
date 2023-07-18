
const lib = require('./lib');
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

  // 4- Create client side encrypted data 
  const eventA = {id: 'e2', streamIds: ['streamA'], type: 'note/txt', content: 'Encrypted by from myself'};
  const keyId = 'user1:' + eventA.streamIds[0] + ':0';
  const userKey = userKeys[keyId];
  const password = lib.decryptPassword(userKey.public.encryptedPassword, userKey.privateKey);
  const encryptedEventContent = lib.encryptWithPassword({type: eventA.type, content: eventA.content}, password);
  const encryptedEventA = structuredClone(eventA);
  encryptedEventA.type = 'encrypted/recrypt-aes-256-gcm-v1';
  encryptedEventA.content = { [keyId] :  encryptedEventContent };
  api.postEvent('user1', encryptedEventA);
  
  // 4- User get his own data and decrypt it
  const userEvents = api.getEvents('user1');
  for (const event of userEvents) { // find a matching key 
    clog('user get encrypted>', event.content);
    decryptEvent(event, userKeys);
  }
  clog('user get decrypted>', userEvents);

  
  // 5- A target send a request to access user data 
  const targetKeys = {};
  // generate 
  const targetKeyFromStreamA = lib.generateKeys('user1:streamA:0');
  targetKeys[targetKeyFromStreamA.public.id] = targetKeyFromStreamA;

  // 5.1 target communicates his public key to the user
  const requestFromTargetToUser = { publicKey: targetKeyFromStreamA.public.publicKey, signPublicKey: targetKeyFromStreamA.public.signPublicKey };

  // 5.2 user creates a transform key from his private key to the target public key for streamA
  const userToTargetTransfromKeys = {};
  for (const streamId of ['streamA']) {
    const keyId = 'user1:' + streamId + ':0';
    const userKey = userKeys[keyId];
    const userToTargetTransfromKey = lib.getTransformKey(userKey, requestFromTargetToUser.publicKey);
    userToTargetTransfromKeys[keyId] = userToTargetTransfromKey;
  }

  // 5.3 user register the target as an authorized recipient on the server
  api.postRecipient('user1', 'target1', { transformKeys: userToTargetTransfromKeys, publicKeys: requestFromTargetToUser });

  // 6.1 - Target Get Streams from the server 
  const streamsFromUser1ForTarget1 = api.getStreams('user1', 'target1');
  clog('target getStreams>', streamsFromUser1ForTarget1);

  
  // 6.2 - Target Get Events from the server
  $$(targetKeys);
  const eventsForTarget = api.getEvents('user1', 'target1');
  for (const event of eventsForTarget) { // find a matching key 
    clog('target get encrypted>', event);
    decryptEvent(event, targetKeys);
  }
  clog('target get decrypted>', eventsForTarget);

  //clog('target get>', lib.decryptArray(api.getData('user1', 'target1'), targetKeys.privateKey));

  /**
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

function decryptEvent(event, keys) {
  if (event.type != 'encrypted/recrypt-aes-256-gcm-v1') return;
  const keyId = Object.keys(event.content)[0];
  const userKey = keys[keyId];
  if (event.content[keyId].encryptedPassword) {
    const decryptedData = lib.decrypt(event.content[keyId], userKey.privateKey);
    Object.assign(event, decryptedData);
  } else {
    
    const password = lib.decryptPassword(userKey.public.encryptedPassword, userKey.privateKey);
    $$({eventContent: event.content[keyId], password});
    const decryptedData = lib.decryptWithPassword(event.content[keyId], password);
    Object.assign(event, decryptedData);
  }
}