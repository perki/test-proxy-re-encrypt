//const Recrypt = require('@ironcorelabs/recrypt-wasm-binding');
import * as Recrypt from "@ironcorelabs/recrypt-wasm-binding";
const lib = require('../src/lib');
lib.init(Recrypt);

const API = require('../src/api');

const api = new API();


/**
 * We have two persons
 *  - "user" is an individual using and 'api' service
 *  - "target" is anothe individual who gets access to "user" data in r/w mode using the 'api' service
 * 
 *  The 'api' only holds encrypted data, 
 *      'user' only can decrypt the data.
 *      'target' can ddcrypt the data only when transformed by 'api' for him.
 * 
 *  The data is encrypted 'end' to 'end' with a central repository encrypted.
 * 
 *  An "attacker", should have either the private key of "user" or 
 *      the private key of "target" + the transform key hold on "api".
 */


// 1- User creates his keys
const userKeys = lib.generateKeys();

// 2- User communicates his public key to the server
api.createUser('user1', {publicKey: userKeys.publicKey, signPublicKey: userKeys.signPublicKey});

// 3- Someone post Data to the server (any one can send unecrypted data to the server)
api.postUnencryptedData('user1', 'Unencrypted from someone 😀');

function clog() {
  document.write(...arguments);
  document.write('<br>');
}

// 4- User get his own data and decrypt it
clog('user get>', lib.decrypt(api.getData('user1'), userKeys.privateKey));

// 5- A target send a request to access user data 
const targetKeys = lib.generateKeys();
// 5.1 target communicates his public key to the user
const requestFromTargetToUser = {publicKey: targetKeys.publicKey, signPublicKey: targetKeys.signPublicKey}; 
// 5.2 user creates a transform key from his private key to the target public key
const userToTargetTransfromKey = lib.getTransformKey(userKeys, requestFromTargetToUser.publicKey);
// 5.3 user register the target as an authorized recipient on the server
api.postRecipient('user1', 'target1', userToTargetTransfromKey);

// 6- Target Get Data from the server
clog('target get>', lib.decrypt(api.getData('user1', 'target1'), targetKeys.privateKey));

// 7- User sends encrypted data
api.postData('user1', lib.encrypt('Encrypted from user', userKeys.publicKey, userKeys.signPrivateKey));

// 8- Target sends encrypted data
api.postData('user1', lib.encrypt('Encrypted from target', api.getPublicKeys('user1').publicKey, targetKeys.signPrivateKey));

// 9- User get his data
clog('user get>', lib.decrypt(api.getData('user1'), userKeys.privateKey));

// 10- Target get user's data
clog('target get>', lib.decrypt(api.getData('user1', 'target1'), targetKeys.privateKey));