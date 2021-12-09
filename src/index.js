const lib = require('./lib');
const API = require('./api');

const api = new API();

// 1- User creates his keys
const userKeys = lib.generateKeys();

// 2- User communicates his public key to the server
api.postPublicKeys('user1', {publicKey: userKeys.publicKey, signPublicKey: userKeys.signPublicKey});

// 3- Somone post Data to the server
api.postUnencryptedData('user1', 'Unencrypted from someone');

// 4- User get his data
console.log('user get>', lib.decrypt(api.getData('user1'), userKeys.privateKey));

// 5- A target send a request to access user data 
const targetKeys = lib.generateKeys();
// 5.1 target communicates his public key to the user
const requestFromTargetToUser = {publicKey: targetKeys.publicKey, signPublicKey: targetKeys.signPublicKey}; 
// 5.2 user creates a transform key from his private key to the target public key
const userToTargetTransfromKey = lib.getTransformKey(userKeys, requestFromTargetToUser.publicKey);
// 5.3 user register the target as an authorized recipient on the server
api.postRecipient('user1', 'target1', userToTargetTransfromKey);

// 6- Target Get Data from the server
console.log('target get>', lib.decrypt(api.getDataFor('user1', 'target1'), targetKeys.privateKey));

// 7- User sends encrypted data
api.postData('user1', lib.encrypt('Encrypted from user', userKeys.publicKey, userKeys.signPrivateKey));

// 8- Target sends encrypted data
api.postData('user1', lib.encrypt('Encrypted from target', api.getPublicKeys('user1').publicKey, targetKeys.signPrivateKey));

// 9- User get his data
console.log('user get>', lib.decrypt(api.getData('user1'), userKeys.privateKey));

// 10- Target get user's data
console.log('target get>', lib.decrypt(api.getDataFor('user1', 'target1'), targetKeys.privateKey));